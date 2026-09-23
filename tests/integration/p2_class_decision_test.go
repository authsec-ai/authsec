package integration

// T6.6 classification (SPEC-iga-phase2-graph.md §2.14.3 "The classification
// contract", §5.5; D-29..D-33), end to end: the REAL route table over the
// P2-0 lab, a workload the REAL scan worker and projector produced, and a
// caller whose token context is a real, active workspace membership row.
//
// Each test names the safeguard it proves; the mutation that removes the
// safeguard is recorded in the task report.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// classFixture is one lab workspace with one projected Lambda workload and one
// verified human ("Priya Shah") whose claims the API carries.
type classFixture struct {
	t        *testing.T
	l        *p2Lab
	api      *readAPI
	workload uuid.UUID
	user     uuid.UUID
	member   uuid.UUID
}

func classSetup(t *testing.T, name string) *classFixture {
	t.Helper()
	l := newP2Lab(t, name, true)
	l.scanAndProject(oneLambda(l))
	var wl []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name = 'refund-processor'`, l.ws).Scan(&wl)
	if len(wl) != 1 {
		t.Fatalf("the lab projected %d refund-processor workloads, want 1", len(wl))
	}
	f := &classFixture{t: t, l: l, api: l.api(), workload: wl[0]}
	name1 := "Priya Shah"
	f.user, f.member = classMember(t, l.db, l.ws, &name1, "priya@test.local", "active")
	f.api.withClaims(classClaims(f.user, f.member))
	return f
}

// classClaims is the token context of a human console session: user_id,
// workspace_membership_id and -- because a real session has one -- client_id.
func classClaims(user, member uuid.UUID) map[string]string {
	return map[string]string{
		"user_id": user.String(), "workspace_membership_id": member.String(), "client_id": "console-client",
	}
}

// classMember creates a user (name nil keeps the column default, 'Not
// Provided'), a role and a membership with the given status, and removes them
// when the test ends.
func classMember(t *testing.T, db *gorm.DB, ws uuid.UUID, name *string, email, status string) (user, member uuid.UUID) {
	t.Helper()
	user, member, role := uuid.New(), uuid.New(), uuid.New()
	var err error
	if name == nil {
		err = db.Exec(`INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`, user, email, ws).Error
	} else {
		err = db.Exec(`INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, ?, ?)`, user, email, *name, ws).Error
	}
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Exec(`INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`,
		role, "class-"+role.String()[:8], ws).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Exec(`INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status)
		VALUES (?, ?, ?, ?, ?)`, member, ws, user, role, status).Error; err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM workspace_memberships WHERE id = ?`, member)
		db.Exec(`DELETE FROM users WHERE id = ?`, user)
		db.Exec(`DELETE FROM roles WHERE id = ?`, role)
	})
	return user, member
}

// classInsertWorkload adds a workload row directly. Used where the projector
// cannot produce the shape needed without a Bedrock fake (provider-native) or
// where a second workload is only a lock target; the classification service
// reads nothing but the iga_workload row.
func classInsertWorkload(t *testing.T, l *p2Lab, name, runtimeKind, classification string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := l.db.Exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
		VALUES (?, ?, ?, ?, 'us-east-1', ?, ?)`,
		id, l.ws, runtimeKind, name, "aws\x1fclass-test\x1f"+id.String(), classification).Error; err != nil {
		t.Fatalf("insert workload: %v", err)
	}
	return id
}

func (f *classFixture) path(workload uuid.UUID) string {
	return "/workloads/" + workload.String() + "/classification"
}

// classBody is a POST body; undoes nil is JSON null.
func classBody(op uuid.UUID, decision, reason string, expected int64, undoes *uuid.UUID) map[string]any {
	b := map[string]any{
		"operation_id": op.String(), "decision": decision, "purpose": "Customer support triage",
		"reason": reason, "expected_version": expected, "undoes_decision_id": nil,
	}
	if undoes != nil {
		b["undoes_decision_id"] = undoes.String()
	}
	return b
}

func (f *classFixture) post(workload uuid.UUID, body map[string]any) (int, map[string]any) {
	f.t.Helper()
	return f.api.do(http.MethodPost, f.path(workload), body)
}

// classify makes one decision that must succeed, returning its data.
func (f *classFixture) classify(workload uuid.UUID, body map[string]any) map[string]any {
	f.t.Helper()
	st, out := f.post(workload, body)
	mustStatus(f.t, "classify", st, out, http.StatusOK)
	return out
}

type classResp struct {
	status int
	body   map[string]any
	err    error
}

// classPost is a POST safe to call from a goroutine: it never touches t.
func classPost(a *readAPI, path string, body any) classResp {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &out)
	return classResp{status: w.Code, body: out, err: err}
}

// classWaitLockWaiter waits until some backend of this database is waiting on
// a lock -- the second request, parked behind the first one's row lock.
func classWaitLockWaiter(t *testing.T, db *gorm.DB) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		db.Raw(`SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n)
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the second request never waited on a lock")
}

type classState struct {
	Classification string
	Version        int64
	Decisions      int64
	Seq            int64
}

// state is the workload's classification, its decision count and the
// workspace clock -- everything one decision transaction writes.
func (f *classFixture) state(workload uuid.UUID) classState {
	f.t.Helper()
	var s classState
	f.l.db.Raw(`SELECT classification, classification_version AS version FROM iga_workload WHERE id = ?`, workload).Scan(&s)
	s.Decisions = f.l.count(`SELECT count(*) FROM iga_workload_classification WHERE workload_id = ?`, workload)
	s.Seq = f.l.count(`SELECT COALESCE(max(seq), 0) FROM iga_classification_clock WHERE workspace_id = ?`, f.l.ws)
	return s
}

func classWant(t *testing.T, what string, got, want classState) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: state = %+v, want %+v", what, got, want)
	}
}

/* ---------------------------------- B22 ----------------------------------- */

// B22: two concurrent retries of ONE operation. Request 1 takes the workload's
// row lock and is held inside its transaction, writes done, not committed.
// Request 2 -- the same operation, byte for byte -- starts and parks on the
// lock. Request 1 commits; request 2 then finds the operation and REPLAYS it.
//
// Safeguard: the operation lookup runs AFTER the lock. Looked up before, request
// 2 misses the uncommitted decision, then waits on the lock, then finds the
// version moved and answers 409 -- a retried save shown as a conflict (E12).
func TestP2ClassConcurrentRetriesReplay(t *testing.T) {
	f := classSetup(t, "p2-class-b22")
	entered, release := make(chan struct{}), make(chan struct{})
	var calls int32
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	f.api.ctl.WithClassificationService(services.NewClassificationService(f.l.db).WithBeforeCommit(func() {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(entered)
			<-release
		}
	}))
	pubs := f.l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, f.l.ws)

	body := classBody(uuid.New(), models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil)
	first, second := make(chan classResp, 1), make(chan classResp, 1)
	go func() { first <- classPost(f.api, f.path(f.workload), body) }()
	select {
	case <-entered:
	case r := <-first:
		t.Fatalf("request 1 finished without reaching its commit: %d %v", r.status, r.body)
	case <-time.After(5 * time.Second):
		t.Fatal("request 1 never reached its commit")
	}
	go func() { second <- classPost(f.api, f.path(f.workload), body) }()
	classWaitLockWaiter(t, f.l.db)
	releaseAll()
	a, b := <-first, <-second

	if a.err != nil || a.status != http.StatusOK || dig(a.body, "data", "replayed") != false {
		t.Fatalf("request 1 = %d %v, want 200 replayed:false", a.status, a.body)
	}
	if b.err != nil || b.status != http.StatusOK || dig(b.body, "data", "replayed") != true {
		t.Fatalf("request 2 (a concurrent retry) = %d %v, want 200 replayed:true", b.status, b.body)
	}
	if digs(a.body, "data", "decision", "id") != digs(b.body, "data", "decision", "id") ||
		num(a.body, "data", "classification_version") != 1 || num(b.body, "data", "classification_version") != 1 {
		t.Fatalf("the replay is not the stored outcome: %v vs %v", a.body, b.body)
	}
	classWant(t, "after two retries of one operation", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 1})
	// Classification is not part of a revision (§5.5): no publication.
	if got := f.l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, f.l.ws); got != pubs {
		t.Fatalf("a decision wrote a publication: %d -> %d", pubs, got)
	}
}

// Step 6: the SAME operation id used concurrently on two DIFFERENT workloads.
// The row lock does not serialize them; the second insert waits on the first's
// operation-key index entry, and when the first commits it is a unique
// violation -- which is 422 operation_id_reused, with nothing of it written.
//
// Safeguard: the 23505 on iga_wc_operation_key is mapped to 422 and rolled
// back. Unmapped, it is 500 internal.
func TestP2ClassSameOperationTwoWorkloadsConcurrently(t *testing.T) {
	f := classSetup(t, "p2-class-two-workloads")
	other := classInsertWorkload(t, f.l, "cs-handler-b", "lambda_function", models.ClassificationUnclassified)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls int32
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	f.api.ctl.WithClassificationService(services.NewClassificationService(f.l.db).WithBeforeCommit(func() {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(entered)
			<-release
		}
	}))

	op := uuid.New()
	first, second := make(chan classResp, 1), make(chan classResp, 1)
	go func() {
		first <- classPost(f.api, f.path(f.workload), classBody(op, models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request 1 never reached its commit")
	}
	go func() {
		second <- classPost(f.api, f.path(other), classBody(op, models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	}()
	classWaitLockWaiter(t, f.l.db) // parked on the operation key, not on a row
	releaseAll()
	a, b := <-first, <-second

	if a.status != http.StatusOK {
		t.Fatalf("request 1 = %d %v, want 200", a.status, a.body)
	}
	if b.status != http.StatusUnprocessableEntity || errCode(b.body) != "operation_id_reused" {
		t.Fatalf("the same operation on another workload, concurrently = %d %v, want 422 operation_id_reused", b.status, b.body)
	}
	classWant(t, "the second workload", f.state(other),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 1})
}

/* ------------------------ retries, reuse and conflict ---------------------- */

// E12: a retry after a dropped response replays the STORED outcome -- even
// after another decision has moved the version since.
func TestP2ClassRetryAfterVersionMovedReplays(t *testing.T) {
	f := classSetup(t, "p2-class-retry")
	body := classBody(uuid.New(), models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil)
	orig := f.classify(f.workload, body)
	undo := classBody(uuid.New(), models.ClassificationUnclassified, "Undo of the decision at 14:02", 1,
		classPtr(classUUID(t, digs(orig, "data", "decision", "id"))))
	f.classify(f.workload, undo)

	st, again := f.post(f.workload, body)
	mustStatus(t, "retry of the first operation", st, again, http.StatusOK)
	if dig(again, "data", "replayed") != true || digs(again, "data", "classification") != models.ClassificationClassified ||
		num(again, "data", "classification_version") != 1 ||
		digs(again, "data", "decision", "id") != digs(orig, "data", "decision", "id") {
		t.Fatalf("retry = %v, want the stored outcome (classified_agent @1, replayed) of %v", again, orig)
	}
	classWant(t, "after the replay", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 2, Decisions: 2, Seq: 2})
}

// The operation is bound to its request (D-29): the same operation_id with
// different content, from a different actor, or on a different workload is
// 422 operation_id_reused, and nothing is written.
//
// Safeguard: the request-hash comparison on a found operation. Without it,
// every reuse "replays" someone else's decision as this request's outcome.
func TestP2ClassOperationReusedIs422(t *testing.T) {
	f := classSetup(t, "p2-class-reused")
	op := uuid.New()
	f.classify(f.workload, classBody(op, models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil))
	before := f.state(f.workload)

	// Different content: the reason.
	st, out := f.post(f.workload, classBody(op, models.ClassificationClassified, "a different reason", 0, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "operation_id_reused" {
		t.Fatalf("same operation, different reason = %d %v, want 422 operation_id_reused", st, out)
	}
	// Different actor, identical body.
	alex := "Alex Kim"
	u2, m2 := classMember(t, f.l.db, f.l.ws, &alex, "alex@test.local", "active")
	f.api.withClaims(classClaims(u2, m2))
	st, out = f.post(f.workload, classBody(op, models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "operation_id_reused" {
		t.Fatalf("same operation, another actor = %d %v, want 422 operation_id_reused", st, out)
	}
	// Different workload, identical body and actor.
	f.api.withClaims(classClaims(f.user, f.member))
	other := classInsertWorkload(t, f.l, "cs-handler-b", "lambda_function", models.ClassificationUnclassified)
	st, out = f.post(other, classBody(op, models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "operation_id_reused" {
		t.Fatalf("same operation, another workload = %d %v, want 422 operation_id_reused", st, out)
	}
	classWant(t, "after three reuses", f.state(f.workload), before)
	if n := f.state(other).Decisions; n != 0 {
		t.Fatalf("a reused operation wrote %d decisions on the other workload", n)
	}
	// Whitespace around the text is not content (D-29: strings trimmed): a
	// retry that differs only there replays.
	padded := classBody(op, models.ClassificationClassified, "  Owns tier-1 ticket routing ", 0, nil)
	padded["purpose"] = " Customer support triage"
	st, out = f.post(f.workload, padded)
	if st != http.StatusOK || dig(out, "data", "replayed") != true {
		t.Fatalf("a retry differing only in surrounding whitespace = %d %v, want 200 replayed", st, out)
	}
}

// Concurrent edits (§2.14.3): a DIFFERENT operation against a stale version
// is 409 classification_conflict carrying the current decision -- who, when,
// why, under a display name resolved now -- and writes nothing. A deliberate
// replacement is a new operation against the version the 409 returned.
//
// Safeguard: the expected_version check. Without it the second person
// silently overwrites the first.
func TestP2ClassStaleVersionIs409WithCurrentDecision(t *testing.T) {
	f := classSetup(t, "p2-class-conflict")
	// A 409 before any decision exists names nobody (nothing claimed).
	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "stale", 5, nil))
	if st != http.StatusConflict || errCode(out) != "classification_conflict" ||
		dig(out, "error", "current", "decided_by") != nil || num(out, "error", "current", "classification_version") != 0 {
		t.Fatalf("wrong version, no decision yet = %d %v, want 409 with decided_by null at version 0", st, out)
	}

	first := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "owns refunds", 0, nil))
	before := f.state(f.workload)

	alex := "Alex Kim"
	u2, m2 := classMember(t, f.l.db, f.l.ws, &alex, "alex@test.local", "active")
	f.api.withClaims(classClaims(u2, m2))
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "mine", 0, nil))
	mustStatus(t, "a different operation against version 0", st, out, http.StatusConflict)
	cur := dig(out, "error", "current")
	if errCode(out) != "classification_conflict" ||
		digs(cur, "classification") != models.ClassificationClassified || num(cur, "classification_version") != 1 ||
		digs(cur, "decided_by", "user_id") != f.user.String() || digs(cur, "decided_by", "display") != "Priya Shah" ||
		digs(cur, "reason") != "owns refunds" || digs(cur, "decided_at") != digs(first, "data", "decision", "decided_at") {
		t.Fatalf("409 current = %v, want Priya Shah's classified_agent @1 'owns refunds'", cur)
	}
	classWant(t, "after the 409", f.state(f.workload), before)

	// "Replace with mine": a new operation against the version the 409 gave.
	latest := classUUID(t, digs(first, "data", "decision", "id"))
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "replaced", 1, &latest))
	mustStatus(t, "replacement against the returned version", st, out, http.StatusOK)
	if digs(out, "data", "decision", "decided_by", "display") != "Alex Kim" {
		t.Fatalf("replacement decided_by = %v, want Alex Kim", dig(out, "data", "decision", "decided_by"))
	}
}

/* ------------------------------ the rules --------------------------------- */

// Provider-native agents are not human-editable (§2.14.3): 422 provider_native,
// nothing written, whatever the version.
//
// Safeguard: the provider-native refusal. Without it a person could relabel
// what AWS itself reports as an agent.
func TestP2ClassProviderNativeIs422(t *testing.T) {
	f := classSetup(t, "p2-class-native")
	agent := classInsertWorkload(t, f.l, "support-agent", "bedrock_agent", models.ClassificationProviderAgent)
	st, out := f.post(agent, classBody(uuid.New(), models.ClassificationClassified, "it is an agent", 0, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "provider_native" {
		t.Fatalf("classify a provider-native agent = %d %v, want 422 provider_native", st, out)
	}
	classWant(t, "provider-native", f.state(agent),
		classState{Classification: models.ClassificationProviderAgent, Version: 0, Decisions: 0, Seq: 0})
}

// Undo (§2.14.3): a NEW decision, unclassified, with undoes_decision_id set --
// recorded, never a deletion; only classified_agent -> unclassified, and only
// of the workload's latest decision (D-30). The history keeps both, newest
// first.
func TestP2ClassUndoIsANewDecision(t *testing.T) {
	f := classSetup(t, "p2-class-undo")
	first := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	firstID := classUUID(t, digs(first, "data", "decision", "id"))

	// Undoing something that is not this workload's latest decision.
	other := classInsertWorkload(t, f.l, "cs-handler-b", "lambda_function", models.ClassificationUnclassified)
	otherDecision := f.classify(other, classBody(uuid.New(), models.ClassificationClassified, "other", 0, nil))
	otherID := classUUID(t, digs(otherDecision, "data", "decision", "id"))
	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, &otherID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("undo naming another workload's decision = %d %v, want 422 invalid_decision", st, out)
	}

	undo := f.classify(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "Undo of the decision at 14:02", 1, &firstID))
	if digs(undo, "data", "classification") != models.ClassificationUnclassified || num(undo, "data", "classification_version") != 2 {
		t.Fatalf("undo = %v, want unclassified @2", undo)
	}
	var row models.IGAWorkloadClassification
	f.l.db.Raw(`SELECT * FROM iga_workload_classification WHERE id = ?`, classUUID(t, digs(undo, "data", "decision", "id"))).Scan(&row)
	if row.UndoesDecisionID == nil || *row.UndoesDecisionID != firstID || row.Previous != models.ClassificationClassified ||
		row.AgainstVersion != 1 || row.ResultVersion != 2 || row.DecidedByUserID != f.user {
		t.Fatalf("undo row = %+v, want undoes %s, previous classified_agent, 1 -> 2, by %s", row, firstID, f.user)
	}
	if n := f.l.count(`SELECT count(*) FROM iga_workload_classification WHERE id = ?`, firstID); n != 1 {
		t.Fatal("the undone decision was deleted; undo must be recorded, never a deletion")
	}

	// A second undo of the same decision: the workload is no longer
	// classified_agent.
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "again", 2, &firstID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("undo of an unclassified workload = %d %v, want 422 invalid_decision", st, out)
	}

	// The history, newest first by result_version (D-33).
	st, hist := f.api.get(f.path(f.workload))
	mustStatus(t, "history", st, hist, http.StatusOK)
	items := digl(hist, "data")
	if len(items) != 2 || num(items[0], "result_version") != 2 || num(items[1], "result_version") != 1 ||
		digs(items[0], "undoes_decision_id") != firstID.String() || dig(items[1], "undoes_decision_id") != nil ||
		digs(items[0], "previous") != models.ClassificationClassified ||
		digs(items[1], "decided_by", "display") != "Priya Shah" || num(hist, "meta", "total") != 2 {
		t.Fatalf("history = %v, want [undo @2, classify @1] with the undo linked", hist)
	}
}

// Validation (D-30): a missing or malformed field is 400 invalid_parameter;
// deciding what the workload already is, or anything on a retired workload,
// is 422 invalid_decision. None of it writes.
func TestP2ClassValidation(t *testing.T) {
	f := classSetup(t, "p2-class-validation")
	good := func() map[string]any {
		return classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil)
	}
	for _, tc := range []struct {
		name  string
		edit  func(b map[string]any)
		param string
	}{
		{"no operation_id", func(b map[string]any) { delete(b, "operation_id") }, "operation_id"},
		{"operation_id not a UUID", func(b map[string]any) { b["operation_id"] = "op-1" }, "operation_id"},
		{"no decision", func(b map[string]any) { delete(b, "decision") }, "decision"},
		{"unknown decision", func(b map[string]any) { b["decision"] = "provider_native_agent" }, "decision"},
		{"no reason", func(b map[string]any) { delete(b, "reason") }, "reason"},
		{"blank reason", func(b map[string]any) { b["reason"] = "   " }, "reason"},
		{"no expected_version", func(b map[string]any) { delete(b, "expected_version") }, "expected_version"},
		{"negative expected_version", func(b map[string]any) { b["expected_version"] = -1 }, "expected_version"},
		{"expected_version not a number", func(b map[string]any) { b["expected_version"] = "0" }, "body"},
		{"undoes_decision_id not a UUID", func(b map[string]any) { b["undoes_decision_id"] = "x" }, "undoes_decision_id"},
		{"undo without the decision it undoes", func(b map[string]any) { b["decision"] = models.ClassificationUnclassified }, "undoes_decision_id"},
		{"classify naming a decision to undo", func(b map[string]any) { b["undoes_decision_id"] = uuid.NewString() }, "undoes_decision_id"},
	} {
		b := good()
		tc.edit(b)
		st, out := f.post(f.workload, b)
		if st != http.StatusBadRequest || errCode(out) != "invalid_parameter" || digs(out, "error", "parameter") != tc.param {
			t.Errorf("%s = %d %v, want 400 invalid_parameter on %s", tc.name, st, out, tc.param)
		}
	}
	classWant(t, "after every 400", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})

	f.classify(f.workload, good())
	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "again", 1, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("classify an already classified workload = %d %v, want 422 invalid_decision", st, out)
	}

	retired := classInsertWorkload(t, f.l, "old-handler", "lambda_function", models.ClassificationUnclassified)
	f.l.db.Exec(`UPDATE iga_workload SET lifecycle = 'retired', retired_reason = 'not_seen' WHERE id = ?`, retired)
	st, out = f.post(retired, good())
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("classify a retired workload = %d %v, want 422 invalid_decision", st, out)
	}
	if n := f.state(retired).Decisions; n != 0 {
		t.Fatalf("a retired workload got %d decisions", n)
	}
	// Its history is still served: a detail route returns retired objects.
	st, out = f.api.get(f.path(retired))
	if st != http.StatusOK || len(digl(out, "data")) != 0 {
		t.Fatalf("history of a retired workload = %d %v, want 200 and an empty list", st, out)
	}
}

/* --------------------------- who, and where -------------------------------- */

// Who may (§2.14.3): only a verified human workspace member decides. A machine
// token, an end-user token (user_id but no membership), a suspended member and
// another workspace's membership are all 403 forbidden in the §5.2 envelope,
// and write nothing. The route demands iga:review; the history iga:read.
func TestP2ClassRequiresAVerifiedHuman(t *testing.T) {
	f := classSetup(t, "p2-class-human")
	if p := f.api.requiredPermission(http.MethodPost, f.path(f.workload)); p != "iga:review" {
		t.Fatalf("POST classification demands %q, want iga:review", p)
	}
	if p := f.api.requiredPermission(http.MethodGet, f.path(f.workload)); p != "iga:read" {
		t.Fatalf("GET classification demands %q, want iga:read", p)
	}
	suspended := "Sam Suspended"
	su, sm := classMember(t, f.l.db, f.l.ws, &suspended, "sam@test.local", "suspended")
	otherWS := newWorkspace(t, f.l.db, "p2-class-human-other")
	ou, om := classMember(t, f.l.db, otherWS, nil, "other@test.local", "active")

	for _, tc := range []struct {
		name   string
		claims map[string]string
	}{
		{"machine token", map[string]string{"client_id": "ci-bot", "sub": "ci-bot"}},
		{"end-user token", map[string]string{"user_id": f.user.String(), "client_id": "app"}},
		{"suspended member", classClaims(su, sm)},
		{"another workspace's membership", classClaims(ou, om)},
		{"membership of another user", classClaims(uuid.New(), f.member)},
		{"user id that is not a UUID", map[string]string{"user_id": "ci-bot", "workspace_membership_id": f.member.String()}},
	} {
		f.api.withClaims(tc.claims)
		st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
		if st != http.StatusForbidden || errCode(out) != "forbidden" {
			t.Errorf("%s = %d %v, want 403 forbidden", tc.name, st, out)
		}
	}
	classWant(t, "after every refusal", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})

	f.api.withClaims(classClaims(f.user, f.member))
	out := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	var by uuid.UUID
	if err := f.l.db.Raw(`SELECT decided_by_user_id FROM iga_workload_classification WHERE workload_id = ?`,
		f.workload).Row().Scan(&by); err != nil {
		t.Fatalf("read decided_by_user_id: %v", err)
	}
	if by != f.user || digs(out, "data", "decision", "decided_by", "user_id") != f.user.String() {
		t.Fatalf("decided_by = %s / %v, want the member's USER id %s", by, dig(out, "data", "decision", "decided_by"), f.user)
	}
}

// E14: a workload id from another workspace is 404 on both routes -- for a
// caller who IS a verified member of their own workspace, so the 404 is the
// workspace scoping, not the actor rule -- and nothing is written anywhere.
func TestP2ClassCrossWorkspaceIs404(t *testing.T) {
	f := classSetup(t, "p2-class-cross")
	otherWS := newWorkspace(t, f.l.db, "p2-class-cross-other")
	ou, om := classMember(t, f.l.db, otherWS, nil, "other@test.local", "active")
	f.api.asWorkspace(otherWS).withClaims(classClaims(ou, om))

	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "not mine", 0, nil))
	if st != http.StatusNotFound || errCode(out) != "not_found" {
		t.Fatalf("POST on another workspace's workload = %d %v, want 404 not_found", st, out)
	}
	st, out = f.api.get(f.path(f.workload))
	if st != http.StatusNotFound || errCode(out) != "not_found" {
		t.Fatalf("GET history of another workspace's workload = %d %v, want 404 not_found", st, out)
	}
	// Another type's reference is 404 too (D-5).
	f.api.asWorkspace(f.l.ws).withClaims(classClaims(f.user, f.member))
	st, out = f.api.do(http.MethodPost, "/workloads/identity:"+f.workload.String()+"/classification",
		classBody(uuid.New(), models.ClassificationClassified, "typed ref of another type", 0, nil))
	if st != http.StatusNotFound {
		t.Fatalf("POST with an identity reference = %d %v, want 404", st, out)
	}
	classWant(t, "after cross-workspace attempts", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})
	if n := f.l.count(`SELECT count(*) FROM iga_classification_clock WHERE workspace_id = ?`, otherWS); n != 0 {
		t.Fatal("a refused cross-workspace decision bumped the other workspace's clock")
	}
}

/* ----------------------- the clock and list consistency ------------------- */

// The classification clock (§5.5) moves exactly once per decision -- not on a
// replay, a 409 or a 422 -- and a classification list's cursor from before a
// decision is 409 listing_changed, reason classification_changed.
func TestP2ClassClockAndListingChanged(t *testing.T) {
	f := classSetup(t, "p2-class-clock")
	r := igaread.NewReader(f.l.db, readTestCursorKey)
	seqNow := func() int64 {
		var s int64
		if err := r.Read(context.Background(), f.l.ws, igaread.Pin{}, func(q *igaread.Query) error {
			var err error
			s, err = igaread.ClassificationSeq(q)
			return err
		}); err != nil {
			t.Fatalf("read seq: %v", err)
		}
		return s
	}
	check := func(c *igaread.Cursor) *igaread.Error {
		return igaread.AsError(r.Read(context.Background(), f.l.ws, igaread.Pin{}, func(q *igaread.Query) error {
			return igaread.CheckClassificationSeq(q, c)
		}))
	}
	if s := seqNow(); s != 0 {
		t.Fatalf("seq before any decision = %d, want 0", s)
	}
	var rev int64
	r.Read(context.Background(), f.l.ws, igaread.Pin{}, func(q *igaread.Query) error { rev = q.Rev.Rev; return nil })
	zero := int64(0)
	page1 := &igaread.Cursor{ClassSeq: &zero}
	if e := check(page1); e != nil {
		t.Fatalf("a cursor at the current seq = %v, want accepted", e)
	}

	body := classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil)
	out := f.classify(f.workload, body)
	if s := seqNow(); s != 1 {
		t.Fatalf("seq after one decision = %d, want 1", s)
	}
	e := check(page1)
	if e == nil || e.Status != http.StatusConflict || e.Code != "listing_changed" || e.Extra["reason"] != "classification_changed" {
		t.Fatalf("a cursor from before a decision = %v, want 409 listing_changed classification_changed", e)
	}
	if e := check(nil); e != nil {
		t.Fatalf("a first page (no cursor) = %v, want accepted", e)
	}
	if e := check(&igaread.Cursor{}); e == nil || e.Code != "cursor_invalid" {
		t.Fatalf("a classification cursor with no clock = %v, want 400 cursor_invalid", e)
	}
	// The revision did not move: classification is not part of one.
	if err := r.Read(context.Background(), f.l.ws, igaread.Pin{Rev: &rev}, func(*igaread.Query) error { return nil }); err != nil {
		t.Fatalf("rev=%d after a decision = %v, want still current", rev, err)
	}

	// No movement on a replay, a 409 or a 422.
	f.classify(f.workload, body)
	f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "stale", 0, nil))
	f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "same", 1, nil))
	if s := seqNow(); s != 1 {
		t.Fatalf("seq after a replay, a 409 and a 422 = %d, want still 1", s)
	}
	id := classUUID(t, digs(out, "data", "decision", "id"))
	f.classify(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, &id))
	if s := seqNow(); s != 2 {
		t.Fatalf("seq after the second decision = %d, want 2", s)
	}
}

// Atomic (§2.14.3): the decision row, the workload update and the clock land
// together or not at all. A clock write that fails leaves no decision row and
// the workload unchanged.
func TestP2ClassDecisionIsAtomic(t *testing.T) {
	f := classSetup(t, "p2-class-atomic")
	fn := "class_fail_clock_" + uuid.NewString()[:8]
	trg := fn + "_trg"
	if err := f.l.db.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.workspace_id = '` + f.l.ws.String() + `'::uuid THEN RAISE EXCEPTION 'clock refused'; END IF;
		RETURN NEW; END $$`).Error; err != nil {
		t.Fatalf("create trigger function: %v", err)
	}
	if err := f.l.db.Exec(`CREATE TRIGGER ` + trg + ` BEFORE INSERT OR UPDATE ON iga_classification_clock
		FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() {
		f.l.db.Exec(`DROP TRIGGER IF EXISTS ` + trg + ` ON iga_classification_clock`)
		f.l.db.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})

	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	if st != http.StatusInternalServerError || errCode(out) != "internal" {
		t.Fatalf("a decision whose clock write fails = %d %v, want 500 internal", st, out)
	}
	classWant(t, "after the failed clock write", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})
}

// D-31: the wait for the workload's row lock is bounded; past it the request
// is 504 query_timeout and writes nothing. Here the lock is held by a plain
// transaction standing in for a projection.
//
// Safeguard: SET LOCAL lock_timeout. Without it the Save hangs behind the lock
// for as long as it is held.
func TestP2ClassLockWaitIsBounded(t *testing.T) {
	f := classSetup(t, "p2-class-lock")
	f.api.ctl.WithClassificationService(services.NewClassificationService(f.l.db).WithLockTimeout(300 * time.Millisecond))
	holder := f.l.db.Begin()
	if err := holder.Exec(`SELECT 1 FROM iga_workload WHERE id = ? FOR UPDATE`, f.workload).Error; err != nil {
		holder.Rollback()
		t.Fatalf("take the lock: %v", err)
	}
	done := make(chan classResp, 1)
	go func() {
		done <- classPost(f.api, f.path(f.workload), classBody(uuid.New(), models.ClassificationClassified, "blocked", 0, nil))
	}()
	var r classResp
	select {
	case r = <-done:
		holder.Rollback()
	case <-time.After(3 * time.Second):
		holder.Rollback()
		r = <-done
		t.Fatalf("the request waited on the lock until it was released (then %d %v), want 504 at the lock timeout", r.status, r.body)
	}
	if r.status != http.StatusGatewayTimeout || errCode(r.body) != "query_timeout" {
		t.Fatalf("a decision behind a held lock = %d %v, want 504 query_timeout", r.status, r.body)
	}
	classWant(t, "after the lock timeout", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})
}

// With IGA_GRAPH_PROJECTION off there is no graph to decide about: 503
// graph_unavailable, like every graph route (§2.8).
func TestP2ClassGraphOffIs503(t *testing.T) {
	l := newP2Lab(t, "p2-class-off", false)
	st, out := l.api().do(http.MethodPost, "/workloads/"+uuid.NewString()+"/classification",
		classBody(uuid.New(), models.ClassificationClassified, "x", 0, nil))
	if st != http.StatusServiceUnavailable || errCode(out) != "graph_unavailable" {
		t.Fatalf("POST with the switch off = %d %v, want 503 graph_unavailable", st, out)
	}
}

/* ------------------- names, latest decision, history paging ---------------- */

// D-32: users.name, unless empty or the 'Not Provided' default; else the
// email; else the user id. A decider with no user record still has a name.
func TestP2ClassDisplayNames(t *testing.T) {
	f := classSetup(t, "p2-class-names")
	blank := "  "
	defaulted, _ := classMember(t, f.l.db, f.l.ws, nil, "defaulted@test.local", "active")
	blanked, _ := classMember(t, f.l.db, f.l.ws, &blank, "blank@test.local", "active")
	gone := uuid.New()
	names, err := igaread.DisplayNames(f.l.db, f.user, defaulted, blanked, gone, f.user)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]string{
		f.user: "Priya Shah", defaulted: "defaulted@test.local", blanked: "blank@test.local", gone: gone.String(),
	}
	for id, w := range want {
		if names[id] != w {
			t.Errorf("display(%s) = %q, want %q", id, names[id], w)
		}
	}
}

// The workload detail's latest decision (igaread.LatestClassification): null
// before any decision; after, the latest by result_version with its id and
// operation id (what an Undo needs) and the decider's name.
func TestP2ClassLatestDecisionForTheDetail(t *testing.T) {
	f := classSetup(t, "p2-class-latest")
	r := igaread.NewReader(f.l.db, readTestCursorKey)
	latest := func() *igaread.LatestDecision {
		var d *igaread.LatestDecision
		if err := r.Read(context.Background(), f.l.ws, igaread.Pin{}, func(q *igaread.Query) error {
			var err error
			d, err = igaread.LatestClassification(q, f.workload)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := latest(); d != nil {
		t.Fatalf("latest before any decision = %+v, want nil", d)
	}
	op := uuid.New()
	out := f.classify(f.workload, classBody(op, models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	id := classUUID(t, digs(out, "data", "decision", "id"))
	undoOp := uuid.New()
	f.classify(f.workload, classBody(undoOp, models.ClassificationUnclassified, "undo", 1, &id))
	d := latest()
	if d == nil || d.OperationID != undoOp || d.Decision != models.ClassificationUnclassified ||
		d.DecidedBy.Display != "Priya Shah" || d.Reason != "undo" || d.Purpose == nil {
		t.Fatalf("latest = %+v, want the undo by Priya Shah", d)
	}
	raw, _ := json.Marshal(d)
	var shape map[string]any
	json.Unmarshal(raw, &shape)
	for _, k := range []string{"id", "operation_id", "decision", "purpose", "reason", "decided_by", "decided_at"} {
		if _, ok := shape[k]; !ok {
			t.Errorf("latest decision JSON lacks %q: %s", k, raw)
		}
	}
}

// History paging: keyset on result_version, newest first; the cursor is bound
// to its workload.
func TestP2ClassHistoryPages(t *testing.T) {
	f := classSetup(t, "p2-class-pages")
	out := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "one", 0, nil))
	id := classUUID(t, digs(out, "data", "decision", "id"))
	f.classify(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "two", 1, &id))
	f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "three", 2, nil))

	st, p1 := f.api.get(f.path(f.workload) + qs("limit", "2"))
	mustStatus(t, "page 1", st, p1, http.StatusOK)
	items := digl(p1, "data")
	next := digs(p1, "meta", "next_cursor")
	if len(items) != 2 || num(items[0], "result_version") != 3 || num(items[1], "result_version") != 2 || next == "" {
		t.Fatalf("page 1 = %v, want versions 3, 2 and a cursor", p1)
	}
	st, p2 := f.api.get(f.path(f.workload) + qs("limit", "2", "cursor", next))
	mustStatus(t, "page 2", st, p2, http.StatusOK)
	if items := digl(p2, "data"); len(items) != 1 || num(items[0], "result_version") != 1 || dig(p2, "meta", "next_cursor") != nil {
		t.Fatalf("page 2 = %v, want version 1 and no cursor", p2)
	}
	other := classInsertWorkload(t, f.l, "cs-handler-b", "lambda_function", models.ClassificationUnclassified)
	st, bad := f.api.get(f.path(other) + qs("cursor", next))
	if st != http.StatusBadRequest || errCode(bad) != "cursor_invalid" {
		t.Fatalf("another workload's history cursor = %d %v, want 400 cursor_invalid", st, bad)
	}
	if st, bad := f.api.get(f.path(f.workload) + qs("limit", "0")); st != http.StatusBadRequest {
		t.Fatalf("limit=0 = %d %v, want 400", st, bad)
	}
}

// can_classify's inputs (classifyCaller): the actor rule and iga:review by the
// same test the POST's middleware applies. With both, CanClassify offers the
// action on an active, non-provider-native workload only.
func TestP2ClassCanClassifyCaller(t *testing.T) {
	f := classSetup(t, "p2-class-capability")
	gin.SetMode(gin.TestMode)
	caller := func(claims map[string]string, jwtClaims jwt.MapClaims) igaread.ClassifyCaller {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range claims {
			c.Set(k, v)
		}
		if jwtClaims != nil {
			c.Set("claims", jwtClaims)
		}
		got, err := f.api.ctl.ClassifyCallerForTest(c, f.l.ws)
		if err != nil {
			t.Fatalf("classifyCaller: %v", err)
		}
		return got
	}
	human := classClaims(f.user, f.member)
	review := jwt.MapClaims{"scope": "iga:read iga:review"}
	readOnly := jwt.MapClaims{"scope": "iga:read"}

	if got := caller(human, review); !got.Human || !got.CanReview {
		t.Fatalf("human reviewer = %+v, want both", got)
	}
	if got := caller(human, readOnly); !got.Human || got.CanReview {
		t.Fatalf("human without iga:review = %+v, want human only", got)
	}
	if got := caller(map[string]string{"user_id": f.user.String()}, review); got.Human || !got.CanReview {
		t.Fatalf("reviewer token that is not a member session = %+v, want review only", got)
	}
	if got := caller(human, nil); got.CanReview {
		t.Fatalf("no claims at all = %+v, want no iga:review", got)
	}
	both := caller(human, review)
	if !igaread.CanClassify(both, models.ClassificationUnclassified, models.IGALifecycleActive) ||
		igaread.CanClassify(both, models.ClassificationProviderAgent, models.IGALifecycleActive) ||
		igaread.CanClassify(caller(human, readOnly), models.ClassificationUnclassified, models.IGALifecycleActive) {
		t.Fatal("CanClassify disagrees with its inputs")
	}
}

func classPtr(u uuid.UUID) *uuid.UUID { return &u }

// refUUIDBare parses a bare UUID from a response (decision ids are not typed
// references: a decision is not a graph object).
func classUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("not a UUID: %q", s)
	}
	return id
}
