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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// classFixture is one lab workspace with one projected Lambda workload and one
// verified human ("Priya Shah") whose claims the API carries.
type classFixture struct {
	t        *testing.T
	l        *p2Lab
	acct     *p2Account
	api      *readAPI
	workload uuid.UUID
	user     uuid.UUID
	member   uuid.UUID
}

func classSetup(t *testing.T, name string) *classFixture {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := oneLambda(l)
	l.scanAndProject(a)
	var wl []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name = 'refund-processor'`, l.ws).Scan(&wl)
	if len(wl) != 1 {
		t.Fatalf("the lab projected %d refund-processor workloads, want 1", len(wl))
	}
	f := &classFixture{t: t, l: l, acct: a, api: l.api(), workload: wl[0]}
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

// insertWorkload adds a workload row directly, with one support row from the
// lab's connector so the graph routes can read it (D-6). Used where the
// projector cannot produce the shape needed without a Bedrock fake
// (provider-native) or where a second workload is only a lock target; the
// classification service reads nothing but the iga_workload row and whether
// something supports it.
func (f *classFixture) insertWorkload(name, runtimeKind, classification string) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	if err := f.l.db.Exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
		VALUES (?, ?, ?, ?, 'us-east-1', ?, ?)`,
		id, f.l.ws, runtimeKind, name, "aws\x1fclass-test\x1f"+id.String(), classification).Error; err != nil {
		f.t.Fatalf("insert workload: %v", err)
	}
	if err := f.l.db.Exec(`INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
		VALUES (?, ?, ?, 'class-test')`, f.l.ws, id, f.acct.conn).Error; err != nil {
		f.t.Fatalf("insert support: %v", err)
	}
	return id
}

// classPublish gives a workspace with no graph one publication (rev 1): the
// connector and scan run its foreign keys need, and the publication row --
// nothing else. It is how a test tells a scoping 404 from D-4's
// nothing-published 404. Removed before the lab's cleanup clears the runs.
func classPublish(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	conn := connectorFor(t, db, ws)
	run := uuid.New()
	if err := db.Exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id) VALUES (?, ?, ?)`, run, ws, conn).Error; err != nil {
		t.Fatalf("seed scan run: %v", err)
	}
	if err := db.Exec(`INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		VALUES (?, 1, now(), ?, '{}')`, ws, run).Error; err != nil {
		t.Fatalf("seed publication: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM iga_publication WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM cloud_scan_run WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
	})
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

// B22 as a free-running race: identical retries of one operation, released at
// once. Nothing orchestrates their order; each decision only dawdles 50 ms
// before its commit -- the window a slow commit or a busy database opens --
// so the retries genuinely overlap instead of running one after another. The
// row lock serializes them and the lookup after it turns every one but the
// first into a replay: all 200, exactly one replayed:false, one decision id,
// one row, one clock tick. The deterministic proof of the order is
// TestP2ClassConcurrentRetriesReplay; this one shows that whatever
// interleaving the scheduler picks, no retry is shown a 409, a 422 or a
// duplicate decision.
func TestP2ClassRetryStormReplays(t *testing.T) {
	f := classSetup(t, "p2-class-storm")
	f.api.ctl.WithClassificationService(services.NewClassificationService(f.l.db).WithBeforeCommit(func() {
		time.Sleep(50 * time.Millisecond)
	}))
	const retries = 8
	body := classBody(uuid.New(), models.ClassificationClassified, "Owns tier-1 ticket routing", 0, nil)
	start := make(chan struct{})
	results := make(chan classResp, retries)
	var wg sync.WaitGroup
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- classPost(f.api, f.path(f.workload), body)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	fresh, ids := 0, map[string]bool{}
	for r := range results {
		if r.err != nil || r.status != http.StatusOK {
			t.Fatalf("a retry in the storm = %d %v, want 200", r.status, r.body)
		}
		if dig(r.body, "data", "replayed") == false {
			fresh++
		}
		ids[digs(r.body, "data", "decision", "id")] = true
	}
	if fresh != 1 || len(ids) != 1 {
		t.Fatalf("%d retries: %d answered replayed:false over %d decision ids, want exactly 1 and 1", retries, fresh, len(ids))
	}
	classWant(t, "after the storm", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 1})
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
	other := f.insertWorkload("cs-handler-b", "lambda_function", models.ClassificationUnclassified)
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
	other := f.insertWorkload("cs-handler-b", "lambda_function", models.ClassificationUnclassified)
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
	agent := f.insertWorkload("support-agent", "bedrock_agent", models.ClassificationProviderAgent)
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
	other := f.insertWorkload("cs-handler-b", "lambda_function", models.ClassificationUnclassified)
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

// Validation (D-30): a missing or malformed field, a blank reason, an unknown
// decision and over-long free text are 400 invalid_parameter naming the
// field, before anything is locked -- and none of it writes.
//
// Safeguards: each check in normalized() and parseClassifyBody. The length
// bounds count characters, not bytes: 2000 two-byte characters are a valid
// reason.
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
		{"null operation_id", func(b map[string]any) { b["operation_id"] = nil }, "operation_id"},
		{"operation_id not a UUID", func(b map[string]any) { b["operation_id"] = "op-1" }, "operation_id"},
		{"no decision", func(b map[string]any) { delete(b, "decision") }, "decision"},
		{"unknown decision", func(b map[string]any) { b["decision"] = "provider_native_agent" }, "decision"},
		{"no reason", func(b map[string]any) { delete(b, "reason") }, "reason"},
		{"blank reason", func(b map[string]any) { b["reason"] = "   " }, "reason"},
		{"reason over 2000 characters", func(b map[string]any) { b["reason"] = strings.Repeat("é", 2001) }, "reason"},
		{"purpose over 500 characters", func(b map[string]any) { b["purpose"] = strings.Repeat("é", 501) }, "purpose"},
		// PostgreSQL text refuses U+0000: sent through, the INSERT fails and
		// the client's malformed text is a 500. Trailing, it is not trimmed.
		{"NUL in reason", func(b map[string]any) { b["reason"] = "handles\u0000tickets" }, "reason"},
		{"NUL in purpose", func(b map[string]any) { b["purpose"] = "triage\u0000" }, "purpose"},
		{"no expected_version", func(b map[string]any) { delete(b, "expected_version") }, "expected_version"},
		{"negative expected_version", func(b map[string]any) { b["expected_version"] = -1 }, "expected_version"},
		{"expected_version not a number", func(b map[string]any) { b["expected_version"] = "0" }, "expected_version"},
		{"expected_version not an integer", func(b map[string]any) { b["expected_version"] = 1.5 }, "expected_version"},
		{"decision not a string", func(b map[string]any) { b["decision"] = 1 }, "decision"},
		{"undoes_decision_id not a UUID", func(b map[string]any) { b["undoes_decision_id"] = "x" }, "undoes_decision_id"},
		// Keys the contract does not define are refused, never ignored: an
		// ignored key is one the request hash does not bind.
		{"an unknown field", func(b map[string]any) { b["workload_id"] = uuid.NewString() }, "workload_id"},
		{"two unknown fields name the first", func(b map[string]any) { b["zeta"], b["alpha"] = 1, 1 }, "alpha"},
		// encoding/json alone matches keys case-insensitively: this would set
		// the version under a spelling the contract does not have.
		{"a field in another case", func(b map[string]any) {
			delete(b, "expected_version")
			b["Expected_Version"] = 0
		}, "Expected_Version"},
	} {
		b := good()
		tc.edit(b)
		st, out := f.post(f.workload, b)
		if st != http.StatusBadRequest || errCode(out) != "invalid_parameter" || digs(out, "error", "parameter") != tc.param {
			t.Errorf("%s = %d %v, want 400 invalid_parameter on %s", tc.name, st, out, tc.param)
		}
	}
	// A body past the size bound is refused even when it would otherwise be a
	// valid decision: here the padding is whitespace inside the object.
	oversized, _ := json.Marshal(good())
	oversized = append(oversized[:1], append(bytes.Repeat([]byte(" "), 70<<10), oversized[1:]...)...)
	for _, raw := range []string{`[]`, `{"operation_id": "`, `{} {}`, `null`, `"x"`, ``, string(oversized)} {
		req := httptest.NewRequest(http.MethodPost, "/api/iga/v1"+f.path(f.workload), strings.NewReader(raw))
		w := httptest.NewRecorder()
		f.api.eng.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusBadRequest || errCode(out) != "invalid_parameter" || digs(out, "error", "parameter") != "body" {
			t.Errorf("body %.40q = %d %v, want 400 invalid_parameter on body", raw, w.Code, out)
		}
	}
	classWant(t, "after every 400", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})

	// At the bounds, in characters: accepted, and stored trimmed.
	b := good()
	b["reason"], b["purpose"] = " "+strings.Repeat("é", 2000)+" ", strings.Repeat("é", 500)
	out := f.classify(f.workload, b)
	if got := digs(out, "data", "decision", "reason"); got != strings.Repeat("é", 2000) {
		t.Fatalf("a 2000-character reason came back as %d characters", len([]rune(got)))
	}
	// Only NUL is refused: other control characters are ordinary text, and a
	// multi-line reason is stored as sent (here as the deliberate replacement
	// at version 1).
	b = good()
	b["expected_version"], b["reason"] = 1, "line one\n\tline two"
	out = f.classify(f.workload, b)
	if got := digs(out, "data", "decision", "reason"); got != "line one\n\tline two" {
		t.Fatalf("a multi-line reason came back as %q", got)
	}
}

// The deliberate replacement (§2.14.3, D-30): classified_agent on a workload
// that is already classified_agent, at the expected version, is a NEW
// decision -- previous = classified_agent, version and clock bumped -- never
// refused as "already an agent". It is how "Replace with mine" after a 409
// records the second person's purpose and reason (§2.14.6).
//
// Safeguard: the decision rules do not refuse classified -> classified.
func TestP2ClassReplacementIsANewDecision(t *testing.T) {
	f := classSetup(t, "p2-class-replace")
	first := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "owns refunds", 0, nil))

	alex := "Alex Kim"
	u2, m2 := classMember(t, f.l.db, f.l.ws, &alex, "alex@test.local", "active")
	f.api.withClaims(classClaims(u2, m2))
	// Purpose is optional: this one gives none.
	body := classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 1, nil)
	delete(body, "purpose")
	out := f.classify(f.workload, body)
	// No purpose given is null -- never "", which would read as a purpose that
	// was recorded as empty -- in the POST outcome and in the history alike.
	if p, present := dig(out, "data", "decision").(map[string]any)["purpose"]; !present || p != nil {
		t.Fatalf("decision.purpose with none given = %v (present %v), want null", p, present)
	}
	st, hist := f.api.get(f.path(f.workload))
	mustStatus(t, "history", st, hist, http.StatusOK)
	if items := digl(hist, "data"); len(items) != 2 || dig(items[0], "purpose") != nil ||
		digs(items[1], "purpose") != "Customer support triage" {
		t.Fatalf("history purposes = %v, want [null, the first decision's]", hist)
	}
	if digs(out, "data", "classification") != models.ClassificationClassified || num(out, "data", "classification_version") != 2 ||
		digs(out, "data", "decision", "decided_by", "display") != "Alex Kim" ||
		digs(out, "data", "decision", "id") == digs(first, "data", "decision", "id") {
		t.Fatalf("replacement = %v, want a new classified_agent decision @2 by Alex Kim", out)
	}
	var row models.IGAWorkloadClassification
	f.l.db.Raw(`SELECT * FROM iga_workload_classification WHERE id = ?`, classUUID(t, digs(out, "data", "decision", "id"))).Scan(&row)
	if row.Previous != models.ClassificationClassified || row.AgainstVersion != 1 || row.ResultVersion != 2 ||
		row.UndoesDecisionID != nil || row.DecidedByUserID != u2 {
		t.Fatalf("replacement row = %+v, want previous classified_agent, 1 -> 2, no undo, by Alex", row)
	}
	classWant(t, "after the replacement", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 2, Decisions: 2, Seq: 2})
}

// D-30's order. After the lock and the operation lookup: provider-native
// (422), then the version (409 with the current decision), and ONLY THEN the
// decision rules (422 invalid_decision): unclassified on a workload that is
// not classified_agent, an undo that does not name this workload's latest
// decision (naming none included), a classify that names a decision to undo,
// and a retired workload. None of them writes.
//
// Safeguards: each rule, and the rules' position after the version check -- a
// stale client is told what changed, not that its request makes no sense
// against a state it never saw.
func TestP2ClassDecisionRulesComeAfterTheVersion(t *testing.T) {
	f := classSetup(t, "p2-class-rules")
	someID := uuid.New()

	// Unclassified on an unclassified workload: 422 at the right version, 409
	// at a wrong one.
	st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 0, &someID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("unclassified on an unclassified workload = %d %v, want 422 invalid_decision", st, out)
	}
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 3, &someID))
	if st != http.StatusConflict || errCode(out) != "classification_conflict" {
		t.Fatalf("the same at a stale version = %d %v, want 409 (the version before the rules)", st, out)
	}
	// A classify naming a decision to undo.
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "classify", 0, &someID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("classified_agent naming a decision to undo = %d %v, want 422 invalid_decision", st, out)
	}
	classWant(t, "after the refused requests", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})

	first := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	firstID := classUUID(t, digs(first, "data", "decision", "id"))
	// An undo naming no decision, or one that is not the latest.
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("an undo naming no decision = %d %v, want 422 invalid_decision", st, out)
	}
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, &someID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("an undo naming an unknown decision = %d %v, want 422 invalid_decision", st, out)
	}
	classWant(t, "after the refused undos", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 1})
	// The workload's own column is the authority for "not classified_agent",
	// not its decision history: with the column unclassified (drift the
	// projector must never cause), even an undo naming the latest
	// classified_agent decision is refused.
	f.l.db.Exec(`UPDATE iga_workload SET classification = 'unclassified' WHERE id = ?`, f.workload)
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, &firstID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("an undo on a workload whose column says unclassified = %d %v, want 422 invalid_decision", st, out)
	}
	f.l.db.Exec(`UPDATE iga_workload SET classification = 'classified_agent' WHERE id = ?`, f.workload)

	// Provider-native comes BEFORE the version: 422 whatever version is sent.
	agent := f.insertWorkload("support-agent", "bedrock_agent", models.ClassificationProviderAgent)
	st, out = f.post(agent, classBody(uuid.New(), models.ClassificationClassified, "it is an agent", 7, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "provider_native" {
		t.Fatalf("a provider-native agent at a wrong version = %d %v, want 422 provider_native", st, out)
	}

	// A retired workload: 409 at a wrong version, 422 at the right one. A
	// retry of an operation that landed before it retired still replays: the
	// lookup comes before every rule.
	old := f.insertWorkload("old-handler", "lambda_function", models.ClassificationUnclassified)
	landed := classBody(uuid.New(), models.ClassificationClassified, "handles refunds", 0, nil)
	oldID := classUUID(t, digs(f.classify(old, landed), "data", "decision", "id"))
	if err := f.l.db.Exec(`UPDATE iga_workload SET lifecycle = 'retired', retired_reason = 'not_seen' WHERE id = ?`, old).Error; err != nil {
		t.Fatalf("retire: %v", err)
	}
	st, out = f.post(old, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 0, &oldID))
	if st != http.StatusConflict || errCode(out) != "classification_conflict" {
		t.Fatalf("a retired workload at a stale version = %d %v, want 409", st, out)
	}
	st, out = f.post(old, classBody(uuid.New(), models.ClassificationUnclassified, "undo", 1, &oldID))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("an undo on a retired workload = %d %v, want 422 invalid_decision", st, out)
	}
	st, out = f.post(old, classBody(uuid.New(), models.ClassificationClassified, "replace", 1, nil))
	if st != http.StatusUnprocessableEntity || errCode(out) != "invalid_decision" {
		t.Fatalf("a classify on a retired workload = %d %v, want 422 invalid_decision", st, out)
	}
	st, out = f.post(old, landed)
	if st != http.StatusOK || dig(out, "data", "replayed") != true {
		t.Fatalf("a retry after the workload retired = %d %v, want 200 replayed", st, out)
	}
	classWant(t, "the retired workload", f.state(old),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 2})
	// Its history is still served: a detail route returns retired objects.
	st, out = f.api.get(f.path(old))
	if st != http.StatusOK || len(digl(out, "data")) != 1 {
		t.Fatalf("history of a retired workload = %d %v, want 200 and its one decision", st, out)
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

// The actor rule's failures are refusals (403); a DATABASE failure while
// checking the membership is not a refusal -- it is 500 internal, so an outage
// is never reported to a person as "you may not" -- and can_classify is then
// an error, never a guessed true or false.
//
// Safeguard: verifiedHuman and classifyCaller map only errNotWorkspaceHuman to
// 403 / false. Here the controller's database is a closed pool.
func TestP2ClassMembershipCheckFailureIs500(t *testing.T) {
	f := classSetup(t, "p2-class-db-error")
	bad, err := gorm.Open(postgres.Open(os.Getenv("IGA_TEST_DSN")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sqlDB, _ := bad.DB()
	sqlDB.Close()
	lab := *f.l
	lab.db = bad
	api := lab.api()
	api.withClaims(classClaims(f.user, f.member))
	st, out := api.do(http.MethodPost, f.path(f.workload), classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
	if st != http.StatusInternalServerError || errCode(out) != "internal" {
		t.Fatalf("a decision whose membership check cannot run = %d %v, want 500 internal", st, out)
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range classClaims(f.user, f.member) {
		c.Set(k, v)
	}
	c.Set("claims", jwt.MapClaims{"scope": "iga:review"})
	if _, err := api.ctl.ClassificationCapabilityForTest(c, f.l.ws, models.ClassificationUnclassified, models.IGALifecycleActive); err == nil {
		t.Fatal("can_classify with the membership check failing = no error, want the request's 500")
	}
	classWant(t, "after the failed check", f.state(f.workload),
		classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})
}

// E14: a workload id from another workspace is 404 on both routes -- for a
// caller who IS a verified member of their own workspace, so the 404 is the
// workspace scoping, not the actor rule -- and nothing is written anywhere.
func TestP2ClassCrossWorkspaceIs404(t *testing.T) {
	f := classSetup(t, "p2-class-cross")
	otherWS := newWorkspace(t, f.l.db, "p2-class-cross-other")
	// The other workspace HAS a publication: otherwise the history's 404 would
	// be D-4's "nothing published", and would prove nothing about scoping.
	classPublish(t, f.l.db, otherWS)
	if err := igaread.NewReader(f.l.db, readTestCursorKey).Read(context.Background(), otherWS, igaread.Pin{},
		func(q *igaread.Query) error {
			if !q.Published() {
				t.Fatal("the other workspace is not published")
			}
			return nil
		}); err != nil {
		t.Fatalf("read the other workspace: %v", err)
	}
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

// classForeignWorkload gives workspace ws (not the lab's) one workload the
// classification routes can read (D-6: an AWS row with a support row from a
// connector of ws), and removes what a test decided about it when it ends.
func classForeignWorkload(t *testing.T, db *gorm.DB, ws uuid.UUID, name string) uuid.UUID {
	t.Helper()
	conn := connectorFor(t, db, ws)
	id := uuid.New()
	if err := db.Exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key)
		VALUES (?, ?, 'lambda', ?, 'us-east-1', ?)`, id, ws, name, "aws\x1fclass-test\x1f"+id.String()).Error; err != nil {
		t.Fatalf("insert workload: %v", err)
	}
	if err := db.Exec(`INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
		VALUES (?, ?, ?, 'class-test')`, ws, id, conn).Error; err != nil {
		t.Fatalf("insert support: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM iga_workload_classification WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM iga_classification_clock WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM iga_object_support WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM iga_workload WHERE workspace_id = ?`, ws)
		db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
	})
	return id
}

// E14 / §5.5 step 2: an operation id names one intent IN ONE WORKSPACE --
// iga_wc_operation_key is UNIQUE (workspace_id, operation_id). The same id
// arriving in another workspace, from that workspace's own member about that
// workspace's own workload, is a fresh decision there: never a replay of, nor
// 422 operation_id_reused against, a decision its caller cannot see.
//
// Safeguard: the step-2 operation lookup is scoped to the workspace. Unscoped,
// workspace B's request finds workspace A's row, whose hash differs (another
// workload, another actor), and is refused as operation_id_reused -- one
// workspace's traffic failing another's, and an answer that tells B the id
// exists somewhere.
func TestP2ClassOperationIdIsPerWorkspace(t *testing.T) {
	f := classSetup(t, "p2-class-op-per-ws")
	op := uuid.New()
	body := classBody(op, models.ClassificationClassified, "handles tier-1 tickets", 0, nil)
	inA := f.classify(f.workload, body)

	otherWS := newWorkspace(t, f.l.db, "p2-class-op-per-ws-other")
	wB := classForeignWorkload(t, f.l.db, otherWS, "refund-processor")
	ou, om := classMember(t, f.l.db, otherWS, nil, "other@test.local", "active")
	f.api.asWorkspace(otherWS).withClaims(classClaims(ou, om))

	// The SAME operation id and the same words, in workspace B.
	st, inB := f.post(wB, body)
	mustStatus(t, "the same operation id in another workspace", st, inB, http.StatusOK)
	if dig(inB, "data", "replayed") != false || digs(inB, "data", "decision", "operation_id") != op.String() ||
		digs(inB, "data", "classification") != models.ClassificationClassified || num(inB, "data", "classification_version") != 1 {
		t.Fatalf("the same operation id in another workspace = %v, want a fresh decision (replayed false, version 1)", inB)
	}
	if digs(inB, "data", "decision", "id") == digs(inA, "data", "decision", "id") {
		t.Fatal("workspace B's decision is workspace A's row")
	}
	// A retry in B replays B's own decision -- the lookup does find what B wrote.
	if again := f.classify(wB, body); dig(again, "data", "replayed") != true ||
		digs(again, "data", "decision", "id") != digs(inB, "data", "decision", "id") {
		t.Fatalf("a retry in workspace B = %v, want the replay of B's decision", again)
	}

	// One decision row and one clock movement in EACH workspace.
	for _, ws := range []uuid.UUID{f.l.ws, otherWS} {
		if n := f.l.count(`SELECT count(*) FROM iga_workload_classification WHERE workspace_id = ? AND operation_id = ?`, ws, op); n != 1 {
			t.Errorf("workspace %s holds %d decisions for the operation, want 1", ws, n)
		}
		if n := f.l.count(`SELECT COALESCE(max(seq), 0) FROM iga_classification_clock WHERE workspace_id = ?`, ws); n != 1 {
			t.Errorf("workspace %s clock = %d, want 1", ws, n)
		}
	}
	classWant(t, "workspace A after B's decision", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 1})
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
	id := classUUID(t, digs(out, "data", "decision", "id"))
	f.classify(f.workload, body)
	if st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "stale", 0, nil)); st != http.StatusConflict {
		t.Fatalf("stale decision = %d %v, want 409", st, out)
	}
	if st, out := f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "undoing?", 1, &id)); st != http.StatusUnprocessableEntity {
		t.Fatalf("a classify naming a decision to undo = %d %v, want 422", st, out)
	}
	if s := seqNow(); s != 1 {
		t.Fatalf("seq after a replay, a 409 and a 422 = %d, want still 1", s)
	}
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

// D-31, the other half: the bound lives and dies with the decision's
// transaction. The service runs on the process's shared pool (config.DB),
// whose connections also serve the projector and every other API; a bound
// left on a pooled connection after a decision committed would make any later
// transaction there that legitimately waits longer on a lock fail with 55P03.
//
// Safeguard: SET LOCAL, not a session-level SET. The service runs here over a
// pool of ONE connection, so the connection each decision used is the one
// SHOW reads afterwards; the bound is a value no server default would have.
func TestP2ClassLockTimeoutIsTransactionScoped(t *testing.T) {
	f := classSetup(t, "p2-class-lock-scope")
	one, err := gorm.Open(postgres.Open(os.Getenv("IGA_TEST_DSN")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sqlDB, err := one.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	show := func(when string) string {
		t.Helper()
		var v string
		if err := sqlDB.QueryRow(`SHOW lock_timeout`).Scan(&v); err != nil {
			t.Fatalf("SHOW lock_timeout %s: %v", when, err)
		}
		return v
	}
	var pid, pidAfter int64
	if err := sqlDB.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatalf("backend pid: %v", err)
	}
	before := show("before any decision")
	if before == "1234ms" {
		t.Fatalf("the server default lock_timeout is already the test's bound (%s)", before)
	}
	f.api.ctl.WithClassificationService(services.NewClassificationService(one).WithLockTimeout(1234 * time.Millisecond))

	body := classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil)
	f.classify(f.workload, body) // a committed decision
	if got := show("after a decision"); got != before {
		t.Fatalf("lock_timeout on the pooled connection after a decision = %s, want the session's %s", got, before)
	}
	f.classify(f.workload, body) // a replay commits too
	if got := show("after a replay"); got != before {
		t.Fatalf("lock_timeout on the pooled connection after a replay = %s, want the session's %s", got, before)
	}
	// The same backend throughout: SHOW read the connection the decisions ran on.
	if err := sqlDB.QueryRow(`SELECT pg_backend_pid()`).Scan(&pidAfter); err != nil || pidAfter != pid {
		t.Fatalf("backend pid %d -> %d (%v): the decisions ran on another connection", pid, pidAfter, err)
	}
	classWant(t, "after the decision and its replay", f.state(f.workload),
		classState{Classification: models.ClassificationClassified, Version: 1, Decisions: 1, Seq: 1})
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

// D-11 / §2.14.14 "Unavailable features": /capabilities reports
// features.classification true exactly when its routes are implemented -- in
// this build, both /workloads/:id/classification routes are -- AND
// graph_projection is on. Off or misconfigured, every graph route is 503, so
// the console must not offer Classify.
//
// Safeguards: the flag is on (not the M0 constant false, which hides a live
// feature), and only when the gate is on (not a constant true).
func TestP2ClassCapabilitiesFeature(t *testing.T) {
	for _, tc := range []struct {
		name       string
		projection bool
		verify     bool
		mode       string
		want       bool
	}{
		{"on", true, true, services.GraphProjectionOn, true},
		{"off", false, false, services.GraphProjectionOff, false},
		// Switched on, schema never verified: the fail-closed state (§2.8).
		{"misconfigured", true, false, services.GraphProjectionMisconfigured, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newP2Lab(t, "p2-class-caps-"+tc.name, false)
			l.gate = services.NewGraphProjectionGate(tc.projection, "")
			if tc.verify {
				if err := l.gate.Verify(l.db); err != nil {
					t.Fatalf("verify: %v", err)
				}
			}
			st, out := l.api().get("/capabilities")
			mustStatus(t, "GET /capabilities", st, out, http.StatusOK)
			if got := digs(out, "data", "graph_projection"); got != tc.mode {
				t.Fatalf("graph_projection = %q, want %q (%v)", got, tc.mode, out)
			}
			feats, _ := dig(out, "data", "features").(map[string]any)
			if len(feats) != 8 {
				t.Fatalf("features = %v, want the eight §5.3 keys", feats)
			}
			if got, ok := feats["classification"].(bool); !ok || got != tc.want {
				t.Fatalf("features.classification = %v, want %v", feats["classification"], tc.want)
			}
		})
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

	// "Latest" is by result_version, never decided_at: decided_at is the
	// transaction's START, so two decisions serialized on the lock can carry
	// start times in either order. Give the older decision the later start
	// time; the latest, the history order and an undo check are unchanged.
	if err := f.l.db.Exec(`UPDATE iga_workload_classification SET decided_at = now() + interval '1 hour' WHERE id = ?`, id).Error; err != nil {
		t.Fatalf("move decided_at: %v", err)
	}
	if d := latest(); d == nil || d.OperationID != undoOp {
		t.Fatalf("latest after decided_at moved = %+v, want still the undo (result_version 2)", d)
	}
	st, hist := f.api.get(f.path(f.workload))
	mustStatus(t, "history", st, hist, http.StatusOK)
	if items := digl(hist, "data"); len(items) != 2 || num(items[0], "result_version") != 2 {
		t.Fatalf("history after decided_at moved = %v, want the undo first", hist)
	}
	// The 409's current decision is the latest one too.
	st, out = f.post(f.workload, classBody(uuid.New(), models.ClassificationClassified, "stale", 0, nil))
	if st != http.StatusConflict || digs(out, "error", "current", "reason") != "undo" {
		t.Fatalf("409 current after decided_at moved = %d %v, want the undo's reason", st, out)
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
	other := f.insertWorkload("cs-handler-b", "lambda_function", models.ClassificationUnclassified)
	st, bad := f.api.get(f.path(other) + qs("cursor", next))
	if st != http.StatusBadRequest || errCode(bad) != "cursor_invalid" {
		t.Fatalf("another workload's history cursor = %d %v, want 400 cursor_invalid", st, bad)
	}
	if st, bad := f.api.get(f.path(f.workload) + qs("limit", "0")); st != http.StatusBadRequest {
		t.Fatalf("limit=0 = %d %v, want 400", st, bad)
	}
}

// D-33: the history runs under §5.1 like every route. meta carries the
// revision; rev pins it; a cursor carries the revision it was issued at, and
// after a new publication both are 409 revision_stale -- although no decision
// is part of a revision. An unknown parameter is 400 naming it (D-75).
//
// Safeguards: the Pin (rev and the cursor's rev) passed to Read, and the
// parameter allowlist.
func TestP2ClassHistoryIsRevisionBound(t *testing.T) {
	f := classSetup(t, "p2-class-history-rev")
	out := f.classify(f.workload, classBody(uuid.New(), models.ClassificationClassified, "one", 0, nil))
	id := classUUID(t, digs(out, "data", "decision", "id"))
	f.classify(f.workload, classBody(uuid.New(), models.ClassificationUnclassified, "two", 1, &id))

	st, p1 := f.api.get(f.path(f.workload) + qs("limit", "1"))
	mustStatus(t, "page 1", st, p1, http.StatusOK)
	rev := num(p1, "meta", "rev")
	next := digs(p1, "meta", "next_cursor")
	if rev < 1 || digs(p1, "meta", "graph_state") != igaread.GraphPublished || next == "" {
		t.Fatalf("page 1 meta = %v, want the current rev, published, and a cursor", dig(p1, "meta"))
	}
	if st, out := f.api.get(f.path(f.workload) + qs("rev", strconv.FormatInt(rev, 10))); st != http.StatusOK {
		t.Fatalf("rev=%d (current) = %d %v, want 200", rev, st, out)
	}
	if st, out := f.api.get(f.path(f.workload) + qs("rev", strconv.FormatInt(rev+1, 10))); st != http.StatusConflict ||
		errCode(out) != "revision_stale" {
		t.Fatalf("rev=%d (not current) = %d %v, want 409 revision_stale", rev+1, st, out)
	}
	for param, v := range map[string]string{"decision": "classified_agent", "sort": "decided_at", "rev": "abc"} {
		st, out := f.api.get(f.path(f.workload) + qs(param, v))
		if st != http.StatusBadRequest || errCode(out) != "invalid_parameter" || digs(out, "error", "parameter") != param {
			t.Errorf("%s=%s = %d %v, want 400 invalid_parameter on %s", param, v, st, out, param)
		}
	}

	// A new publication: the role gains a policy and the account is scanned
	// and projected again.
	f.acct.attach("refund-lambda-role", f.acct.managed("TicketReadAgain", docTicketRead))
	f.l.scanAndProject(f.acct)
	var cur int64
	f.l.db.Raw(`SELECT max(rev) FROM iga_publication WHERE workspace_id = ?`, f.l.ws).Scan(&cur)
	if cur <= rev {
		t.Fatalf("the rescan did not publish: rev %d -> %d", rev, cur)
	}
	st, stale := f.api.get(f.path(f.workload) + qs("limit", "1", "cursor", next))
	if st != http.StatusConflict || errCode(stale) != "revision_stale" || num(stale, "error", "requested_rev") != rev {
		t.Fatalf("a cursor from rev %d after rev %d published = %d %v, want 409 revision_stale", rev, cur, st, stale)
	}
	if st, out := f.api.get(f.path(f.workload) + qs("rev", strconv.FormatInt(rev, 10))); st != http.StatusConflict {
		t.Fatalf("rev=%d after rev %d published = %d %v, want 409", rev, cur, st, out)
	}
	// Restarting from page one works, at the new revision.
	st, again := f.api.get(f.path(f.workload) + qs("limit", "1"))
	if st != http.StatusOK || num(again, "meta", "rev") != cur || len(digl(again, "data")) != 1 {
		t.Fatalf("page 1 after the publication = %d %v, want 200 at rev %d", st, again, cur)
	}
}

// D-6: only a workload the graph routes can read -- an AWS row with a support
// row -- may be decided about or have its history read. An AWS row nothing
// supports, or a row of another provider, is 404 on both routes, with no hint
// and nothing written.
//
// Safeguards: the support-row and provider conditions in the locking SELECT
// and in ClassificationWorkloadReadable.
func TestP2ClassUnreadableWorkloadIs404(t *testing.T) {
	f := classSetup(t, "p2-class-unreadable")
	unsupported := f.insertWorkload("orphan", "lambda_function", models.ClassificationUnclassified)
	f.l.db.Exec(`DELETE FROM iga_object_support WHERE workload_id = ?`, unsupported)
	github := f.insertWorkload("gh-runner", "lambda_function", models.ClassificationUnclassified)
	f.l.db.Exec(`UPDATE iga_workload SET provider = 'github' WHERE id = ?`, github)

	for name, w := range map[string]uuid.UUID{"an unsupported AWS row": unsupported, "a GitHub row": github} {
		st, out := f.post(w, classBody(uuid.New(), models.ClassificationClassified, "handles tier-1 tickets", 0, nil))
		if st != http.StatusNotFound || errCode(out) != "not_found" {
			t.Errorf("POST on %s = %d %v, want 404", name, st, out)
		}
		st, out = f.api.get(f.path(w))
		if st != http.StatusNotFound || errCode(out) != "not_found" {
			t.Errorf("GET history of %s = %d %v, want 404", name, st, out)
		}
		classWant(t, name, f.state(w),
			classState{Classification: models.ClassificationUnclassified, Version: 0, Decisions: 0, Seq: 0})
	}
}

// D-4: with nothing published there is no workload to read. Here a supported
// AWS row stands in for one -- the projector never leaves a workload without
// a publication -- and its history is still 404, never a list at no revision.
//
// Safeguard: the published check in GetWorkloadClassification.
func TestP2ClassHistoryNothingPublishedIs404(t *testing.T) {
	l := newP2Lab(t, "p2-class-unpublished", true)
	f := &classFixture{t: t, l: l, acct: l.account(accountA), api: l.api()}
	w := f.insertWorkload("early", "lambda_function", models.ClassificationUnclassified)
	if st, out := f.api.get(f.path(w)); st != http.StatusNotFound || errCode(out) != "not_found" {
		t.Fatalf("history with nothing published = %d %v, want 404 (D-4)", st, out)
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

	// The value the workload detail states (D-83), end to end over the
	// controller: true only for a verified human with iga:review on an active,
	// non-provider-native workload.
	capability := func(claims map[string]string, jwtClaims jwt.MapClaims, classification, lifecycle string) bool {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range claims {
			c.Set(k, v)
		}
		c.Set("claims", jwtClaims)
		got, err := f.api.ctl.ClassificationCapabilityForTest(c, f.l.ws, classification, lifecycle)
		if err != nil {
			t.Fatalf("classificationCapability: %v", err)
		}
		return got
	}
	suspended := "Sam Suspended"
	su, sm := classMember(t, f.l.db, f.l.ws, &suspended, "sam@test.local", "suspended")
	for _, tc := range []struct {
		name           string
		claims         map[string]string
		jwt            jwt.MapClaims
		classification string
		lifecycle      string
		want           bool
	}{
		{"reviewer, unclassified", human, review, models.ClassificationUnclassified, models.IGALifecycleActive, true},
		{"reviewer, classified (undo, replace)", human, review, models.ClassificationClassified, models.IGALifecycleActive, true},
		{"reviewer, provider-native", human, review, models.ClassificationProviderAgent, models.IGALifecycleActive, false},
		{"reviewer, retired", human, review, models.ClassificationUnclassified, models.IGALifecycleRetired, false},
		{"member without iga:review", human, readOnly, models.ClassificationUnclassified, models.IGALifecycleActive, false},
		{"suspended member with iga:review", classClaims(su, sm), review, models.ClassificationUnclassified, models.IGALifecycleActive, false},
		{"machine token with iga:review", map[string]string{"client_id": "ci-bot"}, review, models.ClassificationUnclassified, models.IGALifecycleActive, false},
	} {
		if got := capability(tc.claims, tc.jwt, tc.classification, tc.lifecycle); got != tc.want {
			t.Errorf("%s: can_classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func classPtr(u uuid.UUID) *uuid.UUID { return &u }

// classUUID parses a bare UUID from a response (decision ids are not typed
// references: a decision is not a graph object).
func classUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("not a UUID: %q", s)
	}
	return id
}
