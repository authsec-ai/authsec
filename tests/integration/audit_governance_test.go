package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/auditchain"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
)

// Audit governance (SPEC-secops-backend-upgrade.md F7 / P18, AS-177):
// the hash chain and its verification (tamper, unrecorded deletes, purge
// gaps), retention per workspace and record class with legal holds,
// second-person retention shortening and break-glass, durable writes whose
// failures are recorded, the per-operator audit view and its isolation,
// suspension blocking the next request, and the operator baseline.

// auditEventsCleanup removes the test workspaces' audit_events rows; since
// migration 167 only a retention or workspace purge may delete them.
func auditEventsCleanup(db *gorm.DB, wss ...uuid.UUID) {
	_ = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL authsec.workspace_purge = 'on'`).Error; err != nil {
			return err
		}
		for _, ws := range wss {
			if err := tx.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, ws.String()).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

type agEnv struct {
	t   *testing.T
	db  *gorm.DB
	api *p3OwnersAPI
	log *monitoring.AuditLogger
}

func agSetup(t *testing.T) *agEnv {
	t.Helper()
	db := igaDB(t)
	p3MetricsOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics()
		}
	})
	prev := config.AuditLogger
	lg := monitoring.NewAuditLogger(db)
	config.AuditLogger = lg
	t.Cleanup(func() { config.AuditLogger = prev })
	return &agEnv{t: t, db: db, api: p3NewOwnersAPI(t, db), log: lg}
}

func (e *agEnv) gov(name string) *p3Gov {
	g := p3NewGov(e.t, e.db, name)
	e.t.Cleanup(func() { auditEventsCleanup(e.db, g.ws) })
	return g
}

// grant gives user's role in g the global permission resource:action.
func (e *agEnv) grant(g *p3Gov, user uuid.UUID, perm string) {
	e.t.Helper()
	p3exec(e.t, e.db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT m.role_id, p.id FROM workspace_memberships m, permissions p
		 WHERE m.workspace_id = ? AND m.user_id = ? AND p.workspace_id IS NULL AND p.resource || ':' || p.action = ?
		ON CONFLICT DO NOTHING`, g.ws, user, perm)
}

func (e *agEnv) call(method, path, tok string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	e.api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// event writes one audit event synchronously at ts.
func (e *agEnv) event(ws uuid.UUID, user, action, method, class string, ts time.Time) *monitoring.AuditEvent {
	e.t.Helper()
	nv := `{"z": 1, "a": {"b": [1, 2.50, "x"]}, "s": "é"}`
	ev := &monitoring.AuditEvent{WorkspaceID: ws.String(), UserID: user, Action: action, Method: method, Resource: "thing",
		ResourceID: uuid.NewString(), Path: "/x", StatusCode: 200, RecordClass: class, Timestamp: ts, NewValues: &nv}
	if err := e.log.Write(ev); err != nil {
		e.t.Fatalf("write audit event: %v", err)
	}
	if ev.Seq == nil {
		e.t.Fatal("the chain trigger did not assign a seq")
	}
	return ev
}

func (e *agEnv) verify(ws uuid.UUID, from, to time.Time) *services.AuditVerifyReport {
	e.t.Helper()
	rep, err := services.NewAuditGovService(e.db).Verify(context.Background(), ws, from, to)
	if err != nil {
		e.t.Fatalf("verify: %v", err)
	}
	return rep
}

// superuser runs q bypassing triggers (an attacker with database access).
func (e *agEnv) superuser(q string, args ...any) {
	e.t.Helper()
	err := e.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL session_replication_role = replica`).Error; err != nil {
			return err
		}
		return tx.Exec(q, args...).Error
	})
	if err != nil {
		e.t.Fatalf("superuser: %v", err)
	}
}

func breakKinds(rep *services.AuditVerifyReport) []string {
	var out []string
	for _, b := range rep.Breaks {
		out = append(out, b.Kind)
	}
	return out
}

func TestAuditChainVerifiesAndDetectsTamper(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-chain-a")
	now := time.Now().UTC()
	var evs []*monitoring.AuditEvent
	for i := 0; i < 6; i++ {
		evs = append(evs, e.event(a.ws, a.author.String(), fmt.Sprintf("thing.update_%d", i), "PUT", "", now.Add(time.Duration(i-10)*time.Minute)))
	}
	for i, ev := range evs {
		if *ev.Seq != int64(i+1) {
			t.Fatalf("seq %d = %d", i, *ev.Seq)
		}
	}
	from, to := now.Add(-time.Hour), now.Add(time.Minute)
	rep := e.verify(a.ws, from, to)
	if !rep.OK || rep.RowsChecked != 6 {
		t.Fatalf("intact chain (Go canonical form must equal the database's): %+v", rep)
	}
	// UPDATE is refused (108), DELETE outside the retention job too (167).
	if err := e.db.Exec(`UPDATE audit_events SET action = 'x' WHERE id = ?`, evs[1].ID).Error; err == nil {
		t.Fatal("UPDATE of an audit row must fail")
	}
	if err := e.db.Exec(`DELETE FROM audit_events WHERE id = ?`, evs[1].ID).Error; err == nil {
		t.Fatal("DELETE of an audit row outside the retention job must fail")
	}
	// A superuser rewrites a row: hash_mismatch.
	e.superuser(`UPDATE audit_events SET action = 'thing.delete' WHERE id = ?`, evs[2].ID)
	rep = e.verify(a.ws, from, to)
	if rep.OK || rep.Breaks[0].Kind != auditchain.BreakHash || rep.Breaks[0].Seq != 3 {
		t.Fatalf("tamper not detected: %+v", rep.Breaks)
	}
	// ... and deletes one: missing_rows (no purge recorded it).
	e.superuser(`DELETE FROM audit_events WHERE id = ?`, evs[4].ID)
	rep = e.verify(a.ws, from, to)
	kinds := breakKinds(rep)
	found := false
	for _, k := range kinds {
		if k == auditchain.BreakMissing {
			found = true
		}
	}
	if !found {
		t.Fatalf("unrecorded delete not detected: %v", kinds)
	}
}

func TestAuditPurgePerWorkspaceClassAndHold(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-purge-a")
	b := e.gov("ag-purge-b")
	svc := services.NewAuditGovService(e.db)
	ctx := context.Background()
	now := time.Now().UTC()
	old200 := now.AddDate(0, 0, -200)
	old400 := now.AddDate(0, 0, -400)
	old100 := now.AddDate(0, 0, -100)

	mk := func(g *p3Gov) map[string]*monitoring.AuditEvent {
		return map[string]*monitoring.AuditEvent{
			"admin400":   e.event(g.ws, g.author.String(), "thing.update", "PUT", monitoring.AuditClassAdminChange, old400),
			"default200": e.event(g.ws, g.author.String(), "thing.read", "", monitoring.AuditClassDefault, old200),
			"held200":    e.event(g.ws, g.author.String(), "thing.read", "", monitoring.AuditClassDefault, old200.Add(time.Hour)),
			"auth200":    e.event(g.ws, g.author.String(), "admin_login_failure", "", monitoring.AuditClassAuth, old200.Add(2*time.Hour)),
			"admin100":   e.event(g.ws, g.author.String(), "thing.update", "PUT", monitoring.AuditClassAdminChange, old100),
			"fresh":      e.event(g.ws, g.author.String(), "thing.update", "PUT", monitoring.AuditClassAdminChange, now.Add(-time.Minute)),
		}
	}
	ea, eb := mk(a), mk(b)
	if _, err := svc.PlaceLegalHold(ctx, a.ws, services.AuditActor{UserID: a.author}, old200.Add(30*time.Minute), old200.Add(90*time.Minute), "litigation 42"); err != nil {
		t.Fatal(err)
	}
	res, err := svc.PurgeWorkspace(ctx, a.ws)
	if err != nil {
		t.Fatal(err)
	}
	// admin400 (365 d), default200 and auth200 (90 d) go; held200 (hold),
	// admin100 (365 d) and fresh stay.
	if res.Deleted != 3 {
		t.Fatalf("deleted %d, want 3", res.Deleted)
	}
	exists := func(ev *monitoring.AuditEvent) bool {
		var n int64
		e.db.Raw(`SELECT count(*) FROM audit_events WHERE id = ?`, ev.ID).Scan(&n)
		return n == 1
	}
	for k, want := range map[string]bool{"admin400": false, "default200": false, "auth200": false, "held200": true, "admin100": true, "fresh": true} {
		if exists(ea[k]) != want {
			t.Errorf("workspace A %s exists=%v, want %v", k, !want, want)
		}
	}
	for k, ev := range eb {
		if !exists(ev) {
			t.Errorf("workspace B's %s was purged by A's retention", k)
		}
	}
	// The chain still verifies across the gaps, and the purge is in it.
	rep := e.verify(a.ws, now.AddDate(0, 0, -399), now.Add(time.Hour))
	if !rep.OK || rep.GapsCrossed == 0 {
		t.Fatalf("chain after purge: %+v", rep)
	}
	var anchors, purged int64
	e.db.Raw(`SELECT count(*) FROM audit_chain_anchor WHERE workspace_id = ? AND reason = 'purge'`, a.ws).Scan(&anchors)
	e.db.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'audit.retention_purged'`, a.ws.String()).Scan(&purged)
	if anchors != 1 || purged != 1 {
		t.Fatalf("anchors before purge = %d, purge audit rows = %d", anchors, purged)
	}
	// A second purge finds nothing; the chain still verifies with the
	// purge's own row appended after the gaps.
	if res, err := svc.PurgeWorkspace(ctx, a.ws); err != nil || res.Deleted != 0 {
		t.Fatalf("second purge: %+v %v", res, err)
	}
	if rep := e.verify(a.ws, now.AddDate(0, 0, -399), now.Add(time.Hour)); !rep.OK {
		t.Fatalf("chain after second purge: %+v", rep.Breaks)
	}
	// New writes continue the chain after the purge.
	e.event(a.ws, a.author.String(), "thing.update", "PUT", "", now)
	if rep := e.verify(a.ws, now.AddDate(0, 0, -399), now.Add(time.Hour)); !rep.OK {
		t.Fatalf("chain after a new write: %+v", rep.Breaks)
	}
	// B's chain is untouched and whole.
	if rep := e.verify(b.ws, now.AddDate(0, 0, -401), now.Add(time.Hour)); !rep.OK || rep.RowsChecked != 6 || rep.GapsCrossed != 0 {
		t.Fatalf("workspace B chain: %+v", rep)
	}
}

func TestAuditRetentionShorteningNeedsSecondPerson(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-ret-a")
	e.grant(a, a.author, "governance:approve")
	e.grant(a, a.approver, "governance:approve")
	scope := "governance:read governance:author governance:approve"
	author := e.api.token(a.ws, a.author, a.authorMember, scope)
	approver := e.api.token(a.ws, a.approver, a.membershipOf(a.approver), scope)

	// Lengthening applies at once.
	code, body := e.call(http.MethodPut, "/api/iga/v1/audit/retention", author,
		map[string]any{"record_class": "default", "retain_days": 400, "reason": "keep longer"})
	if code != http.StatusOK {
		t.Fatalf("lengthen: %d %v", code, body)
	}
	// Shortening is a pending change.
	code, body = e.call(http.MethodPut, "/api/iga/v1/audit/retention", author,
		map[string]any{"record_class": "default", "retain_days": 30, "reason": "cost"})
	if code != http.StatusAccepted {
		t.Fatalf("shorten: %d %v", code, body)
	}
	ch := body["data"].(map[string]any)["change"].(map[string]any)
	id := ch["id"].(string)
	// Break-glass is refused while another approver exists.
	code, body = e.call(http.MethodPut, "/api/iga/v1/audit/retention", author,
		map[string]any{"record_class": "auth", "retain_days": 30, "reason": "cost", "break_glass": true})
	if code != http.StatusConflict || p3ErrCode(body) != services.GovCodeSecondPersonAvailable {
		t.Fatalf("break-glass with a second person: %d %v", code, body)
	}
	// The requester cannot approve.
	code, body = e.call(http.MethodPost, "/api/iga/v1/audit/changes/"+id+"/approve", author, nil)
	if code != http.StatusForbidden || p3ErrCode(body) != services.GovCodeSelfApproval {
		t.Fatalf("self approval: %d %v", code, body)
	}
	// The DB-level check refuses it too.
	if err := e.db.Exec(`UPDATE audit_governance_change SET status = 'applied', decided_by = requested_by WHERE id = ?`, id).Error; err == nil {
		t.Fatal("the database must refuse decided_by = requested_by")
	}
	// Still 400 days until the second person approves.
	days := func() float64 {
		_, body := e.call(http.MethodGet, "/api/iga/v1/audit/retention", author, nil)
		for _, r := range body["data"].([]any) {
			m := r.(map[string]any)
			if m["record_class"] == "default" {
				return m["retain_days"].(float64)
			}
		}
		return -1
	}
	if d := days(); d != 400 {
		t.Fatalf("retention before approval = %v", d)
	}
	code, body = e.call(http.MethodPost, "/api/iga/v1/audit/changes/"+id+"/approve", approver, map[string]any{"reason": "ok"})
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	if d := days(); d != 30 {
		t.Fatalf("retention after approval = %v", d)
	}
	// Another workspace cannot see or decide the change.
	other := e.gov("ag-ret-b")
	e.grant(other, other.author, "governance:approve")
	otherTok := e.api.token(other.ws, other.author, other.authorMember, scope)
	if code, _ := e.call(http.MethodPost, "/api/iga/v1/audit/changes/"+id+"/reject", otherTok, nil); code != http.StatusNotFound {
		t.Fatalf("other workspace decided the change: %d", code)
	}

	// Single approver: break-glass applies alone with a review due.
	solo := e.gov("ag-ret-solo")
	e.grant(solo, solo.author, "governance:approve")
	soloTok := e.api.token(solo.ws, solo.author, solo.authorMember, scope)
	code, body = e.call(http.MethodPut, "/api/iga/v1/audit/retention", soloTok,
		map[string]any{"record_class": "default", "retain_days": 30, "reason": "single admin", "break_glass": true})
	if code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, body)
	}
	c := body["data"].(map[string]any)["change"].(map[string]any)
	if c["break_glass"] != true || c["review_due_at"] == nil || c["status"] != "applied" {
		t.Fatalf("break-glass change: %v", c)
	}
	var ev int64
	e.db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, solo.ws, services.GovEventAuditBreakGlass).Scan(&ev)
	if ev != 1 {
		t.Fatalf("break-glass event count = %d", ev)
	}
}

func TestAuditWriteFailureIsRecordedNotSilent(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-fail-a")
	bad := `{not json`
	err := e.log.Write(&monitoring.AuditEvent{WorkspaceID: a.ws.String(), UserID: a.author.String(), Action: "thing.update",
		Method: "PUT", OldValues: &bad})
	if err == nil {
		t.Fatal("an unwritable event must return an error")
	}
	var n int64
	e.db.Raw(`SELECT count(*) FROM audit_write_failure WHERE workspace_id = ? AND state = 'pending'`, a.ws).Scan(&n)
	if n != 1 {
		t.Fatalf("write failure rows = %d", n)
	}
	tok := e.api.token(a.ws, a.author, a.authorMember, "governance:read")
	code, body := e.call(http.MethodGet, "/api/iga/v1/audit/write-failures", tok, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 1 {
		t.Fatalf("write failures: %d %v", code, body)
	}
	// The replay announces it (a governance event) and keeps trying.
	svc := services.NewAuditGovService(e.db)
	if err := svc.ReplayWorkspaceFailures(context.Background(), a.ws); err != nil {
		t.Fatal(err)
	}
	e.db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, a.ws, services.GovEventAuditWriteFailed).Scan(&n)
	if n != 1 {
		t.Fatalf("write-failed events = %d", n)
	}
	// A replayable failure lands in the chain.
	good, _ := json.Marshal(monitoring.AuditEvent{WorkspaceID: a.ws.String(), UserID: a.author.String(), Action: "thing.replayed",
		Method: "PUT", Timestamp: time.Now().UTC().Add(-time.Minute)})
	p3exec(t, e.db, `INSERT INTO audit_write_failure (workspace_id, event, error, attempts) VALUES (?, ?::jsonb, 'db down', 3)`, a.ws, string(good))
	if err := svc.ReplayWorkspaceFailures(context.Background(), a.ws); err != nil {
		t.Fatal(err)
	}
	var seq *int64
	e.db.Raw(`SELECT replayed_seq FROM audit_write_failure WHERE workspace_id = ? AND state = 'replayed'`, a.ws).Scan(&seq)
	if seq == nil {
		t.Fatal("the replayable failure was not replayed")
	}
	e.db.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'thing.replayed' AND seq = ?`, a.ws.String(), *seq).Scan(&n)
	if n != 1 {
		t.Fatal("the replayed event is not in the chain")
	}
}

func TestAuditOperatorViewIsolation(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-op-a")
	b := e.gov("ag-op-b")
	now := time.Now().UTC()
	old := `{"name": "before"}`
	ev := &monitoring.AuditEvent{WorkspaceID: a.ws.String(), UserID: a.author.String(), Action: "application_updated",
		Resource: "application", ResourceID: "app-1", Method: "PUT", StatusCode: 200, OldValues: &old, Timestamp: now.Add(-time.Minute)}
	if err := e.log.Write(ev); err != nil {
		t.Fatal(err)
	}
	e.event(a.ws, a.approver.String(), "thing.update", "PUT", "", now.Add(-time.Minute))
	e.event(b.ws, b.author.String(), "thing.update", "PUT", "", now.Add(-time.Minute))

	ta := e.api.token(a.ws, a.author, a.authorMember, "governance:read")
	tb := e.api.token(b.ws, b.author, b.authorMember, "governance:read")
	from := now.Add(-time.Hour).Format(time.RFC3339)
	code, body := e.call(http.MethodGet, "/api/iga/v1/audit/events?actor="+a.author.String()+"&from="+from, ta, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 1 {
		t.Fatalf("operator filter: %d %v", code, body)
	}
	// Workspace B asking for A's operator sees nothing.
	code, body = e.call(http.MethodGet, "/api/iga/v1/audit/events?actor="+a.author.String(), tb, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 0 {
		t.Fatalf("cross-workspace operator filter: %d %v", code, body)
	}
	// Decisions: A sees its operator's reversible change; B gets 404.
	code, body = e.call(http.MethodGet, "/api/iga/v1/audit/operators/"+a.author.String()+"/decisions?from="+from, ta, nil)
	if code != http.StatusOK {
		t.Fatalf("decisions: %d %v", code, body)
	}
	ds := body["data"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["reversible"] != true {
		t.Fatalf("decisions: %v", ds)
	}
	if code, _ := e.call(http.MethodGet, "/api/iga/v1/audit/operators/"+a.author.String()+"/decisions", tb, nil); code != http.StatusNotFound {
		t.Fatalf("cross-workspace decisions: %d", code)
	}
}

func TestOperatorSuspendBlocksNextRequest(t *testing.T) {
	e := agSetup(t)
	raw, err := sql.Open("postgres", os.Getenv("IGA_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(2)
	t.Cleanup(func() { raw.Close() })
	prevDatabase := config.Database
	config.Database = &database.DBConnection{DB: raw}
	t.Cleanup(func() { config.Database = prevDatabase })

	a := e.gov("ag-susp-a")
	b := e.gov("ag-susp-b")
	third, thirdMember := a.member("third-"+a.ws.String()[:8]+"@p3own.test", "Tia Third", "active")
	e.grant(a, a.author, "governance:approve")
	e.grant(a, third, "governance:approve")
	scope := "governance:read governance:emergency governance:approve"
	author := e.api.token(a.ws, a.author, a.authorMember, scope)
	target := e.api.token(a.ws, a.approver, a.membershipOf(a.approver), scope)
	thirdTok := e.api.token(a.ws, third, thirdMember, scope)
	otherTok := e.api.token(b.ws, b.author, b.authorMember, scope)

	if code, body := e.call(http.MethodGet, "/api/iga/v1/audit/events", target, nil); code != http.StatusOK {
		t.Fatalf("before suspension: %d %v", code, body)
	}
	if code, body := e.call(http.MethodPost, "/authsec/admin/operators/"+a.author.String()+"/suspend", author,
		map[string]any{"reason": "me"}); code != http.StatusConflict || p3ErrCode(body) != services.GovCodeCannotSuspendSelf {
		t.Fatalf("self suspend: %d %v", code, body)
	}
	if code, _ := e.call(http.MethodPost, "/authsec/admin/operators/"+a.approver.String()+"/suspend", otherTok,
		map[string]any{"reason": "x"}); code != http.StatusNotFound {
		t.Fatalf("cross-workspace suspend: %d", code)
	}
	if code, body := e.call(http.MethodPost, "/authsec/admin/operators/"+a.approver.String()+"/suspend", author,
		map[string]any{"reason": "credential leak"}); code != http.StatusOK {
		t.Fatalf("suspend: %d %v", code, body)
	}
	if code, _ := e.call(http.MethodGet, "/api/iga/v1/audit/events", target, nil); code != http.StatusUnauthorized {
		t.Fatalf("suspended operator's next request: %d, want 401", code)
	}
	// Lifting is tier 3: the requester cannot approve, a third person can.
	code, body := e.call(http.MethodPost, "/authsec/admin/operators/"+a.approver.String()+"/unsuspend", author,
		map[string]any{"reason": "rotated"})
	if code != http.StatusAccepted {
		t.Fatalf("unsuspend request: %d %v", code, body)
	}
	id := body["data"].(map[string]any)["change"].(map[string]any)["id"].(string)
	if code, _ := e.call(http.MethodPost, "/api/iga/v1/audit/changes/"+id+"/approve", author, nil); code != http.StatusForbidden {
		t.Fatalf("requester approved the unsuspension: %d", code)
	}
	if code, _ := e.call(http.MethodGet, "/api/iga/v1/audit/events", target, nil); code != http.StatusUnauthorized {
		t.Fatalf("still suspended before approval: %d", code)
	}
	if code, body := e.call(http.MethodPost, "/api/iga/v1/audit/changes/"+id+"/approve", thirdTok, nil); code != http.StatusOK {
		t.Fatalf("approve unsuspend: %d %v", code, body)
	}
	if code, _ := e.call(http.MethodGet, "/api/iga/v1/audit/events", target, nil); code != http.StatusOK {
		t.Fatalf("after unsuspension: %d", code)
	}
}

func TestOperatorBaselineRaisesOutOfPatternAlert(t *testing.T) {
	e := agSetup(t)
	a := e.gov("ag-base-a")
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	for i := 0; i < 15; i++ {
		e.event(a.ws, a.author.String(), "thing.update", "PUT", "", hour.Add(time.Duration(i)*time.Minute))
	}
	for i := 0; i < 3; i++ {
		e.event(a.ws, a.approver.String(), "thing.update", "PUT", "", hour.Add(time.Duration(i)*time.Minute))
	}
	svc := services.NewAuditGovService(e.db)
	raised, err := svc.BaselineWorkspace(context.Background(), a.ws)
	if err != nil {
		t.Fatal(err)
	}
	if len(raised) != 1 || raised[0].UserID != a.author.String() || raised[0].Metric != "writes" || raised[0].Observed != 15 || raised[0].Threshold != 10 {
		t.Fatalf("alerts: %+v", raised)
	}
	if again, err := svc.BaselineWorkspace(context.Background(), a.ws); err != nil || len(again) != 0 {
		t.Fatalf("a second run raised again: %+v %v", again, err)
	}
	var n int64
	e.db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ?`, a.ws, services.GovEventOperatorOutOfPattern).Scan(&n)
	if n != 1 {
		t.Fatalf("out-of-pattern events = %d", n)
	}
	if services.OperatorThreshold(5) != 15 || services.OperatorThreshold(1) != 10 {
		t.Fatal("threshold must be max(10, 3 x p95)")
	}
}
