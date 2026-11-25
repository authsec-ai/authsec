package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime cases (SPEC-secops-backend-upgrade.md W3): clustering of new
// alerts into cases (shared indicator, window, a success breaks the group,
// never across workspaces), one case per alert, and every case route with
// its cross-workspace 404.

// acAlert inserts an alert of ws directly (detection, severity, times).
func acAlert(t *testing.T, db *gorm.DB, ws, conn, identity uuid.UUID, workloads []uuid.UUID, det, sev string, first, last time.Time) uuid.UUID {
	t.Helper()
	if workloads == nil {
		workloads = []uuid.UUID{}
	}
	wl, _ := json.Marshal(workloads)
	evID := "ev-" + uuid.NewString()[:12]
	ev, _ := json.Marshal([]map[string]any{{"event_id": evID, "time": first, "source": "secretsmanager.amazonaws.com", "name": "GetSecretValue"}})
	var id uuid.UUID
	if err := db.Raw(`INSERT INTO agent_alert (workspace_id, connector_id, identity_id, workload_ids, subject_label, subject_name, detection,
	                     severity, title, dedupe_key, first_seen, last_seen, event_count, evidence, state)
	                  VALUES (?, ?, ?, ?::jsonb, 'agent', 'order-agent', ?, ?, ?, ?, ?, ?, 1, ?::jsonb, 'open') RETURNING id`,
		ws, conn, identity, string(wl), det, sev, det+": order-agent", identity.String()+"/"+det+"/"+evID, first, last, string(ev)).Scan(&id).Error; err != nil {
		t.Fatal(err)
	}
	return id
}

// acCaseOf is the case an alert is in (uuid.Nil: none).
func acCaseOf(t *testing.T, db *gorm.DB, ws, alert uuid.UUID) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := db.Raw(`SELECT case_id FROM agent_case_alert WHERE workspace_id = ? AND alert_id = ?`, ws, alert).Scan(&ids).Error; err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		return uuid.Nil
	}
	return ids[0]
}

func acCluster(t *testing.T, db *gorm.DB, ws uuid.UUID, at time.Time) {
	t.Helper()
	if _, err := services.NewAgentCaseService(db).WithClock(func() time.Time { return at }).ClusterPending(context.Background(), ws); err != nil {
		t.Fatal(err)
	}
}

func acEvents(t *testing.T, db *gorm.DB, ws, caseID uuid.UUID, event string) int {
	t.Helper()
	var n int
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND payload->>'case_id' = ?`, ws, event, caseID.String()).Scan(&n)
	return n
}

// The sink's hook: a new alert joins the open case sharing its identity, or
// opens one (by system); workspaces never share a case or a case number.
func TestAgentCasesClusterNewAlertsThroughTheSink(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-cases-sink-a")
	b := p3NewGov(t, db, "ar-cases-sink-b")
	r := arSetup(t, db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	const role = "arn:aws:iam::111111111111:role/case-agent"
	const other = "arn:aws:iam::111111111111:role/other-agent"
	idA, idA2, idB := uuid.New(), uuid.New(), uuid.New()
	r.set(a.ws, role, agentruntime.Subject{IdentityID: idA, ConnectorID: a.conn, Label: agentruntime.LabelAgent, Name: "case-agent"})
	r.set(a.ws, other, agentruntime.Subject{IdentityID: idA2, ConnectorID: a.conn, Label: agentruntime.LabelAgent, Name: "other-agent"})
	r.set(b.ws, role, agentruntime.Subject{IdentityID: idB, ConnectorID: b.conn, Label: agentruntime.LabelAgent, Name: "case-agent"})

	dispatch := func(ws, conn uuid.UUID, evs ...agentruntime.Event) {
		t.Helper()
		if err := agentruntime.Dispatch(ctx, ws, conn, evs); err != nil {
			t.Fatal(err)
		}
	}
	dispatch(a.ws, a.conn, arEvent("cs-a1", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-30*time.Minute)))
	dispatch(a.ws, a.conn, arEvent("cs-a2", role, "iam.amazonaws.com", "CreateAccessKey", now.Add(-20*time.Minute)))
	dispatch(a.ws, a.conn, arEvent("cs-a3", other, "iam.amazonaws.com", "CreateAccessKey", now.Add(-10*time.Minute)))
	dispatch(b.ws, b.conn, arEvent("cs-a1", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-30*time.Minute)))

	as, bs := arAlerts(t, db, a.ws), arAlerts(t, db, b.ws)
	if len(as) != 3 || len(bs) != 1 {
		t.Fatalf("alerts: A %d, B %d", len(as), len(bs))
	}
	c1, c2, c3 := acCaseOf(t, db, a.ws, as[0].ID), acCaseOf(t, db, a.ws, as[1].ID), acCaseOf(t, db, a.ws, as[2].ID)
	if c1 == uuid.Nil || c1 != c2 {
		t.Fatalf("D1 and D2 on one identity must share a case: %s %s", c1, c2)
	}
	if c3 == uuid.Nil || c3 == c1 {
		t.Fatalf("another identity must open its own case: %s", c3)
	}
	cb := acCaseOf(t, db, b.ws, bs[0].ID)
	if cb == uuid.Nil || cb == c1 {
		t.Fatalf("B's alert case: %s", cb)
	}
	var rows []struct {
		Number   int
		OpenedBy string
		Severity string
	}
	db.Raw(`SELECT number, opened_by, severity FROM agent_case WHERE workspace_id = ? ORDER BY number`, a.ws).Scan(&rows)
	if len(rows) != 2 || rows[0].Number != 1 || rows[1].Number != 2 || rows[0].OpenedBy != "system" || rows[0].Severity != "high" {
		t.Fatalf("A's cases: %+v", rows)
	}
	var bNum int
	db.Raw(`SELECT number FROM agent_case WHERE workspace_id = ?`, b.ws).Scan(&bNum)
	if bNum != 1 {
		t.Errorf("B's first case number: %d", bNum)
	}
	// No case of A holds B's alert, and the reverse.
	var cross int
	db.Raw(`SELECT count(*) FROM agent_case_alert ca JOIN agent_alert al ON al.id = ca.alert_id WHERE ca.workspace_id <> al.workspace_id`).Scan(&cross)
	if cross != 0 {
		t.Fatalf("%d memberships across workspaces", cross)
	}
	if acEvents(t, db, a.ws, c1, "case.opened") != 1 || acEvents(t, db, a.ws, c1, "case.alert_added") != 2 {
		t.Errorf("case log of %s", c1)
	}
	var pinned int
	db.Raw(`SELECT count(*) FROM agent_case_evidence WHERE workspace_id = ? AND case_id = ?`, a.ws, c1).Scan(&pinned)
	if pinned != 2 {
		t.Errorf("pinned evidence of case 1: %d, want 2", pinned)
	}
}

// Clustering rules over stored alerts (the cluster worker / backfill path).
func TestAgentCasesClusteringRules(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "ar-cases-rules")
	other := p3NewGov(t, db, "ar-cases-rules-b")
	t0 := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	ws := g.ws

	// A success breaks a group of refusals.
	x := uuid.New()
	attempt := acAlert(t, db, ws, g.conn, x, nil, "D5", "medium", t0, t0.Add(5*time.Minute))
	acCluster(t, db, ws, t0)
	success := acAlert(t, db, ws, g.conn, x, nil, "D1", "high", t0.Add(time.Hour), t0.Add(time.Hour))
	acCluster(t, db, ws, t0)
	cAttempt, cSuccess := acCaseOf(t, db, ws, attempt), acCaseOf(t, db, ws, success)
	if cAttempt == uuid.Nil || cSuccess == uuid.Nil || cAttempt == cSuccess {
		t.Fatalf("a success must open a new case: attempt %s success %s", cAttempt, cSuccess)
	}
	var rel int
	db.Raw(`SELECT count(*) FROM agent_case_link WHERE workspace_id = ? AND case_id = ? AND other_case_id = ? AND relation = 'related'`,
		ws, cSuccess, cAttempt).Scan(&rel)
	if rel != 1 {
		t.Fatalf("related link: %d", rel)
	}
	// Later alerts join the most recently active case (the success case),
	// and a success joins a case that already holds a success.
	signal := acAlert(t, db, ws, g.conn, x, nil, "D8", "medium", t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	success2 := acAlert(t, db, ws, g.conn, x, nil, "D3", "high", t0.Add(3*time.Hour), t0.Add(3*time.Hour))
	acCluster(t, db, ws, t0)
	if acCaseOf(t, db, ws, signal) != cSuccess || acCaseOf(t, db, ws, success2) != cSuccess {
		t.Fatalf("later alerts: %s %s, want %s", acCaseOf(t, db, ws, signal), acCaseOf(t, db, ws, success2), cSuccess)
	}

	// The window: 30 h after a case's last activity is a new case.
	y := uuid.New()
	y1 := acAlert(t, db, ws, g.conn, y, nil, "D1", "high", t0, t0)
	acCluster(t, db, ws, t0)
	y2 := acAlert(t, db, ws, g.conn, y, nil, "D3", "high", t0.Add(30*time.Hour), t0.Add(30*time.Hour))
	acCluster(t, db, ws, t0)
	if acCaseOf(t, db, ws, y1) == acCaseOf(t, db, ws, y2) {
		t.Fatal("an alert outside the window joined the case")
	}
	y3 := acAlert(t, db, ws, g.conn, y, nil, "D2", "high", t0.Add(40*time.Hour), t0.Add(40*time.Hour))
	acCluster(t, db, ws, t0)
	if acCaseOf(t, db, ws, y3) != acCaseOf(t, db, ws, y2) {
		t.Fatal("an alert inside the window did not join")
	}

	// A shared workload (the agent) joins two identities; a different one
	// does not.
	w := uuid.New()
	z1 := acAlert(t, db, ws, g.conn, uuid.New(), []uuid.UUID{w}, "D2", "high", t0, t0)
	acCluster(t, db, ws, t0)
	z2 := acAlert(t, db, ws, g.conn, uuid.New(), []uuid.UUID{uuid.New(), w}, "D4", "medium", t0.Add(time.Hour), t0.Add(time.Hour))
	z3 := acAlert(t, db, ws, g.conn, uuid.New(), []uuid.UUID{uuid.New()}, "D4", "medium", t0.Add(time.Hour), t0.Add(time.Hour))
	acCluster(t, db, ws, t0)
	if acCaseOf(t, db, ws, z1) != acCaseOf(t, db, ws, z2) || acCaseOf(t, db, ws, z3) == acCaseOf(t, db, ws, z1) {
		t.Fatal("workload indicator clustering")
	}

	// A closed case takes no new alert.
	if _, err := services.NewAgentCaseService(db).Close(context.Background(), ws, acCaseOf(t, db, ws, z1), g.author,
		services.AgentCaseClose{Outcome: "benign"}); err != nil {
		t.Fatal(err)
	}
	z4 := acAlert(t, db, ws, g.conn, uuid.New(), []uuid.UUID{w}, "D2", "high", t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	acCluster(t, db, ws, t0)
	if c := acCaseOf(t, db, ws, z4); c == uuid.Nil || c == acCaseOf(t, db, ws, z1) {
		t.Fatalf("alert after close: %s", c)
	}

	// Never across workspaces: the same identity and workload ids in
	// another workspace open that workspace's own case.
	o := acAlert(t, db, other.ws, other.conn, x, []uuid.UUID{w}, "D1", "high", t0.Add(time.Hour), t0.Add(time.Hour))
	acCluster(t, db, other.ws, t0)
	oc := acCaseOf(t, db, other.ws, o)
	if oc == uuid.Nil || oc == cSuccess || oc == acCaseOf(t, db, ws, z4) {
		t.Fatalf("other workspace's alert case: %s", oc)
	}
	var n int
	db.Raw(`SELECT count(*) FROM agent_case_alert WHERE workspace_id = ? AND case_id = ?`, other.ws, oc).Scan(&n)
	if n != 1 {
		t.Fatalf("other workspace's case holds %d alerts", n)
	}

	// One case per alert, in the schema itself.
	err := db.Exec(`INSERT INTO agent_case_alert (workspace_id, case_id, alert_id, added_by) VALUES (?, ?, ?, 'system')`,
		ws, cAttempt, success).Error
	if err == nil {
		t.Fatal("an alert was put in a second case")
	}
}

func TestAgentCasesRoutesAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-cases-api-a")
	b := p3NewGov(t, db, "ar-cases-api-b")
	p3Audit(t, db, a.ws, b.ws)
	api := p3NewOwnersAPI(t, db)
	all := "governance:read governance:enforce"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	tokReader := api.token(a.ws, a.author, a.authorMember, "discovery:read")
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	x := uuid.New()
	a1 := acAlert(t, db, a.ws, a.conn, x, nil, "D1", "high", t0, t0)
	a2 := acAlert(t, db, a.ws, a.conn, x, nil, "D2", "medium", t0, t0)
	a3 := acAlert(t, db, a.ws, a.conn, x, nil, "D3", "medium", t0, t0)
	acCluster(t, db, a.ws, t0)
	caseA := acCaseOf(t, db, a.ws, a1)
	if caseA == uuid.Nil || acCaseOf(t, db, a.ws, a3) != caseA {
		t.Fatal("A's alerts not clustered")
	}
	bAlert := acAlert(t, db, b.ws, b.conn, uuid.New(), nil, "D1", "high", t0, t0)
	acCluster(t, db, b.ws, t0)
	caseB := acCaseOf(t, db, b.ws, bAlert)
	cA, cB := caseA.String(), caseB.String()

	// Reads.
	if code, body := arCall(t, api, http.MethodGet, "/cases", tokA, nil); code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "data", 0, "id") != cA {
		t.Fatalf("A lists: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/cases?agent="+x.String()+"&state=open&assignee=none", tokReader, nil); code != http.StatusOK || len(digl(body, "data")) != 1 {
		t.Fatalf("A filters by agent: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/cases?agent="+x.String(), tokB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B filters by A's agent: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/cases/"+cA, tokReader, nil); code != http.StatusOK ||
		len(digl(body, "data", "alerts")) != 3 || len(digl(body, "data", "asks")) != 0 || len(digl(body, "data", "log")) < 4 ||
		digs(body, "data", "severity") != "high" {
		t.Fatalf("A reads its case: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodGet, "/cases?state=resolved", tokA, nil); code != http.StatusBadRequest {
		t.Errorf("bad state filter: %d", code)
	}

	// Workspace B: every route on A's case is 404, like an unknown id.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/cases/" + cA, nil},
		{http.MethodPost, "/cases/" + cA + "/assign", map[string]any{"assignee_user_id": b.author}},
		{http.MethodPost, "/cases/" + cA + "/notes", map[string]any{"body": "x"}},
		{http.MethodPost, "/cases/" + cA + "/split", map[string]any{"alert_ids": []uuid.UUID{a1}}},
		{http.MethodPost, "/cases/" + cA + "/alerts", map[string]any{"alert_ids": []uuid.UUID{bAlert}}},
		{http.MethodPost, "/cases/" + cA + "/severity", map[string]any{"severity": "high"}},
		{http.MethodPost, "/cases/" + cA + "/close", map[string]any{"outcome": "benign"}},
		{http.MethodPost, "/cases/" + cA + "/reopen", nil},
		{http.MethodPost, "/cases/" + cA + "/export", nil},
		{http.MethodGet, "/cases/" + uuid.NewString(), nil},
		{http.MethodGet, "/cases/not-a-uuid", nil},
		// B cannot pull A's alert into its case, nor open a case from it.
		{http.MethodPost, "/cases/" + cB + "/alerts", map[string]any{"alert_ids": []uuid.UUID{a1}}},
		{http.MethodPost, "/cases", map[string]any{"alert_ids": []uuid.UUID{a1}}},
		// Nor close its case as a duplicate of A's.
		{http.MethodPost, "/cases/" + cB + "/close", map[string]any{"outcome": "duplicate", "duplicate_of": caseA}},
	} {
		if code, body := arCall(t, api, c.method, c.path, tokB, c.body); code != http.StatusNotFound {
			t.Errorf("B %s %s: %d %v, want 404", c.method, c.path, code, body)
		}
	}
	if acCaseOf(t, db, a.ws, a1) != caseA {
		t.Fatal("A's alert moved by B")
	}
	// A read-only token cannot change a case.
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+cA+"/notes", tokReader, map[string]any{"body": "x"}); code != http.StatusForbidden {
		t.Errorf("discovery:read writes a note: %d", code)
	}

	// Assign: a member of A; not B's member; unassign.
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+cA+"/assign", tokA, map[string]any{"assignee_user_id": a.approver}); code != http.StatusOK ||
		digs(body, "data", "assignee_user_id") != a.approver.String() {
		t.Fatalf("assign: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+cA+"/assign", tokA, map[string]any{"assignee_user_id": b.author}); code != http.StatusBadRequest ||
		digs(body, "error", "code") != "assignee_not_member" {
		t.Fatalf("assign a non-member: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/cases?assignee="+a.approver.String(), tokA, nil); code != http.StatusOK || len(digl(body, "data")) != 1 {
		t.Fatalf("filter by assignee: %d %v", code, body)
	}

	// Notes: append-only, bounded.
	code, body := arCall(t, api, http.MethodPost, "/cases/"+cA+"/notes", tokA, map[string]any{"body": "looking at the role's trail"})
	if code != http.StatusCreated {
		t.Fatalf("note: %d %v", code, body)
	}
	noteID := digs(body, "data", "id")
	if err := db.Exec(`UPDATE agent_case_note SET body = 'rewritten' WHERE id = ?`, noteID).Error; err == nil {
		t.Fatal("a note was rewritten")
	}
	if err := db.Exec(`DELETE FROM agent_case_note WHERE id = ?`, noteID).Error; err == nil {
		t.Fatal("a note was deleted")
	}
	long := make([]byte, 10001)
	for i := range long {
		long[i] = 'a'
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+cA+"/notes", tokA, map[string]any{"body": string(long)}); code != http.StatusBadRequest {
		t.Errorf("an over-long note: %d", code)
	}

	// Split: a3 to a new case linked split_from; splitting everything is refused.
	code, body = arCall(t, api, http.MethodPost, "/cases/"+cA+"/split", tokA, map[string]any{"alert_ids": []uuid.UUID{a3}})
	if code != http.StatusCreated {
		t.Fatalf("split: %d %v", code, body)
	}
	split, _ := uuid.Parse(digs(body, "data", "id"))
	if acCaseOf(t, db, a.ws, a3) != split || digs(body, "data", "severity") != "medium" {
		t.Fatalf("split moved: %s %v", acCaseOf(t, db, a.ws, a3), body)
	}
	var links int
	db.Raw(`SELECT count(*) FROM agent_case_link WHERE workspace_id = ? AND case_id = ? AND other_case_id = ? AND relation = 'split_from'`,
		a.ws, split, caseA).Scan(&links)
	if links != 1 {
		t.Fatalf("split_from links: %d", links)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+cA+"/split", tokA, map[string]any{"alert_ids": []uuid.UUID{a1, a2}}); code != http.StatusBadRequest {
		t.Errorf("splitting every alert: %d", code)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+cA+"/split", tokA, map[string]any{"alert_ids": []uuid.UUID{a3}}); code != http.StatusConflict {
		t.Errorf("splitting an alert of another case: %d", code)
	}

	// Move a2 into the split case: removed from its old case, logged on both.
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/alerts", tokA, map[string]any{"alert_ids": []uuid.UUID{a2}}); code != http.StatusOK ||
		digs(body, "data", "alert_count") != "2" && dig(body, "data", "alert_count") != float64(2) {
		t.Fatalf("move: %d %v", code, body)
	}
	if acCaseOf(t, db, a.ws, a2) != split {
		t.Fatal("a2 not moved")
	}
	if acEvents(t, db, a.ws, caseA, "case.alert_removed") != 2 || acEvents(t, db, a.ws, split, "case.alert_added") != 2 {
		t.Errorf("move log: removed %d added %d", acEvents(t, db, a.ws, caseA, "case.alert_removed"), acEvents(t, db, a.ws, split, "case.alert_added"))
	}
	var moved int
	db.Raw(`SELECT count(*) FROM agent_case_evidence WHERE workspace_id = ? AND case_id = ? AND alert_id = ?`, a.ws, split, a2).Scan(&moved)
	if moved != 1 {
		t.Errorf("a2's evidence pin did not follow it: %d", moved)
	}

	// Severity: raise is allowed, lowering is refused (tier 3).
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/severity", tokA, map[string]any{"severity": "high"}); code != http.StatusOK ||
		digs(body, "data", "severity") != "high" || digs(body, "data", "classified_at") == "" {
		t.Fatalf("raise: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/severity", tokA, map[string]any{"severity": "low"}); code != http.StatusConflict {
		t.Errorf("lowering: %d", code)
	}

	// Close needs an outcome; duplicate needs duplicate_of.
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/close", tokA, map[string]any{"reason": "done"}); code != http.StatusBadRequest {
		t.Fatalf("close without outcome: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/close", tokA, map[string]any{"outcome": "duplicate"}); code != http.StatusBadRequest {
		t.Errorf("duplicate without duplicate_of: %d", code)
	}
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/close", tokA,
		map[string]any{"outcome": "duplicate", "duplicate_of": caseA, "reason": "same incident"}); code != http.StatusOK ||
		digs(body, "data", "state") != "closed" || digs(body, "data", "outcome") != "duplicate" {
		t.Fatalf("close: %d %v", code, body)
	}
	// A closed case's alerts are frozen; it takes notes; assigning is refused.
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+cA+"/alerts", tokA, map[string]any{"alert_ids": []uuid.UUID{a2}}); code != http.StatusConflict {
		t.Errorf("moving out of a closed case: %d", code)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/assign", tokA, map[string]any{"assignee_user_id": nil}); code != http.StatusConflict {
		t.Errorf("assigning a closed case: %d", code)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/notes", tokA, map[string]any{"body": "post-mortem"}); code != http.StatusCreated {
		t.Errorf("note on a closed case: %d", code)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/close", tokA, map[string]any{"outcome": "benign"}); code != http.StatusConflict {
		t.Errorf("closing twice: %d", code)
	}

	// Reopen.
	if code, body := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/reopen", tokA, map[string]any{"reason": "new evidence"}); code != http.StatusOK ||
		digs(body, "data", "state") != "open" || dig(body, "data", "outcome") != nil || dig(body, "data", "reopened_count") != float64(1) {
		t.Fatalf("reopen: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodPost, "/cases/"+split.String()+"/reopen", tokA, nil); code != http.StatusConflict {
		t.Errorf("reopening an open case: %d", code)
	}

	// Create from alerts (moves a2 out of the reopened case).
	code, body = arCall(t, api, http.MethodPost, "/cases", tokA, map[string]any{"alert_ids": []uuid.UUID{a2}, "title": "credential creation"})
	if code != http.StatusCreated || digs(body, "data", "opened_by") != a.author.String() || digs(body, "data", "title") != "credential creation" {
		t.Fatalf("create: %d %v", code, body)
	}
	created, _ := uuid.Parse(digs(body, "data", "id"))
	if acCaseOf(t, db, a.ws, a2) != created {
		t.Fatal("create did not take the alert")
	}

	// Export: same hash twice; case.exported logged each time, outside the bundle.
	exp := func() (string, map[string]any) {
		t.Helper()
		code, body := arCall(t, api, http.MethodPost, "/cases/"+cA+"/export", tokA, nil)
		if code != http.StatusOK {
			t.Fatalf("export: %d %v", code, body)
		}
		return digs(body, "data", "sha256"), body
	}
	h1, body1 := exp()
	h2, _ := exp()
	if len(h1) != 64 || h1 != h2 {
		t.Fatalf("export hash not stable: %s %s", h1, h2)
	}
	raw, _ := json.Marshal(dig(body1, "data", "bundle"))
	if services.AgentCaseBundleHash(raw) != h1 {
		t.Errorf("the hash is not over the bundle served")
	}
	if digs(body1, "data", "bundle", "format") != services.AgentCaseExportFormat || len(digl(body1, "data", "bundle", "notes")) != 1 {
		t.Errorf("bundle: %v", dig(body1, "data", "bundle"))
	}
	if n := acEvents(t, db, a.ws, caseA, "case.exported"); n != 2 {
		t.Errorf("case.exported events: %d", n)
	}
	// A change to the case changes the hash.
	arCall(t, api, http.MethodPost, "/cases/"+cA+"/notes", tokA, map[string]any{"body": "another"})
	if h3, _ := exp(); h3 == h1 {
		t.Error("the hash did not change with the case")
	}

	// B's case is untouched and its list never shows A's cases.
	if code, body := arCall(t, api, http.MethodGet, "/cases", tokB, nil); code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "data", 0, "id") != cB {
		t.Fatalf("B lists: %d %v", code, body)
	}
	if ok, err := services.NewAgentCaseService(db).CaseExists(context.Background(), b.ws, caseA); err != nil || ok {
		t.Fatalf("CaseExists across workspaces: %v %v", ok, err)
	}
	if ok, err := services.NewAgentCaseService(db).CaseExists(context.Background(), a.ws, caseA); err != nil || !ok {
		t.Fatalf("CaseExists: %v %v", ok, err)
	}
}
