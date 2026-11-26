package integration

// Asks and their delivery (SPEC-secops-backend-upgrade.md W4) against a real
// database: the server picks the deciders (W7 resolution: agent scope, then
// the agent's estate scope, then the default group) and the due time (the
// workspace policy by the object's severity, or an earlier external
// deadline; never the body); the requester never decides; escalation moves
// along the path and ends overdue but open; "not mine" passes the ask on;
// withdraw; the policy's loosening is a tier-3 pending change; a Slack answer
// to a tier-2 ask waits for the same person's console confirmation, and a
// forged, replayed or tampered click is refused; Jira / ServiceNow /
// PagerDuty / Opsgenie against fake servers, safehttp refusing a loopback
// site; W7's agent.ask_needed raising real asks; a case shows its asks. Every
// route is exercised from a second workspace (404).
//
// Needs IGA_TEST_DSN (skipped otherwise).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

/* --------------------------------- harness -------------------------------- */

type askAPI struct {
	t      *testing.T
	db     *gorm.DB
	eng    *gin.Engine
	ws     uuid.UUID
	claims map[string]string
}

func newAskAPI(t *testing.T, db *gorm.DB) *askAPI {
	gin.SetMode(gin.TestMode)
	a := &askAPI{t: t, db: db, claims: map[string]string{}}
	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		if a.ws != uuid.Nil {
			tenancy.Set(c, tenancy.Context{WorkspaceID: a.ws, PrincipalKind: "user"})
		}
		for k, v := range a.claims {
			c.Set(k, v)
		}
		c.Next()
	})
	pass := func(c *gin.Context) { c.Next() }
	platform.RegisterAgentAskRoutes(g, platform.NewAgentAsksControllerWith(db), platform.AgentAskRouteGuards{
		Read: pass, GovRead: pass, Author: pass, Enforce: pass, IGARead: pass, IGAAdmin: pass})
	a.eng = eng
	return a
}

// as is a client acting as a member of ws (its own engine).
func (a *askAPI) as(ws, user, membership uuid.UUID) *askAPI {
	cp := newAskAPI(a.t, a.db)
	cp.ws = ws
	cp.claims = map[string]string{"user_id": user.String(), "workspace_membership_id": membership.String(), "client_id": "console"}
	return cp
}

func (a *askAPI) do(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	rd := bytes.NewReader(nil)
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	a.eng.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: %d, not JSON: %s", method, path, rec.Code, rec.Body.String())
		}
	}
	return rec.Code, out
}

func askErrCode(b map[string]any) string {
	e, _ := b["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

// askCleanup removes the workspaces' asks (their log is append-only: the
// workspace purge flag, as the workspace deletion sets it).
func askCleanup(t *testing.T, db *gorm.DB, wss ...uuid.UUID) {
	t.Cleanup(func() {
		_ = db.Transaction(func(tx *gorm.DB) error {
			tx.Exec(`SET LOCAL authsec.workspace_purge = 'on'`)
			for _, ws := range wss {
				for _, tbl := range []string{"agent_ask_external", "agent_ask", "agent_ask_integration", "agent_ask_policy",
					"pending_change", "iga_gov_job", "iga_gov_notification", "agent_case", "agent_alert"} {
					tx.Exec(`DELETE FROM `+tbl+` WHERE workspace_id = ?`, ws)
				}
			}
			return nil
		})
	})
}

func askChoices() []map[string]any {
	return []map[string]any{{"id": "retire", "label": "Retire it"}, {"id": "keep", "label": "Keep it"}}
}

func askBody(kind, id string) map[string]any {
	return map[string]any{"about": map[string]any{"kind": kind, "id": id}, "question": "What should happen to it?", "choices": askChoices()}
}

func askUUIDs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// askGroup creates a responder group with one accepted member and a scope.
func askGroup(t *testing.T, db *gorm.DB, ws, by, member uuid.UUID, name, scopeKind, scopeRef string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	gs := services.NewResponderGroupService(db)
	g, err := gs.Create(ctx, ws, by, name, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gs.AddMember(ctx, ws, g.ID, by, member, "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Accept(ctx, ws, g.ID, member); err != nil {
		t.Fatal(err)
	}
	if _, err := gs.AddScope(ctx, ws, g.ID, by, scopeKind, scopeRef); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func askMembership(t *testing.T, db *gorm.DB, ws, user uuid.UUID) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, ws, user).Scan(&ids)
	if len(ids) != 1 {
		t.Fatalf("membership of %s: %v", user, ids)
	}
	return ids[0]
}

func askCreate(t *testing.T, api *askAPI, body map[string]any) map[string]any {
	t.Helper()
	code, out := api.do("POST", "/agent-runtime/asks", body)
	if code != 200 {
		t.Fatalf("create ask: %d %v", code, out)
	}
	return aiData(out)
}

func askAlert(t *testing.T, db *gorm.DB, w *aiWorld, severity string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	arExec(t, db, `INSERT INTO agent_alert (id, workspace_id, connector_id, identity_id, workload_ids, subject_label, detection, severity,
		title, dedupe_key, first_seen, last_seen) VALUES (?, ?, ?, ?, ?::jsonb, 'agent', 'D1', ?, 'Secret read', ?, now(), now())`,
		id, w.ws, w.conn, w.identity, `["`+w.workload.String()+`"]`, severity, "ask-test:"+id.String())
	return id
}

/* ---------------------------------- tests --------------------------------- */

func TestAgentAskDeciderPrecedenceDueAndRequester(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aska")
	b := aiSeed(t, db, "askb")
	askCleanup(t, db, a.ws, b.ws)
	aiLink(t, db, a.ws)
	aiLink(t, db, b.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	api := newAskAPI(t, db)
	human := api.as(a.ws, a.human, a.membership)

	// No group of its own: the workspace default group (its admin). The
	// creator is excluded; due from the policy (medium: 24 h).
	before := time.Now()
	ask := askCreate(t, human, askBody("agent", wa.String()))
	if ask["resolved_via"] != "default" || strings.Join(askUUIDs(ask["deciders"]), ",") != a.admin.String() {
		t.Fatalf("default resolution: %v %v", ask["resolved_via"], ask["deciders"])
	}
	due, _ := time.Parse(time.RFC3339Nano, ask["due_at"].(string))
	if ask["due_source"] != "policy" || due.Before(before.Add(24*time.Hour-time.Minute)) || due.After(time.Now().Add(24*time.Hour+time.Minute)) {
		t.Fatalf("due %v %v", ask["due_at"], ask["due_source"])
	}

	// The agent's estate scope (its account) beats the default.
	acct := askGroup(t, db, a.ws, a.human, a.approver, "Account responders", "account", a.account)
	ask = askCreate(t, human, askBody("agent", wa.String()))
	if ask["resolved_via"] != "account" || ask["decider_group_id"] != acct.String() ||
		strings.Join(askUUIDs(ask["deciders"]), ",") != a.approver.String() {
		t.Fatalf("account resolution: %v", ask)
	}
	if n := len(ask["path"].([]any)); n != 3 { // account group, default group, admins
		t.Fatalf("path %v", ask["path"])
	}
	// A group holding the agent itself beats the estate scope.
	askGroup(t, db, a.ws, a.human, a.admin, "Agent owners", "agent", wa.String())
	ask = askCreate(t, human, askBody("agent", wa.String()))
	if ask["resolved_via"] != "agent" || strings.Join(askUUIDs(ask["deciders"]), ",") != a.admin.String() {
		t.Fatalf("agent resolution: %v", ask)
	}
	// An agent without scopes: the default group.
	if ask = askCreate(t, human, askBody("agent", sa.String())); ask["resolved_via"] != "default" {
		t.Fatalf("sighting: %v", ask["resolved_via"])
	}

	// The alert's severity sets the due time (high: 4 h) and its workload
	// names the agent.
	alert := askAlert(t, db, a, "high")
	ask = askCreate(t, human, askBody("alert", alert.String()))
	due, _ = time.Parse(time.RFC3339Nano, ask["due_at"].(string))
	if ask["severity"] != "high" || ask["agent_id"] != wa.String() || due.After(time.Now().Add(4*time.Hour+time.Minute)) {
		t.Fatalf("alert ask: %v", ask)
	}
	// An earlier external deadline with its source shortens it; a later one does not.
	soon := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	body := askBody("alert", alert.String())
	body["external_deadline"] = map[string]any{"at": soon.Format(time.RFC3339), "source": "regulator notice 2026-114"}
	ask = askCreate(t, human, body)
	if ask["due_source"] != "external_deadline" || ask["external_deadline_source"] != "regulator notice 2026-114" {
		t.Fatalf("external deadline: %v", ask)
	}
	body["external_deadline"] = map[string]any{"at": time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339), "source": "x"}
	if ask = askCreate(t, human, body); ask["due_source"] != "policy" {
		t.Fatalf("a later external deadline lengthened the due time: %v", ask)
	}
	// Who decides, when, and how severe are never taken from the body.
	for _, k := range []string{"due_at", "deciders", "decider_group_id", "severity", "hours_per_step", "path"} {
		body := askBody("agent", wa.String())
		body[k] = "x"
		if code, out := human.do("POST", "/agent-runtime/asks", body); code != 400 {
			t.Fatalf("body %s accepted: %d %v", k, code, out)
		}
	}
	// Raised by AuthSec only.
	if code, _ := human.do("POST", "/agent-runtime/asks", askBody("gateway_call", uuid.NewString())); code != 400 {
		t.Fatal("a gateway_call ask from the console")
	}

	// The requester never decides: the account group (the requester alone)
	// is skipped.
	ctx := context.Background()
	appr := a.approver
	id, err := services.CreateAsk(ctx, db, a.ws, services.AskInput{AboutKind: "alert", AboutID: alert.String(),
		Question: "Release the stop the approver asked for?", Choices: []services.AskChoice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}},
		RequesterUserID: &appr, Tier: 2})
	if err != nil {
		t.Fatal(err)
	}
	approver := api.as(a.ws, a.approver, a.approverM)
	code, out := approver.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "yes"})
	if code != 403 || askErrCode(out) != services.GovCodeRequesterDecides {
		t.Fatalf("requester answered: %d %v", code, out)
	}
	// The admin (agent owners group) answers; a choice not offered is refused.
	adminM := askMembership(t, db, a.ws, a.admin)
	admin := api.as(a.ws, a.admin, adminM)
	if code, _ := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "maybe"}); code != 400 {
		t.Fatalf("an unknown choice: %d", code)
	}
	if code, out := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "yes"}); code != 200 ||
		aiData(out)["state"] != "answered" || aiData(out)["answer_channel"] != "console" {
		t.Fatalf("admin answers: %d %v", code, out)
	}
	if code, _ := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "no"}); code != 409 {
		t.Fatal("answered twice")
	}
	// Mine.
	_, out = approver.do("GET", "/agent-runtime/asks?mine=true", nil)
	for _, x := range out["data"].([]any) {
		if x.(map[string]any)["id"] == id.String() {
			t.Fatal("the requester's list shows the ask as theirs")
		}
	}

	// Another workspace: 404 for every route, and nothing listed.
	bHuman := api.as(b.ws, b.human, b.membership)
	for _, r := range []struct{ m, p string }{{"GET", ""}, {"POST", "/answer"}, {"POST", "/not-mine"}, {"POST", "/withdraw"}, {"POST", "/confirm"}} {
		var bd any
		if r.m == "POST" {
			bd = map[string]any{"choice": "yes"}
			if r.p != "/answer" {
				bd = map[string]any{}
			}
		}
		if code, _ := bHuman.do(r.m, "/agent-runtime/asks/"+id.String()+r.p, bd); code != 404 {
			t.Errorf("%s %s from B: %d, want 404", r.m, r.p, code)
		}
	}
	if _, out := bHuman.do("GET", "/agent-runtime/asks", nil); len(out["data"].([]any)) != 0 {
		t.Fatalf("B lists A's asks: %v", out)
	}
	if code, _ := bHuman.do("POST", "/agent-runtime/asks", askBody("agent", wa.String())); code != 400 {
		t.Fatal("B raised an ask about A's agent")
	}
	if code, _ := bHuman.do("POST", "/agent-runtime/asks", askBody("alert", alert.String())); code != 400 {
		t.Fatal("B raised an ask about A's alert")
	}
}

func TestAgentAskEscalationNotMineWithdraw(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aske")
	askCleanup(t, db, a.ws)
	aiLink(t, db, a.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	askGroup(t, db, a.ws, a.human, a.approver, "Account responders", "account", a.account)
	api := newAskAPI(t, db)
	human := api.as(a.ws, a.human, a.membership)
	approver := api.as(a.ws, a.approver, a.approverM)
	adminM := askMembership(t, db, a.ws, a.admin)
	admin := api.as(a.ws, a.admin, adminM)
	ctx := context.Background()

	// Escalation: account group -> default group -> admins -> overdue (open).
	ask := askCreate(t, human, askBody("agent", wa.String()))
	id := uuid.MustParse(ask["id"].(string))
	clock := time.Now()
	svc := services.NewAgentAskService(db).WithClock(func() time.Time { return clock })
	if m, o, err := svc.EscalateWorkspace(ctx, a.ws); err != nil || m+o != 0 {
		t.Fatalf("nothing is due yet: %d %d %v", m, o, err)
	}
	clock = clock.Add(25 * time.Hour)
	if m, _, err := svc.EscalateWorkspace(ctx, a.ws); err != nil || m != 1 {
		t.Fatalf("first escalation: %d %v", m, err)
	}
	got, _ := svc.Get(ctx, a.ws, a.admin, id)
	if got.Step != 1 || len(got.Deciders) != 1 || got.Deciders[0] != a.admin || !got.DueAt.Equal(clock.Add(4*time.Hour).UTC().Truncate(time.Microsecond)) && got.DueAt.Sub(clock.Add(4*time.Hour)).Abs() > time.Second {
		t.Fatalf("after escalation: step %d deciders %v due %s", got.Step, got.Deciders, got.DueAt)
	}
	if !*got.CanAnswer {
		t.Fatal("the default group's admin cannot answer")
	}
	// The account group's member no longer decides.
	if code, out := approver.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "keep"}); code != 403 ||
		askErrCode(out) != services.GovCodeNotDecider {
		t.Fatalf("a previous step's decider answered: %d %v", code, out)
	}
	clock = clock.Add(5 * time.Hour)
	if m, _, _ := svc.EscalateWorkspace(ctx, a.ws); m != 1 {
		t.Fatal("second escalation (admins)")
	}
	clock = clock.Add(5 * time.Hour)
	if m, o, _ := svc.EscalateWorkspace(ctx, a.ws); m != 0 || o != 1 {
		t.Fatalf("end of path: moved %d overdue %d", m, o)
	}
	got, _ = svc.Get(ctx, a.ws, a.admin, id)
	if !got.Overdue || got.State != "open" || got.Step != 2 {
		t.Fatalf("overdue: %+v", got)
	}
	if len(aiEvents(t, db, a.ws, services.GovEventAskEscalated)) != 2 || len(aiEvents(t, db, a.ws, services.GovEventAskOverdue)) != 1 {
		t.Fatal("escalation events")
	}
	clock = clock.Add(10 * time.Hour)
	if m, o, _ := svc.EscalateWorkspace(ctx, a.ws); m+o != 0 {
		t.Fatal("an overdue ask was escalated again")
	}
	kinds := []string{}
	for _, e := range got.Events {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "asked,escalated,escalated,overdue" {
		t.Fatalf("ask log %v", kinds)
	}
	// Still answerable by the last step's people.
	if code, out := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/answer", map[string]any{"choice": "retire"}); code != 200 {
		t.Fatalf("the overdue ask could not be answered: %d %v", code, out)
	}

	// Not mine: the account group's member passes it on and is excluded.
	ask = askCreate(t, human, askBody("agent", wa.String()))
	id = uuid.MustParse(ask["id"].(string))
	code, out := approver.do("POST", "/agent-runtime/asks/"+id.String()+"/not-mine", map[string]any{"reason": "not my account"})
	if code != 200 || aiData(out)["step"].(float64) != 1 {
		t.Fatalf("not mine: %d %v", code, out)
	}
	if code, _ := approver.do("POST", "/agent-runtime/asks/"+id.String()+"/not-mine", map[string]any{}); code != 403 {
		t.Fatal("not mine twice")
	}
	// The admin is the last person who can decide: not mine is refused.
	if code, out := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/not-mine", map[string]any{}); code != 409 ||
		askErrCode(out) != services.GovCodeNoNextStep {
		t.Fatalf("not mine at the end: %d %v", code, out)
	}
	if len(aiEvents(t, db, a.ws, services.GovEventAskDisputed)) != 1 {
		t.Fatal("disputed event")
	}

	// Withdraw: the creator, or governance:approve; nobody else.
	if code, out := admin.do("POST", "/agent-runtime/asks/"+id.String()+"/withdraw", map[string]any{}); code != 403 {
		t.Fatalf("admin (neither) withdrew: %d %v", code, out)
	}
	if code, out := human.do("POST", "/agent-runtime/asks/"+id.String()+"/withdraw", map[string]any{"reason": "moot"}); code != 200 ||
		aiData(out)["state"] != "withdrawn" {
		t.Fatalf("creator withdraws: %d %v", code, out)
	}
	ask = askCreate(t, human, askBody("agent", wa.String()))
	if code, _ := approver.do("POST", "/agent-runtime/asks/"+ask["id"].(string)+"/withdraw", nil); code != 200 {
		t.Fatal("an approver withdraws")
	}
}

func TestAgentAskPolicyTier3(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "askp")
	b := aiSeed(t, db, "askq")
	askCleanup(t, db, a.ws, b.ws)
	api := newAskAPI(t, db)
	human := api.as(a.ws, a.human, a.membership)
	_, out := human.do("GET", "/agent-runtime/asks/policy", nil)
	p := aiData(out)
	if p["due_high_hours"].(float64) != 4 || p["due_medium_hours"].(float64) != 24 || p["due_low_hours"].(float64) != 72 || p["version"].(float64) != 0 {
		t.Fatalf("defaults %v", p)
	}
	// Tightening applies at once.
	code, out := human.do("PUT", "/agent-runtime/asks/policy", map[string]any{"version": 0, "due_high_hours": 2, "channel_webhook": true})
	if code != 200 || aiData(out)["applied"] != true || dig(out, "data", "policy", "due_high_hours").(float64) != 2 {
		t.Fatalf("tighten: %d %v", code, out)
	}
	// A stale version is refused.
	if code, _ := human.do("PUT", "/agent-runtime/asks/policy", map[string]any{"version": 0, "due_high_hours": 1}); code != 409 {
		t.Fatal("stale version accepted")
	}
	// Loosening with a second approver in the workspace: a pending change.
	code, out = human.do("PUT", "/agent-runtime/asks/policy", map[string]any{"version": 1, "due_high_hours": 12, "reason": "night shift"})
	if code != 200 || aiData(out)["applied"] != false || dig(out, "data", "pending_change", "kind") != "agent_ask_policy" {
		t.Fatalf("loosen: %d %v", code, out)
	}
	changeID := uuid.MustParse(dig(out, "data", "pending_change", "id").(string))
	if _, out = human.do("GET", "/agent-runtime/asks/policy", nil); aiData(out)["due_high_hours"].(float64) != 2 {
		t.Fatal("a loosening applied without the second person")
	}
	// Due times follow the policy now in force (high: 2 h).
	pcs := services.NewPendingChangeService(db)
	if _, _, err := pcs.Approve(context.Background(), a.ws, changeID, a.human); err == nil {
		t.Fatal("the requester approved their own loosening")
	}
	if _, _, err := pcs.Approve(context.Background(), b.ws, changeID, b.approver); err == nil {
		t.Fatal("another workspace approved the change")
	}
	if _, _, err := pcs.Approve(context.Background(), a.ws, changeID, a.approver); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, out = human.do("GET", "/agent-runtime/asks/policy", nil); aiData(out)["due_high_hours"].(float64) != 12 {
		t.Fatalf("approved loosening not applied: %v", out)
	}
	// The only approver loosening: break-glass, applied and flagged.
	approver := api.as(a.ws, a.approver, a.approverM)
	code, out = approver.do("PUT", "/agent-runtime/asks/policy", map[string]any{"version": 2, "channel_email": false})
	if code != 200 || aiData(out)["applied"] != true || aiData(out)["break_glass"] != true {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	// B's policy is untouched.
	if _, out = api.as(b.ws, b.human, b.membership).do("GET", "/agent-runtime/asks/policy", nil); aiData(out)["version"].(float64) != 0 {
		t.Fatalf("B's policy changed: %v", out)
	}
}

/* ---------------------------------- Slack --------------------------------- */

func TestAgentAskSlackAnswerStepUp(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "asks")
	askCleanup(t, db, a.ws)
	aiLink(t, db, a.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	askGroup(t, db, a.ws, a.human, a.approver, "Account responders", "account", a.account)
	pg := services.NewPolicyGate(true, p3GraphOn(t, db))
	if err := pg.Verify(db); err != nil {
		t.Fatal(err)
	}
	app := newP3sApp(t, db, pg)
	team := "TASK" + strings.ToUpper(uuid.NewString()[:8]) // unique: a team is installed in one workspace
	app.connectDirect(a.ws, team, "CASKS", a.admin)
	t.Cleanup(func() { db.Exec(`DELETE FROM slack_user_link WHERE workspace_id = ?`, a.ws); db.Exec(`DELETE FROM workspace_slack_integration WHERE workspace_id = ?`, a.ws) })
	app.link(a.ws, "UAPPR", a.approver)
	app.link(a.ws, "UHUMAN", a.human)
	email := &p3Outbox{}
	worker := p3NotifyWorker(db, email, &p3Outbox{})
	ctx := context.Background()

	raise := func(tier int) uuid.UUID {
		id, err := services.CreateAsk(ctx, db, a.ws, services.AskInput{AboutKind: "agent", AboutID: wa.String(), Tier: tier,
			Question: "Stop this agent's sessions on the shared role?",
			Choices:  []services.AskChoice{{ID: "stop", Label: "Stop them"}, {ID: "leave", Label: "Leave them"}}})
		if err != nil {
			t.Fatal(err)
		}
		p3Drain(t, worker)
		return id
	}
	id := raise(2)
	posts := app.fake.PostsTo("UAPPR")
	if len(posts) != 1 {
		t.Fatalf("%d Slack posts to the decider", len(posts))
	}
	if len(app.fake.PostsTo("UHUMAN")) != 0 {
		t.Fatal("a person who does not decide got the ask")
	}
	var em string
	db.Raw(`SELECT email FROM users WHERE id = ?`, a.approver).Scan(&em)
	if ms := email.to(em); len(ms) != 1 || !strings.Contains(ms[0].Subject, "Stop this agent") {
		t.Fatalf("e-mail to the decider: %v", ms)
	}
	post := posts[0]
	btn := p3sButtons(post)
	if btn["ask_choice_0"] == "" || btn["ask_not_mine"] == "" {
		t.Fatalf("buttons %v", btn)
	}
	click := func(user, action, value string) (int, map[string]any) {
		return app.click(p3sClick{team: team, user: user, messageTS: post.TS, action: action, value: value})
	}
	// A tampered button (another choice under the first's token) is refused.
	v, _ := slackapp.DecodeButtonValue(btn["ask_choice_0"])
	v.Choice = "leave"
	if code, out := click("UAPPR", "ask_choice_1", v.Encode()); code != 409 || askErrCode(out) != services.GovCodeAskChanged {
		t.Fatalf("tampered button: %d %v", code, out)
	}
	// A forged signature and a stale timestamp are refused before anything.
	body := p3sClick{team: team, user: "UAPPR", messageTS: post.TS, action: "ask_choice_0", value: btn["ask_choice_0"], actionTS: app.nextActionTS()}.body()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if code, _ := app.postAck(body, ts, "v0=deadbeef"); code != 401 {
		t.Fatalf("forged signature: %d", code)
	}
	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	if code, _ := app.postAck(body, old, slackapp.Sign(p3sSigning, old, body)); code != 401 {
		t.Fatalf("stale timestamp: %d", code)
	}
	// The real click: tier 2 from Slack waits for the console.
	code, out, ts, sig := app.signed(body)
	if code != 200 || dig(out, "data", "result", "state") != "pending_step_up" {
		t.Fatalf("Slack answer: %d %v", code, out)
	}
	// The same request again is a replay.
	if code, _ := app.postAck(body, ts, sig); code != 401 {
		t.Fatalf("replay: %d", code)
	}
	got, _ := services.NewAgentAskService(db).Get(ctx, a.ws, a.approver, id)
	if got.State != "pending_step_up" || got.PendingChoice == nil || *got.PendingChoice != "stop" || got.AnsweredBy != nil {
		t.Fatalf("pending: %+v", got)
	}
	api := newAskAPI(t, db)
	adminM := askMembership(t, db, a.ws, a.admin)
	if code, out := api.as(a.ws, a.admin, adminM).do("POST", "/agent-runtime/asks/"+id.String()+"/confirm", nil); code != 403 ||
		askErrCode(out) != services.GovCodeStepUpOtherPerson {
		t.Fatalf("another person confirmed: %d %v", code, out)
	}
	code, out = api.as(a.ws, a.approver, a.approverM).do("POST", "/agent-runtime/asks/"+id.String()+"/confirm", nil)
	if code != 200 || aiData(out)["state"] != "answered" || aiData(out)["answer_channel"] != "slack" || aiData(out)["answer_choice"] != "stop" {
		t.Fatalf("confirm: %d %v", code, out)
	}
	// Another workspace cannot confirm it.
	b := aiSeed(t, db, "askt")
	askCleanup(t, db, b.ws)
	if code, _ := api.as(b.ws, b.human, b.membership).do("POST", "/agent-runtime/asks/"+id.String()+"/confirm", nil); code != 404 {
		t.Fatal("B confirmed A's ask")
	}

	// Tier 1 from Slack takes effect at once; the clicker must be the
	// notice's recipient.
	id1 := raise(1)
	var p1 []string
	for _, p := range app.fake.PostsTo("UAPPR") {
		p1 = append(p1, p.TS)
	}
	post = app.fake.PostsTo("UAPPR")[len(p1)-1]
	btn = p3sButtons(post)
	if code, _ := click("UHUMAN", "ask_choice_0", btn["ask_choice_0"]); code != 403 {
		t.Fatalf("another member clicked the decider's message: %d", code)
	}
	code, out = click("UAPPR", "ask_choice_1", btn["ask_choice_1"])
	if code != 200 || dig(out, "data", "result", "state") != "answered" {
		t.Fatalf("tier-1 Slack answer: %d %v", code, out)
	}
	got, _ = services.NewAgentAskService(db).Get(ctx, a.ws, a.approver, id1)
	if got.AnswerChannel == nil || *got.AnswerChannel != "slack" || *got.AnswerChoice != "leave" {
		t.Fatalf("tier-1: %+v", got)
	}
}

/* -------------------------------- connectors ------------------------------ */

type askFakeTool struct {
	mu        sync.Mutex
	srv       *httptest.Server
	calls     []string
	jiraState string
	snState   string
}

func newAskFakeTool(t *testing.T) *askFakeTool {
	f := &askFakeTool{jiraState: "indeterminate", snState: "1"}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		defer f.mu.Unlock()
		call := r.Method + " " + r.URL.Path
		if ea, ok := body["event_action"].(string); ok {
			call += " " + ea
		}
		f.calls = append(f.calls, call)
		switch {
		case r.URL.Path == "/rest/api/3/issue" && r.Method == "POST":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"1","key":"SEC-1"}`))
		case strings.HasPrefix(r.URL.Path, "/rest/api/3/issue/"):
			_, _ = fmt.Fprintf(w, `{"key":"SEC-1","fields":{"status":{"name":"X","statusCategory":{"key":%q}}}}`, f.jiraState)
		case r.URL.Path == "/api/now/table/incident" && r.Method == "POST":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"result":{"sys_id":"sys1","number":"INC001","state":"1"}}`))
		case strings.HasPrefix(r.URL.Path, "/api/now/table/incident/"):
			_, _ = fmt.Fprintf(w, `{"result":{"sys_id":"sys1","number":"INC001","state":%q}}`, f.snState)
		case r.URL.Path == "/v2/enqueue":
			w.WriteHeader(202)
			_, _ = fmt.Fprintf(w, `{"status":"success","dedup_key":%q}`, body["dedup_key"])
		case strings.HasPrefix(r.URL.Path, "/v2/alerts"):
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"result":"ok"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *askFakeTool) has(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

func askExternals(t *testing.T, db *gorm.DB, ws uuid.UUID, where string, args ...any) []services.AgentAskExternalVw {
	t.Helper()
	var out []services.AgentAskExternalVw
	db.Raw(`SELECT id, provider, kind, ask_id, case_id, external_key, external_url, state, last_status, attempts, last_error,
		created_at, updated_at, resolved_at FROM agent_ask_external WHERE workspace_id = ? AND `+where+` ORDER BY provider`,
		append([]any{ws}, args...)...).Scan(&out)
	return out
}

func TestAgentAskTicketingAndPaging(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "askc")
	b := aiSeed(t, db, "askd")
	askCleanup(t, db, a.ws, b.ws)
	aiLink(t, db, a.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	tool := newAskFakeTool(t)
	kv := newP3sKV()
	t.Cleanup(services.SetAgentAskVault(kv))
	t.Cleanup(services.SetAgentAskHTTPClient(tool.srv.Client()))
	t.Cleanup(services.SetAgentAskProviderBases(map[string]string{"pagerduty": tool.srv.URL, "opsgenie": tool.srv.URL}))
	api := newAskAPI(t, db)
	adminM := askMembership(t, db, a.ws, a.admin)
	admin := api.as(a.ws, a.admin, adminM)
	human := api.as(a.ws, a.human, a.membership)
	ctx := context.Background()
	svc := services.NewAgentAskService(db)

	const jiraToken, pdKey = "jira-api-token-SECRET-1234", "pd-routing-key-SECRET-9876"
	code, out := admin.do("PUT", "/integrations/ticketing/jira", map[string]any{"secret": jiraToken, "config": map[string]any{
		"site_url": tool.srv.URL, "email": "bot@acme.test", "project_key": "SEC", "create_for": "both"}})
	if code != 200 {
		t.Fatalf("jira: %d %v", code, out)
	}
	if code, out := admin.do("PUT", "/integrations/paging/pagerduty", map[string]any{"secret": pdKey}); code != 200 {
		t.Fatalf("pagerduty: %d %v", code, out)
	}
	if code, _ := admin.do("PUT", "/integrations/paging/jira", map[string]any{"secret": "x"}); code != 404 {
		t.Fatal("jira accepted as paging")
	}
	if code, _ := admin.do("PUT", "/integrations/ticketing/servicenow", map[string]any{"config": map[string]any{
		"instance_url": tool.srv.URL, "username": "svc"}}); code != 400 {
		t.Fatal("an integration without its secret")
	}
	// The secret is in Vault only: never returned, never in the row.
	_, out = admin.do("GET", "/integrations/ticketing", nil)
	raw, _ := json.Marshal(out)
	var row struct{ SecretRef, Config string }
	db.Raw(`SELECT secret_ref, config::text AS config FROM agent_ask_integration WHERE workspace_id = ? AND provider = 'jira'`, a.ws).Scan(&row)
	if strings.Contains(string(raw), jiraToken) || strings.Contains(row.Config, jiraToken) || strings.Contains(row.SecretRef, jiraToken) ||
		!strings.HasPrefix(row.SecretRef, "kv/data/secret/workspaces/"+a.ws.String()+"/") {
		t.Fatalf("secret leaked or misplaced: %s / %+v", raw, row)
	}
	if s, _ := kv.ReadSecret(row.SecretRef); s["secret"] != jiraToken {
		t.Fatal("secret not in Vault")
	}
	if _, out := api.as(b.ws, b.human, b.membership).do("GET", "/integrations/ticketing", nil); len(out["data"].([]any)) != 0 {
		t.Fatal("B sees A's integration")
	}
	if code, _ := api.as(b.ws, b.human, b.membership).do("DELETE", "/integrations/ticketing/jira", nil); code != 404 {
		t.Fatal("B deleted A's integration")
	}

	// A high-severity ask: a Jira issue and a PagerDuty incident.
	alert := askAlert(t, db, a, "high")
	ask := askCreate(t, human, askBody("alert", alert.String()))
	askID := uuid.MustParse(ask["id"].(string))
	items := askExternals(t, db, a.ws, "ask_id = ?", askID)
	if len(items) != 2 || items[0].Provider != "jira" || items[1].Provider != "pagerduty" || items[0].State != "pending" {
		t.Fatalf("queued items %+v", items)
	}
	for _, it := range items {
		if err := svc.SyncExternal(ctx, a.ws, it.ID); err != nil {
			t.Fatal(err)
		}
	}
	if !tool.has("POST /rest/api/3/issue") || !tool.has("POST /v2/enqueue trigger") {
		t.Fatalf("calls %v", tool.calls)
	}
	items = askExternals(t, db, a.ws, "ask_id = ?", askID)
	if items[0].State != "open" || items[0].ExternalKey != "SEC-1" || items[1].State != "open" || items[1].ExternalKey == "" {
		t.Fatalf("opened %+v", items)
	}
	// The ticket resolved externally closes the link only: the ask stays open.
	tool.mu.Lock()
	tool.jiraState = "done"
	tool.mu.Unlock()
	if err := svc.SyncExternal(ctx, a.ws, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if it := askExternals(t, db, a.ws, "id = ?", items[0].ID); it[0].State != "resolved" || it[0].ResolvedAt == nil {
		t.Fatalf("ticket %+v", it)
	}
	got, _ := svc.Get(ctx, a.ws, a.admin, askID)
	if got.State != "open" {
		t.Fatalf("a resolved ticket answered the ask: %s", got.State)
	}
	// Answering the ask resolves its page.
	if code, out := admin.do("POST", "/agent-runtime/asks/"+askID.String()+"/answer", map[string]any{"choice": "keep"}); code != 200 {
		t.Fatalf("answer: %d %v", code, out)
	}
	if it := askExternals(t, db, a.ws, "id = ?", items[1].ID); it[0].State != "resolving" {
		t.Fatalf("page after the answer %+v", it)
	}
	if err := svc.SyncExternal(ctx, a.ws, items[1].ID); err != nil {
		t.Fatal(err)
	}
	if it := askExternals(t, db, a.ws, "id = ?", items[1].ID); it[0].State != "resolved" || !tool.has("POST /v2/enqueue resolve") {
		t.Fatalf("page resolved %+v %v", it, tool.calls)
	}
	got, _ = svc.Get(ctx, a.ws, a.admin, askID)
	var ek []string
	for _, e := range got.Events {
		ek = append(ek, e.Kind)
	}
	for _, want := range []string{"ticket_opened", "paged", "ticket_resolved", "answered", "page_resolved"} {
		if !strings.Contains(strings.Join(ek, ","), want) {
			t.Fatalf("ask log %v lacks %s", ek, want)
		}
	}
	// A medium ask is ticketed but not paged.
	if ask := askCreate(t, human, askBody("agent", wa.String())); len(askExternals(t, db, a.ws, "ask_id = ?", uuid.MustParse(ask["id"].(string)))) != 1 {
		t.Fatal("a medium ask was paged")
	}

	// ServiceNow and Opsgenie, and a case ticket; the case shows its asks.
	if code, out := admin.do("PUT", "/integrations/ticketing/servicenow", map[string]any{"secret": "sn-pass", "config": map[string]any{
		"instance_url": tool.srv.URL, "username": "svc", "create_for": "cases"}}); code != 200 {
		t.Fatalf("servicenow: %d %v", code, out)
	}
	if code, _ := admin.do("PUT", "/integrations/paging/opsgenie", map[string]any{"secret": "og-key", "config": map[string]any{"region": "eu"}}); code != 200 {
		t.Fatal("opsgenie")
	}
	caseID := uuid.New()
	arExec(t, db, `INSERT INTO agent_case (id, workspace_id, number, title, severity, opened_by) VALUES (?, ?, 1, 'Secret read', 'high', 'system')`,
		caseID, a.ws)
	code, out = human.do("POST", "/agent-runtime/cases/"+caseID.String()+"/tickets", map[string]any{"provider": "servicenow"})
	if code != 200 {
		t.Fatalf("case ticket: %d %v", code, out)
	}
	cid := uuid.MustParse(aiData(out)["id"].(string))
	if err := svc.SyncExternal(ctx, a.ws, cid); err != nil {
		t.Fatal(err)
	}
	tool.mu.Lock()
	tool.snState = "6"
	tool.mu.Unlock()
	if err := svc.SyncExternal(ctx, a.ws, cid); err != nil {
		t.Fatal(err)
	}
	if it := askExternals(t, db, a.ws, "id = ?", cid); it[0].State != "resolved" || it[0].ExternalKey != "sys1" {
		t.Fatalf("servicenow case ticket %+v", it)
	}
	if code, _ := api.as(b.ws, b.human, b.membership).do("POST", "/agent-runtime/cases/"+caseID.String()+"/tickets",
		map[string]any{"provider": "servicenow"}); code != 404 {
		t.Fatal("B ticketed A's case")
	}
	caseAsk := askCreate(t, human, askBody("case", caseID.String()))
	if caseAsk["case_id"] != caseID.String() || caseAsk["severity"] != "high" {
		t.Fatalf("case ask %v", caseAsk)
	}
	og := askExternals(t, db, a.ws, "ask_id = ? AND provider = 'opsgenie'", uuid.MustParse(caseAsk["id"].(string)))
	if len(og) != 1 {
		t.Fatal("a high case ask was not paged on Opsgenie")
	}
	if err := svc.SyncExternal(ctx, a.ws, og[0].ID); err != nil || !tool.has("POST /v2/alerts") {
		t.Fatalf("opsgenie trigger %v %v", err, tool.calls)
	}
	cv, err := services.NewAgentCaseService(db).Get(ctx, a.ws, caseID)
	if err != nil || len(cv.Asks) != 1 || cv.Asks[0].ID.String() != caseAsk["id"] {
		t.Fatalf("case asks %+v %v", cv, err)
	}
	if _, err := services.NewAgentCaseService(db).Get(ctx, b.ws, caseID); err == nil {
		t.Fatal("B read A's case")
	}

	// The production client (internal/safehttp) refuses a site on a
	// loopback address: the item fails at once, nothing is sent.
	t.Setenv("MCP_ALLOW_LOOPBACK", "")
	t.Setenv("OUTBOUND_ALLOWED_CIDRS", "")
	t.Setenv("OUTBOUND_ALLOWED_HOSTS", "")
	services.SetAgentAskHTTPClient(nil)
	tool.mu.Lock()
	n := len(tool.calls)
	tool.mu.Unlock()
	blocked := askCreate(t, human, askBody("agent", wa.String()))
	bi := askExternals(t, db, a.ws, "ask_id = ?", uuid.MustParse(blocked["id"].(string)))
	if err := svc.SyncExternal(ctx, a.ws, bi[0].ID); err != nil {
		t.Fatal(err)
	}
	if it := askExternals(t, db, a.ws, "id = ?", bi[0].ID); it[0].State != "failed" || !strings.Contains(it[0].LastError, "not allowed") {
		t.Fatalf("blocked site: %+v", it)
	}
	tool.mu.Lock()
	if len(tool.calls) != n {
		t.Fatal("a request reached the loopback site through the safe client")
	}
	tool.mu.Unlock()
	if len(aiEvents(t, db, a.ws, services.GovEventAskExternalFailed)) == 0 {
		t.Fatal("no failure event")
	}

	// Removing the integration destroys its secret.
	if code, _ := admin.do("DELETE", "/integrations/ticketing/jira", nil); code != 200 {
		t.Fatal("delete")
	}
	if s, _ := kv.ReadSecret(row.SecretRef); s != nil && s["secret"] != nil {
		t.Fatal("the secret survived the removal")
	}
}

/* ----------------------------- ask_needed -> ask ---------------------------- */

func TestAgentAskNeededRaisesAsks(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "askn")
	b := aiSeed(t, db, "asko")
	askCleanup(t, db, a.ws, b.ws)
	aiLink(t, db, a.ws)
	aiLink(t, db, b.ws)
	ctx := context.Background()
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	arExec(t, db, `UPDATE discovered_agents SET runtime_status = 'gone' WHERE id = ?`, a.sighting)
	if r, err := services.RunAgentIdentitySweep(ctx, db, a.ws, time.Now()); err != nil || r.DeletedAtSource != 1 {
		t.Fatalf("sweep %+v %v", r, err)
	}
	if len(aiEvents(t, db, a.ws, services.GovEventAgentAskNeeded)) != 1 {
		t.Fatal("the event is still written")
	}
	asks, _, err := services.NewAgentAskService(db).List(ctx, a.ws, a.admin, services.AgentAskFilter{AboutKind: "agent", AboutID: sa.String()})
	if err != nil || len(asks) != 1 || asks[0].CreatedByKind != "system" || asks[0].Severity != "low" || asks[0].State != "open" {
		t.Fatalf("deleted-at-source ask %+v %v", asks, err)
	}
	if !strings.Contains(string(asks[0].Context), services.AskReasonDeletedAtSource) {
		t.Fatalf("context %s", asks[0].Context)
	}
	// Idempotent per agent and reason.
	sweepAgain := services.AskInput{AboutKind: "agent", AboutID: sa.String(), Question: "q?", DedupeKey: "agent:" + sa.String() + ":deleted_at_source",
		Choices: []services.AskChoice{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	id2, err := services.CreateAsk(ctx, db, a.ws, sweepAgain)
	if err != nil || id2 != asks[0].ID {
		t.Fatalf("dedupe: %s vs %s (%v)", id2, asks[0].ID, err)
	}
	// The leaver's ask never goes to the leaver.
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	askGroup(t, db, a.ws, a.human, a.approver, "Account responders", "account", a.account)
	dir := services.NewDirectoryService(db)
	active, inactive := true, false
	em := "ravi-askn@test.local"
	if _, _, err := dir.Upsert(ctx, a.ws, services.DirectoryPersonInput{Source: "scim", ExternalID: "ravi", Email: &em, Active: &active}); err != nil {
		t.Fatal(err)
	}
	if _, n, err := dir.Upsert(ctx, a.ws, services.DirectoryPersonInput{Source: "scim", ExternalID: "ravi", Active: &inactive}); err != nil || n != 1 {
		t.Fatalf("leaver %d %v", n, err)
	}
	asks, _, _ = services.NewAgentAskService(db).List(ctx, a.ws, uuid.Nil, services.AgentAskFilter{AboutKind: "agent", AboutID: wa.String()})
	if len(asks) != 1 || asks[0].Severity != "medium" {
		t.Fatalf("leaver ask %+v", asks)
	}
	for _, d := range asks[0].Deciders {
		if d == a.approver {
			t.Fatal("the leaver decides the ask about their own departure")
		}
	}
	// Nothing in B.
	if bs, _, _ := services.NewAgentAskService(db).List(ctx, b.ws, uuid.Nil, services.AgentAskFilter{}); len(bs) != 0 {
		t.Fatalf("A's asks raised in B: %d", len(bs))
	}
}
