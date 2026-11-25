package integration

// One agent id, lifecycle, classification, directory, responder groups and
// hygiene (SPEC-secops-backend-upgrade.md W7) against a real database:
// alias linking and its idempotent backfill; endings move every alias; merge
// re-points aliases; "not an agent" needs a reason; instances and an unknown
// deployer; lowering a risk class or a classification needs a second person
// with governance:approve; the leaver raises agent.ask_needed; responder
// resolution precedence and delegation; the stale-agent and overdue-key
// sweep; deleted at source. Every route is exercised from two workspaces:
// A never reads or changes B's rows (404).
//
// Needs IGA_TEST_DSN (skipped otherwise).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// aiWorld is one workspace with agents from three sources.
type aiWorld struct {
	ws, conn   uuid.UUID
	account    string
	workload   uuid.UUID // iga_workload classified_agent, supported by conn
	mirror     uuid.UUID // discovered_agents AWS mirror of workload
	sighting   uuid.UUID // a standalone k8s sighting
	igaAgent   uuid.UUID // iga_agents row
	linked     uuid.UUID // discovered_agents accepted-linked to igaAgent
	identity   uuid.UUID // cloud_identity of the workload
	human      uuid.UUID
	membership uuid.UUID
	approver   uuid.UUID // second person with governance:approve
	approverM  uuid.UUID
	admin      uuid.UUID // holds the role named admin
}

func aiSeed(t *testing.T, db *gorm.DB, name string) *aiWorld {
	t.Helper()
	w := &aiWorld{ws: newWorkspace(t, db, name), conn: uuid.New(), account: fmt.Sprintf("%012d", time.Now().UnixNano()%1e12)}
	arExec(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
		VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault://aws/test')`, w.conn, w.ws, w.account)
	t.Cleanup(func() {
		for _, tbl := range []string{"agent_hygiene_finding", "agent_pending_change", "responder_group", "directory_person", "agent",
			"iga_agent_instances", "discovered_agent_iga_links", "iga_agents", "iga_object_support", "iga_workload", "discovered_agents",
			"cloud_usage", "cloud_secret", "cloud_resource", "cloud_identity", "cloud_connector"} {
			db.Exec(`DELETE FROM `+tbl+` WHERE workspace_id = ?`, w.ws)
		}
	})
	w.identity = uuid.New()
	arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
		VALUES (?, ?, ?, 'iam_role', ?, 'bot-role', '{}'::jsonb)`, w.identity, w.ws, w.conn, "arn:aws:iam::"+w.account+":role/bot-role-"+name)
	w.workload = uuid.New()
	arExec(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
		VALUES (?, ?, 'lambda_function', ?, 'us-east-1', ?, 'classified_agent')`, w.workload, w.ws, "bot-"+name, "ai-test\x1f"+w.workload.String())
	arExec(t, db, `INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key) VALUES (?, ?, ?, 'ai-test')`,
		w.ws, w.workload, w.conn)
	sighting := func(source, fp string, md map[string]any) uuid.UUID {
		id := uuid.New()
		raw, _ := json.Marshal(md)
		arExec(t, db, `INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name, metadata)
			VALUES (?, ?, ?, ?, ?, ?::jsonb)`, id, w.ws, source, fp, fp, string(raw))
		return id
	}
	w.mirror = sighting("aws", "aws:"+name+":mirror", map[string]any{"iga_workload_id": w.workload.String(), "account_id": w.account})
	w.sighting = sighting("k8s_webhook", "k8s:"+name+":standalone", map[string]any{})
	w.igaAgent = uuid.New()
	arExec(t, db, `INSERT INTO iga_agents (id, workspace_id, display_name, rollup_state) VALUES (?, ?, ?, 'confirmed')`, w.igaAgent, w.ws, "estate-"+name)
	w.linked = sighting("repo_scan", "repo:"+name+":linked", map[string]any{})
	arExec(t, db, `INSERT INTO discovered_agent_iga_links (workspace_id, discovered_agent_id, iga_agent_id, state, strength, decided_at) VALUES (?, ?, ?, 'accepted', 'strong', now())`,
		w.ws, w.linked, w.igaAgent)

	n1, n2 := "Priya "+name, "Ravi "+name
	w.human, w.membership = classMember(t, db, w.ws, &n1, "priya-"+name+"@test.local", "active")
	w.approver, w.approverM = classMember(t, db, w.ws, &n2, "ravi-"+name+"@test.local", "active")
	arExec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT m.role_id, p.id FROM workspace_memberships m, permissions p
		 WHERE m.id = ? AND p.resource = 'governance' AND p.action = 'approve' AND p.workspace_id IS NULL
		ON CONFLICT DO NOTHING`, w.approverM)
	// An admin (role named admin) for the default responder group.
	n3 := "Asha " + name
	var adminM uuid.UUID
	w.admin, adminM = classMember(t, db, w.ws, &n3, "asha-"+name+"@test.local", "active")
	arExec(t, db, `UPDATE roles SET name = 'admin' WHERE id = (SELECT role_id FROM workspace_memberships WHERE id = ?)`, adminM)
	return w
}

func aiLink(t *testing.T, db *gorm.DB, ws uuid.UUID) int {
	t.Helper()
	n, err := services.LinkAgentSourcesInWorkspace(context.Background(), db, ws, "", "")
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	return n
}

func aiAgentOf(t *testing.T, db *gorm.DB, ws uuid.UUID, table string, id uuid.UUID) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	db.Raw(`SELECT agent_id FROM agent_alias WHERE workspace_id = ? AND source_table = ? AND source_id = ?`, ws, table, id.String()).Scan(&ids)
	if len(ids) != 1 {
		t.Fatalf("%s %s: %d aliases, want 1", table, id, len(ids))
	}
	return ids[0]
}

// aiAPI is the route table with the token's workspace and claims set.
type aiAPI struct {
	t        *testing.T
	eng      *gin.Engine
	ws       uuid.UUID
	claims   map[string]string
	lastPerm string
}

func newAIAPI(t *testing.T, db *gorm.DB) *aiAPI {
	gin.SetMode(gin.TestMode)
	a := &aiAPI{t: t, claims: map[string]string{}}
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
	platform.RegisterAgentIdentityRoutes(g, platform.NewAgentIdentityControllerWith(db), func(resource, action string) gin.HandlerFunc {
		return func(c *gin.Context) { a.lastPerm = resource + ":" + action; c.Next() }
	})
	a.eng = eng
	return a
}

func (a *aiAPI) as(ws, user, membership uuid.UUID) *aiAPI {
	a.ws = ws
	a.claims = map[string]string{"user_id": user.String(), "workspace_membership_id": membership.String(), "client_id": "console"}
	return a
}

func (a *aiAPI) do(method, path string, body any) (int, map[string]any) {
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

func aiData(b map[string]any) map[string]any { m, _ := b["data"].(map[string]any); return m }

func aiEvents(t *testing.T, db *gorm.DB, ws uuid.UUID, name string) []map[string]any {
	t.Helper()
	var raws []string
	db.Raw(`SELECT payload::text FROM iga_gov_event WHERE workspace_id = ? AND event = ? ORDER BY id`, ws, name).Scan(&raws)
	out := []map[string]any{}
	for _, r := range raws {
		var m map[string]any
		_ = json.Unmarshal([]byte(r), &m)
		out = append(out, m)
	}
	return out
}

func TestAgentIdentityLinkingAndBackfill(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aila")
	b := aiSeed(t, db, "ailb")

	if n := aiLink(t, db, a.ws); n != 5 {
		t.Fatalf("A linked %d aliases, want 5 (workload, mirror, sighting, linked sighting, iga agent)", n)
	}
	var bAliases int64
	db.Raw(`SELECT count(*) FROM agent_alias WHERE workspace_id = ?`, b.ws).Scan(&bAliases)
	if bAliases != 0 {
		t.Fatalf("linking A wrote %d aliases in B", bAliases)
	}
	// The AWS mirror joins its workload's agent; the accepted link joins the
	// iga agent's; the standalone sighting is an agent of its own.
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	if m := aiAgentOf(t, db, a.ws, "discovered_agents", a.mirror); m != wa {
		t.Fatalf("mirror agent %s, workload agent %s", m, wa)
	}
	ga := aiAgentOf(t, db, a.ws, "iga_agents", a.igaAgent)
	if l := aiAgentOf(t, db, a.ws, "discovered_agents", a.linked); l != ga {
		t.Fatalf("linked sighting agent %s, iga agent %s", l, ga)
	}
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	if sa == wa || sa == ga || wa == ga {
		t.Fatalf("distinct sources share an agent: %s %s %s", wa, ga, sa)
	}
	var agents int64
	db.Raw(`SELECT count(*) FROM agent WHERE workspace_id = ?`, a.ws).Scan(&agents)
	if agents != 3 {
		t.Fatalf("A has %d agents, want 3", agents)
	}
	// Idempotent: a second pass (the sweep, the backfill) links nothing.
	if n := aiLink(t, db, a.ws); n != 0 {
		t.Fatalf("second link pass wrote %d aliases", n)
	}
	// The backfill function as the migration runs it (all workspaces).
	if err := db.Exec(`SELECT public.agent_identity_link(id) FROM workspaces WHERE id IN (?, ?)`, a.ws, b.ws).Error; err != nil {
		t.Fatalf("backfill: %v", err)
	}
	db.Raw(`SELECT count(*) FROM agent_alias WHERE workspace_id = ?`, b.ws).Scan(&bAliases)
	if bAliases != 5 {
		t.Fatalf("backfill linked %d of B's aliases, want 5", bAliases)
	}
	// A classification undo with its reason ends the workload's agent too
	// once the workload is its only source ("not an agent" on AWS).
	wl2 := uuid.New()
	arExec(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
		VALUES (?, ?, 'lambda_function', 'solo', 'us-east-1', ?, 'unclassified')`, wl2, a.ws, "ai-test\x1f"+wl2.String())
	arExec(t, db, `INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key) VALUES (?, ?, ?, 'ai-test')`, a.ws, wl2, a.conn)
	ctx := tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: a.ws})
	cls := services.NewClassificationService(db)
	res, err := cls.Classify(ctx, services.ClassifyRequest{WorkloadID: wl2, ActorUserID: a.human, OperationID: uuid.New(),
		Decision: "classified_agent", Reason: "calls a model", ExpectedVersion: 0})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	solo := aiAgentOf(t, db, a.ws, "iga_workload", wl2)
	latest := res.Decision.ID
	if _, err := cls.Classify(ctx, services.ClassifyRequest{WorkloadID: wl2, ActorUserID: a.human, OperationID: uuid.New(),
		Decision: "unclassified", Reason: "a batch job, no autonomy", ExpectedVersion: 1, UndoesDecisionID: &latest}); err != nil {
		t.Fatalf("undo: %v (%+v)", err, res)
	}
	var st struct{ State, EndedReason string }
	db.Raw(`SELECT state, ended_reason FROM agent WHERE id = ?`, solo).Scan(&st)
	if st.State != "not_an_agent" || st.EndedReason != "a batch job, no autonomy" {
		t.Fatalf("undone workload's agent: %+v", st)
	}
}

func TestAgentIdentityEndingsAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aiea")
	b := aiSeed(t, db, "aieb")
	aiLink(t, db, a.ws)
	aiLink(t, db, b.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	ga := aiAgentOf(t, db, a.ws, "iga_agents", a.igaAgent)
	wb := aiAgentOf(t, db, b.ws, "iga_workload", b.workload)

	api := newAIAPI(t, db).as(a.ws, a.human, a.membership)
	code, body := api.do("GET", "/agent-identities", nil)
	if code != 200 || len(body["data"].([]any)) != 3 || api.lastPerm != "discovery:read" {
		t.Fatalf("list: %d %v", code, body)
	}
	if raw, _ := json.Marshal(body); strings.Contains(string(raw), wb.String()) {
		t.Fatal("A's list shows B's agent")
	}
	code, body = api.do("GET", "/agent-identities/"+wa.String(), nil)
	if code != 200 || len(aiData(body)["aliases"].([]any)) != 2 {
		t.Fatalf("detail: %d %v", code, body)
	}
	// B's agent is not found from A, on every route.
	for _, r := range []struct{ m, p string }{{"GET", "/agent-identities/" + wb.String()}, {"POST", "/agent-identities/" + wb.String() + "/retire"},
		{"PUT", "/agent-identities/" + wb.String() + "/risk-class"}, {"PUT", "/agent-identities/" + wb.String() + "/purpose"},
		{"GET", "/agent-identities/" + wb.String() + "/responder"}, {"POST", "/agent-identities/" + wb.String() + "/deployers"}} {
		if code, _ := api.do(r.m, r.p, map[string]any{"reason": "x"}); code != 404 {
			t.Errorf("%s %s from A: %d, want 404", r.m, r.p, code)
		}
	}
	// Reason required on every ending.
	for _, act := range []string{"retire", "not-an-agent", "transfer", "merge"} {
		if code, body := api.do("POST", "/agent-identities/"+sa.String()+"/"+act, map[string]any{}); code != 400 {
			t.Errorf("%s without reason: %d %v", act, code, body)
		}
	}
	// A machine token never decides.
	machine := newAIAPI(t, db)
	machine.ws = a.ws
	machine.claims = map[string]string{"user_id": a.human.String(), "client_id": "svc"}
	if code, _ := machine.do("POST", "/agent-identities/"+sa.String()+"/retire", map[string]any{"reason": "x"}); code != 403 {
		t.Errorf("machine retire: %d", code)
	}
	// Merge: the iga agent into the workload agent. Every alias moves.
	code, body = api.do("POST", "/agent-identities/"+ga.String()+"/merge", map[string]any{"reason": "same bot", "merge_into": wb.String()})
	if code != 400 {
		t.Fatalf("merge into B's agent: %d %v", code, body)
	}
	code, body = api.do("POST", "/agent-identities/"+ga.String()+"/merge", map[string]any{"reason": "same bot", "merge_into": wa.String()})
	if code != 200 || aiData(body)["state"] != "merged" || aiData(body)["merged_into"] != wa.String() {
		t.Fatalf("merge: %d %v", code, body)
	}
	if got := aiAgentOf(t, db, a.ws, "iga_agents", a.igaAgent); got != wa {
		t.Fatalf("merged alias points at %s, want survivor %s", got, wa)
	}
	if got := aiAgentOf(t, db, a.ws, "discovered_agents", a.linked); got != wa {
		t.Fatalf("merged linked sighting points at %s", got)
	}
	// Retire the survivor: one decision, every alias (now four) follows.
	code, body = api.do("POST", "/agent-identities/"+wa.String()+"/retire", map[string]any{"reason": "decommissioned"})
	if code != 200 || aiData(body)["state"] != "retired" {
		t.Fatalf("retire: %d %v", code, body)
	}
	ev := aiEvents(t, db, a.ws, services.GovEventAgentRetired)
	if len(ev) != 1 || len(ev[0]["aliases"].([]any)) != 4 {
		t.Fatalf("retire event: %v", ev)
	}
	if code, _ := api.do("POST", "/agent-identities/"+wa.String()+"/transfer", map[string]any{"reason": "x", "transfer_to": "y"}); code != 409 {
		t.Errorf("ending an ended agent: %d", code)
	}
	code, body = api.do("POST", "/agent-identities/"+sa.String()+"/not-an-agent", map[string]any{"reason": "a cron job"})
	if code != 200 || aiData(body)["state"] != "not_an_agent" {
		t.Fatalf("not an agent: %d %v", code, body)
	}
	var bState string
	db.Raw(`SELECT state FROM agent WHERE id = ?`, wb).Scan(&bState)
	if bState != "active" {
		t.Fatalf("B's agent changed: %s", bState)
	}
}

func TestAgentRiskAndClassificationSecondPerson(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aira")
	b := aiSeed(t, db, "airb")
	aiLink(t, db, a.ws)
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	api := newAIAPI(t, db).as(a.ws, a.human, a.membership)

	if code, body := api.do("PUT", "/agent-identities/"+sa.String()+"/purpose", map[string]any{"purpose": "Triage support tickets"}); code != 200 {
		t.Fatalf("purpose: %d %v", code, body)
	}
	code, body := api.do("PUT", "/agent-identities/"+sa.String()+"/risk-class",
		map[string]any{"risk_class": "high", "obligations": []string{"human oversight"}, "reason": "touches customer data"})
	if code != 200 || aiData(body)["applied"] == nil || api.lastPerm != "governance:author" {
		t.Fatalf("raise: %d %v", code, body)
	}
	code, body = api.do("PUT", "/agent-identities/"+sa.String()+"/risk-class", map[string]any{"risk_class": "limited", "reason": "scope narrowed"})
	pc, _ := aiData(body)["pending_change"].(map[string]any)
	if code != 200 || pc == nil || aiData(body)["applied"] != nil {
		t.Fatalf("lower is not pending: %d %v", code, body)
	}
	pcID := pc["id"].(string)
	// The requester cannot approve; another member without governance:approve
	// cannot; B cannot see it; the approver applies it.
	if code, body := api.do("POST", "/agent-changes/"+pcID+"/approve", nil); code != 403 || body["error"].(map[string]any)["code"] != "self_approval" {
		t.Fatalf("self approval: %d %v", code, body)
	}
	other := newAIAPI(t, db).as(a.ws, a.admin, uuid.Nil)
	var adminM uuid.UUID
	db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, a.ws, a.admin).Scan(&adminM)
	other.as(a.ws, a.admin, adminM)
	if code, _ := other.do("POST", "/agent-changes/"+pcID+"/approve", nil); code != 403 {
		t.Fatalf("approve without governance:approve: %d", code)
	}
	apiB := newAIAPI(t, db).as(b.ws, b.approver, b.approverM)
	if code, _ := apiB.do("POST", "/agent-changes/"+pcID+"/approve", nil); code != 404 {
		t.Fatalf("B approving A's change: %d", code)
	}
	approver := newAIAPI(t, db).as(a.ws, a.approver, a.approverM)
	if code, body := approver.do("POST", "/agent-changes/"+pcID+"/approve", map[string]any{"reason": "agreed"}); code != 200 || aiData(body)["state"] != "applied" {
		t.Fatalf("approve: %d %v", code, body)
	}
	code, body = api.do("GET", "/agent-identities/"+sa.String(), nil)
	rc := aiData(body)["risk_class"].(map[string]any)
	if code != 200 || rc["risk_class"] != "limited" || rc["approved_by_user_id"] != a.approver.String() {
		t.Fatalf("after approval: %v", rc)
	}

	// Resource classification: raise applies (tier 0), lower waits.
	res := uuid.New()
	arExec(t, db, `INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 's3_bucket', ?, 'pii')`,
		res, a.ws, a.conn, "arn:aws:s3:::pii-"+a.account)
	resB := uuid.New()
	arExec(t, db, `INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 's3_bucket', ?, 'b')`,
		resB, b.ws, b.conn, "arn:aws:s3:::b-"+b.account)
	if code, _ := api.do("PUT", "/resources/"+resB.String()+"/classification", map[string]any{"sensitivity": "high", "reason": "x"}); code != 404 {
		t.Fatalf("A classifying B's resource: %d", code)
	}
	if code, _ := api.do("GET", "/resources/"+resB.String()+"/classification", nil); code != 404 {
		t.Fatalf("A reading B's classification: %d", code)
	}
	code, body = api.do("PUT", "/resources/"+res.String()+"/classification",
		map[string]any{"sensitivity": "high", "crown_jewel": true, "data_category": "PII", "residency": "EU", "reason": "customer records"})
	ap, _ := aiData(body)["applied"].(map[string]any)
	if code != 200 || ap == nil || ap["sensitivity_source"] != "customer_classification" || ap["crown_jewel"] != true || ap["data_category"] != "pii" {
		t.Fatalf("raise classification: %d %v", code, body)
	}
	code, body = api.do("PUT", "/resources/"+res.String()+"/classification", map[string]any{"crown_jewel": false, "reason": "archived"})
	pc, _ = aiData(body)["pending_change"].(map[string]any)
	if code != 200 || pc == nil {
		t.Fatalf("lower classification is not pending: %d %v", code, body)
	}
	var cj bool
	db.Raw(`SELECT crown_jewel FROM cloud_resource WHERE id = ?`, res).Scan(&cj)
	if !cj {
		t.Fatal("a lowering applied without a second person")
	}
	if code, _ := approver.do("POST", "/agent-changes/"+pc["id"].(string)+"/approve", nil); code != 200 {
		t.Fatalf("approve lowering: %d", code)
	}
	db.Raw(`SELECT crown_jewel FROM cloud_resource WHERE id = ?`, res).Scan(&cj)
	if cj {
		t.Fatal("approved lowering not applied")
	}
}

func TestAgentInstancesAndUnknownDeployer(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aiia")
	b := aiSeed(t, db, "aiib")
	aiLink(t, db, a.ws)
	aiLink(t, db, b.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	ctx := context.Background()
	record := func(ws uuid.UUID, src uuid.UUID, digest, deployer string) services.AgentInstanceOutcome {
		var out services.AgentInstanceOutcome
		if err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
			var err error
			out, err = services.RecordAgentInstance(tx, ws, services.AgentInstanceObservation{SourceTable: "iga_workload",
				SourceID: src.String(), NativeWorkloadID: "arn:fn", RuntimeKind: "lambda_function", ArtifactDigest: digest,
				Deployer: deployer, Model: "anthropic.claude", CloudIdentityID: &a.identity})
			return err
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
		return out
	}
	if o := record(a.ws, a.workload, "lambda-sha256:one", "arn:aws:iam::1:role/ci"); !o.Created || o.UnknownDeployer {
		t.Fatalf("first instance: %+v", o)
	}
	if o := record(a.ws, a.workload, "lambda-sha256:one", "arn:aws:iam::1:role/ci"); o.Created {
		t.Fatalf("same digest made a new instance: %+v", o)
	}
	if o := record(a.ws, a.workload, "lambda-sha256:two", "arn:aws:iam::1:user/mallory"); !o.Created || !o.UnknownDeployer {
		t.Fatalf("unknown deployer not flagged: %+v", o)
	}
	// B's workload id under A's workspace names no agent there.
	if o := record(a.ws, b.workload, "x", "y"); o.AgentID != nil {
		t.Fatalf("A recorded an instance of B's workload: %+v", o)
	}
	api := newAIAPI(t, db).as(a.ws, a.human, a.membership)
	code, body := api.do("GET", "/agent-hygiene/findings?kind=unknown_deployer", nil)
	if code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("unknown deployer finding: %d %v", code, body)
	}
	if ev := aiEvents(t, db, a.ws, services.GovEventAgentUnknownDeployer); len(ev) != 1 {
		t.Fatalf("unknown deployer events: %v", ev)
	}
	asks := aiEvents(t, db, a.ws, services.GovEventAgentAskNeeded)
	if len(asks) != 1 || asks[0]["reason"] != services.AskReasonUnknownDeployer {
		t.Fatalf("ask events: %v", asks)
	}
	code, body = api.do("GET", "/agent-identities/"+wa.String(), nil)
	if code != 200 || len(aiData(body)["instances"].([]any)) != 2 {
		t.Fatalf("instances: %d %v", code, body)
	}
	// Recording the deployer resolves the finding.
	if code, body := api.do("POST", "/agent-identities/"+wa.String()+"/deployers", map[string]any{"deployer": "arn:aws:iam::1:user/mallory"}); code != 200 {
		t.Fatalf("record deployer: %d %v", code, body)
	}
	code, body = api.do("GET", "/agent-hygiene/findings?kind=unknown_deployer&state=open", nil)
	if code != 200 || len(body["data"].([]any)) != 0 {
		t.Fatalf("finding still open: %v", body)
	}
	apiB := newAIAPI(t, db).as(b.ws, b.human, b.membership)
	if _, body := apiB.do("GET", "/agent-hygiene/findings", nil); len(body["data"].([]any)) != 0 {
		t.Fatalf("B sees A's findings: %v", body)
	}
}

func TestResponderGroupsResolutionAndLeaver(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aiga")
	b := aiSeed(t, db, "aigb")
	aiLink(t, db, a.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	api := newAIAPI(t, db).as(a.ws, a.human, a.membership)

	// No group yet: the default one is created with the admin.
	code, body := api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	d := aiData(body)
	if code != 200 || d["via"] != "default" || len(d["deciders"].([]any)) != 1 ||
		d["deciders"].([]any)[0].(map[string]any)["user_id"] != a.admin.String() {
		t.Fatalf("default resolution: %d %v", code, body)
	}
	mk := func(name string) string {
		code, body := api.do("POST", "/responder-groups", map[string]any{"name": name})
		if code != 200 {
			t.Fatalf("create %s: %d %v", name, code, body)
		}
		return aiData(body)["id"].(string)
	}
	acct, agentG := mk("Account team"), mk("Agent team")
	if code, _ := api.do("POST", "/responder-groups/"+acct+"/scopes", map[string]any{"scope_kind": "account", "scope_ref": a.account}); code != 200 {
		t.Fatalf("account scope: %d", code)
	}
	if code, body := api.do("POST", "/responder-groups/"+agentG+"/members", map[string]any{"user_id": a.human.String()}); code != 200 {
		t.Fatalf("member: %d %v", code, body)
	}
	if code, _ := api.do("POST", "/responder-groups/"+agentG+"/scopes", map[string]any{"scope_kind": "agent", "scope_ref": wa.String()}); code != 200 {
		t.Fatalf("agent scope: %d", code)
	}
	_, body = api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	if d := aiData(body); d["via"] != "agent" || len(d["deciders"].([]any)) != 0 {
		t.Fatalf("agent group (candidate not yet a decider): %v", d)
	}
	// Only the candidate accepts.
	approver := newAIAPI(t, db).as(a.ws, a.approver, a.approverM)
	if code, _ := approver.do("POST", "/responder-groups/"+agentG+"/accept", nil); code != 403 {
		t.Fatalf("someone else accepting: %d", code)
	}
	if code, _ := api.do("POST", "/responder-groups/"+agentG+"/accept", nil); code != 200 {
		t.Fatalf("accept: %d", code)
	}
	_, body = api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	if dd := aiData(body)["deciders"].([]any); len(dd) != 1 || dd[0].(map[string]any)["user_id"] != a.human.String() {
		t.Fatalf("accepted decider: %v", body)
	}
	// Delegation: the delegate decides until the end date.
	until := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	if code, body := api.do("POST", "/responder-groups/"+agentG+"/delegate", map[string]any{"delegate_to": a.approver.String(), "until": until}); code != 200 {
		t.Fatalf("delegate: %d %v", code, body)
	}
	_, body = api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	if dd := aiData(body)["deciders"].([]any); dd[0].(map[string]any)["user_id"] != a.approver.String() {
		t.Fatalf("delegate not deciding: %v", body)
	}
	if code, _ := api.do("POST", "/responder-groups/"+agentG+"/delegate", map[string]any{}); code != 200 {
		t.Fatalf("end delegation: %d", code)
	}
	// Handover of the agent group's scopes to the account group: the agent
	// scope moves; resolution follows it.
	if code, _ := api.do("POST", "/responder-groups/"+agentG+"/handover", map[string]any{"to_group_id": acct}); code != 200 {
		t.Fatalf("handover: %d", code)
	}
	_, body = api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	if d := aiData(body); d["via"] != "agent" || d["group_id"] != acct {
		t.Fatalf("after handover: %v", d)
	}
	// Remove the agent scope: the account scope (from the supporting
	// connector) decides.
	_, body = api.do("GET", "/responder-groups/"+acct, nil)
	for _, s := range aiData(body)["scopes"].([]any) {
		sm := s.(map[string]any)
		if sm["scope_kind"] == "agent" {
			if code, _ := api.do("DELETE", "/responder-groups/"+acct+"/scopes/"+sm["id"].(string), nil); code != 200 {
				t.Fatalf("remove scope: %d", code)
			}
		}
	}
	_, body = api.do("GET", "/agent-identities/"+wa.String()+"/responder", nil)
	if d := aiData(body); d["via"] != "account" || d["scope_ref"] != a.account {
		t.Fatalf("account resolution: %v", d)
	}
	// Isolation: B cannot read, change or accept A's groups.
	apiB := newAIAPI(t, db).as(b.ws, b.human, b.membership)
	for _, r := range []struct{ m, p string }{{"GET", "/responder-groups/" + acct}, {"PATCH", "/responder-groups/" + acct},
		{"DELETE", "/responder-groups/" + acct}, {"POST", "/responder-groups/" + acct + "/accept"},
		{"POST", "/responder-groups/" + acct + "/members"}, {"POST", "/responder-groups/" + acct + "/handover"}} {
		if code, _ := apiB.do(r.m, r.p, map[string]any{}); code != 404 {
			t.Errorf("%s %s from B: %d, want 404", r.m, r.p, code)
		}
	}
	if _, body := apiB.do("GET", "/responder-groups", nil); strings.Contains(fmt.Sprint(body), acct) {
		t.Fatal("B lists A's group")
	}
	// The default group cannot be deleted.
	_, body = api.do("GET", "/responder-groups", nil)
	def := body["data"].([]any)[0].(map[string]any)
	if code, _ := api.do("DELETE", "/responder-groups/"+def["id"].(string), nil); code != 409 {
		t.Fatalf("delete default: %d", code)
	}

	// Leaver: the account group's only accepted member leaves (SCIM).
	if code, _ := api.do("POST", "/responder-groups/"+acct+"/members", map[string]any{"user_id": a.approver.String()}); code != 200 {
		t.Fatal("assign approver")
	}
	if code, _ := approver.do("POST", "/responder-groups/"+acct+"/accept", nil); code != 200 {
		t.Fatal("approver accepts")
	}
	dir := services.NewDirectoryService(db)
	ctx := context.Background()
	active, inactive := true, false
	email := "ravi-aiga@test.local"
	if _, n, err := dir.Upsert(ctx, a.ws, services.DirectoryPersonInput{Source: "scim", ExternalID: "ravi", Email: &email, Active: &active}); err != nil || n != 0 {
		t.Fatalf("directory upsert: %v %d", err, n)
	}
	p, n, err := dir.Upsert(ctx, a.ws, services.DirectoryPersonInput{Source: "scim", ExternalID: "ravi", Active: &inactive})
	if err != nil || p.Status != "left" || p.UserID == nil || *p.UserID != a.approver || n != 1 {
		t.Fatalf("leaver: %+v n=%d err=%v", p, n, err)
	}
	asks := aiEvents(t, db, a.ws, services.GovEventAgentAskNeeded)
	if len(asks) != 1 || asks[0]["reason"] != services.AskReasonDeciderLeft || asks[0]["agent_id"] != wa.String() {
		t.Fatalf("leaver asks: %v", asks)
	}
	if len(aiEvents(t, db, b.ws, services.GovEventAgentAskNeeded)) != 0 {
		t.Fatal("A's leaver raised asks in B")
	}
	// A leave window is leave, not left.
	from := time.Now().Add(-time.Hour)
	if p, _, _ := dir.Upsert(ctx, a.ws, services.DirectoryPersonInput{Source: "scim", ExternalID: "on-leave", Active: &active, LeaveFrom: &from}); p.Status != "leave" {
		t.Fatalf("leave status: %s", p.Status)
	}
	_, body = apiB.do("GET", "/directory/people", nil)
	if len(body["data"].([]any)) != 0 {
		t.Fatalf("B sees A's directory: %v", body)
	}
}

func TestAgentHygieneSweep(t *testing.T) {
	db := igaDB(t)
	a := aiSeed(t, db, "aiha")
	b := aiSeed(t, db, "aihb")
	ctx := context.Background()
	now := time.Now()
	sweep := func(ws uuid.UUID) services.AgentSweepResult {
		r, err := services.RunAgentIdentitySweep(ctx, db, ws, now)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		return r
	}
	sweep(a.ws)
	wa := aiAgentOf(t, db, a.ws, "iga_workload", a.workload)
	// Merge the iga agent into the workload agent so its rollup follows.
	ga := aiAgentOf(t, db, a.ws, "iga_agents", a.igaAgent)
	if _, err := services.NewAgentIdentityService(db).EndAgent(ctx, a.ws, ga, a.human,
		services.AgentEndRequest{Action: "merge", Reason: "same", MergeInto: wa}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if err := tenancy.InWorkspace(ctx, db, a.ws, func(tx *gorm.DB) error {
		_, err := services.RecordAgentInstance(tx, a.ws, services.AgentInstanceObservation{SourceTable: "iga_workload",
			SourceID: a.workload.String(), NativeWorkloadID: "arn:fn", CloudIdentityID: &a.identity})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	arExec(t, db, `INSERT INTO cloud_usage (workspace_id, connector_id, identity_id, service, source, attrs, last_used_at)
		VALUES (?, ?, ?, 'bedrock', 'cloudtrail', '{}'::jsonb, now() - interval '40 days')`, a.ws, a.conn, a.identity)
	// Overdue and fresh keys.
	arExec(t, db, `INSERT INTO cloud_secret (workspace_id, connector_id, identity_id, kind, native_id, created_at, status)
		VALUES (?, ?, ?, 'access_key', 'AKIAOLD000000000AIHA', now() - interval '100 days', 'active'),
		       (?, ?, ?, 'access_key', 'AKIANEW000000000AIHA', now() - interval '10 days', 'active')`,
		a.ws, a.conn, a.identity, a.ws, a.conn, a.identity)

	r := sweep(a.ws)
	if r.StaleOpened != 1 || r.OverdueOpened != 1 {
		t.Fatalf("sweep: %+v", r)
	}
	var rollup, state string
	db.Raw(`SELECT rollup_state FROM iga_agents WHERE id = ?`, a.igaAgent).Scan(&rollup)
	db.Raw(`SELECT state FROM agent WHERE id = ?`, wa).Scan(&state)
	if rollup != "stale" || state != "active" {
		t.Fatalf("stale: rollup %s state %s", rollup, state)
	}
	var keys []string
	db.Raw(`SELECT subject_key FROM agent_hygiene_finding WHERE workspace_id = ? AND kind = 'overdue_key' AND state = 'open'`, a.ws).Scan(&keys)
	if len(keys) != 1 || keys[0] != "AKIAOLD000000000AIHA" {
		t.Fatalf("overdue keys: %v", keys)
	}
	if r := sweep(a.ws); r.StaleOpened != 0 || r.OverdueOpened != 0 {
		t.Fatalf("second sweep reopened: %+v", r)
	}
	// A call again: stale resolves and the rollup is restored.
	arExec(t, db, `UPDATE cloud_usage SET last_used_at = now() WHERE workspace_id = ?`, a.ws)
	if r := sweep(a.ws); r.StaleResolved != 1 {
		t.Fatalf("stale not resolved: %+v", r)
	}
	db.Raw(`SELECT rollup_state FROM iga_agents WHERE id = ?`, a.igaAgent).Scan(&rollup)
	if rollup != "confirmed" {
		t.Fatalf("rollup not restored: %s", rollup)
	}
	// Deleted at source: every source of the standalone sighting is gone.
	sa := aiAgentOf(t, db, a.ws, "discovered_agents", a.sighting)
	arExec(t, db, `UPDATE discovered_agents SET runtime_status = 'gone' WHERE id = ?`, a.sighting)
	if r := sweep(a.ws); r.DeletedAtSource != 1 {
		t.Fatalf("deleted at source: %+v", r)
	}
	db.Raw(`SELECT state FROM agent WHERE id = ?`, sa).Scan(&state)
	asks := aiEvents(t, db, a.ws, services.GovEventAgentAskNeeded)
	if state != "deleted_at_source" || len(asks) != 1 || asks[0]["reason"] != services.AskReasonDeletedAtSource {
		t.Fatalf("deleted at source: %s %v", state, asks)
	}
	arExec(t, db, `UPDATE discovered_agents SET runtime_status = 'running' WHERE id = ?`, a.sighting)
	if r := sweep(a.ws); r.Reappeared != 1 {
		t.Fatalf("reappeared: %+v", r)
	}
	// B: nothing of A's leaked into B's sweep.
	sweep(b.ws)
	var n int64
	db.Raw(`SELECT count(*) FROM agent_hygiene_finding WHERE workspace_id = ?`, b.ws).Scan(&n)
	if n != 0 {
		t.Fatalf("B has %d hygiene findings", n)
	}
}
