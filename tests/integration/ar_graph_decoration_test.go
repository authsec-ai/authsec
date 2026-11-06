package integration

// Agent runtime visibility on the access graph (internal/igaread/agent_runtime.go,
// services/agent_runtime_graph.go) over a graph the REAL scan worker and
// projector built: an AI workload's model-call evidence (cloud_usage
// cloudtrail/bedrock), an open alert, a pending suggestion and a live
// containment show on the role's and its Lambda's nodes in /graph,
// /graph/expand, /graph/path and the identity and workload details; a
// model-level containment marks only the grant whose statement allows a
// model action, an identity-level one every grant of the role. Workspace B,
// the same AWS account with the same ARNs, sees none of A's decoration, and a
// node without agent-runtime data is byte for byte what it is without the
// decoration installed.
//
// Needs IGA_TEST_DSN (skipped otherwise), like the rest of this package.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
)

const docBotModels = `{"Version":"2012-10-17","Statement":[{"Sid":"Models","Effect":"Allow",` +
	`"Action":["bedrock:InvokeModel","bedrock:Converse"],"Resource":"*"}]}`

// arGraphFixture: support-bot runs as SupportBotRole, which BotModels lets
// call Bedrock and TicketRead lets read support-tickets/*; plain-fn runs as
// PlainRole (ToolboxRead), which has no agent-runtime data.
func arGraphFixture(t *testing.T, l *p2Lab) *p2Account {
	t.Helper()
	a := l.account(accountA)
	bot := a.role("SupportBotRole", "AROASUPPORTBOTROLE01")
	a.attach("SupportBotRole", a.managed("BotModels", docBotModels))
	a.attach("SupportBotRole", a.managed("TicketRead", docTicketRead))
	plain := a.role("PlainRole", "AROAPLAINROLE0000001")
	a.attach("PlainRole", a.managed("ToolboxRead", docToolboxRead))
	listsFunctions(a, "us-east-1", "support-bot", bot, "plain-fn", plain)
	return a
}

// arGraphRaw is a route's exact response bytes.
func arGraphRaw(t *testing.T, api *readAPI, path string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, nil)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

// arGraphSeen collects every agent_runtime and contained a body carries.
func arGraphSeen(body map[string]any) (nodes, edges []string) {
	for _, n := range digl(body, "data", "nodes") {
		if dig(n, "agent_runtime") != nil {
			nodes = append(nodes, digs(n, "ref"))
		}
	}
	for _, p := range digl(body, "data", "paths") {
		for _, n := range digl(p, "nodes") {
			if dig(n, "agent_runtime") != nil {
				nodes = append(nodes, digs(n, "ref"))
			}
		}
		for _, e := range digl(p, "edges") {
			if dig(e, "contained") != nil {
				edges = append(edges, digs(e, "claim"))
			}
		}
	}
	for _, e := range digl(body, "data", "edges") {
		if dig(e, "contained") != nil {
			edges = append(edges, digs(e, "claim"))
		}
	}
	return nodes, edges
}

func TestARGraphDecoration(t *testing.T) {
	home := newP2Lab(t, "ar-graph-home", true)
	other := newP2Lab(t, "ar-graph-other", true)
	prev := igaread.SetAgentRuntimeSource(services.AgentRuntimeGraphSource{})
	t.Cleanup(func() {
		igaread.SetAgentRuntimeSource(prev)
		for _, ws := range []uuid.UUID{home.ws, other.ws} {
			for _, tbl := range []string{"agent_containment", "agent_alert", "agent_suggestion", "agent_finding"} {
				home.db.Exec(`DELETE FROM `+tbl+` WHERE workspace_id = ?`, ws)
			}
		}
		other.cleanup()
		home.cleanup()
	})
	ha, oa := arGraphFixture(t, home), arGraphFixture(t, other)
	home.scanAndProject(ha)
	other.scanAndProject(oa)
	db := home.db

	// A's agent-runtime rows on SupportBotRole and support-bot.
	var cloudRole uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`,
		home.ws, ha.roleARN("SupportBotRole")).Row().Scan(&cloudRole); err != nil {
		t.Fatalf("cloud identity: %v", err)
	}
	last := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	attrs, _ := json.Marshal(agentruntime.ModelCallUsage{Calls: 12, Denied: 2, LastCallAt: &last,
		Models:        map[string]int{"anthropic.claude-3-haiku": 10, "amazon.titan-text": 2},
		OtherServices: map[string]int{"s3.amazonaws.com": 3}})
	arExec(t, db, `INSERT INTO cloud_usage (workspace_id, connector_id, identity_id, service, source, attrs, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?::jsonb, now())
		ON CONFLICT (identity_id, service, source) DO UPDATE SET attrs = EXCLUDED.attrs`,
		home.ws, ha.conn, cloudRole, agentruntime.UsageService, agentruntime.UsageSource, string(attrs))
	bot := graphWorkload(t, home, "support-bot")
	role := graphIdentity(t, home, "SupportBotRole")
	suggestion := uuid.New()
	arExec(t, db, `INSERT INTO agent_suggestion (id, workspace_id, workload_id, connector_id, identity_id, rule, rule_version)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, suggestion, home.ws, refUUID(t, bot), ha.conn, cloudRole,
		services.AgentSuggestRule, services.AgentSuggestRuleVersion)
	arExec(t, db, `INSERT INTO agent_alert (workspace_id, connector_id, identity_id, subject_label, detection, severity, title,
		dedupe_key, first_seen, last_seen) VALUES (?, ?, ?, 'suggested_agent', 'D1', 'medium', 'Reads a secret', 'd1-a', now(), now()),
		(?, ?, ?, 'suggested_agent', 'D3', 'high', 'Changes IAM', 'd3-a', now(), now()),
		(?, ?, ?, 'suggested_agent', 'D2', 'high', 'Creates credentials', 'd2-a', now(), now())`,
		home.ws, ha.conn, cloudRole, home.ws, ha.conn, cloudRole, home.ws, ha.conn, cloudRole)
	// The third alert is resolved: not open.
	arExec(t, db, `UPDATE agent_alert SET state = 'resolved' WHERE workspace_id = ? AND dedupe_key = 'd2-a'`, home.ws)
	name := "Ritam"
	user, _ := classMember(t, db, home.ws, &name, "ritam-ar-graph@test.local", "active")
	contain := uuid.New()
	arExec(t, db, `INSERT INTO agent_containment (id, workspace_id, connector_id, identity_id, identity_kind, identity_arn, unique_id,
		level, state, reason, created_by, contained_at) VALUES (?, ?, ?, ?, 'iam_role', ?, 'AROASUPPORTBOTROLE01', 'model', 'contained',
		'stop model use', ?, now())`, contain, home.ws, ha.conn, cloudRole, ha.roleARN("SupportBotRole"), user)

	api := home.api()
	body := graphGet(t, api, "/graph"+qs("root", bot, "direction", "forward"))
	contractCheck(t, "/graph", body, contractGraph)
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	for _, ref := range []string{bot, role} {
		ar := dig(nodes[ref], "agent_runtime")
		if ar == nil {
			t.Fatalf("%s carries no agent_runtime: %v", ref, nodes[ref])
		}
		if digs(ar, "label") != "suggested_agent" || num(ar, "model_calls", "calls") != 12 || num(ar, "model_calls", "denied") != 2 ||
			digs(ar, "model_calls", "last_call_at") != "2026-11-04T09:30:00Z" ||
			digs(ar, "model_calls", "models", 0, "model") != "anthropic.claude-3-haiku" || num(ar, "model_calls", "models", 0, "calls") != 10 ||
			len(digl(ar, "model_calls", "models")) != 2 {
			t.Errorf("%s agent_runtime = %s, want suggested_agent with 12 calls, 2 refused, claude first", ref, contractJSON(ar))
		}
		if num(ar, "open_alerts", "count") != 2 || digs(ar, "open_alerts", "highest_severity") != "high" || num(ar, "open_findings") != 0 {
			t.Errorf("%s alerts/findings = %s, want 2 open (highest high), 0 findings", ref, contractJSON(ar))
		}
		if digs(ar, "suggestion", "id") != suggestion.String() || digs(ar, "suggestion", "state") != "pending" {
			t.Errorf("%s suggestion = %v", ref, dig(ar, "suggestion"))
		}
		if digs(ar, "containment", "id") != contain.String() || digs(ar, "containment", "level") != "model" ||
			digs(ar, "containment", "state") != "contained" || dig(ar, "containment", "effective") != nil {
			t.Errorf("%s containment = %v", ref, dig(ar, "containment"))
		}
	}
	for ref, n := range nodes {
		if ref != bot && ref != role && dig(n, "agent_runtime") != nil {
			t.Errorf("%s (%s) carries agent_runtime: %v", ref, digs(n, "kind"), dig(n, "agent_runtime"))
		}
	}
	models, tickets := graphStatementOf(t, home, "BotModels"), graphStatementOf(t, home, "TicketRead")
	grants := graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant")
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want BotModels' and TicketRead's", grants)
	}
	for _, g := range grants {
		c := dig(g.Raw, "contained")
		switch g.To {
		case models:
			if digs(c, "id") != contain.String() || digs(c, "level") != "model" {
				t.Errorf("bedrock grant contained = %v, want the model-level containment", c)
			}
		case tickets:
			if c != nil {
				t.Errorf("s3 grant contained = %v, want none at model level", c)
			}
		}
	}
	for _, e := range graphEdges(t, digl(body, "data", "edges")) {
		if e.Kind != "grant" && dig(e.Raw, "contained") != nil {
			t.Errorf("%s edge %s carries contained", e.Kind, e.Claim)
		}
	}

	// /graph/expand: the role's grants, the same marks.
	exp := graphGet(t, api, "/graph/expand"+qs("node", role, "edge", "grant", "direction", "forward"))
	contractCheck(t, "/graph/expand", exp, contractGraphExpand)
	if _, es := arGraphSeen(exp); len(es) != 1 {
		t.Errorf("expand contained edges = %v, want the bedrock grant only", es)
	}
	// Reverse from the bedrock statement: the role is the far node, decorated
	// in the same level as its grant.
	rev := graphGet(t, api, "/graph"+qs("root", models, "direction", "reverse"))
	contractCheck(t, "/graph reverse", rev, contractGraph)
	if ns, es := arGraphSeen(rev); len(es) != 1 || !arGraphHas(ns, role) || !arGraphHas(ns, bot) {
		t.Errorf("reverse decoration = nodes %v edges %v, want the role and the Lambda, the bedrock grant", ns, es)
	}
	// /graph/path to the tickets: the role and the Lambda decorated, the s3
	// grant not contained.
	path := graphGet(t, api, "/graph/path"+qs("from", bot, "to", graphResource(t, home, "arn:aws:s3:::support-tickets/*")))
	contractCheck(t, "/graph/path", path, contractGraphPath)
	if ns, es := arGraphSeen(path); len(es) != 0 || !arGraphHas(ns, role) || !arGraphHas(ns, bot) {
		t.Errorf("path decoration = nodes %v edges %v, want the role and the Lambda and no contained edge", ns, es)
	}
	// The details carry what the nodes carry.
	_, idBody := api.get("/identities/" + role)
	contractCheck(t, "/identities/:id", idBody, contractIdentityDetail("iam_role"))
	if digs(idBody, "data", "agent_runtime", "containment", "id") != contain.String() {
		t.Errorf("identity detail agent_runtime = %v", dig(idBody, "data", "agent_runtime"))
	}
	_, wBody := api.get("/workloads/" + bot)
	contractCheck(t, "/workloads/:id", wBody, contractDetail(contractWorkloadDetail, contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))))
	if digs(wBody, "data", "agent_runtime", "suggestion", "id") != suggestion.String() {
		t.Errorf("workload detail agent_runtime = %v", dig(wBody, "data", "agent_runtime"))
	}

	// Identity level: every grant of the role.
	arExec(t, db, `UPDATE agent_containment SET state = 'released', released_at = now() WHERE id = ?`, contain)
	ident := uuid.New()
	arExec(t, db, `INSERT INTO agent_containment (id, workspace_id, connector_id, identity_id, identity_kind, identity_arn, unique_id,
		level, state, reason, created_by, contained_at, effective) VALUES (?, ?, ?, ?, 'iam_role', ?, 'AROASUPPORTBOTROLE01', 'identity',
		'contained', 'stop everything', ?, now(), true)`, ident, home.ws, ha.conn, cloudRole, ha.roleARN("SupportBotRole"), user)
	body = graphGet(t, api, "/graph"+qs("root", role, "direction", "forward"))
	for _, g := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant") {
		if digs(g.Raw, "contained", "id") != ident.String() || digs(g.Raw, "contained", "level") != "identity" {
			t.Errorf("grant %s contained = %v, want the identity-level containment", g.To, dig(g.Raw, "contained"))
		}
	}
	if n := graphNodes(t, digl(body, "data", "nodes"))[role]; dig(n, "agent_runtime", "containment", "effective") != true {
		t.Errorf("role containment = %v, want identity level, effective", dig(n, "agent_runtime", "containment"))
	}
	// A preview marks nothing: release, then preview at identity level.
	arExec(t, db, `UPDATE agent_containment SET state = 'released', released_at = now() WHERE id = ?`, ident)
	preview := uuid.New()
	arExec(t, db, `INSERT INTO agent_containment (id, workspace_id, connector_id, identity_id, identity_kind, identity_arn, unique_id,
		level, state, reason, created_by) VALUES (?, ?, ?, ?, 'iam_role', ?, 'AROASUPPORTBOTROLE01', 'identity', 'previewed', 'look', ?)`,
		preview, home.ws, ha.conn, cloudRole, ha.roleARN("SupportBotRole"), user)
	body = graphGet(t, api, "/graph"+qs("root", role, "direction", "forward"))
	if _, es := arGraphSeen(body); len(es) != 0 {
		t.Errorf("a previewed containment marks grants: %v", es)
	}
	if n := graphNodes(t, digl(body, "data", "nodes"))[role]; digs(n, "agent_runtime", "containment", "state") != "previewed" {
		t.Errorf("role containment = %v, want the preview shown on the node", dig(n, "agent_runtime", "containment"))
	}

	// A node without agent-runtime data is what it was without the
	// decoration: PlainRole's graph, byte for byte.
	plain := graphIdentity(t, home, "PlainRole")
	plainPath := "/graph" + qs("root", plain, "direction", "reverse")
	with := arGraphRaw(t, api, plainPath)
	igaread.SetAgentRuntimeSource(nil)
	without := arGraphRaw(t, api, plainPath)
	igaread.SetAgentRuntimeSource(services.AgentRuntimeGraphSource{})
	if string(with) != string(without) {
		t.Errorf("PlainRole's graph changed with the decoration installed:\nwith    %s\nwithout %s", with, without)
	}
	if strings.Contains(string(with), "agent_runtime") || strings.Contains(string(with), "contained") {
		t.Errorf("PlainRole's graph carries agent-runtime fields: %s", with)
	}

	// Workspace B: the same account and ARNs, none of A's decoration.
	oapi := other.api()
	oBot, oRole := graphWorkload(t, other, "support-bot"), graphIdentity(t, other, "SupportBotRole")
	for _, p := range []string{
		"/graph" + qs("root", oBot, "direction", "forward"),
		"/graph" + qs("root", graphStatementOf(t, other, "BotModels"), "direction", "reverse"),
		"/graph/expand" + qs("node", oRole, "edge", "grant", "direction", "forward"),
		"/identities/" + oRole,
		"/workloads/" + oBot,
	} {
		raw := string(arGraphRaw(t, oapi, p))
		if strings.Contains(raw, "agent_runtime") || strings.Contains(raw, "contained") {
			t.Errorf("workspace B %s carries agent-runtime fields: %s", p, raw)
		}
		for _, id := range []uuid.UUID{suggestion, contain, ident, preview, cloudRole} {
			if strings.Contains(raw, id.String()) {
				t.Errorf("workspace B %s names A's %s", p, id)
			}
		}
	}
	// And A's refs stay 404 from B, decoration or not.
	if code, b := oapi.get("/graph" + qs("root", bot, "direction", "forward")); code != 404 {
		t.Errorf("A's workload from B = %d %v, want 404", code, b)
	}
}

func arGraphHas(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
