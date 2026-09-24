package integration

// T6.3 -- GET /api/iga/v1/workloads/:id (SPEC-iga-phase2-graph.md §5.3 Agents &
// workloads; D-4, D-5, D-6, D-83, D-85): the list row, plus continuity,
// provider_attrs, sources and the latest classification decision, over
// graphs the REAL scan worker and projector built. Gates: "retired object
// readable" (E8); cross-workspace ids and GitHub rows are 404 (E14, D-6).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
)

// The detail is the list row plus the detail's own fields, all read from the
// graph: continuity, the provider's display facts (env var NAMES, never
// values), the connector that holds it, no decision yet, and can_classify
// always stated.
func TestP2WdetailDetailShape(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-shape")
	api := l.api()
	id := wdetailWorkload(t, l, "ticket-tools")
	role := wdetailIdentity(t, l, "SharedToolRole")

	body := wdetailGet(t, api, "/workloads/"+id.String())
	d := dig(body, "data")
	for field, want := range map[string]string{
		"ref": refOf("workload", id), "name": "ticket-tools", "runtime_kind": models.WorkloadLambdaFunction,
		"arn":            "arn:aws:lambda:us-east-1:" + a.id + ":function:ticket-tools",
		"region":         "us-east-1",
		"classification": models.ClassificationUnclassified,
		"lifecycle":      models.IGALifecycleActive, "state": "current",
		"continuity": models.ContinuityRecognitionOnly,
	} {
		if got := digs(d, field); got != want {
			t.Errorf("data.%s = %q, want %q", field, got, want)
		}
	}
	if digs(d, "account", "id") != a.id || dig(d, "account", "connected") != true || digs(d, "account", "label") != "acct-"+a.id {
		t.Errorf("account = %v, want the connector's account, labelled and connected", dig(d, "account"))
	}
	if digs(d, "execution_role", "state") != models.ExecRoleResolved || digs(d, "execution_role", "identity") != refOf("identity", role) ||
		digs(d, "execution_role", "name") != "SharedToolRole" {
		t.Errorf("execution_role = %v, want resolved to SharedToolRole", dig(d, "execution_role"))
	}
	if digs(d, "instances", "state") != "not_collected" || dig(d, "first_seen_at") == nil || dig(d, "last_confirmed_at") == nil {
		t.Errorf("list-row fields missing: %s", wdetailJSON(d))
	}
	if m, ok := d.(map[string]any); !ok || m["retired_reason"] != nil {
		t.Errorf("retired_reason = %v, want present and null on an active workload", dig(d, "retired_reason"))
	} else if _, present := m["retired_reason"]; !present {
		t.Error("retired_reason is absent: the detail always states it")
	}

	// provider_attrs: the D-85 allowlist, exactly its four keys.
	pa, _ := dig(d, "provider_attrs").(map[string]any)
	if len(pa) != 4 {
		t.Errorf("provider_attrs = %v, want exactly status, foundation_model, env_var_names, gateway_targets", pa)
	}
	if digs(pa, "status") != "Active" || dig(pa, "foundation_model") != nil || dig(pa, "gateway_targets") != nil {
		t.Errorf("provider_attrs = %v, want status Active and no model or targets for a Lambda", pa)
	}
	if got := strings.Join(wdetailStrings(dig(pa, "env_var_names")), ","); got != "LOG_LEVEL,TICKET_QUEUE" {
		t.Errorf("env_var_names = %q, want the two names, sorted", got)
	}
	if strings.Contains(wdetailJSON(body), wdetailSecretValue) {
		t.Fatal("an environment variable VALUE reached the response")
	}
	if n := l.count(`SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND provider_attrs::text LIKE ?`,
		l.ws, "%"+wdetailSecretValue+"%"); n != 0 {
		t.Fatal("an environment variable VALUE was stored in iga_workload.provider_attrs")
	}
	// A Lambda with no variables states [] -- collected, and none -- never
	// null ("not collected").
	other := dig(wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, "refund-tools").String()), "data", "provider_attrs")
	if names, ok := dig(other, "env_var_names").([]any); !ok || len(names) != 0 {
		t.Errorf("refund-tools env_var_names = %v, want [] (collected, none)", dig(other, "env_var_names"))
	}

	srcs := digl(d, "sources")
	// D-96: one entry per support row, in the shape every detail gives it.
	if len(srcs) != 1 || digs(srcs[0], "integration") != refOf("cloud_connector", a.conn) || digs(srcs[0], "account", "id") != a.id ||
		digs(srcs[0], "account", "label") != "acct-"+a.id || digs(srcs[0], "state") != "current" || dig(srcs[0], "last_confirmed_at") == nil ||
		!strings.HasPrefix(digs(srcs[0], "presence"), "presence:") {
		t.Errorf("sources = %s, want the one connector, current", wdetailJSON(srcs))
	}
	if m := d.(map[string]any); m["decision"] != nil {
		t.Errorf("decision = %v, want null before anyone decided", m["decision"])
	}
	if dig(body, "meta", "capabilities", "can_classify") != false {
		t.Errorf("meta.capabilities = %v, want can_classify stated false for a token that is no workspace member", dig(body, "meta", "capabilities"))
	}
	if num(body, "meta", "rev") != 1 || digs(body, "meta", "graph_state") != "published" {
		t.Errorf("meta = %v, want rev 1, published", dig(body, "meta"))
	}
	if cov, ok := dig(body, "meta", "coverage").([]any); !ok || len(cov) != 0 {
		t.Errorf("meta.coverage = %v, want [] on a clean scan", dig(body, "meta", "coverage"))
	}

	// D-5: the typed reference is the same object; the §5.1 revision contract.
	if got := digs(wdetailGet(t, api, "/workloads/"+refOf("workload", id)), "data", "ref"); got != refOf("workload", id) {
		t.Errorf("GET by typed ref = %q", got)
	}
	code, stale := api.get("/workloads/" + id.String() + qs("rev", "7"))
	if code != http.StatusConflict || errCode(stale) != "revision_stale" || num(stale, "error", "current_rev") != 1 {
		t.Errorf("rev=7 = %d %v, want 409 revision_stale naming rev 1", code, stale)
	}
	// D-75: a parameter the route does not define is 400 naming it.
	code, bad := api.get("/workloads/" + id.String() + qs("lifecycle", "all"))
	if code != http.StatusBadRequest || errCode(bad) != "invalid_parameter" || digs(bad, "error", "parameter") != "lifecycle" {
		t.Errorf("an unknown parameter = %d %v, want 400 naming it", code, bad)
	}
}

// provider_attrs is written by the projector from the collected workload, and
// a rescan that collects new facts replaces them (D-85: no read-side
// fallback). Bedrock agents carry their model, gateways their targets
// [{id, name, status, type}] -- all four keys on every target.
func TestP2WdetailProviderAttrsFollowRescan(t *testing.T) {
	l := newP2Lab(t, "p2-wdetail-attrs", true)
	a := l.account(accountA)
	role := a.role("attrs-role", "AROAWDETAILATTRS0001")
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "attrs-fn", role: role, env: []string{"ALPHA", "BETA"}})
	f := &s3bFakes{
		bedrock: &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{"AGENTWDETAIL": {
			AgentId: aws.String("AGENTWDETAIL"), AgentName: aws.String("triage-bot"),
			AgentArn:             aws.String("arn:aws:bedrock:us-east-1:" + a.id + ":agent/AGENTWDETAIL"),
			AgentResourceRoleArn: aws.String(role), AgentStatus: bedrockagenttypes.AgentStatusPrepared,
			FoundationModel: aws.String("anthropic.claude-v2"),
		}}},
		agentCore: &fakeAgentCore{
			gateways: []agentcoretypes.GatewaySummary{{GatewayId: aws.String("gw-wd"), Name: aws.String("tools-gw"),
				Status: agentcoretypes.GatewayStatusReady}},
			gatewayRoleByID: map[string]string{"gw-wd": role},
			targetsByGateway: map[string][]agentcoretypes.TargetSummary{"gw-wd": {
				{TargetId: aws.String("tgt-1"), Name: aws.String("lambda-tool"),
					Status: agentcoretypes.TargetStatusReady, TargetType: agentcoretypes.TargetTypeLambda},
			}},
		},
	}
	s3bScanAndProject(l, a, f)
	api := l.api()
	attrs := func(name string) map[string]any {
		pa, _ := dig(wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, name).String()), "data", "provider_attrs").(map[string]any)
		return pa
	}

	if got := strings.Join(wdetailStrings(attrs("attrs-fn")["env_var_names"]), ","); got != "ALPHA,BETA" {
		t.Fatalf("scan 1 env_var_names = %q, want ALPHA,BETA", got)
	}
	agent := attrs("triage-bot")
	if digs(agent, "foundation_model") != "anthropic.claude-v2" || digs(agent, "status") != string(bedrockagenttypes.AgentStatusPrepared) ||
		agent["env_var_names"] != nil || agent["gateway_targets"] != nil {
		t.Errorf("bedrock agent provider_attrs = %v, want its model and status, nothing else", agent)
	}
	gw := attrs("tools-gw")
	targets := digl(gw, "gateway_targets")
	if len(targets) != 1 || digs(targets[0], "id") != "tgt-1" || digs(targets[0], "name") != "lambda-tool" ||
		digs(targets[0], "status") != string(agentcoretypes.TargetStatusReady) || digs(targets[0], "type") != string(agentcoretypes.TargetTypeLambda) {
		t.Errorf("gateway_targets = %s, want [{id tgt-1, name lambda-tool, status READY, type LAMBDA}]", wdetailJSON(targets))
	}
	if gw["foundation_model"] != nil || gw["env_var_names"] != nil {
		t.Errorf("gateway provider_attrs = %v, want no model and no variables", gw)
	}

	// Rescan: the function's variables changed, the gateway lost its target.
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "attrs-fn", role: role, env: []string{"GAMMA"}})
	f.agentCore.targetsByGateway["gw-wd"] = nil
	s3bScanAndProject(l, a, f)
	if got := strings.Join(wdetailStrings(attrs("attrs-fn")["env_var_names"]), ","); got != "GAMMA" {
		t.Errorf("after the rescan env_var_names = %q, want GAMMA: the projector must rewrite provider_attrs", got)
	}
	if targets, ok := attrs("tools-gw")["gateway_targets"].([]any); !ok || len(targets) != 0 {
		t.Errorf("after the rescan gateway_targets = %v, want [] (read in full, none left)", attrs("tools-gw")["gateway_targets"])
	}

	// A list this scan did NOT read is null ("not collected"), never [] and
	// never the list an earlier scan kept (D-85; "never claim more than the
	// data proves").
	//
	// Scan 3: Lambda returns the function's environment as an error (it could
	// not decrypt the variables with the function's KMS key) -- nothing was
	// read, so the names are unknown, not "none". The gateway gets a target
	// again, read in full.
	wdetailEnvironmentUnread(a, "us-east-1", "attrs-fn")
	f.agentCore.targetsByGateway["gw-wd"] = []agentcoretypes.TargetSummary{{TargetId: aws.String("tgt-2"), Name: aws.String("mcp-tool"),
		Status: agentcoretypes.TargetStatusReady, TargetType: agentcoretypes.TargetTypeMcpServer}}
	s3bScanAndProject(l, a, f)
	fnAttrs := attrs("attrs-fn")
	if v, present := fnAttrs["env_var_names"]; !present || v != nil {
		t.Errorf("env_var_names with the environment returned as an error = %v (present %v), want null: not read, never []", v, present)
	}
	if strings.Contains(wdetailJSON(fnAttrs), "KMSAccessDenied") || strings.Contains(wdetailJSON(fnAttrs), "decrypt") {
		t.Errorf("provider_attrs = %s: the error is not an allowlisted fact", wdetailJSON(fnAttrs))
	}
	if targets := digl(attrs("tools-gw"), "gateway_targets"); len(targets) != 1 || digs(targets[0], "id") != "tgt-2" {
		t.Fatalf("scan 3 gateway_targets = %s, want [tgt-2]", wdetailJSON(targets))
	}

	// Scan 4: ListGatewayTargets fails. The collector keeps tgt-2 on
	// cloud_workload (workloadAttrsMerge), but this scan confirmed nothing,
	// so the detail says "not collected" rather than show tgt-2 as the
	// gateway's current list. The variables are readable again: a good read
	// clears the unread flag.
	f.agentCore.listTargetsFail = denied("bedrock-agentcore:ListGatewayTargets")
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "attrs-fn", role: role, env: []string{"GAMMA"}})
	s3bScanAndProject(l, a, f)
	var kept int64
	l.db.Raw(`SELECT jsonb_array_length(attrs->'gateway_targets') FROM cloud_workload
	           WHERE workspace_id = ? AND name = 'tools-gw' AND attrs->>'targets_incomplete' = 'true'`, l.ws).Scan(&kept)
	if kept != 1 {
		t.Fatalf("setup: the collector kept %d targets with targets_incomplete, want tgt-2 kept", kept)
	}
	gwAttrs := attrs("tools-gw")
	if v, present := gwAttrs["gateway_targets"]; !present || v != nil {
		t.Errorf("gateway_targets after a failed ListGatewayTargets = %s (present %v), want null: not read this scan, never the kept list", wdetailJSON(v), present)
	}
	if got := strings.Join(wdetailStrings(attrs("attrs-fn")["env_var_names"]), ","); got != "GAMMA" {
		t.Errorf("env_var_names once readable again = %q, want GAMMA", got)
	}
}

// E8 / §5.2 "Retired objects": a retired workload is readable on every route,
// with lifecycle, retired_reason and last_confirmed_at; its tabs say whose
// they are and that the workload is retired, so the console can say they
// hold no current data rather than render them empty.
func TestP2WdetailRetiredWorkloadReadable(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-retired")
	api := l.api()
	id := wdetailWorkload(t, l, "refund-tools")
	role := a.roleARN("SharedToolRole")
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "ticket-tools", role: role})
	l.scanAndProject(a)

	body := wdetailGet(t, api, "/workloads/"+id.String())
	d := dig(body, "data")
	if digs(d, "lifecycle") != models.IGALifecycleRetired || digs(d, "retired_reason") != models.RetiredUnsupported ||
		dig(d, "last_confirmed_at") == nil || digs(d, "state") != "ended" {
		t.Fatalf("retired detail = %s, want lifecycle retired, retired_reason unsupported, a last confirmation, state ended", wdetailJSON(d))
	}
	if srcs := digl(d, "sources"); len(srcs) != 1 || digs(srcs[0], "state") != "ended" {
		t.Errorf("sources = %s, want the connector's support, ended", wdetailJSON(srcs))
	}
	if dig(body, "meta", "capabilities", "can_classify") != false {
		t.Errorf("can_classify on a retired workload = %v, want false", dig(body, "meta", "capabilities"))
	}
	ids := wdetailGet(t, api, "/workloads/"+id.String()+"/identities")
	if digs(ids, "meta", "workload", "lifecycle") != models.IGALifecycleRetired ||
		digs(ids, "meta", "workload", "retired_reason") != models.RetiredUnsupported {
		t.Errorf("identities meta.workload = %v, want the retired workload", dig(ids, "meta", "workload"))
	}
	if items := digl(ids, "data", "execution", "items"); len(items) != 0 {
		t.Errorf("a retired workload's live execution = %s, want none (its edge ended)", wdetailJSON(items))
	}
	ended := digl(wdetailGet(t, api, "/workloads/"+id.String()+"/identities"+qs("include_ended", "true")), "data", "execution", "items")
	if len(ended) != 1 || digs(ended[0], "state") != "ended" || digs(ended[0], "ended_reason") == "" || dig(ended[0], "valid_to") == nil {
		t.Errorf("include_ended execution = %s, want the ended executes_as with valid_to and ended_reason", wdetailJSON(ended))
	}
	res := wdetailGet(t, api, "/workloads/"+id.String()+"/resources")
	if digs(res, "meta", "workload", "lifecycle") != models.IGALifecycleRetired || len(digl(res, "data")) != 0 {
		t.Errorf("retired resources = %s, want an empty page marked with the retired workload", wdetailJSON(res))
	}
}

// E14 / D-4 / D-5 / D-6: every route answers 404 not_found, with no hint, for
// an id that is not THIS workspace's readable AWS workload.
func TestP2WdetailNotFound(t *testing.T) {
	// Every lab exists before any scans (each clears the shared run table
	// when created); this cleanup, registered last, runs first and removes
	// every workspace's graph rows before a lab clears the runs they
	// reference.
	home := newP2Lab(t, "p2-wdetail-404-home", true)
	other := newP2Lab(t, "p2-wdetail-404-other", true)
	empty := newP2Lab(t, "p2-wdetail-404-empty", true)
	t.Cleanup(func() { empty.cleanup(); other.cleanup(); home.cleanup() })
	ha := wdetailShared(home)
	oa := other.account(accountB)
	orole := oa.role("OtherRole", "AROAWDETAILOTHER0001")
	wdetailFunctions(oa, "us-east-1", wdetailFn{name: "other-fn", role: orole})
	other.scanAndProject(oa)

	api := home.api()
	own := wdetailWorkload(t, home, "ticket-tools")
	foreign := wdetailWorkload(t, other, "other-fn")
	statement := uuid.Nil
	if err := home.db.Raw(`SELECT id FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`, home.ws).
		Row().Scan(&statement); err != nil {
		t.Fatalf("setup: no statement to probe with: %v", err)
	}

	// A GitHub row shares the table and even has a support row: it is still
	// not a graph row (D-6). An AWS row no projection pass supported is not
	// one either. Inserted directly: the projector writes neither shape.
	conn := ha.conn
	github, unsupported := uuid.New(), uuid.New()
	for _, row := range []struct {
		id       uuid.UUID
		provider string
	}{{github, "github"}, {unsupported, "aws"}} {
		if err := home.db.Exec(`INSERT INTO iga_workload (id, workspace_id, provider, runtime_kind, display_name, source_key)
		                        VALUES (?, ?, ?, 'lambda_function', 'not-a-graph-row', ?)`,
			row.id, home.ws, row.provider, row.provider+"\x1fwdetail\x1f"+row.id.String()).Error; err != nil {
			t.Fatalf("insert %s workload: %v", row.provider, err)
		}
	}
	if err := home.db.Exec(`INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
	                        VALUES (?, ?, ?, 'wdetail-github')`, home.ws, github, conn).Error; err != nil {
		t.Fatalf("insert github support: %v", err)
	}

	for name, id := range map[string]string{
		"another workspace's workload": foreign.String(),
		"a GitHub row with support":    github.String(),
		"an AWS row with no support":   unsupported.String(),
		"another type's reference":     refOf("statement", statement),
		"a malformed id":               "not-a-uuid",
		"an unknown id":                uuid.NewString(),
	} {
		for _, path := range wdetailPaths(id) {
			code, body := api.get(path)
			if code != http.StatusNotFound || errCode(body) != "not_found" {
				t.Errorf("%s: GET %s = %d %s, want 404 not_found", name, path, code, wdetailJSON(body))
			}
			if s := wdetailJSON(body); strings.Contains(s, "other-fn") || strings.Contains(s, other.ws.String()) {
				t.Errorf("%s: GET %s leaked the other workspace: %s", name, path, s)
			}
		}
	}
	// Positive control: the same routes resolve the home workload.
	for _, path := range wdetailPaths(own.String()) {
		wdetailGet(t, api, path)
	}
	// The other workspace's own token reads its workload: the 404 above is
	// about the workspace, nothing else.
	wdetailGet(t, other.api(), "/workloads/"+foreign.String())

	// D-4: before the first publication no object exists, so a detail is 404
	// -- even for a workload row that is otherwise readable (AWS, supported:
	// inserted directly, since no pass writes one without publishing).
	ea := empty.account(accountA)
	early := uuid.New()
	if err := empty.db.Exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, source_key)
	                         VALUES (?, ?, 'lambda_function', 'unpublished', ?)`,
		early, empty.ws, "awswdetail-unpublished"+early.String()).Error; err != nil {
		t.Fatalf("insert unpublished workload: %v", err)
	}
	if err := empty.db.Exec(`INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
	                         VALUES (?, ?, ?, 'wdetail-unpublished')`, empty.ws, early, ea.conn).Error; err != nil {
		t.Fatalf("insert unpublished support: %v", err)
	}
	for _, id := range []string{own.String(), early.String()} {
		for _, path := range wdetailPaths(id) {
			if code, body := empty.api().get(path); code != http.StatusNotFound || errCode(body) != "not_found" {
				t.Errorf("nothing published: GET %s = %d %v, want 404", path, code, body)
			}
		}
	}
}

// wdetailScopedGet calls a graph route through the REAL route table with a
// token that also carries jwt claims (scope), which the read harness's string
// claims cannot: can_classify reads iga:review with authz.Allows, the test
// the classification POST's middleware applies.
func wdetailScopedGet(t *testing.T, l *p2Lab, claims map[string]string, scope, path string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey)
	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		c.Set("workspace_id", l.ws.String())
		for k, v := range claims {
			c.Set(k, v)
		}
		c.Set("claims", jwt.MapClaims{"scope": scope})
		c.Next()
	})
	platform.RegisterIGAGraphReadRoutes(g, ctl, func(string, string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Next() }
	})
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, nil))
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, w.Code, w.Body.String())
	}
	return out
}

// meta.capabilities.can_classify (D-83) on the detail: true only for a
// verified human with iga:review on an active workload that is not
// provider-native; always stated, never absent. And the latest decision is
// on the detail in the POST's data.decision shape, with its id for an Undo.
func TestP2WdetailCanClassifyAndDecision(t *testing.T) {
	f := classSetup(t, "p2-wdetail-classify")
	path := "/workloads/" + f.workload.String()
	human := classClaims(f.user, f.member)
	can := func(claims map[string]string, scope, p string) any {
		return dig(wdetailScopedGet(t, f.l, claims, scope, p), "meta", "capabilities", "can_classify")
	}
	for _, tc := range []struct {
		name   string
		claims map[string]string
		scope  string
		want   bool
	}{
		{"verified human with iga:review", human, "iga:read iga:review", true},
		{"verified human without iga:review", human, "iga:read", false},
		{"iga:review on a token that is no member session", map[string]string{"user_id": f.user.String()}, "iga:read iga:review", false},
	} {
		if got := can(tc.claims, tc.scope, path); got != tc.want {
			t.Errorf("%s: can_classify = %v, want %v", tc.name, got, tc.want)
		}
	}

	op := uuid.New()
	out := f.classify(f.workload, classBody(op, models.ClassificationClassified, "routes tier-1 tickets", 0, nil))
	decisionID := digs(out, "data", "decision", "id")
	d := dig(wdetailGet(t, f.api, path), "data")
	if digs(d, "classification") != models.ClassificationClassified || num(d, "classification_version") != 1 {
		t.Errorf("after a decision classification = %s v%d", digs(d, "classification"), num(d, "classification_version"))
	}
	dec := dig(d, "decision")
	if digs(dec, "id") != decisionID || digs(dec, "operation_id") != op.String() || digs(dec, "decision") != models.ClassificationClassified ||
		digs(dec, "reason") != "routes tier-1 tickets" || digs(dec, "decided_by", "user_id") != f.user.String() ||
		digs(dec, "decided_by", "display") != "Priya Shah" || dig(dec, "decided_at") == nil {
		t.Errorf("decision = %s, want the decision just made, by Priya Shah, with its id", wdetailJSON(dec))
	}
	// Classified: an undo or a replacement is still offered.
	if got := can(human, "iga:read iga:review", path); got != true {
		t.Errorf("can_classify on a classified workload = %v, want true (undo)", got)
	}

	// A provider-native agent is never human-editable: false, whoever asks.
	native := f.insertWorkload("native-agent", models.WorkloadBedrockAgent, models.ClassificationProviderAgent)
	if got := can(human, "iga:read iga:review", "/workloads/"+native.String()); got != false {
		t.Errorf("can_classify on a provider-native agent = %v, want false", got)
	}
}

// D-89 / D-73: a revoked connector's workload stays readable with its stored
// state, its account reads not connected, and every route's meta.coverage
// says nothing of that account is refreshed any more ({surface: "*", state:
// revoked}).
func TestP2WdetailRevokedConnector(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-revoked")
	if err := a.svc.RevokeConnector(l.ws, a.conn); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	api := l.api()
	id := wdetailWorkload(t, l, "ticket-tools").String()
	for _, path := range wdetailPaths(id) {
		body := wdetailGet(t, api, path)
		found := false
		for _, c := range digl(body, "meta", "coverage") {
			if digs(c, "account_id") == a.id && digs(c, "surface") == "*" && digs(c, "state") == models.CloudConnectorRevoked {
				found = true
			}
		}
		if !found {
			t.Errorf("GET %s meta.coverage = %s, want the revoked account noted", path, wdetailJSON(dig(body, "meta", "coverage")))
		}
	}
	d := dig(wdetailGet(t, api, "/workloads/"+id), "data")
	if dig(d, "account", "connected") != false || digs(d, "state") != "current" || digs(d, "lifecycle") != models.IGALifecycleActive {
		t.Errorf("revoked detail = %s, want its stored state, account not connected", wdetailJSON(d))
	}
}
