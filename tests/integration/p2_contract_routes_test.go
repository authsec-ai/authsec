package integration

// The frozen §5 contract, route by route (SPEC-iga-phase2-graph.md §5.2,
// §5.3; T6.7): every route RegisterIGAGraphReadRoutes mounts is called against
// the ONE rich estate of p2_contract_lab_test.go -- built by the real scan
// worker and projector -- and its body is checked field by field against the
// shapes of p2_contract_schemas_test.go, then against what the estate says
// each field must hold. A route added to the table without a contract case,
// or a field renamed, dropped, turned from null into absent or added without
// the contract, fails here.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// contractCase is one call: the route pattern it exercises (as gin registered
// it), the path to call, the shape of a 200 body, and the estate's facts.
type contractCase struct {
	route string
	path  string
	shape contractShape
	check func(t *testing.T, body map[string]any)
}

func TestP2ContractEveryRouteFieldByField(t *testing.T) {
	f := contractLab(t)
	api := f.api
	u := func(ref string) string { return refUUID(t, ref).String() }

	var cloudRole, cloudLambda uuid.UUID
	f.l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND name = 'SharedToolRole'`, f.l.ws).Scan(&cloudRole)
	f.l.db.Raw(`SELECT id FROM cloud_workload WHERE workspace_id = ? AND name = 'ticket-tools'`, f.l.ws).Scan(&cloudLambda)
	if cloudRole == uuid.Nil || cloudLambda == uuid.Nil {
		t.Fatalf("fixture: cloud inventory rows missing (role %v, lambda %v)", cloudRole, cloudLambda)
	}
	grantOps := evidenceGrant(t, f.l, "ops", "OpsRead", "ReadOps")
	grantOwn := evidenceGrant(t, f.l, "priya", "PriyaOwn", "OwnRead")
	grantFinance := evidenceGrant(t, f.l, "SharedToolRole", "FinanceAll", "AllButFinance")
	grantExternal := evidenceGrant(t, f.l, "SharedToolRole", "ExternalKey", "Decrypt")
	coverageB := "coverage:" + f.runB.ID.String() + ":iam_groups"

	cases := []contractCase{
		{route: "GET /capabilities", path: "/capabilities", shape: contractCapabilities, check: func(t *testing.T, b map[string]any) {
			if digs(b, "data", "graph_projection") != "on" || dig(b, "data", "reason") != nil || digs(b, "data", "schema_head") != "036" {
				t.Errorf("capabilities = %s, want on, reason null, schema_head 036", contractJSON(b["data"]))
			}
			for k, v := range dig(b, "data", "features").(map[string]any) {
				if v != true {
					t.Errorf("features.%s = %v, want true with the switch on (D-11)", k, v)
				}
			}
		}},
		{route: "GET /pipeline", path: "/pipeline", shape: contractPipeline, check: func(t *testing.T, b map[string]any) {
			if digs(b, "data", "barrier", "state") != "idle" || num(b, "data", "current_rev") != 3 {
				t.Errorf("pipeline = %s, want idle at rev 3", contractJSON(b["data"]))
			}
			accts := digl(b, "data", "accounts")
			if len(accts) != 2 || digs(accts[0], "account_id") != accountA || digs(accts[1], "account_id") != accountB {
				t.Fatalf("pipeline accounts = %s, want A then B (by label)", contractJSON(accts))
			}
			// D-56: every connector with a published run is at the current rev;
			// the rev that published its own run is on its projection.
			if num(accts[0], "last_published_rev") != 3 || num(accts[1], "last_published_rev") != 3 ||
				num(accts[0], "projection", "rev") != 3 || num(accts[1], "projection", "rev") != 2 {
				t.Errorf("pipeline revs = %s", contractJSON(accts))
			}
			contractSamePublication(t, b, digs(b, "data", "current_published_at"))
		}},
		{route: "GET /coverage", path: "/coverage", shape: contractCoverage, check: func(t *testing.T, b map[string]any) {
			if n := len(digl(b, "data")); n != 2 {
				t.Fatalf("coverage accounts = %d, want 2 (the connected accounts)", n)
			}
			s := contractSurface(t, b, accountB, "iam_groups")
			if digs(s, "state") != "denied" || digs(s, "error_code") != "AccessDenied" || digs(s, "prevents") != "surface_denied" ||
				dig(s, "count") != nil || digs(s, "run") != refOf("cloud_scan_run", f.runB.ID) || digs(s, "ref") != coverageB {
				t.Errorf("B iam_groups = %s, want denied AccessDenied surface_denied, count null, run B's", contractJSON(s))
			}
			if s := contractSurface(t, b, accountA, "iam_roles"); digs(s, "state") != "reached" || dig(s, "prevents") != nil || dig(s, "count") == nil {
				t.Errorf("A iam_roles = %s, want reached with a count, prevents null", contractJSON(s))
			}
		}},
		{route: "GET /coverage", path: "/coverage?account=" + accountB, shape: contractCoverage, check: func(t *testing.T, b map[string]any) {
			if d := digl(b, "data"); len(d) != 1 || digs(d[0], "account", "id") != accountB {
				t.Errorf("coverage?account=B = %s, want B only", contractJSON(d))
			}
		}},

		/* ------------------------------ workloads ------------------------------ */

		{route: "GET /workloads", path: "/workloads", shape: contractList(contractWorkloadRow, contractListMeta()), check: func(t *testing.T, b map[string]any) {
			rows := digl(b, "data")
			if got := contractPluck(rows, "name"); !reflect.DeepEqual(got, []string{"orphan-fn", "support-bot", "ticket-tools", "ticket-worker"}) {
				t.Errorf("workloads by name = %v", got)
			}
			byName := contractByName(rows, "name")
			if er := dig(byName["ticket-tools"], "execution_role"); digs(er, "identity") != f.shared || digs(er, "name") != "SharedToolRole" {
				t.Errorf("ticket-tools execution_role = %s", contractJSON(er))
			}
			if er := dig(byName["ticket-worker"], "execution_role"); digs(er, "identity") != f.shared {
				t.Errorf("ticket-worker execution_role = %s, want the SAME SharedToolRole", contractJSON(er))
			}
			if er := dig(byName["orphan-fn"], "execution_role"); digs(er, "state") != "not_in_inventory" ||
				digs(er, "execution_role_arn") != f.a.roleARN("MissingRole") {
				t.Errorf("orphan-fn execution_role = %s, want not_in_inventory naming MissingRole", contractJSON(er))
			}
			if digs(byName["support-bot"], "classification") != "provider_native_agent" ||
				digs(byName["ticket-tools"], "classification") != "classified_agent" || num(byName["ticket-tools"], "classification_version") != 1 {
				t.Errorf("classifications = %s", contractJSON(rows))
			}
			if num(b, "meta", "rev") != 3 || digs(b, "meta", "graph_state") != "published" || num(b, "meta", "total") != 4 ||
				dig(b, "meta", "next_cursor") != nil || num(b, "meta", "limit") != 100 {
				t.Errorf("list meta = %s", contractJSON(b["meta"]))
			}
		}},
		{route: "GET /workloads", path: "/workloads?facets=account,runtime_kind,classification,region&limit=1",
			shape: contractList(contractWorkloadRow, contractListMeta()), check: func(t *testing.T, b map[string]any) {
				if n := len(digl(b, "data")); n != 1 || dig(b, "meta", "next_cursor") == nil || num(b, "meta", "total") != 4 {
					t.Errorf("limit=1 page = %d rows, meta %s", n, contractJSON(b["meta"]))
				}
				fa := contractFacet(b, "account")
				if fa["unknown"] != 0 || fa[accountA] != 4 { // D-14: unknown always offered
					t.Errorf("account facet = %v", fa)
				}
				if rk := contractFacet(b, "runtime_kind"); rk["lambda_function"] != 2 || rk["ecs_task_definition"] != 1 || rk["bedrock_agent"] != 1 {
					t.Errorf("runtime_kind facet = %v", rk)
				}
				if c := contractFacet(b, "classification"); c["agent"] != 2 || c["provider_native_agent"] != 1 || c["classified_agent"] != 1 || c["unclassified"] != 2 {
					t.Errorf("classification facet = %v", c)
				}
				if r := contractFacet(b, "region"); r["us-east-1"] != 4 || r["not_stated"] != 0 {
					t.Errorf("region facet = %v", r)
				}
			}},
		{route: "GET /workloads/:id", path: "/workloads/" + u(f.lambda),
			shape: contractDetail(contractWorkloadDetail, contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "ref") != f.lambda || digs(d, "continuity") != "recognition_only" || dig(d, "retired_reason") != nil {
					t.Errorf("detail = %s", contractJSON(d))
				}
				if digs(d, "decision", "decision") != "classified_agent" || digs(d, "decision", "decided_by", "display") != "Priya Shah" ||
					digs(d, "decision", "decided_by", "user_id") != f.user.String() || digs(d, "decision", "purpose") != "Customer support triage" {
					t.Errorf("decision = %s", contractJSON(dig(d, "decision")))
				}
				if s := digl(d, "sources"); len(s) != 1 || digs(s[0], "integration") != refOf("cloud_connector", f.a.conn) ||
					digs(s[0], "account", "id") != accountA || digs(s[0], "state") != "current" {
					t.Errorf("sources = %s", contractJSON(s))
				}
				// D-83: stated, and false for a token that is no verified human.
				if dig(b, "meta", "capabilities", "can_classify") != false {
					t.Errorf("can_classify = %v", dig(b, "meta", "capabilities"))
				}
			}},
		{route: "GET /workloads/:id", path: "/workloads/" + f.agent, // D-5: the typed ref form
			shape: contractDetail(contractWorkloadDetail, contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))),
			check: func(t *testing.T, b map[string]any) {
				pa := dig(b, "data", "provider_attrs")
				if digs(pa, "foundation_model") != "amazon.titan-text-express-v1" || digs(pa, "status") != "PREPARED" || dig(pa, "env_var_names") != nil {
					t.Errorf("bedrock provider_attrs = %s", contractJSON(pa))
				}
			}},
		{route: "GET /workloads/:id/identities", path: "/workloads/" + u(f.lambda) + "/identities", shape: contractWorkloadIdentities,
			check: func(t *testing.T, b map[string]any) {
				ex := digl(b, "data", "execution", "items")
				if len(ex) != 1 || digs(ex[0], "identity", "ref") != f.shared || digs(ex[0], "claim") != f.executesLambda ||
					num(ex[0], "used_by_count", "value") != 2 || dig(ex[0], "used_by_count", "exact") != true {
					t.Errorf("execution = %s, want SharedToolRole used by 2 workloads", contractJSON(ex))
				}
				if digs(b, "data", "execution_role_state") != "resolved" || dig(b, "data", "execution_role_arn") != nil {
					t.Errorf("execution_role_state/_arn = %v / %v", dig(b, "data", "execution_role_state"), dig(b, "data", "execution_role_arn"))
				}
				ma := digl(b, "data", "may_assume", "items")
				if len(ma) != 1 || digs(ma[0], "target", "ref") != f.cross || digs(ma[0], "claim") != f.crossEdge ||
					digs(ma[0], "via_identity") != f.shared || dig(ma[0], "conditions") != nil {
					t.Errorf("may_assume = %s, want SharedToolRole -> CrossRole, no conditions", contractJSON(ma))
				}
			}},
		{route: "GET /workloads/:id/identities", path: "/workloads/" + u(f.ecs) + "/identities", shape: contractWorkloadIdentities,
			check: func(t *testing.T, b map[string]any) {
				other := digl(b, "data", "other", "items")
				if len(other) != 1 || digs(other[0], "type") != "task_execution_role" || digs(other[0], "identity", "ref") != f.pull {
					t.Errorf("ECS other = %s, want ImagePullRole as task_execution_role", contractJSON(other))
				}
			}},
		{route: "GET /workloads/:id/identities", path: "/workloads/" + u(f.orphan) + "/identities", shape: contractWorkloadIdentities,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "execution_role_state") != "not_in_inventory" || digs(b, "data", "execution_role_arn") != f.a.roleARN("MissingRole") ||
					len(digl(b, "data", "execution", "items")) != 0 {
					t.Errorf("orphan tab = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /workloads/:id/resources", path: "/workloads/" + u(f.lambda) + "/resources", shape: contractWorkloadResources,
			check: func(t *testing.T, b map[string]any) {
				rows := digl(b, "data")
				// Default sort: kind rank exact < selector < external, then name (D-13).
				if got := contractPluck(rows, "resource", "text"); !reflect.DeepEqual(got, []string{
					contractKeyB, contractBucket, "*", contractTickets, contractKeyC}) {
					t.Errorf("resources = %v", got)
				}
				tickets := contractByName(rows, "resource", "text")[contractTickets]
				gs := digl(tickets, "grants")
				if len(gs) != 2 || digs(gs[0], "claim") != f.grantReadTickets || digs(gs[1], "claim") != f.grantToolbox ||
					digs(gs[0], "statement", "sid") != "ReadTickets" || digs(gs[1], "statement", "sid") != "" ||
					num(gs[0], "statement", "index") != 1 || num(gs[1], "statement", "index") != 1 {
					t.Errorf("support-tickets/* grants = %s, want ReadTickets and the Sid-less ToolboxRead, one line each", contractJSON(gs))
				}
				if r := dig(tickets, "restrictions"); num(r, "deny_statements") != 1 || dig(r, "permissions_boundary") != false {
					t.Errorf("restrictions = %s, want the one Deny, no boundary (D-78)", contractJSON(r))
				}
				star := contractByName(rows, "resource", "text")["*"]
				if ex := digl(star, "grants", 0, "exclusions"); len(ex) != 1 || digs(ex[0], "text") != contractFinance {
					t.Errorf("* grant exclusions = %s, want finance/*", contractJSON(ex))
				}
				if k := dig(contractByName(rows, "resource", "text")[contractKeyC], "resource"); digs(k, "kind") != "external" ||
					dig(k, "account", "connected") != false || digs(k, "account", "id") != contractAccountC {
					t.Errorf("C's key = %s, want external in an unconnected account", contractJSON(k))
				}
			}},
		{route: "GET /workloads/:id/changes", path: "/workloads/" + u(f.lambda) + "/changes", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				ev := contractEvents(b)
				if ev["first_seen"] == nil || ev["statement_revised"] == nil || ev["grant_ended"] == nil || ev["policy_detached"] == nil {
					t.Fatalf("workload changes = %v, want first_seen, statement_revised, grant_ended, policy_detached", contractEventNames(b))
				}
				ge := ev["grant_ended"]
				if digs(ge, "via") != f.shared || len(digl(ge, "remaining")) != 2 || digs(ge, "paths", 0, "remains") != "current" {
					t.Errorf("grant_ended = %s, want via SharedToolRole with TicketRead and ToolboxRead remaining", contractJSON(ge))
				}
				if digs(b, "meta", "kind") != "configuration" || num(b, "meta", "limit") != 50 {
					t.Errorf("changes meta = %s", contractJSON(b["meta"]))
				}
			}},
		{route: "GET /workloads/:id/changes", path: "/workloads/" + u(f.lambda) + "/changes?kind=coverage", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "meta", "kind") != "coverage" {
					t.Errorf("kind = %v", dig(b, "meta", "kind"))
				}
			}},
		{route: "GET /workloads/:id/classification", path: "/workloads/" + u(f.lambda) + "/classification",
			shape: contractList(contractHistoryItem, contractListMeta()), check: func(t *testing.T, b map[string]any) {
				h := digl(b, "data")
				if len(h) != 1 || digs(h[0], "previous") != "unclassified" || num(h[0], "result_version") != 1 ||
					num(h[0], "against_version") != 0 || dig(h[0], "undoes_decision_id") != nil {
					t.Errorf("history = %s", contractJSON(h))
				}
			}},

		/* ------------------------------ identities ----------------------------- */

		{route: "GET /identities", path: "/identities?facets=account,kind", shape: contractList(contractIdentityRow, contractListMeta()),
			check: func(t *testing.T, b map[string]any) {
				rows := digl(b, "data")
				if len(rows) != 9 || num(b, "meta", "total") != 9 {
					t.Errorf("identities = %v", contractPluck(rows, "name"))
				}
				if n := contractByName(rows, "name")["SharedToolRole"]; num(n, "used_by_count", "value") != 2 {
					t.Errorf("SharedToolRole used_by_count = %v", dig(n, "used_by_count"))
				}
				if fa := contractFacet(b, "account"); fa[accountA] != 7 || fa[accountB] != 2 || fa["unknown"] != 0 {
					t.Errorf("account facet = %v", fa)
				}
				if k := contractFacet(b, "kind"); k["iam_role"] != 7 || k["iam_user"] != 1 || k["iam_group"] != 1 {
					t.Errorf("kind facet = %v", k)
				}
				if !contractHasCoverage(b, accountB, "iam_groups", "denied") {
					t.Errorf("identities coverage = %s, want B's denied iam_groups", contractJSON(dig(b, "meta", "coverage")))
				}
			}},
		{route: "GET /identities", path: "/identities?lifecycle=retired", shape: contractList(contractIdentityRow, contractListMeta()),
			check: func(t *testing.T, b map[string]any) {
				rows := digl(b, "data")
				if len(rows) != 1 || digs(rows[0], "ref") != f.temp || digs(rows[0], "retired_reason") != "unsupported" || digs(rows[0], "state") != "ended" {
					t.Errorf("retired = %s, want TempRole retired unsupported", contractJSON(rows))
				}
			}},
		{route: "GET /identities/:id", path: "/identities/" + u(f.shared), shape: contractIdentityDetail("iam_role"),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "immutable_key") != "AROASHAREDTOOLROLE01" || digs(d, "continuity") != "immutable" ||
					digs(d, "provider_attrs", "tags", "team") != "support" || dig(d, "retired_reason") != nil {
					t.Errorf("SharedToolRole = %s", contractJSON(d))
				}
			}},
		{route: "GET /identities/:id", path: "/identities/" + u(f.priya), shape: contractIdentityDetail("iam_user"),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "provider_attrs", "permissions_boundary_arn") != "arn:aws:iam::aws:policy/PowerUserAccess" {
					t.Errorf("priya boundary = %v", dig(d, "provider_attrs"))
				}
				creds := contractByName(digl(d, "credentials"), "key_id")
				if a := creds["AKIACONTRACTACTIVE01"]; digs(a, "status") != "Active" || digs(a, "lifecycle") != "active" || dig(a, "last_used_at") == nil {
					t.Errorf("active key = %s", contractJSON(a))
				}
				if i := creds["AKIACONTRACTINACTIV1"]; digs(i, "status") != "Inactive" {
					t.Errorf("inactive key = %s", contractJSON(i))
				}
			}},
		{route: "GET /identities/:id", path: "/identities/" + f.ops, shape: contractIdentityDetail("iam_group")},
		{route: "GET /identities/:id", path: "/identities/" + u(f.temp), shape: contractIdentityDetail("iam_role"),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				// §5.2: a retired object is readable, with lifecycle, retired_reason and
				// last_confirmed_at; its one source is ended.
				if digs(d, "lifecycle") != "retired" || digs(d, "retired_reason") != "unsupported" || dig(d, "last_confirmed_at") == nil ||
					digs(d, "sources", 0, "state") != "ended" || digs(d, "sources", 0, "ended_reason") != "not_seen" {
					t.Errorf("retired TempRole = %s", contractJSON(d))
				}
			}},
		{route: "GET /identities/:id/used-by", path: "/identities/" + u(f.shared) + "/used-by", shape: contractUsedBy("iam_role"),
			check: func(t *testing.T, b map[string]any) {
				ws := digl(b, "data", "workloads", "items")
				if got := contractPluck(ws, "workload", "name"); !reflect.DeepEqual(got, []string{"ticket-tools", "ticket-worker"}) {
					t.Errorf("used-by workloads = %v, want both, the role once (E5)", got)
				}
				ps := contractPluck(digl(b, "data", "principals", "items"), "principal", "name")
				if !reflect.DeepEqual(ps, []string{"ecs-tasks.amazonaws.com", "lambda.amazonaws.com"}) {
					t.Errorf("used-by principals = %v", ps)
				}
			}},
		{route: "GET /identities/:id/used-by", path: "/identities/" + u(f.cross) + "/used-by", shape: contractUsedBy("iam_role"),
			check: func(t *testing.T, b map[string]any) {
				ps := contractPluck(digl(b, "data", "principals", "items"), "principal", "name")
				if !reflect.DeepEqual(ps, []string{"LoopRole", "SharedToolRole"}) {
					t.Errorf("CrossRole principals = %v, want LoopRole (the cycle) and A's SharedToolRole", ps)
				}
			}},
		{route: "GET /identities/:id/used-by", path: "/identities/" + u(f.ops) + "/used-by", shape: contractUsedBy("iam_group"),
			check: func(t *testing.T, b map[string]any) {
				if m := digl(b, "data", "members", "items"); len(m) != 1 || digs(m[0], "member", "ref") != f.priya {
					t.Errorf("ops members = %s", contractJSON(m))
				}
			}},
		{route: "GET /identities/:id/used-by", path: "/identities/" + u(f.priya) + "/used-by", shape: contractUsedBy("iam_user")},
		{route: "GET /identities/:id/permissions", path: "/identities/" + u(f.shared) + "/permissions", shape: contractPermissions,
			check: func(t *testing.T, b map[string]any) {
				ps := contractByName(digl(b, "data", "policies"), "name")
				if len(ps) != 7 || ps["LegacyRead"] != nil {
					t.Errorf("policies = %v, want the 7 attached (LegacyRead detached)", contractPluck(digl(b, "data", "policies"), "name"))
				}
				if st := digl(ps["GuardRails"], "statements"); len(st) != 1 || digs(st[0], "effect") != "deny" || dig(st[0], "grant") != nil {
					t.Errorf("GuardRails = %s, want the Deny with no grant", contractJSON(st))
				}
				if st := digl(ps["AuditRead"], "statements"); len(st) != 0 {
					t.Errorf("AuditRead statements = %s, want none (unreadable document)", contractJSON(st))
				}
				if st := digl(ps["TicketRead"], "statements"); len(st) != 2 || digs(st[0], "grant") != f.grantReadTickets ||
					num(st[1], "index") != 2 || dig(st[1], "condition") == nil {
					t.Errorf("TicketRead = %s", contractJSON(st))
				}
				if dig(b, "data", "boundary", "policy") != nil || len(digl(b, "data", "inherited")) != 0 {
					t.Errorf("boundary/inherited = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /identities/:id/permissions", path: "/identities/" + u(f.priya) + "/permissions", shape: contractPermissions,
			check: func(t *testing.T, b map[string]any) {
				bp := dig(b, "data", "boundary", "policy")
				if digs(bp, "name") != "PowerUserAccess" || digs(bp, "assignment", "kind") != "boundary" || dig(bp, "statements", 0, "grant") != nil {
					t.Errorf("boundary = %s, want PowerUserAccess, never a grant", contractJSON(bp))
				}
				inh := digl(b, "data", "inherited")
				if len(inh) != 1 || digs(inh[0], "group") != f.ops || digs(inh[0], "policies", 0, "name") != "OpsRead" ||
					digs(inh[0], "policies", 0, "assignment", "via_group") != f.ops {
					t.Errorf("inherited = %s", contractJSON(inh))
				}
			}},
		{route: "GET /identities/:id/permissions", path: "/identities/" + u(f.ops) + "/permissions", shape: contractPermissions},
		{route: "GET /identities/:id/changes", path: "/identities/" + u(f.shared) + "/changes", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				if ev := contractEvents(b); ev["relationship_started"] == nil || ev["policy_detached"] == nil {
					t.Errorf("identity changes = %v", contractEventNames(b))
				}
			}},

		/* -------------------------- external principals ------------------------ */

		{route: "GET /external-principals/:id", path: "/external-principals/" + u(f.oidc), shape: contractExternalDetail,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "mechanism") != "oidc" || digs(d, "issuer") != "token.actions.githubusercontent.com" ||
					digs(d, "subject") != contractSub || dig(d, "account") != nil || dig(d, "resolution") != nil {
					t.Errorf("oidc principal = %s", contractJSON(d))
				}
			}},
		{route: "GET /external-principals/:id", path: "/external-principals/" + u(f.rootC), shape: contractExternalDetail,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "mechanism") != "aws_account" || digs(d, "account", "id") != contractAccountC ||
					dig(d, "account", "connected") != false || dig(d, "account_connected") != false {
					t.Errorf("C's root = %s, want aws_account in an unconnected account (E11)", contractJSON(d))
				}
			}},
		{route: "GET /external-principals/:id/referenced-by", path: "/external-principals/" + u(f.oidc) + "/referenced-by", shape: contractReferencedBy,
			check: func(t *testing.T, b map[string]any) {
				rows := digl(b, "data")
				if len(rows) != 1 || digs(rows[0], "target", "ref") != f.github || digs(rows[0], "mechanism") != "oidc_federation" ||
					digs(rows[0], "statement", "sid") != "FromMain" || digs(rows[0], "conditions", "StringEquals", "token.actions.githubusercontent.com:sub") != contractSub {
					t.Errorf("referenced-by = %s", contractJSON(rows))
				}
			}},

		/* ------------------------------- resources ----------------------------- */

		{route: "GET /resources", path: "/resources?facets=kind,service,account", shape: contractList(contractResourceRow, contractListMeta()),
			check: func(t *testing.T, b map[string]any) {
				rows := digl(b, "data")
				kinds := contractPluck(rows, "kind")
				if len(rows) != 8 || !sort.SliceIsSorted(kinds, func(i, j int) bool {
					return contractKindRank[kinds[i]] < contractKindRank[kinds[j]]
				}) {
					t.Errorf("resources = %v kinds %v, want 8 by kind rank", contractPluck(rows, "text"), kinds)
				}
				byText := contractByName(rows, "text")
				if n := byText[contractTickets]; num(n, "named_by_count", "value") != 4 || num(n, "excluded_by_count", "value") != 0 {
					t.Errorf("support-tickets/* counts = %s", contractJSON(n))
				}
				if n := byText[contractFinance]; num(n, "named_by_count", "value") != 0 || num(n, "excluded_by_count", "value") != 1 {
					t.Errorf("finance/* counts = %s, want excluded once, named never (D-17)", contractJSON(n))
				}
				if fk := contractFacet(b, "kind"); fk["exact"] != 2 || fk["selector"] != 5 || fk["external"] != 1 {
					t.Errorf("kind facet = %v", fk)
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.tickets), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				// Two connectors vouch for the selector (§2.10B): A's and B's policies name it.
				if s := digl(d, "sources"); len(s) != 2 || dig(d, "resource_policy", "read") != false || dig(d, "resource_policy", "has_deny") != nil {
					t.Errorf("support-tickets/* = %s", contractJSON(d))
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.bucket), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				if rp := dig(b, "data", "resource_policy"); dig(rp, "read") != true || dig(rp, "has_deny") != true {
					t.Errorf("bucket resource_policy = %s, want read with a Deny (D-19)", contractJSON(rp))
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.keyC), shape: contractResourceDetail},
		{route: "GET /resources/:id", path: "/resources/" + u(f.keyB), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				if a := dig(b, "data", "account"); digs(a, "id") != accountB || dig(a, "connected") != true || digs(b, "data", "kind") != "exact" {
					t.Errorf("B's key = %s, want exact in connected B", contractJSON(b["data"]))
				}
			}},
		{route: "GET /resources/:id/access", path: "/resources/" + u(f.tickets) + "/access", shape: contractResourceAccess,
			check: func(t *testing.T, b map[string]any) {
				acc := digl(b, "data", "access")
				var grants []string
				for _, r := range acc {
					grants = append(grants, digs(r, "grant", "claim"))
				}
				sort.Strings(grants)
				want := []string{f.grantReadTickets, f.grantToolbox, evidenceGrant(t, f.l, "CrossRole", "SandboxRead", "ReadSandbox")}
				sort.Strings(want)
				if !reflect.DeepEqual(grants, want) {
					t.Errorf("access grants = %v, want %v", grants, want)
				}
				dn := digl(b, "data", "deny_statements_naming")
				if len(dn) != 1 || digs(dn[0], "statement", "sid") != "NoDeletes" || len(digl(b, "data", "excluded_by")) != 0 {
					t.Errorf("restrictions = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /resources/:id/access", path: "/resources/" + u(f.finance) + "/access", shape: contractResourceAccess,
			check: func(t *testing.T, b map[string]any) {
				ex := digl(b, "data", "excluded_by")
				if len(digl(b, "data", "access")) != 0 || len(ex) != 1 || digs(ex[0], "statement", "ref") != f.allButFinance {
					t.Errorf("finance/* access = %s, want AllButFinance under excluded_by only (E4, B19)", contractJSON(b["data"]))
				}
			}},
		{route: "GET /resources/:id/changes", path: "/resources/" + u(f.tickets) + "/changes", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				if ev := contractEvents(b); ev["grant_ended"] == nil || ev["first_seen"] == nil {
					t.Errorf("resource changes = %v", contractEventNames(b))
				}
			}},

		/* --------------------------------- graph ------------------------------- */

		{route: "GET /graph", path: "/graph" + qs("root", f.lambda, "direction", "forward"), shape: contractGraph,
			check: func(t *testing.T, b map[string]any) {
				nodes := graphNodes(t, digl(b, "data", "nodes"))
				rt, tb := nodes[f.readTickets], nodes[f.toolboxStmt]
				// §5.4 independent grants: two statement nodes, one group_key.
				if rt == nil || tb == nil || digs(rt, "group_key") == "" || digs(rt, "group_key") != digs(tb, "group_key") || digs(tb, "sid") != "" {
					t.Errorf("ReadTickets/ToolboxRead nodes = %s / %s", contractJSON(rt), contractJSON(tb))
				}
				if fin := nodes[f.allButFinance]; len(digl(fin, "exclusions")) != 1 || nodes[f.finance] != nil {
					t.Errorf("FinanceAll = %s; finance/* must be an exclusion, never a node", contractJSON(fin))
				}
				if !contractHasEdge(b, f.crossEdge, func(e any) bool { return dig(e, "crosses_account") == true }) {
					t.Errorf("SharedToolRole -> CrossRole must be crosses_account")
				}
				if digs(b, "data", "truncated", "bound_by") != "assume_hops" || len(digl(b, "data", "frontier")) == 0 {
					t.Errorf("truncated/frontier = %v / %v, want assume_hops with a frontier", dig(b, "data", "truncated"), dig(b, "data", "frontier"))
				}
			}},
		{route: "GET /graph", path: "/graph" + qs("root", f.lambda, "direction", "forward", "assume_hops", "4"), shape: contractGraph,
			check: func(t *testing.T, b map[string]any) {
				// §5.4 cycles: LoopRole -> CrossRole closes the cycle.
				if !contractHasEdge(b, "", func(e any) bool { return dig(e, "closes_cycle") == true && digs(e, "to") == f.cross }) {
					t.Errorf("no closes_cycle edge into CrossRole: %s", contractJSON(dig(b, "data", "edges")))
				}
				if dig(b, "data", "truncated") != nil {
					t.Errorf("truncated = %v, want null: the whole neighbourhood fits", dig(b, "data", "truncated"))
				}
			}},
		{route: "GET /graph", path: "/graph" + qs("root", f.tickets, "direction", "reverse"), shape: contractGraph},
		{route: "GET /graph", path: "/graph" + qs("root", f.priya, "direction", "forward"), shape: contractGraph},
		{route: "GET /graph", path: "/graph" + qs("root", f.rootC, "direction", "forward"), shape: contractGraph},
		{route: "GET /graph/expand", path: "/graph/expand" + qs("node", f.shared, "edge", "can_assume", "direction", "forward"), shape: contractGraphExpand,
			check: func(t *testing.T, b map[string]any) {
				if es := digl(b, "data", "edges"); len(es) != 1 || digs(es[0], "claim") != f.crossEdge || dig(b, "data", "next_cursor") != nil {
					t.Errorf("expand = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /graph/path", path: "/graph/path" + qs("from", f.lambda, "to", f.tickets), shape: contractGraphPath,
			check: func(t *testing.T, b map[string]any) {
				ps := digl(b, "data", "paths")
				if digs(b, "data", "outcome") != "found" || len(ps) != 3 || dig(b, "data", "more_paths") != false {
					t.Errorf("path = %s, want found with 3 paths (ReadTickets, ToolboxRead, via CrossRole)", contractJSON(b["data"]))
				}
			}},
		{route: "GET /graph/path", path: "/graph/path" + qs("from", f.lambda, "to", f.finance), shape: contractGraphPath,
			check: func(t *testing.T, b map[string]any) {
				// B19: an exclusion is never a destination.
				if o := digs(b, "data", "outcome"); o == "found" {
					t.Errorf("a path to the excluded finance/* = %s", contractJSON(b["data"]))
				}
			}},

		/* --------------------------------- evidence ----------------------------- */

		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "claim", "sentence") != "SharedToolRole is granted s3:GetObject on support-tickets/* by TicketRead (statement ReadTickets)." {
					t.Errorf("sentence = %q", digs(d, "claim", "sentence"))
				}
				if st := dig(d, "status"); digs(st, "basis") != "declared" || digs(st, "lifecycle") != "current" || digs(st, "collection") != "complete" {
					t.Errorf("status = %s", contractJSON(st))
				}
				codes := evidenceCodes(b)
				for _, want := range []string{"effective_access_not_evaluated", "deny_statements_present", "organizations_not_collected", "selector_may_match_nothing"} {
					if !contractContains(codes, want) {
						t.Errorf("limitations %v, want %s", codes, want)
					}
				}
				if contractContains(codes, "resource_existence_not_verified") {
					t.Errorf("a selector-only grant carries resource_existence_not_verified (D-21)")
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets, "claim", f.grantToolbox), shape: contractEvidenceMany,
			check: func(t *testing.T, b map[string]any) {
				if s := digs(b, "meta", "summary", "sentence"); !strings.Contains(s, "by 2 statements") {
					t.Errorf("summary = %q (D-79)", s)
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.executesLambda), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.crossEdge), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantOps), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantOwn), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantFinance), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantExternal), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.lambda), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.oidc), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets, "include", "raw"), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				if raw := digl(b, "data", "raw"); len(raw) != len(digl(b, "data", "facts")) {
					t.Errorf("raw = %s, want aligned with facts (D-80)", contractJSON(raw))
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", coverageB), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "status", "collection") != "stale" || evidenceLim(b, "surface_denied") == nil {
					t.Errorf("coverage claim = %s", contractJSON(b["data"]))
				}
			}},

		/* ---------------------------------- lookup ------------------------------ */

		{route: "GET /lookup", path: "/lookup" + qs("cloud_ref", "cloud_identity:"+cloudRole.String()), shape: contractLookup,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "ref") != f.shared || digs(b, "data", "lifecycle") != "active" {
					t.Errorf("lookup role = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /lookup", path: "/lookup" + qs("cloud_ref", "cloud_workload:"+cloudLambda.String()), shape: contractLookup,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "ref") != f.lambda {
					t.Errorf("lookup lambda = %s", contractJSON(b["data"]))
				}
			}},
	}

	covered := map[string]bool{}
	for _, c := range cases {
		c := c
		covered[c.route] = true
		t.Run(c.route+" "+c.path, func(t *testing.T) {
			code, body := api.get(c.path)
			mustStatus(t, c.path, code, body, http.StatusOK)
			contractCheck(t, c.path, body, c.shape)
			contractRevisionEcho(t, c.path, body)
			if c.check != nil {
				c.check(t, body)
			}
		})
	}

	// Every GET the route table mounts has a case above; the one POST has its
	// own test (TestP2ContractClassificationPost).
	for _, r := range api.eng.Routes() {
		route := r.Method + " " + strings.TrimPrefix(r.Path, "/api/iga/v1")
		if r.Method == http.MethodPost {
			continue
		}
		if !covered[route] {
			t.Errorf("route %s has no contract case", route)
		}
	}
}

// contractRevisionEcho is §5.1's echo: every revision-bound response carries
// the current revision and its publication time -- and /capabilities, which
// reports the deployment and not the graph, carries no meta at all.
func contractRevisionEcho(t *testing.T, path string, body map[string]any) {
	t.Helper()
	if path == "/capabilities" {
		if _, has := body["meta"]; has {
			t.Errorf("/capabilities carries meta %v", body["meta"])
		}
		return
	}
	if num(body, "meta", "rev") != 3 || digs(body, "meta", "graph_state") != "published" || dig(body, "meta", "published_at") == nil {
		t.Errorf("%s meta = %s, want rev 3, published", path, contractJSON(body["meta"]))
	}
}

// contractSamePublication: a publication's time is rendered the same way
// wherever it appears, so the console can compare the pinned revision's
// published_at with /pipeline's and with a 409's (D-94).
func contractSamePublication(t *testing.T, body map[string]any, other string) {
	t.Helper()
	if got := digs(body, "meta", "published_at"); got != other {
		t.Errorf("the current publication's time renders as %q in meta and %q elsewhere", got, other)
	}
}

var contractKindRank = map[string]int{"exact": 0, "selector": 1, "external": 2}

func contractPluck(rows []any, path ...any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, digs(r, path...))
	}
	return out
}

func contractByName(rows []any, path ...any) map[string]any {
	out := map[string]any{}
	for _, r := range rows {
		out[digs(r, path...)] = r
	}
	return out
}

func contractFacet(body map[string]any, name string) map[string]int64 {
	out := map[string]int64{}
	for _, v := range digl(body, "meta", "facets", name) {
		out[digs(v, "value")] = num(v, "count")
	}
	return out
}

func contractSurface(t *testing.T, body map[string]any, account, surface string) any {
	t.Helper()
	for _, a := range digl(body, "data") {
		if digs(a, "account", "id") != account {
			continue
		}
		for _, s := range digl(a, "surfaces") {
			if digs(s, "surface") == surface {
				return s
			}
		}
	}
	t.Fatalf("coverage has no %s %s", account, surface)
	return nil
}

func contractHasCoverage(body map[string]any, account, surface, state string) bool {
	for _, c := range digl(body, "meta", "coverage") {
		if digs(c, "account_id") == account && digs(c, "surface") == surface && digs(c, "state") == state {
			return true
		}
	}
	return false
}

func contractEvents(body map[string]any) map[string]any {
	out := map[string]any{}
	for _, e := range digl(body, "data") {
		if _, seen := out[digs(e, "event")]; !seen {
			out[digs(e, "event")] = e
		}
	}
	return out
}

func contractEventNames(body map[string]any) []string {
	return contractPluck(digl(body, "data"), "event")
}

func contractHasEdge(body map[string]any, claim string, pred func(any) bool) bool {
	for _, e := range digl(body, "data", "edges") {
		if (claim == "" || digs(e, "claim") == claim) && pred(e) {
			return true
		}
	}
	return false
}

func contractContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// contractCanonical renders a value as canonical JSON (sorted keys), so two
// limitations compare by content.
func contractCanonical(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// D-35: a graph edge IS a claim, and its limitations are the SAME function's
// as /evidence's for that claim, restricted to the codes that need no facts --
// same codes, same fields, same order -- plus, on an edge that crosses
// accounts, the far account's coverage (§5.4). And every path carries exactly
// the union of its steps' limitations.
func TestP2ContractGraphLimitationsAreEvidences(t *testing.T) {
	f := contractLab(t)
	api := f.api
	evidence := map[string][]any{}
	fetch := func(claim string) []any {
		if l, ok := evidence[claim]; ok {
			return l
		}
		b := evidenceGet(t, api, claim)
		var out []any
		for _, l := range digl(b, "data", "limitations") {
			if igaread.FactFreeLimitations[digs(l, "code")] {
				out = append(out, l)
			}
		}
		evidence[claim] = out
		return out
	}
	responses := map[string]map[string]any{}
	for _, p := range []string{
		"/graph" + qs("root", f.lambda, "direction", "forward", "assume_hops", "4"),
		"/graph" + qs("root", f.tickets, "direction", "reverse"),
		"/graph" + qs("root", f.priya, "direction", "forward"),
		"/graph" + qs("root", f.rootC, "direction", "forward"),
		"/graph/expand" + qs("node", f.shared, "edge", "can_assume", "direction", "forward"),
		"/graph/path" + qs("from", f.lambda, "to", f.tickets),
	} {
		code, body := api.get(p)
		mustStatus(t, p, code, body, http.StatusOK)
		responses[p] = body
	}
	checked := 0
	for p, body := range responses {
		var edges []any
		edges = append(edges, digl(body, "data", "edges")...)
		for _, path := range digl(body, "data", "paths") {
			edges = append(edges, digl(path, "edges")...)
		}
		for _, e := range edges {
			claim := digs(e, "claim")
			want := fetch(claim)
			got := digl(e, "limitations")
			var extra, wantOnly []string
			gotSet := map[string]bool{}
			for _, l := range got {
				gotSet[contractCanonical(l)] = true
			}
			wantSet := map[string]bool{}
			for _, l := range want {
				k := contractCanonical(l)
				wantSet[k] = true
				if !gotSet[k] {
					wantOnly = append(wantOnly, k)
				}
			}
			for _, l := range got {
				k := contractCanonical(l)
				if wantSet[k] {
					continue
				}
				// The far account's coverage is the graph's own addition (§5.4).
				if dig(e, "crosses_account") == true && strings.HasPrefix(digs(l, "code"), "surface_") {
					continue
				}
				extra = append(extra, k)
			}
			if len(extra) > 0 || len(wantOnly) > 0 {
				t.Errorf("%s edge %s (%s): graph has %v beyond /evidence; /evidence has %v the graph lacks",
					p, claim, digs(e, "kind"), extra, wantOnly)
			}
			if dig(e, "crosses_account") != true && contractCanonical(got) != contractCanonical(contractOrNil(want)) {
				t.Errorf("%s edge %s: order differs from /evidence: %s vs %s", p, claim, contractCanonical(got), contractCanonical(want))
			}
			checked++
		}
		for i, path := range digl(body, "data", "paths") {
			union := map[string]bool{}
			for _, step := range append(append([]any{}, digl(path, "nodes")...), digl(path, "edges")...) {
				for _, l := range digl(step, "limitations") {
					union[contractCanonical(l)] = true
				}
			}
			have := map[string]bool{}
			for _, l := range digl(path, "limitations") {
				have[contractCanonical(l)] = true
			}
			if !reflect.DeepEqual(union, have) {
				t.Errorf("%s path %d limitations are not the union of its steps': %v vs %v", p, i, have, union)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d edges compared; the fixture's graphs should hold far more", checked)
	}
}

func contractOrNil(ls []any) []any {
	if ls == nil {
		return []any{}
	}
	return ls
}
