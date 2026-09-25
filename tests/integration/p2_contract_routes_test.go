package integration

// The frozen §5 contract, route by route (SPEC-iga-phase2-graph.md §5.2,
// §5.3; T6.7): every route RegisterIGAGraphReadRoutes mounts is called against
// the ONE rich estate of p2_contract_lab_test.go -- built by the real scan
// worker and projector -- and its body is checked field by field against the
// shapes of p2_contract_schemas_test.go, then against what the estate says
// each field must hold. A route added to the table without a contract case,
// or a field renamed, dropped, turned from null into absent or added without
// the contract, fails here. The error statuses and envelopes are
// p2_contract_errors_test.go's.

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

// contractCurrentRev is the fixture's revision: A, B, A again, B again.
const contractCurrentRev = 4

// contractCases is the table: at least one case per GET route, and for the
// routes whose body differs by object kind (a role, a user, a group), one per
// kind.
func contractCases(t *testing.T, f *contractFixture) []contractCase {
	t.Helper()
	u := func(ref string) string { return refUUID(t, ref).String() }
	l := f.l

	var cloudRoles, cloudLambdas []uuid.UUID
	l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND name = 'SharedToolRole'`, l.ws).Scan(&cloudRoles)
	l.db.Raw(`SELECT id FROM cloud_workload WHERE workspace_id = ? AND name = 'ticket-tools'`, l.ws).Scan(&cloudLambdas)
	if len(cloudRoles) != 1 || len(cloudLambdas) != 1 {
		t.Fatalf("fixture: cloud inventory rows (role %v, lambda %v), want one each", cloudRoles, cloudLambdas)
	}
	grantOps := evidenceGrant(t, l, "ops", "OpsRead", "ReadOps")
	grantOwn := evidenceGrant(t, l, "priya", "PriyaOwn", "OwnRead")
	grantFinance := evidenceGrant(t, l, "SharedToolRole", "FinanceAll", "AllButFinance")
	grantExternal := evidenceGrant(t, l, "SharedToolRole", "ExternalKey", "Decrypt")
	grantSandbox := evidenceGrant(t, l, "CrossRole", "SandboxRead", "ReadSandbox")
	grantLegacy := evidenceGrant(t, l, "SharedToolRole", "LegacyRead", "LegacyGet") // ended by the detach
	opsBucket := evidenceNode(t, l, "resource", "iga_resources", "arn:aws:s3:::ops-bucket/*")
	// D-80: a coverage claim names a run the revision was built from -- B's
	// SECOND run, which superseded its first everywhere.
	coverageB := igaread.CoverageRef(f.runB2.ID, "iam_roles")

	return append([]contractCase{
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
			if digs(b, "data", "barrier", "state") != "idle" || num(b, "data", "current_rev") != contractCurrentRev {
				t.Errorf("pipeline = %s, want idle at the current rev", contractJSON(b["data"]))
			}
			accts := digl(b, "data", "accounts")
			if len(accts) != 2 || digs(accts[0], "account_id") != accountA || digs(accts[1], "account_id") != accountB {
				t.Fatalf("pipeline accounts = %s, want A then B (by label, D-92)", contractJSON(accts))
			}
			// D-56: every connector with a published run is at the current rev;
			// the rev that published its own latest run is on its projection.
			if num(accts[0], "last_published_rev") != contractCurrentRev || num(accts[1], "last_published_rev") != contractCurrentRev ||
				num(accts[0], "projection", "rev") != 3 || num(accts[1], "projection", "rev") != 4 ||
				digs(accts[1], "latest_run", "ref") != refOf("cloud_scan_run", f.runB2.ID) {
				t.Errorf("pipeline revs = %s", contractJSON(accts))
			}
		}},
		{route: "GET /coverage", path: "/coverage", shape: contractCoverage, check: func(t *testing.T, b map[string]any) {
			if n := len(digl(b, "data")); n != 2 {
				t.Fatalf("coverage accounts = %d, want 2 (the connected accounts)", n)
			}
			// §5.3: state, count, error_code, api, since, prevents, run -- the
			// AWS code as returned, never a guessed permission (§2.14.13).
			s := contractSurface(t, b, accountB, "iam_roles")
			if digs(s, "state") != "denied" || digs(s, "error_code") != "AccessDenied" || digs(s, "prevents") != "surface_denied" ||
				dig(s, "count") != nil || digs(s, "run") != refOf("cloud_scan_run", f.runB2.ID) || digs(s, "ref") != coverageB ||
				digs(s, "api") == "" || dig(s, "since") == nil {
				t.Errorf("B iam_roles = %s, want denied AccessDenied surface_denied, count null, B's second run", contractJSON(s))
			}
			if s := contractSurface(t, b, accountA, "iam_roles"); digs(s, "state") != "reached" || dig(s, "prevents") != nil ||
				dig(s, "count") == nil || dig(s, "error_code") != nil {
				t.Errorf("A iam_roles = %s, want reached with a count, prevents and error_code null", contractJSON(s))
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
			// §5.3 l.5853: not resolved carries the ARN the workload names.
			if er := dig(byName["orphan-fn"], "execution_role"); digs(er, "state") != "not_in_inventory" ||
				digs(er, "execution_role_arn") != f.a.roleARN("MissingRole") {
				t.Errorf("orphan-fn execution_role = %s, want not_in_inventory naming MissingRole", contractJSON(er))
			}
			if digs(byName["support-bot"], "classification") != "provider_native_agent" ||
				digs(byName["ticket-tools"], "classification") != "classified_agent" || num(byName["ticket-tools"], "classification_version") != 1 {
				t.Errorf("classifications = %s", contractJSON(rows))
			}
			if a := dig(byName["ticket-tools"], "account"); digs(a, "id") != accountA || dig(a, "connected") != true || digs(a, "label") != "acct-"+accountA {
				t.Errorf("account = %s", contractJSON(a))
			}
			if num(b, "meta", "total") != 4 || dig(b, "meta", "next_cursor") != nil || num(b, "meta", "limit") != 100 || dig(b, "meta", "facets") != nil {
				t.Errorf("list meta = %s, want total 4, no next page, limit 100, no facets unasked", contractJSON(b["meta"]))
			}
		}},
		{route: "GET /workloads", path: "/workloads?facets=account,runtime_kind,classification,region&limit=1",
			shape: contractList(contractWorkloadRow, contractListMeta()), check: func(t *testing.T, b map[string]any) {
				if n := len(digl(b, "data")); n != 1 || dig(b, "meta", "next_cursor") == nil || num(b, "meta", "total") != 4 || num(b, "meta", "limit") != 1 {
					t.Errorf("limit=1 page = %d rows, meta %s", n, contractJSON(b["meta"]))
				}
				fa := contractFacet(b, "account")
				if fa["unknown"] != 0 || fa[accountA] != 4 || contractFacetLabel(b, "account", accountA) != "acct-"+accountA {
					t.Errorf("account facet = %v, want A 4 and unknown offered at 0 (D-14)", fa)
				}
				if rk := contractFacet(b, "runtime_kind"); rk["lambda_function"] != 2 || rk["ecs_task_definition"] != 1 || rk["bedrock_agent"] != 1 {
					t.Errorf("runtime_kind facet = %v", rk)
				}
				if c := contractFacet(b, "classification"); c["agent"] != 2 || c["provider_native_agent"] != 1 || c["classified_agent"] != 1 || c["unclassified"] != 2 {
					t.Errorf("classification facet = %v", c)
				}
				if r := contractFacet(b, "region"); r["us-east-1"] != 4 || r["not_stated"] != 0 {
					t.Errorf("region facet = %v, want us-east-1 4 and not_stated offered (D-14)", r)
				}
			}},
		{route: "GET /workloads/:id", path: "/workloads/" + u(f.lambda),
			shape: contractDetail(contractWorkloadDetail, contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "ref") != f.lambda || digs(d, "continuity") != "recognition_only" || dig(d, "retired_reason") != nil {
					t.Errorf("detail = %s", contractJSON(d))
				}
				// §5.3: the latest decision {decision, purpose, reason, decided_by
				// {user_id, display}, decided_at}; §5.5 display names.
				if digs(d, "decision", "decision") != "classified_agent" || digs(d, "decision", "decided_by", "display") != "Priya Shah" ||
					digs(d, "decision", "decided_by", "user_id") != f.user.String() || digs(d, "decision", "purpose") != "Customer support triage" ||
					digs(d, "decision", "reason") != "Owns tier-1 ticket routing" {
					t.Errorf("decision = %s", contractJSON(dig(d, "decision")))
				}
				if s := digl(d, "sources"); len(s) != 1 || digs(s[0], "integration") != refOf("cloud_connector", f.a.conn) ||
					digs(s[0], "account", "id") != accountA || digs(s[0], "state") != "current" || dig(s[0], "ended_reason") != nil {
					t.Errorf("sources = %s", contractJSON(s))
				}
				// D-83: stated, and false for a token that is no verified human.
				if !reflect.DeepEqual(dig(b, "meta", "capabilities"), map[string]any{"can_classify": false}) {
					t.Errorf("capabilities = %v, want exactly {can_classify: false}", dig(b, "meta", "capabilities"))
				}
			}},
		{route: "GET /workloads/:id", path: "/workloads/" + f.agent, // D-5: the typed ref form
			shape: contractDetail(contractWorkloadDetail, contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))),
			check: func(t *testing.T, b map[string]any) {
				pa := dig(b, "data", "provider_attrs")
				if digs(pa, "foundation_model") != "amazon.titan-text-express-v1" || digs(pa, "status") != "PREPARED" ||
					dig(pa, "env_var_names") != nil || dig(pa, "gateway_targets") != nil {
					t.Errorf("bedrock provider_attrs = %s (D-85)", contractJSON(pa))
				}
				if dig(b, "data", "decision") != nil {
					t.Errorf("decision = %v, want null: nobody decided", dig(b, "data", "decision"))
				}
			}},
		{route: "GET /workloads/:id/identities", path: "/workloads/" + u(f.lambda) + "/identities", shape: contractWorkloadIdentities,
			check: func(t *testing.T, b map[string]any) {
				ex := digl(b, "data", "execution", "items")
				if len(ex) != 1 || digs(ex[0], "identity", "ref") != f.shared || digs(ex[0], "claim") != f.executesLambda ||
					digs(ex[0], "type") != "executes_as" || num(ex[0], "used_by_count", "value") != 2 || dig(ex[0], "used_by_count", "exact") != true {
					t.Errorf("execution = %s, want SharedToolRole used by 2 workloads", contractJSON(ex))
				}
				if digs(b, "data", "execution_role_state") != "resolved" || dig(b, "data", "execution_role_arn") != nil {
					t.Errorf("execution_role_state/_arn = %v / %v", dig(b, "data", "execution_role_state"), dig(b, "data", "execution_role_arn"))
				}
				ma := digl(b, "data", "may_assume", "items")
				if len(ma) != 1 || digs(ma[0], "target", "ref") != f.cross || digs(ma[0], "claim") != f.crossEdge ||
					digs(ma[0], "via_identity") != f.shared || dig(ma[0], "conditions") != nil || digs(ma[0], "state") != "stale" ||
					dig(ma[0], "statement", "negated") != false || digs(ma[0], "statement", "sid") != "FromTools" ||
					!strings.Contains(digs(ma[0], "statement", "key"), "trust") {
					t.Errorf("may_assume = %s, want SharedToolRole -> CrossRole, stale since B's roles were not read", contractJSON(ma))
				}
				if !reflect.DeepEqual(dig(b, "meta", "capabilities"), map[string]any{}) {
					t.Errorf("capabilities = %v, want {} (D-97)", dig(b, "meta", "capabilities"))
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
				// §5.3: one line per grant -- two policies, two lines, never merged.
				if len(gs) != 2 || digs(gs[0], "claim") != f.grantReadTickets || digs(gs[1], "claim") != f.grantToolbox ||
					digs(gs[0], "statement", "sid") != "ReadTickets" || digs(gs[1], "statement", "sid") != "" ||
					num(gs[0], "statement", "index") != 1 || num(gs[1], "statement", "index") != 1 ||
					digs(gs[0], "policy", "name") != "TicketRead" || digs(gs[0], "via_identity") != f.shared {
					t.Errorf("support-tickets/* grants = %s, want ReadTickets and the Sid-less ToolboxRead, one line each", contractJSON(gs))
				}
				if r := dig(tickets, "restrictions"); num(r, "deny_statements") != 1 || dig(r, "permissions_boundary") != false {
					t.Errorf("restrictions = %s, want the one Deny, no boundary (D-78)", contractJSON(r))
				}
				star := contractByName(rows, "resource", "text")["*"]
				if ex := digl(star, "grants", 0, "exclusions"); len(ex) != 1 || digs(ex[0], "text") != contractFinance {
					t.Errorf("* grant exclusions = %s, want finance/*", contractJSON(ex))
				}
				if r := dig(star, "resource"); dig(r, "service") != nil || dig(r, "account") != nil || dig(r, "region") != nil {
					t.Errorf("* = %s, want service, account and region null", contractJSON(r))
				}
				if k := dig(contractByName(rows, "resource", "text")[contractKeyC], "resource"); digs(k, "kind") != "external" ||
					dig(k, "account", "connected") != false || digs(k, "account", "id") != contractAccountC || digs(k, "service") != "kms" {
					t.Errorf("C's key = %s, want external in an unconnected account", contractJSON(k))
				}
				if !contractHasCoverage(b, accountA, "policy_documents", "partial") {
					t.Errorf("coverage = %s, want A's unreadable policy document", contractJSON(dig(b, "meta", "coverage")))
				}
			}},
		{route: "GET /workloads/:id/changes", path: "/workloads/" + u(f.lambda) + "/changes", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				ev := contractEvents(b)
				for _, want := range []string{"first_seen", "relationship_started", "policy_attached", "grant_started",
					"statement_revised", "grant_ended", "policy_detached"} {
					if ev[want] == nil {
						t.Errorf("workload changes = %v, want %s", contractEventNames(b), want)
					}
				}
				// §5.3: a grant's end carries the grants that REMAIN on the path.
				ge := ev["grant_ended"]
				if digs(ge, "via") != f.shared || len(digl(ge, "remaining")) != 2 || digs(ge, "paths", 0, "remains") != "current" ||
					digs(ge, "paths", 0, "target") != f.tickets {
					t.Errorf("grant_ended = %s, want via SharedToolRole with TicketRead and ToolboxRead remaining", contractJSON(ge))
				}
				if sr := ev["statement_revised"]; dig(sr, "before") == nil || dig(sr, "after") == nil || num(sr, "rev") != 3 ||
					digs(sr, "run") != refOf("cloud_scan_run", f.runA2.ID) {
					t.Errorf("statement_revised = %s, want before/after, at rev 3 by A's second run", contractJSON(sr))
				}
				if digs(b, "meta", "kind") != "configuration" || num(b, "meta", "limit") != 50 || dig(b, "meta", "history_begins") == nil {
					t.Errorf("changes meta = %s", contractJSON(b["meta"]))
				}
			}},
		{route: "GET /workloads/:id/changes", path: "/workloads/" + u(f.lambda) + "/changes?kind=coverage", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "meta", "kind") != "coverage" {
					t.Errorf("kind = %v", dig(b, "meta", "kind"))
				}
				for _, e := range digl(b, "data") {
					if digs(e, "event") != "coverage_changed" {
						t.Errorf("kind=coverage returned %s", contractJSON(e))
					}
				}
			}},
		{route: "GET /workloads/:id/classification", path: "/workloads/" + u(f.lambda) + "/classification",
			shape: contractList(contractHistoryItem, contractListMeta()), check: func(t *testing.T, b map[string]any) {
				h := digl(b, "data")
				if len(h) != 1 || digs(h[0], "previous") != "unclassified" || num(h[0], "result_version") != 1 ||
					num(h[0], "against_version") != 0 || dig(h[0], "undoes_decision_id") != nil || digs(h[0], "decided_by", "display") != "Priya Shah" {
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
				byName := contractByName(rows, "name")
				if n := byName["SharedToolRole"]; num(n, "used_by_count", "value") != 2 || dig(n, "used_by_count", "exact") != true {
					t.Errorf("SharedToolRole used_by_count = %v", dig(n, "used_by_count"))
				}
				// D-74: a stale row says why, with the surface that was not read.
				if n := byName["CrossRole"]; digs(n, "state") != "stale" || digs(n, "stale_reason", 0, "surface") != "iam_roles" ||
					digs(n, "stale_reason", 0, "state") != "denied" || digs(n, "stale_reason", 0, "account_id") != accountB {
					t.Errorf("CrossRole = %s, want stale because B's iam_roles was denied", contractJSON(n))
				}
				if fa := contractFacet(b, "account"); fa[accountA] != 7 || fa[accountB] != 2 || fa["unknown"] != 0 {
					t.Errorf("account facet = %v", fa)
				}
				if k := contractFacet(b, "kind"); k["iam_role"] != 7 || k["iam_user"] != 1 || k["iam_group"] != 1 {
					t.Errorf("kind facet = %v", k)
				}
				if !contractHasCoverage(b, accountB, "iam_groups", "denied") || !contractHasCoverage(b, accountB, "iam_roles", "denied") {
					t.Errorf("identities coverage = %s, want B's denied iam_groups and iam_roles", contractJSON(dig(b, "meta", "coverage")))
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
					digs(d, "provider_attrs", "tags", "team") != "support" || dig(d, "retired_reason") != nil ||
					dig(d, "provider_attrs", "trust_has_deny") != false || dig(d, "provider_attrs", "permissions_boundary_arn") != nil {
					t.Errorf("SharedToolRole = %s", contractJSON(d))
				}
				if !reflect.DeepEqual(dig(b, "meta", "capabilities"), map[string]any{}) {
					t.Errorf("capabilities = %v, want {} (D-97)", dig(b, "meta", "capabilities"))
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
		{route: "GET /identities/:id", path: "/identities/" + u(f.cross), shape: contractIdentityDetail("iam_role"),
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "state") != "stale" || len(digl(d, "stale_reason")) == 0 || digs(d, "sources", 0, "state") != "stale" {
					t.Errorf("CrossRole = %s, want stale with its stale_reason and a stale source", contractJSON(d))
				}
				if !contractHasCoverage(b, accountB, "iam_roles", "denied") {
					t.Errorf("detail coverage = %s, want its own partition's gap (D-73)", contractJSON(dig(b, "meta", "coverage")))
				}
			}},
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
				ps := digl(b, "data", "principals", "items")
				if got := contractPluck(ps, "principal", "name"); !reflect.DeepEqual(got, []string{"LoopRole", "SharedToolRole"}) {
					t.Errorf("CrossRole principals = %v, want LoopRole (the cycle) and A's SharedToolRole", got)
				}
				// The same can_assume, the same trust-statement object, as the
				// workload's may_assume names it (D-98).
				for _, p := range ps {
					if digs(p, "claim") == f.crossEdge && (digs(p, "mechanism") != "sts_assume_role" || digs(p, "state") != "stale" ||
						digs(p, "statement", "sid") != "FromTools") {
						t.Errorf("SharedToolRole -> CrossRole = %s", contractJSON(p))
					}
				}
			}},
		{route: "GET /identities/:id/used-by", path: "/identities/" + u(f.ops) + "/used-by", shape: contractUsedBy("iam_group"),
			check: func(t *testing.T, b map[string]any) {
				if m := digl(b, "data", "members", "items"); len(m) != 1 || digs(m[0], "member", "ref") != f.priya || digs(m[0], "type") != "member_of" {
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
				// §5.3: a Deny appears under its policy with effect deny and no grant.
				if st := digl(ps["GuardRails"], "statements"); len(st) != 1 || digs(st[0], "effect") != "deny" || dig(st[0], "grant") != nil {
					t.Errorf("GuardRails = %s, want the Deny with no grant", contractJSON(st))
				}
				if st := digl(ps["AuditRead"], "statements"); len(st) != 0 {
					t.Errorf("AuditRead statements = %s, want none (unreadable document)", contractJSON(st))
				}
				if st := digl(ps["TicketRead"], "statements"); len(st) != 2 || digs(st[0], "grant") != f.grantReadTickets ||
					num(st[1], "index") != 2 || dig(st[1], "condition") == nil || num(st[1], "revision_count") != 2 {
					t.Errorf("TicketRead = %s, want ReadTickets granted and ListTickets (index 2) with its edited Condition", contractJSON(st))
				}
				if dig(b, "data", "boundary", "policy") != nil || len(digl(b, "data", "inherited")) != 0 {
					t.Errorf("boundary/inherited = %s", contractJSON(b["data"]))
				}
				act := dig(b, "data", "activity")
				if digs(act, "source") != "access_advisor" || digs(act, "state") != "collected" || digs(act, "services", 0, "namespace") != "s3" ||
					dig(act, "services", 0, "last_authenticated_attempt") == nil || digs(act, "tracking_note") == "" {
					t.Errorf("activity = %s (D-86)", contractJSON(act))
				}
			}},
		{route: "GET /identities/:id/permissions", path: "/identities/" + u(f.priya) + "/permissions", shape: contractPermissions,
			check: func(t *testing.T, b map[string]any) {
				bp := dig(b, "data", "boundary", "policy")
				// §5.3: boundary policies appear under boundary, never as grants.
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
				if ev := contractEvents(b); ev["relationship_started"] == nil || ev["policy_detached"] == nil || ev["first_seen"] == nil {
					t.Errorf("identity changes = %v", contractEventNames(b))
				}
			}},
		{route: "GET /identities/:id/changes", path: "/identities/" + u(f.temp) + "/changes", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				if r := contractEvents(b)["retired"]; digs(r, "reason") != "unsupported" || num(r, "rev") != 3 {
					t.Errorf("TempRole retired = %s, want reason unsupported at rev 3", contractJSON(r))
				}
			}},
		{route: "GET /identities/:id/changes", path: "/identities/" + u(f.cross) + "/changes?kind=coverage", shape: contractChanges,
			check: func(t *testing.T, b map[string]any) {
				var found bool
				for _, e := range digl(b, "data") {
					if digs(e, "detail", "surface") == "iam_roles" && digs(e, "before", "state") == "reached" && digs(e, "after", "state") == "denied" {
						found = true
					}
				}
				if !found {
					t.Errorf("CrossRole coverage changes = %s, want iam_roles reached -> denied", contractJSON(b["data"]))
				}
			}},

		/* -------------------------- external principals ------------------------ */

		{route: "GET /external-principals/:id", path: "/external-principals/" + u(f.oidc), shape: contractExternalDetail,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				if digs(d, "mechanism") != "oidc" || digs(d, "issuer") != "token.actions.githubusercontent.com" ||
					digs(d, "subject") != contractSub || dig(d, "account") != nil || dig(d, "account_connected") != nil ||
					dig(d, "resolution") != nil || digs(d, "lifecycle") != "active" || dig(d, "retired_reason") != nil {
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
					t.Errorf("resources = %v kinds %v, want 8 by kind rank (D-13)", contractPluck(rows, "text"), kinds)
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
				// The six S3 references state no account (Unknown account,
				// §2.14.10); the keys state theirs; A is offered at 0 (D-14).
				if fa := contractFacet(b, "account"); fa["unknown"] != 6 || fa[contractAccountC] != 1 || fa[accountB] != 1 || fa[accountA] != 0 {
					t.Errorf("account facet = %v, want the account-less references under unknown", fa)
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.tickets), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				// Two connectors vouch for the selector (§2.10B): A's and B's policies name it.
				if s := digl(d, "sources"); len(s) != 2 || dig(d, "resource_policy", "read") != false || dig(d, "resource_policy", "has_deny") != nil ||
					digs(d, "existence") != "not_verified" || dig(d, "retired_reason") != nil {
					t.Errorf("support-tickets/* = %s", contractJSON(d))
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.bucket), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				if rp := dig(b, "data", "resource_policy"); dig(rp, "read") != true || dig(rp, "has_deny") != true {
					t.Errorf("bucket resource_policy = %s, want read with a Deny (D-19)", contractJSON(rp))
				}
			}},
		{route: "GET /resources/:id", path: "/resources/" + u(f.keyC), shape: contractResourceDetail,
			check: func(t *testing.T, b map[string]any) {
				if a := dig(b, "data", "account"); digs(a, "id") != contractAccountC || dig(a, "connected") != false || digs(b, "data", "kind") != "external" {
					t.Errorf("C's key = %s, want external in unconnected C (D-16)", contractJSON(b["data"]))
				}
			}},
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
				want := []string{f.grantReadTickets, f.grantToolbox, grantSandbox}
				sort.Strings(want)
				if !reflect.DeepEqual(grants, want) {
					t.Errorf("access grants = %v, want %v", grants, want)
				}
				dn := digl(b, "data", "deny_statements_naming")
				if len(dn) != 1 || digs(dn[0], "statement", "sid") != "NoDeletes" || len(digl(b, "data", "excluded_by")) != 0 {
					t.Errorf("restrictions = %s", contractJSON(b["data"]))
				}
				// §5.3 "paged by holder": limit and total count HOLDERS -- two
				// holders, three (holder, grant) rows (D-99).
				if num(b, "meta", "total") != 2 || len(acc) != 3 {
					t.Errorf("access meta = %s, want the two holders counted", contractJSON(b["meta"]))
				}
			}},
		{route: "GET /resources/:id/access", path: "/resources/" + u(f.finance) + "/access", shape: contractResourceAccess,
			check: func(t *testing.T, b map[string]any) {
				ex := digl(b, "data", "excluded_by")
				if len(digl(b, "data", "access")) != 0 || len(ex) != 1 || digs(ex[0], "statement", "ref") != f.allButFinance {
					t.Errorf("finance/* access = %s, want AllButFinance under excluded_by only (E4, B19)", contractJSON(b["data"]))
				}
			}},
		{route: "GET /resources/:id/access", path: "/resources/" + u(opsBucket) + "/access", shape: contractResourceAccess,
			check: func(t *testing.T, b map[string]any) {
				// D-18: the group's own row, and one for its member through it,
				// naming the group and the membership the grant reaches her by.
				rows := contractByName(digl(b, "data", "access"), "holder", "name")
				if len(rows) != 2 || dig(rows["ops"], "via_group") != nil || digs(rows["ops"], "grant", "claim") != grantOps {
					t.Errorf("ops-bucket/* access = %s, want ops's own row and priya's through it", contractJSON(b["data"]))
				}
				vg := dig(rows["priya"], "via_group")
				if digs(vg, "ref") != f.ops || digs(vg, "name") != "ops" || digs(vg, "membership", "state") != "current" ||
					!strings.HasPrefix(digs(vg, "membership", "claim"), "relationship:") || digs(rows["priya"], "grant", "claim") != grantOps {
					t.Errorf("priya via ops = %s", contractJSON(rows["priya"]))
				}
				if num(b, "meta", "total") != 2 {
					t.Errorf("access meta = %s, want two holders", contractJSON(b["meta"]))
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
				// §5.3's example, node by node: a workload and a role labelled by
				// name, a statement by its actions, a resource by the resource
				// part of its ARN, each with its kind.
				for ref, want := range map[string][2]string{
					f.lambda: {"workload", "ticket-tools"}, f.shared: {"iam_role", "SharedToolRole"},
					f.readTickets: {"statement", "s3:GetObject"}, f.toolboxStmt: {"statement", "s3:GetObject"},
					f.tickets: {"selector", "support-tickets/*"},
				} {
					if n := nodes[ref]; digs(n, "kind") != want[0] || digs(n, "label") != want[1] {
						t.Errorf("node %s = %s, want kind %q label %q", ref, contractJSON(n), want[0], want[1])
					}
				}
				if !contractHasEdge(b, f.executesLambda, func(e any) bool {
					return digs(e, "kind") == "executes_as" && digs(e, "from") == f.lambda && digs(e, "to") == f.shared && digs(e, "state") == "current"
				}) {
					t.Errorf("no current executes_as edge ticket-tools -> SharedToolRole")
				}
				if !contractHasEdge(b, "", func(e any) bool {
					return digs(e, "kind") == "target" && digs(e, "mode") == "resource" && digs(e, "from") == f.readTickets && digs(e, "to") == f.tickets
				}) {
					t.Errorf("no target edge ReadTickets -> support-tickets/* (mode resource)")
				}
				// §5.4 lifecycle: current and stale by default; the ended LegacyGet
				// grant only when include_ended asks (D-12).
				if contractHasEdge(b, grantLegacy, func(any) bool { return true }) {
					t.Errorf("the ended LegacyGet grant is on the default graph")
				}
				for _, e := range digl(b, "data", "frontier") {
					if strings.HasSuffix(digs(e, "expand"), contractIncludeEnded) {
						t.Errorf("frontier expand %q asks for ended claims the request did not", digs(e, "expand"))
					}
				}
				rt, tb := nodes[f.readTickets], nodes[f.toolboxStmt]
				// §5.4 independent grants: two statement nodes, one group_key.
				if rt == nil || tb == nil || digs(rt, "group_key") == "" || digs(rt, "group_key") != digs(tb, "group_key") ||
					dig(tb, "sid") != "" || digs(rt, "policy") != "TicketRead" || digs(tb, "policy") != "ToolboxRead" {
					t.Errorf("ReadTickets/ToolboxRead nodes = %s / %s", contractJSON(rt), contractJSON(tb))
				}
				if fin := nodes[f.allButFinance]; len(digl(fin, "exclusions")) != 1 || nodes[f.finance] != nil {
					t.Errorf("FinanceAll = %s; finance/* must be an exclusion, never a node", contractJSON(fin))
				}
				if !contractHasEdge(b, f.crossEdge, func(e any) bool {
					return dig(e, "crosses_account") == true && digs(e, "state") == "stale" && len(digl(e, "stale_reason")) > 0
				}) {
					t.Errorf("SharedToolRole -> CrossRole must be crosses_account, stale, with its stale_reason")
				}
				if !contractHasEdge(b, f.grantReadTickets, func(e any) bool {
					return digs(e, "kind") == "grant" && digs(e, "from") == f.shared && digs(e, "to") == f.readTickets && digs(e, "policy") == "TicketRead"
				}) {
					t.Errorf("no grant edge SharedToolRole -> ReadTickets")
				}
				if n := nodes[f.shared]; num(n, "restrictions", "deny_statements") != 1 || dig(n, "restrictions", "permissions_boundary") != false {
					t.Errorf("SharedToolRole restrictions = %s", contractJSON(dig(n, "restrictions")))
				}
				if digs(b, "data", "truncated", "bound_by") != "assume_hops" || len(digl(b, "data", "frontier")) == 0 {
					t.Errorf("truncated/frontier = %v / %v, want assume_hops with a frontier", dig(b, "data", "truncated"), dig(b, "data", "frontier"))
				}
				if digs(b, "data", "root") != f.lambda {
					t.Errorf("root = %v", dig(b, "data", "root"))
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
		{route: "GET /graph", path: "/graph" + qs("root", f.rootC, "direction", "forward"), shape: contractGraph,
			check: func(t *testing.T, b map[string]any) {
				n := graphNodes(t, digl(b, "data", "nodes"))[f.rootC]
				if digs(n, "lifecycle") != "active" || digs(n, "mechanism") != "aws_account" || dig(n, "account", "connected") != false {
					t.Errorf("C's root node = %s", contractJSON(n))
				}
			}},
		{route: "GET /graph/expand", path: "/graph/expand" + qs("node", f.shared, "edge", "can_assume", "direction", "forward"), shape: contractGraphExpand,
			check: func(t *testing.T, b map[string]any) {
				if es := digl(b, "data", "edges"); len(es) != 1 || digs(es[0], "claim") != f.crossEdge || dig(b, "data", "next_cursor") != nil {
					t.Errorf("expand = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /graph/path", path: "/graph/path" + qs("from", f.lambda, "to", f.tickets), shape: contractGraphPath,
			check: func(t *testing.T, b map[string]any) {
				ps := digl(b, "data", "paths")
				if digs(b, "data", "outcome") != "found" || len(ps) != 3 || dig(b, "data", "more_paths") != false ||
					dig(b, "data", "bound_by") != nil || digs(b, "data", "direction") != "forward" {
					t.Errorf("path = %s, want found with 3 paths (ReadTickets, ToolboxRead, via CrossRole)", contractJSON(b["data"]))
				}
			}},
		{route: "GET /graph/path", path: "/graph/path" + qs("from", f.lambda, "to", f.finance), shape: contractGraphPath,
			check: func(t *testing.T, b map[string]any) {
				// B19: an exclusion is never a destination.
				if o := digs(b, "data", "outcome"); o == "found" || len(digl(b, "data", "paths")) != 0 || dig(b, "data", "direction") != nil {
					t.Errorf("a path to the excluded finance/* = %s", contractJSON(b["data"]))
				}
			}},

		/* --------------------------------- evidence ----------------------------- */

		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				d := b["data"]
				// §5.3's example sentence, exactly.
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
				if len(digl(d, "facts")) == 0 || dig(d, "raw") != nil || dig(d, "freshness", "stale_since") != nil {
					t.Errorf("facts/raw/freshness = %s", contractJSON(d))
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets, "claim", f.grantToolbox), shape: contractEvidenceMany,
			check: func(t *testing.T, b map[string]any) {
				if s := digs(b, "meta", "summary", "sentence"); !strings.Contains(s, "by 2 statements") {
					t.Errorf("summary = %q (D-79)", s)
				}
				if d := digl(b, "data"); digs(d[0], "claim", "ref") != f.grantReadTickets || digs(d[1], "claim", "ref") != f.grantToolbox {
					t.Errorf("data order = %v, want the request's (D-79)", contractPluck(d, "claim", "ref"))
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.executesLambda), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.crossEdge), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				// A stale claim: lifecycle stale, its staleness dated (D-23), its
				// collection not complete (D-80), the gap named.
				d := b["data"]
				if digs(d, "status", "lifecycle") != "stale" || digs(d, "status", "collection") == "complete" ||
					dig(d, "freshness", "stale_since") == nil || evidenceLim(b, "surface_denied") == nil ||
					evidenceLim(b, "caller_permission_not_evaluated") == nil {
					t.Errorf("stale can_assume evidence = %s", contractJSON(d))
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantOps), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantOwn), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantFinance), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantExternal), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", grantSandbox), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.lambda), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.oidc), shape: contractEvidence},
		{route: "GET /evidence", path: "/evidence" + qs("claim", f.grantReadTickets, "include", "raw"), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				if raw := digl(b, "data", "raw"); len(raw) == 0 || len(raw) != len(digl(b, "data", "facts")) {
					t.Errorf("raw = %s, want aligned with facts (D-80)", contractJSON(raw))
				}
			}},
		{route: "GET /evidence", path: "/evidence" + qs("claim", coverageB), shape: contractEvidence,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "status", "collection") != "stale" || evidenceLim(b, "surface_denied") == nil || dig(b, "data", "status", "basis") != nil {
					t.Errorf("coverage claim = %s", contractJSON(b["data"]))
				}
			}},

		/* ----------------------- ended claims (D-12 include_ended) ------------- */

		// LegacyRead's detach ended its assignment and its grant (rev 3). With
		// include_ended each view shows them, ended, with valid_to and
		// ended_reason -- the shapes' §5.1 rule holds every other row to
		// neither -- and never as current.
		{route: "GET /identities/:id/permissions", path: "/identities/" + u(f.shared) + "/permissions" + qs("include_ended", "true"),
			shape: contractPermissions, check: func(t *testing.T, b map[string]any) {
				lr := contractByName(digl(b, "data", "policies"), "name")["LegacyRead"]
				if digs(lr, "assignment", "state") != "ended" || dig(lr, "assignment", "valid_to") == nil ||
					digs(lr, "statements", 0, "grant") != grantLegacy || digs(lr, "statements", 0, "grant_state") != "ended" {
					t.Errorf("LegacyRead = %s, want its ended assignment and grant", contractJSON(lr))
				}
			}},
		{route: "GET /workloads/:id/resources", path: "/workloads/" + u(f.lambda) + "/resources" + qs("include_ended", "true"),
			shape: contractWorkloadResources, check: func(t *testing.T, b map[string]any) {
				gs := digl(contractByName(digl(b, "data"), "resource", "text")[contractTickets], "grants")
				var ended any
				for _, g := range gs {
					if digs(g, "claim") == grantLegacy {
						ended = g
					}
				}
				if len(gs) != 3 || digs(ended, "state") != "ended" || dig(ended, "valid_to") == nil || dig(ended, "ended_reason") == nil {
					t.Errorf("support-tickets/* grants = %s, want ReadTickets, ToolboxRead and the ended LegacyGet", contractJSON(gs))
				}
			}},
		{route: "GET /resources/:id/access", path: "/resources/" + u(f.tickets) + "/access" + qs("include_ended", "true"),
			shape: contractResourceAccess, check: func(t *testing.T, b map[string]any) {
				var ended any
				for _, r := range digl(b, "data", "access") {
					if digs(r, "grant", "claim") == grantLegacy {
						ended = r
					}
				}
				if digs(ended, "state") != "ended" || digs(ended, "grant", "state") != "ended" {
					t.Errorf("access = %s, want the ended LegacyGet grant, ended", contractJSON(b["data"]))
				}
			}},
		{route: "GET /graph", path: "/graph" + qs("root", f.lambda, "direction", "forward", "include_ended", "true"), shape: contractGraph,
			check: func(t *testing.T, b map[string]any) {
				if !contractHasEdge(b, grantLegacy, func(e any) bool { return digs(e, "state") == "ended" && digs(e, "kind") == "grant" }) {
					t.Errorf("no ended LegacyGet grant edge with include_ended")
				}
				fr := digl(b, "data", "frontier")
				for _, e := range fr {
					if !strings.HasSuffix(digs(e, "expand"), contractIncludeEnded) {
						t.Errorf("frontier expand %q drops include_ended: the expansion would hide what the canvas shows", digs(e, "expand"))
					}
				}
				if len(fr) == 0 {
					t.Errorf("no frontier: the fixture's can_assume beyond assume_hops should leave one")
				}
			}},

		/* ---------------------------------- lookup ------------------------------ */

		{route: "GET /lookup", path: "/lookup" + qs("cloud_ref", "cloud_identity:"+cloudRoles[0].String()), shape: contractLookup,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "ref") != f.shared || digs(b, "data", "lifecycle") != "active" {
					t.Errorf("lookup role = %s", contractJSON(b["data"]))
				}
			}},
		{route: "GET /lookup", path: "/lookup" + qs("cloud_ref", "cloud_workload:"+cloudLambdas[0].String()), shape: contractLookup,
			check: func(t *testing.T, b map[string]any) {
				if digs(b, "data", "ref") != f.lambda {
					t.Errorf("lookup lambda = %s", contractJSON(b["data"]))
				}
			}},
	}, contractParameterCases(t, f)...)
}

// contractParameterCases: every filter value, sort key (both directions) and
// section §5.3 names for a list or a paged tab is accepted -- a console built
// against §5.3 never meets a 400 for a parameter the contract promises -- and
// each filter chooses the rows the estate says it must (as names, sorted).
func contractParameterCases(t *testing.T, f *contractFixture) []contractCase {
	t.Helper()
	u := func(ref string) string { return refUUID(t, ref).String() }
	names := func(field string, want ...string) func(*testing.T, map[string]any) {
		return func(t *testing.T, b map[string]any) {
			got := contractPluck(digl(b, "data"), field)
			sort.Strings(got)
			w := append([]string{}, want...)
			sort.Strings(w)
			if !reflect.DeepEqual(got, w) {
				t.Errorf("rows = %v, want %v", got, w)
			}
		}
	}
	conn := refOf("cloud_connector", f.a.conn)
	wl := contractList(contractWorkloadRow, contractListMeta())
	id := contractList(contractIdentityRow, contractListMeta())
	rs := contractList(contractResourceRow, contractListMeta())
	all := []string{"orphan-fn", "support-bot", "ticket-tools", "ticket-worker"}
	var out []contractCase
	add := func(route, path string, shape contractShape, check func(*testing.T, map[string]any)) {
		out = append(out, contractCase{route: route, path: path, shape: shape, check: check})
	}

	// GET /workloads (§5.3 Agents & workloads).
	for _, c := range []struct {
		q    string
		want []string
	}{
		{qs("q", "ticket"), []string{"ticket-tools", "ticket-worker"}},
		{qs("account", accountA), all},
		{qs("account", "unknown"), nil},
		{qs("lifecycle", "retired"), nil},
		{qs("lifecycle", "all"), all},
		{qs("region", "us-east-1"), all},
		{qs("region", "not_stated"), nil},
		{qs("integration", conn), all},
		{qs("runtime_kind", "lambda_function"), []string{"orphan-fn", "ticket-tools"}},
		{qs("runtime_kind", "ecs_task_definition"), []string{"ticket-worker"}},
		{qs("runtime_kind", "ec2_instance"), nil},
		{qs("runtime_kind", "bedrock_agent"), []string{"support-bot"}},
		{qs("runtime_kind", "bedrock_agentcore_runtime"), nil},
		{qs("runtime_kind", "bedrock_agentcore_gateway"), nil},
		{qs("classification", "agent"), []string{"support-bot", "ticket-tools"}},
		{qs("classification", "provider_native_agent"), []string{"support-bot"}},
		{qs("classification", "classified_agent"), []string{"ticket-tools"}},
		{qs("classification", "unclassified"), []string{"orphan-fn", "ticket-worker"}},
		{qs("execution_role_state", "resolved"), []string{"support-bot", "ticket-tools", "ticket-worker"}},
		{qs("execution_role_state", "not_in_inventory"), []string{"orphan-fn"}},
		{qs("execution_role_state", "not_in_scan"), nil},
		{qs("execution_role_state", "none"), nil},
	} {
		add("GET /workloads", "/workloads"+c.q, wl, names("name", c.want...))
	}
	for _, s := range []string{"name", "-name", "account", "-account", "last_confirmed", "-last_confirmed", "classification", "-classification"} {
		add("GET /workloads", "/workloads"+qs("sort", s), wl, names("name", all...))
	}

	// GET /identities (§5.3 Identities).
	roles := []string{"CrossRole", "GithubDeployRole", "ImagePullRole", "LoopRole", "PartnerRole", "SharedToolRole", "SupportAgentRole"}
	for _, c := range []struct {
		q    string
		want []string
	}{
		{qs("kind", "iam_role"), roles},
		{qs("kind", "iam_user"), []string{"priya"}},
		{qs("kind", "iam_group"), []string{"ops"}},
		{qs("used_by", "workloads"), []string{"ImagePullRole", "SharedToolRole", "SupportAgentRole"}},
		{qs("account", accountB), []string{"CrossRole", "LoopRole"}},
		{qs("q", "AROASHAREDTOOLROLE01"), []string{"SharedToolRole"}},
		{qs("lifecycle", "retired"), []string{"TempRole"}},
		{qs("lifecycle", "all"), append(append([]string{}, roles...), "ops", "priya", "TempRole")},
		{qs("account", accountA, "account", accountB), append(append([]string{}, roles...), "ops", "priya")}, // §5.2: repeatable
		{qs("account", accountB, "kind", "iam_role"), []string{"CrossRole", "LoopRole"}},
	} {
		add("GET /identities", "/identities"+c.q, id, names("name", c.want...))
	}
	for _, s := range []string{"name", "-name", "kind", "-kind", "account", "-account", "last_confirmed", "-last_confirmed"} {
		add("GET /identities", "/identities"+qs("sort", s), id, names("name", append(roles, "ops", "priya")...))
	}

	// GET /resources (§5.3 Resources).
	for _, c := range []struct {
		q    string
		want []string
	}{
		{qs("kind", "exact"), []string{contractBucket, contractKeyB}},
		{qs("kind", "external"), []string{contractKeyC}},
		{qs("service", "kms"), []string{contractKeyB, contractKeyC}},
		{qs("account", "unknown", "kind", "selector"), []string{"*", contractTickets, contractFinance,
			"arn:aws:s3:::ops-bucket/*", "arn:aws:s3:::priya-scratch/*"}},
		{qs("region", "not_stated", "service", "kms"), nil},
		{qs("q", contractKeyC), []string{contractKeyC}},
		{qs("lifecycle", "retired"), nil},
	} {
		add("GET /resources", "/resources"+c.q, rs, names("text", c.want...))
	}
	for _, s := range []string{"kind", "-kind", "name", "-name", "service", "-service", "account", "-account"} {
		add("GET /resources", "/resources"+qs("sort", s), rs, func(t *testing.T, b map[string]any) {
			if n := len(digl(b, "data")); n != 8 {
				t.Errorf("rows = %d, want 8", n)
			}
		})
	}

	// The paged tabs' own sorts and sections (§5.3; D-77).
	for _, s := range []string{"kind", "name", "-kind", "-name"} {
		add("GET /workloads/:id/resources", "/workloads/"+u(f.lambda)+"/resources"+qs("sort", s), contractWorkloadResources,
			func(t *testing.T, b map[string]any) {
				if n := len(digl(b, "data")); n != 5 {
					t.Errorf("rows = %d, want 5", n)
				}
			})
	}
	// D-77: ?section= returns that section ALONE (the closed shapes reject
	// the others), and the section's cursor pages it.
	add("GET /workloads/:id/identities", "/workloads/"+u(f.lambda)+"/identities"+qs("section", "may_assume"),
		contractWorkloadIdentitiesSection("may_assume"), func(t *testing.T, b map[string]any) {
			if len(digl(b, "data", "may_assume", "items")) != 1 {
				t.Errorf("section=may_assume = %s", contractJSON(b["data"]))
			}
		})
	add("GET /identities/:id/used-by", "/identities/"+u(f.cross)+"/used-by"+qs("section", "principals", "limit", "1"),
		contractUsedBySection("iam_role", "principals"), func(t *testing.T, b map[string]any) {
			sec := dig(b, "data", "principals")
			next := digs(sec, "next_cursor")
			if len(digl(sec, "items")) != 1 || num(sec, "total") != 2 || next == "" {
				t.Fatalf("section=principals limit=1 = %s, want 1 of 2 with a next page", contractJSON(sec))
			}
			p := "/identities/" + u(f.cross) + "/used-by" + qs("section", "principals", "limit", "1", "cursor", next)
			code, page := f.api.get(p)
			mustStatus(t, p, code, page, http.StatusOK)
			contractCheck(t, p, page, contractUsedBySection("iam_role", "principals"))
			second := dig(page, "data", "principals")
			if len(digl(second, "items")) != 1 || dig(second, "next_cursor") != nil ||
				digs(second, "items", 0, "claim") == digs(sec, "items", 0, "claim") {
				t.Errorf("second page = %s, want the other principal and no further page", contractJSON(second))
			}
		})
	add("GET /workloads/:id/changes", "/workloads/"+u(f.lambda)+"/changes"+qs("kind", "configuration", "limit", "1"), contractChanges,
		func(t *testing.T, b map[string]any) {
			next := digs(b, "meta", "next_cursor")
			if len(digl(b, "data")) != 1 || next == "" {
				t.Fatalf("one event per page = %s", contractJSON(b["meta"]))
			}
			p := "/workloads/" + u(f.lambda) + "/changes" + qs("kind", "configuration", "limit", "1", "cursor", next)
			code, page := f.api.get(p)
			mustStatus(t, p, code, page, http.StatusOK)
			contractCheck(t, p, page, contractChanges)
			if len(digl(page, "data")) != 1 || digs(page, "data", 0, "id") == digs(b, "data", 0, "id") {
				t.Errorf("second page = %s, want the next event", contractJSON(page["data"]))
			}
		})
	return out
}

func TestP2ContractEveryRouteFieldByField(t *testing.T) {
	f := contractLab(t)
	api := f.api
	cases := contractCases(t, f)

	// The one rendering of the current publication's time (D-96): every
	// revision-bound response's meta.published_at is /pipeline's
	// current_published_at, to the character.
	code, pipe := api.get("/pipeline")
	mustStatus(t, "/pipeline", code, pipe, http.StatusOK)
	published := digs(pipe, "data", "current_published_at")
	if published == "" || !strings.HasSuffix(published, "Z") || strings.Contains(published, ".") {
		t.Fatalf("current_published_at = %q, want RFC 3339 UTC to the second (D-96)", published)
	}

	covered := map[string]bool{}
	for _, c := range cases {
		c := c
		covered[c.route] = true
		t.Run(c.route+" "+c.path, func(t *testing.T) {
			code, body := api.get(c.path)
			mustStatus(t, c.path, code, body, http.StatusOK)
			contractCheck(t, c.path, body, c.shape)
			contractRevisionEcho(t, c.path, body, published)
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
			if route != "POST /workloads/:id/classification" {
				t.Errorf("POST route %s has no contract test", route)
			}
			continue
		}
		if !covered[route] {
			t.Errorf("route %s has no contract case", route)
		}
	}
}

// contractRevisionEcho is §5.1's echo: every revision-bound response carries
// the current revision and its publication time, rendered as everywhere else
// (D-96) -- and /capabilities, which reports the deployment and not the
// graph, carries no meta at all.
func contractRevisionEcho(t *testing.T, path string, body map[string]any, published string) {
	t.Helper()
	if path == "/capabilities" {
		if _, has := body["meta"]; has {
			t.Errorf("/capabilities carries meta %v", body["meta"])
		}
		return
	}
	if num(body, "meta", "rev") != contractCurrentRev || digs(body, "meta", "graph_state") != "published" ||
		digs(body, "meta", "published_at") != published {
		t.Errorf("%s meta = %s, want rev %d, published, published_at %q", path, contractJSON(body["meta"]), contractCurrentRev, published)
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

func contractFacetLabel(body map[string]any, name, value string) string {
	for _, v := range digl(body, "meta", "facets", name) {
		if digs(v, "value") == value {
			return digs(v, "label")
		}
	}
	return ""
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

// contractNodeRestrictionCodes are the codes a NODE may carry beyond
// /evidence's for its presence: its restrictions' (D-98; §5.4 "every path
// through a restricted node carries the matching limitation").
var contractNodeRestrictionCodes = map[string]map[string]bool{
	"identity":  {"deny_statements_present": true, "permissions_boundary_present": true, "not_principal_unresolved": true},
	"statement": {"conditions_not_evaluated": true, "negated_statement": true},
}

// D-35: every graph element's limitations are the SAME function's as
// /evidence's, restricted to the codes that need no facts -- same codes, same
// fields, same order. An EDGE is a claim: its list is /evidence's for that
// claim, plus, on an edge that crosses accounts, the far account's coverage
// (§5.4). A NODE's is /evidence's for its presence plus exactly the
// limitations of its restrictions, which must agree with its restrictions
// field. And every path carries exactly the union of its steps' limitations.
func TestP2ContractGraphLimitationsAreEvidences(t *testing.T) {
	f := contractLab(t)
	api := f.api
	evidence := map[string][]any{}
	fetch := func(claim string) []any {
		if l, ok := evidence[claim]; ok {
			return l
		}
		b := evidenceGet(t, api, claim)
		out := []any{}
		for _, l := range digl(b, "data", "limitations") {
			if igaread.FactFreeLimitations[digs(l, "code")] {
				out = append(out, l)
			}
		}
		evidence[claim] = out
		return out
	}
	// An identity's trust_has_not_principal as its detail states it (D-85),
	// read once per identity.
	notPrincipal := map[string]bool{}
	trustNotPrincipal := func(ref string) bool {
		if v, ok := notPrincipal[ref]; ok {
			return v
		}
		code, body := api.get("/identities/" + refUUID(t, ref).String())
		mustStatus(t, "identity detail "+ref, code, body, http.StatusOK)
		notPrincipal[ref] = dig(body, "data", "provider_attrs", "trust_has_not_principal") == true
		return notPrincipal[ref]
	}
	// The far account's coverage a crossing edge must carry (§5.4): every
	// surface of A that /coverage says prevents something, as a limitation.
	code, cov := api.get("/coverage" + qs("account", accountA))
	mustStatus(t, "/coverage", code, cov, http.StatusOK)
	var farA []any
	for _, s := range digl(cov, "data", 0, "surfaces") {
		if p := digs(s, "prevents"); strings.HasPrefix(p, "surface_") {
			farA = append(farA, map[string]any{"code": p, "account_id": accountA, "surface": digs(s, "surface"),
				"state": digs(s, "state"), "since": dig(s, "since")})
		}
	}
	if len(farA) == 0 {
		t.Fatalf("fixture: A has no coverage gap to carry across (its unreadable document is one)")
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
	edgesChecked, nodesChecked, restricted, far := 0, 0, 0, 0
	for p, body := range responses {
		var edges, nodes []any
		edges = append(edges, digl(body, "data", "edges")...)
		nodes = append(nodes, digl(body, "data", "nodes")...)
		for _, path := range digl(body, "data", "paths") {
			edges = append(edges, digl(path, "edges")...)
			nodes = append(nodes, digl(path, "nodes")...)
		}
		for _, e := range edges {
			claim := digs(e, "claim")
			want, got := fetch(claim), digl(e, "limitations")
			if dig(e, "crosses_account") == true {
				// The far account's coverage is the graph's one addition.
				var extra []any
				got, extra = contractSplit(got, func(l any) bool {
					return strings.HasPrefix(digs(l, "code"), "surface_") && !contractHas(want, l)
				})
				for _, l := range extra {
					far++
					if digs(l, "account_id") == "" {
						t.Errorf("%s edge %s: far coverage %s names no account", p, claim, contractCanonical(l))
					}
				}
			}
			if contractCanonical(contractOrEmpty(got)) != contractCanonical(want) {
				t.Errorf("%s edge %s (%s): limitations\n  graph    %s\n  evidence %s", p, claim, digs(e, "kind"),
					contractCanonical(got), contractCanonical(want))
			}
			// B's trust of A's role crosses into A: it carries every one of A's
			// gaps (the claim is B's; A is the far account).
			if claim == f.crossEdge {
				for _, l := range farA {
					if !contractHas(digl(e, "limitations"), l) {
						t.Errorf("%s edge %s lacks the far account's %s", p, claim, contractCanonical(l))
					}
				}
			}
			edgesChecked++
		}
		for _, n := range nodes {
			ref := digs(n, "ref")
			typ, _, _ := strings.Cut(ref, ":")
			want, got := fetch(ref), digl(n, "limitations")
			own, extra := contractSplit(got, func(l any) bool { return !contractHas(want, l) })
			for _, l := range extra {
				if !contractNodeRestrictionCodes[typ][digs(l, "code")] {
					t.Errorf("%s node %s carries %s beyond /evidence's, which is no restriction of a %s",
						p, ref, contractCanonical(l), typ)
				}
			}
			if contractCanonical(contractOrEmpty(own)) != contractCanonical(want) {
				t.Errorf("%s node %s: /evidence's limitations %s, the node's own %s", p, ref,
					contractCanonical(want), contractCanonical(own))
			}
			// The limitations agree with the restrictions they state.
			if typ == "identity" {
				deny := graphLim(digl(n, "limitations"), "deny_statements_present")
				count := num(n, "restrictions", "deny_statements")
				if (deny == nil) != (count == 0) || (deny != nil && num(deny, "count") != count) {
					t.Errorf("%s node %s: restrictions.deny_statements %d, limitation %v", p, ref, count, deny)
				}
				bound := graphLim(digl(n, "limitations"), "permissions_boundary_present")
				if (bound != nil) != (dig(n, "restrictions", "permissions_boundary") == true) || (bound != nil && dig(bound, "holder") != true) {
					t.Errorf("%s node %s: restrictions %v, limitation %v", p, ref, dig(n, "restrictions"), bound)
				}
				// D-44: not_principal_unresolved exactly when the role's trust
				// uses NotPrincipal, as its detail states it -- required, not
				// merely allowed (TestP2ContractGraphNotPrincipalUnresolved
				// holds a role that does).
				np := graphLim(digl(n, "limitations"), "not_principal_unresolved")
				if want := trustNotPrincipal(ref); (np != nil) != want {
					t.Errorf("%s node %s: not_principal_unresolved %v, but its trust_has_not_principal is %v", p, ref, np, want)
				}
				if deny != nil || bound != nil {
					restricted++
				}
			}
			nodesChecked++
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
	if edgesChecked < 20 || nodesChecked < 20 || restricted < 2 {
		t.Fatalf("only %d edges, %d nodes (%d restricted identities) compared; the fixture's graphs hold far more",
			edgesChecked, nodesChecked, restricted)
	}
	t.Logf("compared %d edges (%d far-coverage additions) and %d nodes (%d restricted identities)", edgesChecked, far, nodesChecked, restricted)
}

// contractSplit partitions ls by pred, keeping order: (not matching, matching).
func contractSplit(ls []any, pred func(any) bool) (keep, split []any) {
	for _, l := range ls {
		if pred(l) {
			split = append(split, l)
		} else {
			keep = append(keep, l)
		}
	}
	return keep, split
}

func contractHas(ls []any, l any) bool {
	k := contractCanonical(l)
	for _, x := range ls {
		if contractCanonical(x) == k {
			return true
		}
	}
	return false
}

func contractOrEmpty(ls []any) []any {
	if ls == nil {
		return []any{}
	}
	return ls
}
