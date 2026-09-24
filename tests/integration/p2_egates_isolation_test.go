package integration

// §7.1 E14 (cross-workspace access) and E16 (existing products unchanged):
// the backend halves. E14's console half -- a workspace switch mid-load never
// showing the previous workspace's rows (UI11) -- and E16's -- every existing
// page behaving as before -- are M3's Playwright run. E15 (keyboard and
// narrow screens) is console-only and has no backend half.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

/* ----------------------------------- E14 ---------------------------------- */

// egatesWorkspaceIDs is one workspace's §7.1 lab, by object kind: the ids a
// probe addresses, and every id the workspace holds (a response of another
// workspace mentioning any of them is a leak).
type egatesWorkspaceIDs struct {
	one map[string]string // ref type -> one typed ref of that type
	all map[string]bool   // every uuid of the workspace's graph and cloud rows
}

func egatesIDsOf(t *testing.T, l *p2Lab, a *egatesAcct) egatesWorkspaceIDs {
	t.Helper()
	w := egatesWorkspaceIDs{one: map[string]string{}, all: map[string]bool{}}
	w.one["workload"] = egatesWorkload(t, l, "ticket-tools", accountA)
	w.one["identity"] = egatesIdentity(t, l, egatesSharedRole)
	w.one["resource"] = egatesResource(t, l, egatesTickets)
	w.one["statement"] = graphStatementOf(t, l, egatesTicketRead)
	w.one["policy"] = refOf("policy", changesPolicy(t, l, egatesTicketRead))
	w.one["grant"] = evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets")
	w.one["relationship"] = refOf("relationship", changesIDOf(t, l, `SELECT id FROM iga_relationship WHERE workspace_id = ?
	    AND relationship_type = 'executes_as' AND source_workload_id = ?`, l.ws, refUUID(t, w.one["workload"])))
	w.one["assignment"] = refOf("assignment", l.assignments(egatesTicketRead)[0].ID)
	w.one["target"] = refOf("target", changesIDOf(t, l, `SELECT id FROM iga_entitlement_target WHERE workspace_id = ?
	    AND entitlement_id = ?`, l.ws, refUUID(t, w.one["statement"])))
	w.one["presence"] = refOf("presence", changesIDOf(t, l, `SELECT id FROM iga_object_support WHERE workspace_id = ?
	    AND resource_id = ? AND connector_id = ?`, l.ws, refUUID(t, w.one["resource"]), a.conn))
	w.one["external_principal"] = refOf("external_principal", changesIDOf(t, l, `SELECT id FROM iga_external_principal
	    WHERE workspace_id = ? AND subject_claim = ?`, l.ws, egatesAccountC))
	w.one["cloud_scan_run"] = refOf("cloud_scan_run", changesIDOf(t, l, `SELECT scan_run_id FROM iga_publication
	    WHERE workspace_id = ? ORDER BY rev LIMIT 1`, l.ws))
	w.one["coverage"] = "coverage:" + strings.TrimPrefix(w.one["cloud_scan_run"], "cloud_scan_run:") + ":" + models.SurfaceIAMRoles
	w.one["cloud_identity"] = refOf("cloud_identity", changesIDOf(t, l, `SELECT id FROM cloud_identity WHERE workspace_id = ?
	    AND connector_id = ? AND native_id = ?`, l.ws, a.conn, a.roleARN(egatesSharedRole)))
	w.one["cloud_workload"] = refOf("cloud_workload", changesIDOf(t, l, `SELECT id FROM cloud_workload WHERE workspace_id = ?
	    AND connector_id = ? AND name = 'ticket-tools'`, l.ws, a.conn))
	w.one["cloud_connector"] = refOf("cloud_connector", a.conn)
	for _, table := range []string{"iga_workload", "iga_identity_accounts", "iga_resources", "iga_entitlements", "iga_policy",
		"iga_access_edges", "iga_relationship", "iga_policy_assignment", "iga_entitlement_target", "iga_object_support",
		"iga_external_principal", "iga_statement_revision", "iga_lifecycle_event", "cloud_connector", "cloud_scan_run",
		"cloud_identity", "cloud_workload", "cloud_policy", "cloud_observation"} {
		var ids []uuid.UUID
		l.db.Raw(`SELECT id FROM `+table+` WHERE workspace_id = ?`, l.ws).Scan(&ids)
		for _, id := range ids {
			w.all[id.String()] = true
		}
	}
	return w
}

var egatesUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// egatesLeak returns the first id of the foreign workspace a body mentions.
func egatesLeak(body map[string]any, foreign egatesWorkspaceIDs) string {
	for _, id := range egatesUUID.FindAllString(egatesJSON(body), -1) {
		if foreign.all[id] {
			return id
		}
	}
	return ""
}

// egatesProbe is one request a route is probed with: the path from the
// requesting workspace, the status it must get there, and whether the same
// path is a positive control (200 from the workspace that owns the ids).
type egatesProbe struct {
	path    string
	body    any
	want    int
	control bool
}

// egatesIDRoute is the object type a /<collection>/:id route addresses. A new
// :id route under one of these collections is probed automatically; under a
// new collection the test fails until it is added here.
var egatesIDRoute = map[string]string{
	"workloads": "workload", "identities": "identity", "resources": "resource", "external-principals": "external_principal",
}

// E14. Two workspaces, each with the §7.1 lab -- the SAME accounts, names and
// ARNs, so only ids tell them apart. Every route of RegisterIGAGraphReadRoutes
// is probed from one workspace with the other's ids: 404 not_found, the same
// path from the owner 200 (so the 404 is about the workspace), and no
// response of either workspace mentions an id of the other. :id routes are
// probed from the route table itself, bare and typed; query-addressed routes
// with every object parameter they take; list routes answer only their own
// rows under every filter, and another workspace's cursor is refused.
//
// Safeguards (mutation-checked): every read filters workspace_id (detail
// lookups and the list queries); a cursor is bound to its workspace.
func TestP2EgatesE14CrossWorkspaceAccess(t *testing.T) {
	home := newP2Lab(t, "p2-egates-e14-home", true)
	other := newP2Lab(t, "p2-egates-e14-other", true)
	// Each lab empties cloud_scan_run when created and at cleanup, and
	// publications reference runs RESTRICT: both labs exist before either
	// scans, and this cleanup (registered last, run first) removes both
	// workspaces' graph rows before either clears the run table.
	t.Cleanup(func() { other.cleanup(); home.cleanup() })
	ha, hb := egatesProduction(t, home), egatesSandbox(t, home)
	oa, ob := egatesProduction(t, other), egatesSandbox(t, other)
	for _, c := range []struct {
		l *p2Lab
		a *egatesAcct
	}{{home, ha}, {home, hb}, {other, oa}, {other, ob}} {
		egatesCycle(c.l, c.a)
	}
	mine, theirs := egatesIDsOf(t, home, ha), egatesIDsOf(t, other, oa)
	// The two workspaces share no id: a probe's 404 is about the workspace,
	// never an id the requester happens to hold too. A coverage claim is
	// "coverage:<run>:<surface>", so its run is what must differ.
	for typ, ref := range theirs.one {
		probe := ref
		if strings.HasPrefix(ref, "coverage:") {
			probe = "cloud_scan_run:" + strings.Split(ref, ":")[1]
		}
		if mine.all[refUUID(t, probe).String()] || mine.one[typ] == ref {
			t.Fatalf("setup: both workspaces hold %s %s", typ, ref)
		}
	}

	// The requesters: a verified human of each workspace (a classification
	// POST is refused for nothing but the foreign id).
	nameH, nameO := "Home Reviewer", "Other Reviewer"
	uh, mh := classMember(t, home.db, home.ws, &nameH, "home@egates.test", "active")
	uo, mo := classMember(t, other.db, other.ws, &nameO, "other@egates.test", "active")
	api := home.api().withClaims(classClaims(uh, mh))
	owner := other.api().withClaims(classClaims(uo, mo))

	classify := map[string]any{"operation_id": uuid.NewString(), "decision": models.ClassificationClassified,
		"purpose": "", "reason": "cross-workspace probe", "expected_version": 0, "undoes_decision_id": nil}
	id := func(ref string) string { return refUUID(t, ref).String() }
	// Query-addressed routes: every object parameter, the owner's ids.
	queryProbes := map[string][]egatesProbe{
		"GET /capabilities": {{path: "/capabilities", want: 200}},
		"GET /pipeline":     {{path: "/pipeline", want: 200}},
		"GET /coverage": {{path: "/coverage", want: 200}, {path: "/coverage" + qs("account", accountA), want: 200},
			{path: "/coverage" + qs("rev", "1"), want: 409}},
		"GET /workloads": {{path: "/workloads", want: 200}, {path: "/workloads" + qs("q", "ticket"), want: 200},
			{path: "/workloads" + qs("integration", theirs.one["cloud_connector"]), want: 200},
			{path: "/workloads" + qs("account", accountB, "facets", "account,region,runtime_kind,classification"), want: 200}},
		"GET /identities": {{path: "/identities", want: 200}, {path: "/identities" + qs("q", egatesSharedRole), want: 200},
			{path: "/identities" + qs("integration", theirs.one["cloud_connector"]), want: 200},
			{path: "/identities" + qs("used_by", "workloads", "facets", "account,kind"), want: 200}},
		"GET /resources": {{path: "/resources", want: 200}, {path: "/resources" + qs("q", "support"), want: 200},
			{path: "/resources" + qs("integration", theirs.one["cloud_connector"]), want: 200}},
		"GET /lookup": {{path: "/lookup" + qs("cloud_ref", theirs.one["cloud_identity"]), want: 404, control: true},
			{path: "/lookup" + qs("cloud_ref", theirs.one["cloud_workload"]), want: 404, control: true}},
		"GET /graph/expand": {{path: "/graph/expand" + qs("node", theirs.one["identity"], "edge", "executes_as", "direction", "reverse"),
			want: 404, control: true}},
		"GET /graph/path": {{path: "/graph/path" + qs("from", theirs.one["workload"], "to", theirs.one["resource"]), want: 404, control: true},
			// Mixed: one end of each workspace -- never a path, never a hint.
			{path: "/graph/path" + qs("from", mine.one["workload"], "to", theirs.one["resource"]), want: 404},
			{path: "/graph/path" + qs("from", theirs.one["workload"], "to", mine.one["resource"]), want: 404}},
	}
	for _, typ := range []string{"workload", "identity", "resource", "statement", "external_principal"} {
		queryProbes["GET /graph"] = append(queryProbes["GET /graph"], egatesProbe{
			path: "/graph" + qs("root", theirs.one[typ], "direction", "forward"), want: 404, control: true})
	}
	for _, typ := range []string{"grant", "assignment", "relationship", "target", "presence", "coverage", "workload",
		"identity", "external_principal", "resource", "policy", "statement"} {
		queryProbes["GET /evidence"] = append(queryProbes["GET /evidence"], egatesProbe{
			path: "/evidence" + qs("claim", theirs.one[typ]), want: 404, control: true})
	}
	// D-79: one foreign claim among the requester's own makes the whole
	// request 404.
	queryProbes["GET /evidence"] = append(queryProbes["GET /evidence"], egatesProbe{
		path: "/evidence" + qs("claim", mine.one["grant"]) + "&claim=" + theirs.one["grant"], want: 404})

	seen := map[string]bool{}
	for _, r := range api.eng.Routes() {
		key := r.Method + " " + strings.TrimPrefix(r.Path, "/api/iga/v1")
		seen[key] = true
		probes, ok := queryProbes[key]
		if strings.Contains(r.Path, ":id") {
			seg := strings.Split(strings.TrimPrefix(r.Path, "/api/iga/v1/"), "/")[0]
			typ := egatesIDRoute[seg]
			if typ == "" {
				t.Errorf("route %s addresses a collection this test does not know: add its object type", key)
				continue
			}
			ref := theirs.one[typ]
			var body any
			if r.Method == http.MethodPost {
				body = classify
			}
			for _, rid := range []string{id(ref), ref} { // D-5: bare and typed
				probes = append(probes, egatesProbe{path: strings.Replace(strings.TrimPrefix(r.Path, "/api/iga/v1"), ":id", rid, 1),
					body: body, want: 404, control: r.Method == http.MethodGet})
			}
		} else if !ok {
			t.Errorf("route %s has no probe in this test: add one for every object parameter it takes", key)
			continue
		}
		for _, p := range probes {
			code, body := api.do(r.Method, p.path, p.body)
			if code != p.want {
				t.Errorf("%s %s from the other workspace = %d %s, want %d", r.Method, p.path, code, egatesJSON(body), p.want)
			}
			if p.want == 404 && (errCode(body) != "not_found" || len(egatesJSON(dig(body, "error"))) > 200) {
				t.Errorf("%s %s: 404 body = %s, want not_found with no hint", r.Method, p.path, egatesJSON(body))
			}
			if leak := egatesLeak(body, theirs); leak != "" {
				t.Errorf("%s %s from the other workspace mentions its id %s: %s", r.Method, p.path, leak, egatesJSON(body))
			}
			if p.control {
				code, body := owner.do(r.Method, p.path, p.body)
				if code != http.StatusOK {
					t.Errorf("control: %s %s from its own workspace = %d %s, want 200", r.Method, p.path, code, egatesJSON(body))
				}
				if leak := egatesLeak(body, mine); leak != "" {
					t.Errorf("control: %s %s mentions the requester's id %s", r.Method, p.path, leak)
				}
			}
		}
	}
	for key := range queryProbes {
		if !seen[key] {
			t.Errorf("probe %s names no registered route", key)
		}
	}

	// The lists answer only their own rows: the same names, other ids.
	for _, path := range []string{"/workloads" + qs("q", "ticket"), "/identities" + qs("q", egatesSharedRole), "/resources" + qs("q", "support")} {
		rows := digl(egatesGet(t, api, path), "data")
		if len(rows) == 0 {
			t.Errorf("%s from home = no rows, want home's own", path)
		}
		for _, row := range rows {
			if !mine.all[refUUID(t, digs(row, "ref")).String()] {
				t.Errorf("%s from home returned %s, which is not home's", path, digs(row, "ref"))
			}
		}
	}
	if rows := digl(egatesGet(t, api, "/workloads"+qs("integration", theirs.one["cloud_connector"])), "data"); len(rows) != 0 {
		t.Errorf("/workloads filtered by the other workspace's connector = %d rows, want none (D-75)", len(rows))
	}
	pl := egatesGet(t, api, "/pipeline")
	if accts := digl(pl, "data", "accounts"); len(accts) != 2 {
		t.Errorf("/pipeline accounts = %d, want home's two", len(accts))
	}
	// Another workspace's cursor is not a position here.
	for _, path := range []string{"/workloads" + qs("limit", "2"), "/identities" + qs("limit", "2"), "/resources" + qs("limit", "1")} {
		theirsPage := egatesGet(t, owner, path)
		cur := digs(theirsPage, "meta", "next_cursor")
		if cur == "" {
			t.Fatalf("setup: %s from the other workspace has no next page", path)
		}
		code, body := api.get(path + "&cursor=" + cur)
		if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
			t.Errorf("%s with the other workspace's cursor = %d %s, want 400 cursor_invalid", path, code, egatesJSON(body))
		}
	}
	used := egatesGet(t, owner, egatesRoute(t, theirs.one["identity"], "/used-by")+qs("section", "workloads", "limit", "1"))
	if cur := digs(used, "data", "workloads", "next_cursor"); cur == "" {
		t.Fatal("setup: the other workspace's used-by has no next page")
	} else if code, body := api.get(egatesRoute(t, mine.one["identity"], "/used-by") + qs("section", "workloads", "limit", "1", "cursor", cur)); code != http.StatusBadRequest ||
		errCode(body) != "cursor_invalid" {
		t.Errorf("home's used-by with the other workspace's cursor = %d %s, want 400 cursor_invalid", code, egatesJSON(body))
	}
}

/* ----------------------------------- E16 ---------------------------------- */

// egatesGitHubAPI is the existing /api/iga/v1 GitHub routes (routes.go), with
// the token's workspace set as AuthMiddleware sets it. Permission middleware
// is not mounted: these routes' permissions are Phase 1's, not under test.
func egatesGitHubAPI(t *testing.T, l *p2Lab) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	ctl := platform.NewIGAController(l.db)
	disc := platform.NewDiscoveryController(l.db)
	cloud := platform.NewCloudAWSController(l.db)
	eng := gin.New()
	var ws uuid.UUID
	eng.Use(func(c *gin.Context) {
		if h := c.GetHeader("X-Egates-Workspace"); h != "" {
			ws = uuid.MustParse(h)
		}
		c.Set("workspace_id", ws.String())
		c.Next()
	})
	g := eng.Group("/api/iga/v1")
	g.GET("/integrations", ctl.ListIntegrations)
	g.GET("/integrations/:integration_id", ctl.GetIntegration)
	g.GET("/integrations/:integration_id/coverage", ctl.GetCoverage)
	g.GET("/integrations/:integration_id/source-health", ctl.GetSourceHealth)
	g.GET("/scan-runs/:scan_id", ctl.GetScanRun)
	g.GET("/agents", ctl.ListAgents)
	g.GET("/agents/:agent_id", ctl.GetAgent)
	g.GET("/agents/:agent_id/evidence", ctl.GetAgentEvidence)
	g.GET("/agents/:agent_id/access-paths", ctl.GetAgentAccessPaths)
	g.GET("/identity-accounts", ctl.ListIdentityAccounts)
	g.GET("/classification-candidates", ctl.ListCandidates)
	d := eng.Group("/authsec/discovery")
	d.GET("/agents", disc.ListDiscoveredAgents)
	d.GET("/coverage", disc.GetCoverage)
	d.GET("/aws/workloads", cloud.ListWorkloads)
	d.GET("/aws/identities", cloud.ListIdentities)
	return eng
}

// egatesCall is one GET on an engine as a workspace.
func egatesCall(t *testing.T, eng *gin.Engine, ws uuid.UUID, path string) (int, any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Egates-Workspace", ws.String())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	var out any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: status %d, body is not JSON: %q", path, w.Code, w.Body.String())
	}
	return w.Code, out
}

var egatesTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// egatesInstallation matches the two GitHub installation ids E16 binds (one
// per workspace: an installation binds once), the only fixture value the two
// workspaces cannot share.
var egatesInstallation = regexp.MustCompile(`inst-egates-(mixed|control)`)

// egatesNormalize masks what legitimately differs between two workspaces
// scanned from the same fixtures -- ids, times and the installation id -- and
// sorts arrays, so two responses compare by their fields and values alone.
func egatesNormalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = egatesNormalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = egatesNormalize(e)
		}
		sort.Slice(out, func(i, j int) bool { return egatesJSON(out[i]) < egatesJSON(out[j]) })
		return out
	case string:
		s := egatesInstallation.ReplaceAllString(egatesUUID.ReplaceAllString(x, "<id>"), "<installation>")
		if egatesTimestamp.MatchString(s) {
			return "<time>"
		}
		return s
	}
	return v
}

// egatesGitHubRows is every GitHub-owned row of the workspace's shared
// tables, rendered whole (updated_at included), in a stable order.
func egatesGitHubRows(t *testing.T, l *p2Lab, ws uuid.UUID) string {
	t.Helper()
	var rows []string
	for _, q := range []string{
		`SELECT to_jsonb(x)::text FROM iga_identity_accounts x WHERE workspace_id = ? AND provider <> 'aws'`,
		`SELECT to_jsonb(x)::text FROM iga_entitlements x WHERE workspace_id = ? AND provider <> 'aws'`,
		`SELECT to_jsonb(x)::text FROM iga_access_edges x WHERE workspace_id = ? AND provider <> 'aws'`,
		`SELECT to_jsonb(x)::text FROM iga_resources x WHERE workspace_id = ? AND provider <> 'aws'`,
		`SELECT to_jsonb(x)::text FROM iga_credentials x WHERE workspace_id = ?`,
		`SELECT to_jsonb(x)::text FROM iga_agents x WHERE workspace_id = ?`,
		`SELECT to_jsonb(x)::text FROM iga_agent_instances x WHERE workspace_id = ?`,
		`SELECT to_jsonb(x)::text FROM iga_classification_candidates x WHERE workspace_id = ?`,
	} {
		var got []string
		if err := l.db.Raw(q, ws).Scan(&got).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		rows = append(rows, got...)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// egatesAWSRows is every AWS-owned row of the shared tables and the graph's
// own, rendered whole.
func egatesAWSRows(t *testing.T, l *p2Lab) string {
	t.Helper()
	var rows []string
	for _, table := range []string{"iga_identity_accounts", "iga_entitlements", "iga_access_edges", "iga_resources"} {
		var got []string
		l.db.Raw(`SELECT to_jsonb(x)::text FROM `+table+` x WHERE workspace_id = ? AND provider = 'aws'`, l.ws).Scan(&got)
		rows = append(rows, got...)
	}
	for _, table := range []string{"iga_workload", "iga_relationship", "iga_policy", "iga_policy_assignment", "iga_object_support"} {
		var got []string
		l.db.Raw(`SELECT to_jsonb(x)::text FROM `+table+` x WHERE workspace_id = ?`, l.ws).Scan(&got)
		rows = append(rows, got...)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// E16. A workspace with the existing GitHub integration AND the §7.1 AWS lab,
// beside a control workspace with the same GitHub integration only. The
// GitHub scan runs before and after the AWS scans and projections. Database:
// the AWS projection touches no GitHub row and the GitHub rescan no AWS row;
// no AWS row in iga_agents or iga_agent_instances; no row without its
// provider. API: every existing GitHub route answers in the mixed workspace
// exactly what it answers in the control (the same fields and values, ids and
// times aside) and mentions no AWS object; the Discovered Agents routes list
// no AWS workload, and the Kubernetes bridge never proposes one; Cloud
// Inventory rows link to their own graph objects, by key, never by name.
//
// Not reachable here, listed for M3: the comparison with the pre-Phase-2
// binary (0e75ad7) itself -- this proves the same binary answers the same
// with and without AWS in the workspace -- and the console pages.
//
// Safeguards (mutation-checked): the GitHub readers filter provider =
// 'github'; the GitHub writer stamps it.
func TestP2EgatesE16ExistingProductsUnchanged(t *testing.T) {
	mixed := newP2Lab(t, "p2-egates-e16-mixed", true)
	control := newWorkspace(t, mixed.db, "p2-egates-e16-control")
	repo := repositories.NewIGARepository(mixed.db)
	mgr := services.NewIGAManager(repo, fixtures(), ownedInstall("inst-egates-mixed", "inst-egates-control"))
	integ := map[uuid.UUID]*models.IGAIntegration{
		mixed.ws: verifiedIntegration(t, mgr, mixed.ws, "inst-egates-mixed"),
		control:  verifiedIntegration(t, mgr, control, "inst-egates-control"),
	}
	scans := map[uuid.UUID]uuid.UUID{}
	githubScan := func(ws uuid.UUID) {
		t.Helper()
		run, err := mgr.StartScan(ws, integ[ws].ID, models.ScanModeFull, "tester")
		if err != nil {
			t.Fatalf("start GitHub scan: %v", err)
		}
		if _, err := mgr.RunScan(context.Background(), ws, run.ID); err != nil {
			t.Fatalf("GitHub scan: %v", err)
		}
		scans[ws] = run.ID
	}
	githubScan(mixed.ws)
	githubScan(control)
	ghBefore := egatesGitHubRows(t, mixed, mixed.ws)
	if ghBefore == "" {
		t.Fatal("setup: the GitHub scan wrote nothing")
	}

	// The AWS lab, scanned and projected.
	a, b := egatesProduction(t, mixed), egatesSandbox(t, mixed)
	egatesCycle(mixed, a)
	egatesCycle(mixed, b)
	if got := egatesGitHubRows(t, mixed, mixed.ws); got != ghBefore {
		t.Errorf("the AWS scans and projections changed GitHub rows:\nbefore %s\nafter  %s", ghBefore, got)
	}
	awsBefore := egatesAWSRows(t, mixed)
	githubScan(mixed.ws)
	githubScan(control)
	if got := egatesAWSRows(t, mixed); got != awsBefore {
		t.Error("the GitHub rescan changed AWS rows")
	}

	// Database: every row names its provider; no AWS row where GitHub reads.
	for _, table := range []string{"iga_identity_accounts", "iga_entitlements", "iga_access_edges", "iga_resources"} {
		if n := mixed.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ? AND provider NOT IN ('aws','github')`, mixed.ws); n != 0 {
			t.Errorf("%s has %d rows with neither provider", table, n)
		}
		if n := mixed.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ? AND provider <> 'aws' AND source_key LIKE 'aws%'`, mixed.ws); n != 0 {
			t.Errorf("%s has %d AWS-keyed rows under another provider", table, n)
		}
	}
	for _, table := range []string{"iga_identity_accounts", "iga_workload", "iga_resources"} {
		col := map[string]string{"iga_identity_accounts": "identity_account_id", "iga_workload": "workload_id", "iga_resources": "resource_id"}[table]
		if n := mixed.count(`SELECT count(*) FROM `+table+` x WHERE x.workspace_id = ? AND x.provider <> 'aws'
		                     AND EXISTS (SELECT 1 FROM iga_object_support s WHERE s.workspace_id = x.workspace_id AND s.`+col+` = x.id)`, mixed.ws); n != 0 {
			t.Errorf("%s: %d rows a connector supports are not provider aws", table, n)
		}
	}
	var awsNames []string
	mixed.db.Raw(`SELECT display_name FROM iga_workload WHERE workspace_id = ?
	              UNION SELECT display_name FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'`, mixed.ws, mixed.ws).Scan(&awsNames)
	for _, table := range []string{"iga_agents", "iga_agent_instances"} {
		var names []string
		mixed.db.Raw(`SELECT display_name FROM `+table+` WHERE workspace_id = ?`, mixed.ws).Scan(&names)
		for _, n := range names {
			for _, aws := range awsNames {
				if n == aws {
					t.Errorf("%s holds %q, an AWS object", table, n)
				}
			}
		}
		if got, want := mixed.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, mixed.ws),
			mixed.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, control); got != want {
			t.Errorf("%s: %d rows in the mixed workspace, %d in the GitHub-only control", table, got, want)
		}
	}

	// API: the mixed workspace answers every GitHub route exactly as the
	// control does, and never with an AWS object.
	eng := egatesGitHubAPI(t, mixed)
	awsIDs := map[string]bool{}
	for _, table := range []string{"iga_workload", "iga_identity_accounts", "iga_resources", "iga_entitlements", "iga_access_edges"} {
		q := `SELECT id FROM ` + table + ` WHERE workspace_id = ?`
		if table != "iga_workload" {
			q += ` AND provider = 'aws'`
		}
		var ids []uuid.UUID
		mixed.db.Raw(q, mixed.ws).Scan(&ids)
		for _, id := range ids {
			awsIDs[id.String()] = true
		}
	}
	agentOf := func(ws uuid.UUID) string {
		var id uuid.UUID
		mixed.db.Raw(`SELECT id FROM iga_agents WHERE workspace_id = ? ORDER BY display_name LIMIT 1`, ws).Scan(&id)
		return id.String()
	}
	paths := func(ws uuid.UUID) []string {
		ag, in := agentOf(ws), integ[ws].ID.String()
		out := []string{"/api/iga/v1/integrations", "/api/iga/v1/integrations/" + in, "/api/iga/v1/integrations/" + in + "/coverage",
			"/api/iga/v1/integrations/" + in + "/source-health", "/api/iga/v1/scan-runs/" + scans[ws].String(),
			"/api/iga/v1/agents", "/api/iga/v1/identity-accounts", "/api/iga/v1/classification-candidates",
			"/authsec/discovery/agents", "/authsec/discovery/coverage"}
		if ag != uuid.Nil.String() {
			out = append(out, "/api/iga/v1/agents/"+ag, "/api/iga/v1/agents/"+ag+"/evidence", "/api/iga/v1/agents/"+ag+"/access-paths")
		}
		return out
	}
	mp, cp := paths(mixed.ws), paths(control)
	if len(mp) != len(cp) {
		t.Fatalf("the mixed workspace has %d GitHub routes to compare, the control %d", len(mp), len(cp))
	}
	for i := range mp {
		mc, mb := egatesCall(t, eng, mixed.ws, mp[i])
		cc, cb := egatesCall(t, eng, control, cp[i])
		if mc != cc {
			t.Errorf("GET %s: %d with AWS in the workspace, %d without", mp[i], mc, cc)
			continue
		}
		raw := egatesJSON(mb)
		for _, id := range egatesUUID.FindAllString(raw, -1) {
			if awsIDs[id] {
				t.Errorf("GET %s returns AWS object %s", mp[i], id)
			}
		}
		for _, s := range []string{"arn:aws:", egatesSharedRole, "ticket-tools", accountA, accountB} {
			if strings.Contains(raw, s) {
				t.Errorf("GET %s mentions %q", mp[i], s)
			}
		}
		if m, c := egatesJSON(egatesNormalize(mb)), egatesJSON(egatesNormalize(cb)); m != c {
			t.Errorf("GET %s differs with AWS in the workspace:\n mixed   %s\n control %s", mp[i], m, c)
		}
	}

	// The Kubernetes bridge: a sighting named like an AWS workload is never
	// proposed a link to it -- AWS workloads are not canonical agents.
	sighting := uuid.New()
	if err := mixed.db.Exec(`INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name)
	                         VALUES (?, ?, 'k8s_webhook', ?, 'ticket-tools')`, sighting, mixed.ws, "fp-egates-"+sighting.String()[:8]).Error; err != nil {
		t.Fatalf("seed a sighting: %v", err)
	}
	t.Cleanup(func() {
		mixed.db.Exec(`DELETE FROM discovered_agent_iga_links WHERE discovered_agent_id = ?`, sighting)
		mixed.db.Exec(`DELETE FROM discovered_agents WHERE id = ?`, sighting)
	})
	if link, err := services.NewIGABridgeManager(mixed.db).ProposeForAgent(mixed.ws, sighting); err != nil || link != nil {
		t.Errorf("the bridge proposed %+v (%v) for a sighting named like an AWS workload, want nothing", link, err)
	}
	if _, body := egatesCall(t, eng, mixed.ws, "/authsec/discovery/agents"); strings.Contains(egatesJSON(body), accountA) ||
		num(body, "total") != 1 {
		t.Errorf("/discovery/agents = %s, want the one sighting and no AWS workload", egatesJSON(body))
	}

	// Cloud Inventory rows link to THEIR graph object: A's and B's
	// ticket-tools share a name, and each resolves to its own.
	api := mixed.api()
	for _, acct := range []*egatesAcct{a, b} {
		_, inv := egatesCall(t, eng, mixed.ws, "/authsec/discovery/aws/workloads?connector_id="+acct.conn.String())
		var cloudID string
		for _, w := range digl(inv, "data") {
			if digs(w, "name") == "ticket-tools" {
				cloudID = digs(w, "id")
			}
		}
		if cloudID == "" {
			t.Fatalf("Cloud Inventory for %s has no ticket-tools row: %s", acct.id, egatesJSON(inv))
		}
		look := egatesGet(t, api, "/lookup"+qs("cloud_ref", "cloud_workload:"+cloudID))
		if digs(look, "data", "ref") != egatesWorkload(t, mixed, "ticket-tools", acct.id) {
			t.Errorf("Cloud Inventory row %s (account %s) links to %s, want its own account's ticket-tools",
				cloudID, acct.id, digs(look, "data", "ref"))
		}
	}
}
