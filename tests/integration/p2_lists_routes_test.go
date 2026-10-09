package integration

// T6.7 over the REAL route table (RegisterIGAGraphReadRoutes): every route
// demands the permission §5.3 names, and E14 -- another workspace's ids are
// 404 not_found on every route that takes one, and no route ever returns
// another workspace's rows.
//
// Table-driven over the engine's own route list, so a route added to the
// table without a case here FAILS this test instead of going unchecked. A
// route whose task has not landed answers 501 not_implemented and is logged,
// not asserted; the moment it is implemented its 404 is.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// listsForeign is one workspace's object ids, to be requested from another.
type listsForeign struct {
	workload, identity, resource, statement uuid.UUID
	grant, relationship, principal          uuid.UUID
	cloudIdentity, cloudWorkload, connector uuid.UUID
	account                                 string
}

func listsForeignIDs(t *testing.T, l *p2Lab, a *p2Account) listsForeign {
	t.Helper()
	f := listsForeign{connector: a.conn, account: a.id}
	for dst, q := range map[*uuid.UUID]string{
		&f.workload:      `SELECT id FROM iga_workload WHERE workspace_id = ? LIMIT 1`,
		&f.identity:      `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`,
		&f.resource:      `SELECT id FROM iga_resources WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`,
		&f.statement:     `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`,
		&f.grant:         `SELECT id FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`,
		&f.relationship:  `SELECT id FROM iga_relationship WHERE workspace_id = ? LIMIT 1`,
		&f.cloudIdentity: `SELECT id FROM cloud_identity WHERE workspace_id = ? LIMIT 1`,
		&f.cloudWorkload: `SELECT id FROM cloud_workload WHERE workspace_id = ? LIMIT 1`,
	} {
		if err := l.db.Raw(q, l.ws).Row().Scan(dst); err != nil {
			t.Fatalf("setup: the foreign workspace has no row for %q: %v", q, err)
		}
	}
	// External principals exist only where a trust policy names one; a random
	// id is still a correct 404 probe when this fixture has none.
	if err := l.db.Raw(`SELECT id FROM iga_external_principal WHERE workspace_id = ? LIMIT 1`,
		l.ws).Row().Scan(&f.principal); err != nil {
		f.principal = uuid.New()
	}
	return f
}

// listsRouteCase is how to call one route with the foreign workspace's ids.
type listsRouteCase struct {
	path string // concrete, with the foreign ids
	body any
	perm string // the permission its middleware must demand
	want int    // the status a request from the OTHER workspace must get
}

func TestP2ListsRoutesPermissionsAndCrossWorkspace(t *testing.T) {
	home := newP2Lab(t, "p2-lists-e14-home", true)
	other := newP2Lab(t, "p2-lists-e14-other", true)
	// Each lab empties cloud_scan_run when it is created and again at cleanup,
	// and publications reference runs RESTRICT: both labs exist before either
	// scans, and this cleanup (registered last, so run first) removes both
	// workspaces' graph rows before either lab clears the run table.
	t.Cleanup(func() { other.cleanup(); home.cleanup() })

	a := oneLambda(home)
	home.scanAndProject(a)
	b := other.account(accountB)
	b.role("OtherRole", "AROAOTHERROLEOTHERRO")
	listsFunctions(b, "us-east-1", "other-fn", b.roleARN("OtherRole"))
	other.scanAndProject(b)
	f := listsForeignIDs(t, home, a)

	// The requester: a verified human of the OTHER workspace, so the only
	// thing wrong with a classification decision is the foreign id.
	user := uuid.New()
	seedUser(t, other.db, other.ws, user, user.String()+"@p2-lists.test")
	membership := seedMembership(t, other.db, other.ws, user, "active")
	api := other.api().withClaims(map[string]string{
		"user_id": user.String(), "workspace_membership_id": membership.String(),
	})

	w, id, res := f.workload.String(), f.identity.String(), f.resource.String()
	const read, review = "iga:read", "iga:review"
	cases := map[string]listsRouteCase{
		"GET /capabilities": {path: "/capabilities", perm: "", want: 200},
		"GET /pipeline":     {path: "/pipeline", perm: read, want: 200},
		"GET /coverage":     {path: "/coverage", perm: read, want: 200},

		"GET /workloads":                    {path: "/workloads", perm: read, want: 200},
		"GET /workloads/:id":                {path: "/workloads/" + w, perm: read, want: 404},
		"GET /workloads/:id/identities":     {path: "/workloads/" + w + "/identities", perm: read, want: 404},
		"GET /workloads/:id/resources":      {path: "/workloads/" + w + "/resources", perm: read, want: 404},
		"GET /workloads/:id/changes":        {path: "/workloads/" + w + "/changes", perm: read, want: 404},
		"GET /workloads/:id/classification": {path: "/workloads/" + w + "/classification", perm: read, want: 404},
		"POST /workloads/:id/classification": {path: "/workloads/" + w + "/classification", perm: review, want: 404,
			body: map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent",
				"purpose": "", "reason": "cross-workspace probe", "expected_version": 0, "undoes_decision_id": nil}},

		"GET /identities":                 {path: "/identities", perm: read, want: 200},
		"GET /identities/:id":             {path: "/identities/" + id, perm: read, want: 404},
		"GET /identities/:id/used-by":     {path: "/identities/" + id + "/used-by", perm: read, want: 404},
		"GET /identities/:id/permissions": {path: "/identities/" + id + "/permissions", perm: read, want: 404},
		"GET /identities/:id/changes":     {path: "/identities/" + id + "/changes", perm: read, want: 404},

		"GET /external-principals/:id":               {path: "/external-principals/" + f.principal.String(), perm: read, want: 404},
		"GET /external-principals/:id/referenced-by": {path: "/external-principals/" + f.principal.String() + "/referenced-by", perm: read, want: 404},

		"GET /resources":             {path: "/resources", perm: read, want: 200},
		"GET /resources/:id":         {path: "/resources/" + res, perm: read, want: 404},
		"GET /resources/:id/access":  {path: "/resources/" + res + "/access", perm: read, want: 404},
		"GET /resources/:id/changes": {path: "/resources/" + res + "/changes", perm: read, want: 404},

		// direction is required on /graph and /graph/expand (D-35), so the
		// probes are otherwise well-formed: the foreign id is the only fault.
		"GET /graph":        {path: "/graph" + qs("root", refOf("workload", f.workload), "direction", "forward"), perm: read, want: 404},
		"GET /graph/expand": {path: "/graph/expand" + qs("node", refOf("identity", f.identity), "edge", "can_assume", "direction", "forward"), perm: read, want: 404},
		"GET /graph/path":   {path: "/graph/path" + qs("from", refOf("workload", f.workload), "to", refOf("resource", f.resource)), perm: read, want: 404},
		"GET /evidence":     {path: "/evidence" + qs("claim", refOf("grant", f.grant)), perm: read, want: 404},
		"GET /lookup":       {path: "/lookup" + qs("cloud_ref", "cloud_identity:"+f.cloudIdentity.String()), perm: read, want: 404},
	}

	// Anything of the home workspace in a response is a leak.
	leaks := []string{f.workload.String(), f.identity.String(), f.resource.String(), f.statement.String(),
		f.grant.String(), f.relationship.String(), f.connector.String(), f.account, "refund-processor"}
	leaked := func(body map[string]any) string {
		raw, _ := json.Marshal(body)
		for _, s := range leaks {
			if strings.Contains(string(raw), s) {
				return s
			}
		}
		return ""
	}

	seen := map[string]bool{}
	for _, r := range api.eng.Routes() {
		key := r.Method + " " + strings.TrimPrefix(r.Path, "/api/iga/v1")
		seen[key] = true
		c, ok := cases[key]
		if !ok {
			t.Errorf("route %s has no case in this table: add its permission and its cross-workspace probe", key)
			continue
		}
		if got := api.requiredPermission(r.Method, c.path); got != c.perm {
			t.Errorf("%s demands %q, want %q", key, got, c.perm)
		}
		code, body := api.do(r.Method, c.path, c.body)
		if code == http.StatusNotImplemented && errCode(body) == "not_implemented" {
			t.Logf("%s: not implemented at this commit; its %d is asserted once it lands", key, c.want)
			continue
		}
		if code != c.want {
			raw, _ := json.Marshal(body)
			t.Errorf("%s from another workspace = %d %s, want %d", key, code, raw, c.want)
		}
		if c.want == 404 && errCode(body) != "not_found" {
			t.Errorf("%s: 404 body = %v, want code not_found with no hint", key, body)
		}
		if s := leaked(body); s != "" {
			t.Errorf("%s from another workspace returned the home workspace's %q", key, s)
		}
	}
	for key := range cases {
		if !seen[key] {
			t.Errorf("case %s names no registered route", key)
		}
	}

	// Object-addressing QUERY parameters of the implemented routes, and a
	// positive control: the same ids from their own workspace do resolve, so
	// the 404s above are about the workspace and nothing else.
	for _, path := range []string{
		"/workloads" + qs("integration", refOf("cloud_connector", f.connector)),
		"/workloads" + qs("q", "refund"),
		"/identities" + qs("q", "refund"),
		"/resources" + qs("q", "support"),
	} {
		body := listsGet(t, api, path)
		if n := len(digl(body, "data")); n != 0 {
			t.Errorf("%s from another workspace = %d rows, want none", path, n)
		}
	}
	if code, body := api.get("/lookup" + qs("cloud_ref", "cloud_workload:"+f.cloudWorkload.String())); code != 404 {
		t.Errorf("a foreign cloud_workload lookup = %d %v, want 404", code, body)
	}
	own := home.api()
	if refs := listsField(digl(listsGet(t, own, "/workloads"), "data"), "ref"); len(refs) != 1 || refs[0] != refOf("workload", f.workload) {
		t.Errorf("home's own /workloads = %v, want its workload", refs)
	}
	if code, body := own.get("/lookup" + qs("cloud_ref", "cloud_identity:"+f.cloudIdentity.String())); code != 200 {
		t.Errorf("home's own lookup = %d %v, want 200", code, body)
	}
	if names := listsField(digl(listsGet(t, api, "/workloads"), "data"), "name"); len(names) != 1 || names[0] != "other-fn" {
		t.Errorf("the other workspace's /workloads = %v, want only its own other-fn", names)
	}
}
