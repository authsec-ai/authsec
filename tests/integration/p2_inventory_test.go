package integration

// The unified inventory (unified-discovery CONTRACT, "The API"): GET
// /api/iga/v1/inventory/workloads, /inventory/identities, /inventory/resources
// over AWS, Kubernetes and GitHub rows of the shared iga_* tables. The estate
// is p2_inventory_harness_test.go's seedHome / seedOther.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

const (
	invWorkloads  = "/inventory/workloads"
	invIdentities = "/inventory/identities"
	invResources  = "/inventory/resources"
)

func invWant(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

// One call lists every provider's rows, in the one row shape: typed ref,
// provider, kind, native id, scope (derived for AWS, stated for k8s and
// github), sub_scope, state, times and attrs without the scope keys.
func TestP2InventoryEveryProvider(t *testing.T) {
	l := newInvLab(t, nil)
	h := l.home

	rows, body := l.list(invWorkloads)
	invWant(t, "workload names", invNames(rows), []string{"billing-fn", "checkout", "Deploy_100%", "repo-agent", "stale-mixed"})
	// No AWS publication in the fixture, and the Kubernetes source has never
	// swept: the rows are AWS and others, so the result is mixed, with the
	// cluster's not_swept note.
	invWant(t, "meta", body["meta"], map[string]any{
		"limit": float64(50), "next_cursor": nil, "total_known": true, "total": float64(5),
		"rev": nil, "published_at": nil, "graph_state": "mixed",
		"coverage": []any{map[string]any{"account_id": invCluster, "surface": "k8s_sweep", "state": "not_swept",
			"affects": "no sweep has been received, so this cluster has no inventory yet"}}})

	aws := invRow(t, rows, "billing-fn")
	invWant(t, "aws workload", aws, map[string]any{
		"ref": refOf("workload", h.ids["billing-fn"]), "provider": "aws", "kind": "lambda_function", "name": "billing-fn",
		"native_id": "arn:aws:lambda:us-east-1:" + invAccountHome + ":function:billing-fn",
		"scope":     map[string]any{"kind": "aws_account", "id": invAccountHome, "label": "prod-account"},
		"sub_scope": "us-east-1", "lifecycle": "active", "retired_reason": nil, "state": "current",
		"first_seen_at": invBase.Format(time.RFC3339), "last_seen_at": invBase.Add(time.Hour).Format(time.RFC3339),
		"attrs": map[string]any{"package_type": "Zip"},
		// Nothing is published in this fixture, so no AWS row can claim it.
		"as_of": nil,
	})
	k8s := invRow(t, rows, "checkout")
	invWant(t, "k8s workload", k8s, map[string]any{
		"ref": refOf("workload", h.ids["checkout"]), "provider": "k8s", "kind": "k8s_deployment", "name": "checkout",
		"native_id": "shop/checkout",
		"scope":     map[string]any{"kind": "k8s_cluster", "id": invCluster, "label": invCluster},
		"sub_scope": "shop", "lifecycle": "active", "retired_reason": nil, "state": "current",
		"first_seen_at": invBase.Format(time.RFC3339), "last_seen_at": invBase.Add(4 * time.Hour).Format(time.RFC3339),
		"attrs":       map[string]any{"fingerprint": "fp-checkout"},
		"graph_state": "unrevisioned", "as_of": nil,
	})
	gh := invRow(t, rows, "Deploy_100%")
	invWant(t, "github workload", gh, map[string]any{
		"ref": refOf("workload", h.ids["Deploy_100%"]), "provider": "github", "kind": "github_actions_workflow", "name": "Deploy_100%",
		"native_id": "deploy.yml",
		"scope":     map[string]any{"kind": "github_org", "id": invOrg, "label": invOrg},
		"sub_scope": "acme/web", "lifecycle": "active", "retired_reason": nil, "state": "stale",
		"first_seen_at": invBase.Format(time.RFC3339), "last_seen_at": invBase.Add(2 * time.Hour).Format(time.RFC3339),
		"attrs":       map[string]any{"path": ".github/workflows/deploy.yml"},
		"graph_state": "unrevisioned", "as_of": nil,
	})
	// A projection may state the native id; it is then the row's.
	invWant(t, "stated native id", digs(invRow(t, rows, "repo-agent"), "native_id"), "acme/web/AGENTS.md")

	rows, _ = l.list(invIdentities)
	invWant(t, "identity names", invNames(rows),
		[]string{"acme-installation", "billing-role", "deploy-key-7", "system:serviceaccount:shop:checkout-sa"})
	role := invRow(t, rows, "billing-role")
	invWant(t, "aws identity scope", role["scope"], map[string]any{"kind": "aws_account", "id": invAccountHome, "label": "prod-account"})
	invWant(t, "aws identity sub_scope (IAM is global)", role["sub_scope"], nil)
	invWant(t, "aws identity native id", role["native_id"], "arn:aws:iam::"+invAccountHome+":role/billing-role")
	invWant(t, "aws identity kind", role["kind"], "iam_role")
	sa := invRow(t, rows, "system:serviceaccount:shop:checkout-sa")
	invWant(t, "k8s identity", []any{sa["ref"], sa["native_id"], sa["sub_scope"], sa["kind"]},
		[]any{refOf("identity", h.ids["system:serviceaccount:shop:checkout-sa"]), "shop/checkout-sa", "shop", "k8s_service_account"})
	inst := invRow(t, rows, "acme-installation")
	invWant(t, "github identity", []any{inst["native_id"], inst["sub_scope"], inst["attrs"]}, []any{"12345", nil, map[string]any{}})

	rows, _ = l.list(invResources)
	table := "arn:aws:dynamodb:us-east-1:" + invAccountHome + ":table/orders"
	invWant(t, "resource names", invNames(rows), []string{"acme/web", table, "secrets"})
	ddb := invRow(t, rows, table)
	invWant(t, "aws resource", []any{ddb["ref"], ddb["native_id"], ddb["scope"], ddb["sub_scope"], ddb["kind"]},
		[]any{refOf("resource", h.ids[table]), table,
			map[string]any{"kind": "aws_account", "id": invAccountHome, "label": "prod-account"}, "us-east-1", "exact"})
	sec := invRow(t, rows, "secrets")
	invWant(t, "cluster-scoped k8s resource", []any{sec["native_id"], sec["sub_scope"], digs(sec, "scope", "id")},
		[]any{"secrets", nil, invCluster})
	repo := invRow(t, rows, "acme/web")
	invWant(t, "github resource", []any{repo["native_id"], repo["sub_scope"], repo["state"], repo["attrs"]},
		[]any{"acme/web", "acme/web", "current", map[string]any{"private": true}})
}

// Listed means: a non-ended support row from any source, not a legacy GitHub
// row, and the lifecycle filter. state is current when any support row is.
func TestP2InventoryVisibility(t *testing.T) {
	l := newInvLab(t, nil)

	for _, lc := range []string{"", "active", "retired", "all"} {
		path := invWorkloads
		if lc != "" {
			path += qs("lifecycle", lc)
		}
		rows, _ := l.list(path)
		for _, hidden := range []string{"ended-only", "unsupported"} {
			for _, n := range invNames(rows) {
				if n == hidden {
					t.Errorf("%s lists %q, which has no non-ended support row", path, hidden)
				}
			}
		}
	}
	for _, c := range []struct{ path, legacy string }{
		{invIdentities, "legacy-gh-identity"}, {invResources, "legacy-gh-repo"},
	} {
		for _, path := range []string{c.path, c.path + qs("lifecycle", "all"), c.path + qs("q", "legacy"), c.path + qs("provider", "github")} {
			rows, _ := l.list(path)
			for _, n := range invNames(rows) {
				if n == c.legacy {
					t.Errorf("%s lists the legacy GitHub row %q (source_key '')", path, n)
				}
			}
		}
	}

	rows, _ := l.list(invWorkloads + qs("lifecycle", "retired"))
	invWant(t, "retired workloads", invNames(rows), []string{"retired-wl"})
	if len(rows) == 1 {
		invWant(t, "retired row", []any{digs(rows[0], "lifecycle"), digs(rows[0], "retired_reason")}, []any{"retired", "deleted"})
	}
	rows, _ = l.list(invWorkloads + qs("lifecycle", "all"))
	invWant(t, "all workloads", invNames(rows), []string{"billing-fn", "checkout", "Deploy_100%", "repo-agent", "retired-wl", "stale-mixed"})

	states := map[string]string{}
	for _, r := range rows {
		states[digs(r, "name")] = digs(r, "state")
	}
	invWant(t, "states", states, map[string]string{
		"billing-fn": "current", "checkout": "current", // stale + current
		"Deploy_100%": "stale", "repo-agent": "current", "retired-wl": "current",
		"stale-mixed": "stale", // stale + ended
	})
}

func TestP2InventoryFilters(t *testing.T) {
	l := newInvLab(t, nil)

	for _, c := range []struct {
		path string
		want []string
	}{
		{qs("provider", "k8s"), []string{"checkout", "stale-mixed"}},
		{"?provider=aws&provider=github", []string{"billing-fn", "Deploy_100%", "repo-agent"}},
		{"?kind=k8s_deployment&kind=github_actions_workflow", []string{"checkout", "Deploy_100%"}},
		{qs("kind", "no_such_kind"), []string{}},
		{qs("scope", invCluster), []string{"checkout", "stale-mixed"}},
		{qs("scope", invAccountHome), []string{"billing-fn"}},
		{"?scope=" + invOrg + "&scope=" + invAccountHome, []string{"billing-fn", "Deploy_100%", "repo-agent"}},
		{qs("scope", invAccountOther), []string{}},
		{"?provider=k8s&scope=" + invOrg, []string{}},
		// q: a case-insensitive substring of the name ...
		{qs("q", "DEPLOY"), []string{"Deploy_100%"}},
		{qs("q", "y_1"), []string{"Deploy_100%"}},
		// ... or of the native id, which the name does not contain.
		{qs("q", "shop/check"), []string{"checkout"}},
		{qs("q", "function:billing"), []string{"billing-fn"}},
		{qs("q", "AGENTS.md"), []string{"repo-agent"}},
		// LIKE metacharacters are literal: "%%" is no row's substring.
		{qs("q", "%%"), []string{}},
		{qs("q", "__"), []string{}},
		{"?provider=k8s&q=check", []string{"checkout"}},
	} {
		rows, body := l.list(invWorkloads + c.path)
		invWant(t, c.path, invNames(rows), c.want)
		if n := num(body, "meta", "total"); n != int64(len(c.want)) {
			t.Errorf("%s total = %d, want %d", c.path, n, len(c.want))
		}
	}
	rows, _ := l.list(invIdentities + qs("provider", "k8s"))
	invWant(t, "k8s identities", invNames(rows), []string{"system:serviceaccount:shop:checkout-sa"})
	rows, _ = l.list(invResources + qs("scope", invAccountHome))
	invWant(t, "resources in the account", invNames(rows), []string{"arn:aws:dynamodb:us-east-1:" + invAccountHome + ":table/orders"})

	// Facets: each counts with every OTHER filter applied.
	_, body := l.list(invWorkloads + qs("provider", "k8s", "facets", "provider,kind,scope"))
	invWant(t, "provider facet (ignores provider)", invFacet(body, "provider"),
		map[string]string{"aws": "AWS:1", "github": "GitHub:2", "k8s": "Kubernetes:2"})
	invWant(t, "kind facet (applies provider)", invFacet(body, "kind"),
		map[string]string{"k8s_cronjob": "Kubernetes CronJob:1", "k8s_deployment": "Kubernetes Deployment:1"})
	invWant(t, "scope facet (applies provider)", invFacet(body, "scope"), map[string]string{invCluster: invCluster + ":2"})
	_, body = l.list(invWorkloads + qs("facets", "scope", "scope", invOrg, "kind", "github_declared_agent"))
	invWant(t, "scope facet (ignores scope, applies kind)", invFacet(body, "scope"),
		map[string]string{invOrg: invOrg + ":1"})
	_, body = l.list(invWorkloads + qs("facets", "scope,provider"))
	invWant(t, "scope facet", invFacet(body, "scope"), map[string]string{
		invAccountHome: "prod-account:1", invCluster: invCluster + ":2", invOrg: invOrg + ":2"})
	if digl(body, "meta", "facets", "kind") != nil {
		t.Errorf("kind facet returned though not asked for")
	}
	// The order: count, then value.
	invWant(t, "scope facet order", []string{digs(body, "meta", "facets", "scope", 0, "value"),
		digs(body, "meta", "facets", "scope", 1, "value"), digs(body, "meta", "facets", "scope", 2, "value")},
		[]string{invOrg, invCluster, invAccountHome})

	// 400s, all in the envelope, naming the parameter.
	for _, c := range []struct{ path, param string }{
		{qs("provider", "gcp"), "provider"},
		{qs("provider", "kubernetes"), "provider"},
		{qs("q", "a"), "q"},
		{qs("lifecycle", "gone"), "lifecycle"},
		{qs("limit", "0"), "limit"},
		{qs("limit", "201"), "limit"},
		{qs("sort", "-name"), "sort"},
		{qs("sort", "last_seen"), "sort"},
		{qs("sort", "kind"), "sort"},
		{qs("facets", "account"), "facets"},
		{qs("account", invAccountHome), "account"},
		{qs("rev", "1"), "rev"},
		{qs("runtime_kind", "lambda_function"), "runtime_kind"},
		{qs("workspace_id", l.other.ws.String()), "workspace_id"},
	} {
		for _, route := range []string{invWorkloads, invIdentities, invResources} {
			code, body := l.get(route + c.path)
			if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" || digs(body, "error", "parameter") != c.param {
				t.Errorf("%s%s = %d %v, want 400 invalid_parameter naming %s", route, c.path, code, body, c.param)
			}
		}
	}
	// Bounds that are allowed.
	rows, body = l.list(invWorkloads + qs("limit", "200", "sort", "-last_seen"))
	invWant(t, "limit 200", num(body, "meta", "limit"), int64(200))
	invWant(t, "-last_seen", invNames(rows), []string{"stale-mixed", "checkout", "repo-agent", "Deploy_100%", "billing-fn"})
}

// Keyset paging under a signed cursor bound to the workspace, the route, the
// filter set and the sort.
func TestP2InventoryPaging(t *testing.T) {
	l := newInvLab(t, nil)

	walk := func(path string) ([]string, []string) {
		t.Helper()
		var names, cursors []string
		next := path
		for i := 0; i < 10; i++ {
			rows, body := l.list(next)
			names = append(names, invNames(rows)...)
			if n := num(body, "meta", "total"); n != 5 {
				t.Errorf("%s total = %d, want 5 on every page", next, n)
			}
			cur := digs(body, "meta", "next_cursor")
			if cur == "" {
				return names, cursors
			}
			cursors = append(cursors, cur)
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			next = path + sep + "cursor=" + url.QueryEscape(cur)
		}
		t.Fatalf("%s did not end", path)
		return nil, nil
	}
	names, cursors := walk(invWorkloads + qs("limit", "2"))
	invWant(t, "name pages", names, []string{"billing-fn", "checkout", "Deploy_100%", "repo-agent", "stale-mixed"})
	invWant(t, "name page count", len(cursors), 2)
	names, _ = walk(invWorkloads + qs("limit", "2", "sort", "-last_seen"))
	invWant(t, "-last_seen pages", names, []string{"stale-mixed", "checkout", "repo-agent", "Deploy_100%", "billing-fn"})
	// The facets and limit do not bind the cursor; the filters do.
	names, _ = walk(invWorkloads + qs("limit", "1", "lifecycle", "active", "facets", "kind"))
	invWant(t, "limit 1 pages", names, []string{"billing-fn", "checkout", "Deploy_100%", "repo-agent", "stale-mixed"})

	_, body := l.list(invWorkloads + qs("limit", "2"))
	cur := digs(body, "meta", "next_cursor")
	if cur == "" {
		t.Fatal("no next_cursor on the first page")
	}
	rows, _ := l.list(invWorkloads + qs("limit", "3", "cursor", cur))
	invWant(t, "a cursor with another limit", invNames(rows), []string{"Deploy_100%", "repo-agent", "stale-mixed"})

	body64, sig, _ := strings.Cut(cur, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(body64)
	var moved map[string]any
	_ = json.Unmarshal(payload, &moved)
	moved["i"] = l.home.ids["stale-mixed"].String()
	raw, _ := json.Marshal(moved)
	tampered := base64.RawURLEncoding.EncodeToString(raw) + "." + sig

	// A cursor of the graph's own workload list, signed with the same key over
	// the same filter hash and sort: another route.
	graph := igaread.NewReader(l.db, readTestCursorKey).SignCursor(igaread.Cursor{
		WS: l.home.ws, Route: "workloads", Filter: igaread.FilterHash(url.Values{}), Sort: "name",
		Key: json.RawMessage(`{"k":["checkout"]}`), ID: l.home.ids["checkout"]})

	for _, c := range []struct {
		name, path string
		ws         uuid.UUID
	}{
		{"tampered", invWorkloads + qs("limit", "2", "cursor", tampered), l.home.ws},
		{"garbage", invWorkloads + qs("cursor", "not-a-cursor"), l.home.ws},
		{"another workspace", invWorkloads + qs("limit", "2", "cursor", cur), l.other.ws},
		{"another filter set", invWorkloads + qs("limit", "2", "provider", "k8s", "cursor", cur), l.home.ws},
		{"another q", invWorkloads + qs("limit", "2", "q", "ch", "cursor", cur), l.home.ws},
		{"another sort", invWorkloads + qs("limit", "2", "sort", "-last_seen", "cursor", cur), l.home.ws},
		{"another inventory route", invIdentities + qs("limit", "2", "cursor", cur), l.home.ws},
		{"another inventory route", invResources + qs("limit", "2", "cursor", cur), l.home.ws},
		{"the graph list's cursor", invWorkloads + qs("cursor", graph), l.home.ws},
	} {
		l.as(c.ws)
		code, body := l.get(c.path)
		l.as(l.home.ws)
		if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
			t.Errorf("%s: %d %v, want 400 cursor_invalid", c.name, code, body)
		}
	}
}

// Rows of another workspace never appear: not on a page, in a total, in a
// facet, nor by name.
func TestP2InventoryWorkspaceIsolation(t *testing.T) {
	l := newInvLab(t, nil)
	leaks := func(body map[string]any, of *invEstate) string {
		raw, _ := json.Marshal(body)
		for name, id := range of.ids {
			if strings.Contains(string(raw), id.String()) {
				return name
			}
		}
		for _, s := range []string{of.account, "billing-other", "acme/other"} {
			if of == l.other && strings.Contains(string(raw), s) {
				return s
			}
		}
		return ""
	}
	for _, route := range []string{invWorkloads, invIdentities, invResources} {
		for _, path := range []string{route + qs("lifecycle", "all", "facets", "provider,kind,scope"),
			route + qs("q", "billing"), route + qs("scope", invAccountOther), route + qs("q", "other")} {
			_, body := l.list(path)
			if s := leaks(body, l.other); s != "" {
				t.Errorf("home %s shows the other workspace's %q", path, s)
			}
		}
	}
	rows, _ := l.list(invWorkloads + qs("q", "billing"))
	invWant(t, "home billing", invNames(rows), []string{"billing-fn"})

	l.as(l.other.ws)
	rows, body := l.list(invWorkloads + qs("facets", "scope"))
	invWant(t, "other workloads", invNames(rows), []string{"billing-other", "checkout"})
	invWant(t, "other checkout", digs(invRow(t, rows, "checkout"), "ref"), refOf("workload", l.other.ids["checkout"]))
	invWant(t, "other scope facet", invFacet(body, "scope"),
		map[string]string{invAccountOther: "other-account:1", invCluster: invCluster + ":1"})
	for _, route := range []string{invWorkloads, invIdentities, invResources} {
		_, body := l.list(route + qs("lifecycle", "all", "facets", "provider,kind,scope"))
		if s := leaks(body, l.home); s != "" {
			t.Errorf("other %s shows the home workspace's %q", route, s)
		}
	}
	rows, _ = l.list(invResources)
	invWant(t, "other resources", invNames(rows), []string{"acme/other"})

	// No workspace in the token: 401, never a list.
	l.as(uuid.Nil)
	code, body := l.get(invWorkloads)
	if code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
		t.Errorf("no token workspace: %d %v, want 401 unauthenticated", code, body)
	}
}

// Every inventory route demands iga:read, and the PRODUCTION chain
// (routes.SetupIGARoutes, AuthMiddleware, Require) answers 401 and 403 in the
// error envelope and serves an allowed request.
func TestP2InventoryAuth(t *testing.T) {
	l := newInvLab(t, nil)
	for _, route := range []string{invWorkloads, invIdentities, invResources} {
		l.get(route)
		l.mu.Lock()
		perm := l.lastPerm
		l.mu.Unlock()
		invWant(t, route+" permission", perm, "iga:read")
	}

	const secret = "p2-inventory-jwt-secret"
	t.Setenv("JWT_SDK_SECRET", secret)
	t.Setenv("JWT_DEF_SECRET", secret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	eng := gin.New()
	routes.SetupIGARoutes(eng, platform.NewIGAController(l.db), l.ctl)
	token := func(claims jwt.MapClaims) string {
		claims["iss"] = "authsec-ai/auth-manager"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["workspace_id"] = l.home.ws.String()
		claims["user_id"] = uuid.NewString()
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, route := range []string{invWorkloads, invIdentities, invResources} {
		for _, c := range []struct {
			name, bearer string
			status       int
			code         string
		}{
			{"no token", "", http.StatusUnauthorized, "unauthenticated"},
			{"bad token", "not-a-jwt", http.StatusUnauthorized, "unauthenticated"},
			{"no iga:read", token(jwt.MapClaims{}), http.StatusForbidden, "forbidden"},
		} {
			code, body := invServe(t, eng, route, c.bearer)
			if code != c.status || errCode(body) != c.code {
				t.Errorf("%s %s: %d %v, want %d %s", route, c.name, code, body, c.status, c.code)
			}
			if c.status == http.StatusForbidden && !reflect.DeepEqual(dig(body, "error", "required_permissions"), []any{"iga:read"}) {
				t.Errorf("%s %s: required_permissions = %v, want [iga:read]", route, c.name, dig(body, "error", "required_permissions"))
			}
		}
		code, body := invServe(t, eng, route, token(jwt.MapClaims{"scope": "iga:read"}))
		if code != http.StatusOK || len(digl(body, "data")) == 0 {
			t.Errorf("%s with iga:read: %d %v, want 200 with rows", route, code, body)
		}
	}
	// A 400 from the handler passes through the envelope wrapper untouched.
	code, body := invServe(t, eng, invWorkloads+qs("bogus", "1"), token(jwt.MapClaims{"scope": "iga:read"}))
	if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
		t.Errorf("unknown parameter through the production chain: %d %v", code, body)
	}
}

// With IGA_GRAPH_PROJECTION off or misconfigured every inventory route is 503
// graph_unavailable -- never an empty list -- before parameters are read.
func TestP2InventoryUnavailable(t *testing.T) {
	for _, c := range []struct {
		name string
		gate *services.GraphProjectionGate
		mode string
	}{
		{"off", services.NewGraphProjectionGate(false, ""), services.GraphProjectionOff},
		{"misconfigured", services.NewGraphProjectionGate(true, `IGA_GRAPH_PROJECTION="maybe" is not on or off`), services.GraphProjectionMisconfigured},
		{"on, not verified", services.NewGraphProjectionGate(true, ""), services.GraphProjectionMisconfigured},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newInvLab(t, c.gate)
			for _, route := range []string{invWorkloads, invIdentities, invResources} {
				for _, path := range []string{route, route + qs("bogus", "1")} {
					code, body := l.get(path)
					if code != http.StatusServiceUnavailable || errCode(body) != "graph_unavailable" ||
						digs(body, "error", "graph_projection") != c.mode {
						t.Errorf("%s: %d %v, want 503 graph_unavailable (%s)", path, code, body, c.mode)
					}
				}
			}
		})
	}
}
