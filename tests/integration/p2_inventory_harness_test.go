package integration

// The unified inventory's harness (unified-discovery CONTRACT, "The API"):
// two workspaces whose iga_* rows are inserted directly -- AWS, Kubernetes and
// GitHub, each with support rows of its own source kind (a cloud connector, a
// k8s discovery source, a GitHub integration, a repo_scan discovery source) --
// and the REAL inventory route table (RegisterIGAInventoryRoutes) over them,
// called through gin with the token's workspace set the way AuthMiddleware
// sets it.
//
// Rows are inserted rather than projected because the Kubernetes and GitHub
// projections that will write them are built in parallel: what this suite
// pins is what the API makes of rows of the contract's shape.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/services"
)

const (
	invAccountHome  = "111122223333"
	invAccountOther = "444455556666"
	invCluster      = "prod-cluster"
	invOrg          = "acme"
)

// invBase is the fixture clock: last_seen_at offsets from it fix the
// -last_seen order.
var invBase = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

type invLab struct {
	t    *testing.T
	db   *gorm.DB
	gate *services.GraphProjectionGate
	ctl  *platform.IGAGraphReadController
	eng  *gin.Engine

	mu       sync.Mutex
	tokenWS  uuid.UUID // the token's workspace for the next request
	lastPerm string    // the permission the last request's route demanded

	home, other *invEstate
}

// invEstate is one workspace's sources and the ids of its fixture rows, by
// the fixture's name for them.
type invEstate struct {
	lab         *invLab
	ws          uuid.UUID
	account     string
	connector   uuid.UUID // AWS: cloud_connector
	scope       uuid.UUID // AWS: the connector's estate scope
	k8sSource   uuid.UUID // Kubernetes: discovery_sources k8s_webhook
	repoScan    uuid.UUID // GitHub repo scanner: discovery_sources repo_scan
	integration uuid.UUID // GitHub IGA provider: iga_integrations
	ids         map[string]uuid.UUID
}

// newInvLab builds both workspaces and their rows. gate nil is the switch on
// and verified.
func newInvLab(t *testing.T, gate *services.GraphProjectionGate) *invLab {
	t.Helper()
	db := igaDB(t)
	if gate == nil {
		gate = services.NewGraphProjectionGate(true, "")
		if err := gate.Verify(db); err != nil {
			t.Fatalf("the integration database must be at 042 for the inventory: %v", err)
		}
	}
	gin.SetMode(gin.TestMode)
	l := &invLab{t: t, db: db, gate: gate,
		ctl: platform.NewIGAGraphReadControllerWith(db, gate, readTestCursorKey)}
	l.home = l.estate("inv-home", invAccountHome, "prod-account")
	l.other = l.estate("inv-other", invAccountOther, "other-account")
	l.tokenWS = l.home.ws
	l.seedHome()
	l.seedOther()

	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		l.mu.Lock()
		ws := l.tokenWS
		l.lastPerm = ""
		l.mu.Unlock()
		if ws != uuid.Nil {
			c.Set("workspace_id", ws.String())
		}
		c.Next()
	})
	platform.RegisterIGAInventoryRoutes(g, l.ctl, func(resource, action string) gin.HandlerFunc {
		perm := resource + ":" + action
		return func(c *gin.Context) {
			l.mu.Lock()
			l.lastPerm = perm
			l.mu.Unlock()
			c.Next()
		}
	})
	l.eng = eng
	return l
}

// estate makes a workspace with one source of every kind.
func (l *invLab) estate(name, account, label string) *invEstate {
	t, db := l.t, l.db
	t.Helper()
	e := &invEstate{lab: l, ws: newWorkspace(t, db, name), account: account, ids: map[string]uuid.UUID{},
		connector: uuid.New(), scope: uuid.New(), k8sSource: uuid.New(), repoScan: uuid.New(), integration: uuid.New()}
	t.Cleanup(func() { e.cleanup() })
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref, attrs)
		  VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault:test', ?::jsonb)`,
			[]any{e.connector, e.ws, account, `{"display_name":"` + label + `"}`}},
		{`INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, display_name, source_key)
		  VALUES (?, ?, 'account', ?, ?)`,
			[]any{e.scope, e.ws, account, igagraph.ScopeKey("aws", "account", account)}},
		{`INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name)
		  VALUES (?, ?, 'k8s_webhook', ?, ?)`, []any{e.k8sSource, e.ws, invCluster, invCluster}},
		{`INSERT INTO discovery_sources (id, workspace_id, kind, display_name)
		  VALUES (?, ?, 'repo_scan', 'acme repositories')`, []any{e.repoScan, e.ws}},
		{`INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, account_native_id, status)
		  VALUES (?, ?, 'github', 'github.com', ?, ?, 'active')`,
			[]any{e.integration, e.ws, "app-" + e.integration.String(), invOrg}},
	} {
		if err := db.Exec(s.sql, s.args...).Error; err != nil {
			t.Fatalf("estate %s: %v", name, err)
		}
	}
	return e
}

func (e *invEstate) cleanup() {
	for _, table := range []string{"iga_object_support", "iga_workload", "iga_identity_accounts", "iga_resources",
		"iga_estate_scopes", "cloud_connector", "discovery_sources", "iga_integrations"} {
		if err := e.lab.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, e.ws).Error; err != nil {
			e.lab.t.Logf("cleanup %s: %v", table, err)
		}
	}
}

// invNode is one fixture row of iga_workload, iga_identity_accounts or
// iga_resources.
type invNode struct {
	table, name, provider, kind, key string
	attrs                            map[string]any
	region                           string // workloads only
	awsScope                         bool   // workloads only: link the connector's estate scope
	retired                          string // retired_reason; "" = active
	seen                             time.Duration
}

// node inserts a row and records its id under its name.
func (e *invEstate) node(n invNode) uuid.UUID {
	t := e.lab.t
	t.Helper()
	id := uuid.New()
	if n.attrs == nil {
		n.attrs = map[string]any{}
	}
	attrs, _ := json.Marshal(n.attrs)
	lifecycle := "active"
	if n.retired != "" {
		lifecycle = "retired"
	}
	seen := invBase.Add(n.seen)
	var err error
	switch n.table {
	case "iga_workload":
		var scope *uuid.UUID
		if n.awsScope {
			scope = &e.scope
		}
		err = e.lab.db.Exec(`INSERT INTO iga_workload (id, workspace_id, estate_scope_id, provider, runtime_kind,
		        display_name, region, lifecycle, retired_reason, source_key, provider_attrs, first_seen_at, last_seen_at)
		    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)`,
			id, e.ws, scope, n.provider, n.kind, n.name, n.region, lifecycle, n.retired, n.key, string(attrs), invBase, seen).Error
	case "iga_identity_accounts":
		err = e.lab.db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, provider, account_kind, display_name,
		        lifecycle, retired_reason, source_key, provider_attrs, first_seen_at, last_seen_at)
		    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)`,
			id, e.ws, n.provider, n.kind, n.name, lifecycle, n.retired, n.key, string(attrs), invBase, seen).Error
	case "iga_resources":
		err = e.lab.db.Exec(`INSERT INTO iga_resources (id, workspace_id, provider, resource_kind, display_name,
		        lifecycle, retired_reason, source_key, provider_attrs, first_seen_at, last_seen_at)
		    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)`,
			id, e.ws, n.provider, n.kind, n.name, lifecycle, n.retired, n.key, string(attrs), invBase, seen).Error
	default:
		t.Fatalf("no table %q", n.table)
	}
	if err != nil {
		t.Fatalf("insert %s %q: %v", n.table, n.name, err)
	}
	e.ids[n.name] = id
	return id
}

// Support sources.
const (
	invByConnector   = "connector"   // AWS
	invByK8s         = "k8s"         // Kubernetes discovery source
	invByRepoScan    = "repo_scan"   // GitHub repo scanner discovery source
	invByIntegration = "integration" // GitHub IGA integration
)

var invSupportColumn = map[string]string{
	"iga_workload": "workload_id", "iga_identity_accounts": "identity_account_id", "iga_resources": "resource_id",
}

// support gives a row one support row from one of the estate's sources, in a
// state. Each call is its own partition, so one row can hold several.
func (e *invEstate) support(table string, node uuid.UUID, by, state string) {
	t := e.lab.t
	t.Helper()
	var connector, source, integration *uuid.UUID
	switch by {
	case invByConnector:
		connector = &e.connector
	case invByK8s:
		source = &e.k8sSource
	case invByRepoScan:
		source = &e.repoScan
	case invByIntegration:
		integration = &e.integration
	default:
		t.Fatalf("no support source %q", by)
	}
	ended := ""
	if state == "ended" {
		ended = "not_observed"
	}
	if err := e.lab.db.Exec(`INSERT INTO iga_object_support (workspace_id, `+invSupportColumn[table]+`,
	        connector_id, discovery_source_id, integration_id, partition_key, state, ended_reason, last_confirmed_at)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ws, node, connector, source, integration, by+":"+uuid.NewString()[:8], state, ended, invBase).Error; err != nil {
		t.Fatalf("support %s %s: %v", table, by, err)
	}
}

// add inserts a row with its support rows, as (source, state) pairs.
func (e *invEstate) add(n invNode, supports ...string) uuid.UUID {
	e.lab.t.Helper()
	id := e.node(n)
	for i := 0; i+1 < len(supports); i += 2 {
		e.support(n.table, id, supports[i], supports[i+1])
	}
	return id
}

func invK8sAttrs(subScope string, extra map[string]any) map[string]any {
	m := map[string]any{"scope_kind": "k8s_cluster", "scope_id": invCluster, "scope_label": invCluster}
	if subScope != "" {
		m["sub_scope"] = subScope
	} else {
		m["sub_scope"] = nil
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func invGitHubAttrs(subScope string, extra map[string]any) map[string]any {
	m := map[string]any{"scope_kind": "github_org", "scope_id": invOrg, "scope_label": invOrg}
	if subScope != "" {
		m["sub_scope"] = subScope
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func invAWSKey(arn string) string { return igagraph.Key("aws", arn) }

func invGitHubKey(parts ...string) string { return igagraph.Key("github", parts...) }

// seedHome is the home workspace. Listed (active):
//
//	workloads   billing-fn (aws, current), checkout (k8s, stale + current =
//	            current), Deploy_100% (github, integration stale = stale),
//	            repo-agent (github repo_scan, native_id stated), stale-mixed
//	            (k8s, stale + ended = stale)
//	identities  acme-installation, billing-role, deploy-key-7,
//	            system:serviceaccount:shop:checkout-sa
//	resources   acme/web, arn:aws:dynamodb:...:table/orders, secrets
//
// Never listed: ended-only (only an ended support row), unsupported (no
// support), the legacy GitHub identity and repository (source_key ”, with a
// current integration support row, so only the legacy rule hides them).
// retired-wl is listed only with lifecycle retired or all.
func (l *invLab) seedHome() {
	e := l.home
	wl := "iga_workload"
	e.add(invNode{table: wl, name: "billing-fn", provider: "aws", kind: "lambda_function", region: "us-east-1", awsScope: true,
		key:   invAWSKey("arn:aws:lambda:us-east-1:" + invAccountHome + ":function:billing-fn"),
		attrs: map[string]any{"package_type": "Zip"}, seen: 1 * time.Hour},
		invByConnector, "current")
	e.add(invNode{table: wl, name: "checkout", provider: "k8s", kind: "k8s_deployment",
		key:   k8sgraph.WorkloadKey(invCluster, "shop", "checkout"),
		attrs: invK8sAttrs("shop", map[string]any{"fingerprint": "fp-checkout"}), seen: 4 * time.Hour},
		invByK8s, "stale", invByK8s, "current")
	e.add(invNode{table: wl, name: "Deploy_100%", provider: "github", kind: "github_actions_workflow",
		key:   invGitHubKey("workflow", "acme/web", "deploy.yml"),
		attrs: invGitHubAttrs("acme/web", map[string]any{"path": ".github/workflows/deploy.yml"}), seen: 2 * time.Hour},
		invByIntegration, "stale")
	e.add(invNode{table: wl, name: "repo-agent", provider: "github", kind: "github_declared_agent",
		key:   invGitHubKey("declared", "acme/web", "agent"),
		attrs: invGitHubAttrs("acme/web", map[string]any{"native_id": "acme/web/AGENTS.md"}), seen: 3 * time.Hour},
		invByRepoScan, "current")
	e.add(invNode{table: wl, name: "stale-mixed", provider: "k8s", kind: "k8s_cronjob",
		key: k8sgraph.WorkloadKey(invCluster, "batch", "stale-mixed"), attrs: invK8sAttrs("batch", nil), seen: 5 * time.Hour},
		invByK8s, "stale", invByK8s, "ended")
	e.add(invNode{table: wl, name: "ended-only", provider: "k8s", kind: "k8s_job",
		key: k8sgraph.WorkloadKey(invCluster, "batch", "ended-only"), attrs: invK8sAttrs("batch", nil), seen: 6 * time.Hour},
		invByK8s, "ended")
	e.add(invNode{table: wl, name: "unsupported", provider: "aws", kind: "lambda_function", region: "us-east-1", awsScope: true,
		key: invAWSKey("arn:aws:lambda:us-east-1:" + invAccountHome + ":function:unsupported"), seen: 7 * time.Hour})
	e.add(invNode{table: wl, name: "retired-wl", provider: "k8s", kind: "k8s_job", retired: "deleted",
		key: k8sgraph.WorkloadKey(invCluster, "batch", "retired-wl"), attrs: invK8sAttrs("batch", nil), seen: 8 * time.Hour},
		invByK8s, "current")

	id := "iga_identity_accounts"
	e.add(invNode{table: id, name: "billing-role", provider: "aws", kind: "iam_role",
		key: invAWSKey("arn:aws:iam::" + invAccountHome + ":role/billing-role"), seen: time.Hour},
		invByConnector, "current")
	e.add(invNode{table: id, name: "system:serviceaccount:shop:checkout-sa", provider: "k8s", kind: "k8s_service_account",
		key: k8sgraph.ServiceAccountKey(invCluster, "shop", "checkout-sa"), attrs: invK8sAttrs("shop", nil), seen: time.Hour},
		invByK8s, "current")
	e.add(invNode{table: id, name: "acme-installation", provider: "github", kind: "github_app_installation",
		key: invGitHubKey("installation", "12345"), attrs: invGitHubAttrs("", nil), seen: time.Hour},
		invByIntegration, "current")
	e.add(invNode{table: id, name: "deploy-key-7", provider: "github", kind: "github_deploy_key",
		key: invGitHubKey("deploy_key", "acme/web", "7"), attrs: invGitHubAttrs("acme/web", nil), seen: time.Hour},
		invByIntegration, "current")
	e.add(invNode{table: id, name: "legacy-gh-identity", provider: "github", kind: "github_app_installation", key: "", seen: time.Hour},
		invByIntegration, "current")

	rs := "iga_resources"
	e.add(invNode{table: rs, name: "arn:aws:dynamodb:us-east-1:" + invAccountHome + ":table/orders", provider: "aws", kind: "exact",
		key:   igagraph.ResourceRefKey("arn:aws:dynamodb:us-east-1:" + invAccountHome + ":table/orders"),
		attrs: map[string]any{"account": invAccountHome, "region": "us-east-1", "account_connected": true}, seen: time.Hour},
		invByConnector, "current")
	e.add(invNode{table: rs, name: "secrets", provider: "k8s", kind: "k8s_resource",
		key: k8sgraph.Key(invCluster, "resource", "secrets"), attrs: invK8sAttrs("", nil), seen: time.Hour},
		invByK8s, "current")
	e.add(invNode{table: rs, name: "acme/web", provider: "github", kind: "github_repository",
		key: invGitHubKey("repo", "acme/web"), attrs: invGitHubAttrs("acme/web", map[string]any{"private": true}), seen: time.Hour},
		invByRepoScan, "current", invByIntegration, "stale")
	e.add(invNode{table: rs, name: "legacy-gh-repo", provider: "github", kind: "github_repository", key: "", seen: time.Hour},
		invByIntegration, "current")
}

// seedOther is the other workspace: rows of every class, one named like the
// home's billing rows and one k8s workload named exactly like a home one, so
// a leak would be visible to a name filter.
func (l *invLab) seedOther() {
	e := l.other
	e.add(invNode{table: "iga_workload", name: "billing-other", provider: "aws", kind: "lambda_function", region: "eu-west-1", awsScope: true,
		key: invAWSKey("arn:aws:lambda:eu-west-1:" + invAccountOther + ":function:billing-other"), seen: time.Hour},
		invByConnector, "current")
	e.add(invNode{table: "iga_workload", name: "checkout", provider: "k8s", kind: "k8s_deployment",
		key: k8sgraph.WorkloadKey(invCluster, "shop", "checkout"), attrs: invK8sAttrs("shop", nil), seen: time.Hour},
		invByK8s, "current")
	e.add(invNode{table: "iga_identity_accounts", name: "billing-other-role", provider: "aws", kind: "iam_role",
		key: invAWSKey("arn:aws:iam::" + invAccountOther + ":role/billing-other-role"), seen: time.Hour},
		invByConnector, "current")
	e.add(invNode{table: "iga_resources", name: "acme/other", provider: "github", kind: "github_repository",
		key: invGitHubKey("repo", "acme/other"), attrs: invGitHubAttrs("acme/other", nil), seen: time.Hour},
		invByRepoScan, "current")
}

// as makes the next requests carry ws in the token.
func (l *invLab) as(ws uuid.UUID) *invLab {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokenWS = ws
	return l
}

// get calls a route of the inventory table (path under /api/iga/v1, with its
// query string) and decodes the body.
func (l *invLab) get(path string) (int, map[string]any) {
	l.t.Helper()
	return invServe(l.t, l.eng, path, "")
}

func invServe(t *testing.T, eng *gin.Engine, path, bearer string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, bytes.NewReader(nil))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("GET %s: status %d, body is not JSON: %q", path, w.Code, w.Body.String())
		}
	}
	return w.Code, out
}

// list calls a route that must answer 200 and returns its rows.
func (l *invLab) list(path string) ([]any, map[string]any) {
	l.t.Helper()
	code, body := l.get(path)
	mustStatus(l.t, path, code, body, http.StatusOK)
	return digl(body, "data"), body
}

// invNames are the rows' names, in order.
func invNames(rows []any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, digs(r, "name"))
	}
	return out
}

// invRow is the row named name, failing when there is not exactly one.
func invRow(t *testing.T, rows []any, name string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, r := range rows {
		if digs(r, "name") == name {
			found = append(found, r.(map[string]any))
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d rows named %q in %v", len(found), name, invNames(rows))
	}
	return found[0]
}

// invFacet maps a facet's chips value -> "label:count".
func invFacet(body map[string]any, name string) map[string]string {
	out := map[string]string{}
	for _, v := range digl(body, "meta", "facets", name) {
		out[digs(v, "value")] = fmt.Sprintf("%s:%d", digs(v, "label"), num(v, "count"))
	}
	return out
}
