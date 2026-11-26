//go:build integration

package flows

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Cross-tenant isolation for the Azure discovery routes
// (/authsec/discovery/azure/*): workspace A's admin never reads, verifies,
// rescans or revokes workspace B's Azure connections, and never sees B's
// identities, resources, grants, secrets, workloads or graph nodes. Each check
// has a positive control -- B sees its own rows -- so a route that returns
// nothing to anyone cannot pass by accident.

type azureSeed struct {
	tenant, sub     uuid.UUID // connector ids
	tenantID, subID string    // Entra tenant id, subscription id
	objectID        string    // a service principal's Entra object id
	identity        uuid.UUID // cloud_identity id
	graphNode       uuid.UUID // iga_identity_accounts id
	marker          string    // appears in every name of this workspace's rows
}

func seedAzure(t *testing.T, tn *Tenant, tag string) azureSeed {
	t.Helper()
	s := azureSeed{tenant: uuid.New(), sub: uuid.New(), tenantID: uuid.NewString(), subID: uuid.NewString(),
		objectID: uuid.NewString(), identity: uuid.New(), graphNode: uuid.New(), marker: "azmark" + tag + uuid.NewString()[:6]}
	ws := tn.WS.WorkspaceID
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if err := config.DB.Exec(q, args...).Error; err != nil {
			t.Fatalf("seed azure %s: %v\n%s", tag, err, q)
		}
	}
	exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
		VALUES (?, ?, 'azure', 'tenant', ?, 'active', 'vault://azure/test')`, s.tenant, ws, s.tenantID)
	exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref)
		VALUES (?, ?, 'azure', 'subscription', ?, ?, 'active', 'vault://azure/test')`, s.sub, ws, s.subID, s.tenantID)
	exec(`INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name)
		VALUES (?, ?, ?, 'service_principal', ?, ?)`, s.identity, ws, s.tenant, s.objectID, "sp-"+s.marker)
	res := uuid.New()
	exec(`INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name)
		VALUES (?, ?, ?, 'storage_account', ?, ?)`, res, ws, s.sub,
		"/subscriptions/"+s.subID+"/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"+tag, "st-"+s.marker)
	exec(`INSERT INTO cloud_permission (workspace_id, connector_id, identity_id, resource_id, effect, actions, scope_kind, native_id, plane, role_name)
		VALUES (?, ?, ?, ?, 'allow', ARRAY['Microsoft.Storage/storageAccounts/read'], 'resource', ?, 'cloud', ?)`,
		ws, s.sub, s.identity, res, "ra-"+s.marker, "Reader "+s.marker)
	exec(`INSERT INTO cloud_secret (workspace_id, connector_id, identity_id, kind, native_id, status)
		VALUES (?, ?, ?, 'client_secret', ?, 'active')`, ws, s.tenant, s.identity, "sec-"+s.marker)
	exec(`INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name)
		VALUES (?, ?, ?, 'function_app', ?, ?)`, ws, s.sub, s.identity,
		"/subscriptions/"+s.subID+"/resourceGroups/rg/providers/Microsoft.Web/sites/fn"+tag, "fn-"+s.marker)
	exec(`INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key, provider_attrs)
		VALUES (?, ?, ?, 'service_principal', 'azure', ?, '{}')`, s.graphNode, ws, "sp-"+s.marker, "azure-sp-"+s.objectID)
	return s
}

func Test_Isolation_AzureDiscovery(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	for _, tn := range []*Tenant{a, b} {
		if err := config.DB.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE workspace_id IS NULL
			ON CONFLICT DO NOTHING`, tn.WS.AdminRoleID).Error; err != nil {
			t.Fatalf("grant permissions: %v", err)
		}
	}
	sa := seedAzure(t, a, "a")
	sb := seedAzure(t, b, "b")
	const base = "/authsec/discovery/azure"

	// Another workspace's connection is 404 on every :id route, and B's
	// connection is untouched by A's revoke.
	for _, c := range []struct{ method, path string }{
		{"GET", "/connectors/" + sb.tenant.String()},
		{"GET", "/connectors/" + sb.sub.String()},
		{"GET", "/connectors/" + sb.tenant.String() + "/scan-runs"},
		{"POST", "/connectors/" + sb.sub.String() + "/verify"},
		{"DELETE", "/connectors/" + sb.sub.String()},
	} {
		assertCrossTenant404(t, c.method, base+c.path, nil, a.AdminToken)
	}
	var status string
	if err := config.DB.Raw(`SELECT status FROM cloud_connector WHERE id = ?`, sb.sub).Scan(&status).Error; err != nil || status != "active" {
		t.Fatalf("B's connector after A's revoke: %q %v", status, err)
	}
	// Positive control: B reads its own connection.
	assertStatus(t, env.Do("GET", base+"/connectors/"+sb.tenant.String(), nil, b.AdminToken), http.StatusOK)

	// Lists: A never sees B's rows; B sees its own (the control).
	lists := []string{"/connectors", "/identities", "/resources", "/grants", "/secrets", "/workloads",
		"/federation", "/foundry", "/usage", "/graph/summary"}
	for _, l := range lists {
		w := env.Do("GET", base+l, nil, a.AdminToken)
		if w.Code >= 500 {
			t.Errorf("A GET %s: %d %s", l, w.Code, w.Body.String())
		}
		body := w.Body.String()
		if strings.Contains(body, sb.marker) || strings.Contains(body, sb.tenantID) || strings.Contains(body, sb.subID) {
			t.Errorf("A GET %s shows workspace B's data: %s", l, body)
		}
	}
	for _, l := range []string{"/connectors", "/identities", "/resources", "/grants", "/secrets", "/workloads"} {
		w := env.Do("GET", base+l, nil, b.AdminToken)
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		if !strings.Contains(body, sb.marker) && !strings.Contains(body, sb.tenantID) {
			t.Errorf("control: B GET %s does not show B's own rows: %s", l, body)
		}
	}

	// Filters naming B's ids return nothing for A.
	for _, q := range []string{
		"/grants?identity_id=" + sb.identity.String(),
		"/identities?connector_id=" + sb.tenant.String(),
		"/resources?connector_id=" + sb.sub.String(),
	} {
		w := env.Do("GET", base+q, nil, a.AdminToken)
		if strings.Contains(w.Body.String(), sb.marker) {
			t.Errorf("A GET %s shows B's rows: %s", q, w.Body.String())
		}
	}

	// Graph: B's node is not found from A; B's Entra object yields nothing.
	w := env.Do("GET", base+"/graph/neighbourhood?ref=identity:"+sb.graphNode.String(), nil, a.AdminToken)
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), sb.marker) {
		t.Errorf("A neighbourhood of B's node: %d %s", w.Code, w.Body.String())
	}
	for _, q := range []string{"/graph/blast-radius?object_id=" + sb.objectID, "/evidence?object_id=" + sb.objectID} {
		w := env.Do("GET", base+q, nil, a.AdminToken)
		if w.Code >= 500 || strings.Contains(w.Body.String(), sb.marker) {
			t.Errorf("A GET %s: %d %s", q, w.Code, w.Body.String())
		}
	}
	_ = sa
}

// The Azure graph projection runs under row-level security for one
// workspace (tenancy.InWorkspace, as projectGraph runs it): the restricted
// role can do everything a pass does, the pass writes only its own
// workspace's graph, and it never reads another workspace's cloud_* rows.
func Test_AzureProjectionUnderRLS(t *testing.T) {
	a, b := TwoTenants(t)
	_ = testsupport.Get(t)
	sa := seedAzure(t, a, "pa")
	sb := seedAzure(t, b, "pb")
	ws := a.WS.WorkspaceID
	// Generation 1: the connectors' current pass, and what it confirmed.
	for _, q := range []string{
		`UPDATE cloud_connector SET scan_generation = 1 WHERE workspace_id = ?`,
		`UPDATE cloud_identity SET last_seen_generation = 1 WHERE workspace_id = ?`,
		`UPDATE cloud_resource SET last_seen_generation = 1 WHERE workspace_id = ?`,
		`UPDATE cloud_permission SET last_seen_generation = 1 WHERE workspace_id = ?`,
		`UPDATE cloud_secret SET last_seen_generation = 1 WHERE workspace_id = ?`,
		`UPDATE cloud_workload SET last_seen_generation = 1 WHERE workspace_id = ?`,
	} {
		if err := config.DB.Exec(q, ws).Error; err != nil {
			t.Fatalf("generation: %v", err)
		}
	}
	runs := map[uuid.UUID]uuid.UUID{}
	for _, c := range []uuid.UUID{sa.tenant, sa.sub} {
		runs[c] = uuid.New()
		if err := config.DB.Exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
			VALUES (?, ?, ?, 1, 'published', now())`, runs[c], ws, c).Error; err != nil {
			t.Fatalf("scan run: %v", err)
		}
	}
	runOf := func(conn uuid.UUID) uuid.UUID { return runs[conn] }
	passes := []azuregraph.Pass{
		{WorkspaceID: ws, ConnectorID: sa.tenant, ScopeKind: models.CloudScopeTenant, ScopeID: sa.tenantID, TenantID: sa.tenantID, RunID: runOf(sa.tenant), Generation: 1},
		{WorkspaceID: ws, ConnectorID: sa.sub, ScopeKind: models.CloudScopeSubscription, ScopeID: sa.subID, TenantID: sa.tenantID, RunID: runOf(sa.sub), Generation: 1},
	}
	for _, p := range passes {
		var res *azuregraph.Result
		err := tenancy.InWorkspace(context.Background(), config.DB, ws, func(tx *gorm.DB) error {
			r, err := azuregraph.ProjectPass(tx, p, time.Now())
			res = r
			return err
		})
		if err != nil {
			t.Fatalf("project %s pass under RLS: %v", p.ScopeKind, err)
		}
		t.Logf("%s pass: %+v", p.ScopeKind, *res)
	}
	var n int64
	config.DB.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'azure' AND display_name LIKE ?`,
		ws, "%"+sa.marker+"%").Scan(&n)
	if n == 0 {
		t.Error("the tenant pass projected no Azure identity")
	}
	config.DB.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND display_name LIKE ?`,
		ws, "%"+sb.marker+"%").Scan(&n)
	if n != 0 {
		t.Errorf("workspace A's pass projected %d of workspace B's identities", n)
	}
	config.DB.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id <> ? AND workspace_id <> ? AND display_name LIKE ?`,
		ws, b.WS.WorkspaceID, "%"+sa.marker+"%").Scan(&n)
	if n != 0 {
		t.Errorf("A's identities written into %d rows of another workspace", n)
	}
}
