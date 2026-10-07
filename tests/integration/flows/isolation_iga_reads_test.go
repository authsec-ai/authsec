//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Cross-tenant isolation for the discovery read models that run through the
// tenant context under row-level security (internal/igaread, internal/k8sread):
// the connections screen and the Kubernetes identity graph.

func Test_Isolation_DiscoveryReads(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	// The plain seed binds a role without permissions; the routes need
	// discovery:read.
	for _, tn := range []*Tenant{a, b} {
		if err := config.DB.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE workspace_id IS NULL
			ON CONFLICT DO NOTHING`, tn.WS.AdminRoleID).Error; err != nil {
			t.Fatalf("grant permissions: %v", err)
		}
	}

	seed := func(tn *Tenant, tag string) (connScope string, saID uuid.UUID) {
		t.Helper()
		connScope = "1111" + strings.ReplaceAll(uuid.NewString()[:8], "-", "") + tag
		if err := config.DB.Exec(`
			INSERT INTO cloud_connector (workspace_id, provider, scope_kind, scope_id, status, auth_ref)
			VALUES (?, 'aws', 'account', ?, 'active', 'arn:aws:iam::'||?||':role/x')`, tn.WS.WorkspaceID, connScope, connScope).Error; err != nil {
			t.Fatalf("seed connector: %v", err)
		}
		saID = uuid.New()
		if err := config.DB.Exec(`
			INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key, provider_attrs)
			VALUES (?, ?, ?, 'k8s_service_account', 'k8s', ?, '{"namespace":"iga-demo"}')`,
			saID, tn.WS.WorkspaceID, "system:serviceaccount:iga-demo:sa-"+tag, "k8s-sa-"+saID.String()).Error; err != nil {
			t.Fatalf("seed k8s identity: %v", err)
		}
		return connScope, saID
	}
	aScope, aSA := seed(a, "a")
	bScope, bSA := seed(b, "b")

	// Another workspace's identity is 404, exactly like an unknown one.
	assertCrossTenant404(t, "GET", "/authsec/discovery/k8s/identities/"+bSA.String()+"/access", nil, a.AdminToken)
	assertCrossTenant404(t, "GET", "/authsec/discovery/k8s/identities/"+uuid.NewString()+"/access", nil, a.AdminToken)
	w := env.Do("GET", "/authsec/discovery/k8s/identities/"+aSA.String()+"/access", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)

	// Lists carry only the caller's workspace.
	w = env.Do("GET", "/authsec/discovery/k8s/identities", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	if body := w.Body.String(); !strings.Contains(body, aSA.String()) || strings.Contains(body, bSA.String()) {
		t.Errorf("k8s identities for A: want A's identity and not B's, got %s", body)
	}
	w = env.Do("GET", "/authsec/discovery/connections", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	if body := w.Body.String(); !strings.Contains(body, aScope) || strings.Contains(body, bScope) {
		t.Errorf("connections for A: want A's connector and not B's, got %s", body)
	}
}
