//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-035: a deny policy blocks issuance by default. It used to be audited
// only, because POLICY_ENGINE_MODE defaulted to "off".
func Test_DenyPolicy_BlocksClientCredentialsByDefault(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("rs: %v", err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("sa: %v", err)
	}
	body := formBody("grant_type", "client_credentials", "scope", "read:"+n, "resource", rs.ResourceURI)

	assertStatus(t, env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, sa.ClientSecret), http.StatusOK)

	if err := config.DB.Exec(`INSERT INTO policies (workspace_id, name, client_id, resource_server_id, token_family, effect)
		VALUES (?, 'deny-test', ?, ?, 'm2m', 'deny')`, ws.WorkspaceID, sa.ClientIDString, rs.RSID).Error; err != nil {
		t.Fatalf("insert deny policy: %v", err)
	}
	w := env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, sa.ClientSecret)
	assertStatus(t, w, http.StatusForbidden)

	// Another workspace's deny policy naming the same client has no effect here.
	config.DB.Exec(`DELETE FROM policies WHERE workspace_id = ? AND name = 'deny-test'`, ws.WorkspaceID)
	other, err := SeedWorkspaceWithAdmin(config.DB, n+"x")
	if err != nil {
		t.Fatalf("seed other: %v", err)
	}
	config.DB.Exec(`INSERT INTO policies (workspace_id, name, client_id, token_family, effect)
		VALUES (?, 'foreign-deny', ?, 'm2m', 'deny')`, other.WorkspaceID, sa.ClientIDString)
	assertStatus(t, env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, sa.ClientSecret), http.StatusOK)
}
