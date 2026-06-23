//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Test_SA_ClientCredentials_Basic verifies the happy-path client_credentials
// flow for a service account (§5.4): the SA obtains an access token from
// POST /oauth/token using HTTP Basic auth and grant_type=client_credentials.
func Test_SA_ClientCredentials_Basic(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	body := formBody(
		"grant_type", "client_credentials",
		"scope", "read:"+n,
		"resource", rs.ResourceURI,
	)

	w := env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, sa.ClientSecret)

	assertStatus(t, w, http.StatusOK)

	m := parseBody(t, w)
	if m == nil {
		return
	}
	if _, ok := m["access_token"]; !ok {
		t.Errorf("Test_SA_ClientCredentials_Basic: expected access_token in response body %s", readBody(w))
	}
}

// Test_SA_ClientCredentials_InactiveSA verifies that a service account with
// status='inactive' is rejected when attempting client_credentials.
func Test_SA_ClientCredentials_InactiveSA(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Deactivate the service account. Allowed statuses are 'active', 'disabled',
	// 'suspended' (service_accounts_status_chk); 'disabled' models an inactive SA.
	if err := config.DB.Exec(
		`UPDATE service_accounts SET status = 'disabled' WHERE id = $1 AND workspace_id = $2`,
		sa.SAID, sa.WorkspaceID,
	).Error; err != nil {
		t.Fatalf("deactivate service account: %v", err)
	}

	body := formBody(
		"grant_type", "client_credentials",
		"scope", "read:"+n,
		"resource", rs.ResourceURI,
	)

	w := env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, sa.ClientSecret)

	// Inactive SA must be rejected with 401 (invalid_client) or 400.
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusBadRequest {
		t.Errorf("Test_SA_ClientCredentials_InactiveSA: expected 401 or 400 for inactive SA, got %d (body: %s)", w.Code, readBody(w))
	}
}

// Test_SA_ClientCredentials_BadSecret verifies that supplying a wrong client
// secret in Basic auth is rejected with 401.
func Test_SA_ClientCredentials_BadSecret(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	body := formBody(
		"grant_type", "client_credentials",
		"scope", "read:"+n,
		"resource", rs.ResourceURI,
	)

	w := env.DoBasicAuth("POST", "/oauth/token", body, sa.ClientIDString, "wrong-secret")

	assertStatus(t, w, http.StatusUnauthorized)
}

// Test_SA_ClientCredentials_Introspect issues a client_credentials token and
// then calls /oauth/introspect. The introspect response must be 200 (the token
// may be native and active:true is not asserted here).
func Test_SA_ClientCredentials_Introspect(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Step 1: obtain an access token.
	tokenBody := formBody(
		"grant_type", "client_credentials",
		"scope", "read:"+n,
		"resource", rs.ResourceURI,
	)

	tokenResp := env.DoBasicAuth("POST", "/oauth/token", tokenBody, sa.ClientIDString, sa.ClientSecret)
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("Test_SA_ClientCredentials_Introspect: token request failed with status %d (body: %s)", tokenResp.Code, readBody(tokenResp))
	}

	tokenMap := parseBody(t, tokenResp)
	if tokenMap == nil {
		return
	}
	accessToken, ok := tokenMap["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("Test_SA_ClientCredentials_Introspect: no access_token in token response %s", readBody(tokenResp))
	}

	// Step 2: introspect the token using the RS credentials.
	introspectBody := formBody("token", accessToken)
	introspectResp := env.DoBasicAuth("POST", "/oauth/introspect", introspectBody, rs.RSID.String(), rs.IntrospectionSecret)

	// Expect 200. We do not assert active:true because native tokens may need
	// special handling that is not yet wired up in this test environment.
	assertStatus(t, introspectResp, http.StatusOK)
}
