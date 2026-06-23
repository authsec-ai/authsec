//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// These tests lock the SDK↔backend contract for the OAuth M2M + XAA journey so
// it cannot silently drift. The TypeScript/Python/Go SDKs read these exact
// fields; an earlier SDK bug checked a nonexistent `xaa_enabled` flag and a
// top-level `recommended_flow`, neither of which the backend ever emitted.

// contains reports whether a JSON array (decoded as []interface{}) holds the
// given string value.
func contains(arr interface{}, want string) bool {
	items, ok := arr.([]interface{})
	if !ok {
		return false
	}
	for _, it := range items {
		if s, ok := it.(string); ok && s == want {
			return true
		}
	}
	return false
}

// Test_Contract_ASMetadata locks the Authorization Server Metadata fields that
// the SDKs use to detect M2M and XAA support.
func Test_Contract_ASMetadata(t *testing.T) {
	env := testsupport.Get(t)

	w := env.Do("GET", "/.well-known/oauth-authorization-server", nil, "")
	assertStatus(t, w, http.StatusOK)

	m := parseBody(t, w)
	if m == nil {
		return
	}

	grantTypes := m["grant_types_supported"]
	for _, want := range []string{
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
	} {
		if !contains(grantTypes, want) {
			t.Errorf("Test_Contract_ASMetadata: grant_types_supported must contain %q, got %v", want, grantTypes)
		}
	}

	idChaining := m["identity_chaining_requested_token_types_supported"]
	if !contains(idChaining, "urn:ietf:params:oauth:token-type:id-jag") {
		t.Errorf("Test_Contract_ASMetadata: identity_chaining_requested_token_types_supported must contain id-jag token type, got %v", idChaining)
	}
}

// Test_Contract_M2M_MintAndIntrospect locks the client_credentials → introspect
// contract: the SA mints a token, and introspecting it yields active=true with
// subject_type=service_account and the granted scope.
func Test_Contract_M2M_MintAndIntrospect(t *testing.T) {
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

	scope := "read:" + n

	tokenBody := formBody(
		"grant_type", "client_credentials",
		"scope", scope,
		"resource", rs.ResourceURI,
	)
	tokenResp := env.DoBasicAuth("POST", "/oauth/token", tokenBody, sa.ClientIDString, sa.ClientSecret)
	assertStatus(t, tokenResp, http.StatusOK)

	tokenMap := parseBody(t, tokenResp)
	if tokenMap == nil {
		return
	}
	accessToken, ok := tokenMap["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("Test_Contract_M2M_MintAndIntrospect: no access_token in token response %s", readBody(tokenResp))
	}

	// Introspection is authenticated with the RESOURCE SERVER's introspection
	// credentials (RFC 7662 protected resource), matching oauth_introspect_flow_test.go.
	introspectBody := formBody("token", accessToken)
	introspectResp := env.DoBasicAuth("POST", "/oauth/introspect", introspectBody, rs.RSID.String(), rs.IntrospectionSecret)
	assertStatus(t, introspectResp, http.StatusOK)

	im := parseBody(t, introspectResp)
	if im == nil {
		return
	}
	if active, _ := im["active"].(bool); !active {
		t.Errorf("Test_Contract_M2M_MintAndIntrospect: expected active=true, got body %s", readBody(introspectResp))
	}
	if st, _ := im["subject_type"].(string); st != "service_account" {
		t.Errorf("Test_Contract_M2M_MintAndIntrospect: expected subject_type=service_account, got %q (body %s)", st, readBody(introspectResp))
	}
	if returnedScope, _ := im["scope"].(string); !splitScopes(returnedScope)[scope] {
		t.Errorf("Test_Contract_M2M_MintAndIntrospect: expected scope to contain %q, got %q", scope, returnedScope)
	}
}

// Test_Contract_TokenExchange_IDJAG locks the RFC 8693 token-exchange → ID-JAG
// contract: an access_token is returned and issued_token_type (when present) is
// the id-jag token type.
func Test_Contract_TokenExchange_IDJAG(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	wsA, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	rsA, err := AddResourceServer(config.DB, wsA, "https://rsa-ct-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, wsA, rsA, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// The subject_token is the wsA admin's JWT; the issuance path classifies it as
	// non-native and verifies it via the Hydra admin introspect fake (same pattern
	// as xaa_id_jag_exchange_flow_test.go's issueIDJAG helper).
	adminToken := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active":    true,
			"sub":       wsA.AdminUserID.String(),
			"client_id": saA.ClientIDString,
			// Hydra nests custom session claims under "ext" (real introspection
			// shape); the token-exchange path reads workspace_id from there.
			"ext": map[string]interface{}{
				"workspace_id": wsA.WorkspaceID.String(),
			},
		}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	form := formBody(
		"grant_type", tokenExchangeGrantType,
		"requested_token_type", idJAGTokenType,
		"subject_token", adminToken,
		"subject_token_type", accessTokenType,
	)
	w := env.DoBasicAuth(http.MethodPost, "/oauth/token", form, saA.ClientIDString, saA.ClientSecret)
	assertStatus(t, w, http.StatusOK)

	m := parseBody(t, w)
	if m == nil {
		return
	}
	if at, _ := m["access_token"].(string); at == "" {
		t.Errorf("Test_Contract_TokenExchange_IDJAG: expected access_token (the ID-JAG) in response, got %s", readBody(w))
	}
	// issued_token_type is optional in the response, but if present it must lock
	// to the id-jag token type (RFC 8693 §2.2.1).
	if itt, ok := m["issued_token_type"].(string); ok {
		if itt != idJAGTokenType {
			t.Errorf("Test_Contract_TokenExchange_IDJAG: expected issued_token_type=%q, got %q", idJAGTokenType, itt)
		}
	} else {
		t.Logf("Test_Contract_TokenExchange_IDJAG: issued_token_type absent from response (not asserted): %s", readBody(w))
	}
}

// Test_Contract_RequesterBootstrap_Shape locks the requester-bootstrap response
// shape the SDKs parse: a top-level targets[] array (NOT a top-level
// recommended_flow), where each target carries resource, recommended_flow, and
// relationship.
func Test_Contract_RequesterBootstrap_Shape(t *testing.T) {
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

	body := formBody("resource", rs.ResourceURI)
	w := env.DoBasicAuth("POST", "/oauth/requester-bootstrap", body, sa.ClientIDString, sa.ClientSecret)
	assertStatus(t, w, http.StatusOK)

	m := parseBody(t, w)
	if m == nil {
		return
	}

	// The old SDK bug read a top-level recommended_flow that never existed.
	if _, bad := m["recommended_flow"]; bad {
		t.Errorf("Test_Contract_RequesterBootstrap_Shape: response must NOT have a top-level recommended_flow; it lives inside each target")
	}

	targets, ok := m["targets"].([]interface{})
	if !ok {
		t.Fatalf("Test_Contract_RequesterBootstrap_Shape: expected top-level targets[] array, got %s", readBody(w))
	}
	if len(targets) == 0 {
		t.Fatalf("Test_Contract_RequesterBootstrap_Shape: expected at least one target for the seeded RS, got empty targets (body %s)", readBody(w))
	}

	// At least one target must carry the contract keys the SDKs parse.
	var found bool
	for _, raw := range targets {
		tgt, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		_, hasResource := tgt["resource"]
		_, hasFlow := tgt["recommended_flow"]
		_, hasRel := tgt["relationship"]
		if hasResource && hasFlow && hasRel {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Test_Contract_RequesterBootstrap_Shape: expected a target with keys resource+recommended_flow+relationship, got %s", readBody(w))
	}
}
