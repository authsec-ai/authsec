//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// tokenExchangeGrantType is the RFC 8693 grant type used to issue ID-JAG tokens.
const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// jwtBearerGrantType is the grant type used to redeem an ID-JAG token.
const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// idJAGTokenType is the requested_token_type value for ID-JAG issuance.
const idJAGTokenType = "urn:ietf:params:oauth:token-type:id-jag"

// accessTokenType is the subject_token_type for an opaque/JWT access token.
const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

// issueIDJAG exchanges the given subject token for an ID-JAG using the SA's
// Basic credentials. Returns the ID-JAG string on success.
func issueIDJAG(t *testing.T, env *testsupport.Env, subjectToken, saClientID, saSecret string) string {
	t.Helper()
	form := formBody(
		"grant_type", tokenExchangeGrantType,
		"requested_token_type", idJAGTokenType,
		"subject_token", subjectToken,
		"subject_token_type", accessTokenType,
	)
	w := env.DoBasicAuth(http.MethodPost, "/oauth/token", form, saClientID, saSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("issueIDJAG: expected 200, got %d: %s", w.Code, readBody(w))
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("issueIDJAG: decode body: %v", err)
	}
	idJAG, _ := resp["access_token"].(string)
	if idJAG == "" {
		t.Fatalf("issueIDJAG: access_token missing from response: %v", resp)
	}
	return idJAG
}

// Test_XAA_IssueRedeemAccessAppB exercises the full XAA ID-JAG roundtrip:
// issue an ID-JAG from workspace A → redeem it against workspace B's RS.
//
// Flow:
//  1. wsA SA issues ID-JAG (Hydra introspect confirms wsA admin as subject).
//  2. Same wsA SA redeems the ID-JAG against wsB RS.
//  3. Expect 200 with access_token (user pre-mapped via oidc_user_identities).
func Test_XAA_IssueRedeemAccessAppB(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	// Seed workspace A + SA.
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin(A): %v", err)
	}
	rsA, err := AddResourceServer(config.DB, wsA, "https://rsa-xaa-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer(A): %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, wsA, rsA, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Wire workspace B + cross-workspace approval.
	xaa, err := AddXAARelationship(config.DB, wsA, saA, rsA, n)
	if err != nil {
		t.Fatalf("AddXAARelationship: %v", err)
	}

	// The subject_token is the wsA admin's JWT (HS256). The issuance path
	// classifies it as non-native and verifies it via Hydra admin introspect.
	// Wire the fake to confirm the token is active with the SA's client_id.
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

	// Step 1: issue ID-JAG.
	idJAG := issueIDJAG(t, env, adminToken, saA.ClientIDString, saA.ClientSecret)

	// Step 2: redeem ID-JAG against wsB RS.
	redeemForm := formBody(
		"grant_type", jwtBearerGrantType,
		"assertion", idJAG,
		"resource", xaa.RSB.ResourceURI,
		"scope", xaa.RSB.ScopeStrings[0],
	)
	redeemResp := env.DoBasicAuth(http.MethodPost, "/oauth/token", redeemForm, saA.ClientIDString, saA.ClientSecret)
	if redeemResp.Code != http.StatusOK {
		t.Fatalf("XAA redeem: expected 200, got %d: %s", redeemResp.Code, readBody(redeemResp))
	}
	var redeemBody map[string]interface{}
	if err := json.NewDecoder(redeemResp.Body).Decode(&redeemBody); err != nil {
		t.Fatalf("XAA redeem: decode body: %v", err)
	}
	if redeemBody["access_token"] == nil || redeemBody["access_token"] == "" {
		t.Errorf("XAA redeem: expected access_token in response, got body=%v", redeemBody)
	}
}

// Test_XAA_SameWorkspaceAllowed verifies the conformant XAA boundary (ID-JAG
// draft §4.1/§7.3): the trust boundary is the resource server, NOT the
// workspace. An agent redeeming an ID-JAG against a DISTINCT MCP server in its
// OWN workspace is valid cross-app delegation (the canonical single-org Okta
// case) and must mint an access token — no same_workspace_use_direct rejection.
func Test_XAA_SameWorkspaceAllowed(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	wsA, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	rsA, err := AddResourceServer(config.DB, wsA, "https://rsa-swa-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, wsA, rsA, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Bridge the wsA admin role → rsA scope so the resolved subject has scopes
	// on rsA (mirrors AddXAARelationship's permission bridge, but same-workspace).
	permID := uuid.New()
	if err := config.DB.Exec(`
		INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES ($1, $2, 'read', $3, $4, NOW(), NOW())`,
		permID, "swa-"+n, "swa-"+n+":read", wsA.WorkspaceID,
	).Error; err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if err := config.DB.Exec(`
		INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		wsA.AdminRoleID, permID,
	).Error; err != nil {
		t.Fatalf("insert role_permission: %v", err)
	}
	if len(rsA.ScopeIDs) > 0 {
		if err := config.DB.Exec(`
			INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			rsA.ScopeIDs[0], permID,
		).Error; err != nil {
			t.Fatalf("insert oauth_scope_permission: %v", err)
		}
	}

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

	// Issue ID-JAG with issuance_workspace = wsA.
	idJAG := issueIDJAG(t, env, adminToken, saA.ClientIDString, saA.ClientSecret)

	// Redeem against wsA RS — same workspace, distinct RS: now ALLOWED.
	redeemForm := formBody(
		"grant_type", jwtBearerGrantType,
		"assertion", idJAG,
		"resource", rsA.ResourceURI,
		"scope", rsA.ScopeStrings[0],
	)
	redeemResp := env.DoBasicAuth(http.MethodPost, "/oauth/token", redeemForm, saA.ClientIDString, saA.ClientSecret)
	if redeemResp.Code != http.StatusOK {
		t.Fatalf("same-workspace XAA: expected 200, got %d: %s", redeemResp.Code, readBody(redeemResp))
	}
	var redeemBody map[string]interface{}
	if err := json.NewDecoder(redeemResp.Body).Decode(&redeemBody); err != nil {
		t.Fatalf("same-workspace XAA: decode body: %v", err)
	}
	if redeemBody["access_token"] == nil || redeemBody["access_token"] == "" {
		t.Errorf("same-workspace XAA: expected access_token, got body=%v", redeemBody)
	}
}

// Test_XAA_SelfDelegationRejected verifies the one remaining hard guard: a
// resource server's OWN client cannot redeem an ID-JAG to reach itself (no
// delegation actually occurs). Expect 400 invalid_grant / self_delegation.
func Test_XAA_SelfDelegationRejected(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	wsA, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	rsA, err := AddResourceServer(config.DB, wsA, "https://rsa-self-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, wsA, rsA, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Make the SA's client the RS's OWN client → self-delegation.
	if err := config.DB.Exec(
		`UPDATE resource_servers SET legacy_client_id = $1 WHERE id = $2`,
		saA.ClientID, rsA.RSID,
	).Error; err != nil {
		t.Fatalf("set legacy_client_id: %v", err)
	}

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

	idJAG := issueIDJAG(t, env, adminToken, saA.ClientIDString, saA.ClientSecret)

	redeemForm := formBody(
		"grant_type", jwtBearerGrantType,
		"assertion", idJAG,
		"resource", rsA.ResourceURI,
	)
	redeemResp := env.DoBasicAuth(http.MethodPost, "/oauth/token", redeemForm, saA.ClientIDString, saA.ClientSecret)
	if redeemResp.Code != http.StatusBadRequest {
		t.Fatalf("self-delegation: expected 400, got %d: %s", redeemResp.Code, readBody(redeemResp))
	}
	r := parseResp(redeemResp)
	if r.Body["error"] != "invalid_grant" {
		t.Errorf("self-delegation: expected error=invalid_grant, got body=%v", r.Body)
	}
}

// Test_XAA_FlagOff_IssuanceBlocked documents that flag-off tests live in flagsoff/.
func Test_XAA_FlagOff_IssuanceBlocked(t *testing.T) {
	t.Log("flag-off issuance rejection is covered by tests/integration/flagsoff/ — skipping in flows binary (XAA flags are ON here)")
}
