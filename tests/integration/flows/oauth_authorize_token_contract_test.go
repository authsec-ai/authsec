//go:build integration && contract

package flows

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/internal/testsupport/fakes"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// seedAuthCodeClient inserts a minimal mcp_oauth_clients row for the
// authorization_code grant type and returns the row UUID, public client_id,
// and hydra_client_id.
func seedAuthCodeClient(t *testing.T, db *gorm.DB, wsID uuid.UUID, nonce string) (uuid.UUID, string, string) {
	t.Helper()
	clientUUID := uuid.New()
	clientID := "authcode-" + nonce
	hydraClientID := "hydra-authcode-" + nonce
	if err := db.Exec(`
		INSERT INTO mcp_oauth_clients (
			id, client_id, hydra_client_id, client_name,
			grant_types, response_types, redirect_uris,
			token_endpoint_auth_method, is_confidential,
			allowed_token_endpoint_auth_methods,
			client_kind, home_workspace_id,
			registration_type, sync_status,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			ARRAY['authorization_code'], ARRAY['code'], ARRAY['http://localhost/callback'],
			'none', false,
			ARRAY['none'],
			'human_app', $5,
			'dcr', 'active',
			NOW(), NOW()
		)`,
		clientUUID, clientID, hydraClientID, "Test AuthCode Client "+nonce, wsID,
	).Error; err != nil {
		t.Fatalf("seedAuthCodeClient: %v", err)
	}
	return clientUUID, clientID, hydraClientID
}

// seedRSClientReg inserts an approved resource_server_client_registrations row.
func seedRSClientReg(t *testing.T, db *gorm.DB, rsID, clientUUID, wsID uuid.UUID) {
	t.Helper()
	if err := db.Exec(`
		INSERT INTO resource_server_client_registrations (
			id, resource_server_id, oauth_client_id, workspace_id,
			status, registration_type, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 'approved', 'dcr', NOW(), NOW())
		ON CONFLICT (resource_server_id, oauth_client_id) DO NOTHING`,
		uuid.New(), rsID, clientUUID, wsID,
	).Error; err != nil {
		t.Fatalf("seedRSClientReg: %v", err)
	}
}

// seedARC inserts an auth_request_contexts row with consent_completed=true and
// consumed=false, expires 10 minutes from now. Returns the state (PK) value.
func seedARC(t *testing.T, db *gorm.DB, contextID uuid.UUID, hydraClientID string, rsID, wsID uuid.UUID, resourceURI, redirectURI string) string {
	t.Helper()
	state := uuid.New().String()
	if err := db.Exec(`
		INSERT INTO auth_request_contexts (
			state, context_id, hydra_client_id,
			resource_server_id, workspace_id, resource_uri, redirect_uri,
			consent_completed, consumed, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, true, false, $8, NOW())`,
		state, contextID.String(), hydraClientID,
		rsID, wsID, resourceURI, redirectURI,
		time.Now().Add(10*time.Minute),
	).Error; err != nil {
		t.Fatalf("seedARC: %v", err)
	}
	return state
}

// seedScopeBridge wires a permissions → role_permissions → oauth_scope_permissions
// chain so that the given role can resolve scopeID through the RBAC resolver.
func seedScopeBridge(t *testing.T, db *gorm.DB, wsID, roleID, scopeID uuid.UUID, nonce string) {
	t.Helper()
	permID := uuid.New()
	if err := db.Exec(`
		INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES ($1, $2, 'read', $3, $4, NOW(), NOW())`,
		permID, "read-"+nonce, fmt.Sprintf("read-%s:read", nonce), wsID,
	).Error; err != nil {
		t.Fatalf("seedScopeBridge permissions: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		roleID, permID,
	).Error; err != nil {
		t.Fatalf("seedScopeBridge role_permissions: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		scopeID, permID,
	).Error; err != nil {
		t.Fatalf("seedScopeBridge oauth_scope_permissions: %v", err)
	}
}

// Test_OAuth_AuthCodeToken_HydraError verifies that a non-200 from Hydra's token
// endpoint is forwarded directly to the caller without modification.
func Test_OAuth_AuthCodeToken_HydraError(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	// Seed a minimal OAuth client — no RS or ARC required because the Hydra
	// rejection happens before any DB lookup beyond the client itself.
	_, clientID, _ := seedAuthCodeClient(t, config.DB, uuid.New(), n)

	env.Fakes.Hydra.OnToken(func(_ *http.Request) (int, map[string]interface{}) {
		return http.StatusBadRequest, map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "authorization code not found or already used",
		}
	})
	defer env.Fakes.Hydra.ResetToken()

	resp := env.Do("POST", "/oauth/token", formBody(
		"grant_type", "authorization_code",
		"client_id", clientID,
		"code", "stale-code",
	), "")

	if resp.Code != http.StatusBadRequest {
		t.Errorf("expected 400 from forwarded Hydra error, got %d: %s", resp.Code, resp.Body.String())
	}
	r := parseResp(resp)
	if r.Body["error"] != "invalid_grant" {
		t.Errorf("expected error=invalid_grant forwarded from Hydra, got body=%v", r.Body)
	}
}

// Test_OAuth_AuthCodeToken_RedirectURIMismatch verifies that a redirect_uri in
// the token request that doesn't match the stored auth context is rejected with
// 400 invalid_grant before any RBAC or RS checks run.
func Test_OAuth_AuthCodeToken_RedirectURIMismatch(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	contextID := uuid.New()
	storedRedirectURI := fmt.Sprintf("http://stored-%s.example.com/callback", n)

	// Seed OAuth client.
	_, clientID, hydraClientID := seedAuthCodeClient(t, config.DB, uuid.New(), n)

	// Seed ARC with a redirect_uri. Dummy RS/workspace UUIDs are fine here
	// because the redirect_uri check (step 5) fires before the RS lookup (step 6).
	seedARC(t, config.DB, contextID, hydraClientID,
		uuid.New(), uuid.New(),
		"http://dummy-rs-"+n+".example.com/mcp",
		storedRedirectURI,
	)

	tok := fakes.MakeFakeJWT(contextID.String(), "dummy-user", "read:x")
	env.Fakes.Hydra.OnToken(func(_ *http.Request) (int, map[string]interface{}) {
		return http.StatusOK, map[string]interface{}{
			"access_token": tok,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read:x",
		}
	})
	defer env.Fakes.Hydra.ResetToken()

	resp := env.Do("POST", "/oauth/token", formBody(
		"grant_type", "authorization_code",
		"client_id", clientID,
		"code", "some-code",
		"redirect_uri", "http://different.example.com/callback",
	), "")

	if resp.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for redirect_uri mismatch, got %d: %s", resp.Code, resp.Body.String())
	}
	r := parseResp(resp)
	if r.Body["error"] != "invalid_grant" {
		t.Errorf("expected error=invalid_grant, got body=%v", r.Body)
	}
}

// Test_OAuth_AuthCodeToken_Happy exercises the full authorization_code→token
// happy path: pre-seeded ARC (consent_completed=true), approved client
// registration, working RBAC scope bridge, fake Hydra returning a JWT with
// context_id embedded. Expects 200 with access_token forwarded from Hydra.
func Test_OAuth_AuthCodeToken_Happy(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	// 1. Workspace + admin user + admin role + role binding.
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	// 2. Resource server with one scope.
	rs, err := AddResourceServer(config.DB, ws, "http://fake-rs-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	scopeString := "read:" + n
	if len(rs.ScopeIDs) == 0 {
		t.Fatal("AddResourceServer returned no scope IDs")
	}

	// 3. authorization_code OAuth client.
	clientUUID, clientID, hydraClientID := seedAuthCodeClient(t, config.DB, ws.WorkspaceID, n)

	// 4. Approved client registration for this RS.
	seedRSClientReg(t, config.DB, rs.RSID, clientUUID, ws.WorkspaceID)

	// 5. RBAC scope bridge: admin role → permission → oauth_scope for read:<n>.
	seedScopeBridge(t, config.DB, ws.WorkspaceID, ws.AdminRoleID, rs.ScopeIDs[0], n)

	// 6. Pre-seed ARC with consent_completed=true, no redirect_uri (skips redirect_uri check).
	contextID := uuid.New()
	seedARC(t, config.DB, contextID, hydraClientID, rs.RSID, ws.WorkspaceID, rs.ResourceURI, "")

	// 7. Wire fake Hydra: token endpoint returns JWT with context_id, introspect
	// confirms active + sub + scope for the RBAC pass.
	adminUserIDStr := ws.AdminUserID.String()
	fakeTok := fakes.MakeFakeJWT(contextID.String(), adminUserIDStr, scopeString)

	env.Fakes.Hydra.OnToken(func(_ *http.Request) (int, map[string]interface{}) {
		return http.StatusOK, map[string]interface{}{
			"access_token": fakeTok,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        scopeString,
		}
	})
	defer env.Fakes.Hydra.ResetToken()

	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active": true,
			"sub":    adminUserIDStr,
			"scope":  scopeString,
		}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	// 8. Exchange the code — resource defaults from ARC when omitted.
	resp := env.Do("POST", "/oauth/token", formBody(
		"grant_type", "authorization_code",
		"client_id", clientID,
		"code", "fake-code",
	), "")

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	r := parseResp(resp)
	if r.Body["access_token"] == nil {
		t.Errorf("expected access_token in response, got body=%v", r.Body)
	}
	if r.Body["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got body=%v", r.Body)
	}
}
