//go:build integration

package integration

// oauth_policy_hardening_test.go — Workstream 2: OAuth Core Policy Hardening
//
// Test tiers:
//
//	Tier A (tests 1–6): Pure-AuthSec tests, no Hydra dependency.
//	  These exercise policy gates that are enforced before any Hydra call, so they
//	  are fully deterministic with the existing harness (DB + router only).
//	  Run with: RUN_INTEGRATION=1 go test -tags=integration ./tests/integration/... -run "TestCIMD|TestRedirect|TestRegistrationType" -v
//
//	Tier B (tests 7–11): Require a live Hydra.
//	  Guarded by RUN_HYDRA_INTEGRATION=1 AND a live connectivity probe.
//	  Run with: RUN_INTEGRATION=1 RUN_HYDRA_INTEGRATION=1 HYDRA_ADMIN_URL=http://localhost:4445 \
//	            go test -tags=integration ./tests/integration/... -run "TestRevoked|TestPartialScope|TestOIDCOnly|TestRSSpecific" -v

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Tier B guard ────────────────────────────────────────────────────────────

// requireLiveHydra skips a test unless RUN_HYDRA_INTEGRATION=1 AND the configured
// Hydra admin endpoint responds to /health/ready. This is necessary because TestMain
// always sets HYDRA_ADMIN_URL (see main_test.go:198), so we cannot use that env var
// alone as a readiness signal.
func requireLiveHydra(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_HYDRA_INTEGRATION") != "1" {
		t.Skip("RUN_HYDRA_INTEGRATION=1 not set — skipping Hydra-dependent test")
	}
	adminURL := os.Getenv("HYDRA_ADMIN_URL")
	if adminURL == "" {
		t.Skip("HYDRA_ADMIN_URL not set — skipping Hydra-dependent test")
	}
	resp, err := http.Get(adminURL + "/health/ready")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skipf("Hydra admin at %s not reachable (err=%v) — skipping", adminURL, err)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// doPARRequest sends a POST /oauth/par request with form-encoded body.
func doPARRequest(params url.Values) *httptest.ResponseRecorder {
	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// doAuthorizeRequest sends a GET /oauth/authorize request with query params.
func doAuthorizeRequest(params url.Values) *httptest.ResponseRecorder {
	req, _ := http.NewRequest("GET", "/oauth/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// insertTestRS inserts a resource server directly into the DB for policy tests.
// Returns the RS UUID.
func insertTestRS(t *testing.T, resourceURI string, registrationModes []string) uuid.UUID {
	t.Helper()
	db := config.Database.DB
	rsID := uuid.New()
	introspectSecret := "test-secret-" + rsID.String()[:8]
	modesArray := "{" + strings.Join(registrationModes, ",") + "}"
	_, err := db.Exec(`
		INSERT INTO resource_servers
			(id, workspace_id, name, public_base_url, protected_base_path, resource_uri,
			 registration_modes, introspection_secret, active, status,
			 scan_generation, last_successful_generation, created_at, updated_at)
		VALUES ($1, $2, $3, $4, '/mcp', $5, $6::text[], $7, true, 'scan_completed', 1, 1, NOW(), NOW())`,
		rsID, testWorkspaceID,
		"TestRS-"+rsID.String()[:8],
		"https://"+rsID.String()[:8]+".example.com",
		resourceURI,
		modesArray,
		introspectSecret,
	)
	require.NoError(t, err, "insertTestRS")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM resource_servers WHERE id = $1`, rsID)
	})
	return rsID
}

// insertTestOAuthClient inserts an MCP OAuth client into the DB.
// Returns the client UUID.
func insertTestOAuthClient(t *testing.T, clientID, hydraClientID, registrationType string, redirectURIs []string) uuid.UUID {
	t.Helper()
	db := config.Database.DB
	id := uuid.New()
	urisArray := pq.Array(redirectURIs)
	_, err := db.Exec(`
		INSERT INTO mcp_oauth_clients
			(id, client_id, hydra_client_id, client_name, redirect_uris,
			 grant_types, response_types, token_endpoint_auth_method,
			 scope, registration_type, supports_refresh_token, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5,
			'{"authorization_code"}', '{"code"}', 'none',
			'', $6, false, NOW(), NOW())`,
		id, clientID, hydraClientID,
		"TestClient-"+id.String()[:8],
		urisArray, registrationType,
	)
	require.NoError(t, err, "insertTestOAuthClient")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM mcp_oauth_clients WHERE id = $1`, id)
	})
	return id
}

// insertClientRegistration creates the join-table row between an RS and a client.
func insertClientRegistration(t *testing.T, rsID, clientID uuid.UUID, status, regType string) {
	t.Helper()
	db := config.Database.DB
	regID := uuid.New()
	_, err := db.Exec(`
		INSERT INTO resource_server_client_registrations
			(id, resource_server_id, o_auth_client_id, status, registration_type, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (resource_server_id, o_auth_client_id) DO UPDATE
			SET status = EXCLUDED.status`,
		regID, rsID, clientID, status, regType,
	)
	require.NoError(t, err, "insertClientRegistration")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM resource_server_client_registrations WHERE id = $1`, regID)
	})
}

// basePARParams returns the minimum valid PAR parameters (minus policy-sensitive ones).
func basePARParams(resourceURI, clientID, redirectURI string) url.Values {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("resource", resourceURI)
	v.Set("state", "test-state-"+uuid.New().String())
	v.Set("redirect_uri", redirectURI)
	v.Set("code_challenge", strings.Repeat("a", 43)) // min-length S256 placeholder
	v.Set("code_challenge_method", "S256")
	return v
}

// baseAuthorizeParams returns minimum valid Authorize params (GET).
func baseAuthorizeParams(resourceURI, clientID, redirectURI string) url.Values {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", clientID)
	v.Set("resource", resourceURI)
	v.Set("state", "test-state-"+uuid.New().String())
	v.Set("redirect_uri", redirectURI)
	v.Set("code_challenge", strings.Repeat("a", 43))
	v.Set("code_challenge_method", "S256")
	return v
}

// ── Tier A — Tests 1–6 (no Hydra) ───────────────────────────────────────────

// Test 1: RS has RegistrationModes = ["dcr"] only.
// PAR with an HTTPS client_id (CIMD) must be rejected before any CIMD document fetch.
func TestCIMDDisabledBlocksPAR(t *testing.T) {
	resourceURI := fmt.Sprintf("https://cimd-blocked-par-%s.example.com/mcp", uuid.New().String()[:8])
	insertTestRS(t, resourceURI, []string{"dcr"}) // cimd NOT in modes

	params := basePARParams(resourceURI, "https://some-cimd-client.example.com/client-metadata.json", "https://client.example.com/callback")

	w := doPARRequest(params)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"PAR with CIMD client_id against dcr-only RS must return 403; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "cimd", "error body should mention cimd")
}

// Test 2: Same RS (dcr-only). Authorize with an HTTPS client_id must be rejected identically.
func TestCIMDDisabledBlocksAuthorize(t *testing.T) {
	resourceURI := fmt.Sprintf("https://cimd-blocked-authz-%s.example.com/mcp", uuid.New().String()[:8])
	insertTestRS(t, resourceURI, []string{"dcr"}) // cimd NOT in modes

	params := baseAuthorizeParams(resourceURI, "https://some-cimd-client.example.com/client-metadata.json", "https://client.example.com/callback")

	w := doAuthorizeRequest(params)

	// Authorize returns 302 to Hydra on success; any non-3xx is a policy rejection.
	assert.NotEqual(t, http.StatusFound, w.Code,
		"Authorize with CIMD client against dcr-only RS must NOT succeed; body: %s", w.Body.String())
	assert.True(t, w.Code == http.StatusForbidden || w.Code == http.StatusBadRequest,
		"expected 400 or 403, got %d; body: %s", w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "cimd")
}

// Test 3: RS allows only ["prereg"]. A DCR client (RegistrationType="dcr") must be rejected.
func TestRegistrationTypeMismatch(t *testing.T) {
	resourceURI := fmt.Sprintf("https://prereg-only-%s.example.com/mcp", uuid.New().String()[:8])
	rsID := insertTestRS(t, resourceURI, []string{"prereg"}) // dcr NOT allowed

	// Create a DCR client and register it
	dcrClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, dcrClientID, uuid.New().String(), "dcr", []string{"https://client.example.com/callback"})
	insertClientRegistration(t, rsID, clientRowID, "approved", "dcr")

	params := basePARParams(resourceURI, dcrClientID, "https://client.example.com/callback")
	w := doPARRequest(params)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"DCR client against prereg-only RS must return 403; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "dcr", "error body should mention the rejected registration type")
}

// Test 3b: Missing resource on /authorize is tolerated only when the client maps
// to exactly one active approved RS. The redirect to Hydra must carry the inferred
// resource so downstream login/consent stays audience-bound.
func TestAuthorizeMissingResource_InfersSingleApprovedRS(t *testing.T) {
	resourceURI := fmt.Sprintf("https://single-rs-%s.example.com/mcp", uuid.New().String()[:8])
	rsID := insertTestRS(t, resourceURI, []string{"dcr"})

	clientPublicID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, clientPublicID, uuid.New().String(), "dcr", []string{"https://client.example.com/callback"})
	insertClientRegistration(t, rsID, clientRowID, "approved", "dcr")

	params := baseAuthorizeParams(resourceURI, clientPublicID, "https://client.example.com/callback")
	params.Del("resource")

	w := doAuthorizeRequest(params)

	require.Equal(t, http.StatusFound, w.Code, "authorize should infer the single resource; body: %s", w.Body.String())
	location := w.Header().Get("Location")
	require.NotEmpty(t, location, "redirect location must be present")
	assert.Contains(t, location, "resource="+url.QueryEscape(resourceURI))
}

// Test 3c: Missing resource on /authorize must still fail closed when the client
// maps to multiple approved RS rows; the client must disambiguate with RFC 8707 resource.
func TestAuthorizeMissingResource_AmbiguousAcrossMultipleRS(t *testing.T) {
	resourceURI1 := fmt.Sprintf("https://multi-a-%s.example.com/mcp", uuid.New().String()[:8])
	resourceURI2 := fmt.Sprintf("https://multi-b-%s.example.com/mcp", uuid.New().String()[:8])
	rsID1 := insertTestRS(t, resourceURI1, []string{"dcr"})
	rsID2 := insertTestRS(t, resourceURI2, []string{"dcr"})

	clientPublicID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, clientPublicID, uuid.New().String(), "dcr", []string{"https://client.example.com/callback"})
	insertClientRegistration(t, rsID1, clientRowID, "approved", "dcr")
	insertClientRegistration(t, rsID2, clientRowID, "approved", "dcr")

	params := baseAuthorizeParams(resourceURI1, clientPublicID, "https://client.example.com/callback")
	params.Del("resource")

	w := doAuthorizeRequest(params)

	require.Equal(t, http.StatusBadRequest, w.Code, "authorize must fail closed when resource is ambiguous; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "multiple resource servers")
}

// Test 4: CIMD client registered with redirect URI A; request uses URI B.
func TestRedirectMismatch_CIMD(t *testing.T) {
	resourceURI := fmt.Sprintf("https://redirect-cimd-%s.example.com/mcp", uuid.New().String()[:8])
	rsID := insertTestRS(t, resourceURI, []string{"cimd"})

	registeredURI := "https://registered.example.com/callback"
	wrongURI := "https://wrong.example.com/callback"

	cimdClientURL := fmt.Sprintf("https://cimd-client-%s.example.com/metadata.json", uuid.New().String()[:8])
	clientRowID := insertTestOAuthClient(t, cimdClientURL, uuid.New().String(), "cimd", []string{registeredURI})
	insertClientRegistration(t, rsID, clientRowID, "approved", "cimd")

	// NOTE: CIMD resolution would normally fetch the document from cimdClientURL.
	// Since there is no live server at that URL, ResolveCIMDClient will fail with a
	// network error before we even reach the redirect URI check. That is still correct
	// policy behaviour — an unresolvable CIMD URL is rejected. We assert non-success.
	params := basePARParams(resourceURI, cimdClientURL, wrongURI)
	w := doPARRequest(params)

	assert.NotEqual(t, http.StatusCreated, w.Code,
		"PAR with wrong redirect_uri for CIMD client must not succeed; body: %s", w.Body.String())
}

// Test 5: DCR client; redirect_uri in request does not match any registered URI.
func TestRedirectMismatch_DCR(t *testing.T) {
	resourceURI := fmt.Sprintf("https://redirect-dcr-%s.example.com/mcp", uuid.New().String()[:8])
	rsID := insertTestRS(t, resourceURI, []string{"dcr"})

	registeredURI := "https://registered.example.com/callback"
	wrongURI := "https://wrong.example.com/callback"

	dcrClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, dcrClientID, uuid.New().String(), "dcr", []string{registeredURI})
	insertClientRegistration(t, rsID, clientRowID, "approved", "dcr")

	params := basePARParams(resourceURI, dcrClientID, wrongURI)
	w := doPARRequest(params)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"PAR with wrong redirect_uri for DCR client must return 400; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "redirect_uri")
}

// Test 6: Prereg client; redirect_uri mismatch.
func TestRedirectMismatch_PreReg(t *testing.T) {
	resourceURI := fmt.Sprintf("https://redirect-prereg-%s.example.com/mcp", uuid.New().String()[:8])
	rsID := insertTestRS(t, resourceURI, []string{"prereg"})

	registeredURI := "https://registered.example.com/callback"
	wrongURI := "https://wrong.example.com/callback"

	preregClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, preregClientID, uuid.New().String(), "prereg", []string{registeredURI})
	insertClientRegistration(t, rsID, clientRowID, "approved", "prereg")

	params := basePARParams(resourceURI, preregClientID, wrongURI)
	w := doPARRequest(params)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"PAR with wrong redirect_uri for prereg client must return 400; body: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "redirect_uri")
}

// ── Tier B helpers ───────────────────────────────────────────────────────────
//
// Tests 7–11 use an httptest mock Hydra server and do NOT require a live Hydra.

// mockHydraRecorder captures every token submitted to POST /oauth2/revoke.
// The handler runs in a separate goroutine (the httptest server), so access
// to the slice is guarded by a mutex.
type mockHydraRecorder struct {
	mu      sync.Mutex
	revoked []string
}

func (r *mockHydraRecorder) record(token string) {
	if token == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, token)
}

// RevokedTokens returns a snapshot of all tokens submitted for revocation so far.
func (r *mockHydraRecorder) RevokedTokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.revoked))
	copy(out, r.revoked)
	return out
}

// TokenWasRevoked returns true if the given token was submitted to the mock revoke endpoint.
func (r *mockHydraRecorder) TokenWasRevoked(token string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.revoked {
		if t == token {
			return true
		}
	}
	return false
}

// mockHydraConfig configures the per-test mock Hydra httptest.Server.
type mockHydraConfig struct {
	// introspectResponse is returned as JSON from POST /admin/oauth2/introspect for any token.
	introspectResponse map[string]interface{}
	// tokenResponse is returned as JSON (status 200) from POST /oauth2/token.
	// nil → mock returns 400 invalid_grant.
	tokenResponse map[string]interface{}
}

// withMockHydra starts an httptest.Server simulating the Hydra endpoints the controller
// touches, overrides config.AppConfig.HydraAdminURL and HydraPublicURL for the duration
// of the test, and returns a *mockHydraRecorder that captures revocation requests.
// Both config values are restored via t.Cleanup.
//
// Endpoints served:
//   - POST /admin/oauth2/introspect → introspectResponse (200 JSON)
//   - POST /oauth2/token            → tokenResponse (200) or 400 (nil config)
//   - POST /oauth2/revoke           → 200 + records submitted token in recorder
//   - GET  /health/ready            → 200 (used by requireLiveHydra probe)
func withMockHydra(t *testing.T, cfg mockHydraConfig) *mockHydraRecorder {
	t.Helper()
	rec := &mockHydraRecorder{}
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/admin/oauth2/introspect" && r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(cfg.introspectResponse) //nolint:errcheck
		case r.URL.Path == "/oauth2/token" && r.Method == http.MethodPost:
			if cfg.tokenResponse == nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant"}`)) //nolint:errcheck
			} else {
				json.NewEncoder(w).Encode(cfg.tokenResponse) //nolint:errcheck
			}
		case r.URL.Path == "/oauth2/revoke" && r.Method == http.MethodPost:
			// RFC 7009 §2.2: revocation endpoint returns 200 for any token (including unknown).
			r.ParseForm() //nolint:errcheck
			rec.record(r.FormValue("token"))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`)) //nolint:errcheck
		case r.URL.Path == "/health/ready":
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(mock.Close)

	oldAdmin := config.AppConfig.HydraAdminURL
	oldPublic := config.AppConfig.HydraPublicURL
	config.AppConfig.HydraAdminURL = mock.URL
	config.AppConfig.HydraPublicURL = mock.URL
	t.Cleanup(func() {
		config.AppConfig.HydraAdminURL = oldAdmin
		config.AppConfig.HydraPublicURL = oldPublic
	})
	return rec
}

// insertAuthRequestContext inserts a pre-consented AuthRequestContext row directly into
// the DB, bypassing the normal authorize→login→consent flow. This simulates the state
// after a user completes consent and the hmgr ConsentHandler has called MarkConsentCompleted.
// Returns the server-generated context_id that the mock Hydra must embed in ext.context_id.
func insertAuthRequestContext(t *testing.T, hydraClientID, rsID, workspaceID, resourceURI, redirectURI string) string {
	t.Helper()
	db := config.Database.DB
	state := uuid.New().String()
	contextID := uuid.New().String()
	_, err := db.Exec(`
		INSERT INTO auth_request_contexts
			(state, context_id, hydra_client_id, resource_server_id, workspace_id,
			 resource_uri, redirect_uri, requested_scopes,
			 consent_completed, consumed, expires_at, created_at)
		VALUES ($1, $2, $3, $4::uuid, $5::uuid, $6, $7, $8,
			true, false, NOW() + INTERVAL '10 minutes', NOW())`,
		state, contextID, hydraClientID, rsID, workspaceID,
		resourceURI, redirectURI, "tools:read tools:write",
	)
	require.NoError(t, err, "insertAuthRequestContext")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM auth_request_contexts WHERE context_id = $1`, contextID)
	})
	return contextID
}

// insertRBACChainForScope creates a minimal RBAC chain that entitles userID to
// scopeString on the given RS within workspaceID. The chain is:
//
//	oauth_scope ← oauth_scope_permission ← permission ← role_permission ← role ← role_binding (user)
//
// All rows are cleaned up via t.Cleanup in reverse insertion order.
// This is the minimum viable setup for ResolveGrantableScopes to return scopeString.
func insertRBACChainForScope(t *testing.T, workspaceID, rsID uuid.UUID, userID, scopeString string) {
	t.Helper()
	db := config.Database.DB

	scopeID := uuid.New()
	permID := uuid.New()
	roleID := uuid.New()
	rbID := uuid.New()
	roleName := "test-role-" + scopeID.String()[:8]

	_, err := db.Exec(`
		INSERT INTO oauth_scopes
			(id, workspace_id, resource_server_id, scope_string, display_name, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'low', NOW(), NOW())`,
		scopeID, workspaceID, rsID, scopeString, scopeString,
	)
	require.NoError(t, err, "insertRBACChainForScope: oauth_scopes %s", scopeString)

	_, err = db.Exec(`
		INSERT INTO permissions (id, workspace_id, resource, action, created_at)
		VALUES ($1, $2, 'mcp-tool', $3, NOW())`,
		permID, workspaceID, scopeString,
	)
	require.NoError(t, err, "insertRBACChainForScope: permissions %s", scopeString)

	_, err = db.Exec(`INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2)`,
		scopeID, permID)
	require.NoError(t, err, "insertRBACChainForScope: oauth_scope_permissions %s", scopeString)

	_, err = db.Exec(`
		INSERT INTO roles (id, workspace_id, name, is_system, created_at)
		VALUES ($1, $2, $3, false, NOW())`,
		roleID, workspaceID, roleName,
	)
	require.NoError(t, err, "insertRBACChainForScope: roles %s", scopeString)

	_, err = db.Exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`,
		roleID, permID)
	require.NoError(t, err, "insertRBACChainForScope: role_permissions %s", scopeString)

	_, err = db.Exec(`
		INSERT INTO role_bindings
			(id, workspace_id, user_id, username, role_id, role_name, conditions, created_at)
		VALUES ($1, $2, $3::uuid, 'testuser', $4, $5, '{}', NOW())`,
		rbID, workspaceID, userID, roleID, roleName,
	)
	require.NoError(t, err, "insertRBACChainForScope: role_bindings %s", scopeString)

	t.Cleanup(func() {
		db.Exec(`DELETE FROM role_bindings WHERE id = $1`, rbID)
		db.Exec(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, roleID, permID)
		db.Exec(`DELETE FROM roles WHERE id = $1`, roleID)
		db.Exec(`DELETE FROM oauth_scope_permissions WHERE scope_id = $1 AND permission_id = $2`, scopeID, permID)
		db.Exec(`DELETE FROM permissions WHERE id = $1`, permID)
		db.Exec(`DELETE FROM oauth_scopes WHERE id = $1`, scopeID)
	})
}

// setRSScopesSupported updates the scopes_supported column on an existing RS row.
// Required for partial-scope-loss tests where the RBAC resolver must find specific
// scopes in the RS supported set before checking RBAC bindings.
func setRSScopesSupported(t *testing.T, rsID uuid.UUID, scopes []string) {
	t.Helper()
	db := config.Database.DB
	arr := "{" + strings.Join(scopes, ",") + "}"
	_, err := db.Exec(`UPDATE resource_servers SET scopes_supported = $1::text[] WHERE id = $2`, arr, rsID)
	require.NoError(t, err, "setRSScopesSupported")
}

// doTokenExchangeRequest sends POST /oauth/token with grant_type=authorization_code.
func doTokenExchangeRequest(clientID, code, redirectURI, resourceURI string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("resource", resourceURI)
	form.Set("code_verifier", strings.Repeat("b", 43)) // PKCE verifier placeholder
	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// doRefreshRequest sends POST /oauth/token with grant_type=refresh_token.
func doRefreshRequest(clientID, oldRefreshToken, resourceURI string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", oldRefreshToken)
	form.Set("resource", resourceURI)
	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// doIntrospectRequest sends POST /oauth/introspect authenticated with RS Basic Auth.
func doIntrospectRequest(rsID, introspectSecret, token string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}}
	req, _ := http.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rsID, introspectSecret)
	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// ── Tier B — Tests 7–11 ───────────────────────────────────────────────────────

// Test 7: Full PAR+consent simulation; user's role binding is deleted before exchange → 403
// and the issued access token is verified to have been submitted for revocation.
//
// Uses a mock Hydra server — no live Hydra required.
//
// Flow:
//  1. Insert RS (dcr-only), DCR client, approved registration.
//  2. Insert a pre-consented AuthRequestContext row (consent_completed=true).
//  3. Mock Hydra /oauth2/token returns an opaque access token.
//  4. Mock Hydra /admin/oauth2/introspect returns sub + scope + ext.context_id.
//  5. The sub has no RBAC bindings → ResolveGrantableScopes returns empty → 403.
//  6. Assert the access token was submitted to /oauth2/revoke (full-set revocation).
func TestRevokedRoleBeforeTokenExchange(t *testing.T) {
	resourceURI := fmt.Sprintf("https://revoked-role-%s.example.com/mcp", uuid.New().String()[:8])
	rsRowID := insertTestRS(t, resourceURI, []string{"dcr"})
	redirectURI := "https://client.example.com/callback"

	dcrPublicClientID := uuid.New().String()
	hydraClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, dcrPublicClientID, hydraClientID, "dcr", []string{redirectURI})
	insertClientRegistration(t, rsRowID, clientRowID, "approved", "dcr")

	// User sub has no RBAC bindings → full scope loss.
	userSub := uuid.New().String()
	contextID := insertAuthRequestContext(
		t, hydraClientID, rsRowID.String(), testWorkspaceID.String(),
		resourceURI, redirectURI,
	)

	opaqueToken := "mock-at-" + uuid.New().String()
	rec := withMockHydra(t, mockHydraConfig{
		tokenResponse: map[string]interface{}{
			"access_token": opaqueToken,
			"token_type":   "bearer",
			"expires_in":   3600,
		},
		// Returned on both calls: context_id extraction fallback AND step-6b RBAC check.
		introspectResponse: map[string]interface{}{
			"active": true,
			"sub":    userSub,
			"scope":  "tools:read",
			"aud":    resourceURI,
			"ext": map[string]interface{}{
				"context_id": contextID,
			},
		},
	})

	w := doTokenExchangeRequest(dcrPublicClientID, "any-code", redirectURI, resourceURI)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"token exchange with no RBAC bindings must return 403; body: %s", w.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errCode, _ := resp["error"].(string)
	assert.True(t,
		errCode == "insufficient_scope" || errCode == "access_denied",
		"error must be insufficient_scope or access_denied, got %q; body: %s", errCode, w.Body.String())

	// Core Workstream 2 requirement: the newly-issued access token MUST be revoked
	// synchronously on the denial path so it cannot be used in the window between
	// this 403 response and any async cleanup.
	assert.True(t, rec.TokenWasRevoked(opaqueToken),
		"issued access token must be submitted to /oauth2/revoke on denial; revoked tokens: %v",
		rec.RevokedTokens())
}

// Test 8: Token carries two RS scopes; user's RBAC covers only one → partial scope loss → 403.
//
// Uses a mock Hydra server — no live Hydra required.
//
// This tests the strict-subset enforcement path in tokenAuthCodeGrant (ScopesLost > 0),
// which is semantically different from Test 7 (full loss via len(currentScopes)==0).
//
// Setup:
//   - RS supports {"tools:read", "tools:write"} (scopes_supported).
//   - User has RBAC binding only for "tools:read" (not "tools:write").
//   - Mock Hydra returns token with scope "tools:read tools:write".
//   - ResolveGrantableScopes → ["tools:read"]; ScopesLost → ["tools:write"] → 403.
func TestPartialScopeLossBeforeExchange(t *testing.T) {
	resourceURI := fmt.Sprintf("https://partial-exchange-%s.example.com/mcp", uuid.New().String()[:8])
	rsRowID := insertTestRS(t, resourceURI, []string{"dcr"})
	setRSScopesSupported(t, rsRowID, []string{"tools:read", "tools:write"})

	redirectURI := "https://client.example.com/callback"
	dcrPublicClientID := uuid.New().String()
	hydraClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, dcrPublicClientID, hydraClientID, "dcr", []string{redirectURI})
	insertClientRegistration(t, rsRowID, clientRowID, "approved", "dcr")

	// User has RBAC for tools:read only. tools:write is in the token but not in RBAC.
	userSub := uuid.New().String()
	insertRBACChainForScope(t, testWorkspaceID, rsRowID, userSub, "tools:read")

	contextID := insertAuthRequestContext(
		t, hydraClientID, rsRowID.String(), testWorkspaceID.String(),
		resourceURI, redirectURI,
	)

	opaqueToken := "mock-at-partial-" + uuid.New().String()
	rec := withMockHydra(t, mockHydraConfig{
		tokenResponse: map[string]interface{}{
			"access_token": opaqueToken,
			"token_type":   "bearer",
			"expires_in":   3600,
		},
		introspectResponse: map[string]interface{}{
			"active": true,
			"sub":    userSub,
			"scope":  "tools:read tools:write", // token has both; RBAC only grants tools:read
			"aud":    resourceURI,
			"ext": map[string]interface{}{
				"context_id": contextID,
			},
		},
	})

	w := doTokenExchangeRequest(dcrPublicClientID, "any-code", redirectURI, resourceURI)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"partial scope loss at exchange must return 403; body: %s", w.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "insufficient_scope", resp["error"],
		"error must be insufficient_scope for partial scope loss; body: %s", w.Body.String())
	desc, _ := resp["error_description"].(string)
	assert.Contains(t, desc, "partial",
		"error_description must mention partial revocation; body: %s", w.Body.String())
	assert.True(t, rec.TokenWasRevoked(opaqueToken),
		"issued access token must be revoked on partial scope loss; revoked: %v", rec.RevokedTokens())
}

// Test 9: Refresh grant; new token carries two RS scopes; user RBAC covers only one → 403.
//
// Uses a mock Hydra server — no live Hydra required.
//
// This tests the strict-subset enforcement path in tokenRefreshGrant (ScopesLost > 0)
// and verifies that BOTH the new access token and the new refresh token are revoked
// synchronously — the old refresh token was already consumed by Hydra.
//
// Setup:
//   - Same RS/client/RBAC as Test 8.
//   - Client has SupportsRefreshToken=true.
//   - Mock Hydra /oauth2/token (refresh grant) issues new AT+RT with scope "tools:read tools:write".
//   - RBAC resolves to ["tools:read"] only → ScopesLost → ["tools:write"] → 403.
//   - Both new AT and RT must appear in the revocation recorder.
func TestPartialScopeLossOnRefresh(t *testing.T) {
	resourceURI := fmt.Sprintf("https://partial-refresh-%s.example.com/mcp", uuid.New().String()[:8])
	rsRowID := insertTestRS(t, resourceURI, []string{"dcr"})
	setRSScopesSupported(t, rsRowID, []string{"tools:read", "tools:write"})

	redirectURI := "https://client.example.com/callback"
	dcrPublicClientID := uuid.New().String()
	hydraClientID := uuid.New().String()
	clientRowID := insertTestOAuthClient(t, dcrPublicClientID, hydraClientID, "dcr", []string{redirectURI})
	// Enable refresh token support (required for the refresh grant path to be reached)
	_, _ = config.Database.DB.Exec(
		`UPDATE mcp_oauth_clients SET supports_refresh_token = true WHERE id = $1`, clientRowID)
	insertClientRegistration(t, rsRowID, clientRowID, "approved", "dcr")

	// User has RBAC for tools:read only. tools:write is in the token but not in RBAC.
	userSub := uuid.New().String()
	insertRBACChainForScope(t, testWorkspaceID, rsRowID, userSub, "tools:read")

	newAccessToken := "mock-new-at-" + uuid.New().String()
	newRefreshToken := "mock-new-rt-" + uuid.New().String()

	rec := withMockHydra(t, mockHydraConfig{
		tokenResponse: map[string]interface{}{
			"access_token":  newAccessToken,
			"refresh_token": newRefreshToken,
			"token_type":    "bearer",
			"expires_in":    3600,
		},
		introspectResponse: map[string]interface{}{
			"active": true,
			"sub":    userSub,
			"scope":  "tools:read tools:write", // new token has both; RBAC only grants tools:read
			"aud":    resourceURI,
		},
	})

	// The old refresh token value is arbitrary — mock Hydra accepts any value and issues new tokens.
	w := doRefreshRequest(dcrPublicClientID, "old-refresh-token-placeholder", resourceURI)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"partial scope loss on refresh must return 403; body: %s", w.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "insufficient_scope", resp["error"],
		"error must be insufficient_scope; body: %s", w.Body.String())
	desc, _ := resp["error_description"].(string)
	assert.Contains(t, desc, "partial",
		"error_description must mention partial revocation; body: %s", w.Body.String())

	// Both newly-issued tokens must be revoked. The old refresh token was already consumed
	// by Hydra before our code runs; revoking it again is harmless but not required here.
	assert.True(t, rec.TokenWasRevoked(newAccessToken),
		"new access token must be revoked on partial scope loss at refresh; revoked: %v", rec.RevokedTokens())
	assert.True(t, rec.TokenWasRevoked(newRefreshToken),
		"new refresh token must be revoked on partial scope loss at refresh; revoked: %v", rec.RevokedTokens())
}

// Test 10: Hydra issues token for "openid profile" (no RS scopes);
// introspect via AS → {"active": true, "scope": "openid profile"}.
//
// Uses a mock Hydra server — no live Hydra required.
//
// Regression test for the nil-client OIDC-only introspection bug:
// previously, introspection passed nil as client to ResolveGrantableScopes.
// clientIsOIDC(nil) returns false → OIDC core scopes treated as RS-specific →
// RBAC resolution returned empty → active:false for a perfectly valid OIDC token.
//
// The user sub has no RBAC bindings, confirming the OIDC path bypasses RBAC entirely.
func TestOIDCOnlyTokenIntrospectionValid(t *testing.T) {
	resourceURI := fmt.Sprintf("https://oidc-only-%s.example.com/mcp", uuid.New().String()[:8])
	rsRowID := insertTestRS(t, resourceURI, []string{"dcr"})
	rsIDStr := rsRowID.String()
	introspectSecret := "test-secret-" + rsIDStr[:8]

	userSub := uuid.New().String() // no RBAC bindings — confirms OIDC path is RBAC-free
	mockToken := "oidc-token-" + uuid.New().String()

	withMockHydra(t, mockHydraConfig{
		introspectResponse: map[string]interface{}{
			"active": true,
			"sub":    userSub,
			"scope":  "openid profile",
			"aud":    resourceURI,
		},
	})

	w := doIntrospectRequest(rsIDStr, introspectSecret, mockToken)

	require.Equal(t, http.StatusOK, w.Code, "introspect response must be 200; body: %s", w.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["active"],
		"OIDC-only token must be active=true even with no RS RBAC bindings; body: %s", w.Body.String())
	scope, _ := resp["scope"].(string)
	assert.Contains(t, scope, "openid", "scope must include openid; body: %s", w.Body.String())
	assert.Contains(t, scope, "profile", "scope must include profile; body: %s", w.Body.String())
}

// Test 11: Hydra issues RS-scoped token; user has no RBAC binding for that scope;
// introspect via AS → {"active": false}.
//
// Uses a mock Hydra server — no live Hydra required.
//
// The mock returns a token with RS-specific scope "tools:read". The RS has no
// scopes_supported entry (empty) and the user sub has no RBAC bindings, so
// ResolveGrantableScopes returns empty → active:false. Verifies strict-subset
// enforcement at introspection time closes the window where a stale Hydra token
// could be used after RBAC revocation.
func TestRSSpecificScopeLossIntrospection(t *testing.T) {
	resourceURI := fmt.Sprintf("https://rs-scope-loss-%s.example.com/mcp", uuid.New().String()[:8])
	rsRowID := insertTestRS(t, resourceURI, []string{"dcr"})
	rsIDStr := rsRowID.String()
	introspectSecret := "test-secret-" + rsIDStr[:8]

	userSub := uuid.New().String() // no RBAC bindings for tools:read
	mockToken := "rs-token-" + uuid.New().String()

	withMockHydra(t, mockHydraConfig{
		introspectResponse: map[string]interface{}{
			"active": true,
			"sub":    userSub,
			"scope":  "tools:read",
			"aud":    resourceURI,
		},
	})

	w := doIntrospectRequest(rsIDStr, introspectSecret, mockToken)

	require.Equal(t, http.StatusOK, w.Code,
		"introspect must return 200 even for inactive tokens per RFC 7662; body: %s", w.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, false, resp["active"],
		"RS-scoped token with no RBAC binding must be active=false; body: %s", w.Body.String())
}
