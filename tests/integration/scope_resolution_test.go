//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── HTTP helpers ────────────────────────────────────────────────────────────

func scopePreviewURL(rsID uuid.UUID, userID uuid.UUID, scopes ...string) string {
	u := fmt.Sprintf("/authsec/resource-servers/%s/scope-resolution-preview?user_id=%s", rsID, userID)
	for _, s := range scopes {
		u += "&scope=" + s
	}
	return u
}

// ─── Test 1: No role binding → all scopes blocked ────────────────────────────

func TestScopePreview_NoRoleBinding(t *testing.T) {
	freshUser := uuid.New() // has no role bindings at all
	url := scopePreviewURL(testW4RSID, freshUser, "tools:w4:read", "tools:w4:write")
	resp := doAdminRequest("GET", url, nil)

	require.Equal(t, 200, resp.Code)

	var body struct {
		Grantable   []string `json:"grantable"`
		Diagnostics []struct {
			Scope   string `json:"scope"`
			Granted bool   `json:"granted"`
			Reason  string `json:"reason"`
		} `json:"diagnostics"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body))

	assert.Empty(t, body.Grantable, "fresh user should have no grantable scopes")
	require.Len(t, body.Diagnostics, 2)
	for _, d := range body.Diagnostics {
		assert.False(t, d.Granted, "scope %s should be blocked", d.Scope)
		assert.Equal(t, "no_rbac_binding", d.Reason)
	}
}

// ─── Test 2: No permission bridge → no_rbac_binding ──────────────────────────

// testEndUserID has the W4 role (grants tools:w4:read via permission bridge),
// but tools:w4:write has no oauth_scope_permissions row — so it's no_rbac_binding.
func TestScopePreview_NoPermissionBridge(t *testing.T) {
	url := scopePreviewURL(testW4RSID, testEndUserID, "tools:w4:write")
	resp := doAdminRequest("GET", url, nil)

	require.Equal(t, 200, resp.Code)

	var body struct {
		Grantable   []string `json:"grantable"`
		Diagnostics []struct {
			Scope   string `json:"scope"`
			Granted bool   `json:"granted"`
			Reason  string `json:"reason"`
		} `json:"diagnostics"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body))

	assert.Empty(t, body.Grantable)
	require.Len(t, body.Diagnostics, 1)
	assert.Equal(t, "tools:w4:write", body.Diagnostics[0].Scope)
	assert.False(t, body.Diagnostics[0].Granted)
	assert.Equal(t, "no_rbac_binding", body.Diagnostics[0].Reason)
}

// ─── Test 3: Scope not in RS.scopes_supported ────────────────────────────────

func TestScopePreview_NotInRSSupported(t *testing.T) {
	url := scopePreviewURL(testW4RSID, testEndUserID, "tools:w4:unknown")
	resp := doAdminRequest("GET", url, nil)

	require.Equal(t, 200, resp.Code)

	var body struct {
		Diagnostics []struct {
			Scope   string `json:"scope"`
			Granted bool   `json:"granted"`
			Reason  string `json:"reason"`
		} `json:"diagnostics"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body))

	require.Len(t, body.Diagnostics, 1)
	assert.Equal(t, "tools:w4:unknown", body.Diagnostics[0].Scope)
	assert.False(t, body.Diagnostics[0].Granted)
	assert.Equal(t, "not_in_rs_supported", body.Diagnostics[0].Reason)
}

// ─── Test 4: Valid stored grant → auto-accept (stale=false, grant!=nil) ──────

func TestConsentService_ValidGrant_AutoAccept(t *testing.T) {
	cs := services.NewConsentService(config.DB)

	grant, stale, err := cs.CheckExistingConsent(
		testTenantID, testEndUserID, testW4MCPClientID, testW4RSID,
		[]string{"tools:w4:read", "tools:w4:write"},
		// Full RBAC set covers both scopes
		[]string{"tools:w4:read", "tools:w4:write"},
		// RS still supports both
		[]string{"tools:w4:read", "tools:w4:write"},
	)

	require.NoError(t, err)
	assert.False(t, stale, "grant should not be stale")
	require.NotNil(t, grant, "grant should be found")
	assert.Equal(t, testW4ConsentGrantID, grant.ID)
}

// ─── Test 5: Stale grant → revoked when RBAC loses a scope ──────────────────

func TestConsentService_StaleGrant_Revoked(t *testing.T) {
	// Create a fresh consent grant for this test so we don't interfere with Test 4
	freshGrantID := uuid.New()
	_, err := config.Database.DB.Exec(`
		INSERT INTO oauth_consent_grants (id, tenant_id, user_id, client_id, resource_server_id, granted_scopes, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['tools:w4:read','tools:w4:write'], NOW() + INTERVAL '30 days', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		freshGrantID, testTenantID, testEndUserID, testW4MCPClientID, testW4RSID)
	require.NoError(t, err)

	cs := services.NewConsentService(config.DB)

	// RBAC revocation: user no longer has write binding
	grant, stale, err := cs.CheckExistingConsent(
		testTenantID, testEndUserID, testW4MCPClientID, testW4RSID,
		[]string{"tools:w4:read", "tools:w4:write"},
		[]string{"tools:w4:read"}, // write revoked from RBAC
		[]string{"tools:w4:read", "tools:w4:write"},
	)

	require.NoError(t, err)
	assert.True(t, stale, "grant should be stale (write RBAC revoked)")
	assert.Nil(t, grant)

	// Verify revoked_at was set in DB
	var revokedAt *time.Time
	row := config.Database.DB.QueryRow(
		`SELECT revoked_at FROM oauth_consent_grants WHERE id = $1`, freshGrantID)
	require.NoError(t, row.Scan(&revokedAt))
	assert.NotNil(t, revokedAt, "revoked_at should be set after stale detection")

	// Sanity check: a narrower request [read] with userEffective=[read,write] should NOT falsely revoke
	// Insert another clean grant
	safeGrantID := uuid.New()
	_, err = config.Database.DB.Exec(`
		INSERT INTO oauth_consent_grants (id, tenant_id, user_id, client_id, resource_server_id, granted_scopes, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['tools:w4:read'], NOW() + INTERVAL '30 days', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		safeGrantID, testTenantID, testEndUserID, testW4MCPClientID, testW4RSID)
	require.NoError(t, err)

	safeGrant, safeStale, safeErr := cs.CheckExistingConsent(
		testTenantID, testEndUserID, testW4MCPClientID, testW4RSID,
		[]string{"tools:w4:read"},             // only read requested
		[]string{"tools:w4:read", "tools:w4:write"}, // user still has write in RBAC
		[]string{"tools:w4:read", "tools:w4:write"},
	)
	require.NoError(t, safeErr)
	assert.False(t, safeStale, "narrower read-only request must not falsely revoke a read-only grant")
	assert.NotNil(t, safeGrant, "read-only grant should be found and valid")
}

// ─── Test 5b: Stale grant → revoked when RS withdraws a scope ────────────────
//
// RBAC is kept fully intact (userEffective still has both scopes); only
// rsSupportedScopes is narrowed to simulate the RS removing the write scope.
// This exercises the second staleness axis added in WS4.

func TestConsentService_StaleGrant_RSWithdrawal(t *testing.T) {
	// Insert a fresh grant so we have a clean row for this test.
	freshGrantID := uuid.New()
	_, err := config.Database.DB.Exec(`
		INSERT INTO oauth_consent_grants (id, tenant_id, user_id, client_id, resource_server_id, granted_scopes, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['tools:w4:read','tools:w4:write'], NOW() + INTERVAL '30 days', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		freshGrantID, testTenantID, testEndUserID, testW4MCPClientID, testW4RSID)
	require.NoError(t, err)

	cs := services.NewConsentService(config.DB)

	// RS withdrawal: RBAC still grants both scopes, but RS has removed 'tools:w4:write'
	// from scopes_supported. The stored grant covering write must be revoked.
	grant, stale, err := cs.CheckExistingConsent(
		testTenantID, testEndUserID, testW4MCPClientID, testW4RSID,
		[]string{"tools:w4:read", "tools:w4:write"},
		[]string{"tools:w4:read", "tools:w4:write"}, // RBAC intact — user still has both
		[]string{"tools:w4:read"},                   // RS withdrew write from scopes_supported
	)

	require.NoError(t, err)
	assert.True(t, stale, "grant should be stale (RS withdrew tools:w4:write)")
	assert.Nil(t, grant)

	// Verify revoked_at was set in DB
	var revokedAt *time.Time
	row := config.Database.DB.QueryRow(
		`SELECT revoked_at FROM oauth_consent_grants WHERE id = $1`, freshGrantID)
	require.NoError(t, row.Scan(&revokedAt))
	assert.NotNil(t, revokedAt, "revoked_at should be set after RS-withdrawal stale detection")
}

// ─── Test 6: Metadata in response (display_name, description, risk_level) ───

func TestScopePreview_MetadataInResponse(t *testing.T) {
	url := scopePreviewURL(testW4RSID, testEndUserID, "tools:w4:read")
	resp := doAdminRequest("GET", url, nil)

	require.Equal(t, 200, resp.Code)

	var body struct {
		Diagnostics []struct {
			Scope       string `json:"scope"`
			Granted     bool   `json:"granted"`
			DisplayName string `json:"display_name"`
			Description string `json:"description"`
			RiskLevel   string `json:"risk_level"`
		} `json:"diagnostics"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body))

	require.Len(t, body.Diagnostics, 1)
	d := body.Diagnostics[0]
	assert.Equal(t, "tools:w4:read", d.Scope)
	assert.True(t, d.Granted)
	assert.Equal(t, "W4 Read Scope", d.DisplayName)
	assert.Equal(t, "Allows reading W4 data", d.Description)
	assert.Equal(t, "low", d.RiskLevel)
}

// ─── Test 7: Blocked reasons + metadata for blocked scopes ───────────────────

func TestScopePreview_BlockedReasonInResponse(t *testing.T) {
	url := scopePreviewURL(testW4RSID, testEndUserID, "tools:w4:write", "tools:w4:unknown")
	resp := doAdminRequest("GET", url, nil)

	require.Equal(t, 200, resp.Code)

	var body struct {
		Diagnostics []struct {
			Scope       string `json:"scope"`
			Granted     bool   `json:"granted"`
			Reason      string `json:"reason"`
			DisplayName string `json:"display_name"`
			RiskLevel   string `json:"risk_level"`
		} `json:"diagnostics"`
	}
	require.NoError(t, json.Unmarshal(resp.Body, &body))

	require.Len(t, body.Diagnostics, 2)

	diagByScope := make(map[string]struct {
		Scope       string `json:"scope"`
		Granted     bool   `json:"granted"`
		Reason      string `json:"reason"`
		DisplayName string `json:"display_name"`
		RiskLevel   string `json:"risk_level"`
	}, 2)
	for _, d := range body.Diagnostics {
		diagByScope[d.Scope] = d
	}

	// tools:w4:write — in RS-supported, but no RBAC bridge
	writeD, ok := diagByScope["tools:w4:write"]
	require.True(t, ok, "tools:w4:write should be in diagnostics")
	assert.False(t, writeD.Granted)
	assert.Equal(t, "no_rbac_binding", writeD.Reason)
	assert.Equal(t, "W4 Write Scope", writeD.DisplayName)
	assert.Equal(t, "high", writeD.RiskLevel)

	// tools:w4:unknown — not in RS-supported
	unknownD, ok := diagByScope["tools:w4:unknown"]
	require.True(t, ok, "tools:w4:unknown should be in diagnostics")
	assert.False(t, unknownD.Granted)
	assert.Equal(t, "not_in_rs_supported", unknownD.Reason)
}

// ─── Test 8: Cross-tenant permission rejected in CreateScope ─────────────────

// POST /authsec/resource-servers/:id/scopes with a permission ID from another tenant.
// Expected: HTTP 201 (scope created), BUT no oauth_scope_permissions row for the foreign permission.
func TestCreateScope_CrossTenantPermissionRejected(t *testing.T) {
	body := map[string]interface{}{
		"scope_string":   "tools:w4:crosstenant",
		"display_name":   "Cross-Tenant Test",
		"description":    "Should reject foreign permission",
		"risk_level":     "low",
		"permission_ids": []string{testOtherTenantPermID.String()}, // foreign tenant's permission
	}

	url := fmt.Sprintf("/authsec/resource-servers/%s/scopes", testW4RSID)
	resp := doAdminRequest("POST", url, body)

	require.Equal(t, 201, resp.Code, "scope creation should succeed even with foreign permission ID; body: %s", string(resp.Body))

	// Extract the created scope ID from the response
	var scopeResp map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.Body, &scopeResp))

	scopeIDStr, ok := scopeResp["id"].(string)
	require.True(t, ok, "response should include scope id")
	scopeID, err := uuid.Parse(scopeIDStr)
	require.NoError(t, err)

	// Verify: no oauth_scope_permissions row linking this scope to the foreign permission
	assertRowCount(t, "oauth_scope_permissions", 0,
		"scope_id = $1 AND permission_id = $2",
		scopeID, testOtherTenantPermID)

	// Verify: the returned permissions list is empty (foreign perm was silently dropped)
	perms, _ := scopeResp["permissions"].([]interface{})
	assert.Empty(t, perms, "permissions list should be empty — foreign permission was silently dropped")

	// Cleanup: remove the created scope so it doesn't pollute other tests
	config.DB.Where("id = ?", scopeID).Delete(&models.OAuthScope{})
}
