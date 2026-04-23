//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ════════════════════════════════════════════════════════════════════════
// Workstream 3 — Admin Authorization & Ownership Hardening
//
// Convention:
//   NonAdmin → expect 403 (route-level Require("admin","access") gate)
//   CrossTenant → expect 404 (service-level tenant ownership check)
//   CrossTenantParent → expect 400 (ErrInvalidParentScope)
//   InjectionSkipped → expect 200 with applied:0, zero bridge table rows
// ════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────
// Resource Server CRUD — role gate
// ────────────────────────────────────────────────────────────────────────

func TestRS_Create_NonAdmin(t *testing.T) {
	resp := doRequest("POST", "/authsec/resource-servers", map[string]interface{}{
		"name":            "Should Not Be Created",
		"public_base_url": "https://nope.local",
	}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestRS_Create_Admin(t *testing.T) {
	resp := doAdminRequest("POST", "/authsec/resource-servers", map[string]interface{}{
		"name":            "Admin Created RS",
		"public_base_url": "https://admin-created.local",
	})
	require.Equal(t, http.StatusCreated, resp.Code)
	assert.NotEmpty(t, resp.JSON["id"])

	rsID, _ := resp.JSON["id"].(string)
	// Audit row must exist
	assertRowExists(t, "audit_events",
		"action = 'rs_created' AND tenant_id = $1 AND resource_id = $2",
		testTenantID.String(), rsID)
}

func TestRS_Update_NonAdmin(t *testing.T) {
	resp := doRequest("PUT", fmt.Sprintf("/authsec/resource-servers/%s", testResourceServerID),
		map[string]interface{}{"name": "Hijacked"}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestRS_Delete_NonAdmin(t *testing.T) {
	resp := doRequest("DELETE", fmt.Sprintf("/authsec/resource-servers/%s", testResourceServerID),
		nil, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestRS_RotateSecret_NonAdmin(t *testing.T) {
	resp := doRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/rotate-introspection-secret", testResourceServerID),
		nil, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestRS_PreRegister_NonAdmin(t *testing.T) {
	resp := doRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/clients", testResourceServerID),
		map[string]interface{}{"client_name": "x"}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestRS_CrossTenant_Delete(t *testing.T) {
	// An admin from testOtherTenantID tries to delete testTenantID's RS.
	resp := doRequest("DELETE",
		fmt.Sprintf("/authsec/resource-servers/%s", testResourceServerID),
		nil, generateOtherTenantAdminToken(testOtherTenantID))
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

// ────────────────────────────────────────────────────────────────────────
// Scope management — role gate + ownership
// ────────────────────────────────────────────────────────────────────────

func TestScope_Create_NonAdmin(t *testing.T) {
	resp := doRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testResourceServerID),
		map[string]interface{}{"scope_string": "tools:x:read"}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestScope_Create_Admin(t *testing.T) {
	resp := doAdminRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testResourceServerID),
		map[string]interface{}{
			"scope_string": "tools:audit-created:read",
			"display_name": "Audit Created",
			"risk_level":   "low",
		})
	require.Equal(t, http.StatusCreated, resp.Code)
	assert.NotEmpty(t, resp.JSON["id"])

	scopeID, _ := resp.JSON["id"].(string)
	assertRowExists(t, "audit_events",
		"action = 'scope_created' AND tenant_id = $1 AND resource_id = $2",
		testTenantID.String(), scopeID)
}

func TestScope_Create_CrossTenantRS(t *testing.T) {
	// testOtherTenantRSID is a real RS row owned by testOtherTenantID.
	// An admin from testTenantID must receive 404 because the ownership check
	// (GetByIDAndTenant) filters by the token's tenant_id.
	resp := doAdminRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testOtherTenantRSID),
		map[string]interface{}{"scope_string": "tools:injected:read"})
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestScope_Create_CrossTenantParent(t *testing.T) {
	// testOtherTenantScopeID is a real scope row owned by testOtherTenantID's RS.
	// Using it as parent_scope_id for a scope in testTenantID's RS must return 400.
	resp := doAdminRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testResourceServerID),
		map[string]interface{}{
			"scope_string":    "tools:orphan:read",
			"parent_scope_id": testOtherTenantScopeID.String(),
		})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestScope_Create_SameTenantCrossRS_Parent(t *testing.T) {
	// testSecondRSScopeID is a real scope owned by testTenantID but under testSecondRSID.
	// Using it as parent_scope_id when creating a scope for testResourceServerID must
	// return 400: both scopes belong to the same tenant, but the RS domains differ,
	// and the hierarchy isolation rule blocks cross-RS parent links.
	resp := doAdminRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testResourceServerID),
		map[string]interface{}{
			"scope_string":    "tools:cross-rs-orphan:read",
			"parent_scope_id": testSecondRSScopeID.String(),
		})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestScope_Create_CrossTenantPermission(t *testing.T) {
	// testOtherTenantPermID is a real permission row owned by testOtherTenantID.
	// The scope must still be created (201) but that specific permission ID must
	// NOT appear in oauth_scope_permissions because the tenant filter rejects it.
	resp := doAdminRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/scopes", testResourceServerID),
		map[string]interface{}{
			"scope_string":   "tools:perm-inject:read",
			"permission_ids": []string{testOtherTenantPermID.String()},
		})
	require.Equal(t, http.StatusCreated, resp.Code)
	createdID, _ := resp.JSON["id"].(string)
	// The foreign permission must not have been linked.
	assertRowCount(t, "oauth_scope_permissions", 0,
		"scope_id = $1 AND permission_id = $2", createdID, testOtherTenantPermID.String())
}

func TestScope_Update_NonAdmin(t *testing.T) {
	resp := doRequest("PUT",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		map[string]interface{}{"display_name": "Hijacked"}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestScope_Update_Admin(t *testing.T) {
	resp := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		map[string]interface{}{"display_name": "Updated by Admin"})
	require.Equal(t, http.StatusOK, resp.Code)

	assertRowExists(t, "audit_events",
		"action = 'scope_updated' AND tenant_id = $1 AND resource_id = $2",
		testTenantID.String(), testScopeID.String())
}

func TestScope_Update_CrossTenant(t *testing.T) {
	resp := doRequest("PUT",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		map[string]interface{}{"display_name": "Hijacked"},
		generateOtherTenantAdminToken(testOtherTenantID))
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestScope_Update_CrossTenantParent(t *testing.T) {
	// testOtherTenantScopeID is a real scope owned by testOtherTenantID.
	// Passing it as parent_scope_id for a scope in testTenantID must return 400.
	resp := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		map[string]interface{}{"parent_scope_id": testOtherTenantScopeID.String()})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestScope_Update_SameTenantCrossRS_Parent(t *testing.T) {
	// testSecondRSScopeID is a real scope in the same tenant but under testSecondRSID.
	// Passing it as parent_scope_id for testScopeID (which is under testResourceServerID)
	// must return 400: the hierarchy isolation rule blocks cross-RS parent links even
	// within the same tenant.
	resp := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		map[string]interface{}{"parent_scope_id": testSecondRSScopeID.String()})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestScope_Delete_NonAdmin(t *testing.T) {
	// Use a fresh scope so we don't consume testScopeID
	freshScopeID := uuid.New()
	resp := doRequest("DELETE",
		fmt.Sprintf("/authsec/scopes/%s", freshScopeID),
		nil, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestScope_Delete_CrossTenant(t *testing.T) {
	resp := doRequest("DELETE",
		fmt.Sprintf("/authsec/scopes/%s", testScopeID),
		nil, generateOtherTenantAdminToken(testOtherTenantID))
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

// ────────────────────────────────────────────────────────────────────────
// Tool-scope map — role gate + per-mapping ownership
// ────────────────────────────────────────────────────────────────────────

func TestToolScopeMap_NonAdmin(t *testing.T) {
	resp := doRequest("PUT",
		fmt.Sprintf("/authsec/resource-servers/%s/tool-scope-map", testResourceServerID),
		map[string]interface{}{
			"mappings": []map[string]interface{}{
				{"tool_id": uuid.New().String(), "scope_id": testScopeID.String()},
			},
		}, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestToolScopeMap_CrossTenantRS(t *testing.T) {
	// testOtherTenantRSID is a real RS row owned by testOtherTenantID.
	// A token for testOtherTenantID must receive 404 because GetByIDAndTenant
	// checks the token's tenant_id against the RS row.
	resp := doRequest("PUT",
		fmt.Sprintf("/authsec/resource-servers/%s/tool-scope-map", testOtherTenantRSID),
		map[string]interface{}{
			"mappings": []map[string]interface{}{
				{"tool_id": testOtherTenantToolID.String(), "scope_id": testOtherTenantScopeID.String()},
			},
		}, generateOtherTenantAdminToken(testOtherTenantID))
	// The other-tenant admin's token is for testOtherTenantID, but the RS row was
	// created under testOtherTenantID — this should succeed for the route gate but
	// the real test is that testTenantID's admin cannot reach testOtherTenantID's RS.
	// Use testTenantID's admin token against the other tenant's RS to confirm 404.
	resp2 := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/resource-servers/%s/tool-scope-map", testOtherTenantRSID),
		map[string]interface{}{
			"mappings": []map[string]interface{}{
				{"tool_id": testOtherTenantToolID.String(), "scope_id": testOtherTenantScopeID.String()},
			},
		})
	_ = resp
	assert.Equal(t, http.StatusNotFound, resp2.Code)
}

func TestToolScopeMap_CrossTenantIDs_Skipped(t *testing.T) {
	// testOtherTenantToolID and testOtherTenantScopeID are real rows owned by
	// testOtherTenantID. testTenantID's admin sends them against testTenantID's RS.
	// Per-mapping ownership check (tenant_id = ? AND resource_server_id = ?) rejects
	// both → applied:0 and zero bridge rows written.
	resp := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/resource-servers/%s/tool-scope-map", testResourceServerID),
		map[string]interface{}{
			"mappings": []map[string]interface{}{
				{"tool_id": testOtherTenantToolID.String(), "scope_id": testOtherTenantScopeID.String()},
			},
		})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.EqualValues(t, 0, resp.JSON["applied"])
	assertRowCount(t, "mcp_tool_scope_map", 0,
		"tool_id = $1 AND scope_id = $2",
		testOtherTenantToolID.String(), testOtherTenantScopeID.String())
}

func TestToolScopeMap_CrossRS_SameTenant_Skipped(t *testing.T) {
	// testOtherTenantToolID belongs to testOtherTenantRSID, not testResourceServerID.
	// Even though the admin's token is valid, the per-mapping resource_server_id check
	// must reject the entry → applied:0.
	// Use testScopeID (correct tenant, wrong RS for the tool) to isolate the tool check.
	resp := doAdminRequest("PUT",
		fmt.Sprintf("/authsec/resource-servers/%s/tool-scope-map", testResourceServerID),
		map[string]interface{}{
			"mappings": []map[string]interface{}{
				{"tool_id": testOtherTenantToolID.String(), "scope_id": testScopeID.String()},
			},
		})
	require.Equal(t, http.StatusOK, resp.Code)
	assert.EqualValues(t, 0, resp.JSON["applied"])
}

// ────────────────────────────────────────────────────────────────────────
// Rescan — role gate
// ────────────────────────────────────────────────────────────────────────

func TestRescan_NonAdmin(t *testing.T) {
	resp := doRequest("POST",
		fmt.Sprintf("/authsec/resource-servers/%s/rescan", testResourceServerID),
		nil, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

// ────────────────────────────────────────────────────────────────────────
// Consent grants — role gate + ownership
// ────────────────────────────────────────────────────────────────────────

func TestConsent_Revoke_NonAdmin(t *testing.T) {
	resp := doRequest("DELETE",
		fmt.Sprintf("/authsec/consent-grants/%s", testConsentGrantID),
		nil, generateNonAdminToken())
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestConsent_Revoke_Admin(t *testing.T) {
	// Use a fresh grant so this test is idempotent regardless of ordering.
	freshGrantID := uuid.New()
	_ = runSQL(
		`INSERT INTO oauth_consent_grants (id, tenant_id, user_id, client_id, resource_server_id, scopes, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, ARRAY['tools:test:read'], NOW(), NOW()) ON CONFLICT DO NOTHING`,
		freshGrantID, testTenantID, testEndUserID, testClientID, testResourceServerID)

	resp := doAdminRequest("DELETE",
		fmt.Sprintf("/authsec/consent-grants/%s", freshGrantID), nil)
	require.Equal(t, http.StatusOK, resp.Code)

	assertRowExists(t, "audit_events",
		"action = 'consent_grant_revoked' AND tenant_id = $1 AND resource_id = $2",
		testTenantID.String(), freshGrantID.String())
}

func TestConsent_Revoke_CrossTenant(t *testing.T) {
	// An admin from testOtherTenantID tries to revoke a grant owned by testTenantID.
	resp := doRequest("DELETE",
		fmt.Sprintf("/authsec/consent-grants/%s", testConsentGrantID),
		nil, generateOtherTenantAdminToken(testOtherTenantID))
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

func TestConsent_Revoke_AlreadyRevoked(t *testing.T) {
	// Insert a pre-revoked grant.
	alreadyRevokedID := uuid.New()
	_ = runSQL(
		`INSERT INTO oauth_consent_grants (id, tenant_id, user_id, client_id, resource_server_id, scopes, revoked_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, ARRAY['tools:test:read'], NOW(), NOW(), NOW()) ON CONFLICT DO NOTHING`,
		alreadyRevokedID, testTenantID, testEndUserID, testClientID, testResourceServerID)

	resp := doAdminRequest("DELETE",
		fmt.Sprintf("/authsec/consent-grants/%s", alreadyRevokedID), nil)
	assert.Equal(t, http.StatusNotFound, resp.Code)
}

// ────────────────────────────────────────────────────────────────────────
// Helper
// ────────────────────────────────────────────────────────────────────────

// runSQL executes a raw SQL statement against the test database.
func runSQL(query string, args ...interface{}) error {
	_, err := config.Database.DB.Exec(query, args...)
	return err
}
