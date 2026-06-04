//go:build integration

package integration

import (
	"fmt"
	"log"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func seedTestData() error {
	db := config.Database.DB

	testWorkspaceID = uuid.New()
	testAdminUserID = uuid.New()
	testEndUserID = uuid.New()
	testClientID = uuid.New()
	testProjectID = uuid.New()
	testAdminRoleID = uuid.New()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// 1. Insert test tenant
	_, err = db.Exec(`
		INSERT INTO tenants (id, workspace_id, email, workspace_domain, workspace_db, name, status, created_at, updated_at)
		VALUES ($1, $1, $2, $3, $4, 'Test Tenant', 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testWorkspaceID, testAdminEmail, testWorkspaceDomain, testDBName)
	if err != nil {
		return fmt.Errorf("insert tenant: %w", err)
	}

	// 2. Insert admin user
	_, err = db.Exec(`
		INSERT INTO users (id, client_id, workspace_id, project_id, email, password_hash,
			workspace_domain, provider, active, created_at, updated_at, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'local', true, NOW(), NOW(), 'Test Admin')
		ON CONFLICT (id) DO NOTHING`,
		testAdminUserID, testClientID, testWorkspaceID, testProjectID,
		testAdminEmail, string(hashedPassword), testWorkspaceDomain)
	if err != nil {
		return fmt.Errorf("insert admin user: %w", err)
	}

	// 3. Insert end user
	_, err = db.Exec(`
		INSERT INTO users (id, client_id, workspace_id, project_id, email, password_hash,
			workspace_domain, provider, active, created_at, updated_at, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'local', true, NOW(), NOW(), 'Test EndUser')
		ON CONFLICT (id) DO NOTHING`,
		testEndUserID, testClientID, testWorkspaceID, testProjectID,
		testEndUserEmail, string(hashedPassword), testWorkspaceDomain)
	if err != nil {
		return fmt.Errorf("insert end user: %w", err)
	}

	// 4. Insert project
	_, _ = db.Exec(`
		INSERT INTO projects (id, name, description, user_id, workspace_id, client_id, active, created_at)
		VALUES ($1, 'Test Project', 'Integration test project', $2, $3, $4, true, NOW())
		ON CONFLICT (id) DO NOTHING`,
		testProjectID, testAdminUserID, testWorkspaceID, testClientID)

	// 5. Insert client
	_, _ = db.Exec(`
		INSERT INTO clients (id, client_id, workspace_id, project_id, owner_id, org_id, name, email,
			status, active, created_at, updated_at)
		VALUES ($1, $1, $2, $3, $4, $2, 'Test Client', $5, 'Active', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testClientID, testWorkspaceID, testProjectID, testAdminUserID, testAdminEmail)

	// 6. Create admin role
	_, _ = db.Exec(`
		INSERT INTO roles (id, workspace_id, name, description, is_system, created_at)
		VALUES ($1, $2, 'admin', 'Admin role', true, NOW())
		ON CONFLICT DO NOTHING`,
		testAdminRoleID, testWorkspaceID)

	// 7. Create user role for end users
	userRoleID := uuid.New()
	_, _ = db.Exec(`
		INSERT INTO roles (id, workspace_id, name, description, is_system, created_at)
		VALUES ($1, $2, 'user', 'User role', false, NOW())
		ON CONFLICT DO NOTHING`,
		userRoleID, testWorkspaceID)

	// 8. Create role binding for admin user
	_, _ = db.Exec(`
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), testWorkspaceID, testAdminUserID, testAdminRoleID)

	// 9. Create role binding for end user
	_, _ = db.Exec(`
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), testWorkspaceID, testEndUserID, userRoleID)

	// 10. Create permissions for test tenant
	permResources := []struct{ resource, action string }{
		{"admin", "access"}, {"admin", "read"}, {"admin", "write"}, {"admin", "manage"}, {"admin", "delete"},
		{"users", "read"}, {"users", "write"}, {"users", "delete"}, {"users", "manage"}, {"users", "active"},
		{"tenants", "read"}, {"tenants", "write"}, {"tenants", "delete"}, {"tenants", "manage"},
		{"clients", "read"}, {"clients", "write"}, {"clients", "admin"},
		{"roles", "manage"}, {"permissions", "manage"},
		{"external-service", "create"}, {"external-service", "read"},
		{"external-service", "update"}, {"external-service", "delete"},
		{"external-service", "credentials"},
		{"migrations", "admin"},
	}
	for _, p := range permResources {
		permID := uuid.New()
		_, _ = db.Exec(`
			INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
			ON CONFLICT DO NOTHING`,
			permID, testWorkspaceID, p.resource, p.action,
			p.resource+":"+p.action, p.resource+":"+p.action)
		// Link to admin role
		_, _ = db.Exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			testAdminRoleID, permID)
	}

	// 11. Create tenant_mappings entry
	_, _ = db.Exec(`
		INSERT INTO tenant_mappings (id, workspace_id, client_id, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), testWorkspaceID, testClientID)

	// ── Workstream 3 seed data ──────────────────────────────────────────────

	// Other tenant — used for cross-tenant 404/403 assertions
	testOtherWorkspaceID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO tenants (id, workspace_id, email, workspace_domain, workspace_db, name, status, created_at, updated_at)
		VALUES ($1, $1, $2, $3, $4, 'Other Tenant', 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testOtherWorkspaceID, "admin@other.authsec.local", "other.authsec.local", testDBName)

	// RS owned by testWorkspaceID (primary)
	testResourceServerID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO resource_servers (id, workspace_id, name, public_base_url, active, created_at, updated_at)
		VALUES ($1, $2, 'Test RS', 'https://rs.test.local', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testResourceServerID, testWorkspaceID)

	// Second RS owned by testWorkspaceID — for same-tenant cross-RS parent isolation test
	testSecondRSID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO resource_servers (id, workspace_id, name, public_base_url, active, created_at, updated_at)
		VALUES ($1, $2, 'Test RS 2', 'https://rs2.test.local', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testSecondRSID, testWorkspaceID)

	// RS owned by testOtherWorkspaceID — used in cross-tenant RS tests
	testOtherTenantRSID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO resource_servers (id, workspace_id, name, public_base_url, active, created_at, updated_at)
		VALUES ($1, $2, 'Other Tenant RS', 'https://rs.other.local', true, NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testOtherTenantRSID, testOtherWorkspaceID)

	// Scope owned by testWorkspaceID + testResourceServerID
	testScopeID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, 'tools:test:read', 'Test Read', 'low', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testScopeID, testWorkspaceID, testResourceServerID)

	// Scope owned by testWorkspaceID + testSecondRSID — for same-tenant cross-RS parent test
	testSecondRSScopeID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, 'tools:secondrs:read', 'Second RS Read', 'low', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testSecondRSScopeID, testWorkspaceID, testSecondRSID)

	// Scope owned by testOtherWorkspaceID + testOtherTenantRSID — used in cross-tenant parent tests
	testOtherTenantScopeID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, 'tools:foreign:read', 'Foreign Read', 'low', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testOtherTenantScopeID, testOtherWorkspaceID, testOtherTenantRSID)

	// Permission owned by testOtherWorkspaceID — used in cross-tenant permission injection test
	testOtherTenantPermID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
		VALUES ($1, $2, 'tools', 'read', 'tools:read', 'tools:read', NOW())
		ON CONFLICT DO NOTHING`,
		testOtherTenantPermID, testOtherWorkspaceID)

	// MCP tool owned by testOtherWorkspaceID + testOtherTenantRSID — for cross-tenant tool-scope map test
	testOtherTenantToolID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO mcp_tools (id, workspace_id, resource_server_id, name, title, discovered_at, last_scan_generation)
		VALUES ($1, $2, $3, 'foreign-tool', 'Foreign Tool', NOW(), 0)
		ON CONFLICT DO NOTHING`,
		testOtherTenantToolID, testOtherWorkspaceID, testOtherTenantRSID)

	// Consent grant owned by testWorkspaceID (not yet revoked)
	testConsentGrantID = uuid.New()
	_, _ = db.Exec(`
		INSERT INTO oauth_consent_grants (id, workspace_id, user_id, client_id, resource_server_id, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['tools:test:read'], NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testConsentGrantID, testWorkspaceID, testEndUserID, testClientID, testResourceServerID)

	log.Printf("Seeded test data: tenant=%s admin=%s enduser=%s rs=%s scope=%s grant=%s other_tenant=%s other_rs=%s other_scope=%s second_rs=%s",
		testWorkspaceID, testAdminUserID, testEndUserID,
		testResourceServerID, testScopeID, testConsentGrantID,
		testOtherWorkspaceID, testOtherTenantRSID, testOtherTenantScopeID, testSecondRSID)

	if err := seedW4Data(); err != nil {
		return fmt.Errorf("seedW4Data: %w", err)
	}
	return nil
}

// seedW4Data seeds Workstream 4 fixtures: RS, scopes, permission bridge, role, MCP client, consent grant.
func seedW4Data() error {
	db := config.Database.DB

	// W4 Resource Server — scopes_supported covers both read + write
	testW4RSID = uuid.New()
	_, err := db.Exec(`
		INSERT INTO resource_servers (id, workspace_id, name, public_base_url, active, scopes_supported, created_at, updated_at)
		VALUES ($1, $2, 'W4 RS', 'https://w4.test.local', true, ARRAY['tools:w4:read','tools:w4:write'], NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testW4RSID, testWorkspaceID)
	if err != nil {
		return fmt.Errorf("insert W4 RS: %w", err)
	}

	// Scope tools:w4:read — has a full permission bridge (oauth_scope_permissions row)
	testW4ScopeID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, description, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, 'tools:w4:read', 'W4 Read Scope', 'Allows reading W4 data', 'low', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testW4ScopeID, testWorkspaceID, testW4RSID)
	if err != nil {
		return fmt.Errorf("insert W4 read scope: %w", err)
	}

	// Scope tools:w4:write — intentionally has NO oauth_scope_permissions row
	testW4NoBridgeScopeID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO oauth_scopes (id, workspace_id, resource_server_id, scope_string, display_name, description, risk_level, created_at, updated_at)
		VALUES ($1, $2, $3, 'tools:w4:write', 'W4 Write Scope', 'Allows writing W4 data', 'high', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testW4NoBridgeScopeID, testWorkspaceID, testW4RSID)
	if err != nil {
		return fmt.Errorf("insert W4 write scope: %w", err)
	}

	// Permission for tools:w4:read
	w4PermID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO permissions (id, workspace_id, resource, action, description, full_permission_string, created_at)
		VALUES ($1, $2, 'tools', 'w4:read', 'W4 read permission', 'tools:w4:read', NOW())
		ON CONFLICT DO NOTHING`,
		w4PermID, testWorkspaceID)
	if err != nil {
		return fmt.Errorf("insert W4 read permission: %w", err)
	}

	// Permission → oauth_scope bridge (only for tools:w4:read)
	_, err = db.Exec(`
		INSERT INTO oauth_scope_permissions (scope_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		testW4ScopeID, w4PermID)
	if err != nil {
		return fmt.Errorf("insert W4 scope permission link: %w", err)
	}

	// Role for W4 end-user access
	testW4RoleID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO roles (id, workspace_id, name, description, is_system, created_at)
		VALUES ($1, $2, 'rs:w4:user', 'W4 user role', false, NOW())
		ON CONFLICT DO NOTHING`,
		testW4RoleID, testWorkspaceID)
	if err != nil {
		return fmt.Errorf("insert W4 role: %w", err)
	}

	// Role → permission binding (role grants the read permission)
	_, err = db.Exec(`
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		testW4RoleID, w4PermID)
	if err != nil {
		return fmt.Errorf("insert W4 role_permissions: %w", err)
	}

	// Role binding: testEndUserID gets the W4 role
	_, err = db.Exec(`
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		uuid.New(), testWorkspaceID, testEndUserID, testW4RoleID)
	if err != nil {
		return fmt.Errorf("insert W4 role binding: %w", err)
	}

	// MCP OAuth client for W4 tests
	testW4MCPClientID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO mcp_oauth_clients (id, client_id, hydra_client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, registration_type, created_at, updated_at)
		VALUES ($1, 'hydra-w4-client', 'hydra-w4-client', 'W4 Test Client', ARRAY['https://w4.test.local/callback'], ARRAY['authorization_code'], ARRAY['code'], 'none', 'pre_registered', NOW(), NOW())
		ON CONFLICT DO NOTHING`,
		testW4MCPClientID)
	if err != nil {
		return fmt.Errorf("insert W4 MCP client: %w", err)
	}

	// Consent grant: testEndUserID has a stored grant covering both read + write (30-day TTL)
	testW4ConsentGrantID = uuid.New()
	_, err = db.Exec(`
		INSERT INTO oauth_consent_grants (id, workspace_id, user_id, client_id, resource_server_id, granted_scopes, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['tools:w4:read','tools:w4:write'], NOW() + INTERVAL '30 days', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING`,
		testW4ConsentGrantID, testWorkspaceID, testEndUserID, testW4MCPClientID, testW4RSID)
	if err != nil {
		return fmt.Errorf("insert W4 consent grant: %w", err)
	}

	log.Printf("Seeded W4 test data: rs=%s readScope=%s writeScope=%s role=%s mcpClient=%s grant=%s",
		testW4RSID, testW4ScopeID, testW4NoBridgeScopeID, testW4RoleID, testW4MCPClientID, testW4ConsentGrantID)
	return nil
}
