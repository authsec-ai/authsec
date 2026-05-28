package admin

import (
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// getUserRoleNames queries role_bindings to get all distinct role names for a user in a tenant.
// RBAC tables (role_bindings, roles) live in the master database.
func getUserRoleNames(userID, tenantID string) ([]string, error) {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return nil, fmt.Errorf("master database not initialized")
	}

	query := `
		SELECT DISTINCT rb.role_name
		FROM role_bindings rb
		WHERE rb.user_id::text = $1
		AND rb.tenant_id::text = $2
		AND rb.role_name IS NOT NULL
		AND rb.role_name != ''
	`
	rows, err := masterDB.DB.Query(query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query user roles: %w", err)
	}
	defer rows.Close()

	var roleNames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan role name: %w", err)
		}
		roleNames = append(roleNames, name)
	}
	return roleNames, nil
}

// findDelegationPolicy looks up an enabled delegation policy matching any of
// the user's roles and the requested agent_type within a workspace. Single-DB
// collapse: tenant_id is now a row predicate on config.DB.
func findDelegationPolicy(tenantID string, roleNames []string, agentType string) (*models.DelegationPolicy, error) {
	if len(roleNames) == 0 {
		return nil, fmt.Errorf("user has no roles")
	}

	var policy models.DelegationPolicy
	result := config.DB.
		Where("tenant_id::text = ? AND role_name IN ? AND agent_type = ? AND enabled = true",
			tenantID, roleNames, agentType).
		First(&policy)

	if result.Error != nil {
		return nil, result.Error
	}
	return &policy, nil
}

// getUserEffectivePermissionStrings returns permission strings ("resource:action") for a user.
// RBAC tables (permissions, role_permissions, role_bindings) live in the master database.
func getUserEffectivePermissionStrings(userID, tenantID string) ([]string, error) {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return nil, fmt.Errorf("master database not initialized")
	}

	query := `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN role_bindings rb ON rp.role_id = rb.role_id
		WHERE rb.user_id::text = $1
		AND rb.tenant_id::text = $2
	`
	rows, err := masterDB.DB.Query(query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query user permissions: %w", err)
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// lookupApplicationIDForLegacyClient resolves a legacy clients.id to its
// matching resource_servers.id via the legacy_client_id mapping populated by
// migration 118. Returns nil when no Application has been backfilled for the
// given clients row — callers should fall back to ClientID during transition.
func lookupApplicationIDForLegacyClient(clientID uuid.UUID) *uuid.UUID {
	if clientID == uuid.Nil {
		return nil
	}
	var appID uuid.UUID
	row := config.DB.Table("resource_servers").
		Select("id").
		Where("legacy_client_id = ?", clientID).
		Limit(1).
		Row()
	if err := row.Scan(&appID); err != nil {
		return nil
	}
	return &appID
}

// validateClientActive checks that a client_id exists and is active in the
// clients table for the given tenant/workspace. Single-DB collapse: queries
// run against the shared config.DB connection.
func validateClientActive(clientID, tenantID string) error {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return fmt.Errorf("master database not initialized")
	}

	query := `
		SELECT id FROM clients
		WHERE client_id::text = $1
		AND workspace_id = $2
		AND (deleted = false OR deleted IS NULL)
		AND status = 'Active'
		LIMIT 1
	`
	var id string
	if err := masterDB.DB.QueryRow(query, clientID, tenantID).Scan(&id); err != nil {
		return fmt.Errorf("client %s not found or not active in tenant %s", clientID, tenantID)
	}
	return nil
}

// resolveDelegationPermissions checks if the user has an enabled delegation policy
// for the requested agent_type, resolves the user's effective permissions, intersects
// with the policy's allowed permissions AND the client's allowed_permissions, and caps
// the TTL. Returns the delegated permissions or an error if delegation is not allowed.
func resolveDelegationPermissions(userID, tenantID, agentType string, ttl *time.Duration) ([]string, string, error) {
	// 1. Get user's role names
	roleNames, err := getUserRoleNames(userID, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to look up user roles: %w", err)
	}
	if len(roleNames) == 0 {
		return nil, "", fmt.Errorf("user has no roles assigned")
	}

	// 2. Find matching delegation policy
	policy, err := findDelegationPolicy(tenantID, roleNames, agentType)
	if err != nil {
		return nil, "", fmt.Errorf("no enabled delegation policy for roles %v and agent_type %q", roleNames, agentType)
	}

	// 3. If policy has a client_id, verify the client is still active
	var clientID string
	if policy.ClientID != nil {
		clientID = policy.ClientID.String()
		if err := validateClientActive(clientID, tenantID); err != nil {
			return nil, "", fmt.Errorf("delegation client is not active: %w", err)
		}
	}

	// 4. Get user's effective permissions
	userPerms, err := getUserEffectivePermissionStrings(userID, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve user permissions: %w", err)
	}

	// 5. Intersect with policy's allowed permissions
	allowedPerms := policy.GetAllowedPermissions()
	delegatedPerms := intersectPermissions(userPerms, allowedPerms)

	// 6. Cap TTL
	if policy.MaxTTLSeconds > 0 && ttl != nil {
		maxTTL := time.Duration(policy.MaxTTLSeconds) * time.Second
		if *ttl > maxTTL {
			*ttl = maxTTL
		}
	}

	log.Printf("[Delegation] User %s delegating to %s (client: %s): %d permissions, TTL %v",
		userID, agentType, clientID, len(delegatedPerms), ttl)

	return delegatedPerms, clientID, nil
}

// getTenantRoleNames returns all distinct role names for a tenant.
func getTenantRoleNames(tenantID string) ([]string, error) {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return nil, fmt.Errorf("master database not initialized")
	}

	query := `SELECT DISTINCT name FROM roles WHERE workspace_id::text = $1 ORDER BY name`
	rows, err := masterDB.DB.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant roles: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		names = append(names, n)
	}
	return names, nil
}

// getTenantPermissionStrings returns all distinct permission strings for a tenant.
func getTenantPermissionStrings(tenantID string) ([]string, error) {
	masterDB := config.GetDatabase()
	if masterDB == nil {
		return nil, fmt.Errorf("master database not initialized")
	}

	query := `
		SELECT DISTINCT p.resource || ':' || p.action
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.id
		WHERE r.tenant_id::text = $1
		ORDER BY 1
	`
	rows, err := masterDB.DB.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query tenant permissions: %w", err)
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// intersectPermissions returns only permissions present in both slices.
// If allowedPerms is empty, returns all userPerms (no restriction).
func intersectPermissions(userPerms, allowedPerms []string) []string {
	if len(allowedPerms) == 0 {
		return userPerms
	}

	allowed := make(map[string]bool, len(allowedPerms))
	for _, p := range allowedPerms {
		allowed[p] = true
	}

	var result []string
	for _, p := range userPerms {
		if allowed[p] {
			result = append(result, p)
		}
	}
	return result
}
