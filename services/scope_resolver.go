package services

import (
	"context"
	"log"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// oidcCoreScopes are AS-level scopes defined by OpenID Connect Core 1.0.
// These bypass the RS scopes_supported check ONLY when the client has opted into OIDC
// (i.e. the client's registered Scope includes "openid").
var oidcCoreScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"offline_access": true,
	"address":        true,
	"phone":          true,
}

// IsOIDCCoreScope returns true if the scope is an OIDC core scope.
func IsOIDCCoreScope(s string) bool {
	return oidcCoreScopes[s]
}

// clientIsOIDC checks whether the client has opted into OIDC by having "openid" in its
// registered Scope field. Non-OIDC clients (legacy MCP) never get OIDC core scopes.
func clientIsOIDC(client *models.MCPOAuthClient) bool {
	if client == nil || client.Scope == "" {
		return false
	}
	for _, s := range strings.Fields(client.Scope) {
		if s == "openid" {
			return true
		}
	}
	return false
}

// ScopeResolver resolves grantable scopes for MCP OAuth using a 3-way intersection:
//
//	granted = requested_scopes ∩ RS.scopes_supported ∩ user_effective_scopes
//
// where user_effective_scopes = user → role_bindings → roles → permissions → oauth_scope_permissions → oauth_scopes.
//
// FAIL-CLOSED:
//   - RS must declare scopes_supported. Empty = no RS scopes granted.
//   - User must have RBAC role bindings with permission→scope mappings. No bindings = no scopes.
//   - OIDC core scopes bypass both RS and RBAC checks, only for OIDC-capable clients.
type ScopeResolver struct {
	db *gorm.DB
}

func NewScopeResolver(db *gorm.DB) *ScopeResolver {
	return &ScopeResolver{db: db}
}

// ResolveGrantableScopes performs the 3-way intersection:
// requested ∩ RS-supported ∩ user-effective-scopes (from RBAC → oauth_scope_permissions).
//
// If the user has no RBAC bindings or no scope mappings, the result is empty (fail-closed).
// OIDC core scopes bypass RBAC for OIDC-capable clients.
func (r *ScopeResolver) ResolveGrantableScopes(
	ctx context.Context,
	tenantID, userID, resourceServerID string,
	requestedScopes []string,
	rs *models.ResourceServer,
	client *models.MCPOAuthClient,
) ([]string, error) {
	isOIDC := clientIsOIDC(client)

	// Build RS supported set
	rsSupported := make(map[string]struct{})
	if rs != nil {
		for _, s := range rs.ScopesSupported {
			rsSupported[s] = struct{}{}
		}
	}

	// Resolve user's effective OAuth scopes from RBAC
	userEffective, err := r.resolveUserEffectiveScopes(ctx, tenantID, userID, resourceServerID)
	if err != nil {
		log.Printf("[SCOPE_RESOLVER] RBAC scope resolution failed user=%s tenant=%s rs=%s: %v",
			userID, tenantID, resourceServerID, err)
		// Fail-closed: on error, grant no RS scopes (OIDC core still pass through)
		userEffective = make(map[string]struct{})
	}

	seen := make(map[string]struct{}, len(requestedScopes))
	var result []string
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		// OIDC core scopes pass through only when the client is OIDC-capable.
		// These are AS-level, not RS-level, and bypass RBAC.
		if oidcCoreScopes[s] {
			if isOIDC {
				seen[s] = struct{}{}
				result = append(result, s)
			}
			continue
		}
		// RS-specific scopes: 3-way intersection
		// 1. Must be in RS supported set
		if _, ok := rsSupported[s]; !ok {
			continue
		}
		// 2. Must be in user's effective scope set (from RBAC)
		if _, ok := userEffective[s]; !ok {
			continue
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}

	return result, nil
}

// resolveUserEffectiveScopes returns the set of OAuth scope strings the user is entitled to
// based on their RBAC role bindings for a specific resource server.
//
// Resolution chain: role_bindings → roles → role_permissions → permissions → oauth_scope_permissions → oauth_scopes
//
// Also performs wildcard expansion: if the user has permission mapped to scope "tools:*",
// all child scopes like "tools:weather:read" are included.
func (r *ScopeResolver) resolveUserEffectiveScopes(
	ctx context.Context,
	tenantID, userID, resourceServerID string,
) (map[string]struct{}, error) {
	result := make(map[string]struct{})

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return result, nil // invalid UUID = no scopes (fail-closed)
	}
	rsUUID, err := uuid.Parse(resourceServerID)
	if err != nil {
		return result, nil
	}

	// Single query: user → role_bindings → roles → role_permissions → permissions → oauth_scope_permissions → oauth_scopes
	// This resolves the full RBAC chain to OAuth scope strings.
	var scopeStrings []string
	err = r.db.WithContext(ctx).
		Table("role_bindings rb").
		Select("DISTINCT os.scope_string").
		Joins("JOIN roles ro ON rb.role_id = ro.id").
		Joins("JOIN role_permissions rp ON ro.id = rp.role_id").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = p.id").
		Joins("JOIN oauth_scopes os ON osp.scope_id = os.id").
		Where("rb.user_id::text = ?", userID).
		Where("(rb.tenant_id IS NULL OR rb.tenant_id = ?)", tenantUUID).
		Where("(ro.tenant_id IS NULL OR ro.tenant_id = ?)", tenantUUID).
		Where("(p.tenant_id IS NULL OR p.tenant_id = ?)", tenantUUID).
		Where("os.tenant_id = ? AND os.resource_server_id = ?", tenantUUID, rsUUID).
		Pluck("os.scope_string", &scopeStrings).Error

	if err != nil {
		return result, err
	}

	for _, s := range scopeStrings {
		result[s] = struct{}{}
	}

	// Expand wildcards: if user has "tools:*", also grant "tools:weather:read", etc.
	if len(result) > 0 {
		r.expandWildcards(ctx, tenantUUID, rsUUID, result)
	}

	return result, nil
}

// expandWildcards checks if any granted scope is a wildcard (ends with ":*") and expands
// it to include all child scopes from the oauth_scopes table.
func (r *ScopeResolver) expandWildcards(ctx context.Context, tenantID, rsID uuid.UUID, effectiveSet map[string]struct{}) {
	var wildcards []string
	for s := range effectiveSet {
		if strings.HasSuffix(s, ":*") {
			wildcards = append(wildcards, s)
		}
	}
	if len(wildcards) == 0 {
		return
	}

	// Load all scopes for this RS to check which ones fall under a wildcard
	var allScopes []string
	r.db.WithContext(ctx).
		Model(&models.OAuthScope{}).
		Where("tenant_id = ? AND resource_server_id = ?", tenantID, rsID).
		Pluck("scope_string", &allScopes)

	for _, scope := range allScopes {
		if _, already := effectiveSet[scope]; already {
			continue
		}
		// Check if any wildcard is an ancestor of this scope
		for _, wc := range wildcards {
			prefix := strings.TrimSuffix(wc, "*")
			if strings.HasPrefix(scope, prefix) {
				effectiveSet[scope] = struct{}{}
				break
			}
		}
	}
}

// ValidateRequestedScopes checks if all requested scopes are valid for this client + RS.
// OIDC core scopes are valid only for OIDC-capable clients (client.Scope contains "openid").
// RS-specific scopes are fail-closed against RS.ScopesSupported.
func ValidateRequestedScopes(scopes []string, rs *models.ResourceServer, client *models.MCPOAuthClient) []string {
	isOIDC := clientIsOIDC(client)

	rsSupported := make(map[string]struct{})
	if rs != nil {
		for _, s := range rs.ScopesSupported {
			rsSupported[s] = struct{}{}
		}
	}

	var invalid []string
	for _, s := range scopes {
		if s == "" {
			continue
		}
		// OIDC core scopes: valid only for OIDC-capable clients
		if oidcCoreScopes[s] {
			if !isOIDC {
				invalid = append(invalid, s)
			}
			continue
		}
		// RS-specific: must be in RS supported set
		if _, ok := rsSupported[s]; !ok {
			invalid = append(invalid, s)
		}
	}
	return invalid
}
