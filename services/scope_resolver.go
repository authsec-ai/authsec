package services

import "github.com/authsec-ai/authsec/models"

// ScopeResolver resolves grantable scopes for MCP OAuth.
// FAIL-CLOSED: RS must declare scopes_supported. Empty = no scopes granted.
type ScopeResolver struct{}

func NewScopeResolver() *ScopeResolver {
	return &ScopeResolver{}
}

// ResolveGrantableScopes intersects requested scopes with RS-supported scopes.
// FAIL-CLOSED: if RS has no scopes_supported, returns empty (nothing granted).
func (r *ScopeResolver) ResolveGrantableScopes(
	requestedScopes []string,
	rs *models.ResourceServer,
	_ *models.MCPOAuthClient,
	_ string, // userID — for future user-level scope policies
) []string {
	if rs == nil || len(rs.ScopesSupported) == 0 {
		return nil // fail-closed: no declared scopes = nothing granted
	}

	supported := make(map[string]struct{}, len(rs.ScopesSupported))
	for _, s := range rs.ScopesSupported {
		supported[s] = struct{}{}
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
		if _, ok := supported[s]; !ok {
			continue
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}

	return result
}

// ValidateRequestedScopes checks if all requested scopes are in the RS's supported set.
// FAIL-CLOSED: if RS has empty scopes_supported, ALL scopes are invalid.
func ValidateRequestedScopes(scopes []string, rs *models.ResourceServer) []string {
	if rs == nil {
		return scopes // all invalid
	}
	if len(rs.ScopesSupported) == 0 {
		// No scopes configured = reject everything except empty request
		var invalid []string
		for _, s := range scopes {
			if s != "" {
				invalid = append(invalid, s)
			}
		}
		return invalid
	}

	supported := make(map[string]struct{}, len(rs.ScopesSupported))
	for _, s := range rs.ScopesSupported {
		supported[s] = struct{}{}
	}
	var invalid []string
	for _, s := range scopes {
		if s == "" {
			continue
		}
		if _, ok := supported[s]; !ok {
			invalid = append(invalid, s)
		}
	}
	return invalid
}
