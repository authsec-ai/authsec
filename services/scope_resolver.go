package services

import "github.com/authsec-ai/authsec/models"

// ScopeResolver is the single source of truth for consent scope intersection.
// It computes: requested ∩ RS supported ∩ client allowed ∩ user allowed.
type ScopeResolver struct{}

func NewScopeResolver() *ScopeResolver {
	return &ScopeResolver{}
}

// ResolveGrantableScopes computes the scopes to grant at consent time.
// For v1, client_allowed and user_allowed are pass-through (no restrictions beyond RS).
func (r *ScopeResolver) ResolveGrantableScopes(
	requestedScopes []string,
	rs *models.ResourceServer,
	_ *models.MCPOAuthClient,
	_ string, // userID — for future user-level scope policies
) []string {
	// 1. requested ∩ rs.ScopesSupported
	rsSet := make(map[string]bool, len(rs.ScopesSupported))
	for _, s := range rs.ScopesSupported {
		rsSet[s] = true
	}

	var result []string
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		if rsSet[s] {
			result = append(result, s)
		}
	}

	// 2. ∩ client allowed scopes (v1: pass-through)
	// 3. ∩ user allowed scopes (v1: pass-through)

	return result
}

// intersectScopes returns the intersection of two scope slices.
func intersectScopes(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	var result []string
	for _, s := range a {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}
