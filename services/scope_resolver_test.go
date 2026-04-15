package services

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/lib/pq"
)

// --- ResolveGrantableScopes tests ---
// These test the resolver with a nil DB, which triggers fail-closed behavior
// for RS-specific scopes (no RBAC = no scopes). OIDC core scopes still pass through.

func TestResolveGrantableScopes_NilRS_ReturnsNothing(t *testing.T) {
	resolver := NewScopeResolver(nil) // nil DB → RBAC resolution fails → empty RS scopes

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"", "", "",
		[]string{"tools:read", "tools:write"},
		nil, // no RS = fail-closed
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected 0 scopes for nil RS (fail-closed), got %d: %#v", len(got), got)
	}
}

func TestResolveGrantableScopes_EmptyScopes_ReturnsNothing(t *testing.T) {
	resolver := NewScopeResolver(nil)

	rs := &models.ResourceServer{
		ScopesSupported: []string{},
	}

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"", "", "",
		[]string{"tools:read", "tools:write"},
		rs, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected 0 scopes for empty scopes_supported (fail-closed), got %d: %#v", len(got), got)
	}
}

func TestResolveGrantableScopes_NoRBAC_RSScopes_FailClosed(t *testing.T) {
	// Without a DB, no RBAC resolution can happen → RS-specific scopes are denied.
	resolver := NewScopeResolver(nil)

	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read", "tools:write", "tools:admin"},
	}

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"tenant-123", "user-456", "rs-789",
		[]string{"tools:read", "tools:write"},
		rs, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without RBAC bindings, no RS scopes should be granted (fail-closed)
	if len(got) != 0 {
		t.Fatalf("expected 0 RS scopes without RBAC bindings (fail-closed), got %d: %#v", len(got), got)
	}
}

func TestResolveGrantableScopes_OIDCClient_GetsOIDCScopes(t *testing.T) {
	// OIDC core scopes bypass RBAC — they should be granted even without DB
	resolver := NewScopeResolver(nil)

	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read"},
	}
	oidcClient := &models.MCPOAuthClient{Scope: "openid profile email"}

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"", "", "",
		[]string{"openid", "profile", "email", "tools:read", "tools:unknown"},
		rs, oidcClient,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only OIDC core scopes should pass through; RS scopes blocked by no RBAC
	want := []string{"openid", "profile", "email"}
	if len(got) != len(want) {
		t.Fatalf("expected %d scopes (OIDC only), got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scope mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestResolveGrantableScopes_NonOIDCClient_DropsOIDCScopes(t *testing.T) {
	resolver := NewScopeResolver(nil)

	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read"},
	}
	nonOIDCClient := &models.MCPOAuthClient{Scope: ""} // no openid

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"", "", "",
		[]string{"openid", "profile", "tools:read"},
		rs, nonOIDCClient,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// OIDC scopes dropped (non-OIDC client), RS scopes blocked (no RBAC)
	if len(got) != 0 {
		t.Fatalf("expected 0 scopes for non-OIDC client without RBAC, got %#v", got)
	}
}

func TestResolveGrantableScopes_Deduplication(t *testing.T) {
	resolver := NewScopeResolver(nil)

	oidcClient := &models.MCPOAuthClient{Scope: "openid"}

	got, err := resolver.ResolveGrantableScopes(
		context.Background(),
		"", "", "",
		[]string{"openid", "openid", "", "openid"},
		nil, oidcClient,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != 1 || got[0] != "openid" {
		t.Fatalf("expected deduped [openid], got %#v", got)
	}
}

// --- ValidateRequestedScopes tests (unchanged — no DB dependency) ---

func TestValidateRequestedScopes_EmptyRS_RejectsAll(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: []string{},
	}

	invalid := ValidateRequestedScopes([]string{"tools:read"}, rs, nil)
	if len(invalid) != 1 || invalid[0] != "tools:read" {
		t.Fatalf("expected all scopes rejected for empty RS, got invalid=%#v", invalid)
	}
}

func TestValidateRequestedScopes_ReturnsInvalid(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read", "tools:write"},
	}

	invalid := ValidateRequestedScopes([]string{"tools:read", "tools:hack"}, rs, nil)
	if len(invalid) != 1 || invalid[0] != "tools:hack" {
		t.Fatalf("expected [tools:hack] invalid, got %#v", invalid)
	}
}

func TestValidateRequestedScopes_NonOIDCClient_RejectsOIDCScopes(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read"},
	}
	nonOIDCClient := &models.MCPOAuthClient{Scope: ""}

	invalid := ValidateRequestedScopes([]string{"openid", "tools:read"}, rs, nonOIDCClient)
	if len(invalid) != 1 || invalid[0] != "openid" {
		t.Fatalf("expected [openid] invalid for non-OIDC client, got %#v", invalid)
	}
}

func TestValidateRequestedScopes_OIDCClient_AcceptsOIDCScopes(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read"},
	}
	oidcClient := &models.MCPOAuthClient{Scope: "openid profile email"}

	invalid := ValidateRequestedScopes([]string{"openid", "profile", "tools:read"}, rs, oidcClient)
	if len(invalid) != 0 {
		t.Fatalf("expected no invalid scopes for OIDC client, got %#v", invalid)
	}
}

// --- Helper function tests ---

func TestIsOIDCCoreScope(t *testing.T) {
	tests := []struct {
		scope string
		want  bool
	}{
		{"openid", true},
		{"profile", true},
		{"email", true},
		{"offline_access", true},
		{"address", true},
		{"phone", true},
		{"tools:read", false},
		{"admin:*", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsOIDCCoreScope(tt.scope); got != tt.want {
			t.Errorf("IsOIDCCoreScope(%q) = %v, want %v", tt.scope, got, tt.want)
		}
	}
}

func TestClientIsOIDC(t *testing.T) {
	tests := []struct {
		name   string
		client *models.MCPOAuthClient
		want   bool
	}{
		{"nil client", nil, false},
		{"empty scope", &models.MCPOAuthClient{Scope: ""}, false},
		{"no openid", &models.MCPOAuthClient{Scope: "tools:read tools:write"}, false},
		{"has openid", &models.MCPOAuthClient{Scope: "openid profile email"}, true},
		{"openid only", &models.MCPOAuthClient{Scope: "openid"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientIsOIDC(tt.client); got != tt.want {
				t.Errorf("clientIsOIDC() = %v, want %v", got, tt.want)
			}
		})
	}
}
