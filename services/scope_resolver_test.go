package services

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/lib/pq"
)

func TestResolveGrantableScopes_NilRS_ReturnsNothing(t *testing.T) {
	resolver := NewScopeResolver()

	got := resolver.ResolveGrantableScopes(
		[]string{"tools:read", "tools:write"},
		nil, // no RS = fail-closed
		nil,
		"",
	)

	if len(got) != 0 {
		t.Fatalf("expected 0 scopes for nil RS (fail-closed), got %d: %#v", len(got), got)
	}
}

func TestResolveGrantableScopes_EmptyScopes_ReturnsNothing(t *testing.T) {
	resolver := NewScopeResolver()

	rs := &models.ResourceServer{
		ScopesSupported: []string{},
	}

	got := resolver.ResolveGrantableScopes(
		[]string{"tools:read", "tools:write"},
		rs,
		nil,
		"",
	)

	if len(got) != 0 {
		t.Fatalf("expected 0 scopes for empty scopes_supported (fail-closed), got %d: %#v", len(got), got)
	}
}

func TestResolveGrantableScopes_IntersectsWithRS(t *testing.T) {
	resolver := NewScopeResolver()

	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read", "tools:write", "tools:admin"},
	}

	got := resolver.ResolveGrantableScopes(
		[]string{"tools:read", "", "tools:write", "tools:read", "tools:unknown"},
		rs,
		nil,
		"",
	)

	// Should return intersection, deduped, blanks removed, order preserved
	want := []string{"tools:read", "tools:write"}
	if len(got) != len(want) {
		t.Fatalf("expected %d scopes, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scope mismatch at %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestValidateRequestedScopes_EmptyRS_RejectsAll(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: []string{},
	}

	invalid := ValidateRequestedScopes([]string{"tools:read"}, rs)
	if len(invalid) != 1 || invalid[0] != "tools:read" {
		t.Fatalf("expected all scopes rejected for empty RS, got invalid=%#v", invalid)
	}
}

func TestValidateRequestedScopes_ReturnsInvalid(t *testing.T) {
	rs := &models.ResourceServer{
		ScopesSupported: pq.StringArray{"tools:read", "tools:write"},
	}

	invalid := ValidateRequestedScopes([]string{"tools:read", "tools:hack"}, rs)
	if len(invalid) != 1 || invalid[0] != "tools:hack" {
		t.Fatalf("expected [tools:hack] invalid, got %#v", invalid)
	}
}
