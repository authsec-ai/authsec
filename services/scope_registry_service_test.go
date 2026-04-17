package services

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// --- findParentScope tests (hierarchy resolution, pure function) ---

func TestFindParentScope_Leaf(t *testing.T) {
	// "tools:weather:read" → parent is "tools:weather:*"
	got := findParentScope("tools:weather:read")
	want := "tools:weather:*"
	if got != want {
		t.Errorf("findParentScope(%q) = %q, want %q", "tools:weather:read", got, want)
	}
}

func TestFindParentScope_Wildcard(t *testing.T) {
	// "tools:weather:*" → parent is "tools:*"
	got := findParentScope("tools:weather:*")
	want := "tools:*"
	if got != want {
		t.Errorf("findParentScope(%q) = %q, want %q", "tools:weather:*", got, want)
	}
}

func TestFindParentScope_TopLevelWildcard(t *testing.T) {
	// "tools:*" → no parent
	got := findParentScope("tools:*")
	if got != "" {
		t.Errorf("findParentScope(%q) = %q, want empty", "tools:*", got)
	}
}

func TestFindParentScope_SinglePart(t *testing.T) {
	// "openid" → no parent
	got := findParentScope("openid")
	if got != "" {
		t.Errorf("findParentScope(%q) = %q, want empty", "openid", got)
	}
}

func TestFindParentScope_FlatScope(t *testing.T) {
	// "weather:read" → "weather:*"
	got := findParentScope("weather:read")
	want := "weather:*"
	if got != want {
		t.Errorf("findParentScope(%q) = %q, want %q", "weather:read", got, want)
	}
}

func TestFindParentScope_DeepHierarchy(t *testing.T) {
	// "mcp:tools:weather:read" → "mcp:tools:weather:*"
	got := findParentScope("mcp:tools:weather:read")
	want := "mcp:tools:weather:*"
	if got != want {
		t.Errorf("findParentScope(%q) = %q, want %q", "mcp:tools:weather:read", got, want)
	}
}

func TestFindParentScope_DeepWildcard(t *testing.T) {
	// "mcp:tools:weather:*" → "mcp:tools:*"
	got := findParentScope("mcp:tools:weather:*")
	want := "mcp:tools:*"
	if got != want {
		t.Errorf("findParentScope(%q) = %q, want %q", "mcp:tools:weather:*", got, want)
	}
}

// --- generateDisplayName tests ---

func TestGenerateDisplayName(t *testing.T) {
	tests := []struct {
		scope string
		want  string
	}{
		{"tools:weather:read", "Weather - Read"},
		{"tools:weather:*", "Weather - All"},
		{"mcp:tools:calendar:write", "Tools - Calendar - Write"},
		{"files:read", "Files - Read"},
		{"openid", "Openid"},
		{"admin:*", "Admin - All"},
		{"tools:get_weather:invoke", "Get Weather - Invoke"},
	}
	for _, tt := range tests {
		got := generateDisplayName(tt.scope)
		if got != tt.want {
			t.Errorf("generateDisplayName(%q) = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

// --- inferRiskLevel tests ---

func TestInferRiskLevel(t *testing.T) {
	tests := []struct {
		scope string
		want  string
	}{
		{"admin:*", "critical"},
		{"files:delete", "critical"},
		{"tools:weather:write", "medium"},
		{"resources:create", "medium"},
		{"tools:weather:update", "medium"},
		{"tools:*", "high"},
		{"mcp:tools:*", "high"},
		{"tools:weather:read", "low"},
		{"files:list", "low"},
		{"openid", "low"},
	}
	for _, tt := range tests {
		got := inferRiskLevel(tt.scope)
		if got != tt.want {
			t.Errorf("inferRiskLevel(%q) = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

// --- ancestorInSet tests (wildcard matching) ---

func TestAncestorInSet_DirectMatch(t *testing.T) {
	svc := &ScopeRegistryService{}
	scope := models_stub{scopeStr: "tools:weather:read"}
	grantedSet := map[string]bool{"tools:weather:*": true}

	got := svc.ancestorInSet(scope.toOAuthScope(), nil, grantedSet)
	if !got {
		t.Error("expected tools:weather:* to cover tools:weather:read")
	}
}

func TestAncestorInSet_GrandparentMatch(t *testing.T) {
	svc := &ScopeRegistryService{}
	scope := models_stub{scopeStr: "tools:weather:read"}
	grantedSet := map[string]bool{"tools:*": true}

	got := svc.ancestorInSet(scope.toOAuthScope(), nil, grantedSet)
	if !got {
		t.Error("expected tools:* to cover tools:weather:read")
	}
}

func TestAncestorInSet_NoMatch(t *testing.T) {
	svc := &ScopeRegistryService{}
	scope := models_stub{scopeStr: "tools:weather:read"}
	grantedSet := map[string]bool{"files:*": true}

	got := svc.ancestorInSet(scope.toOAuthScope(), nil, grantedSet)
	if got {
		t.Error("expected files:* NOT to cover tools:weather:read")
	}
}

func TestAncestorInSet_SinglePart(t *testing.T) {
	svc := &ScopeRegistryService{}
	scope := models_stub{scopeStr: "openid"}
	grantedSet := map[string]bool{"openid": true}

	// Single part has no wildcard ancestor, direct set match is separate logic
	got := svc.ancestorInSet(scope.toOAuthScope(), nil, grantedSet)
	if got {
		t.Error("single-part scope should not have wildcard ancestor match")
	}
}

// --- helpers ---

type models_stub struct {
	scopeStr string
}

func (m models_stub) toOAuthScope() models.OAuthScope {
	return models.OAuthScope{ScopeString: m.scopeStr}
}
