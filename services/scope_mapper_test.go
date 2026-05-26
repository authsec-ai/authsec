package services

import (
	"testing"

	mcpclient "github.com/authsec-ai/authsec/internal/mcp"
)

func makeTools(names ...string) []mcpclient.Tool {
	tools := make([]mcpclient.Tool, len(names))
	for i, n := range names {
		tools[i] = mcpclient.Tool{Name: n}
	}
	return tools
}

func TestMapToolsToScopes_ExactMatch(t *testing.T) {
	tools := makeTools("get_weather")
	scopes := []string{"tools:get_weather:read", "tools:get_weather:write"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d: %+v", len(mappings), mappings)
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %d: %v", len(unmapped), unmapped)
	}
	for _, m := range mappings {
		if m.ToolName != "get_weather" {
			t.Errorf("expected tool name 'get_weather', got %q", m.ToolName)
		}
		if !m.AutoMatched {
			t.Error("expected AutoMatched=true")
		}
	}
}

func TestMapToolsToScopes_WildcardMatch(t *testing.T) {
	tools := makeTools("get_weather")
	scopes := []string{"tools:get_weather:*"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if mappings[0].ScopeString != "tools:get_weather:*" {
		t.Errorf("expected scope 'tools:get_weather:*', got %q", mappings[0].ScopeString)
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_MCPPrefixed(t *testing.T) {
	tools := makeTools("get_weather")
	scopes := []string{"mcp:tools:get_weather:read", "mcp:tools:get_weather:*"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_FlatMatch(t *testing.T) {
	tools := makeTools("weather")
	scopes := []string{"weather:read", "weather:write"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
	for _, m := range mappings {
		if m.ToolName != "weather" {
			t.Errorf("expected tool name 'weather', got %q", m.ToolName)
		}
	}
}

func TestMapToolsToScopes_GlobalWildcard(t *testing.T) {
	tools := makeTools("get_weather", "set_alert", "list_events")
	scopes := []string{"tools:*"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	// Global wildcard maps to ALL tools
	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings for tools:*, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_AuthSecCanonicalGlobalToolScope(t *testing.T) {
	tools := makeTools("get_weather", "set_alert")
	scopes := []string{"demo:tools:read"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 2 {
		t.Fatalf("expected canonical global tool scope to map to every tool, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_AuthSecCanonicalPerToolScope(t *testing.T) {
	tools := makeTools("get-weather", "set_alert")
	scopes := []string{"demo:tool:get_weather:invoke"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 1 {
		t.Fatalf("expected one per-tool mapping, got %d", len(mappings))
	}
	if mappings[0].ToolName != "get-weather" {
		t.Fatalf("expected original tool name, got %q", mappings[0].ToolName)
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_MCPGlobalWildcard(t *testing.T) {
	tools := makeTools("get_weather", "set_alert")
	scopes := []string{"mcp:tools:*"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings for mcp:tools:*, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_UnmappedScopes(t *testing.T) {
	tools := makeTools("get_weather")
	scopes := []string{"tools:get_weather:read", "admin:*", "system:health"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if len(unmapped) != 2 {
		t.Fatalf("expected 2 unmapped, got %d: %v", len(unmapped), unmapped)
	}
	if unmapped[0] != "admin:*" || unmapped[1] != "system:health" {
		t.Errorf("unexpected unmapped: %v", unmapped)
	}
}

func TestMapToolsToScopes_HyphenNormalization(t *testing.T) {
	tools := makeTools("get-weather") // hyphen in tool name
	scopes := []string{"tools:get_weather:read"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping (hyphen→underscore normalization), got %d", len(mappings))
	}
	// Tool name should be the ORIGINAL (with hyphen)
	if mappings[0].ToolName != "get-weather" {
		t.Errorf("expected original tool name 'get-weather', got %q", mappings[0].ToolName)
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %v", unmapped)
	}
}

func TestMapToolsToScopes_NoTools(t *testing.T) {
	var tools []mcpclient.Tool
	scopes := []string{"tools:weather:read", "admin:*"}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings for empty tools, got %d", len(mappings))
	}
	if len(unmapped) != 2 {
		t.Fatalf("expected 2 unmapped, got %d", len(unmapped))
	}
}

func TestMapToolsToScopes_NoScopes(t *testing.T) {
	tools := makeTools("get_weather")
	var scopes []string

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 0 {
		t.Fatalf("expected 0 mappings for empty scopes, got %d", len(mappings))
	}
	if len(unmapped) != 0 {
		t.Fatalf("expected 0 unmapped, got %d", len(unmapped))
	}
}

func TestMapToolsToScopes_MultipleToolsMixed(t *testing.T) {
	tools := makeTools("get_weather", "create_event", "list_files")
	scopes := []string{
		"tools:get_weather:read",
		"tools:create_event:write",
		"tools:list_files:read",
		"admin:manage",
	}

	mappings, unmapped := MapToolsToScopes(tools, scopes)

	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings, got %d: %+v", len(mappings), mappings)
	}
	if len(unmapped) != 1 || unmapped[0] != "admin:manage" {
		t.Fatalf("expected [admin:manage] unmapped, got %v", unmapped)
	}
}

func TestResolveToolName_PreservesOriginal(t *testing.T) {
	tools := makeTools("get-weather")
	got := resolveToolName("get_weather", tools)
	if got != "get-weather" {
		t.Errorf("resolveToolName should return original 'get-weather', got %q", got)
	}
}

func TestResolveToolName_NoMatch(t *testing.T) {
	tools := makeTools("other_tool")
	got := resolveToolName("unknown", tools)
	if got != "unknown" {
		t.Errorf("resolveToolName should return candidate if no match, got %q", got)
	}
}
