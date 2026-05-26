package services

import (
	"strings"

	mcpclient "github.com/authsec-ai/authsec/internal/mcp"
)

// ToolScopeMapping represents a matched tool→scope pair.
type ToolScopeMapping struct {
	ToolName    string
	ScopeString string
	AutoMatched bool
}

// MapToolsToScopes matches MCP tools to OAuth scope strings by naming convention.
//
// Convention patterns (tried in order):
//  1. "tools:<tool_name>:<action>"   → exact match
//  2. "tools:<tool_name>:*"          → wildcard match
//  3. "mcp:tools:<tool_name>:<action>" → prefixed variant
//  4. "mcp:tools:<tool_name>:*"      → prefixed wildcard
//  5. "<tool_name>:<action>"         → flat match (e.g. "weather:read")
//  6. "tools:*"                      → global wildcard → maps to ALL tools
//  7. "<app>:tools:<action>"         → AuthSec canonical global tool scope
//  8. "<app>:tool:<tool_name>:<action>" → AuthSec canonical per-tool scope
//
// Scope strings that don't match any tool are returned as unmapped.
func MapToolsToScopes(tools []mcpclient.Tool, scopeStrings []string) ([]ToolScopeMapping, []string) {
	var mappings []ToolScopeMapping
	var unmapped []string

	// Build a set of tool names for quick lookup
	toolNames := make(map[string]bool, len(tools))
	for _, t := range tools {
		toolNames[t.Name] = true
		// Also normalize: replace hyphens with underscores
		toolNames[strings.ReplaceAll(t.Name, "-", "_")] = true
	}

	for _, scope := range scopeStrings {
		matched := false
		parts := strings.Split(scope, ":")

		switch {
		// "tools:<tool_name>:<action>" or "tools:<tool_name>:*"
		case len(parts) == 3 && parts[0] == "tools":
			toolName := parts[1]
			if toolNames[toolName] {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    resolveToolName(toolName, tools),
					ScopeString: scope,
					AutoMatched: true,
				})
				matched = true
			}

		// "mcp:tools:<tool_name>:<action>" or "mcp:tools:<tool_name>:*"
		case len(parts) == 4 && parts[0] == "mcp" && parts[1] == "tools":
			toolName := parts[2]
			if toolNames[toolName] {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    resolveToolName(toolName, tools),
					ScopeString: scope,
					AutoMatched: true,
				})
				matched = true
			}

		// "<tool_name>:<action>" — flat format (but NOT global wildcards like "tools:*")
		case len(parts) == 2 && scope != "tools:*" && scope != "mcp:tools:*":
			toolName := parts[0]
			if toolNames[toolName] {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    resolveToolName(toolName, tools),
					ScopeString: scope,
					AutoMatched: true,
				})
				matched = true
			}

		// "tools:*" or "mcp:tools:*" — global wildcard → maps to ALL tools
		case scope == "tools:*" || scope == "mcp:tools:*":
			for _, t := range tools {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    t.Name,
					ScopeString: scope,
					AutoMatched: true,
				})
			}
			matched = true

		// "<app>:tools:<action>" or "<app>:tools:*" — AuthSec canonical global
		// tool scope. Maps to every discovered tool; the app prefix is authoritative.
		case len(parts) == 3 && parts[1] == "tools":
			for _, t := range tools {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    t.Name,
					ScopeString: scope,
					AutoMatched: true,
				})
			}
			matched = true

		// "<app>:tool:<tool_name>:<action>" — AuthSec canonical per-tool scope.
		case len(parts) == 4 && parts[1] == "tool":
			toolName := parts[2]
			if toolNames[toolName] {
				mappings = append(mappings, ToolScopeMapping{
					ToolName:    resolveToolName(toolName, tools),
					ScopeString: scope,
					AutoMatched: true,
				})
				matched = true
			}
		}

		if !matched {
			unmapped = append(unmapped, scope)
		}
	}

	return mappings, unmapped
}

// resolveToolName returns the actual tool name (preserving original casing/hyphens).
func resolveToolName(candidate string, tools []mcpclient.Tool) string {
	for _, t := range tools {
		if t.Name == candidate || strings.ReplaceAll(t.Name, "-", "_") == candidate {
			return t.Name
		}
	}
	return candidate
}
