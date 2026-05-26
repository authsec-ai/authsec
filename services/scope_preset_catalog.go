package services

import (
	"strings"
	"unicode"
)

// PresetScopeDef is one scope inside a preset. The Suffix may contain template
// placeholders that are expanded at registration time:
//
//	<app>      → the Application's slugified name (see SlugForApp)
//	<resource> → a per-resource segment; these are template hints only and are
//	             NOT expanded by ExpandPresetScopes — operators map them later
//	             when wiring tools.
type PresetScopeDef struct {
	Suffix      string `json:"suffix"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// ScopePreset is a hardcoded starter set of scopes shown on the Create Application page.
type ScopePreset struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Category    string           `json:"category"` // common | domain | custom
	Description string           `json:"description"`
	Recommended bool             `json:"recommended"`
	Scopes      []PresetScopeDef `json:"scopes"`
}

// ScopePresetCatalog is the canonical list of 12 presets surfaced in the UI.
// IDs are part of the public contract — the frontend matches against them.
var ScopePresetCatalog = []ScopePreset{
	{ID: "read_only", Name: "Read only", Category: "common",
		Description: "Search / catalog / read-only servers",
		Scopes: []PresetScopeDef{
			{Suffix: "<app>:read", Description: "Read operations", Risk: "low"},
			{Suffix: "<app>:tools:read", Description: "List and call read-only tools", Risk: "low"},
		}},
	{ID: "read_write", Name: "Read + Write", Category: "common", Recommended: true,
		Description: "Default for most MCP servers",
		Scopes: []PresetScopeDef{
			{Suffix: "<app>:read", Description: "Read operations", Risk: "low"},
			{Suffix: "<app>:write", Description: "Write operations", Risk: "medium"},
			{Suffix: "<app>:tools:read", Description: "List and call read-only tools", Risk: "low"},
			{Suffix: "<app>:tools:write", Description: "Call mutating tools", Risk: "medium"},
		}},
	{ID: "read_write_admin", Name: "Read + Write + Admin", Category: "common",
		Description: "Adds destructive / privileged actions",
		Scopes: []PresetScopeDef{
			{Suffix: "<app>:read", Description: "Read operations", Risk: "low"},
			{Suffix: "<app>:write", Description: "Write operations", Risk: "medium"},
			{Suffix: "<app>:tools:read", Description: "List and call read-only tools", Risk: "low"},
			{Suffix: "<app>:tools:write", Description: "Call mutating tools", Risk: "medium"},
			{Suffix: "<app>:admin", Description: "Administrative actions", Risk: "critical"},
		}},
	{ID: "per_resource_crud", Name: "Per-resource CRUD", Category: "common",
		Description: "Tools span multiple resource kinds",
		Scopes: []PresetScopeDef{
			{Suffix: "<app>:<resource>:read", Description: "Per-resource read", Risk: "low"},
			{Suffix: "<app>:<resource>:write", Description: "Per-resource write", Risk: "medium"},
		}},
	{ID: "code_repos", Name: "Code & repos", Category: "domain",
		Description: "GitHub / GitLab MCP shape",
		Scopes: []PresetScopeDef{
			{Suffix: "repo:read", Description: "Read repositories and PRs", Risk: "low"},
			{Suffix: "pr:write", Description: "Comment and merge PRs", Risk: "medium"},
			{Suffix: "repo:admin", Description: "Destructive repo actions", Risk: "critical"},
		}},
	{ID: "messaging", Name: "Messaging", Category: "domain",
		Description: "Slack / Teams / Discord shape",
		Scopes: []PresetScopeDef{
			{Suffix: "messages:read", Description: "Read messages", Risk: "low"},
			{Suffix: "messages:send", Description: "Send messages", Risk: "medium"},
			{Suffix: "channels:admin", Description: "Manage channels", Risk: "critical"},
		}},
	{ID: "file_storage", Name: "File storage", Category: "domain",
		Description: "S3 / Drive / Dropbox shape",
		Scopes: []PresetScopeDef{
			{Suffix: "files:read", Description: "Read files", Risk: "low"},
			{Suffix: "files:write", Description: "Write files", Risk: "medium"},
			{Suffix: "files:delete", Description: "Delete files", Risk: "critical"},
		}},
	{ID: "workflow_actions", Name: "Workflow / actions", Category: "domain",
		Description: "Run-and-watch automation",
		Scopes: []PresetScopeDef{
			{Suffix: "jobs:read", Description: "Read job status", Risk: "low"},
			{Suffix: "jobs:trigger", Description: "Trigger jobs", Risk: "medium"},
			{Suffix: "jobs:cancel", Description: "Cancel jobs", Risk: "medium"},
		}},
	{ID: "database", Name: "Database", Category: "domain",
		Description: "Read-write SQL / NoSQL shape",
		Scopes: []PresetScopeDef{
			{Suffix: "query:read", Description: "Read queries", Risk: "low"},
			{Suffix: "query:write", Description: "Mutating queries", Risk: "medium"},
			{Suffix: "schema:admin", Description: "Schema changes", Risk: "critical"},
		}},
	{ID: "knowledge_rag", Name: "Knowledge / RAG", Category: "domain",
		Description: "Retrieval-augmented servers",
		Scopes: []PresetScopeDef{
			{Suffix: "docs:read", Description: "Read documents", Risk: "low"},
			{Suffix: "vectors:read", Description: "Read vector index", Risk: "low"},
			{Suffix: "docs:write", Description: "Index new documents", Risk: "medium"},
		}},
	{ID: "voice_agent", Name: "Voice agent", Category: "domain",
		Description: "Real-time + replay flows",
		Scopes: []PresetScopeDef{
			{Suffix: "sessions:create", Description: "Start voice sessions", Risk: "medium"},
			{Suffix: "recordings:read", Description: "Replay recordings", Risk: "low"},
		}},
	{ID: "blank", Name: "Blank", Category: "custom",
		Description: "Start closed with no starter scopes",
		Scopes:      []PresetScopeDef{}},
}

// GetScopePreset returns the preset with the given id and a found flag.
func GetScopePreset(id string) (*ScopePreset, bool) {
	for i := range ScopePresetCatalog {
		if ScopePresetCatalog[i].ID == id {
			return &ScopePresetCatalog[i], true
		}
	}
	return nil, false
}

// SlugForApp converts a free-form Application name to a slug usable in scope
// strings. Rules: lowercase; whitespace and hyphens become underscores; any
// non-alphanumeric (other than underscore) characters are stripped; consecutive
// underscores collapsed; trimmed and capped at 32 chars.
//
//	"GitHub MCP Server" → "github_mcp_server"
//	"GitHub MCP"        → "github_mcp"
//	"Acme-Cloud!! 2"    → "acme_cloud_2"
func SlugForApp(name string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToLower(name) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevUnderscore = false
		case r == '_' || r == '-' || unicode.IsSpace(r):
			if !prevUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				prevUnderscore = true
			}
		default:
			// stripped
		}
	}
	out := strings.TrimRight(b.String(), "_")
	if len(out) > 32 {
		out = strings.TrimRight(out[:32], "_")
	}
	return out
}

// ExpandPresetScopes returns canonical AuthSec scope strings for a preset with
// <app> expanded to the supplied slug. Domain presets are also namespaced under
// the app slug so server-defined scope vocabularies never become authoritative.
// Suffixes that still contain <resource> after app expansion are skipped — they
// are template hints, not concrete scopes.
func ExpandPresetScopes(preset *ScopePreset, appSlug string) []string {
	if preset == nil {
		return nil
	}
	out := make([]string, 0, len(preset.Scopes))
	for _, ss := range preset.Scopes {
		expanded := strings.ReplaceAll(ss.Suffix, "<app>", appSlug)
		if strings.Contains(expanded, "<resource>") {
			// Template only — not a concrete scope.
			continue
		}
		if appSlug != "" && !strings.HasPrefix(expanded, appSlug+":") {
			expanded = appSlug + ":" + expanded
		}
		out = append(out, expanded)
	}
	return out
}
