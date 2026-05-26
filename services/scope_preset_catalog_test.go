package services

import (
	"testing"
)

func TestSlugForApp(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"GitHub MCP Server", "github_mcp_server"},
		{"GitHub MCP", "github_mcp"},
		{"Acme-Cloud!! 2", "acme_cloud_2"},
		{"  leading  trailing  ", "leading_trailing"},
		{"hello", "hello"},
		{"a/b\\c", "abc"},
		{"___mixed---spaces   here", "mixed_spaces_here"},
		// Cap at 32 chars, trim trailing underscores after the cap.
		{"this_is_a_very_long_application_name_that_should_be_truncated",
			"this_is_a_very_long_application"},
	}
	for _, c := range cases {
		got := SlugForApp(c.in)
		if got != c.want {
			t.Errorf("SlugForApp(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(got) > 32 {
			t.Errorf("SlugForApp(%q) length %d > 32", c.in, len(got))
		}
	}
}

func TestGetScopePreset(t *testing.T) {
	t.Parallel()

	if len(ScopePresetCatalog) != 12 {
		t.Fatalf("expected 12 presets in catalog, got %d", len(ScopePresetCatalog))
	}

	// Spot-check well-known IDs.
	for _, id := range []string{"read_only", "read_write", "read_write_admin",
		"per_resource_crud", "code_repos", "messaging", "file_storage",
		"workflow_actions", "database", "knowledge_rag", "voice_agent", "blank"} {
		p, ok := GetScopePreset(id)
		if !ok {
			t.Errorf("GetScopePreset(%q) not found", id)
			continue
		}
		if p.ID != id {
			t.Errorf("GetScopePreset(%q).ID = %q", id, p.ID)
		}
	}

	if _, ok := GetScopePreset("nonexistent"); ok {
		t.Error("expected GetScopePreset(\"nonexistent\") to return ok=false")
	}

	// Exactly one preset should be flagged Recommended.
	recommended := 0
	for _, p := range ScopePresetCatalog {
		if p.Recommended {
			recommended++
		}
	}
	if recommended != 1 {
		t.Errorf("expected exactly 1 recommended preset, got %d", recommended)
	}
}

func TestExpandPresetScopes(t *testing.T) {
	t.Parallel()

	// read_write: all concrete scopes are namespaced under <app>.
	rw, ok := GetScopePreset("read_write")
	if !ok {
		t.Fatal("read_write preset missing")
	}
	got := ExpandPresetScopes(rw, "github_mcp")
	want := []string{"github_mcp:read", "github_mcp:write", "github_mcp:tools:read", "github_mcp:tools:write"}
	if !equalStringSlices(got, want) {
		t.Errorf("ExpandPresetScopes(read_write) = %v, want %v", got, want)
	}

	// per_resource_crud: every suffix has <resource> — all should be skipped.
	prc, _ := GetScopePreset("per_resource_crud")
	got = ExpandPresetScopes(prc, "myapp")
	if len(got) != 0 {
		t.Errorf("ExpandPresetScopes(per_resource_crud) expected 0 concrete scopes, got %v", got)
	}

	// code_repos: domain-shape suffixes are still namespaced under the app slug.
	cr, _ := GetScopePreset("code_repos")
	got = ExpandPresetScopes(cr, "anything")
	want = []string{"anything:repo:read", "anything:pr:write", "anything:repo:admin"}
	if !equalStringSlices(got, want) {
		t.Errorf("ExpandPresetScopes(code_repos) = %v, want %v", got, want)
	}

	// blank: empty preset returns empty.
	bl, _ := GetScopePreset("blank")
	got = ExpandPresetScopes(bl, "any")
	if len(got) != 0 {
		t.Errorf("ExpandPresetScopes(blank) expected empty, got %v", got)
	}

	// nil preset is safe.
	if got := ExpandPresetScopes(nil, "x"); got != nil {
		t.Errorf("ExpandPresetScopes(nil) = %v, want nil", got)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
