package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/services"
)

// customPatternFixtures holds one repository with a file the SHIPPED catalogue
// deliberately ignores: an agent manifest under a house-specific name.
func customPatternFixtures() *services.FixtureProvider {
	manifest, _ := json.Marshal(map[string]interface{}{
		"name": "housekeeping-bot", "model": "claude-sonnet-5",
		"apiKey": "sk-must-never-be-persisted",
	})
	return &services.FixtureProvider{
		ProviderName: "github",
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-c", DisplayName: "acme/custom", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-c": {{Path: "ops/housekeeping.bot.json", SHA: "sha-bot", Size: int64(len(manifest))}},
		},
		Blobs: map[string][]byte{"repo-c:ops/housekeeping.bot.json": manifest},
	}
}

// The whole point of configurable patterns: a customer names their manifests
// something we never shipped a rule for, and can be seen anyway — without a
// release.
func TestWorkspacePatternOverlayChangesWhatAScanFinds(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-patterns")
	catalogs := services.NewRuleCatalogService(db)
	scanner := services.NewGitHubRepoScannerWithProvider(db, customPatternFixtures())

	srcID := newScanSource(t, db, ws, "acme-custom", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
	})

	// Shipped catalogue: *.bot.json is not a pattern we know, so the file is
	// never even fetched.
	before, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	if before.SightingsNew != 0 || before.FilesFetched != 0 {
		t.Fatalf("the built-in catalogue should not match this file, got new=%d fetched=%d",
			before.SightingsNew, before.FilesFetched)
	}
	t.Log("PASS: unknown filename invisible to the shipped patterns, and never downloaded")

	// Teach this workspace the pattern — pointing a NEW glob at an EXISTING
	// parser, which is the common case and needs no release.
	overlay := services.RuleCatalogOverlay{CustomRules: []services.CustomRule{{
		ID: "custom.house-bot", Extractor: "manifest",
		PathGlobs:     []string{"*.bot.json"},
		EvidenceMode:  "deployment_declared",
		SensitiveKeys: []string{"apiKey"},
	}}}
	if _, err := catalogs.Save(ws, overlay, "admin"); err != nil {
		t.Fatalf("save overlay: %v", err)
	}

	after, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan after overlay: %v", err)
	}
	if after.SightingsNew != 1 {
		t.Fatalf("the configured pattern should have found the manifest, got new=%d fetched=%d",
			after.SightingsNew, after.FilesFetched)
	}
	t.Log("PASS: the same repository now yields a finding, with no code change")

	// The finding records which ruleset produced it, and the secret VALUE is
	// still not persisted — a custom rule does not get to loosen that.
	var meta []byte
	if err := db.Raw(`SELECT metadata FROM discovered_agents
	                  WHERE workspace_id = ? AND source = 'repo_scan'`, ws).
		Row().Scan(&meta); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var facts map[string]interface{}
	if err := json.Unmarshal(meta, &facts); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if facts["rule_id"] != "custom.house-bot" {
		t.Fatalf("finding should name the custom rule, got %v", facts["rule_id"])
	}
	cv, _ := facts["catalog_version"].(string)
	if cv == "" || cv == services.DefaultRuleCatalog().Version {
		t.Fatalf("a customised scan must stamp its own catalogue version, got %q", cv)
	}
	if string(meta) != "" && containsSecret(string(meta)) {
		t.Fatal("a custom rule must not be able to persist a secret value")
	}
	t.Logf("PASS: finding stamped catalog_version=%s, secret value still absent", cv)

	// Resetting returns the workspace to the shipped patterns.
	if err := catalogs.Reset(ws); err != nil {
		t.Fatalf("reset: %v", err)
	}
	cat, _, err := catalogs.Resolve(ws)
	if err != nil {
		t.Fatalf("resolve after reset: %v", err)
	}
	if cat.Version != services.DefaultRuleCatalog().Version {
		t.Fatalf("reset should restore the built-in version, got %q", cat.Version)
	}
	t.Log("PASS: reset restores the shipped catalogue")
}

func containsSecret(s string) bool {
	return len(s) > 0 && (indexOf(s, "sk-must-never-be-persisted") >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
