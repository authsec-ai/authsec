package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// A selected repository the installation never exposed must be reported BY NAME.
//
// This is the coverage hole that hides itself. The scan loop walks the live
// grant, so a plan entry absent from that grant is never visited and never
// mentioned: the stored plan still claims the repository is covered, the result
// still says complete, and nobody learns the grant was never made. The admin's
// own words — the name they typed — are the only usable signal here, because
// the provider cannot name a repository it declined to show us.
func TestGitHubSelectedButNotGrantedIsNamed(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-ungranted")

	// acme/payments is in the fixture grant; acme/ghost never is.
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-with-ghost",
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories": map[string]interface{}{
				"mode":    "selected",
				"include": []string{"acme/payments", "acme/ghost"},
			},
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	scanner := services.NewGitHubRepoScannerWithProvider(db, fixtures())
	res, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("scan: scanned=%d excluded=%d not_granted=%d failed=%d complete=%v",
		res.ReposScanned, res.ReposExcluded, res.ReposSelectedNotGranted,
		res.ReposFailed, res.Complete)

	if res.ReposSelectedNotGranted != 1 {
		t.Fatalf("expected exactly 1 selected-but-not-granted repository, got %d",
			res.ReposSelectedNotGranted)
	}
	var named bool
	for _, n := range res.SelectedNotGranted {
		if n == "acme/ghost" {
			named = true
		}
	}
	if !named {
		t.Fatalf("the ungranted selection must be named in the result, got %v",
			res.SelectedNotGranted)
	}

	// It is not a failure: no call was ever attempted against it.
	if res.ReposFailed != 0 {
		t.Fatalf("an ungranted selection is not a fetch failure, got failed=%d", res.ReposFailed)
	}

	// And it appears in the excluded roll-up too, by BARE name — the ticket
	// says an ungranted include "appears as excluded, with its name", and a
	// consumer matching on the repository it asked for needs an exact match.
	var inExcluded bool
	for _, n := range res.Excluded {
		if n == "acme/ghost" {
			inExcluded = true
		}
	}
	if !inExcluded {
		t.Fatalf("an ungranted selection must also appear as excluded, by name; got %v", res.Excluded)
	}
	// The counter stays consistent with the list it summarises.
	if res.ReposExcluded != len(res.Excluded) {
		t.Fatalf("repos_excluded (%d) must match the named excluded list (%d)",
			res.ReposExcluded, len(res.Excluded))
	}

	// Part of the selected scope went uninspected, so the scan cannot claim to
	// be complete for that scope — otherwise a missing grant reads as an
	// all-clear.
	if res.Complete {
		t.Fatal("a scan that never reached a selected repository is not complete for the selected scope")
	}

	// The warning must carry the name too, so an operator reading only the
	// warning list can act without cross-referencing the counters.
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "acme/ghost") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected a warning naming the ungranted repository, got %v", res.Warnings)
	}

	// The granted half still scanned normally: one bad plan entry must not
	// cost the coverage we do have.
	if res.ReposScanned != 1 {
		t.Fatalf("the granted selection should still be scanned, got %d", res.ReposScanned)
	}
	t.Logf("PASS: %v named, kept distinct from failures and exclusions, scope marked incomplete",
		res.SelectedNotGranted)
}

// The grant disclosure travels in the payload, not in UI copy.
//
// A client that renders counters without it shows an organisation-wide claim
// the scan cannot support. Carrying it as an unconditional field is what stops
// the omission from being possible by accident.
func TestGitHubScanResultCarriesGrantDisclosure(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-disclosure")

	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-disclosure",
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories":    map[string]interface{}{"mode": "all"},
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	scanner := services.NewGitHubRepoScannerWithProvider(db, fixtures())
	res, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if res.Disclosure == "" {
		t.Fatal("the scan result must carry the grant disclosure, not leave it to UI copy")
	}
	// Serialised, because the field only does its job if a client receives it.
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(blob, &wire); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	got, ok := wire["disclosure"].(string)
	if !ok || got == "" {
		t.Fatalf("disclosure missing from the serialised payload: %s", blob)
	}
	if !strings.Contains(got, "not evidence") {
		t.Fatalf("the disclosure must say absence is not evidence of no agents, got %q", got)
	}
	t.Logf("PASS: disclosure shipped in the payload: %q", got)
}

// An archived repository is scanned and annotated, never silently skipped.
//
// Read-only is not empty. An archived repository still names real secrets and
// runtimes, so skipping it would shrink coverage without saying so — the
// failure mode this whole surface exists to prevent. The annotation is what
// lets a reviewer discount a finding they cannot merge a fix for.
func TestGitHubArchivedRepositoryIsScannedAndFlagged(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-archived")

	manifest, _ := json.Marshal(map[string]interface{}{
		"name":        "legacy-triage-agent",
		"description": "left behind in an archived repo",
		"model":       "gpt-4o",
	})
	provider := &services.FixtureProvider{
		ProviderName: "github",
		Caps:         map[string]string{models.ClassRepoDeclaration: models.CoverageComplete},
		Scopes: []services.ProviderScope{
			{
				Kind: "repository", NativeID: "repo-arch",
				DisplayName: "acme/retired", DefaultBranch: "main", Archived: true,
			},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-arch": {{Path: "agent.json", SHA: "sha-arch", Size: int64(len(manifest))}},
		},
		Blobs: map[string][]byte{"repo-arch:agent.json": manifest},
	}

	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-archived",
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories":    map[string]interface{}{"mode": "all"},
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	// The selection surface flags it before any budget is spent.
	scanner := services.NewGitHubRepoScannerWithProvider(db, provider)
	choices, err := scanner.ListSelectableRepositories(context.Background(), ws, src.ID)
	if err != nil {
		t.Fatalf("list selectable: %v", err)
	}
	if len(choices) != 1 || !choices[0].Archived {
		t.Fatalf("the selection surface must flag an archived repository, got %+v", choices)
	}

	res, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("scan: scanned=%d archived=%d sightings_new=%d complete=%v",
		res.ReposScanned, res.ReposArchived, res.SightingsNew, res.Complete)

	// Scanned, not skipped.
	if res.ReposScanned != 1 {
		t.Fatalf("an archived repository must still be scanned, got scanned=%d", res.ReposScanned)
	}
	if res.ReposArchived != 1 || len(res.Archived) != 1 || res.Archived[0] != "acme/retired" {
		t.Fatalf("the archived repository must be named in the result, got %d/%v",
			res.ReposArchived, res.Archived)
	}
	if res.SightingsNew == 0 {
		t.Fatal("the declaration inside the archived repository should have been reported")
	}

	// The annotation reached the inventory row, so a reviewer can see why the
	// finding cannot be fixed in place.
	var flagged int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND metadata->>'repository_archived' = 'true'`, ws).Scan(&flagged)
	if flagged == 0 {
		t.Fatal("expected the sighting metadata to record repository_archived")
	}
	t.Logf("PASS: archived repository scanned, named in the result, and %d row(s) annotated", flagged)
}
