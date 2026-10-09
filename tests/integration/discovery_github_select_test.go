package integration

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// The scan plan is explicit: a repository is selected or excluded, and an
// excluded repository is reported rather than silently contributing nothing.
// "We chose not to look" must never look like "there was nothing there".
func TestGitHubRepoSelectionIsExplicit(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-select")

	// A source that selects ONE of the three fixture repositories.
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-selected",
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories": map[string]interface{}{
				"mode": "selected", "include": []string{"acme/payments"},
			},
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	scanner := services.NewGitHubRepoScannerWithProvider(db, fixtures())

	// The selection surface lists what the installation exposes, marking the plan.
	choices, err := scanner.ListSelectableRepositories(context.Background(), ws, src.ID)
	if err != nil {
		t.Fatalf("list selectable: %v", err)
	}
	if len(choices) != 3 {
		t.Fatalf("expected all 3 installation repos offered, got %d", len(choices))
	}
	selected := 0
	for _, c := range choices {
		if c.Selected {
			selected++
			if c.FullName != "acme/payments" {
				t.Fatalf("wrong repo marked selected: %s", c.FullName)
			}
		}
	}
	if selected != 1 {
		t.Fatalf("expected exactly 1 repo marked selected, got %d", selected)
	}
	t.Logf("PASS: 3 repositories offered, 1 marked selected")

	res, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("scan: mode=%s scanned=%d excluded=%d failed=%d complete=%v",
		res.SelectionMode, res.ReposScanned, res.ReposExcluded, res.ReposFailed, res.Complete)

	if res.ReposScanned != 1 {
		t.Fatalf("only the selected repository should be scanned, got %d", res.ReposScanned)
	}
	// The two unselected repos must be reported, not silently dropped.
	if res.ReposExcluded != 2 || len(res.Excluded) != 2 {
		t.Fatalf("expected 2 excluded repositories named in the result, got %d/%v",
			res.ReposExcluded, res.Excluded)
	}
	// Excluding is a choice, not a failure: the denied repo was never reached.
	if res.ReposFailed != 0 {
		t.Fatalf("an excluded repository must not count as a failure, got %d", res.ReposFailed)
	}
	t.Logf("PASS: excluded repositories named (%v) and kept distinct from failures", res.Excluded)

	// Widening the plan to "all" reaches the rest, including the 403 repo,
	// which now correctly counts as a failure rather than an exclusion.
	if _, err := disco.UpdateSource(ws, src.ID, services.DiscoverySourceUpdateInput{
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories":    map[string]interface{}{"mode": "all"},
		},
	}); err != nil {
		t.Fatalf("widen plan: %v", err)
	}
	res2, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if res2.ReposExcluded != 0 {
		t.Fatalf(`mode "all" should exclude nothing, got %d`, res2.ReposExcluded)
	}
	if res2.ReposFailed == 0 {
		t.Fatal("the denied repository should now be reached and counted as failed")
	}
	if res2.Complete {
		t.Fatal("a scan with a denied repo and a truncated tree is not complete")
	}
	t.Logf("PASS: widening to all reached %d repos, %d failed, complete=%v",
		res2.ReposScanned, res2.ReposFailed, res2.Complete)
}
