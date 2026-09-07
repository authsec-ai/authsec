package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// countingProvider counts the calls that cost API quota, so a scan's cost can
// be asserted rather than assumed. Everything not counted is inherited.
type countingProvider struct {
	*services.FixtureProvider
	trees, dirs, blobs, codeowners int
}

func (c *countingProvider) ListCodeowners(ctx context.Context, in services.ProviderContext, s services.ProviderScope) ([]services.CodeownerRule, error) {
	c.codeowners++
	return c.FixtureProvider.ListCodeowners(ctx, in, s)
}

func (c *countingProvider) ListTree(ctx context.Context, in services.ProviderContext, s services.ProviderScope) ([]services.TreeEntry, bool, error) {
	c.trees++
	return c.FixtureProvider.ListTree(ctx, in, s)
}

func (c *countingProvider) ListTreeDir(ctx context.Context, in services.ProviderContext, s services.ProviderScope, dir string) ([]services.TreeEntry, error) {
	c.dirs++
	return c.FixtureProvider.ListTreeDir(ctx, in, s, dir)
}

func (c *countingProvider) FetchBlob(ctx context.Context, in services.ProviderContext, s services.ProviderScope, e services.TreeEntry) ([]byte, error) {
	c.blobs++
	return c.FixtureProvider.FetchBlob(ctx, in, s, e)
}

// oneRepoProvider is a deterministic single-repository fixture: three paths, of
// which exactly one is a declaration the catalogue names.
func oneRepoProvider() *countingProvider {
	manifest, _ := json.Marshal(map[string]interface{}{
		"name":  "cost-probe-agent",
		"model": "gpt-4o",
	})
	return &countingProvider{FixtureProvider: &services.FixtureProvider{
		ProviderName: "github",
		Caps:         map[string]string{models.ClassRepoDeclaration: models.CoverageComplete},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-cost", DisplayName: "acme/cost", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-cost": {
				{Path: "README.md", SHA: "r1", Size: 10},
				{Path: "agent.json", SHA: "a1", Size: int64(len(manifest))},
				{Path: "docs/guide.md", SHA: "d1", Size: 20},
			},
		},
		Blobs: map[string][]byte{"repo-cost:agent.json": manifest},
	}}
}

func repoScanSource(t *testing.T, disco services.DiscoveryManager, ws uuid.UUID, name string) uuid.UUID {
	t.Helper()
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: name,
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories":    map[string]interface{}{"mode": "all"},
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	return src.ID
}

// A scan costs one tree listing plus one fetch per MATCHED path — not per path
// in the repository.
//
// This is the constraint that makes repository scanning sellable at all: a
// 30,000-file repository must cost a handful of calls, not 30,000. Asserting it
// by request count is the only way it stays true, because a stray fetch outside
// the match check is invisible in the results.
func TestGitHubScanCostIsOneTreePlusMatchedBlobs(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-cost")
	srcID := repoScanSource(t, disco, ws, "acme-cost")

	p := oneRepoProvider()
	res, err := services.NewGitHubRepoScannerWithProvider(db, p).
		Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("cost: tree_calls=%d dir_calls=%d blob_fetches=%d (3 paths, 1 matched)",
		p.trees, p.dirs, p.blobs)

	if p.trees != 1 {
		t.Fatalf("expected exactly 1 recursive tree listing, got %d", p.trees)
	}
	if p.blobs != 1 {
		t.Fatalf("expected exactly 1 blob fetch for the 1 matched path, got %d", p.blobs)
	}
	// No recovery calls: the tree was not truncated, so there is nothing to
	// recover and spending calls on it would be pure waste.
	if p.dirs != 0 {
		t.Fatalf("an untruncated tree must trigger no per-directory listing, got %d", p.dirs)
	}
	if res.FilesFetched != 1 || res.SightingsNew != 1 {
		t.Fatalf("expected 1 fetched file and 1 new sighting, got fetched=%d new=%d",
			res.FilesFetched, res.SightingsNew)
	}
	t.Log("PASS: 1 tree call + 1 fetch for the only matched path; unmatched paths never fetched")
}

// Re-scanning an unchanged repository fetches ZERO blobs and still advances
// last-seen for every finding.
//
// Both halves matter. Skipping the fetch is the cost win; still reporting the
// sighting is the correctness half — without it every unchanged agent decays
// into looking stale, so the inventory would imply "possibly gone" for exactly
// the declarations the scan just confirmed are still there.
func TestGitHubRescanSkipsUnchangedBlobsButAdvancesLastSeen(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-incremental")
	srcID := repoScanSource(t, disco, ws, "acme-incremental")

	p := oneRepoProvider()
	scanner := services.NewGitHubRepoScannerWithProvider(db, p)

	first, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if first.FilesFetched != 1 || first.BlobsSkipped != 0 {
		t.Fatalf("first scan should fetch, not skip: fetched=%d skipped=%d",
			first.FilesFetched, first.BlobsSkipped)
	}

	var seenBefore time.Time
	db.Raw(`SELECT last_seen_at FROM discovered_agents
	        WHERE workspace_id=? AND source=?`, ws, models.DiscoverySourceRepoScan).Scan(&seenBefore)
	if seenBefore.IsZero() {
		t.Fatal("expected a sighting row after the first scan")
	}

	blobsAfterFirst := p.blobs
	second, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	t.Logf("rescan: fetched=%d skipped=%d bumped=%d (provider blob calls %d -> %d)",
		second.FilesFetched, second.BlobsSkipped, second.SightingsBumped,
		blobsAfterFirst, p.blobs)

	// Zero blobs fetched — at the provider AND in the report.
	if p.blobs != blobsAfterFirst {
		t.Fatalf("an unchanged blob must not be fetched again: provider calls went %d -> %d",
			blobsAfterFirst, p.blobs)
	}
	if second.FilesFetched != 0 {
		t.Fatalf("rescan of an unchanged repository must fetch 0 blobs, got %d", second.FilesFetched)
	}
	if second.BlobsSkipped != 1 {
		t.Fatalf("expected 1 skipped unchanged blob, got %d", second.BlobsSkipped)
	}

	// Last-seen still advanced, and the row was not duplicated.
	var seenAfter time.Time
	var rows int64
	db.Raw(`SELECT last_seen_at FROM discovered_agents
	        WHERE workspace_id=? AND source=?`, ws, models.DiscoverySourceRepoScan).Scan(&seenAfter)
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND source=?`, ws, models.DiscoverySourceRepoScan).Scan(&rows)
	if !seenAfter.After(seenBefore) {
		t.Fatalf("last_seen_at must advance on a skipped-but-confirmed finding: %v -> %v",
			seenBefore, seenAfter)
	}
	if rows != 1 {
		t.Fatalf("a rescan must upsert, not duplicate: %d rows", rows)
	}

	// The facts survived the empty-metadata touch: skipping the fetch must not
	// erase what the first scan learned.
	var kept int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND metadata->>'blob_sha' = ?`, ws, "a1").Scan(&kept)
	if kept != 1 {
		t.Fatal("the stored evidence must survive an incremental touch")
	}
	t.Log("PASS: 0 blobs fetched, 1 skipped, last_seen advanced, evidence preserved")
}

// A truncated tree recovers the catalogue's directories and still reports the
// scope incomplete.
//
// Recovery narrows the gap; it cannot close it. A rule whose glob is a bare
// basename can match at any depth, and those depths were never walked — so the
// honest result is "more findings AND still partial", never a restored
// all-clear.
func TestGitHubTruncatedTreeRecoversCatalogueDirectories(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-truncated")
	srcID := repoScanSource(t, disco, ws, "acme-truncated")

	workflow := []byte("on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n" +
		"      - uses: anthropics/claude-code-action@v1\n")

	// The truncated recursive tree shows only the README. The workflow exists
	// but fell past the cut-off, so recovery is the only way to see it.
	p := &countingProvider{FixtureProvider: &services.FixtureProvider{
		ProviderName: "github",
		Caps:         map[string]string{models.ClassRepoDeclaration: models.CoverageComplete},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-big", DisplayName: "acme/big", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-big": {{Path: "README.md", SHA: "r1", Size: 10}},
		},
		Truncated: map[string]bool{"repo-big": true},
		DirTrees: map[string][]services.TreeEntry{
			"repo-big:.github/workflows": {
				{Path: ".github/workflows/agent.yml", SHA: "w1", Size: int64(len(workflow))},
			},
		},
		Blobs: map[string][]byte{"repo-big:.github/workflows/agent.yml": workflow},
	}}

	res, err := services.NewGitHubRepoScannerWithProvider(db, p).
		Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("truncated: recovered=%d fetched=%d new=%d dir_calls=%d complete=%v",
		res.PathsRecovered, res.FilesFetched, res.SightingsNew, p.dirs, res.Complete)

	if res.ReposTruncated != 1 {
		t.Fatalf("expected the repository counted as truncated, got %d", res.ReposTruncated)
	}
	if p.dirs == 0 {
		t.Fatal("a truncated tree must trigger per-directory recovery")
	}
	if res.PathsRecovered < 1 {
		t.Fatalf("expected at least 1 path recovered past the cut-off, got %d", res.PathsRecovered)
	}
	// The recovered declaration became a real finding.
	if res.SightingsNew < 1 {
		t.Fatalf("the recovered declaration should have produced a sighting, got %d", res.SightingsNew)
	}
	// And the honesty half: recovery must not upgrade the coverage claim.
	if res.Complete {
		t.Fatal("recovery narrows a truncated scan, it must never mark it complete")
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "truncated") && strings.Contains(w, "never inspected") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the warning must still state that paths outside the catalogue went uninspected, got %v",
			res.Warnings)
	}
	t.Logf("PASS: %d path(s) recovered into %d finding(s), scope still reported incomplete",
		res.PathsRecovered, res.SightingsNew)
}
