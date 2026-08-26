package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// twoMatchProvider is one repository holding TWO catalogue-matched declarations
// among unmatched noise, so "one fetch PER MATCHED PATH" can be distinguished
// from "one fetch total".
func twoMatchProvider() *countingProvider {
	manifest, _ := json.Marshal(map[string]interface{}{
		"name":  "multi-a",
		"model": "gpt-4o",
	})
	workflow := []byte("on:\n  push:\njobs:\n  x:\n    steps:\n" +
		"      - uses: anthropics/claude-code-action@v1\n")

	return &countingProvider{FixtureProvider: &services.FixtureProvider{
		ProviderName: "github",
		Caps:         map[string]string{models.ClassRepoDeclaration: models.CoverageComplete},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-two", DisplayName: "acme/two", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-two": {
				{Path: "README.md", SHA: "n1", Size: 10},
				{Path: "agent.json", SHA: "m1", Size: int64(len(manifest))},
				{Path: "docs/notes.md", SHA: "n2", Size: 12},
				{Path: ".github/workflows/ci.yml", SHA: "w1", Size: int64(len(workflow))},
			},
		},
		Blobs: map[string][]byte{
			"repo-two:agent.json":               manifest,
			"repo-two:.github/workflows/ci.yml": workflow,
		},
	}}
}

// One tree call plus one fetch PER MATCHED PATH — the quantifier, not just the
// total.
//
// The earlier version of this assertion used a fixture with a single matched
// path, so it could not tell "one fetch per match" from "one fetch, then stop".
// Two matched paths among two unmatched ones is the smallest fixture that can.
func TestGitHubScanFetchesOncePerMatchedPath(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-permatch")
	srcID := repoScanSource(t, disco, ws, "acme-permatch")

	p := twoMatchProvider()
	res, err := services.NewGitHubRepoScannerWithProvider(db, p).
		Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("cost: tree=%d dir=%d blob=%d codeowners=%d (4 paths, 2 matched)",
		p.trees, p.dirs, p.blobs, p.codeowners)

	if p.trees != 1 {
		t.Fatalf("expected 1 recursive tree listing, got %d", p.trees)
	}
	// The quantifier: exactly as many fetches as matched paths.
	if p.blobs != 2 {
		t.Fatalf("expected exactly 2 blob fetches for the 2 matched paths, got %d", p.blobs)
	}
	if res.FilesFetched != 2 || res.SightingsNew != 2 {
		t.Fatalf("expected 2 fetched / 2 new sightings, got fetched=%d new=%d",
			res.FilesFetched, res.SightingsNew)
	}
	// CODEOWNERS is a real per-repository call the scan makes, so it belongs in
	// the honest cost picture even though the ticket's formula omits it. Once
	// per repository, never once per matched file.
	if p.codeowners != 1 {
		t.Fatalf("CODEOWNERS must be read once per repository, got %d", p.codeowners)
	}
	t.Logf("PASS: 1 tree + 1 CODEOWNERS + exactly 2 fetches for 2 matched paths of 4")
}

// Re-scanning advances last-seen for EVERY finding, not just the first.
//
// The quantifier is the point: a scalar assertion over one row cannot show that
// a repository's second and third declarations were also confirmed, and a
// partial touch would leave some agents decaying toward "possibly gone" while
// the scan reported success.
func TestGitHubRescanAdvancesLastSeenForEveryFinding(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-everyfinding")
	srcID := repoScanSource(t, disco, ws, "acme-everyfinding")

	p := twoMatchProvider()
	scanner := services.NewGitHubRepoScannerWithProvider(db, p)

	first, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if first.SightingsNew != 2 {
		t.Fatalf("expected 2 findings to work with, got %d", first.SightingsNew)
	}

	// The watermark every row must beat.
	var before time.Time
	db.Raw(`SELECT max(last_seen_at) FROM discovered_agents
	        WHERE workspace_id=? AND source=?`, ws, models.DiscoverySourceRepoScan).Scan(&before)
	if before.IsZero() {
		t.Fatal("expected sighting rows after the first scan")
	}

	blobsBefore := p.blobs
	second, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}

	// Zero fetches for the whole repository, not just for one file.
	if p.blobs != blobsBefore {
		t.Fatalf("unchanged blobs must not be refetched: %d -> %d", blobsBefore, p.blobs)
	}
	if second.FilesFetched != 0 || second.BlobsSkipped != 2 {
		t.Fatalf("expected 0 fetched and 2 skipped, got fetched=%d skipped=%d",
			second.FilesFetched, second.BlobsSkipped)
	}

	// EVERY row advanced: count the rows that beat the watermark and require it
	// to equal the total, so a partial touch fails loudly.
	var advanced, total int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND source=? AND last_seen_at > ?`,
		ws, models.DiscoverySourceRepoScan, before).Scan(&advanced)
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND source=?`, ws, models.DiscoverySourceRepoScan).Scan(&total)

	if total != 2 {
		t.Fatalf("expected 2 inventory rows, got %d", total)
	}
	if advanced != total {
		t.Fatalf("last_seen_at must advance for EVERY finding: %d of %d advanced", advanced, total)
	}
	t.Logf("PASS: 0 blobs fetched, 2 skipped, last_seen advanced on %d/%d findings", advanced, total)
}

// A repository we could not read and a FILE we could not fetch are different
// outcomes and must not share a counter.
//
// Merging them makes the number unreadable: an admin cannot tell one dead
// repository from one healthy repository with a couple of unfetchable blobs,
// and those need different fixes.
func TestGitHubRepoFailureIsDistinctFromFileFailure(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-failsplit")
	srcID := repoScanSource(t, disco, ws, "acme-failsplit")

	manifest, _ := json.Marshal(map[string]interface{}{"name": "ok-agent", "model": "gpt-4o"})
	workflow := []byte("on:\n  push:\njobs:\n  x:\n    steps:\n" +
		"      - uses: anthropics/claude-code-action@v1\n")

	// repo-live reads fine, but one of its two matched declarations has no blob
	// behind it. repo-dead cannot be read at all.
	p := &countingProvider{FixtureProvider: &services.FixtureProvider{
		ProviderName: "github",
		Caps:         map[string]string{models.ClassRepoDeclaration: models.CoverageComplete},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-live", DisplayName: "acme/live", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "repo-dead", DisplayName: "acme/dead", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-live": {
				{Path: "agent.json", SHA: "ok1", Size: int64(len(manifest))},
				// Matched by the workflow rule, but deliberately has no blob.
				{Path: ".github/workflows/broken.yml", SHA: "bad1", Size: int64(len(workflow))},
			},
		},
		Blobs:      map[string][]byte{"repo-live:agent.json": manifest},
		FailScopes: map[string]error{"repo-dead": errAccessDenied{}},
	}}

	res, err := services.NewGitHubRepoScannerWithProvider(db, p).
		Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("outcomes: scanned=%d repos_failed=%d files_failed=%d excluded=%d truncated=%d",
		res.ReposScanned, res.ReposFailed, res.FilesFailed, res.ReposExcluded, res.ReposTruncated)

	// One repository read, one repository dead — the repo counter reflects
	// repositories only.
	if res.ReposScanned != 1 {
		t.Fatalf("expected 1 repository scanned, got %d", res.ReposScanned)
	}
	if res.ReposFailed != 1 {
		t.Fatalf("expected exactly 1 FAILED REPOSITORY, got %d", res.ReposFailed)
	}
	// The unfetchable file is counted apart, and named.
	if res.FilesFailed != 1 {
		t.Fatalf("expected exactly 1 failed FILE, got %d", res.FilesFailed)
	}
	if len(res.FailedFiles) != 1 {
		t.Fatalf("a failed file must be named, got %v", res.FailedFiles)
	}
	// FAILED carries its reason, per repository.
	if len(res.Failed) != 1 {
		t.Fatalf("a failed repository must be named with its reason, got %v", res.Failed)
	}
	// The healthy declaration still landed: one bad blob must not cost the
	// coverage we did get.
	if res.SightingsNew != 1 {
		t.Fatalf("the readable declaration should still be reported, got %d", res.SightingsNew)
	}
	if res.Complete {
		t.Fatal("a scan with a dead repository and an unfetchable file is not complete")
	}
	t.Logf("PASS: repos_failed=%v kept distinct from files_failed=%v", res.Failed, res.FailedFiles)
}

// errAccessDenied is a stand-in for a provider permission failure.
type errAccessDenied struct{}

func (errAccessDenied) Error() string { return "403 permission denied for repository" }

// The repository listing reflects a live grant CHANGE, within one call each
// time, and carries each repository's default branch.
//
// This is a state-transition claim, so a single call against a fixed grant
// cannot demonstrate it: the listing has to be observed before and after the
// grant set actually changes, with no stale entry surviving.
func TestGitHubRepositoryListingReflectsGrantChange(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-grantchange")
	srcID := repoScanSource(t, disco, ws, "acme-grantchange")

	p := &countingProvider{FixtureProvider: &services.FixtureProvider{
		ProviderName: "github",
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "r1", DisplayName: "acme/one", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "r2", DisplayName: "acme/two", DefaultBranch: "develop"},
		},
	}}
	scanner := services.NewGitHubRepoScannerWithProvider(db, p)

	before, err := scanner.ListSelectableRepositories(context.Background(), ws, srcID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(before) != 2 {
		t.Fatalf("expected the 2 granted repositories, got %d", len(before))
	}
	// Each listed repository carries its default branch, verbatim from the
	// provider — the scan reads trees at this ref, so a wrong branch means
	// scanning the wrong code.
	branches := map[string]string{}
	for _, c := range before {
		branches[c.FullName] = c.DefaultBranch
	}
	if branches["acme/one"] != "main" || branches["acme/two"] != "develop" {
		t.Fatalf("default branches must be carried through, got %v", branches)
	}

	// The grant CHANGES on GitHub: one repository added, one revoked.
	p.FixtureProvider.Scopes = []services.ProviderScope{
		{Kind: "repository", NativeID: "r1", DisplayName: "acme/one", DefaultBranch: "main"},
		{Kind: "repository", NativeID: "r3", DisplayName: "acme/three", DefaultBranch: "trunk"},
	}

	after, err := scanner.ListSelectableRepositories(context.Background(), ws, srcID)
	if err != nil {
		t.Fatalf("relist: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range after {
		seen[c.FullName] = true
	}
	if !seen["acme/three"] {
		t.Fatalf("a newly granted repository must appear on the next call, got %v", seen)
	}
	if seen["acme/two"] {
		t.Fatalf("a revoked repository must not survive as a stale entry, got %v", seen)
	}
	if len(after) != 2 {
		t.Fatalf("expected 2 repositories after the grant change, got %d", len(after))
	}
	t.Logf("PASS: grant change reflected in one call — added acme/three, dropped acme/two")
}

// A GitHub repo_scan source is visible alongside Kubernetes sources in the same
// listing.
//
// This is what makes GitHub a peer channel rather than a parallel system: if
// one listing returns both kinds, the downstream inventory, coverage, claim and
// quarantine paths need no GitHub-specific code at all.
func TestGitHubSourceListsAlongsideKubernetesSource(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-gh-peer")

	if _, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceK8sWebhook, DisplayName: "prod-cluster",
	}); err != nil {
		t.Fatalf("create k8s source: %v", err)
	}
	if _, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-github",
		Config: map[string]interface{}{
			"installation_id": "12345",
			"repositories":    map[string]interface{}{"mode": "all"},
		},
	}); err != nil {
		t.Fatalf("create github source: %v", err)
	}

	// One kind-agnostic listing must return both.
	all, err := disco.ListSources(ws, "", false)
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	kinds := map[string]bool{}
	for _, s := range all {
		kinds[s.Kind] = true
	}
	if !kinds[models.DiscoverySourceK8sWebhook] || !kinds[models.DiscoverySourceRepoScan] {
		t.Fatalf("one listing must return both kinds, got %v", kinds)
	}

	// And each kind is still filterable on its own, so a caller that wants only
	// repository sources is not forced to filter client-side.
	onlyRepo, err := disco.ListSources(ws, models.DiscoverySourceRepoScan, false)
	if err != nil {
		t.Fatalf("list repo sources: %v", err)
	}
	if len(onlyRepo) != 1 || onlyRepo[0].Kind != models.DiscoverySourceRepoScan {
		t.Fatalf("expected exactly 1 repo_scan source when filtered, got %d", len(onlyRepo))
	}
	t.Logf("PASS: %d sources listed together, both kinds present: %v", len(all), kinds)
}
