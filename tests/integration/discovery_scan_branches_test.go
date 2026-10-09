package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// branchFixtures builds ONE repository with four refs:
//
//	main            the default branch, holding agent.json
//	stale           a leftover branch at the SAME commit as main
//	feature/new     a branch whose agent.json DIFFERS from main's
//	feature/extra   a fourth ref, present only to exceed a cap of 3
//
// That shape covers the three things all-branch scanning has to get right:
// don't duplicate a declaration that is merely un-deleted, do surface one that
// is genuinely different, and never pretend a capped scan saw everything.
func branchFixtures() *services.FixtureProvider {
	mainManifest, _ := json.Marshal(map[string]interface{}{
		"name": "release-notes-agent", "model": "claude-sonnet-5",
	})
	branchManifest, _ := json.Marshal(map[string]interface{}{
		"name": "experimental-agent", "model": "claude-sonnet-5",
		"apiKey": "sk-must-never-be-persisted",
	})

	return &services.FixtureProvider{
		ProviderName: "github",
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-b", DisplayName: "acme/branchy", DefaultBranch: "main"},
		},
		Branches: map[string][]services.ProviderBranch{
			"repo-b": {
				{Name: "main", CommitSHA: "commit-main"},
				// Same commit as main: its tree is identical by definition, so
				// the scanner must not spend a second tree call on it.
				{Name: "stale", CommitSHA: "commit-main"},
				{Name: "feature/new", CommitSHA: "commit-feature"},
				{Name: "feature/extra", CommitSHA: "commit-extra"},
			},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-b": {{Path: "agent.json", SHA: "sha-main", Size: int64(len(mainManifest))}},
		},
		RefTrees: map[string][]services.TreeEntry{
			// A genuinely different blob at the same path.
			"repo-b@feature/new": {{Path: "agent.json", SHA: "sha-feature", Size: int64(len(branchManifest))}},
			// Same blob as main: the same declaration, unmerged. Must not
			// produce a second finding.
			"repo-b@feature/extra": {{Path: "agent.json", SHA: "sha-main", Size: int64(len(mainManifest))}},
		},
		Blobs: map[string][]byte{
			"repo-b:agent.json": mainManifest,
		},
	}
}

// All-branch coverage must add the declarations that are only on a branch,
// without duplicating the ones that are merely sitting on an un-deleted copy of
// the default branch.
func TestAllBranchScanningSurfacesOnlyGenuinelyNewDeclarations(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-branches")

	// Baseline: default-branch only. One declaration, one row.
	srcDefault := newScanSource(t, db, ws, "branchy-default", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
		"branches":        map[string]interface{}{"mode": "default"},
	})
	scanner := services.NewGitHubRepoScannerWithProvider(db, branchFixtures())
	base, err := scanner.Scan(context.Background(), ws, srcDefault, "admin")
	if err != nil {
		t.Fatalf("default-branch scan: %v", err)
	}
	if base.BranchesScanned != 1 {
		t.Fatalf("default mode must read exactly one ref, read %d", base.BranchesScanned)
	}
	if base.SightingsNew != 1 {
		t.Fatalf("expected 1 declaration on main, got %d", base.SightingsNew)
	}
	t.Logf("PASS: default mode read 1 ref and found 1 declaration")

	// Now all-branch on a separate source, with a cap big enough for all four.
	srcAll := newScanSource(t, db, ws, "branchy-all", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
		"branches":        map[string]interface{}{"mode": "all", "max_per_repo": 10},
	})
	all, err := scanner.Scan(context.Background(), ws, srcAll, "admin")
	if err != nil {
		t.Fatalf("all-branch scan: %v", err)
	}

	// Four refs accounted for, but "stale" shares main's commit so its tree
	// costs nothing.
	if all.BranchesScanned != 4 {
		t.Fatalf("all mode must account for all 4 refs, got %d", all.BranchesScanned)
	}
	// main + feature/new + feature/extra were walked; stale was deduped by
	// commit. Only feature/new holds a DIFFERENT blob, so exactly one new
	// finding beyond the default branch.
	if all.SightingsNew != 1 {
		t.Fatalf("expected exactly 1 branch-only declaration, got %d new (bumped=%d)",
			all.SightingsNew, all.SightingsBumped)
	}
	if !all.Complete {
		t.Fatalf("nothing was unreadable or capped, so the scan should be complete; warnings=%v", all.Warnings)
	}
	t.Logf("PASS: all mode accounted for 4 refs and added exactly 1 branch-only finding")

	// The branch-only finding must be distinguishable from a live one.
	var meta []byte
	err = db.Raw(`SELECT metadata FROM discovered_agents
	              WHERE workspace_id = ? AND fingerprint LIKE 'gh:repo-b@%'`, ws).
		Row().Scan(&meta)
	if err != nil {
		t.Fatalf("branch finding not stored under a ref-qualified fingerprint: %v", err)
	}
	var facts map[string]interface{}
	if err := json.Unmarshal(meta, &facts); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if facts["branch"] != "feature/new" {
		t.Fatalf("finding must record its ref, got %v", facts["branch"])
	}
	if facts["is_default_branch"] != false {
		t.Fatal("a branch-only declaration must be marked is_default_branch=false; " +
			"a reviewer has to be able to tell a proposal from live configuration")
	}
	t.Log("PASS: branch finding records branch=feature/new is_default_branch=false")

	// The default-branch finding kept its ORIGINAL ref-free fingerprint, so
	// nothing recorded before branch coverage existed was orphaned.
	var mainRows int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id = ? AND fingerprint = 'gh:repo-b:agent.json'`, ws).
		Row().Scan(&mainRows)
	if mainRows != 1 {
		t.Fatalf("the default-branch fingerprint must stay ref-free and stable, found %d rows", mainRows)
	}
	t.Log("PASS: default-branch fingerprint unchanged, so pre-existing findings are not orphaned")
}

// A capped scan must never look like a complete one.
func TestBranchCapForcesIncompleteCoverage(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-branch-cap")

	srcID := newScanSource(t, db, ws, "branchy-capped", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
		// Four refs exist; read two.
		"branches": map[string]interface{}{"mode": "all", "max_per_repo": 2},
	})
	scanner := services.NewGitHubRepoScannerWithProvider(db, branchFixtures())
	res, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("capped scan: %v", err)
	}

	if res.BranchesSkipped != 2 {
		t.Fatalf("expected 2 refs skipped by the cap, got %d", res.BranchesSkipped)
	}
	if res.Complete {
		t.Fatal("a scan that knowingly skipped refs must not report complete coverage")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("the cap must be reported, not applied silently")
	}
	t.Logf("PASS: cap skipped %d refs, forced incomplete, warned: %q",
		res.BranchesSkipped, res.Warnings[0])
}

// A provider that cannot list refs must degrade to the default branch LOUDLY.
// Silently reading one branch and calling it all-branch coverage would be the
// same false all-clear in a new costume.
func TestUnlistableBranchesDegradeHonestly(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-branch-fail")

	fx := branchFixtures()
	fx.FailBranches = map[string]error{"repo-b": context.DeadlineExceeded}

	srcID := newScanSource(t, db, ws, "branchy-unlistable", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
		"branches":        map[string]interface{}{"mode": "all"},
	})
	scanner := services.NewGitHubRepoScannerWithProvider(db, fx)
	res, err := scanner.Scan(context.Background(), ws, srcID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if res.BranchesScanned != 1 {
		t.Fatalf("expected a fallback to the single default branch, got %d", res.BranchesScanned)
	}
	if res.Complete {
		t.Fatal("failing to enumerate refs is a coverage gap and must clear complete")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("the degradation must be reported")
	}
	t.Logf("PASS: degraded to the default branch and said so: %q", res.Warnings[0])
}

// The queue and branch coverage compose: the plan is snapshotted onto the run,
// so a finished report says which ref policy actually produced it.
func TestRunRecordsTheBranchPlanItRanUnder(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-branch-run")
	runs := repositories.NewDiscoveryScanRunRepository(db)

	srcID := newScanSource(t, db, ws, "branchy-queued", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
		"branches":        map[string]interface{}{"mode": "all", "max_per_repo": 10},
	})
	run, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if run.BranchMode != models.BranchModeAll || run.MaxBranches != 10 {
		t.Fatalf("the branch plan must be snapshotted at enqueue, got mode=%q max=%d",
			run.BranchMode, run.MaxBranches)
	}

	worker := services.NewDiscoveryScanWorkerWithScanner(db,
		services.NewGitHubRepoScannerWithProvider(db, branchFixtures()))
	done := drain(t, worker, runs, ws, run.ID, 5)

	if done.Status != models.ScanRunSucceeded {
		t.Fatalf("run failed: %q %q", done.Status, done.Error)
	}
	if done.BranchesScanned != 4 {
		t.Fatalf("the run must record every ref accounted for, got %d", done.BranchesScanned)
	}
	if done.BranchMode != models.BranchModeAll {
		t.Fatalf("the finished report must name the ref policy, got %q", done.BranchMode)
	}
	t.Logf("PASS: run reports branch_mode=%s branches_scanned=%d",
		done.BranchMode, done.BranchesScanned)
}
