package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// newScanSource creates a repo_scan source with an explicit plan.
func newScanSource(t *testing.T, db *gorm.DB, ws uuid.UUID, name string, cfg map[string]interface{}) uuid.UUID {
	t.Helper()
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: name, Config: cfg,
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	return src.ID
}

// drain runs the worker until the named run reaches a terminal state. The
// worker claims the oldest runnable row globally, so a shared test database may
// hand it someone else's run first; looping keeps the test deterministic
// without needing an empty queue.
func drain(t *testing.T, w *services.DiscoveryScanWorker, runs repositories.DiscoveryScanRunRepository,
	ws, runID uuid.UUID, maxTicks int) *models.DiscoveryScanRun {
	t.Helper()
	for i := 0; i < maxTicks; i++ {
		run, err := runs.Get(ws, runID)
		if err != nil {
			t.Fatalf("read run: %v", err)
		}
		if run.Terminal() {
			return run
		}
		if _, err := w.RunOnce(context.Background()); err != nil {
			t.Logf("worker tick %d: %v", i, err)
		}
	}
	run, _ := runs.Get(ws, runID)
	t.Fatalf("run did not reach a terminal state; last status=%q", run.Status)
	return nil
}

// A scan must be queued, executed off the request path, and WRITTEN DOWN.
//
// The whole point of the run record is that the answer survives: before it, a
// scan's result existed only in the HTTP response, so refreshing the console
// lost "3 agents found, 1 repository unreadable" permanently.
func TestScanIsQueuedAndItsReportPersists(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-queue")
	runs := repositories.NewDiscoveryScanRunRepository(db)

	srcID := newScanSource(t, db, ws, "acme", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
	})

	run, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if run.Status != models.ScanRunQueued {
		t.Fatalf("a queued scan must start queued, got %q", run.Status)
	}
	if run.SelectionMode != "all" {
		t.Fatalf("the plan must be snapshotted at enqueue, got mode %q", run.SelectionMode)
	}
	t.Logf("PASS: enqueued run %s without running anything inline", run.ID)

	worker := services.NewDiscoveryScanWorkerWithScanner(db,
		services.NewGitHubRepoScannerWithProvider(db, fixtures()))
	done := drain(t, worker, runs, ws, run.ID, 5)

	if done.Status != models.ScanRunSucceeded {
		t.Fatalf("expected the run to succeed, got %q (error=%q)", done.Status, done.Error)
	}
	// The fixture has a denied repository and a truncated tree, so the scan did
	// everything it could AND still saw less than everything. Both must be true
	// at once: succeeded, but not complete.
	if done.Complete {
		t.Fatal("a scan with a denied repository and a truncated tree must not be complete")
	}
	if !done.Degraded {
		t.Fatal("degraded must record that coverage was lost")
	}
	if done.ReposFailed == 0 {
		t.Fatal("the denied repository must be counted as failed")
	}
	if done.SightingsNew == 0 {
		t.Fatal("the scan found nothing; the fixture declares two agents")
	}
	if done.FinishedAt == nil {
		t.Fatal("a terminal run must record when it finished")
	}
	t.Logf("PASS: persisted report scanned=%d failed=%d new=%d complete=%v",
		done.ReposScanned, done.ReposFailed, done.SightingsNew, done.Complete)

	// The report outlives the request: history is readable afterwards.
	history, err := runs.ListForSource(ws, srcID, 10)
	if err != nil || len(history) != 1 {
		t.Fatalf("expected 1 run in history, got %d (%v)", len(history), err)
	}
	t.Logf("PASS: run history readable after the fact (%d run)", len(history))
}

// Two workers must never scan the same source at once: they would race on
// identical fingerprints and spend the installation's rate limit twice to
// produce one answer.
func TestSecondScanIsRefusedWhileOneIsActive(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-dup")

	srcID := newScanSource(t, db, ws, "acme", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
	})

	first, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	second, err := services.EnqueueGitHubScan(db, ws, srcID, "bob")
	if err != repositories.ErrScanAlreadyActive {
		t.Fatalf("expected ErrScanAlreadyActive on the second enqueue, got %v", err)
	}
	// The caller is handed the run already in flight, so the console can watch
	// it instead of showing a dead-end error.
	if second == nil || second.ID != first.ID {
		t.Fatal("the refusal must return the run already in flight")
	}
	t.Logf("PASS: second scan refused and pointed at run %s", first.ID)
}

// A plan that selects nothing must be refused UP FRONT, synchronously.
//
// Accepting it would queue a run that reports scanned=0 complete=true — which a
// console cannot help but render as "we looked and your organisation is clean".
func TestEmptySelectionIsRefusedBeforeQueueing(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-empty")

	srcID := newScanSource(t, db, ws, "acme", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "selected", "include": []string{}},
	})

	if _, err := services.EnqueueGitHubScan(db, ws, srcID, "alice"); err == nil {
		t.Fatal("queueing a scan that would inspect nothing must fail")
	}
	var queued int64
	db.Model(&models.DiscoveryScanRun{}).Where("source_id = ?", srcID).Count(&queued)
	if queued != 0 {
		t.Fatalf("a refused scan must leave no run behind, found %d", queued)
	}
	t.Log("PASS: empty selection refused synchronously, no run created")
}

// An interrupted scan must RESUME, not restart, and its totals must not go
// backwards when it does.
//
// This is the failure that made org-wide scanning unusable: a deploy halfway
// through a 500-repository scan meant paying for all 500 again, and the report
// resetting to zero.
func TestInterruptedScanResumesWithoutRegressing(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-resume")
	runs := repositories.NewDiscoveryScanRunRepository(db)

	srcID := newScanSource(t, db, ws, "acme", map[string]interface{}{
		"installation_id": "12345",
		"repositories":    map[string]interface{}{"mode": "all"},
	})
	run, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	worker := services.NewDiscoveryScanWorkerWithScanner(db,
		services.NewGitHubRepoScannerWithProvider(db, fixtures()))
	first := drain(t, worker, runs, ws, run.ID, 5)
	if first.Status != models.ScanRunSucceeded {
		t.Fatalf("setup scan failed: %q %q", first.Status, first.Error)
	}

	// Everything the first pass finished is on the cursor.
	var raw []byte
	if err := db.Raw(`SELECT cursor FROM discovery_scan_runs WHERE id = ?`, run.ID).
		Row().Scan(&raw); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	var cur models.ScanCursor
	if err := json.Unmarshal(raw, &cur); err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	if len(cur.Done) == 0 {
		t.Fatal("a finished scan must leave a cursor naming the units it completed")
	}
	t.Logf("PASS: cursor recorded %d completed units: %v", len(cur.Done), cur.Done)

	// Now simulate the interruption: put the run back to queued with its cursor
	// and totals intact, exactly as Requeue would after a shutdown.
	if err := db.Exec(`UPDATE discovery_scan_runs
	        SET status='queued', finished_at=NULL, leased_by='', leased_until=NULL
	        WHERE id = ?`, run.ID).Error; err != nil {
		t.Fatalf("simulate interruption: %v", err)
	}

	resumed := drain(t, worker, runs, ws, run.ID, 5)
	if resumed.Status != models.ScanRunSucceeded {
		t.Fatalf("resumed run failed: %q %q", resumed.Status, resumed.Error)
	}

	// The units already done were skipped, so the resume reported no NEW
	// sightings — but the totals from the first pass must still be there.
	if resumed.SightingsNew < first.SightingsNew {
		t.Fatalf("totals regressed on resume: new was %d, now %d",
			first.SightingsNew, resumed.SightingsNew)
	}
	if resumed.ReposScanned < first.ReposScanned {
		t.Fatalf("repos_scanned regressed on resume: was %d, now %d",
			first.ReposScanned, resumed.ReposScanned)
	}
	// The gap seen on the first attempt is still remembered.
	if !resumed.Degraded || resumed.Complete {
		t.Fatal("a gap seen by an earlier attempt must survive the resume")
	}
	t.Logf("PASS: resumed with totals intact (scanned=%d new=%d) and degradation remembered",
		resumed.ReposScanned, resumed.SightingsNew)
}
