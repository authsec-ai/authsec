package integration

// P2-0 scenario 9: a crash between publication and coverage.
//
// The old sequence was Publish -> FinalizeCoverage -> SetCoverage (best
// effort). A crash in that gap made the loss PERMANENT: the projection job
// would then read absent coverage, canEnd would refuse every partition, and
// the graph would silently never close anything -- an outage that looks like
// caution.
//
// The fix is that coverage, publication and the projection job's enqueue share
// ONE transaction. That is a property about a transaction boundary, so it is
// provable without killing a process: make the last step fail, and require
// that NOTHING landed. A test that only exercised the happy path would pass
// just as well against the broken three-step version.

import (
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"gorm.io/gorm"
)

func coverageFor(surfaces map[string]models.SurfaceCoverage) models.ScanCoverage {
	return models.ScanCoverage{Generation: 1, Status: "complete", Surfaces: surfaces}
}

// A failure anywhere inside the publish transaction must leave the run
// UNPUBLISHED, its coverage unstamped and no projection job behind.
func TestPublishWithCoverageIsAtomicOnFailure(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-publish-atomic-fail")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	boom := errors.New("enqueue failed: simulated crash inside the publish transaction")
	err = runs.PublishWithCoverage(run.ID, "worker-a", run.LeaseVersion,
		coverageFor(map[string]models.SurfaceCoverage{
			models.SurfaceIAMRoles: {State: models.CloudCoverageReached, Count: 3},
		}),
		func(tx *gorm.DB, published *models.CloudScanRun) error {
			// Everything before this point has been written in this
			// transaction: coverage stamped, status flipped to published.
			return boom
		})
	if !errors.Is(err, boom) {
		t.Fatalf("want the hook's error to surface, got %v", err)
	}

	// NOTHING may have landed.
	var status string
	var coverage []byte
	var publishedAt *time.Time
	if err := db.Raw(`SELECT status, coverage, published_at FROM cloud_scan_run WHERE id = ?`,
		run.ID).Row().Scan(&status, &coverage, &publishedAt); err != nil {
		t.Fatalf("read run: %v", err)
	}
	if status == models.CloudScanRunPublished {
		t.Error("the run is PUBLISHED although the transaction failed; " +
			"a reader would treat this inventory as authoritative")
	}
	if publishedAt != nil {
		t.Error("published_at was stamped by a failed transaction")
	}
	if len(coverage) > 2 { // '{}' is the column default
		t.Errorf("coverage was stamped by a failed transaction: %s", coverage)
	}
	var jobs int64
	db.Raw(`SELECT count(*) FROM iga_projection_job WHERE scan_run_id = ?`, run.ID).Scan(&jobs)
	if jobs != 0 {
		t.Errorf("%d projection jobs exist for a run that never published", jobs)
	}
}

// The converse, so the test above cannot pass by simply never publishing:
// on success all three land together.
func TestPublishWithCoverageCommitsAllThree(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-publish-atomic-ok")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	jobsRepo := repositories.NewIGAProjectionJobRepository(db)
	err = runs.PublishWithCoverage(run.ID, "worker-a", run.LeaseVersion,
		coverageFor(map[string]models.SurfaceCoverage{
			models.SurfaceIAMRoles: {State: models.CloudCoverageReached, Count: 3},
		}),
		func(tx *gorm.DB, published *models.CloudScanRun) error {
			return jobsRepo.EnqueueTx(tx, &models.IGAProjectionJob{
				WorkspaceID: published.WorkspaceID,
				ScanRunID:   published.ID,
				ConnectorID: published.ConnectorID,
				Generation:  published.Generation,
				Status:      models.ProjectionQueued,
			})
		})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	var status string
	var coverage []byte
	var publishedAt *time.Time
	db.Raw(`SELECT status, coverage, published_at FROM cloud_scan_run WHERE id = ?`, run.ID).
		Row().Scan(&status, &coverage, &publishedAt)
	if status != models.CloudScanRunPublished {
		t.Errorf("status = %q, want published", status)
	}
	if publishedAt == nil {
		t.Error("published_at not stamped")
	}
	// The coverage a reader consults must be THIS run's own report.
	decoded := models.DecodeScanCoverage(coverage)
	if s, ok := decoded.Surfaces[models.SurfaceIAMRoles]; !ok || s.State != models.CloudCoverageReached {
		t.Errorf("this run's coverage was not stamped: %s", coverage)
	}
	var jobs int64
	db.Raw(`SELECT count(*) FROM iga_projection_job WHERE scan_run_id = ?`, run.ID).Scan(&jobs)
	if jobs != 1 {
		t.Errorf("%d projection jobs, want exactly 1: a published run always has one", jobs)
	}
}

// A superseded worker cannot publish at all -- the fence is checked in the
// same transaction, so neither coverage nor publication lands.
func TestPublishWithCoverageRefusesASupersededWorker(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-publish-atomic-fence")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, _ := runs.Claim("worker-a", time.Minute, time.Now())

	// worker-b reclaims: the fence version moves on.
	db.Exec(`UPDATE cloud_scan_run SET lease_expires_at = now() - interval '2 minutes' WHERE id = ?`, run.ID)
	if _, err := runs.Claim("worker-b", time.Minute, time.Now()); err != nil {
		t.Fatalf("reclaim: %v", err)
	}

	called := false
	err := runs.PublishWithCoverage(run.ID, "worker-a", run.LeaseVersion,
		coverageFor(map[string]models.SurfaceCoverage{}),
		func(tx *gorm.DB, published *models.CloudScanRun) error { called = true; return nil })
	if err == nil {
		t.Fatal("a superseded worker published")
	}
	if called {
		t.Error("the enqueue hook ran for a superseded worker")
	}
	var status string
	db.Raw(`SELECT status FROM cloud_scan_run WHERE id = ?`, run.ID).Scan(&status)
	if status == models.CloudScanRunPublished {
		t.Error("a superseded worker's publication landed")
	}
}
