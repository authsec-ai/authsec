package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Durable scan execution: ownership, leases and fencing.
//
// The property under test is not "a scan runs". It is that a scan cannot be run
// twice at once, cannot be lost when its worker dies, and cannot be published
// by a worker that has been superseded. Each of those was possible when a scan
// was a `go func()` started by an HTTP handler.

// scanRuns returns the repository with an EMPTY cloud_scan_run table.
//
// Claim is deliberately global -- a worker drains the queue, it does not watch
// one connector -- so a run left behind by an earlier test is claimable by this
// one, and the tests would assert against each other's rows. Clearing the table
// is the honest way to get determinism without weakening Claim to suit tests.
func scanRuns(t *testing.T, db *gorm.DB) repositories.CloudScanRunRepository {
	t.Helper()
	clearScanRuns(t, db)
	t.Cleanup(func() { clearScanRuns(t, db) })
	return repositories.NewCloudScanRunRepository(db)
}

// clearScanRuns empties the run table, observations first.
//
// cloud_observation references cloud_scan_run with ON DELETE RESTRICT, on
// purpose: evidence must not disappear because someone pruned a scan, and
// retention is a deliberate policy rather than a side effect of housekeeping.
// The test has to honour that ordering like any other caller would.
func clearScanRuns(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Exec(`DELETE FROM cloud_observation`).Error; err != nil {
		t.Fatalf("clear observations: %v", err)
	}
	if err := db.Exec(`DELETE FROM cloud_scan_run`).Error; err != nil {
		t.Fatalf("clear scan runs: %v", err)
	}
}

// connectorFor makes the minimum row the scan-run FK needs.
func connectorFor(t *testing.T, db *gorm.DB, ws uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := db.Exec(`
		INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref, scan_generation)
		VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault:test', 0)`,
		id, ws, "2204"+id.String()[:8]).Error
	if err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	return id
}

func TestOnlyOneScanMayBeLivePerConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-single")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// Two operators clicking Scan, or one clicking twice. Both used to start a
	// goroutine; whichever finished last reconciled away the other's rows.
	_, err := runs.Enqueue(ws, conn, "manual")
	if err != repositories.ErrScanAlreadyLive {
		t.Fatalf("second enqueue = %v, want ErrScanAlreadyLive", err)
	}
}

func TestAFinishedRunFreesTheConnectorForTheNextScan(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-sequential")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	first, err := runs.Enqueue(ws, conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	claimed, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if err := runs.Publish(first.ID, "worker-a", claimed.LeaseVersion); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("a published run must not block the next scan: %v", err)
	}
}

func TestAClaimAssignsAGenerationAndQueuedRunsDoNotBurnOne(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-generation")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	queued, err := runs.Enqueue(ws, conn, "manual")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// A queued run has no generation. Reconciliation reads generations as
	// evidence a pass happened, so handing one to a run that never starts would
	// be a claim the deletion logic believes.
	if queued.Generation != 0 {
		t.Fatalf("queued run has generation %d, want 0", queued.Generation)
	}
	claimed, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || claimed == nil {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if claimed.Generation <= 0 {
		t.Fatalf("claimed run has generation %d, want > 0", claimed.Generation)
	}
}

func TestACrashedWorkersRunIsReclaimedAfterItsLeaseExpires(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-reclaim")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Now()
	first, err := runs.Claim("worker-a", time.Minute, now)
	if err != nil || first == nil {
		t.Fatalf("first claim: %v %v", first, err)
	}

	// worker-a dies here. Nothing announces it; the lease simply lapses.
	nothing, err := runs.Claim("worker-b", time.Minute, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if nothing != nil {
		t.Fatal("a live lease must not be claimable by another worker")
	}

	second, err := runs.Claim("worker-b", time.Minute, now.Add(2*time.Minute))
	if err != nil || second == nil {
		t.Fatalf("an expired lease must be reclaimable, got %v %v", second, err)
	}
	if second.ID != first.ID {
		t.Fatal("worker-b should resume the SAME run, not start a new one")
	}
	if second.LeaseVersion <= first.LeaseVersion {
		t.Fatalf("lease version must advance on reclaim: %d -> %d",
			first.LeaseVersion, second.LeaseVersion)
	}
	if second.Generation != first.Generation {
		t.Fatalf("a resumed run keeps its generation: %d -> %d",
			first.Generation, second.Generation)
	}
}

func TestASupersededWorkerCannotPublish(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-fence")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Now()
	stale, _ := runs.Claim("worker-a", time.Minute, now)
	fresh, _ := runs.Claim("worker-b", time.Minute, now.Add(2*time.Minute))
	if stale == nil || fresh == nil {
		t.Fatal("test setup: both claims should have succeeded")
	}

	// worker-a wakes up with results computed before worker-b took over. They
	// are older than the run that replaced it, and publishing them would make
	// the inventory go backwards.
	err := runs.Publish(stale.ID, "worker-a", stale.LeaseVersion)
	if err == nil {
		t.Fatal("a superseded worker published; the fence did not hold")
	}
	if !isLeaseLost(err) {
		t.Fatalf("publish error = %v, want ErrLeaseLost", err)
	}
	// Renewing must fail for the same reason — a lost lease is not recoverable
	// by asking for more time.
	if err := runs.Renew(stale.ID, "worker-a", stale.LeaseVersion, time.Minute); !isLeaseLost(err) {
		t.Fatalf("renew error = %v, want ErrLeaseLost", err)
	}
	// And the current holder must still be able to finish.
	if err := runs.Publish(fresh.ID, "worker-b", fresh.LeaseVersion); err != nil {
		t.Fatalf("the current holder must be able to publish: %v", err)
	}
}

func TestASupersededWorkerCannotRecordAFailureEither(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-fail-fence")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Now()
	stale, _ := runs.Claim("worker-a", time.Minute, now)
	fresh, _ := runs.Claim("worker-b", time.Minute, now.Add(2*time.Minute))

	// Otherwise a straggler's error would overwrite the live run's outcome and
	// the connector would report a failure that the current pass did not have.
	if err := runs.Fail(stale.ID, "worker-a", stale.LeaseVersion, "boom"); !isLeaseLost(err) {
		t.Fatalf("fail from a superseded worker = %v, want ErrLeaseLost", err)
	}
	after, err := runs.Get(fresh.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Status != models.CloudScanRunRunning {
		t.Fatalf("live run status = %q, want running", after.Status)
	}
	if after.LastError != "" {
		t.Fatalf("live run picked up the straggler's error: %q", after.LastError)
	}
}

func isLeaseLost(err error) bool {
	return errors.Is(err, repositories.ErrLeaseLost)
}

// --- the worker's own failure handling ------------------------------------

func TestAFailedRunIsRecordedAndFreesTheConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-scan-run-failure")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// A worker with no onboarding service cannot assume the customer's role, so
	// the IAM scan fails. What matters is what happens next: the run must end
	// as `failed` with the reason recorded, and the connector must become
	// scannable again. A run that fails and stays `running` would block the
	// connector forever behind an attempt nobody can retry.
	worker := services.NewAWSScanWorker(db, nil).WithOwner("worker-failing")
	worked, err := worker.RunOnce(context.Background())
	if !worked {
		t.Fatal("the worker should have claimed the queued run")
	}
	if err == nil {
		t.Fatal("a scan that cannot assume the role must report an error")
	}

	latest, gerr := runs.Latest(ws, conn)
	if gerr != nil {
		t.Fatalf("latest: %v", gerr)
	}
	if latest.Status != models.CloudScanRunFailed {
		t.Fatalf("status = %q, want failed", latest.Status)
	}
	if latest.LastError == "" {
		t.Error("a failed run must record why; an unexplained failure is not actionable")
	}
	if latest.PublishedAt != nil {
		t.Error("a failed run must not be published: publication is what says the inventory is current")
	}
	// The connector is free again.
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("a failed run must not block the next scan: %v", err)
	}
}

func TestTheWorkerFindsNothingWhenTheQueueIsEmpty(t *testing.T) {
	db := igaDB(t)
	_ = scanRuns(t, db) // empties the table

	worker := services.NewAWSScanWorker(db, nil).WithOwner("worker-idle")
	worked, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("an empty queue is not an error: %v", err)
	}
	if worked {
		t.Fatal("the worker reported work on an empty queue")
	}
}
