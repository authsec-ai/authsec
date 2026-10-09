package igagraph_test

// Regression tests for the wedged-workspace bug.
//
// Three reachable paths once left iga_pipeline_lease busy with NO code path
// that ever returned it to idle, so every later scan in that workspace was
// refused forever. The old blind sweep had been deleted -- correctly, since it
// returned an expired PROJECTING barrier to idle, which is the overwrite the
// barrier exists to prevent -- but nothing replaced it, and AbandonTx and
// ExpiredCandidates had no callers. "Only abandon reaches idle" was true only
// because nothing reached idle at all.
//
// These assert the fix: recovery is phase-aware, frees a workspace whose work
// can no longer progress, and leaves alone work that is still claimable.
//
// They were originally written to assert the BUG (no job claimable, new scan
// refused) and passed in that form; inverted here, they fail without the fix.

import (
	"context"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

func wedgeSetup(t *testing.T) (*fixture, models.CloudScanRun) {
	f := newFixture(t)
	run := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	f.exec(`INSERT INTO iga_projection_job (workspace_id, scan_run_id, connector_id, generation)
	        VALUES ($1,$2,$3,1)`, f.workspace, run.ID, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1,'projecting','w1',$2, now() + interval '15 minutes', 7)`, f.workspace, run.ID)
	return f, run
}

// projectionService builds the real service over the real repositories.
func projectionService(f *fixture) *services.ProjectionService {
	return projectionServiceAs(f, "recovery-worker")
}

// projectionServiceAs is the same, under a named owner -- the exits are fenced
// on the owner, so a test that supersedes a worker needs to choose it.
func projectionServiceAs(f *fixture, owner string) *services.ProjectionService {
	return services.NewProjectionService(
		f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		repositories.NewIGAGraphRepository(),
		owner, time.Minute,
	)
}

// assertRecoveryFrees runs the recovery loop a month on -- every lease long
// expired -- and requires the workspace to accept a new scan afterwards.
func assertRecoveryFrees(t *testing.T, f *fixture, pipe repositories.IGAPipelineLeaseRepository) {
	t.Helper()
	later := time.Now().Add(30 * 24 * time.Hour)

	if err := projectionService(f).RecoverStalled(context.Background(), later); err != nil {
		t.Fatalf("recovery: %v", err)
	}

	l, err := pipe.Get(f.workspace)
	if err != nil {
		t.Fatalf("read barrier: %v", err)
	}
	if l.State != models.PipelineIdle {
		t.Fatalf("barrier still %s after recovery; the workspace is wedged", l.State)
	}

	newRun := f.publishedRun(f.connector, 2, map[string]models.SurfaceCoverage{})
	if _, err := pipe.AcquireForCollection(f.workspace, "w3", newRun.ID, time.Minute, later); err != nil {
		t.Fatalf("a new scan was still refused after recovery: %v", err)
	}
	t.Log("recovery freed the workspace; a new scan is admitted")
}

// Path 1: ONE transient projection failure.
//
// failKeepBarrier deliberately keeps the barrier -- the pending projection's
// inventory must stay frozen. That is only safe if the job can be claimed
// again; when `failed` was terminal, the retry never happened, the
// attempts-ceiling escalation was unreachable, and the workspace froze on the
// first transient error.
func TestTransientFailureIsRetriedThenRecovered(t *testing.T) {
	f, _ := wedgeSetup(t)
	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)

	j, err := jobs.Claim("w1", time.Minute, time.Now())
	if err != nil || j == nil {
		t.Fatalf("first claim: job=%v err=%v", j, err)
	}
	if err := jobs.Fail(j.ID, "w1", j.LeaseVersion, "transient: connection reset"); err != nil {
		t.Fatalf("fail: %v", err)
	}

	// A failed job below the ceiling must be CLAIMABLE again once its backoff
	// has passed -- otherwise nothing ever retries and nothing ever escalates.
	afterBackoff := time.Now().Add(repositories.ProjectionRetryBackoff + time.Minute)
	again, err := jobs.Claim("w2", time.Minute, afterBackoff)
	if err != nil {
		t.Fatalf("reclaim after failure: %v", err)
	}
	if again == nil {
		t.Fatal("a failed job below the attempts ceiling was never claimable again; " +
			"its barrier is held, so the workspace would stay frozen forever")
	}
	if again.ID != j.ID {
		t.Fatalf("reclaimed a different job: %s vs %s", again.ID, j.ID)
	}
	t.Log("failed job was reclaimed after backoff")

	// And once it exhausts its attempts, recovery frees the workspace.
	f.exec(`UPDATE iga_projection_job SET attempts=$2, lease_expires_at = now() - interval '1 minute'
	         WHERE id=$1`, j.ID, repositories.MaxProjectionAttempts)
	assertRecoveryFrees(t, f, pipe)
}

// Path 2: the worker crashes on the FINAL attempt. Claim requires
// attempts < Max, so the job can never be picked up again; only recovery can
// resolve it.
func TestCrashOnLastAttemptIsRecovered(t *testing.T) {
	f, run := wedgeSetup(t)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	f.exec(`UPDATE iga_projection_job SET status='running', lease_owner='w1',
	          lease_expires_at = now() - interval '1 minute', attempts=$2 WHERE scan_run_id=$1`,
		run.ID, repositories.MaxProjectionAttempts)
	assertRecoveryFrees(t, f, pipe)

	// The job is terminal, not left running for a worker that will never come.
	var status string
	f.gorm.Raw(`SELECT status FROM iga_projection_job WHERE scan_run_id = ?`, run.ID).Scan(&status)
	if status != models.ProjectionAbandoned {
		t.Errorf("job status = %q, want abandoned: abandon terminalizes the job BEFORE idling the barrier", status)
	}
}

// Path 3: a scan run past its attempts ceiling is failed without releasing the
// `collecting` barrier a previous attempt took. The run is terminal, so
// AcquireForCollection's same-run recovery can never apply either.
func TestScanGiveUpIsRecovered(t *testing.T) {
	f := newFixture(t)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	dead := uuid.New()
	f.exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status)
	        VALUES ($1,$2,$3,1,'failed')`, dead, f.workspace, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1,'collecting','w1',$2, now() - interval '1 minute', 3)`, f.workspace, dead)
	assertRecoveryFrees(t, f, pipe)
}

// Recovery must NOT touch work that can still progress: an expired collecting
// barrier whose run is still claimable belongs to that run's own reclaim.
// Abandoning it here would cancel a healthy scan that was merely slow.
func TestRecoveryLeavesClaimableWorkAlone(t *testing.T) {
	f := newFixture(t)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	live := uuid.New()
	// A running run whose worker died: its lease has lapsed, so
	// cloud_scan_run.Claim will reclaim it. cloud_scan_run_lease_chk requires
	// a running row to carry a lease, hence the owner and expiry.
	f.exec(`INSERT INTO cloud_scan_run
	          (id, workspace_id, connector_id, generation, status, lease_owner, lease_expires_at)
	        VALUES ($1,$2,$3,1,'running','w1', now() - interval '1 minute')`,
		live, f.workspace, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1,'collecting','w1',$2, now() - interval '1 minute', 3)`, f.workspace, live)

	if err := projectionService(f).RecoverStalled(
		context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	l, _ := pipe.Get(f.workspace)
	if l.State != models.PipelineCollecting {
		t.Fatalf("recovery released a barrier whose run is still claimable (state=%s)", l.State)
	}
	t.Log("recovery left a still-claimable run's barrier in place")
}

// Positive control: an idle barrier admits a scan, so the assertions above are
// about the wedge and not a broken fixture.
func TestControlIdleAdmits(t *testing.T) {
	f := newFixture(t)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	run := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	if _, err := pipe.AcquireForCollection(f.workspace, "w2", run.ID, time.Minute, time.Now()); err != nil {
		t.Fatalf("idle barrier refused a scan: %v", err)
	}
	t.Log("control: idle barrier admits a scan")
}
