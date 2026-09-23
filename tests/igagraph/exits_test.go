package igagraph_test

// The three exits from a claimed projection job, against the REAL
// repositories and a real database.
//
// These had no coverage at all: the projection harness stubs every ownership
// check with okFencer, and nothing else touched ProjectionService. That gap is
// where the wedged-workspace bug lived -- failKeepBarrier's escalation was
// unreachable and nobody noticed, because no test ever reached it.
//
// The contract each asserts:
//
//	completeAndRelease  job complete  + barrier idle      (success, or replay)
//	abandonAndRelease   job abandoned + barrier idle      (superseded, or ceiling)
//	failKeepBarrier     job failed    + barrier UNCHANGED (transient; retried)
//
// plus the property that makes "never release someone else's barrier" true:
// both writes in a *AndRelease are fenced and share one transaction, so a
// superseded worker changes NOTHING.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// claimedJob sets up a projecting barrier HELD BY THE JOB (job:<id>, §2.10A)
// and the job claimed by `owner`, returning the job and the barrier version --
// the state every exit starts in.
func claimedJob(t *testing.T, owner string) (*fixture, *models.IGAProjectionJob, int64) {
	t.Helper()
	f := newFixture(t)
	run := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job (id, workspace_id, scan_run_id, connector_id, generation)
	        VALUES ($1,$2,$3,$4,1)`, jobID, f.workspace, run.ID, f.connector)
	f.exec(`INSERT INTO iga_pipeline_lease (workspace_id, state, holder, scan_run_id, expires_at, version)
	        VALUES ($1,'projecting',$2,$3, now() + interval '15 minutes', 7)`,
		f.workspace, models.PipelineJobHolder(jobID), run.ID)

	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	job, err := jobs.Claim(owner, time.Minute, time.Now())
	if err != nil || job == nil {
		t.Fatalf("claim: job=%v err=%v", job, err)
	}
	return f, job, 7
}

func jobStatus(t *testing.T, f *fixture, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.gorm.Raw(`SELECT status FROM iga_projection_job WHERE id = ?`, id).
		Scan(&s).Error; err != nil {
		t.Fatalf("read job status: %v", err)
	}
	return s
}

func barrierState(t *testing.T, f *fixture) string {
	t.Helper()
	var s string
	if err := f.gorm.Raw(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = ?`,
		f.workspace).Scan(&s).Error; err != nil {
		t.Fatalf("read barrier: %v", err)
	}
	return s
}

// EXIT 1: success. Job complete, barrier idle, and the workspace usable again.
func TestExitCompleteAndRelease(t *testing.T) {
	f, job, version := claimedJob(t, "w1")
	svc := projectionServiceAs(f, "w1")

	if err := svc.CompleteAndReleaseForTest(context.Background(), job, version); err != nil {
		t.Fatalf("completeAndRelease: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionComplete {
		t.Errorf("job = %q, want complete", got)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q, want idle", got)
	}
	// The point of releasing: the next scan can run.
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	next := f.publishedRun(f.connector, 2, map[string]models.SurfaceCoverage{})
	if _, err := pipe.AcquireForCollection(f.workspace, "w2", next.ID, time.Minute, time.Now()); err != nil {
		t.Errorf("workspace not usable after a successful projection: %v", err)
	}
}

// EXIT 2: superseded. Job abandoned, barrier idle.
func TestExitAbandonAndRelease(t *testing.T) {
	f, job, version := claimedJob(t, "w1")
	svc := projectionServiceAs(f, "w1")

	if err := svc.AbandonAndReleaseForTest(
		context.Background(), job, version, "superseded by a newer publication"); err != nil {
		t.Fatalf("abandonAndRelease: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionAbandoned {
		t.Errorf("job = %q, want abandoned", got)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q, want idle", got)
	}
}

// EXIT 3a: a transient failure BELOW the ceiling. The job is failed but the
// barrier is deliberately KEPT: the pending projection's inventory must stay
// frozen until it succeeds. Releasing here would admit a scan that could
// rewrite what the retry is about to read.
func TestExitFailKeepBarrierBelowCeiling(t *testing.T) {
	f, job, version := claimedJob(t, "w1")
	svc := projectionServiceAs(f, "w1")

	job.Attempts = 1 // well below the ceiling
	if err := svc.FailKeepBarrierForTest(
		context.Background(), job, version, errors.New("transient: connection reset")); err != nil {
		t.Fatalf("failKeepBarrier: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionFailed {
		t.Errorf("job = %q, want failed", got)
	}
	if got := barrierState(t, f); got != models.PipelineProjecting {
		t.Fatalf("barrier = %q, want projecting: a transient failure must NOT release it", got)
	}

	// ...and the job must still be reclaimable, or the barrier it is holding
	// would never be released by anyone.
	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	again, err := jobs.Claim("w2", time.Minute,
		time.Now().Add(repositories.ProjectionRetryBackoff+time.Minute))
	if err != nil || again == nil {
		t.Fatalf("a failed job below the ceiling must be reclaimable, got job=%v err=%v", again, err)
	}
}

// EXIT 3b: AT the ceiling it is no longer transient. It escalates to
// abandonAndRelease so the job becomes terminal and the workspace is
// unblocked. This is the path that was unreachable before: `failed` was
// terminal, so the job was never reclaimed and never arrived here.
func TestExitFailKeepBarrierAtCeilingEscalates(t *testing.T) {
	f, job, version := claimedJob(t, "w1")
	svc := projectionServiceAs(f, "w1")

	job.Attempts = svc.MaxAttemptsForTest() // at the ceiling
	if err := svc.FailKeepBarrierForTest(
		context.Background(), job, version, errors.New("still broken")); err != nil {
		t.Fatalf("failKeepBarrier at ceiling: %v", err)
	}
	if got := jobStatus(t, f, job.ID); got != models.ProjectionAbandoned {
		t.Errorf("job = %q, want abandoned: at the ceiling it must escalate", got)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q, want idle: the workspace must be unblocked", got)
	}
}

// FENCING. A superseded worker must change NOTHING -- not the job, not the
// barrier. With the barrier held by the JOB, supersession is a job-lease
// reclaim: the barrier's holder and version do not move, and the old worker is
// fenced out by the job's lease_version inside the same transaction.
func TestExitsRefuseASupersededWorker(t *testing.T) {
	f, job, version := claimedJob(t, "w1")

	// w2 reclaims the job once w1's lease lapses: lease_version moves on.
	f.exec(`UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, job.ID)
	jobs := repositories.NewIGAProjectionJobRepository(f.gorm)
	reclaimed, err := jobs.Claim("w2", time.Minute, time.Now())
	if err != nil || reclaimed == nil || reclaimed.ID != job.ID {
		t.Fatalf("w2 reclaim: job=%v err=%v", reclaimed, err)
	}
	if reclaimed.LeaseVersion == job.LeaseVersion {
		t.Fatal("reclaim did not move the job's lease version")
	}

	stale := projectionServiceAs(f, "w1")
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"completeAndRelease", func() error {
			return stale.CompleteAndReleaseForTest(context.Background(), job, version)
		}},
		{"abandonAndRelease", func() error {
			return stale.AbandonAndReleaseForTest(context.Background(), job, version, "stale")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("a superseded worker was allowed to settle the job")
			}
			if got := jobStatus(t, f, job.ID); got != models.ProjectionRunning {
				t.Errorf("job = %q, want running: a superseded worker must not terminalize it", got)
			}
			if got := barrierState(t, f); got != models.PipelineProjecting {
				t.Errorf("barrier = %q, want projecting: a superseded worker must not release it", got)
			}
		})
	}

	// And the CURRENT holder of the job proceeds at once -- no expiry to wait
	// out, because the barrier names the job, not a worker (T1.2).
	if err := projectionServiceAs(f, "w2").
		CompleteAndReleaseForTest(context.Background(), reclaimed, version); err != nil {
		t.Fatalf("the reclaiming worker could not settle the job it holds: %v", err)
	}
	if got := barrierState(t, f); got != models.PipelineIdle {
		t.Errorf("barrier = %q after the holder completed, want idle", got)
	}
}

// The barrier heartbeat. A projection that outruns the barrier lease would
// otherwise appear in ExpiredCandidates while perfectly healthy, and the
// recovery loop could abandon live work. RenewHeld extends the expiry WITHOUT
// bumping the version, so the holder's fence stays valid.
func TestBarrierHeartbeatRenewsWithoutBreakingTheFence(t *testing.T) {
	f, job, version := claimedJob(t, "w1")
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	fence := repositories.PipelineFence{
		WorkspaceID: f.workspace, Phase: models.PipelineProjecting,
		RunID: job.ScanRunID, Version: version, Holder: models.PipelineJobHolder(job.ID),
	}

	// Let it lapse: recovery would now consider this workspace stalled.
	f.exec(`UPDATE iga_pipeline_lease SET expires_at = now() - interval '1 minute'
	         WHERE workspace_id = $1`, f.workspace)
	stalled, err := pipe.ExpiredCandidates(time.Now(), 50)
	if err != nil {
		t.Fatalf("expired candidates: %v", err)
	}
	if len(stalled) == 0 {
		t.Fatal("precondition: an expired barrier must be a recovery candidate")
	}

	// A heartbeat tick.
	if err := pipe.RenewHeld(fence, 15*time.Minute, time.Now()); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// It is no longer a candidate, so recovery will not touch live work...
	stalled, err = pipe.ExpiredCandidates(time.Now(), 50)
	if err != nil {
		t.Fatalf("expired candidates after renew: %v", err)
	}
	for _, l := range stalled {
		if l.WorkspaceID == f.workspace {
			t.Fatal("a renewed barrier is still listed as expired; recovery could abandon live work")
		}
	}

	// ...and the holder's fence STILL WORKS. Bumping the version here would
	// fence out the very worker doing the work.
	l, err := pipe.Get(f.workspace)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if l.Version != version {
		t.Errorf("renew moved the version %d -> %d; the holder's own fence would now fail",
			version, l.Version)
	}
	if err := projectionServiceAs(f, "w1").
		CompleteAndReleaseForTest(context.Background(), job, version); err != nil {
		t.Fatalf("the holder could not settle its job after a renewal: %v", err)
	}
}
