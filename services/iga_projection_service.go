package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// MinProjectionSchemaVersion is the migration the projector cannot run below.
//
// §6.3: 027-034 ship in ONE release, and core reconciliation writes 034's
// table. With 027-033 applied and 034 missing, every reconcile run fails with
// relation "iga_external_principal" does not exist -- a PLAN-time error, so it
// fires even when no row matches. Declining to start is the honest failure;
// starting and failing every pass is not.
const MinProjectionSchemaVersion = 34

// ProjectionService claims projection jobs and turns published runs into the
// canonical graph.
//
// It mirrors AWSScanWorker (Run / RunOnce / execute / heartbeat) so there is
// ONE worker shape in this codebase, not two.
type ProjectionService struct {
	db       *gorm.DB
	jobs     repositories.IGAProjectionJobRepository
	pipeline repositories.IGAPipelineLeaseRepository
	graph    repositories.IGAGraphRepository

	owner       string
	lease       time.Duration
	maxAttempts int
	now         func() time.Time
}

func NewProjectionService(
	db *gorm.DB,
	jobs repositories.IGAProjectionJobRepository,
	pipeline repositories.IGAPipelineLeaseRepository,
	graph repositories.IGAGraphRepository,
	owner string, lease time.Duration,
) *ProjectionService {
	if lease <= 0 {
		lease = 5 * time.Minute
	}
	return &ProjectionService{
		db: db, jobs: jobs, pipeline: pipeline, graph: graph,
		owner: owner, lease: lease,
		maxAttempts: repositories.MaxProjectionAttempts,
		now:         time.Now,
	}
}

// projectionFencer binds the two ownership proofs the graph transaction needs:
// this worker still owns the JOB, and still holds the workspace BARRIER in the
// projecting phase.
type projectionFencer struct {
	jobs     repositories.IGAProjectionJobRepository
	pipeline repositories.IGAPipelineLeaseRepository
	version  int64
}

func (f projectionFencer) AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, v int64) error {
	return f.jobs.AssertOwnedTx(tx, jobID, owner, v)
}

func (f projectionFencer) AssertHeldTx(tx *gorm.DB, ws, runID uuid.UUID, version int64) error {
	return f.pipeline.AssertHeldTx(tx, repositories.PipelineFence{
		WorkspaceID: ws, Phase: models.PipelineProjecting, RunID: runID, Version: version,
	})
}

// EnsureSchema refuses to run below the migration head this phase requires.
func (s *ProjectionService) EnsureSchema() error {
	head, err := repositories.MigrationHead(s.db)
	if err != nil {
		return fmt.Errorf("read migration head: %w", err)
	}
	if head < MinProjectionSchemaVersion {
		return fmt.Errorf(
			"projector requires migration %d, database is at %d: core reconciliation "+
				"writes iga_external_principal and would fail at plan time on every pass",
			MinProjectionSchemaVersion, head)
	}
	return nil
}

// Run claims jobs until the context ends.
func (s *ProjectionService) Run(ctx context.Context, poll time.Duration) {
	if err := s.EnsureSchema(); err != nil {
		log.Printf("[projection] not starting: %v", err)
		return
	}
	if poll <= 0 {
		poll = 10 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for {
				worked, err := s.RunOnce(ctx)
				if err != nil {
					log.Printf("[projection] %v", err)
				}
				if !worked {
					break
				}
			}
		}
	}
}

// RunOnce claims at most one job and projects it. Returns whether it worked.
func (s *ProjectionService) RunOnce(ctx context.Context) (bool, error) {
	job, err := s.jobs.Claim(s.owner, s.lease, s.now())
	if err != nil || job == nil {
		return false, err
	}
	stop := s.heartbeat(ctx, job)
	defer stop()

	// The barrier must be PROJECTING for this run and held by us. A reclaimed
	// job inherits a barrier whose previous holder is gone: recover it into
	// the SAME phase under a new version rather than releasing it, because the
	// published run's inventory is still being read.
	version, err := s.holdBarrier(job)
	if err != nil {
		// Cannot establish the barrier -- do not terminalize the job and do
		// not touch a barrier we may not hold. Let the lease lapse.
		return true, fmt.Errorf("projection job %s: %w", job.ID, err)
	}

	// STALENESS IS NOT CHECKED HERE. A check before the read is stale by the
	// time the read runs; Load performs it inside the same repeatable-read
	// snapshot as the inventory queries and returns ErrSuperseded.
	snap, err := igagraph.Load(ctx, s.db, job.ScanRunID)
	if errors.Is(err, igagraph.ErrSuperseded) {
		return true, s.abandonAndRelease(ctx, job, version, "superseded during load")
	}
	if err != nil {
		return true, s.failKeepBarrier(ctx, job, version, err)
	}

	err = s.projectAndReconcile(ctx, snap, job, version)

	// A replay of a run that already committed is SUCCESS, not failure. The
	// graph transaction wrote nothing on this attempt (§4.6 step 2), so there
	// is nothing to undo -- only the job and the barrier to settle, in the
	// same order and transaction as a normal completion.
	var done *igagraph.AlreadyPublished
	if errors.As(err, &done) {
		return true, s.completeAndRelease(ctx, job, version)
	}
	if errors.Is(err, igagraph.ErrSuperseded) {
		return true, s.abandonAndRelease(ctx, job, version, "superseded by a newer publication")
	}
	if err != nil {
		return true, s.failKeepBarrier(ctx, job, version, err)
	}
	return true, s.completeAndRelease(ctx, job, version)
}

// holdBarrier returns the barrier version this worker holds for the job's run,
// recovering an expired projecting lease into the same phase when its previous
// holder is gone.
func (s *ProjectionService) holdBarrier(job *models.IGAProjectionJob) (int64, error) {
	lease, err := s.pipeline.Get(job.WorkspaceID)
	if err != nil {
		return 0, fmt.Errorf("pipeline barrier missing: %w", err)
	}
	if lease.State != models.PipelineProjecting ||
		lease.ScanRunID == nil || *lease.ScanRunID != job.ScanRunID {
		return 0, fmt.Errorf("%w: barrier is %s for run %v, not projecting run %s",
			repositories.ErrPipelineLost, lease.State, lease.ScanRunID, job.ScanRunID)
	}
	now := s.now()
	if lease.ExpiresAt != nil && lease.ExpiresAt.After(now) {
		// Still live. Only its own holder may proceed.
		if lease.Holder != s.owner {
			return 0, fmt.Errorf("%w: barrier held by %s", repositories.ErrPipelineLost, lease.Holder)
		}
		return lease.Version, nil
	}
	// Expired: take it over IN THE SAME PHASE.
	return s.pipeline.RecoverProjecting(job.WorkspaceID, s.owner, job.ScanRunID, s.lease, now)
}

// There are exactly THREE exits from a claimed projection job, and each has ONE
// implementation. No other path terminalizes a job or moves the barrier:
//
//	completeAndRelease  job complete  + barrier idle      (success, or replay)
//	abandonAndRelease   job abandoned + barrier idle      (superseded, or past the ceiling)
//	failKeepBarrier     job failed    + barrier UNCHANGED (transient; will be retried)
//
// FENCING IS WHAT MAKES "never release someone else's barrier" TRUE. Both
// writes in a *AndRelease are fenced -- the job on its lease_version, the
// barrier on (workspace, phase, run, version) -- and they share ONE
// transaction. If recovery has already reclaimed either, that fence matches
// zero rows, the transaction rolls back, and THIS worker changes nothing.

// completeAndRelease is the ONLY way a projection leaves the projecting phase
// successfully. Job first, barrier second, one transaction: there is no
// committed state in which the barrier is idle while the job could still
// commit. A crash before it commits leaves both as they were; recovery
// reclaims projecting and the replay hits AlreadyPublished and lands here
// again. Idempotent by construction, because every step is fenced.
func (s *ProjectionService) completeAndRelease(
	ctx context.Context, job *models.IGAProjectionJob, version int64,
) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.jobs.CompleteTx(tx, job.ID, s.owner, job.LeaseVersion); err != nil {
			return err
		}
		return s.pipeline.ReleaseTx(tx, s.fence(job, version))
	})
}

func (s *ProjectionService) abandonAndRelease(
	ctx context.Context, job *models.IGAProjectionJob, version int64, reason string,
) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.jobs.AbandonTx(tx, job.ID, s.owner, job.LeaseVersion, reason); err != nil {
			return err // ErrLeaseLost: not ours any more -- change nothing
		}
		return s.pipeline.ReleaseTx(tx, s.fence(job, version))
	})
}

// failKeepBarrier records a TRANSIENT failure and deliberately leaves the
// barrier projecting. The job is not terminal: it is reclaimed and retried,
// and its inventory must stay frozen until it succeeds -- releasing here would
// admit a scan while this projection is still pending, which is the overwrite
// the barrier exists to prevent.
//
// Past the attempts ceiling it is no longer transient and escalates to
// abandonAndRelease: the job becomes terminal and the workspace is unblocked,
// with the failure recorded to alert on.
func (s *ProjectionService) failKeepBarrier(
	ctx context.Context, job *models.IGAProjectionJob, version int64, cause error,
) error {
	if job.Attempts >= s.maxAttempts {
		return s.abandonAndRelease(ctx, job, version,
			fmt.Sprintf("gave up after %d attempts: %v", job.Attempts, cause))
	}
	return s.jobs.Fail(job.ID, s.owner, job.LeaseVersion, cause.Error())
}

func (s *ProjectionService) fence(job *models.IGAProjectionJob, version int64) repositories.PipelineFence {
	return repositories.PipelineFence{
		WorkspaceID: job.WorkspaceID,
		Phase:       models.PipelineProjecting,
		RunID:       job.ScanRunID,
		Version:     version,
	}
}

// projectAndReconcile is THE ONE TRANSACTION.
//
// Project and Reconcile are its two halves. Committing projection first
// publishes a graph in which nothing has been closed yet -- every stale edge
// still reading `current` -- and a crash in between leaves it that way until
// the next run. One transaction means readers see the before state or the
// after state, never the gap.
func (s *ProjectionService) projectAndReconcile(
	ctx context.Context, snap *igagraph.Snapshot,
	job *models.IGAProjectionJob, pipelineVersion int64,
) error {
	existing, err := igagraph.LoadExisting(ctx, s.db, snap.Run.WorkspaceID)
	if err != nil {
		return err
	}

	fencer := projectionFencer{jobs: s.jobs, pipeline: s.pipeline, version: pipelineVersion}
	projector := igagraph.NewProjector(
		s.graph, fencer, existing,
		job.ID, s.owner, job.LeaseVersion, pipelineVersion,
		s.now, igagraph.LastGenerationFor,
	)
	reconciler := igagraph.NewReconciler(s.now)

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := projector.Project(tx, snap); err != nil {
			return err
		}
		return reconciler.Reconcile(tx, snap)
	})
}

// heartbeat renews the job lease while the projection runs.
func (s *ProjectionService) heartbeat(ctx context.Context, job *models.IGAProjectionJob) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(s.lease / 3)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.jobs.Renew(job.ID, s.owner, job.LeaseVersion, s.lease); err != nil {
					// The lease is gone. Stop renewing; the next fenced write
					// inside the transaction fails and nothing is committed.
					return
				}
			}
		}
	}()
	return func() { close(done) }
}
