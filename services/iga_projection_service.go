package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

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

	owner string
	lease time.Duration
	// barrierLease is the workspace barrier's expiry, renewed on the same
	// heartbeat tick as the job lease.
	barrierLease time.Duration
	maxAttempts  int
	now          func() time.Time

	// beforeGraphTx runs once a pass has read its inputs -- the run's
	// snapshot and the existing graph -- and before its graph transaction
	// opens. Tests only (WithBeforeGraphTx): it is how §7.1 E13 supersedes a
	// LIVE pass of this service, so what stands between a superseded pass
	// and the graph is exactly this service's own fencer.
	beforeGraphTx func(job models.IGAProjectionJob)

	// v2 scheduling. Zero values keep the cloud worker on its existing path.
	v2Turn    int
	v2Checked bool
	v2OK      bool
	cloudHold time.Duration
	collector CollectorGraphWriter
	// beforeCollectorTx runs after the collector barrier is acquired and
	// before the publication transaction. Tests only.
	beforeCollectorTx func()
	// stopAfterBarrier returns after the barrier is acquired, without
	// publishing. Tests use it to simulate a dead worker.
	stopAfterBarrier bool
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
		barrierLease: 15 * time.Minute,
		maxAttempts:  repositories.MaxProjectionAttempts,
		now:          time.Now,
	}
}

// NewDefaultProjectionService wires the production service. The owner names
// this process for the job lease; the barrier is held by the JOB, so two
// services with different owners hand work to each other without waiting.
func NewDefaultProjectionService(db *gorm.DB) *ProjectionService {
	host, _ := os.Hostname()
	return NewProjectionService(db,
		repositories.NewIGAProjectionJobRepository(db),
		repositories.NewIGAPipelineLeaseRepository(db),
		repositories.NewIGAGraphRepository(),
		fmt.Sprintf("projector/%s/%d/%s", host, os.Getpid(), uuid.NewString()[:8]),
		5*time.Minute)
}

// WithBeforeGraphTx makes every pass call fn after it has read its inputs and
// before its graph transaction opens, with the job as claimed. Tests only: fn
// may expire and reclaim the job, and the pass then runs on the lease it
// claimed, exactly as a paused worker wakes -- nothing but the fence inside
// the transaction refuses it. Nothing is held while fn runs (the snapshot's
// read-only transaction has closed), so fn may use the database freely.
func (s *ProjectionService) WithBeforeGraphTx(fn func(job models.IGAProjectionJob)) *ProjectionService {
	s.beforeGraphTx = fn
	return s
}

// projectionFencer binds the two ownership proofs the graph transaction needs:
// this worker still owns the JOB, and the workspace BARRIER is still projecting
// this run, held by this job, at this version.
type projectionFencer struct {
	jobs     repositories.IGAProjectionJobRepository
	pipeline repositories.IGAPipelineLeaseRepository
	jobID    uuid.UUID
}

func (f projectionFencer) AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, v int64) error {
	return f.jobs.AssertOwnedTx(tx, jobID, owner, v)
}

func (f projectionFencer) AssertHeldTx(tx *gorm.DB, ws, runID uuid.UUID, version int64) error {
	return f.pipeline.AssertHeldTx(tx, repositories.PipelineFence{
		WorkspaceID: ws, Phase: models.PipelineProjecting, RunID: runID, Version: version,
		Holder: models.PipelineJobHolder(f.jobID),
	})
}

// Run claims jobs until the context ends.
//
// main starts it ONLY once IGA_GRAPH_PROJECTION is on and the schema verified
// (GraphProjectionGate.VerifyUntilReady), so it never runs against a schema it
// cannot use -- the switch decides, not a probe here.
func (s *ProjectionService) Run(ctx context.Context, poll time.Duration) {
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
			// Recovery. Deleting the old blind sweep was right -- it returned
			// an expired projecting barrier to idle, which is the overwrite
			// the barrier exists to prevent -- but nothing replaced it, and
			// then NOTHING ever reached idle. A workspace whose projection
			// failed once stayed frozen forever.
			if err := s.RecoverStalled(ctx, s.now()); err != nil {
				log.Printf("[projection] recovery: %v", err)
			}
		}
	}
}

// RecoverStalled frees barriers whose work can no longer make progress.
//
// It is PHASE-AWARE, which is the whole point: expiry alone never means
// "release". For each expired barrier it asks whether the work behind it is
// still reachable, and only gives up when it is not.
//
//	collecting + run still claimable   -> leave it; the scan's own reclaim wins
//	collecting + run terminal          -> abandon; nobody will ever finish it
//	projecting + job still claimable   -> leave it; the job's own reclaim wins
//	projecting + job complete          -> release; completeAndRelease was
//	                                      interrupted between its two writes
//	projecting + job unreachable       -> abandon
//
// Abandon terminalizes the run and the job FIRST and only then returns the
// barrier to idle, in one transaction, so nothing is admitted while either
// could still commit.
func (s *ProjectionService) RecoverStalled(ctx context.Context, now time.Time) error {
	stalled, err := s.pipeline.ExpiredCandidates(now, 50)
	if err != nil {
		return err
	}
	for i := range stalled {
		lease := stalled[i]
		if lease.ScanRunID == nil && lease.IGAScanRunID == nil {
			continue // idle rows carry no run; ExpiredCandidates excludes them
		}
		fence := repositories.PipelineFence{
			WorkspaceID: lease.WorkspaceID,
			Phase:       lease.State,
			Version:     lease.Version,
			Holder:      lease.Holder,
		}
		if lease.IGAScanRunID != nil && lease.ScanRunID == nil {
			fence.RunKind = models.RunKindCollector
			fence.RunID = *lease.IGAScanRunID
		} else if lease.ScanRunID != nil {
			fence.RunID = *lease.ScanRunID
		} else {
			continue
		}
		// Decide AND act in one transaction, with the run or job row locked
		// (FOR UPDATE), so a worker that claims or heartbeats the job while
		// recovery is deciding cannot be abandoned on a stale read (R2).
		var reason string
		var action recoveryAction
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var derr error
			reason, action, derr = s.recoveryFor(tx, lease, now)
			if derr != nil {
				return derr
			}
			switch action {
			case recoveryRelease:
				return s.pipeline.ReleaseTx(tx, fence)
			case recoveryAbandon:
				return s.pipeline.AbandonTx(tx, fence, reason)
			}
			return nil
		})
		switch {
		case err != nil:
			log.Printf("[projection] recovery %s (%s): %v", lease.WorkspaceID, lease.State, err)
		case action == recoveryAbandon:
			log.Printf("[projection] recovered wedged workspace %s (%s): %s",
				lease.WorkspaceID, lease.State, reason)
		}
	}
	return nil
}

type recoveryAction int

const (
	recoveryLeave recoveryAction = iota
	recoveryRelease
	recoveryAbandon
)

// recoveryFor decides what an expired barrier needs, by asking whether the
// work behind it can still be picked up by anyone -- or is being worked on
// right now.
//
// A row that does not exist is unreachable work; a row that could not be READ
// is not evidence of anything, so a read error is returned and the barrier is
// left for the next pass rather than abandoned.
func (s *ProjectionService) recoveryFor(
	tx *gorm.DB, lease models.IGAPipelineLease, now time.Time,
) (string, recoveryAction, error) {
	locked := tx.Clauses(clause.Locking{Strength: "UPDATE"})
	switch lease.State {
	case models.PipelineCollecting:
		var run models.CloudScanRun
		if err := locked.First(&run, "id = ?", *lease.ScanRunID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "collecting barrier for a run that no longer exists", recoveryAbandon, nil
			}
			return "", recoveryLeave, fmt.Errorf("read scan run: %w", err)
		}
		if run.Terminal() {
			// The scan gave up (or was abandoned) without releasing the
			// barrier a previous attempt took. Nobody will finish it.
			return fmt.Sprintf("scan run is %s and will not resume", run.Status), recoveryAbandon, nil
		}
		// queued or running-but-expired: the scan worker's own Claim reclaims
		// it and AcquireForCollection takes the barrier back in-phase.
		return "", recoveryLeave, nil

	case models.PipelineProjecting:
		var job models.IGAProjectionJob
		q := locked
		switch {
		case lease.IGAScanRunID != nil && lease.ScanRunID == nil:
			q = q.Where("iga_scan_run_id = ?", *lease.IGAScanRunID)
		case lease.ScanRunID != nil:
			q = q.Where("scan_run_id = ?", *lease.ScanRunID)
		default:
			return "projecting barrier with no run", recoveryAbandon, nil
		}
		if err := q.First(&job).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "projecting barrier with no projection job", recoveryAbandon, nil
			}
			return "", recoveryLeave, fmt.Errorf("read projection job: %w", err)
		}
		switch job.Status {
		case models.ProjectionComplete:
			// completeAndRelease is one transaction, so this should be
			// unreachable -- but if the barrier is somehow still held for a
			// completed job, releasing is right and abandoning would wrongly
			// mark a successful job abandoned.
			return "", recoveryRelease, nil
		case models.ProjectionAbandoned:
			return "projection job already abandoned", recoveryAbandon, nil
		}
		// An attempt running under a live lease is being worked on NOW, even
		// if it is the last one allowed: the ceiling decides whether another
		// attempt may START, never whether the current one may finish.
		if job.Status == models.ProjectionRunning && job.LeaseExpiresAt != nil && job.LeaseExpiresAt.After(now) {
			return "", recoveryLeave, nil
		}
		if job.Attempts >= s.maxAttempts {
			// Past the ceiling, Claim will never pick it up again.
			return fmt.Sprintf("projection gave up after %d attempts", job.Attempts), recoveryAbandon, nil
		}
		// queued, running-but-expired, or failed past its backoff: all
		// claimable, so the job's own reclaim gets another go.
		return "", recoveryLeave, nil
	}
	return "", recoveryLeave, nil
}

// WithCloudHold sleeps after a cloud claim when IGA_V2_PROJECTION is on.
// Tests use it to prove the scheduler gives the collector arm a turn before a
// queue of slow cloud jobs drains. Production leaves it zero.
func (s *ProjectionService) WithCloudHold(d time.Duration) *ProjectionService {
	s.cloudHold = d
	return s
}

// WithCollectorWriter installs the normalizer the collector arm runs. The
// default is SupportWriter, which writes support against canonical rows that
// already exist. Tests install FixtureWriter, which also creates nodes.
func (s *ProjectionService) WithCollectorWriter(w CollectorGraphWriter) *ProjectionService {
	s.collector = w
	return s
}

// WithBeforeCollectorTx runs fn after the collector barrier is acquired and
// before its publication transaction. Tests only.
func (s *ProjectionService) WithBeforeCollectorTx(fn func()) *ProjectionService {
	s.beforeCollectorTx = fn
	return s
}

// WithStopAfterBarrier makes the next collector pass return after the barrier
// is acquired. Tests only: it is a dead worker that still holds the job.
func (s *ProjectionService) WithStopAfterBarrier() *ProjectionService {
	s.stopAfterBarrier = true
	return s
}

// RunOnce claims at most one job and projects it. Returns whether it worked.
//
// With IGA_V2_PROJECTION on, turns alternate between the collector arm and the
// cloud arm. A turn whose arm has nothing falls through to the other, so an
// idle arm never skips a job that is waiting. Flag off claims cloud jobs only.
func (s *ProjectionService) RunOnce(ctx context.Context) (bool, error) {
	if V2ProjectionEnabled() && s.v2SchemaReady() {
		s.v2Turn++
		if s.v2Turn%2 == 0 {
			worked, err := s.projectCollectorOnce(ctx)
			if worked || err != nil {
				return worked, err
			}
		}
	}
	worked, err := s.runCloudOnce(ctx)
	if V2ProjectionEnabled() && s.v2SchemaReady() && !worked && err == nil {
		return s.projectCollectorOnce(ctx)
	}
	return worked, err
}

func (s *ProjectionService) v2SchemaReady() bool {
	if s.v2Checked {
		return s.v2OK
	}
	s.v2Checked = true
	if err := VerifyV2ProjectionSchema(s.db); err != nil {
		log.Printf("[projection] %s", err.Error())
		s.v2OK = false
		return false
	}
	s.v2OK = true
	return true
}

// runCloudOnce is the cloud claim path. Collector jobs are not visible to it.
func (s *ProjectionService) runCloudOnce(ctx context.Context) (bool, error) {
	job, err := s.jobs.Claim(s.owner, s.lease, s.now())
	if err != nil || job == nil {
		return false, err
	}
	if s.cloudHold > 0 && V2ProjectionEnabled() {
		time.Sleep(s.cloudHold)
	}
	// The barrier must be PROJECTING this run and held by THIS JOB (§2.10A).
	// The job lease is the fence between workers; the barrier names the job,
	// so a reclaimed job proceeds at once instead of waiting out a lease held
	// in a dead worker's name.
	version, err := s.holdBarrier(job)
	if err != nil {
		// The barrier is not this job's -- an inconsistency, not contention.
		// Do NOT terminalize the job and do NOT touch the barrier. Hand the job
		// back (to the back of the queue) and let recovery settle the barrier.
		if rerr := s.jobs.Requeue(job.ID, s.owner, job.LeaseVersion); rerr != nil {
			log.Printf("[projection] could not requeue job %s: %v", job.ID, rerr)
		}
		return true, fmt.Errorf("projection job %s: %w", job.ID, err)
	}

	// Heartbeat starts only once the barrier is established, because it
	// renews BOTH the job lease and the barrier: a projection that outruns the
	// barrier lease would otherwise show up in ExpiredCandidates while
	// perfectly healthy, and recovery could abandon live work.
	stop := s.heartbeat(ctx, job, version)
	defer stop()

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

// holdBarrier returns the barrier version when the barrier is projecting this
// job's run and is held by this job. There is no worker name to match and no
// expiry to consult: whoever holds the job's lease may proceed (§4.11).
func (s *ProjectionService) holdBarrier(job *models.IGAProjectionJob) (int64, error) {
	lease, err := s.pipeline.Get(job.WorkspaceID)
	if err != nil {
		return 0, fmt.Errorf("pipeline barrier missing: %w", err)
	}
	want := models.PipelineJobHolder(job.ID)
	if lease.State != models.PipelineProjecting ||
		lease.ScanRunID == nil || *lease.ScanRunID != job.ScanRunID ||
		lease.Holder != want {
		return 0, fmt.Errorf("%w: barrier is %s/%s for run %v, not %s for run %s",
			repositories.ErrPipelineLost, lease.State, lease.Holder, lease.ScanRunID,
			want, job.ScanRunID)
	}
	// A reclaim can find the barrier already past its expiry. Renew it now,
	// not at the first heartbeat: until then recovery would see an expired
	// barrier over a job that is in fact being worked (R2).
	if err := s.pipeline.RenewHeld(s.fence(job, lease.Version), s.barrierLease, s.now()); err != nil {
		return 0, err
	}
	return lease.Version, nil
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
		Holder:      models.PipelineJobHolder(job.ID),
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

	fencer := projectionFencer{jobs: s.jobs, pipeline: s.pipeline, jobID: job.ID}
	projector := igagraph.NewProjector(
		s.graph, fencer, existing,
		job.ID, s.owner, job.LeaseVersion, pipelineVersion,
		s.now, igagraph.LastGenerationFor,
	)
	reconciler := igagraph.NewReconciler(s.now)

	if s.beforeGraphTx != nil {
		s.beforeGraphTx(*job)
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := projector.Project(tx, snap); err != nil {
			return err
		}
		// Reconcile with the exclusions Project computed -- what this run's
		// unreadable documents declared, which must go stale and never end --
		// then flush the lifecycle log. Its FK to the publication is
		// DEFERRED, so the events commit only together with it (036).
		if err := reconciler.Reconcile(tx, snap, projector.Exclusions(), projector.Events()); err != nil {
			return err
		}
		// Edges written without their required evidence are still published --
		// the configuration was read -- but never silently (§4.8): the count
		// per edge kind and role is reported with the run it came from.
		if len(projector.EvidenceMissing) > 0 {
			log.Printf("[projection] run %s published edges missing evidence: %v",
				job.ScanRunID, projector.EvidenceMissing)
		}
		return projector.Events().Flush(tx, s.graph)
	})
}

// heartbeat renews the job lease while the projection runs.
func (s *ProjectionService) heartbeat(
	ctx context.Context, job *models.IGAProjectionJob, barrierVersion int64,
) func() {
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
				// And the barrier, on the SAME tick. Renewing one without the
				// other is how a healthy long projection ends up looking
				// stalled to the recovery loop.
				if err := s.pipeline.RenewHeld(s.fence(job, barrierVersion),
					s.barrierLease, s.now()); err != nil {
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

/* ----------------------------- test seams -------------------------------- */
//
// The three exits are the contract that decides whether a workspace is left
// usable, and they were previously reachable only through a full RunOnce with
// a real snapshot -- which is why they had no coverage at all and the wedge
// went unnoticed. These expose them directly, named for their purpose, so a
// test asserts job state + barrier state + fencing rather than the plumbing
// that leads there.

// CompleteAndReleaseForTest exposes completeAndRelease.
func (s *ProjectionService) CompleteAndReleaseForTest(
	ctx context.Context, job *models.IGAProjectionJob, barrierVersion int64,
) error {
	return s.completeAndRelease(ctx, job, barrierVersion)
}

// AbandonAndReleaseForTest exposes abandonAndRelease.
func (s *ProjectionService) AbandonAndReleaseForTest(
	ctx context.Context, job *models.IGAProjectionJob, barrierVersion int64, reason string,
) error {
	return s.abandonAndRelease(ctx, job, barrierVersion, reason)
}

// FailKeepBarrierForTest exposes failKeepBarrier, including its escalation to
// abandonAndRelease past the attempts ceiling.
func (s *ProjectionService) FailKeepBarrierForTest(
	ctx context.Context, job *models.IGAProjectionJob, barrierVersion int64, cause error,
) error {
	return s.failKeepBarrier(ctx, job, barrierVersion, cause)
}

// MaxAttemptsForTest reports the ceiling failKeepBarrier escalates at.
func (s *ProjectionService) MaxAttemptsForTest() int { return s.maxAttempts }
