package services

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"

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
	now   func() time.Time
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
		owner: owner, lease: lease, now: time.Now,
	}
}

// Run claims jobs until the context ends.
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
			// Recovery sweep: a worker that died holding the pipeline must not
			// wedge its workspace permanently.
			if _, err := s.pipeline.Sweep(s.now()); err != nil {
				log.Printf("[projection] pipeline sweep: %v", err)
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

	// STALENESS IS NOT CHECKED HERE. A check before the read is stale by the
	// time the read runs; Load performs it inside the same repeatable-read
	// snapshot as the inventory queries and returns ErrSuperseded.
	snap, err := igagraph.Load(ctx, s.db, job.ScanRunID)
	if errors.Is(err, igagraph.ErrSuperseded) {
		// Detected inside the snapshot, which is the only place it can be
		// detected reliably. RECORDED, not silent: a permanently-losing job
		// must not look like one that never ran.
		return true, s.jobs.Abandon(job.ID, s.owner, job.LeaseVersion, "superseded during load")
	}
	if err != nil {
		return true, s.jobs.Fail(job.ID, s.owner, job.LeaseVersion, err.Error())
	}

	// The pipeline version this job must still hold. Read once, asserted
	// inside the graph transaction.
	lease, err := s.pipeline.Get(snap.Run.WorkspaceID)
	if err != nil {
		return true, s.jobs.Fail(job.ID, s.owner, job.LeaseVersion, "pipeline lease missing: "+err.Error())
	}

	if err := s.projectAndReconcile(ctx, snap, job, lease.Version); err != nil {
		if errors.Is(err, igagraph.ErrObsoleteGeneration) {
			return true, s.jobs.Abandon(job.ID, s.owner, job.LeaseVersion, "generation already projected")
		}
		// FAIL, DO NOT COMPLETE. The lease expires, the job is reclaimed, and
		// projection is idempotent -- so a retry converges. A job marked
		// complete after a partial write is unrecoverable without a manual
		// rebuild.
		return true, s.jobs.Fail(job.ID, s.owner, job.LeaseVersion, err.Error())
	}

	if err := s.jobs.Complete(job.ID, s.owner, job.LeaseVersion); err != nil {
		return true, err
	}
	// Projection is done; hand the workspace back so the next scan can claim
	// it. A failure here is recovered by the expiry sweep.
	if err := s.pipeline.Release(snap.Run.WorkspaceID, lease.Version); err != nil {
		log.Printf("[projection] release pipeline: %v", err)
	}
	return true, nil
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

	projector := igagraph.NewProjector(
		s.graph, s.jobs, existing,
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
