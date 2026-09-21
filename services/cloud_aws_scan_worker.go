package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// How long a worker holds a scan before another may take it, and how often it
// says it is still alive.
//
// The lease has to outlast the longest gap between renewals, not the longest
// scan: the scan renews as it goes. Five minutes against a one-minute heartbeat
// leaves four missed renewals of slack, which is generous for a GC pause and
// short enough that a crashed worker's account is rescannable within the
// quarter-hour.
const (
	scanLeaseDuration = 5 * time.Minute
	// projectionPipelineLease is how long the workspace barrier is held once
	// publication hands it to the projector. Longer than the scan lease
	// because a projection that overruns must not have its workspace stolen
	// mid-transaction; the expiry sweep is the backstop, not the normal path.
	projectionPipelineLease = 15 * time.Minute
	scanLeaseHeartbeat      = 1 * time.Minute
	scanPollInterval        = 10 * time.Second
	// A run that has failed this many times stops being retried. Without this a
	// permanently broken connector is retried forever and starves the queue.
	scanMaxAttempts = 3
)

// AWSScanWorker executes queued AWS scans.
//
// It exists because a scan used to be a `go func()` started by an HTTP handler:
// a restart lost the run with nothing recording it had been in flight, two
// requests could walk the same account at once, and a worker everyone had given
// up on could still publish results older than the run that replaced it.
//
// The worker owns none of the scanning logic — it claims a run, calls the same
// three scanners the handler used to, and publishes under a fence.
type AWSScanWorker struct {
	db      *gorm.DB
	runs    repositories.CloudScanRunRepository
	svc     *AWSOnboardingService
	owner   string
	lease   time.Duration
	poll    time.Duration
	nowFunc func() time.Time

	// The Phase 2 pipeline (§2.10A). jobs enqueues the projection work inside
	// the publish transaction; pipeline is the workspace-wide barrier that
	// stops a second connector's scan rewriting inventory a projection is
	// about to read.
	jobs     repositories.IGAProjectionJobRepository
	pipeline repositories.IGAPipelineLeaseRepository
	// pipelineVersion is the fence this worker claimed for the workspace. It
	// is demanded by every later transition, so a worker that slept past its
	// expiry is refused because the version moved on.
	pipelineVersion int64
}

func NewAWSScanWorker(db *gorm.DB, svc *AWSOnboardingService) *AWSScanWorker {
	host, _ := os.Hostname()
	return &AWSScanWorker{
		db:       db,
		runs:     repositories.NewCloudScanRunRepository(db),
		jobs:     repositories.NewIGAProjectionJobRepository(db),
		pipeline: repositories.NewIGAPipelineLeaseRepository(db),
		svc:      svc,
		owner:    fmt.Sprintf("%s/%d/%s", host, os.Getpid(), uuid.NewString()[:8]),
		lease:    scanLeaseDuration,
		poll:     scanPollInterval,
		nowFunc:  time.Now,
	}
}

// WithOwner names this worker. Tests use it to stage two workers against one
// run; production uses the host/pid/nonce default.
func (w *AWSScanWorker) WithOwner(owner string) *AWSScanWorker { w.owner = owner; return w }

// WithLease shortens the lease so a test can let one expire without waiting.
func (w *AWSScanWorker) WithLease(d time.Duration) *AWSScanWorker { w.lease = d; return w }

// WithClock replaces time.Now, so a test can move past a lease expiry.
func (w *AWSScanWorker) WithClock(f func() time.Time) *AWSScanWorker { w.nowFunc = f; return w }

// Run polls for claimable scans until the context ends.
func (w *AWSScanWorker) Run(ctx context.Context) {
	log.Printf("aws scan worker %s started", w.owner)
	for {
		select {
		case <-ctx.Done():
			log.Printf("aws scan worker %s stopping", w.owner)
			return
		default:
		}
		worked, err := w.RunOnce(ctx)
		if err != nil {
			log.Printf("aws scan worker %s: %v", w.owner, err)
		}
		if !worked {
			select {
			case <-ctx.Done():
				return
			case <-time.After(w.poll):
			}
		}
	}
}

// RunOnce claims and executes at most one scan. Reports whether it found work.
//
// Separated from Run so a test can drive exactly one pass rather than race a
// polling loop.
func (w *AWSScanWorker) RunOnce(ctx context.Context) (bool, error) {
	run, err := w.runs.Claim(w.owner, w.lease, w.nowFunc())
	if err != nil {
		return false, fmt.Errorf("claim: %w", err)
	}
	if run == nil {
		return false, nil
	}

	// A run that has failed repeatedly is stopped rather than retried forever:
	// a permanently broken connector would otherwise occupy the queue and hide
	// every other account's scan behind it.
	if run.Attempts > scanMaxAttempts {
		_ = w.runs.Fail(run.ID, w.owner, run.LeaseVersion,
			fmt.Sprintf("gave up after %d attempts", run.Attempts-1))
		return true, nil
	}

	// THE WORKSPACE BARRIER (§2.10A). Claimed before any inventory is written
	// and released only after projection finishes, so a published run's
	// inventory cannot change while its projection reads it.
	//
	// Refusal is not an error: another connector in this workspace is
	// collecting or projecting. The run goes back to the queue and is claimed
	// again once the workspace is free. THIS IS THE THROUGHPUT CEILING the
	// spec states plainly -- a customer with five AWS accounts scans them one
	// at a time, and nothing narrower is sound because the shared-resource
	// writer crosses connectors.
	version, perr := w.pipeline.ClaimForCollection(
		run.WorkspaceID, w.owner, run.ID, projectionPipelineLease, w.nowFunc())
	if perr != nil {
		if rerr := w.runs.Requeue(run.ID, w.owner, run.LeaseVersion); rerr != nil {
			log.Printf("aws scan worker %s: could not requeue run %s: %v", w.owner, run.ID, rerr)
		}
		return true, nil
	}
	w.pipelineVersion = version

	if err := w.execute(ctx, run); err != nil {
		// Hand the workspace back: publication never happened, so nothing is
		// waiting to be projected and holding the barrier would block every
		// other connector until the sweep.
		if rerr := w.pipeline.Release(run.WorkspaceID, w.pipelineVersion); rerr != nil {
			log.Printf("aws scan worker %s: could not release pipeline: %v", w.owner, rerr)
		}
		// Fail is fenced too. If it returns ErrLeaseLost the run was already
		// taken by someone else, and recording our failure on it would overwrite
		// their result with ours.
		if ferr := w.runs.Fail(run.ID, w.owner, run.LeaseVersion, err.Error()); ferr != nil {
			log.Printf("aws scan worker %s: could not record failure for run %s: %v",
				w.owner, run.ID, ferr)
		}
		return true, err
	}
	return true, nil
}

// execute performs the three scans and publishes, holding the lease throughout.
func (w *AWSScanWorker) execute(ctx context.Context, run *models.CloudScanRun) error {
	stop := w.heartbeat(ctx, run)
	defer stop()

	// Evidence is anchored on THIS run. That anchor is why the observation
	// table could exist at all: before cloud_scan_run there was nothing durable
	// for a cloud fact to point at, and the alternative -- borrowing the GitHub
	// pipeline's iga_scan_runs -- would have forced AWS into that pipeline as a
	// side effect of adding evidence.
	evidence := NewObservationWriter(
		w.db, run.WorkspaceID, run.ConnectorID, run.ID, run.Generation)

	scanner := NewAWSIAMScanner(w.db, w.svc).WithEvidence(evidence)
	permissionScanner := NewAWSPermissionScanner(w.db, w.svc).WithEvidence(evidence)
	workloadScanner := NewAWSWorkloadScanner(w.db, w.svc).WithEvidence(evidence)

	snapshot, err := scanner.Scan(ctx, run.WorkspaceID, run.ConnectorID)
	if err != nil {
		return fmt.Errorf("iam scan: %w", err)
	}

	// The permission and workload scans are chained on the same snapshot so
	// every row they write carries one generation. Their errors do NOT abort
	// the run: a denied surface is a coverage fact, not a failure, and the
	// identities already written are worth keeping.
	permSnapshot, permErr := permissionScanner.ScanFromSnapshot(ctx, run.WorkspaceID, snapshot)
	if permErr != nil {
		log.Printf("aws permission scan: run=%s: %v", run.ID, permErr)
	}
	workloadSnapshot, workloadErr := workloadScanner.ScanFromSnapshot(ctx, run.WorkspaceID, snapshot)
	if workloadErr != nil {
		log.Printf("aws workload scan: run=%s: %v", run.ID, workloadErr)
	}

	var permSurfaces, workloadSurfaces map[string]models.SurfaceCoverage
	if permSnapshot != nil {
		permSurfaces = permSnapshot.Surfaces
	}
	if workloadSnapshot != nil {
		workloadSurfaces = workloadSnapshot.Surfaces
	}

	// COVERAGE FIRST, THEN PUBLICATION AND THE PROJECTION JOB -- ALL IN ONE
	// TRANSACTION, under the existing lease fence (§2.8).
	//
	// FinalizeCoverage performs no writes, so computing it before publication
	// costs nothing. The previous sequence published first and stamped
	// coverage best-effort afterwards, on the argument that a superseded
	// worker must not overwrite the winner's report -- but the FENCE already
	// guarantees that, and inside one transaction the ordering of the two
	// writes is not observable.
	//
	// What the old sequence could not guarantee: a crash between publication
	// and coverage made the loss PERMANENT. The projection job would then read
	// absent coverage, canEnd would refuse every partition, and the graph would
	// silently never close anything -- an outage that looks like caution.
	merged := scanner.FinalizeCoverage(run.WorkspaceID, run.ConnectorID, snapshot.Coverage,
		snapshot.CredentialReportSurface, permErr, permSurfaces, workloadErr, workloadSurfaces)

	if err := w.runs.PublishWithCoverage(run.ID, w.owner, run.LeaseVersion, merged,
		func(tx *gorm.DB, published *models.CloudScanRun) error {
			// A published run ALWAYS has a job. A crash between the two is
			// impossible rather than recovered.
			if err := w.jobs.EnqueueTx(tx, &models.IGAProjectionJob{
				WorkspaceID: published.WorkspaceID,
				ScanRunID:   published.ID,
				ConnectorID: published.ConnectorID,
				Generation:  published.Generation,
				Status:      models.ProjectionQueued,
			}); err != nil {
				return fmt.Errorf("enqueue projection job: %w", err)
			}
			// Hand the workspace barrier from collecting to projecting in the
			// SAME transaction, so it is never released in between -- that gap
			// is where a second connector's scan would overwrite a shared
			// resource row the projection is about to read (§2.10A).
			if _, err := w.pipeline.ToProjectingTx(tx, published.WorkspaceID,
				w.owner, w.pipelineVersion, projectionPipelineLease); err != nil {
				return fmt.Errorf("pipeline to projecting: %w", err)
			}
			return nil
		}); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	written, skipped := evidence.Counts()
	log.Printf("aws scan run %s published: evidence %d new, %d unchanged",
		run.ID, written, skipped)
	return nil
}

// heartbeat renews the lease while the scan runs, and stops on return.
//
// Without it a scan longer than the lease would have its run claimed by another
// worker mid-flight, and both would then be walking the same account.
func (w *AWSScanWorker) heartbeat(ctx context.Context, run *models.CloudScanRun) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(scanLeaseHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := w.runs.Renew(run.ID, w.owner, run.LeaseVersion, w.lease); err != nil {
					// Losing the lease mid-scan is not recoverable by renewing
					// harder. The run belongs to someone else now; this worker's
					// publication will be refused, which is the correct outcome.
					log.Printf("aws scan worker %s: lease lost on run %s: %v", w.owner, run.ID, err)
					return
				}
			}
		}
	}()
	return func() { close(done) }
}
