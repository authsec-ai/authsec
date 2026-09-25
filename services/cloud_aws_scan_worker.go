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
	// projectionPipelineLease is the workspace barrier's expiry, in either
	// phase. Renewed on every heartbeat, so it bounds how long a DEAD holder
	// blocks recovery, not how long a live one may work.
	projectionPipelineLease = 15 * time.Minute
	scanLeaseHeartbeat      = 1 * time.Minute
	scanPollInterval        = 10 * time.Second
	// A run that has failed this many times stops being retried. Without this a
	// permanently broken connector is retried forever and starves the queue.
	scanMaxAttempts = 3
)

// ScannerHook lets a caller configure the three scanners a run uses -- how the
// integration suite gives the REAL worker fake AWS clients, so two consecutive
// scans through the worker are exercised rather than reasoned about.
type ScannerHook func(iam *AWSIAMScanner, perm *AWSPermissionScanner, wl *AWSWorkloadScanner)

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

	// gate is IGA_GRAPH_PROJECTION (§2.8), and the ONLY thing that decides
	// whether this worker uses the barrier and enqueues projection jobs:
	//
	//	off                 Phase 1 exactly: no barrier, no job, no Phase 2 SQL
	//	on, not verified    claims nothing (fail closed)
	//	on, verified        barrier + job enqueue + hand-off to the job
	gate *GraphProjectionGate

	// The Phase 2 pipeline (§2.10A). jobs enqueues the projection work inside
	// the publish transaction; pipeline is the workspace-wide barrier that
	// stops a second connector's scan rewriting inventory a projection is
	// about to read.
	jobs     repositories.IGAProjectionJobRepository
	pipeline repositories.IGAPipelineLeaseRepository

	scannerHook ScannerHook
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

// WithPoll sets the sleep between empty or refused claims.
func (w *AWSScanWorker) WithPoll(d time.Duration) *AWSScanWorker { w.poll = d; return w }

// WithGraphProjection binds the worker to a projection gate. Without one it
// reads the process-wide gate, which defaults to off.
func (w *AWSScanWorker) WithGraphProjection(g *GraphProjectionGate) *AWSScanWorker {
	w.gate = g
	return w
}

// WithScannerHook configures every run's scanners, e.g. with fake AWS clients.
func (w *AWSScanWorker) WithScannerHook(h ScannerHook) *AWSScanWorker { w.scannerHook = h; return w }

func (w *AWSScanWorker) projectionGate() *GraphProjectionGate {
	if w.gate != nil {
		return w.gate
	}
	return GraphProjection()
}

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

// RunOnce claims and executes at most one scan. Reports whether it did work;
// false after an empty queue AND after a refused claim, so Run sleeps its poll
// interval before claiming again (§2.10A -- a refused run that is re-claimed at
// once is a hot loop).
//
// Separated from Run so a test can drive exactly one pass rather than race a
// polling loop.
func (w *AWSScanWorker) RunOnce(ctx context.Context) (bool, error) {
	gate := w.projectionGate()
	if !gate.ClaimAllowed() {
		// FAIL CLOSED (§2.8). The switch is on and the schema is not verified.
		// Falling back to Phase 1 here would scan without the barrier while a
		// projector elsewhere may run, which is the overwrite it prevents.
		return false, nil
	}
	pipeline := gate.PipelineMode()

	var run *models.CloudScanRun
	var err error
	if pipeline {
		run, err = w.runs.ClaimForPipeline(w.owner, w.lease, w.nowFunc())
	} else {
		run, err = w.runs.Claim(w.owner, w.lease, w.nowFunc())
	}
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

	if !pipeline {
		// IGA_GRAPH_PROJECTION off: exactly the Phase 1 behaviour. No barrier,
		// no job, and nothing in this path names a Phase 2 table -- so it runs
		// unchanged against any schema, any number of consecutive times (S1).
		if err := w.execute(ctx, run, 0); err != nil {
			if ferr := w.runs.Fail(run.ID, w.owner, run.LeaseVersion, err.Error()); ferr != nil {
				log.Printf("aws scan worker %s: could not record failure for run %s: %v",
					w.owner, run.ID, ferr)
			}
			return true, err
		}
		return true, nil
	}

	// THE WORKSPACE BARRIER (§2.10A). Claimed before any inventory is written
	// and released only after projection finishes, so a published run's
	// inventory cannot change while its projection reads it.
	//
	// Refusal is not an error: another connector in this workspace is
	// collecting or projecting. The run goes to the BACK of the queue and this
	// worker backs off. THIS IS THE THROUGHPUT CEILING the spec states
	// plainly -- a customer with five AWS accounts scans them one at a time.
	version, perr := w.pipeline.AcquireForCollection(
		run.WorkspaceID, w.owner, run.ID, projectionPipelineLease, w.nowFunc())
	if perr != nil {
		if rerr := w.runs.Requeue(run.ID, w.owner, run.LeaseVersion); rerr != nil {
			log.Printf("aws scan worker %s: could not requeue run %s: %v", w.owner, run.ID, rerr)
		}
		return false, nil
	}

	if err := w.execute(ctx, run, version); err != nil {
		// TERMINALIZE THE RUN AND RELEASE THE BARRIER TOGETHER (§2.10A).
		//
		// The run is `failed`, not `abandoned`: abandon means giving up past
		// the attempts ceiling, and a transient scan failure is retried. But
		// the barrier must still come back to idle, because publication never
		// happened -- nothing is waiting to be projected, and holding
		// `collecting` would block every other connector in the workspace.
		//
		// One transaction, both fenced: if this worker has already been
		// superseded, neither write lands and the current owner decides.
		if terr := w.db.Transaction(func(tx *gorm.DB) error {
			if ferr := w.runs.FailTx(tx, run.ID, w.owner, run.LeaseVersion, err.Error()); ferr != nil {
				return ferr
			}
			return w.pipeline.ReleaseTx(tx, repositories.PipelineFence{
				WorkspaceID: run.WorkspaceID,
				Phase:       models.PipelineCollecting,
				RunID:       run.ID,
				Version:     version,
				Holder:      w.owner,
			})
		}); terr != nil {
			log.Printf("aws scan worker %s: could not record failure for run %s: %v",
				w.owner, run.ID, terr)
		}
		return true, err
	}
	return true, nil
}

// execute performs the three scans and publishes, holding the lease throughout.
// barrierVersion is 0 in Phase 1 mode, and the collecting barrier's version in
// pipeline mode.
func (w *AWSScanWorker) execute(ctx context.Context, run *models.CloudScanRun, barrierVersion int64) error {
	pipeline := barrierVersion > 0

	// CANCELLATION FOR PROMPTNESS (§2.10A, part 3). If this worker loses its
	// lease mid-scan, the heartbeat cancels execCtx so context-aware work stops
	// as soon as possible. That is NECESSARY but NOT SUFFICIENT: an in-flight
	// write can already be past its ctx check, so promptness alone cannot
	// guarantee a superseded worker writes nothing.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := w.heartbeat(execCtx, run, barrierVersion, cancel)
	defer stop()

	// THE FENCE FOR CORRECTNESS (§2.10A, part 3). Every inventory write AND
	// DELETE this run makes validates, in the same transaction, that this
	// worker still owns the run -- against the row Claim bumps on reclaim.
	fence := repositories.ScanFence{
		RunID: run.ID, Owner: w.owner, LeaseVersion: run.LeaseVersion,
	}

	// Evidence is anchored on THIS run.
	evidence := NewObservationWriter(
		w.db, run.WorkspaceID, run.ConnectorID, run.ID, run.Generation).WithFence(fence)

	// THE RUN'S SCOPE, READ ONCE (§5.3 PATCH .../connectors/:id, D-54): a
	// region change applies from the NEXT scan. Every scanner below reads the
	// connector through this pinned service, so a PATCH landing mid-run cannot
	// give the EKS pass one region list and the compute pass another.
	svc := w.svc
	if svc != nil {
		pinned, perr := svc.ForRun(run.WorkspaceID, run.ConnectorID)
		if perr != nil {
			return fmt.Errorf("read connector: %w", perr)
		}
		svc = pinned
	}

	// ONE GENERATION PER RUN (§1.3, T1.5). The run's generation was assigned at
	// its first claim and survives a reclaim; the scanner stamps every row with
	// it and never recomputes scan_generation + 1 from the connector, which on
	// a reclaimed run named a DIFFERENT generation from the one its evidence
	// and its projection job carry.
	scanner := NewAWSIAMScanner(w.db, svc).WithEvidence(evidence).WithFence(fence).
		WithGeneration(run.Generation)
	permissionScanner := NewAWSPermissionScanner(w.db, svc).WithEvidence(evidence).WithFence(fence)
	workloadScanner := NewAWSWorkloadScanner(w.db, svc).WithEvidence(evidence).WithFence(fence)
	if w.scannerHook != nil {
		w.scannerHook(scanner, permissionScanner, workloadScanner)
	}

	snapshot, err := scanner.Scan(execCtx, run.WorkspaceID, run.ConnectorID)
	if err != nil {
		return fmt.Errorf("iam scan: %w", err)
	}

	// The permission and workload scans are chained on the same snapshot so
	// every row they write carries one generation. Their errors do NOT abort
	// the run: a denied surface is a coverage fact, not a failure, and the
	// identities already written are worth keeping.
	permSnapshot, permErr := permissionScanner.ScanFromSnapshot(execCtx, run.WorkspaceID, snapshot)
	if permErr != nil {
		log.Printf("aws permission scan: run=%s: %v", run.ID, permErr)
	}
	workloadSnapshot, workloadErr := workloadScanner.ScanFromSnapshot(execCtx, run.WorkspaceID, snapshot)
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

	// COVERAGE FIRST, THEN PUBLICATION, THE PROJECTION JOB AND THE BARRIER
	// HAND-OFF -- ALL IN ONE TRANSACTION, under the existing lease fence
	// (§2.8). A crash between publication and coverage used to make the loss
	// permanent: the projection would read absent coverage, canEnd would refuse
	// every partition, and the graph would silently never close anything.
	merged := scanner.FinalizeCoverage(run.WorkspaceID, run.ConnectorID, snapshot.Coverage,
		snapshot.CredentialReportSurface, permErr, permSurfaces, workloadErr, workloadSurfaces)

	if err := w.runs.PublishWithCoverage(run.ID, w.owner, run.LeaseVersion, merged,
		func(tx *gorm.DB, published *models.CloudScanRun) error {
			if !pipeline {
				// Phase 1: publication and coverage commit together, which is
				// all it needs. No job -- nothing would ever claim it.
				return nil
			}
			// A published run ALWAYS has a job. A crash between the two is
			// impossible rather than recovered.
			job := &models.IGAProjectionJob{
				WorkspaceID: published.WorkspaceID,
				ScanRunID:   published.ID,
				ConnectorID: published.ConnectorID,
				Generation:  published.Generation,
				Status:      models.ProjectionQueued,
			}
			if err := w.jobs.EnqueueTx(tx, job); err != nil {
				return fmt.Errorf("enqueue projection job: %w", err)
			}
			// HAND THE BARRIER TO THE JOB in the SAME transaction (§2.10A):
			// collecting -> projecting, holder = job:<id>. It is never
			// released in between -- that gap is where a second connector's
			// scan would overwrite a shared row the projection is about to
			// read -- and it is held by the JOB, so whichever worker claims
			// that job may proceed at once.
			if _, err := w.pipeline.ToProjectingTx(tx, published.WorkspaceID,
				w.owner, published.ID, barrierVersion, job.ID, projectionPipelineLease); err != nil {
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
// worker mid-flight, and both would then be walking the same account. In
// pipeline mode it renews the COLLECTING barrier on the same tick, so a long
// scan never looks stalled to recovery.
func (w *AWSScanWorker) heartbeat(
	ctx context.Context, run *models.CloudScanRun, barrierVersion int64, onLost context.CancelFunc,
) func() {
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
					onLost()
					return
				}
				if barrierVersion > 0 {
					if err := w.pipeline.RenewHeld(repositories.PipelineFence{
						WorkspaceID: run.WorkspaceID, Phase: models.PipelineCollecting,
						RunID: run.ID, Version: barrierVersion, Holder: w.owner,
					}, projectionPipelineLease, w.nowFunc()); err != nil {
						log.Printf("aws scan worker %s: barrier lost on run %s: %v", w.owner, run.ID, err)
						onLost()
						return
					}
				}
			}
		}
	}()
	return func() { close(done) }
}
