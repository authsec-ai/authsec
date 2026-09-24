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
	scanLeaseDuration  = 5 * time.Minute
	scanLeaseHeartbeat = 1 * time.Minute
	scanPollInterval   = 10 * time.Second
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
}

func NewAWSScanWorker(db *gorm.DB, svc *AWSOnboardingService) *AWSScanWorker {
	host, _ := os.Hostname()
	return &AWSScanWorker{
		db:      db,
		runs:    repositories.NewCloudScanRunRepository(db),
		svc:     svc,
		owner:   fmt.Sprintf("%s/%d/%s", host, os.Getpid(), uuid.NewString()[:8]),
		lease:   scanLeaseDuration,
		poll:    scanPollInterval,
		nowFunc: time.Now,
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

	if err := w.execute(ctx, run); err != nil {
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

	// The same run.Generation the evidence writer above was built with. One
	// number, read once, so a row and the observation explaining it can never
	// disagree about which pass produced them.
	scanner := NewAWSIAMScanner(w.db, w.svc).
		WithEvidence(evidence).
		WithGeneration(run.Generation)
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

	// PUBLISH BEFORE COVERAGE, and refuse to write coverage if publication is
	// refused.
	//
	// Publication is the fence check. A worker whose lease was taken has stale
	// results, and coverage is the customer-visible claim "this is what your
	// account looks like" -- so it must not be written by a worker that has
	// already been superseded. Doing coverage first would let the loser
	// overwrite the winner's report.
	if err := w.runs.Publish(run.ID, w.owner, run.LeaseVersion); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	merged := scanner.FinalizeCoverage(run.WorkspaceID, run.ConnectorID, snapshot.Coverage,
		snapshot.CredentialReportSurface, permErr, permSurfaces, workloadErr, workloadSurfaces)

	// Stamped onto this run specifically, not only the connector: the
	// connector's coverage column is overwritten by whatever scan runs next,
	// so it can only ever answer for the newest one. A reader asking whether
	// THIS run licensed reconciliation must be able to read this run's own
	// report regardless of what has scanned since. Best effort, like
	// persistCoverage above it -- losing this write must not undo a
	// publication that already succeeded.
	if err := w.runs.SetCoverage(run.ID, merged); err != nil {
		log.Printf("aws scan run %s: could not stamp per-run coverage: %v", run.ID, err)
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
