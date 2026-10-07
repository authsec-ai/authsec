package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// PolicyJobWorker runs iga_gov_job (SPEC-iga-phase3-policy.md §8.1, T3.08).
//
// It claims with the fenced lease of iga_projection_job (repository
// IGAGovJobRepository): lease 2 minutes, renewed every 30 s while the handler
// runs. Every write a handler makes goes through PolicyJobRun.InTx, which
// locks the job row and proves the fence first, so a superseded worker gets
// ErrPolicyJobLeaseLost instead of a write. External calls go through
// PolicyJobRun.External (fence and lease margin checked before, fence
// re-checked after) or, for AWS mutations, the write-ahead attempt log
// (IGAGovAttemptLog).
//
// Kinds are claimed only when a handler is registered for them: a kind whose
// task has not landed stays queued rather than being "completed" by nothing
// (DECISION: deploy, verify, compile_plans, notify, observe_tick and the rest
// are not given no-op handlers; only the periodic kinds the scheduler
// produces are, so their rows do not pile up -- see RegisterPolicyJobNoops).
//
// It is started from cmd/main.go only when IGA_POLICY=on and the Phase 3
// schema verified, and claims nothing while the gate reads unavailable.
type PolicyJobWorker struct {
	db    *gorm.DB
	jobs  repositories.IGAGovJobRepository
	owner string
	gate  func() bool

	mu       sync.RWMutex
	handlers map[string]PolicyJobKind

	scheduler *PolicyJobScheduler

	Lease       time.Duration // default PolicyJobLease
	RenewEvery  time.Duration // default PolicyJobRenewEvery
	Concurrency int           // jobs run at once by this worker; default 4
	Grace       time.Duration // shutdown: how long running jobs may finish; default 30 s
	// PruneAfter is how long complete and abandoned jobs are kept; default 7 days.
	PruneAfter time.Duration

	now func() time.Time

	lastPrune time.Time
}

// §8.1 lease and renewal.
const (
	PolicyJobLease      = 2 * time.Minute
	PolicyJobRenewEvery = 30 * time.Second
	// PolicyJobExternalMargin is the least lease time an external call may
	// start with (§8.1: "the lease must have at least 60 s left or the worker
	// stops before sending").
	PolicyJobExternalMargin = 60 * time.Second
)

// PolicyJobHandler does one job. Return nil to complete it; an error built by
// PolicyJobAbandon or PolicyJobRetryLater to abandon or hand it back; any
// other error fails the try (retried with the kind's backoff until
// max_attempts). ErrPolicyJobLeaseLost (from any fenced call) stops the job
// without a further write: another worker owns it now.
type PolicyJobHandler func(ctx context.Context, run *PolicyJobRun) error

// PolicyJobKind registers a handler for one kind.
type PolicyJobKind struct {
	Kind    string
	Handler PolicyJobHandler
	// Backoff is the delay before a failed try is retried, from the attempts
	// made so far (>= 1). Default 30 s x attempts.
	Backoff func(attempts int) time.Duration
	// Timeout bounds one try; 0 means no bound beyond the lease.
	Timeout time.Duration
}

// policyJobOutcome errors.
type policyJobAbandon struct{ reason string }

func (e *policyJobAbandon) Error() string { return "abandon: " + e.reason }

type policyJobRetryLater struct {
	after  time.Duration
	reason string
}

func (e *policyJobRetryLater) Error() string { return "retry later: " + e.reason }

// PolicyJobAbandon makes the handler's job `abandoned` with the reason: the
// work no longer applies (subject gone, superseded). Recorded, not silent.
func PolicyJobAbandon(reason string) error { return &policyJobAbandon{reason: reason} }

// PolicyJobRetryLater hands the job back to the queue after the delay without
// counting the attempt: it could not proceed for a reason that is not its
// own (another job holds what it needs; settle_after not reached).
func PolicyJobRetryLater(after time.Duration, reason string) error {
	return &policyJobRetryLater{after: after, reason: reason}
}

// NewPolicyJobWorker builds a worker over db. owner names this worker in
// lease_owner; empty means hostname:pid:random.
func NewPolicyJobWorker(db *gorm.DB, owner string) *PolicyJobWorker {
	if owner == "" {
		host, _ := os.Hostname()
		owner = fmt.Sprintf("policy-worker:%s:%d:%s", host, os.Getpid(), uuid.NewString()[:8])
	}
	w := &PolicyJobWorker{
		db: db, jobs: repositories.NewIGAGovJobRepository(db), owner: owner,
		handlers: map[string]PolicyJobKind{},
		now:      time.Now,
		gate:     func() bool { return PolicyGateState().Available() },
	}
	w.scheduler = NewPolicyJobScheduler(db)
	return w
}

// Owner is this worker's lease_owner.
func (w *PolicyJobWorker) Owner() string { return w.owner }

// WithGate replaces the availability check (tests).
func (w *PolicyJobWorker) WithGate(available func() bool) *PolicyJobWorker {
	w.gate = available
	return w
}

// WithClock replaces the clock used for claims (tests).
func (w *PolicyJobWorker) WithClock(now func() time.Time) *PolicyJobWorker {
	w.now = now
	return w
}

// Scheduler is the worker's periodic-job scheduler, run on every loop tick.
func (w *PolicyJobWorker) Scheduler() *PolicyJobScheduler { return w.scheduler }

// Register installs a handler. A later registration of the same kind replaces
// the earlier one (a task filling a kind replaces its no-op).
func (w *PolicyJobWorker) Register(k PolicyJobKind) {
	if k.Kind == "" || k.Handler == nil {
		panic("policy job registration needs a kind and a handler")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers[k.Kind] = k
}

// Kinds lists the registered kinds.
func (w *PolicyJobWorker) Kinds() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]string, 0, len(w.handlers))
	for k := range w.handlers {
		out = append(out, k)
	}
	return out
}

func (w *PolicyJobWorker) handler(kind string) (PolicyJobKind, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	k, ok := w.handlers[kind]
	return k, ok
}

func (w *PolicyJobWorker) lease() time.Duration {
	if w.Lease > 0 {
		return w.Lease
	}
	return PolicyJobLease
}

func (w *PolicyJobWorker) renewEvery() time.Duration {
	if w.RenewEvery > 0 {
		return w.RenewEvery
	}
	return PolicyJobRenewEvery
}

// Run is the worker loop: every poll it sweeps exhausted jobs, runs the
// scheduler, and claims jobs up to Concurrency. It returns when ctx ends,
// after a graceful shutdown: no new claims, running jobs get Grace to finish,
// then their contexts are cancelled and each unfinished job is handed back
// (Requeue, attempt not counted). A handler cancelled mid-external-call
// leaves its write-ahead attempt `dispatched`, which the next owner marks
// `unknown` (§8.1) -- never re-sent.
func (w *PolicyJobWorker) Run(ctx context.Context, poll time.Duration) {
	if poll <= 0 {
		poll = 5 * time.Second
	}
	conc := w.Concurrency
	if conc <= 0 {
		conc = 4
	}
	grace := w.Grace
	if grace <= 0 {
		grace = 30 * time.Second
	}
	log.Printf("[policy-worker] %s started: kinds %v, lease %s, renew every %s, concurrency %d",
		w.owner, w.Kinds(), w.lease(), w.renewEvery(), conc)

	// Job contexts are NOT children of ctx: shutdown gives them Grace first.
	jobCtx, cancelJobs := context.WithCancel(context.Background())
	defer cancelJobs()
	slots := make(chan struct{}, conc)
	var wg sync.WaitGroup

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		w.tick(ctx, jobCtx, slots, &wg)
		select {
		case <-ctx.Done():
			log.Printf("[policy-worker] %s stopping: waiting up to %s for running jobs", w.owner, grace)
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(grace):
				log.Printf("[policy-worker] %s grace elapsed: cancelling running jobs (each is handed back)", w.owner)
				cancelJobs()
				<-done
			}
			log.Printf("[policy-worker] %s stopped", w.owner)
			return
		case <-ticker.C:
		}
	}
}

func (w *PolicyJobWorker) tick(ctx, jobCtx context.Context, slots chan struct{}, wg *sync.WaitGroup) {
	if ctx.Err() != nil {
		return
	}
	if w.gate != nil && !w.gate() {
		return // fail closed: the gate went unavailable; claim nothing
	}
	w.Sweep()
	if err := w.scheduler.Tick(ctx, w.now()); err != nil {
		log.Printf("[policy-worker] scheduler: %v", err)
	}
	for ctx.Err() == nil {
		select {
		case slots <- struct{}{}:
		default:
			return // every slot busy
		}
		job, err := w.claim()
		if err != nil || job == nil {
			<-slots
			if err != nil {
				log.Printf("[policy-worker] claim: %v", err)
			}
			return
		}
		wg.Add(1)
		go func(j *models.IGAGovJob) {
			defer wg.Done()
			defer func() { <-slots }()
			w.execute(jobCtx, j)
		}(job)
	}
}

// Sweep fails running jobs whose lease lapsed with no attempts left, and
// prunes finished jobs at most hourly.
func (w *PolicyJobWorker) Sweep() {
	now := w.now()
	if n, err := w.jobs.FailExhausted(now); err != nil {
		log.Printf("[policy-worker] sweep exhausted: %v", err)
	} else if n > 0 {
		log.Printf("[policy-worker] %d job(s) failed: lease expired with no attempts left", n)
	}
	if now.Sub(w.lastPrune) < time.Hour {
		return
	}
	w.lastPrune = now
	keep := w.PruneAfter
	if keep <= 0 {
		keep = 7 * 24 * time.Hour
	}
	if _, err := w.jobs.PruneFinished(now.Add(-keep)); err != nil {
		log.Printf("[policy-worker] prune: %v", err)
	}
}

func (w *PolicyJobWorker) claim() (*models.IGAGovJob, error) {
	kinds := w.Kinds()
	if len(kinds) == 0 {
		return nil, nil
	}
	return w.jobs.Claim(w.owner, w.lease(), w.now(), kinds)
}

// RunOnce claims and runs at most one job synchronously. It reports whether
// a job was run. Tests drive the worker with it.
func (w *PolicyJobWorker) RunOnce(ctx context.Context) (bool, error) {
	job, err := w.claim()
	if err != nil || job == nil {
		return false, err
	}
	w.execute(ctx, job)
	return true, nil
}

// execute runs one claimed job under its lease: a renewer keeps the lease
// alive and cancels the handler the moment the fence is lost.
func (w *PolicyJobWorker) execute(parent context.Context, job *models.IGAGovJob) {
	fence := repositories.PolicyJobFence{JobID: job.ID, Owner: w.owner, Version: job.LeaseVersion}
	k, ok := w.handler(job.Kind)
	if !ok {
		// Registered when claimed, unregistered since: hand it back.
		_ = w.jobs.Requeue(fence, 0)
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if k.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, k.Timeout)
		defer cancel()
	}
	run := &PolicyJobRun{Job: *job, Fence: fence, db: w.db, jobs: w.jobs, now: w.now, lease: w.lease()}

	renewDone := make(chan struct{})
	stopRenew := make(chan struct{})
	go func() {
		defer close(renewDone)
		t := time.NewTicker(w.renewEvery())
		defer t.Stop()
		for {
			select {
			case <-stopRenew:
				return
			case <-t.C:
				err := w.jobs.Renew(fence, w.lease())
				if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
					run.markLost()
					cancel()
					return
				}
				if err != nil {
					log.Printf("[policy-worker] renew %s %s: %v", job.Kind, job.ID, err)
				}
			}
		}
	}()

	err := safeHandle(ctx, k.Handler, run)
	close(stopRenew)
	<-renewDone

	w.finish(parent, k, run, err)
}

func safeHandle(ctx context.Context, h PolicyJobHandler, run *PolicyJobRun) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panic: %v\n%s", p, debug.Stack())
		}
	}()
	return h(ctx, run)
}

func (w *PolicyJobWorker) finish(parent context.Context, k PolicyJobKind, run *PolicyJobRun, err error) {
	job, fence := run.Job, run.Fence
	var ab *policyJobAbandon
	var rl *policyJobRetryLater
	var werr error
	switch {
	case run.lost() || errors.Is(err, repositories.ErrPolicyJobLeaseLost):
		log.Printf("[policy-worker] %s %s: lease lost at version %d; another worker owns it, nothing more written",
			job.Kind, job.ID, fence.Version)
		return
	case err == nil:
		werr = w.jobs.Complete(fence)
	case errors.As(err, &ab):
		werr = w.jobs.Abandon(fence, ab.reason)
	case errors.As(err, &rl):
		werr = w.jobs.Requeue(fence, rl.after)
	case parent.Err() != nil:
		// Shutdown cancelled it: not the job's fault, the attempt is given back.
		werr = w.jobs.Requeue(fence, 0)
	default:
		backoff := 30 * time.Second * time.Duration(job.Attempts)
		if k.Backoff != nil {
			backoff = k.Backoff(job.Attempts)
		}
		log.Printf("[policy-worker] %s %s attempt %d/%d failed: %v", job.Kind, job.ID, job.Attempts, job.MaxAttempts, err)
		werr = w.jobs.Fail(fence, err.Error(), backoff)
	}
	if werr != nil && !errors.Is(werr, repositories.ErrPolicyJobLeaseLost) {
		log.Printf("[policy-worker] %s %s: recording the outcome: %v", job.Kind, job.ID, werr)
	}
}

// PolicyJobRun is one claimed job and its fence: what a handler uses to write
// (InTx), to check it still owns the job (CheckFence) and to make an external
// call inside the lease margin (External).
type PolicyJobRun struct {
	Job   models.IGAGovJob
	Fence repositories.PolicyJobFence

	db    *gorm.DB
	jobs  repositories.IGAGovJobRepository
	now   func() time.Time
	lease time.Duration

	lostMu sync.Mutex
	isLost bool
}

// NewPolicyJobRun builds a run for a job claimed outside a worker (tests, and
// code that claims through the repository directly).
func NewPolicyJobRun(db *gorm.DB, job models.IGAGovJob, owner string) *PolicyJobRun {
	return &PolicyJobRun{
		Job: job, Fence: repositories.PolicyJobFence{JobID: job.ID, Owner: owner, Version: job.LeaseVersion},
		db: db, jobs: repositories.NewIGAGovJobRepository(db), now: time.Now, lease: PolicyJobLease,
	}
}

func (r *PolicyJobRun) markLost() {
	r.lostMu.Lock()
	r.isLost = true
	r.lostMu.Unlock()
}

func (r *PolicyJobRun) lost() bool {
	r.lostMu.Lock()
	defer r.lostMu.Unlock()
	return r.isLost
}

// DB is the worker's database, for READS. Writes go through InTx.
func (r *PolicyJobRun) DB() *gorm.DB { return r.db }

// Jobs is the job repository (to enqueue follow-up jobs inside InTx).
func (r *PolicyJobRun) Jobs() repositories.IGAGovJobRepository { return r.jobs }

// InTx runs fn in one transaction that first locks the job row and proves the
// fence (AssertOwnedTx): every write the job makes is fenced, and a reclaim
// waits for this transaction rather than racing it.
func (r *PolicyJobRun) InTx(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := r.jobs.AssertOwnedTx(tx, r.Fence); err != nil {
			if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
				r.markLost()
			}
			return err
		}
		return fn(tx)
	})
}

// CheckFence returns ErrPolicyJobLeaseLost when the job's lease is no longer
// this run's.
func (r *PolicyJobRun) CheckFence() error {
	_, err := r.jobs.LeaseRemaining(r.Fence, r.now())
	if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		r.markLost()
	}
	return err
}

// EnsureMargin proves the fence and that the lease has at least margin left,
// renewing once if it is short. ErrPolicyJobLeaseShort when it still is.
func (r *PolicyJobRun) EnsureMargin(margin time.Duration) error {
	left, err := r.jobs.LeaseRemaining(r.Fence, r.now())
	if err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			r.markLost()
		}
		return err
	}
	if left >= margin {
		return nil
	}
	if err := r.jobs.Renew(r.Fence, r.lease); err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			r.markLost()
		}
		return err
	}
	if left, err = r.jobs.LeaseRemaining(r.Fence, r.now()); err != nil {
		return err
	}
	if left < margin {
		return fmt.Errorf("%w: %s left, %s needed", repositories.ErrPolicyJobLeaseShort, left.Round(time.Second), margin)
	}
	return nil
}

// External makes an external call inside the lease margin (§8.1): the fence
// and at least margin of lease are proven BEFORE the call (else it is not
// made), and the fence is re-checked AFTER it. If the fence was lost while
// the call ran, the call's result must be discarded: External returns
// ErrPolicyJobLeaseLost (wrapping the call's own error, if any), and the
// handler must write nothing from it. margin <= 0 means
// PolicyJobExternalMargin.
//
// External is for calls whose repetition is harmless (reads, idempotent
// tags). An AWS MUTATION goes through IGAGovAttemptLog.Execute, which also
// records the write-ahead attempt.
func (r *PolicyJobRun) External(ctx context.Context, margin time.Duration, call func(ctx context.Context) error) error {
	if margin <= 0 {
		margin = PolicyJobExternalMargin
	}
	if err := r.EnsureMargin(margin); err != nil {
		return err
	}
	callErr := call(ctx)
	if err := r.CheckFence(); err != nil {
		if callErr != nil {
			return fmt.Errorf("%w (the call returned: %v)", err, callErr)
		}
		return err
	}
	return callErr
}

// RegisterPolicyJobNoops registers a no-op handler for each periodic kind the
// scheduler produces whose real handler belongs to a later task (drift_check
// T3.16, refresh_activity T3.15, iac_sync T3.17), so scheduled rows complete
// instead of piling up queued. The later task's Register replaces it.
func RegisterPolicyJobNoops(w *PolicyJobWorker) {
	for _, kind := range []string{repositories.GovJobDriftCheck, repositories.GovJobRefreshActivity, repositories.GovJobIaCSync} {
		w.Register(PolicyJobKind{Kind: kind, Handler: func(context.Context, *PolicyJobRun) error { return nil }})
	}
}

// NewDefaultPolicyJobWorker is the production worker: the handlers that exist
// in this build (evaluate_owner_rules, T3.07; notify, T3.12) plus the no-op periodic kinds,
// and the default schedules. Later tasks Register their kinds here.
func NewDefaultPolicyJobWorker(db *gorm.DB) *PolicyJobWorker {
	w := NewPolicyJobWorker(db, "")
	RegisterPolicyJobNoops(w)
	w.Register(PolicyJobKind{Kind: repositories.GovJobEvaluateOwnerRules,
		Handler: NewIGAGovOwnershipService(db).EvaluateOwnerRulesHandler})
	// T3.12: notify delivers iga_gov_notification rows (email, webhook, and
	// the channels registered with RegisterGovNotificationChannel); retry
	// attempt x 10 min, dead after 5 (§8.1).
	w.Register(NewGovNotifier(db).JobKind())
	return w
}

// StartDefaultPolicyJobWorker runs NewDefaultPolicyJobWorker until ctx ends
// and returns a channel closed when it has stopped (after its graceful
// shutdown).
func StartDefaultPolicyJobWorker(ctx context.Context, db *gorm.DB) <-chan struct{} {
	done := make(chan struct{})
	w := NewDefaultPolicyJobWorker(db)
	w.Grace = 20 * time.Second
	go func() {
		defer close(done)
		w.Run(ctx, 5*time.Second)
	}()
	return done
}
