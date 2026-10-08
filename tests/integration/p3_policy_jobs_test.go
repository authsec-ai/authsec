package integration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.08 (SPEC-iga-phase3-policy.md §8.1): the iga_gov_job worker -- fenced
// claim / renew / reclaim, the scheduler, the worker loop and its graceful
// shutdown, and the lease margin around external calls. Against the
// integration database (047-056).

func p3Job(t *testing.T, db *gorm.DB, ws uuid.UUID, kind, key string) *models.IGAGovJob {
	t.Helper()
	j := &models.IGAGovJob{WorkspaceID: ws, Kind: kind, DedupeKey: key}
	if created, err := repositories.NewIGAGovJobRepository(db).EnqueueTx(db, j); err != nil || !created {
		t.Fatalf("enqueue %s %s: created %v, %v", kind, key, created, err)
	}
	return j
}

func p3JobRow(t *testing.T, db *gorm.DB, id uuid.UUID) models.IGAGovJob {
	t.Helper()
	j, err := repositories.NewIGAGovJobRepository(db).Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return *j
}

// p3ClaimOwn claims, as owner, the next claimable job of kinds at now, and
// requires it to be this workspace's (the integration database is shared by
// the suite; a foreign job is a harness problem, not a pass).
func p3ClaimOwn(t *testing.T, db *gorm.DB, ws uuid.UUID, owner string, lease time.Duration, now time.Time, kinds ...string) *models.IGAGovJob {
	t.Helper()
	j, err := repositories.NewIGAGovJobRepository(db).Claim(owner, lease, now, kinds)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if j != nil && j.WorkspaceID != ws {
		t.Fatalf("claimed another workspace's job %s (%s): leftover rows in the integration database", j.ID, j.Kind)
	}
	return j
}

// Enqueue: one open job per (workspace, kind, dedupe_key); a retried enqueue
// returns the open job's id, never one that names no row. Periodic: not again
// within the interval after completion. Once: never again, whatever status.
func TestP3T308JobEnqueueDedupe(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-enqueue")
	repo := repositories.NewIGAGovJobRepository(db)

	first := p3Job(t, db, g.ws, repositories.GovJobDriftCheck, "deployment:x")
	again := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobDriftCheck, DedupeKey: "deployment:x"}
	if created, err := repo.EnqueueTx(db, again); err != nil || created || again.ID != first.ID {
		t.Fatalf("second enqueue: created %v err %v id %s, want the open job %s", created, err, again.ID, first.ID)
	}
	// Another kind, same key: its own job.
	p3Job(t, db, g.ws, repositories.GovJobVerify, "deployment:x")

	// Periodic: open -> not created; completed recently -> not created;
	// completed longer ago than the interval -> created.
	now := time.Now()
	j := p3ClaimOwn(t, db, g.ws, "w1", time.Minute, now, repositories.GovJobDriftCheck)
	if j == nil || j.ID != first.ID {
		t.Fatalf("claim = %+v, want %s", j, first.ID)
	}
	per := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobDriftCheck, DedupeKey: "deployment:x"}
	if created, err := repo.EnqueuePeriodicTx(db, per, 10*time.Minute); err != nil || created || per.ID != first.ID {
		t.Fatalf("periodic while running: created %v err %v id %s", created, err, per.ID)
	}
	if err := repo.Complete(repositories.PolicyJobFence{JobID: j.ID, Owner: "w1", Version: j.LeaseVersion}); err != nil {
		t.Fatal(err)
	}
	per = &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobDriftCheck, DedupeKey: "deployment:x"}
	if created, err := repo.EnqueuePeriodicTx(db, per, 10*time.Minute); err != nil || created || per.ID != uuid.Nil {
		t.Fatalf("periodic within the interval: created %v err %v id %s, want suppressed", created, err, per.ID)
	}
	p3exec(t, db, `UPDATE iga_gov_job SET completed_at = now() - interval '11 minutes' WHERE id = ?`, j.ID)
	per = &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobDriftCheck, DedupeKey: "deployment:x"}
	if created, err := repo.EnqueuePeriodicTx(db, per, 10*time.Minute); err != nil || !created {
		t.Fatalf("periodic after the interval: created %v err %v", created, err)
	}

	// Once: after the job ended (here: failed), never again.
	once := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobRefreshActivity, DedupeKey: "connector:c:after:t", MaxAttempts: 1}
	if created, err := repo.EnqueueOnceTx(db, once); err != nil || !created {
		t.Fatalf("once: %v %v", created, err)
	}
	oj := p3ClaimOwn(t, db, g.ws, "w1", time.Minute, time.Now(), repositories.GovJobRefreshActivity)
	if err := repo.Fail(repositories.PolicyJobFence{JobID: oj.ID, Owner: "w1", Version: oj.LeaseVersion}, "boom", 0); err != nil {
		t.Fatal(err)
	}
	if st := p3JobRow(t, db, oj.ID).Status; st != models.GovJobFailed {
		t.Fatalf("max_attempts 1 failure: status %s, want failed", st)
	}
	once2 := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobRefreshActivity, DedupeKey: "connector:c:after:t"}
	if created, err := repo.EnqueueOnceTx(db, once2); err != nil || created {
		t.Fatalf("once after failure: created %v err %v, want suppressed", created, err)
	}
}

// Claim / renew / reclaim / fence lost (§8.1): a live lease is not claimable;
// a lapsed one is reclaimed with lease_version + 1; every write of the old
// holder is then refused with ErrPolicyJobLeaseLost.
//
// Safeguards (mutation-checked): the lease_version bump in Claim; the fence
// predicate of fencedJob; the owner/version check of AssertOwnedTx.
func TestP3T308ClaimRenewReclaimFenceLost(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-fence")
	repo := repositories.NewIGAGovJobRepository(db)
	job := p3Job(t, db, g.ws, repositories.GovJobIaCSync, "iac:1")
	t0 := time.Now()

	a := p3ClaimOwn(t, db, g.ws, "worker-a", 2*time.Minute, t0, repositories.GovJobIaCSync)
	if a == nil || a.ID != job.ID || a.LeaseVersion != 1 || a.Attempts != 1 || a.Status != models.GovJobRunning {
		t.Fatalf("first claim: %+v", a)
	}
	fa := repositories.PolicyJobFence{JobID: a.ID, Owner: "worker-a", Version: a.LeaseVersion}
	if b := p3ClaimOwn(t, db, g.ws, "worker-b", 2*time.Minute, t0.Add(time.Minute), repositories.GovJobIaCSync); b != nil {
		t.Fatalf("a live lease was claimed by another worker: %+v", b)
	}
	if err := repo.Renew(fa, 2*time.Minute); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if left, err := repo.LeaseRemaining(fa, time.Now()); err != nil || left < 100*time.Second {
		t.Fatalf("lease remaining after renew: %s %v", left, err)
	}
	// The holder stalls past its lease: B reclaims.
	b := p3ClaimOwn(t, db, g.ws, "worker-b", 2*time.Minute, time.Now().Add(3*time.Minute), repositories.GovJobIaCSync)
	if b == nil || b.ID != job.ID || b.LeaseVersion != 2 || b.Attempts != 2 {
		t.Fatalf("reclaim: %+v", b)
	}
	fb := repositories.PolicyJobFence{JobID: b.ID, Owner: "worker-b", Version: b.LeaseVersion}
	for name, err := range map[string]error{
		"renew":    repo.Renew(fa, time.Minute),
		"complete": repo.Complete(fa),
		"fail":     repo.Fail(fa, "x", 0),
		"abandon":  repo.Abandon(fa, "x"),
		"requeue":  repo.Requeue(fa, 0),
		"assert":   db.Transaction(func(tx *gorm.DB) error { return repo.AssertOwnedTx(tx, fa) }),
	} {
		if !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			t.Errorf("old holder's %s = %v, want ErrPolicyJobLeaseLost", name, err)
		}
	}
	if _, err := repo.LeaseRemaining(fa, time.Now()); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Errorf("old holder's lease remaining = %v, want lost", err)
	}
	// Even the same owner name with the old version is refused.
	if err := repo.Complete(repositories.PolicyJobFence{JobID: b.ID, Owner: "worker-b", Version: 1}); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Errorf("stale version under the current owner name: %v", err)
	}
	if err := repo.Complete(fb); err != nil {
		t.Fatalf("new holder completes: %v", err)
	}
	if got := p3JobRow(t, db, job.ID); got.Status != models.GovJobComplete || got.LeaseOwner != "" || got.CompletedAt == nil {
		t.Fatalf("after complete: %+v", got)
	}
	// A completed job is not claimable, and its holder can no longer write.
	if c := p3ClaimOwn(t, db, g.ws, "worker-c", time.Minute, time.Now().Add(time.Hour), repositories.GovJobIaCSync); c != nil {
		t.Fatalf("a complete job was claimed: %+v", c)
	}
	if err := repo.Renew(fb, time.Minute); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("renew after complete: %v", err)
	}
}

// Fail retries with backoff until max_attempts, then is terminal; Requeue
// gives the attempt back; the kinds filter; FailExhausted ends a lapsed job
// with no attempts left; at most 10 deploy jobs of a workspace run at once.
func TestP3T308FailRetryRequeueExhausted(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-retry")
	repo := repositories.NewIGAGovJobRepository(db)

	j := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobNotify, DedupeKey: "notification:1", MaxAttempts: 2}
	if _, err := repo.EnqueueTx(db, j); err != nil {
		t.Fatal(err)
	}
	if c := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobDriftCheck); c != nil {
		t.Fatalf("the kinds filter let a notify job through: %+v", c)
	}
	c := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobNotify)
	// Requeue gives the attempt back and leaves it claimable.
	if err := repo.Requeue(repositories.PolicyJobFence{JobID: c.ID, Owner: "w", Version: c.LeaseVersion}, 0); err != nil {
		t.Fatal(err)
	}
	if r := p3JobRow(t, db, j.ID); r.Status != models.GovJobQueued || r.Attempts != 0 {
		t.Fatalf("after requeue: %+v", r)
	}
	c = p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobNotify)
	if err := repo.Fail(repositories.PolicyJobFence{JobID: c.ID, Owner: "w", Version: c.LeaseVersion}, "smtp down", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	r := p3JobRow(t, db, j.ID)
	if r.Status != models.GovJobQueued || r.Attempts != 1 || r.LastError != "smtp down" || time.Until(r.RunAfter) < 9*time.Minute {
		t.Fatalf("after a retryable failure: %+v", r)
	}
	if c := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobNotify); c != nil {
		t.Fatalf("claimed during its backoff: %+v", c)
	}
	c = p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now().Add(11*time.Minute), repositories.GovJobNotify)
	if c == nil || c.Attempts != 2 {
		t.Fatalf("after the backoff: %+v", c)
	}
	if err := repo.Fail(repositories.PolicyJobFence{JobID: c.ID, Owner: "w", Version: c.LeaseVersion}, "still down", time.Minute); err != nil {
		t.Fatal(err)
	}
	if r := p3JobRow(t, db, j.ID); r.Status != models.GovJobFailed || r.CompletedAt == nil {
		t.Fatalf("at max_attempts: %+v, want failed", r)
	}

	// A running job whose lease lapsed with no attempts left: FailExhausted.
	x := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobVerify, DedupeKey: "deployment:ex", MaxAttempts: 1}
	if _, err := repo.EnqueueTx(db, x); err != nil {
		t.Fatal(err)
	}
	xc := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobVerify)
	if xc == nil {
		t.Fatal("no claim")
	}
	if again := p3ClaimOwn(t, db, g.ws, "w2", time.Minute, time.Now().Add(time.Hour), repositories.GovJobVerify); again != nil {
		t.Fatalf("an exhausted job was reclaimed: %+v", again)
	}
	if n, err := repo.FailExhausted(time.Now().Add(time.Hour)); err != nil || n < 1 {
		t.Fatalf("fail exhausted: %d %v", n, err)
	}
	if r := p3JobRow(t, db, x.ID); r.Status != models.GovJobFailed || r.LastError == "" {
		t.Fatalf("exhausted job: %+v", r)
	}

	// Ten running deploy jobs of the workspace: the eleventh waits.
	for i := 0; i < 11; i++ {
		p3Job(t, db, g.ws, repositories.GovJobDeploy, "deployment:cap-"+uuid.NewString())
	}
	for i := 0; i < 10; i++ {
		if c := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobDeploy); c == nil {
			t.Fatalf("deploy claim %d refused below the cap", i+1)
		}
	}
	if c := p3ClaimOwn(t, db, g.ws, "w", time.Minute, time.Now(), repositories.GovJobDeploy); c != nil {
		t.Fatalf("an eleventh deploy job ran concurrently: %+v", c)
	}
}

// Two workers never run one job: many jobs, two workers draining them at once
// -- each job's handler effect (an iga_gov_event written through the fenced
// InTx) lands exactly once. Then a stalled holder: worker A's lease lapses
// mid-handler, B reclaims and completes, and A's late write is refused.
//
// Safeguards (mutation-checked): FOR UPDATE SKIP LOCKED in Claim; InTx's
// AssertOwnedTx.
func TestP3T308TwoWorkersNeverRunOneJob(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-two-workers")
	const n = 30
	for i := 0; i < n; i++ {
		p3Job(t, db, g.ws, repositories.GovJobIaCSync, "iac:"+uuid.NewString())
	}
	var mu sync.Mutex
	runs := map[uuid.UUID]int{}
	handler := func(ctx context.Context, run *services.PolicyJobRun) error {
		if run.Job.WorkspaceID != g.ws {
			return services.PolicyJobRetryLater(time.Hour, "not this test's job")
		}
		mu.Lock()
		runs[run.Job.ID]++
		mu.Unlock()
		time.Sleep(3 * time.Millisecond)
		return run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Create(&models.IGAGovEvent{WorkspaceID: g.ws, Event: "test.effect", ActorKind: models.GovActorSystem,
				ActorID: run.Fence.Owner, Payload: []byte(`{"job":"` + run.Job.ID.String() + `"}`)}).Error
		})
	}
	var wg sync.WaitGroup
	for _, name := range []string{"worker-a", "worker-b"} {
		w := services.NewPolicyJobWorker(db, name).WithGate(func() bool { return true })
		w.Register(services.PolicyJobKind{Kind: repositories.GovJobIaCSync, Handler: handler})
		wg.Add(1)
		go func(w *services.PolicyJobWorker) {
			defer wg.Done()
			for {
				ran, err := w.RunOnce(context.Background())
				if err != nil {
					t.Errorf("run once: %v", err)
					return
				}
				if !ran {
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if len(runs) != n {
		t.Fatalf("%d jobs ran, want %d", len(runs), n)
	}
	for id, c := range runs {
		if c != 1 {
			t.Errorf("job %s ran %d times", id, c)
		}
	}
	var effects, complete int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'test.effect'`, g.ws).Scan(&effects)
	db.Raw(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'iac_sync' AND status = 'complete'`, g.ws).Scan(&complete)
	if effects != n || complete != n {
		t.Fatalf("effects %d, complete %d, want %d each", effects, complete, n)
	}

	// The stalled holder.
	stalled := p3Job(t, db, g.ws, repositories.GovJobDriftCheck, "deployment:stall")
	release := make(chan struct{})
	var aErr atomic.Value
	a := services.NewPolicyJobWorker(db, "stall-a").WithGate(func() bool { return true })
	a.Lease, a.RenewEvery = 300*time.Millisecond, time.Hour // never renews: its lease lapses
	a.Register(services.PolicyJobKind{Kind: repositories.GovJobDriftCheck, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		<-release
		err := run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Create(&models.IGAGovEvent{WorkspaceID: g.ws, Event: "test.stalled", ActorKind: models.GovActorSystem,
				ActorID: "stall-a", Payload: []byte(`{}`)}).Error
		})
		aErr.Store(errBox{err})
		return err
	}})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if ran, err := a.RunOnce(context.Background()); !ran || err != nil {
			t.Errorf("A did not run: %v %v", ran, err)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	b := services.NewPolicyJobWorker(db, "stall-b").WithGate(func() bool { return true })
	b.Register(services.PolicyJobKind{Kind: repositories.GovJobDriftCheck, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		return run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Create(&models.IGAGovEvent{WorkspaceID: g.ws, Event: "test.stalled", ActorKind: models.GovActorSystem,
				ActorID: "stall-b", Payload: []byte(`{}`)}).Error
		})
	}})
	if ran, err := b.RunOnce(context.Background()); !ran || err != nil {
		t.Fatalf("B did not reclaim the lapsed job: %v %v", ran, err)
	}
	close(release)
	<-done
	if e, _ := aErr.Load().(errBox); !errors.Is(e.err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("A's late write = %v, want ErrPolicyJobLeaseLost", e.err)
	}
	var actors []string
	db.Raw(`SELECT actor_id FROM iga_gov_event WHERE workspace_id = ? AND event = 'test.stalled'`, g.ws).Scan(&actors)
	if len(actors) != 1 || actors[0] != "stall-b" {
		t.Fatalf("stalled job effects by %v, want only stall-b", actors)
	}
	if r := p3JobRow(t, db, stalled.ID); r.Status != models.GovJobComplete || r.LeaseVersion != 2 {
		t.Fatalf("stalled job: %+v, want complete at lease version 2", r)
	}
}

type errBox struct{ err error }

// The worker loop: it claims nothing while the gate is unavailable; with it
// on, it runs jobs; on shutdown it stops claiming, lets a job that finishes
// within the grace complete, and hands back (attempt not counted) one that
// does not. The handler outcome mapping: abandon, retry-later, failure.
func TestP3T308WorkerLoopAndGracefulShutdown(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-loop")
	quick := p3Job(t, db, g.ws, repositories.GovJobIaCSync, "iac:quick")
	slow := p3Job(t, db, g.ws, repositories.GovJobDriftCheck, "deployment:slow")

	var gateOn atomic.Bool
	w := services.NewPolicyJobWorker(db, "loop").WithGate(gateOn.Load)
	w.Grace, w.Concurrency = 300*time.Millisecond, 2
	slowStarted := make(chan struct{})
	w.Register(services.PolicyJobKind{Kind: repositories.GovJobIaCSync, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		if run.Job.WorkspaceID != g.ws {
			return services.PolicyJobRetryLater(time.Hour, "foreign")
		}
		return nil
	}})
	w.Register(services.PolicyJobKind{Kind: repositories.GovJobDriftCheck, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		if run.Job.WorkspaceID != g.ws {
			return services.PolicyJobRetryLater(time.Hour, "foreign")
		}
		close(slowStarted)
		<-ctx.Done() // runs until the shutdown cancels it
		return ctx.Err()
	}})
	// The scheduler has nothing of this workspace to add; keep it quiet.
	w.Scheduler().Every = time.Hour

	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { w.Run(ctx, 20*time.Millisecond); close(stopped) }()

	time.Sleep(150 * time.Millisecond)
	if r := p3JobRow(t, db, quick.ID); r.Status != models.GovJobQueued {
		t.Fatalf("claimed with the gate unavailable: %+v", r)
	}
	gateOn.Store(true)
	select {
	case <-slowStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow job never started")
	}
	deadline := time.Now().Add(5 * time.Second)
	for p3JobRow(t, db, quick.ID).Status != models.GovJobComplete {
		if time.Now().After(deadline) {
			t.Fatalf("quick job: %+v", p3JobRow(t, db, quick.ID))
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not stop")
	}
	if r := p3JobRow(t, db, slow.ID); r.Status != models.GovJobQueued || r.Attempts != 0 || r.LeaseOwner != "" {
		t.Fatalf("the job cancelled by shutdown: %+v, want queued with the attempt given back", r)
	}

	// Outcome mapping, through RunOnce.
	ab := p3Job(t, db, g.ws, repositories.GovJobRefreshActivity, "connector:ab")
	w2 := services.NewPolicyJobWorker(db, "outcomes").WithGate(func() bool { return true })
	var calls int32
	w2.Register(services.PolicyJobKind{Kind: repositories.GovJobRefreshActivity, Backoff: func(int) time.Duration { return time.Hour },
		Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
			switch atomic.AddInt32(&calls, 1) {
			case 1:
				return errors.New("transient")
			default:
				return services.PolicyJobAbandon("subject gone")
			}
		}})
	if ran, err := w2.RunOnce(context.Background()); !ran || err != nil {
		t.Fatal(ran, err)
	}
	if r := p3JobRow(t, db, ab.ID); r.Status != models.GovJobQueued || r.LastError != "transient" || time.Until(r.RunAfter) < 50*time.Minute {
		t.Fatalf("after a failure: %+v, want queued with the kind's backoff", r)
	}
	// The worker's clock is authoritative for run_after (T3.08 decision 1:
	// Claim compares run_after with the WORKER's now). Writing the
	// database's now() here made the test flaky whenever the database clock
	// ran ahead of the test process's: the job was not yet due.
	p3exec(t, db, `UPDATE iga_gov_job SET run_after = ? WHERE id = ?`, time.Now().Add(-time.Second), ab.ID)
	if ran, err := w2.RunOnce(context.Background()); !ran || err != nil {
		t.Fatal(ran, err)
	}
	if r := p3JobRow(t, db, ab.ID); r.Status != models.GovJobAbandoned || r.LastError != "subject gone" {
		t.Fatalf("after abandon: %+v", r)
	}
}

// The lease margin around an external call (§8.1): the call is not made
// without the fence and at least the margin of lease; a fence lost while the
// call ran makes External return ErrPolicyJobLeaseLost, and the worker then
// writes nothing.
//
// Safeguards (mutation-checked): EnsureMargin's comparison; External's
// re-check after the call.
func TestP3T308ExternalCallLeaseMargin(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-margin")

	// A worker whose lease is shorter than the margin can never call out.
	short := p3Job(t, db, g.ws, repositories.GovJobIaCSync, "iac:short")
	var calls int32
	var got atomic.Value
	w := services.NewPolicyJobWorker(db, "short-lease").WithGate(func() bool { return true })
	w.Lease = 30 * time.Second
	w.Register(services.PolicyJobKind{Kind: repositories.GovJobIaCSync, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		err := run.External(ctx, 0, func(context.Context) error { atomic.AddInt32(&calls, 1); return nil })
		got.Store(errBox{err})
		return err
	}})
	if ran, _ := w.RunOnce(context.Background()); !ran {
		t.Fatal("not run")
	}
	if e, _ := got.Load().(errBox); !errors.Is(e.err, repositories.ErrPolicyJobLeaseShort) || calls != 0 {
		t.Fatalf("short lease: err %v, calls %d; want ErrPolicyJobLeaseShort and no call", e.err, calls)
	}
	if r := p3JobRow(t, db, short.ID); r.Status != models.GovJobQueued || r.Attempts != 1 {
		t.Fatalf("short-lease job: %+v, want a counted failed try", r)
	}

	// The fence is lost while the call runs (another worker reclaims).
	lost := p3Job(t, db, g.ws, repositories.GovJobDriftCheck, "deployment:lost")
	w2 := services.NewPolicyJobWorker(db, "loses-fence").WithGate(func() bool { return true })
	var wrote int32
	w2.Register(services.PolicyJobKind{Kind: repositories.GovJobDriftCheck, Handler: func(ctx context.Context, run *services.PolicyJobRun) error {
		err := run.External(ctx, 0, func(context.Context) error {
			atomic.AddInt32(&calls, 1)
			// Mid-call, the lease lapses and another worker takes it.
			p3exec(t, db, `UPDATE iga_gov_job SET lease_expires_at = now() - interval '1 second' WHERE id = ?`, run.Job.ID)
			if c := p3ClaimOwn(t, db, g.ws, "thief", time.Minute, time.Now(), repositories.GovJobDriftCheck); c == nil {
				t.Error("the thief could not reclaim")
			}
			return nil
		})
		got.Store(errBox{err})
		if err != nil {
			return err
		}
		atomic.AddInt32(&wrote, 1)
		return nil
	}})
	if ran, _ := w2.RunOnce(context.Background()); !ran {
		t.Fatal("not run")
	}
	if e, _ := got.Load().(errBox); !errors.Is(e.err, repositories.ErrPolicyJobLeaseLost) || wrote != 0 {
		t.Fatalf("lost fence: err %v wrote %d; want ErrPolicyJobLeaseLost and nothing written", e.err, wrote)
	}
	if r := p3JobRow(t, db, lost.ID); r.Status != models.GovJobRunning || r.LeaseOwner != "thief" || r.LeaseVersion != 2 {
		t.Fatalf("after the lost fence the old holder wrote: %+v", r)
	}
}

// The scheduler (§8.1): drift_check every 10 min per verified deployment and
// every 5 min for 24 h after an unknown attempt on the control;
// refresh_activity once per (connector, observe_evidence_required_after);
// replicas ticking together enqueue one job per subject.
func TestP3T308SchedulerPeriodicJobs(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-jobs-scheduler")
	plain, late := g.lane(), g.lane()
	dPlain := g.deployment(plain, "verified")
	dLate := g.deployment(late, "verified")
	// An unknown attempt on late's control within 24 h (on a second, older
	// deployment row of the same control that is now failed).
	dOld := g.deployment(late, "failed")
	p3exec(t, db, `INSERT INTO iga_gov_attempt (workspace_id, deployment_id, op_seq, attempt_no, lease_version, operation, request_hash, status)
		VALUES (?, ?, 0, 1, 1, 'CreatePolicyVersion', 'sha256:r', 'prepared')`, g.ws, dOld)
	p3exec(t, db, `UPDATE iga_gov_attempt SET status = 'dispatched', signed_at = now(), dispatched_at = now() WHERE deployment_id = ?`, dOld)
	p3exec(t, db, `UPDATE iga_gov_attempt SET status = 'unknown' WHERE deployment_id = ?`, dOld)
	// A rollout observing, for refresh_activity.
	after := time.Now().Add(4 * time.Hour).UTC().Truncate(time.Second)
	p3exec(t, db, `INSERT INTO iga_gov_rollout (workspace_id, version_id, stage, observe_until, observe_evidence_required_after)
		VALUES (?, ?, 'observe', ?, ?)`, g.ws, plain.version, after.Add(-4*time.Hour), after)

	s1, s2 := services.NewPolicyJobScheduler(db), services.NewPolicyJobScheduler(db)
	var wg sync.WaitGroup
	for _, s := range []*services.PolicyJobScheduler{s1, s2} {
		wg.Add(1)
		go func(s *services.PolicyJobScheduler) {
			defer wg.Done()
			if _, err := s.RunSchedulesNow(context.Background(), time.Now()); err != nil {
				t.Errorf("schedule: %v", err)
			}
		}(s)
	}
	wg.Wait()
	type row struct {
		Kind, DedupeKey string
		RunAfter        time.Time
	}
	var rows []row
	db.Raw(`SELECT kind, dedupe_key, run_after FROM iga_gov_job WHERE workspace_id = ? ORDER BY kind, dedupe_key`, g.ws).Scan(&rows)
	want := map[string]bool{
		"drift_check|deployment:" + dPlain.String():                                              true,
		"drift_check|deployment:" + dLate.String():                                               true,
		"refresh_activity|connector:" + g.conn.String() + ":after:" + after.Format(time.RFC3339): true,
	}
	if len(rows) != len(want) {
		t.Fatalf("jobs %+v, want exactly %v", rows, want)
	}
	for _, r := range rows {
		if !want[r.Kind+"|"+r.DedupeKey] {
			t.Errorf("unexpected job %+v", r)
		}
		if r.Kind == repositories.GovJobRefreshActivity && !r.RunAfter.Equal(after) {
			t.Errorf("refresh_activity runs at %s, want %s", r.RunAfter, after)
		}
	}

	// Complete both drift checks 6 minutes ago: only the late-watch one
	// (every 5 min) is due again.
	p3exec(t, db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() - interval '6 minutes'
		WHERE workspace_id = ? AND kind = 'drift_check'`, g.ws)
	n, err := s1.RunSchedulesNow(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var open []string
	db.Raw(`SELECT dedupe_key FROM iga_gov_job WHERE workspace_id = ? AND status = 'queued' AND kind = 'drift_check'`, g.ws).Scan(&open)
	if n != 1 || len(open) != 1 || open[0] != "deployment:"+dLate.String() {
		t.Fatalf("after 6 minutes: %d enqueued, open %v; want only the late-watch deployment", n, open)
	}
	// refresh_activity is once: completing it does not bring it back.
	p3exec(t, db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() - interval '2 hours' WHERE workspace_id = ? AND kind = 'refresh_activity'`, g.ws)
	if _, err := s1.RunSchedulesNow(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	var refreshes int64
	db.Raw(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'refresh_activity'`, g.ws).Scan(&refreshes)
	if refreshes != 1 {
		t.Fatalf("refresh_activity rows %d, want 1 (once)", refreshes)
	}
}

// The worker's start condition (cmd/main.go): VerifyUntilReady's ready hook --
// where main starts the policy job worker -- runs only after the Phase 3
// schema verified with IGA_POLICY on; never with it off or misconfigured.
func TestP3T308WorkerStartsOnlyWhenPolicyVerified(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	for _, tc := range []struct {
		name string
		gate *services.PolicyGate
		want bool
	}{
		{"on and verified", services.NewPolicyGate(true, "", graphOn), true},
		{"off", services.NewPolicyGate(false, "", graphOn), false},
		{"bad switch value", services.NewPolicyGate(true, `IGA_POLICY="maybe" is not on or off`, graphOn), false},
	} {
		started := false
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		tc.gate.VerifyUntilReady(ctx, db, 10*time.Millisecond, func() { started = true })
		cancel()
		if started != tc.want {
			t.Errorf("%s: worker started = %v, want %v", tc.name, started, tc.want)
		}
	}
}
