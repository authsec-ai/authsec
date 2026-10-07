package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.08 (SPEC-iga-phase3-policy.md §8.1, probes DB122-DB129): the write-ahead
// attempt lifecycle as the reusable component T3.10 calls, against the real
// tables, with a FAKE external operation and fault injection -- the
// A13/A25/A58(a,b) shapes on the attempt side: kill after dispatch, kill
// after prepare, client timeout with a late answer, the fence lost mid-call.
// No AWS call is made anywhere.

// p3FakeIAM is the external system: it counts requests that REACHED it and
// applies them, whatever happens to the caller afterwards.
type p3FakeIAM struct {
	mu      sync.Mutex
	calls   int
	applied []string
}

func (f *p3FakeIAM) receive(op string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.applied = append(f.applied, op)
}

func (f *p3FakeIAM) count() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([]string(nil), f.applied...)
}

// answers: the request reaches AWS, is applied, and the answer comes back.
func (f *p3FakeIAM) answers(op, requestID string) services.AttemptCall {
	return func(ctx context.Context) (services.AttemptAnswer, error) {
		f.receive(op)
		return services.AttemptAnswer{Outcome: services.AttemptOutcomeOK, RequestID: requestID}, nil
	}
}

// p3DeployRun enqueues and claims a deploy job for the deployment as owner,
// and returns its run.
func p3DeployRun(t *testing.T, db *gorm.DB, g *p3Gov, dep uuid.UUID, owner string, lease time.Duration, at time.Time) *services.PolicyJobRun {
	t.Helper()
	repo := repositories.NewIGAGovJobRepository(db)
	j := &models.IGAGovJob{WorkspaceID: g.ws, Kind: repositories.GovJobDeploy, DedupeKey: "deployment:" + dep.String(), SubjectID: &dep,
		RunAfter: at.Add(-time.Second)} // claimable at the claim time given
	if _, err := repo.EnqueueTx(db, j); err != nil {
		t.Fatal(err)
	}
	c := p3ClaimOwn(t, db, g.ws, owner, lease, at, repositories.GovJobDeploy)
	if c == nil || c.ID != j.ID {
		t.Fatalf("%s could not claim the deploy job: %+v", owner, c)
	}
	return services.NewPolicyJobRun(db, *c, owner)
}

func p3Attempts(t *testing.T, db *gorm.DB, dep uuid.UUID) []models.IGAGovAttempt {
	t.Helper()
	var out []models.IGAGovAttempt
	if err := db.Where("deployment_id = ?", dep).Order("op_seq, attempt_no").Find(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

func p3Deployment(t *testing.T, db *gorm.DB, id uuid.UUID) models.IGAGovDeployment {
	t.Helper()
	var d models.IGAGovDeployment
	if err := db.First(&d, "id = ?", id).Error; err != nil {
		t.Fatal(err)
	}
	return d
}

func p3Req(g *p3Gov, dep uuid.UUID, seq int, op string) services.AttemptRequest {
	return services.AttemptRequest{WorkspaceID: g.ws, DeploymentID: dep, OpSeq: seq, Operation: op,
		RequestHash: "sha256:req-" + op, DocumentHash: g.docHash}
}

// The happy path: prepared -> dispatched -> completed, the op recorded in
// completed_ops in the same transaction, one event per step, the deployment's
// attempts counted; a retryable answer completes the attempt without marking
// the op done, and the retry is attempt_no 2.
func TestP3T308AttemptLifecycleHappyPath(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-happy")
	dep := g.deployment(g.lane(), "applying")
	run := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, time.Now())
	log := services.NewIGAGovAttemptLog(db)
	iam := &p3FakeIAM{}

	res, err := log.Execute(context.Background(), run, p3Req(g, dep, 0, "CreatePolicy"), iam.answers("CreatePolicy", "req-1"))
	if err != nil || res.Unknown || res.Answer == nil {
		t.Fatalf("execute: %+v %v", res, err)
	}
	// A throttled answer proves the request was not applied: completed
	// retryable, op not done; the retry is a NEW attempt.
	throttled := func(ctx context.Context) (services.AttemptAnswer, error) {
		return services.AttemptAnswer{Outcome: services.AttemptOutcomeRetryable, RequestID: "req-2", ErrorCode: "Throttling"}, nil
	}
	if _, err := log.Execute(context.Background(), run, p3Req(g, dep, 1, "PutRolePermissionsBoundary"), throttled); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Execute(context.Background(), run, p3Req(g, dep, 1, "PutRolePermissionsBoundary"), iam.answers("PutRolePermissionsBoundary", "req-3")); err != nil {
		t.Fatal(err)
	}
	ats := p3Attempts(t, db, dep)
	if len(ats) != 3 {
		t.Fatalf("attempts: %+v", ats)
	}
	for i, want := range []struct {
		seq, no int
		outcome string
	}{{0, 1, "ok"}, {1, 1, "retryable"}, {1, 2, "ok"}} {
		a := ats[i]
		if a.OpSeq != want.seq || a.AttemptNo != want.no || a.Status != models.GovAttemptCompleted || a.Outcome == nil ||
			*a.Outcome != want.outcome || a.SignedAt == nil || a.DispatchedAt == nil || a.LeaseVersion != run.Fence.Version {
			t.Errorf("attempt %d: %+v, want op %d attempt %d %s", i, a, want.seq, want.no, want.outcome)
		}
	}
	d := p3Deployment(t, db, dep)
	var ops []map[string]any
	_ = json.Unmarshal(d.CompletedOps, &ops)
	if len(ops) != 2 || ops[0]["operation"] != "CreatePolicy" || ops[1]["operation"] != "PutRolePermissionsBoundary" || d.Attempts != 3 {
		t.Fatalf("deployment completed_ops %s attempts %d", d.CompletedOps, d.Attempts)
	}
	if n, _ := iam.count(); n != 2 {
		t.Fatalf("requests reaching IAM: %d", n)
	}
	evs := g.events()
	if len(evs) != 9 || evs[0] != "attempt.prepared" || evs[1] != "attempt.dispatched" || evs[2] != "attempt.completed" {
		t.Fatalf("events %v", evs)
	}
	// One open attempt per deployment: a second prepare while one is open is
	// refused.
	a, err := log.Prepare(context.Background(), run, p3Req(g, dep, 2, "TagPolicy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Prepare(context.Background(), run, p3Req(g, dep, 3, "TagPolicy")); !errors.Is(err, services.ErrAttemptOpen) {
		t.Fatalf("second open attempt: %v, want ErrAttemptOpen", err)
	}
	// The table refuses completing an attempt that was never dispatched.
	if err := log.Complete(context.Background(), run, a, services.AttemptAnswer{Outcome: "ok"}); !errors.Is(err, services.ErrAttemptState) {
		t.Fatalf("complete of a prepared attempt: %v", err)
	}
}

// A58(a) / A13 / A25 on the attempt side: the worker is killed after AWS
// accepted the request and before the answer was recorded. The replacement
// finds the attempt `dispatched`, marks it `unknown`, moves the deployment to
// outcome_unknown with settle_after = signed_at + 15 min, and NEVER re-sends;
// the old worker's late answer is refused by the fence; nothing more can be
// prepared on the deployment until the unknown is resolved.
//
// Safeguards (mutation-checked): Recover's dispatched -> unknown (never
// re-prepare); Complete's fence; the settle window.
func TestP3T308AttemptKilledAfterDispatch(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-kill-dispatch")
	dep := g.deployment(g.lane(), "applying")
	t0 := time.Now()
	runA := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, t0)
	log := services.NewIGAGovAttemptLog(db)
	iam := &p3FakeIAM{}

	att, err := log.Prepare(context.Background(), runA, p3Req(g, dep, 0, "CreatePolicyVersion"))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Dispatch(context.Background(), runA, att); err != nil {
		t.Fatal(err)
	}
	// The request reaches AWS and is applied ... and the worker dies here.
	answer, _ := iam.answers("CreatePolicyVersion", "req-late")(context.Background())

	// Its lease lapses; worker B takes the job over.
	repo := repositories.NewIGAGovJobRepository(db)
	jobB := p3ClaimOwn(t, db, g.ws, "worker-b", 2*time.Minute, t0.Add(3*time.Minute), repositories.GovJobDeploy)
	if jobB == nil {
		t.Fatal("B could not reclaim")
	}
	runB := services.NewPolicyJobRun(db, *jobB, "worker-b")
	rec, err := log.Recover(context.Background(), runB, g.ws, dep)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Action != services.RecoveryOutcomeUnknown || rec.SettleAfter == nil {
		t.Fatalf("recover: %+v, want outcome_unknown", rec)
	}
	ats := p3Attempts(t, db, dep)
	if len(ats) != 1 || ats[0].Status != models.GovAttemptUnknown || ats[0].ResolvedAs != nil {
		t.Fatalf("attempts after recovery: %+v", ats)
	}
	d := p3Deployment(t, db, dep)
	if d.State != models.GovDeployOutcomeUnknown || d.OutcomeUnknownOp != "0:CreatePolicyVersion" || d.SettleAfter == nil ||
		d.SettleAfter.Sub(*ats[0].SignedAt) != 15*time.Minute {
		t.Fatalf("deployment: state %s op %q settle %v signed %v", d.State, d.OutcomeUnknownOp, d.SettleAfter, ats[0].SignedAt)
	}
	// Never re-sent: B cannot prepare anything on the deployment while the
	// unknown attempt is unresolved (409 outcome_unknown_pending upstream).
	if _, err := log.Execute(context.Background(), runB, p3Req(g, dep, 0, "CreatePolicyVersion"), iam.answers("CreatePolicyVersion", "dup")); !errors.Is(err, services.ErrAttemptOpen) {
		t.Fatalf("re-send after unknown: %v, want ErrAttemptOpen", err)
	}
	if open, err := log.OpenAttempt(db, g.ws, dep); err != nil || open == nil || open.Status != models.GovAttemptUnknown {
		t.Fatalf("open attempt: %+v %v", open, err)
	}
	// Recover again: the role stays held.
	if rec, err := log.Recover(context.Background(), runB, g.ws, dep); err != nil || rec.Action != services.RecoveryHold {
		t.Fatalf("second recover: %+v %v, want hold", rec, err)
	}
	// The old worker comes back with its answer: refused, nothing changes.
	if err := log.Complete(context.Background(), runA, att, answer); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("old worker's late complete: %v, want ErrPolicyJobLeaseLost", err)
	}
	if ats := p3Attempts(t, db, dep); ats[0].Status != models.GovAttemptUnknown || ats[0].RequestID != "" {
		t.Fatalf("after the late answer: %+v", ats[0])
	}
	// The one-deployment-per-role index holds while outcome_unknown (DB131):
	// no other deployment on the control can start.
	var l struct{ VersionID, PlanID, ControlID, ApprovalID uuid.UUID }
	db.Raw(`SELECT version_id, plan_id, control_id, approval_id FROM iga_gov_deployment WHERE id = ?`, dep).Scan(&l)
	if err := db.Exec(`INSERT INTO iga_gov_deployment (workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, 'apply', 'direct', 'queued')`, g.ws, l.VersionID, l.PlanID, l.ControlID, l.ApprovalID).Error; err == nil {
		t.Fatal("a second deployment started on a role whose outcome is unknown")
	}
	if n, _ := iam.count(); n != 1 {
		t.Fatalf("requests reaching IAM: %d, want 1 (never re-sent)", n)
	}

	// Step 2 resolution (T3.16 establishes it): not_applied -> the deployment
	// returns to applying and the op may be re-prepared as attempt 2.
	if err := log.ResolveUnknown(context.Background(), runB, &ats[0], services.AttemptResolvedNotApplied); err != nil {
		t.Fatal(err)
	}
	if d := p3Deployment(t, db, dep); d.State != models.GovDeployApplying {
		t.Fatalf("after resolution: %s", d.State)
	}
	res, err := log.Execute(context.Background(), runB, p3Req(g, dep, 0, "CreatePolicyVersion"), iam.answers("CreatePolicyVersion", "req-2"))
	if err != nil || res.Attempt.AttemptNo != 2 {
		t.Fatalf("re-prepare after not_applied: %+v %v", res, err)
	}
	if err := log.ResolveUnknown(context.Background(), runB, &ats[0], services.AttemptResolvedApplied); !errors.Is(err, services.ErrAttemptState) {
		t.Fatalf("a resolved attempt was resolved again: %v", err)
	}
	_ = repo
}

// A58(a) second half: killed after PREPARE. Nothing was sent; the
// replacement abandons it and re-prepares as attempt_no + 1.
func TestP3T308AttemptKilledAfterPrepare(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-kill-prepare")
	dep := g.deployment(g.lane(), "applying")
	t0 := time.Now()
	runA := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, t0)
	log := services.NewIGAGovAttemptLog(db)
	iam := &p3FakeIAM{}
	if _, err := log.Prepare(context.Background(), runA, p3Req(g, dep, 0, "CreatePolicy")); err != nil {
		t.Fatal(err)
	}
	// Dies before dispatch. B takes over.
	jobB := p3ClaimOwn(t, db, g.ws, "worker-b", 2*time.Minute, t0.Add(3*time.Minute), repositories.GovJobDeploy)
	runB := services.NewPolicyJobRun(db, *jobB, "worker-b")
	rec, err := log.Recover(context.Background(), runB, g.ws, dep)
	if err != nil || rec.Action != services.RecoveryReprepare {
		t.Fatalf("recover: %+v %v", rec, err)
	}
	res, err := log.Execute(context.Background(), runB, p3Req(g, dep, 0, "CreatePolicy"), iam.answers("CreatePolicy", "req-b"))
	if err != nil {
		t.Fatal(err)
	}
	ats := p3Attempts(t, db, dep)
	if len(ats) != 2 || ats[0].Status != models.GovAttemptAbandoned || ats[0].CompletedAt == nil || ats[0].DispatchedAt != nil ||
		ats[1].AttemptNo != 2 || ats[1].Status != models.GovAttemptCompleted || ats[1].LeaseVersion != jobB.LeaseVersion || res.Unknown {
		t.Fatalf("attempts: %+v", ats)
	}
	if n, _ := iam.count(); n != 1 {
		t.Fatalf("requests reaching IAM: %d, want 1", n)
	}
	// A's prepared attempt cannot be dispatched by A any more.
	if err := log.Dispatch(context.Background(), runA, &ats[0]); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("A dispatching after takeover: %v", err)
	}
}

// A58(b): the call outlives the client timeout. The attempt is `unknown`, the
// deployment outcome_unknown; the call is not retried (one request reached
// IAM) and its LATE answer, arriving after the timeout, is discarded -- the
// fake applied it, which only the resolution step may establish.
//
// Safeguards (mutation-checked): Execute treating the timeout as no answer.
func TestP3T308AttemptTimeoutLateAnswer(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-timeout")
	dep := g.deployment(g.lane(), "applying")
	run := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, time.Now())
	log := services.NewIGAGovAttemptLog(db)
	log.CallTimeout = 200 * time.Millisecond
	iam := &p3FakeIAM{}
	lateDone := make(chan struct{})
	slow := func(ctx context.Context) (services.AttemptAnswer, error) {
		defer close(lateDone)
		time.Sleep(600 * time.Millisecond) // ignores ctx: the request is in flight
		iam.receive("CreatePolicyVersion")
		return services.AttemptAnswer{Outcome: services.AttemptOutcomeOK, RequestID: "late"}, nil
	}
	start := time.Now()
	res, err := log.Execute(context.Background(), run, p3Req(g, dep, 0, "CreatePolicyVersion"), slow)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unknown || res.SettleAfter == nil || res.Answer != nil || time.Since(start) > 550*time.Millisecond {
		t.Fatalf("result %+v after %s: want unknown at the timeout", res, time.Since(start))
	}
	<-lateDone
	time.Sleep(50 * time.Millisecond)
	ats := p3Attempts(t, db, dep)
	if len(ats) != 1 || ats[0].Status != models.GovAttemptUnknown || ats[0].RequestID != "" {
		t.Fatalf("after the late answer: %+v", ats)
	}
	if d := p3Deployment(t, db, dep); d.State != models.GovDeployOutcomeUnknown {
		t.Fatalf("deployment %s", d.State)
	}
	if n, applied := iam.count(); n != 1 || len(applied) != 1 {
		t.Fatalf("IAM saw %d requests (%v): want exactly the one, never retried", n, applied)
	}

	// A connection error (no answer) is the same: unknown, not retried.
	dep2 := g.deployment(g.lane(), "applying")
	run2 := p3DeployRun(t, db, g, dep2, "worker-a", 2*time.Minute, time.Now())
	reset := func(ctx context.Context) (services.AttemptAnswer, error) {
		iam.receive("PutRolePermissionsBoundary")
		return services.AttemptAnswer{}, errors.New("read tcp: connection reset by peer")
	}
	res, err = log.Execute(context.Background(), run2, p3Req(g, dep2, 0, "PutRolePermissionsBoundary"), reset)
	if err != nil || !res.Unknown {
		t.Fatalf("connection reset: %+v %v", res, err)
	}
	if n, _ := iam.count(); n != 2 {
		t.Fatalf("requests %d", n)
	}
}

// The fence is lost while the call is in flight (lease lost mid-call): the
// answer cannot be recorded (Complete is fenced), the attempt stays
// `dispatched`, and the replacement marks it unknown -- the safe direction.
// And the lease margin: with less than 60 s of lease, nothing is sent and
// the prepared attempt is abandoned.
func TestP3T308AttemptFenceLostMidCallAndMargin(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-fence")
	dep := g.deployment(g.lane(), "applying")
	run := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, time.Now())
	log := services.NewIGAGovAttemptLog(db)
	iam := &p3FakeIAM{}
	var thief *models.IGAGovJob
	stolen := func(ctx context.Context) (services.AttemptAnswer, error) {
		iam.receive("CreatePolicy")
		thief = p3ClaimOwn(t, db, g.ws, "worker-b", 2*time.Minute, time.Now().Add(5*time.Minute), repositories.GovJobDeploy)
		return services.AttemptAnswer{Outcome: services.AttemptOutcomeOK, RequestID: "req"}, nil
	}
	if _, err := log.Execute(context.Background(), run, p3Req(g, dep, 0, "CreatePolicy"), stolen); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("execute with the fence lost mid-call: %v", err)
	}
	if ats := p3Attempts(t, db, dep); len(ats) != 1 || ats[0].Status != models.GovAttemptDispatched {
		t.Fatalf("attempt after a lost fence: %+v, want still dispatched", ats)
	}
	runB := services.NewPolicyJobRun(db, *thief, "worker-b")
	if rec, err := log.Recover(context.Background(), runB, g.ws, dep); err != nil || rec.Action != services.RecoveryOutcomeUnknown {
		t.Fatalf("recover: %+v %v", rec, err)
	}

	// Margin: a 30 s lease is under the 60 s margin -- nothing sent.
	dep2 := g.deployment(g.lane(), "applying")
	short := p3DeployRun(t, db, g, dep2, "worker-c", 30*time.Second, time.Now())
	before, _ := iam.count()
	if _, err := log.Execute(context.Background(), short, p3Req(g, dep2, 0, "CreatePolicy"), iam.answers("CreatePolicy", "x")); !errors.Is(err, repositories.ErrPolicyJobLeaseShort) {
		t.Fatalf("short lease: %v, want ErrPolicyJobLeaseShort", err)
	}
	if after, _ := iam.count(); after != before {
		t.Fatal("a request was sent without the lease margin")
	}
	if ats := p3Attempts(t, db, dep2); len(ats) != 1 || ats[0].Status != models.GovAttemptAbandoned || ats[0].DispatchedAt != nil {
		t.Fatalf("short-lease attempt: %+v, want abandoned, never dispatched", ats)
	}
	if d := p3Deployment(t, db, dep2); d.State != models.GovDeployApplying {
		t.Fatalf("short-lease deployment: %s", d.State)
	}
}

// Shutdown mid-call (the worker's job context is cancelled while the request
// is in flight): the in-process worker records the attempt unknown itself,
// under its still-valid fence, before handing the job back.
func TestP3T308AttemptCancelledMidCall(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3own-attempt-cancel")
	dep := g.deployment(g.lane(), "applying")
	run := p3DeployRun(t, db, g, dep, "worker-a", 2*time.Minute, time.Now())
	log := services.NewIGAGovAttemptLog(db)
	ctx, cancel := context.WithCancel(context.Background())
	inFlight := make(chan struct{})
	call := func(c context.Context) (services.AttemptAnswer, error) {
		close(inFlight)
		<-c.Done()
		return services.AttemptAnswer{}, c.Err()
	}
	go func() { <-inFlight; cancel() }()
	res, err := log.Execute(ctx, run, p3Req(g, dep, 0, "CreatePolicy"), call)
	if err != nil || !res.Unknown {
		t.Fatalf("cancelled mid-call: %+v %v", res, err)
	}
	if d := p3Deployment(t, db, dep); d.State != models.GovDeployOutcomeUnknown {
		t.Fatalf("deployment %s", d.State)
	}
}
