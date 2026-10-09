package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Review fixes P1-5 (a deploy job that exhausts its attempts no longer locks
// the role forever; the stuck-deployment sweeper; the operator path of a
// stuck applying), P1-7 (resolve_unknown reads the enforcement session's
// CloudTrail through LookupEvents; the late-mutation watch matches by
// operation and target and covers the control whatever its deployment's
// state) and P1-8 (the binding is re-checked before each dispatch). Every
// test runs the real deploy / resolve_unknown / verify / drift_check jobs
// over the fake account, whose CloudTrail records what it received.

// worker is a real policy job worker over the lab's clock with the
// deployment kinds (and the sweeper) registered. Other open jobs of the
// lab's workspace are closed first so it claims only what the test queues.
func (d *dLab) worker() *services.PolicyJobWorker {
	d.t.Helper()
	p3exec(d.t, d.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND status IN ('queued','running')`, d.ws)
	w := services.NewPolicyJobWorker(d.db, "fx-dep-"+uuid.NewString()[:8]).WithClock(d.now).WithGate(func() bool { return true })
	d.dep.Register(w)
	return w
}

// runOnce runs one job through the worker and fails when none was claimable.
func (d *dLab) runOnce(w *services.PolicyJobWorker) {
	d.t.Helper()
	ran, err := w.RunOnce(context.Background())
	if err != nil || !ran {
		d.t.Fatalf("worker: ran %v err %v", ran, err)
	}
}

func (d *dLab) jobsOf(dep uuid.UUID, kind string) []models.IGAGovJob {
	d.t.Helper()
	var js []models.IGAGovJob
	if err := d.db.Where("workspace_id = ? AND kind = ? AND dedupe_key = ?", d.ws, kind, "deployment:"+dep.String()).
		Order("created_at").Find(&js).Error; err != nil {
		d.t.Fatal(err)
	}
	return js
}

func (d *dLab) openJob(dep uuid.UUID, kind string) *models.IGAGovJob {
	for _, j := range d.jobsOf(dep, kind) {
		if j.Status == models.GovJobQueued || j.Status == models.GovJobRunning {
			jj := j
			return &jj
		}
	}
	return nil
}

func (d *dLab) events(dep uuid.UUID, name string) []map[string]any {
	d.t.Helper()
	var rows []struct{ Payload []byte }
	d.db.Raw(`SELECT payload FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? AND event = ? ORDER BY id`, d.ws, dep, name).Scan(&rows)
	out := []map[string]any{}
	for _, r := range rows {
		m := map[string]any{}
		_ = json.Unmarshal(r.Payload, &m)
		out = append(out, m)
	}
	return out
}

// callsFor counts the fake account's write calls of action on the role or
// its AuthSec boundary (the binding self-test's own calls excluded).
func (d *dLab) callsFor(x *x3Role, action string) int {
	n := 0
	for _, c := range d.fake.Calls {
		if strings.HasPrefix(c, action+" ") && (strings.Contains(c, ":role/"+x.name+" ") || strings.Contains(c, x.role.RoleID)) {
			n++
		}
	}
	return n
}

// roleHeld proves the role is still held: the in-flight index refuses
// another deployment on the control.
func (d *dLab) roleHeld(dep uuid.UUID) bool {
	err := d.db.Exec(`INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		SELECT gen_random_uuid(), workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, 'queued' FROM iga_gov_deployment WHERE id = ?`, dep).Error
	if err == nil {
		d.db.Exec(`DELETE FROM iga_gov_deployment WHERE control_id = (SELECT control_id FROM iga_gov_deployment WHERE id = ?) AND id <> ? AND state = 'queued'`, dep, dep)
	}
	return err != nil
}

// settle advances past settle_after and takes resolve_unknown's two readings
// 5 minutes apart.
func (d *dLab) settleAndResolve(dep uuid.UUID) {
	d.t.Helper()
	d.advance(16 * time.Minute)
	if err := d.runJob("resolve_unknown", dep); !isRetryLater(err) {
		d.t.Fatalf("first reading: %v (%s)", err, d.state(dep))
	}
	d.advance(6 * time.Minute)
	d.mustRun("resolve_unknown", dep)
}

func (d *dLab) verifyApplied(x *x3Role, dep uuid.UUID) {
	d.t.Helper()
	arn := *d.planOf(dep).DesiredBoundaryARN
	d.publish(x, d.now().Add(time.Second), arn, d.ledgerVersion(x, arn))
	d.mustRun("verify", dep)
	if st := d.state(dep); st != "verified" {
		d.t.Fatalf("verify %s: %s", dep, st)
	}
}

// failBeforeOp makes the deploy job's handler fail (an error, as a crashing
// worker) before op k while *on.
func (d *dLab) failBeforeOp(k int, on *bool) {
	d.dep.Executor = func(e *services.IGAGovAWSExecutor) {
		e.WithSleep(noSleep)
		e.FaultBeforeOp = func(i int, _ igagov.Op) error {
			if *on && i == k {
				return fmt.Errorf("injected: the worker dies before op %d", i)
			}
			return nil
		}
	}
}

/* ---------------------------------- P1-5 ---------------------------------- */

// P1-5: a deploy job that exhausts its attempts AFTER changing AWS (op 0,
// CreatePolicy, done; op 1 never reached) leaves the deployment
// outcome_unresolved -- still holding the role, the operator choices
// offered -- not applying forever; the operator's Re-read through the §7.6
// route (governance:enforce, audited, with its event) returns it to applying
// with a fresh deploy job, which finishes without re-sending op 0.
//
// Fails on the base: the deployment stays applying with its job failed and
// no route accepts it (409 not_unresolved).
func TestP3FixP15ExhaustedDeployJobHoldsRoleForOperator(t *testing.T) {
	d := newDLab(t)
	x := d.role("P15Exhaust", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	dep := d.queue(x, s, igagov.PlanApply)
	failing := true
	d.failBeforeOp(1, &failing)
	w := d.worker()
	if err := services.EnqueueDeployTx(d.db, d.ws, dep); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		d.runOnce(w)
		d.advance(10 * time.Minute)
	}
	js := d.jobsOf(dep, repositories.GovJobDeploy)
	if len(js) != 1 || js[0].Status != models.GovJobFailed || js[0].Attempts != 5 {
		t.Fatalf("deploy job: %+v", js)
	}
	dd := d.deployment(dep)
	if dd.State != models.GovDeployOutcomeUnresolved || !strings.HasPrefix(dd.StateReason, services.DepReasonDeployJobExhausted) ||
		dd.OutcomeUnknownOp != "1:PutRolePermissionsBoundary" || dd.SettleAfter == nil {
		t.Fatalf("after exhaustion: %s %q op %q", dd.State, dd.StateReason, dd.OutcomeUnknownOp)
	}
	if ev := d.events(dep, services.GovEventDeploymentUnresolved); len(ev) != 1 || ev[0]["cause"] != services.DepReasonDeployJobExhausted {
		t.Fatalf("unresolved event: %v", ev)
	}
	if !d.roleHeld(dep) {
		t.Fatal("the role was released while its boundary may be half-applied")
	}
	if d.callsFor(x, "iam:CreatePolicy") != 1 || d.callsFor(x, "iam:PutRolePermissionsBoundary") != 0 {
		t.Fatalf("calls: %v", d.fake.Calls)
	}

	// The operator path, through the route.
	services.SetGovDeployEnv(d.env)
	t.Cleanup(func() { services.SetGovDeployEnv(services.GovDeployEnv{}) })
	api := p3NewOwnersAPI(t, d.db)
	p3Audit(t, d.db, d.ws)
	user, mem := d.memberM("governance:read", "governance:enforce")
	tok := api.token(d.ws, user, mem, "governance:read governance:enforce")
	failing = false
	code, body := api.call(http.MethodPost, "/deployments/"+dep.String()+"/resolve", tok, map[string]any{"action": "reread", "reason": "the worker is fixed"})
	if code != 200 || digs(body, "data", "state") != models.GovDeployApplying {
		t.Fatalf("resolve reread: %d %v", code, body)
	}
	p3WaitAudit(t, d.db, d.ws, http.MethodPost, "/api/iga/v1/policy/deployments/"+dep.String()+"/resolve")
	if ev := d.events(dep, services.GovEventDeploymentResolveReq); len(ev) != 1 || ev[0]["from_state"] != models.GovDeployOutcomeUnresolved {
		t.Fatalf("resolve event: %v", ev)
	}
	if d.openJob(dep, repositories.GovJobDeploy) == nil {
		t.Fatal("re-read queued no deploy job")
	}
	d.runOnce(w)
	if st := d.state(dep); st != models.GovDeployAppliedUnverified {
		t.Fatalf("after re-read: %s %s", st, d.deployment(dep).StateReason)
	}
	if d.callsFor(x, "iam:CreatePolicy") != 1 || d.callsFor(x, "iam:PutRolePermissionsBoundary") != 1 {
		t.Fatalf("calls after re-read: %v", d.fake.Calls)
	}
}

// P1-5: a deploy job that exhausts its attempts before anything was sent
// fails the deployment (§8.4 terminal) and releases the role.
func TestP3FixP15ExhaustedBeforeAnySendFailsAndReleases(t *testing.T) {
	d := newDLab(t)
	x := d.role("P15NoSend", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	dep := d.queue(x, s, igagov.PlanApply)
	failing := true
	d.failBeforeOp(0, &failing)
	w := d.worker()
	if err := services.EnqueueDeployTx(d.db, d.ws, dep); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		d.runOnce(w)
		d.advance(10 * time.Minute)
	}
	dd := d.deployment(dep)
	if dd.State != models.GovDeployFailed || !strings.HasPrefix(dd.StateReason, services.DepReasonDeployJobExhausted) {
		t.Fatalf("after exhaustion: %s %q", dd.State, dd.StateReason)
	}
	if d.roleHeld(dep) {
		t.Fatal("a deployment that never sent anything still holds the role")
	}
	if d.callsFor(x, "iam:CreatePolicy")+d.callsFor(x, "iam:PutRolePermissionsBoundary") != 0 {
		t.Fatalf("calls: %v", d.fake.Calls)
	}
}

// P1-5 + A58 (a): the worker dies after AWS applied CreatePolicy and before
// the answer was recorded, at its last attempt; its lease lapses. The
// worker's sweep fails the job and the exhaustion hook applies §8.1's
// replacement rule: the dispatched attempt becomes unknown, the deployment
// outcome_unknown with resolve_unknown at settle_after -- never re-sent.
// The enforcement session's CloudTrail shows the CreatePolicy applied, the
// readings agree, and the deploy job finishes with ONE CreatePolicy.
func TestP3FixP15LapsedLeaseAtCeilingA58a(t *testing.T) {
	d := newDLab(t)
	x := d.role("P15Lapsed", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	dep := d.queue(x, s, igagov.PlanApply)
	w := d.worker()
	if err := services.EnqueueDeployTx(d.db, d.ws, dep); err != nil {
		t.Fatal(err)
	}
	p3exec(t, d.db, `UPDATE iga_gov_job SET attempts = max_attempts - 1 WHERE workspace_id = ? AND dedupe_key = ?`, d.ws, "deployment:"+dep.String())
	d.fake.AfterApply["iam:CreatePolicy"] = func(context.Context) error {
		delete(d.fake.AfterApply, "iam:CreatePolicy")
		// The worker dies: its lease lapses and it never writes again.
		d.db.Exec(`UPDATE iga_gov_job SET lease_owner = 'dead-worker', lease_version = lease_version + 1, lease_expires_at = ?
			WHERE workspace_id = ? AND dedupe_key = ? AND status = 'running'`, d.now().Add(-time.Second), d.ws, "deployment:"+dep.String())
		return errors.New("connection reset by peer")
	}
	d.runOnce(w)
	var att models.IGAGovAttempt
	d.db.Where("deployment_id = ? AND op_seq = 0", dep).Take(&att)
	if att.Status != models.GovAttemptDispatched || d.state(dep) != models.GovDeployApplying {
		t.Fatalf("after the crash: attempt %s, deployment %s", att.Status, d.state(dep))
	}
	w.Sweep()
	if js := d.jobsOf(dep, repositories.GovJobDeploy); len(js) != 1 || js[0].Status != models.GovJobFailed {
		t.Fatalf("deploy job after sweep: %+v", js)
	}
	dd := d.deployment(dep)
	d.db.Where("id = ?", att.ID).Take(&att)
	if dd.State != models.GovDeployOutcomeUnknown || att.Status != models.GovAttemptUnknown || dd.OutcomeUnknownOp != "0:CreatePolicy" {
		t.Fatalf("after the exhaustion hook: deployment %s %q, attempt %s", dd.State, dd.OutcomeUnknownOp, att.Status)
	}
	if j := d.openJob(dep, repositories.GovJobResolveUnknown); j == nil || j.RunAfter.Before(*dd.SettleAfter) {
		t.Fatalf("resolve_unknown at settle_after: %+v", j)
	}
	if !d.roleHeld(dep) || d.callsFor(x, "iam:CreatePolicy") != 1 {
		t.Fatalf("held %v, CreatePolicy x%d", d.roleHeld(dep), d.callsFor(x, "iam:CreatePolicy"))
	}
	d.settleAndResolve(dep)
	d.db.Where("id = ?", att.ID).Take(&att)
	if att.ResolvedAs == nil || *att.ResolvedAs != services.AttemptResolvedApplied || d.state(dep) != models.GovDeployApplying {
		t.Fatalf("resolution: %v %s", att.ResolvedAs, d.state(dep))
	}
	if ev := d.events(dep, services.GovEventUnknownReading); len(ev) != 2 || ev[1]["trail"] != "applied" {
		t.Fatalf("readings: %v", ev)
	}
	d.mustRun("deploy", dep)
	if st := d.state(dep); st != models.GovDeployAppliedUnverified || d.callsFor(x, "iam:CreatePolicy") != 1 {
		t.Fatalf("resume: %s, CreatePolicy x%d", st, d.callsFor(x, "iam:CreatePolicy"))
	}
}

// P1-5: the sweeper re-enqueues the job of an in-flight deployment that has
// none (a crash between the transaction that moved it and the one that
// should have queued its job): applying -> deploy, outcome_unknown ->
// resolve_unknown at settle_after; each with deployment.job_requeued.
func TestP3FixP15SweeperRequeuesLostJobs(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	_, _, held := dUnknownApply(t, d, "P15SweepUnknown")
	x := d.role("P15SweepApplying", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.queue(x, d.storeApproved(x, tp.Apply, *tp.Undo), igagov.PlanApply)
	stop := true
	d.failBeforeOp(1, &stop)
	if err := d.runJob("deploy", dep); err == nil || d.state(dep) != models.GovDeployApplying {
		t.Fatalf("setup: %v %s", err, d.state(dep))
	}
	stop = false
	// Both jobs are lost (never committed, or pruned).
	p3exec(t, d.db, `DELETE FROM iga_gov_job WHERE workspace_id = ? AND dedupe_key IN (?, ?)`, d.ws, "deployment:"+dep.String(), "deployment:"+held.String())
	w := d.worker()
	d.advance(3 * time.Minute)
	if err := w.RunSweepersNow(ctx); err != nil {
		t.Fatal(err)
	}
	if d.openJob(dep, repositories.GovJobDeploy) == nil {
		t.Fatal("the applying deployment's deploy job was not re-enqueued")
	}
	hj := d.openJob(held, repositories.GovJobResolveUnknown)
	if hj == nil || hj.RunAfter.Before(*d.deployment(held).SettleAfter) {
		t.Fatalf("the outcome_unknown deployment's resolve_unknown: %+v", hj)
	}
	for _, id := range []uuid.UUID{dep, held} {
		if ev := d.events(id, services.GovEventDeploymentRequeued); len(ev) != 1 {
			t.Fatalf("requeued event of %s: %v", id, ev)
		}
	}
	p3exec(t, d.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() WHERE id = ?`, hj.ID)
	d.runOnce(w)
	if st := d.state(dep); st != models.GovDeployAppliedUnverified {
		t.Fatalf("after the re-enqueued deploy job: %s %s", st, d.deployment(dep).StateReason)
	}
}

// P1-5: ResolveUnknown fails loudly when the deployment is not
// outcome_unknown -- the attempt's resolution rolls back with it.
func TestP3FixP15ResolveUnknownChecksTheDeploymentMoved(t *testing.T) {
	d := newDLab(t)
	_, _, dep := dUnknownApply(t, d, "P15Resolve")
	d.fake.EditTrail(func(rs []enforcetest.TrailRecord) []enforcetest.TrailRecord {
		for i := range rs {
			rs[i].ErrorCode, rs[i].Response = "AccessDenied", nil
		}
		return rs
	})
	d.settleAndResolve(dep)
	if d.state(dep) != models.GovDeployOutcomeUnresolved {
		t.Fatalf("setup: %s", d.state(dep))
	}
	var att models.IGAGovAttempt
	d.db.Where("deployment_id = ? AND status = 'unknown'", dep).Take(&att)
	repo := repositories.NewIGAGovJobRepository(d.db)
	sid := dep
	if _, err := repo.EnqueueTx(d.db, &models.IGAGovJob{WorkspaceID: d.ws, Kind: repositories.GovJobResolveUnknown, SubjectID: &sid,
		DedupeKey: "fx-resolve:" + dep.String(), RunAfter: d.now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	j := p3ClaimOwn(t, d.db, d.ws, "fx-resolve", 2*time.Minute, d.now(), repositories.GovJobResolveUnknown)
	run := services.NewPolicyJobRun(d.db, *j, "fx-resolve")
	err := d.dep.AttemptLog().ResolveUnknown(context.Background(), run, &att, services.AttemptResolvedApplied)
	if !errors.Is(err, services.ErrAttemptState) {
		t.Fatalf("resolve while unresolved: %v", err)
	}
	var after models.IGAGovAttempt
	d.db.Where("id = ?", att.ID).Take(&after)
	if after.ResolvedAs != nil || d.state(dep) != models.GovDeployOutcomeUnresolved {
		t.Fatalf("a refused resolution left %v / %s", after.ResolvedAs, d.state(dep))
	}
}

// P1-5: a dispatched attempt whose deployment was moved meanwhile is still
// marked unknown (Recover no longer refuses it), the deployment's state
// untouched, so recovery of the deployment is not blocked forever.
func TestP3FixP15RecoverMarksDispatchedUnknownWhateverTheState(t *testing.T) {
	d := newDLab(t)
	x := d.role("P15Recover", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.queue(x, d.storeApproved(x, tp.Apply, *tp.Undo), igagov.PlanApply)
	d.fake.AfterApply["iam:CreatePolicy"] = func(context.Context) error {
		delete(d.fake.AfterApply, "iam:CreatePolicy")
		// While the answer is lost the deployment is moved by someone else
		// and this worker loses its lease.
		d.db.Exec(`UPDATE iga_gov_job SET lease_version = lease_version + 1 WHERE workspace_id = ? AND dedupe_key = ? AND status = 'running'`,
			d.ws, "deployment:"+dep.String())
		d.db.Exec(`UPDATE iga_gov_deployment SET state = 'blocked', state_reason = 'moved meanwhile' WHERE id = ?`, dep)
		return errors.New("connection reset by peer")
	}
	_ = d.runJob("deploy", dep)
	sid := dep
	repo := repositories.NewIGAGovJobRepository(d.db)
	if _, err := repo.EnqueueTx(d.db, &models.IGAGovJob{WorkspaceID: d.ws, Kind: repositories.GovJobDeploy, SubjectID: &sid,
		DedupeKey: "fx-recover:" + dep.String(), RunAfter: d.now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	j := p3ClaimOwn(t, d.db, d.ws, "fx-recover", 2*time.Minute, d.now(), repositories.GovJobDeploy)
	rec, err := d.dep.AttemptLog().Recover(context.Background(), services.NewPolicyJobRun(d.db, *j, "fx-recover"), d.ws, dep)
	if err != nil || rec.Action != services.RecoveryOutcomeUnknown {
		t.Fatalf("recover: %+v %v", rec, err)
	}
	var att models.IGAGovAttempt
	d.db.Where("deployment_id = ? AND op_seq = 0", dep).Take(&att)
	if att.Status != models.GovAttemptUnknown || d.state(dep) != "blocked" {
		t.Fatalf("attempt %s deployment %s", att.Status, d.state(dep))
	}
}

/* ---------------------------------- P1-8 ---------------------------------- */

// P1-8: the binding is revoked between op 0 and op 1 of a run: op 1 is
// prepared, refused by the per-dispatch check and abandoned -- never sent --
// and the deployment stops blocked with binding_not_verified (revoked).
//
// Fails on the base: the run keeps the client it assumed and sends op 1.
func TestP3FixP18RevokedBindingStopsTheRun(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("P18Revoke", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.queue(x, d.storeApproved(x, tp.Apply, *tp.Undo), igagov.PlanApply)
	d.fake.AfterApply["iam:CreatePolicy"] = func(context.Context) error {
		delete(d.fake.AfterApply, "iam:CreatePolicy")
		if _, err := d.enf.svc.Revoke(ctx, d.ws, d.conn.ID, d.user, "incident: stop all changes"); err != nil {
			t.Errorf("revoke: %v", err)
		}
		return nil
	}
	d.mustRun("deploy", dep)
	dd := d.deployment(dep)
	if dd.State != models.GovDeployBlocked || !strings.HasPrefix(dd.StateReason, "binding_not_verified") || !strings.Contains(dd.StateReason, "revoked") {
		t.Fatalf("after revocation: %s %q", dd.State, dd.StateReason)
	}
	if d.callsFor(x, "iam:CreatePolicy") != 1 || d.callsFor(x, "iam:PutRolePermissionsBoundary") != 0 {
		t.Fatalf("calls: %v", d.fake.Calls)
	}
	var atts []models.IGAGovAttempt
	d.db.Where("deployment_id = ? AND op_seq = 1", dep).Find(&atts)
	if len(atts) != 1 || atts[0].Status != models.GovAttemptAbandoned || atts[0].DispatchedAt != nil {
		t.Fatalf("op 1 attempts: %+v", atts)
	}
	if d.roleHeld(dep) {
		t.Fatal("the stopped deployment still holds the role")
	}
}

/* ---------------------------------- P1-7 ---------------------------------- */

// v2 compiles and stores the role's next version (sns and sqs removed).
func (d *dLab) next(x *x3Role, remove ...string) x3Stored {
	tp := d.compile(d.fake.Discovery(), x, remove...)
	return d.storeApproved(x, tp.Apply, *tp.Undo)
}

// A58 (b), (c), (e): a CreatePolicyVersion delayed past the client timeout is
// unknown (one attempt, no SDK retry); an undo and another deployment on the
// role are refused while it is; after settle_after the readings (state
// before) and CloudTrail (no event of the request yet) resolve it
// not_applied and the version is deployed by a new attempt; version 3 is
// deployed and verified; THEN the delayed request lands: the control's
// drift check (every 5 minutes while watched) reports
// late_mutation_suspected on version 3's deployment, matched by operation
// and target, and nothing is re-applied or reverted.
func TestP3FixP17DelayedVersionLandsLateA58bce(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("P17Delayed", "/", nil)
	d1 := d.applyAndVerify(x, d.next(x, "sqs"))
	s2 := d.next(x, "sns", "sqs")
	d2 := d.queue(x, s2, igagov.PlanApply)
	d.dep.AttemptLog().CallTimeout = 300 * time.Millisecond
	release := d.fake.HoldNext("iam:CreatePolicyVersion")
	t.Cleanup(release)
	d.mustRun("deploy", d2)
	if st := d.state(d2); st != models.GovDeployOutcomeUnknown {
		t.Fatalf("(b) after the client timeout: %s %s", st, d.deployment(d2).StateReason)
	}
	var n int64
	d.db.Raw(`SELECT count(*) FROM iga_gov_attempt WHERE deployment_id = ? AND operation = 'CreatePolicyVersion'`, d2).Scan(&n)
	if n != 1 || d.callsFor(x, "iam:CreatePolicyVersion") != 0 {
		t.Fatalf("(b) attempts %d, calls that reached AWS %d", n, d.callsFor(x, "iam:CreatePolicyVersion"))
	}
	// (c) conflicting work is refused while unknown.
	if _, err := d.dep.Undo(ctx, d.ws, d.approver, d1, services.GovUndoRequest{}, false); govCode(err) != services.GovCodeOutcomeUnknownPending {
		t.Fatalf("(c) undo: %v", err)
	}
	if !d.roleHeld(d2) {
		t.Fatal("(c) another deployment started on the held role")
	}
	d.settleAndResolve(d2)
	if st := d.state(d2); st != models.GovDeployApplying {
		t.Fatalf("resolution: %s %s", st, d.deployment(d2).StateReason)
	}
	d.mustRun("deploy", d2)
	d.verifyApplied(x, d2)
	d3 := d.applyAndVerify(x, d.next(x, "sns", "sqs", "ec2"))
	calls := len(d.fake.Calls)
	release() // (e) the delayed request reaches AWS now
	doc2 := *d.planOf(d2).DesiredDocumentHash
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, doc, _, _ := d.fake.PolicyState(*d.planOf(d3).DesiredBoundaryARN)
		if _, h, err := igagov.CanonicalDocument(doc); err == nil && h == doc2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the delayed CreatePolicyVersion never landed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	calls++ // the late request itself
	due := dueDriftCheck(t, d, d3)
	if due == nil || due.Every != services.DriftCheckEveryAfterLate {
		t.Fatalf("(e) drift_check of version 3 while watched: %+v", due)
	}
	d.mustRun("drift_check", d3)
	dd := d.deployment(d3)
	if dd.State != models.GovDeployDrifted || dd.StateReason != services.DriftLateMutation {
		t.Fatalf("(e) late mutation: %s %q", dd.State, dd.StateReason)
	}
	ev := d.events(d3, services.GovEventDriftLateMutation)
	if len(ev) != 1 || ev[0]["operation"] != "CreatePolicyVersion" || ev[0]["attempt_deployment_id"] != d2.String() {
		t.Fatalf("(e) event: %v", ev)
	}
	if len(d.fake.Calls) != calls {
		t.Fatalf("(e) something was re-applied or reverted: %v", d.fake.Calls[calls:])
	}
}

// dueDriftCheck is the drift_check schedule's item for dep, nil when not due.
func dueDriftCheck(t *testing.T, d *dLab, dep uuid.UUID) *services.ScheduledPolicyJob {
	t.Helper()
	for _, sc := range services.DefaultPolicyJobSchedules() {
		if sc.Kind != repositories.GovJobDriftCheck {
			continue
		}
		items, err := sc.Due(context.Background(), d.db, d.now())
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.SubjectID != nil && *it.SubjectID == dep {
				i := it
				return &i
			}
		}
	}
	return nil
}

// P1-7: the late-mutation watch matches a DETACH (no document hash) by
// operation and target, and watches the control whatever its deployment's
// state. An undo's DeleteRolePermissionsBoundary is delayed past the client
// timeout and resolved not_applied (no CloudTrail event, the boundary still
// there); the undo then completes and the role is re-applied, left
// applied_unverified. When the delayed detach lands, the control's drift
// check -- scheduled for the applied_unverified deployment because the
// control is watched -- reports late_mutation_suspected on it.
//
// Fails on the base: drift_check is scheduled and run only for verified
// deployments, and a late mutation is matched by document hash only.
func TestP3FixP17LateDetachWatchedWhateverTheState(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("P17Detach", "/", nil)
	s1 := d.next(x, "sqs")
	d1 := d.applyAndVerify(x, s1)
	u, err := d.dep.Undo(ctx, d.ws, d.approver, d1, services.GovUndoRequest{}, false)
	if err != nil {
		t.Fatal(err)
	}
	d.dep.AttemptLog().CallTimeout = 300 * time.Millisecond
	release := d.fake.HoldNext("iam:DeleteRolePermissionsBoundary")
	t.Cleanup(release)
	d.mustRun("deploy", u.ID)
	if st := d.state(u.ID); st != models.GovDeployOutcomeUnknown {
		t.Fatalf("undo after the timeout: %s", st)
	}
	d.settleAndResolve(u.ID)
	d.mustRun("deploy", u.ID)
	if st := d.state(u.ID); st != models.GovDeployAppliedUnverified {
		t.Fatalf("undo: %s %s", st, d.deployment(u.ID).StateReason)
	}
	d.publish(x, d.now().Add(time.Second), "", "")
	d.retirePolicy(*d.planOf(d1).DesiredBoundaryARN)
	d.mustRun("verify", u.ID)
	if d.state(u.ID) != "verified" {
		t.Fatalf("undo verify: %s", d.state(u.ID))
	}
	d2 := d.queue(x, d.next(x, "sqs"), igagov.PlanApply)
	d.mustRun("deploy", d2)
	if st := d.state(d2); st != models.GovDeployAppliedUnverified {
		t.Fatalf("re-apply: %s %s", st, d.deployment(d2).StateReason)
	}
	calls := len(d.fake.Calls)
	release()
	deadline := time.Now().Add(5 * time.Second)
	for d.fake.BoundaryOf(x.name) != "" {
		if time.Now().After(deadline) {
			t.Fatal("the delayed DeleteRolePermissionsBoundary never landed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	calls++
	due := dueDriftCheck(t, d, d2)
	if due == nil || due.Every != services.DriftCheckEveryAfterLate {
		t.Fatalf("the applied_unverified deployment of the watched control is not checked: %+v", due)
	}
	d.mustRun("drift_check", d2)
	ev := d.events(d2, services.GovEventDriftLateMutation)
	if len(ev) != 1 || ev[0]["operation"] != "DeleteRolePermissionsBoundary" || ev[0]["deployment_state"] != models.GovDeployAppliedUnverified {
		t.Fatalf("late detach: %v", ev)
	}
	d.mustRun("drift_check", d2) // reported once
	if len(d.events(d2, services.GovEventDriftLateMutation)) != 1 || len(d.fake.Calls) != calls {
		t.Fatalf("repeat report or writes: %v", d.fake.Calls[calls:])
	}
}

// unknownTag deploys version 2 of an applied role (CreatePolicyVersion,
// TagPolicy) with TagPolicy's answer lost; applied says whether AWS applied
// the tag (the answer lost after) or never received it (held past the
// client timeout).
func unknownTag(t *testing.T, d *dLab, name string, applied bool) (*x3Role, uuid.UUID) {
	t.Helper()
	x := d.role(name, "/", nil)
	d.applyAndVerify(x, d.next(x, "sqs"))
	dep := d.queue(x, d.next(x, "sns", "sqs"), igagov.PlanApply)
	if applied {
		d.fake.AfterApply["iam:TagPolicy"] = func(context.Context) error {
			delete(d.fake.AfterApply, "iam:TagPolicy")
			return errors.New("connection reset by peer")
		}
	} else {
		d.dep.AttemptLog().CallTimeout = 300 * time.Millisecond
		t.Cleanup(d.fake.HoldNext("iam:TagPolicy"))
	}
	d.mustRun("deploy", dep)
	dd := d.deployment(dep)
	if dd.State != models.GovDeployOutcomeUnknown || !strings.HasSuffix(dd.OutcomeUnknownOp, ":TagPolicy") {
		t.Fatalf("setup: %s %q", dd.State, dd.OutcomeUnknownOp)
	}
	return x, dep
}

// P1-7: an op a read cannot see (TagPolicy) is resolved ONLY from the
// enforcement session's CloudTrail: an applied event resolves it applied;
// no event leaves the outcome unresolved -- never not_applied by default --
// and an unreadable trail too.
//
// Fails on the base: with no event (and with the trail unreadable, its error
// swallowed) the attempt is resolved not_applied and the deployment resumes.
func TestP3FixP17UnobservableOpResolvedOnlyFromCloudTrail(t *testing.T) {
	d := newDLab(t)
	t.Run("applied event", func(t *testing.T) {
		_, dep := unknownTag(t, d, "P17TagApplied", true)
		d.settleAndResolve(dep)
		var att models.IGAGovAttempt
		d.db.Where("deployment_id = ? AND status = 'unknown'", dep).Take(&att)
		if d.state(dep) != models.GovDeployApplying || att.ResolvedAs == nil || *att.ResolvedAs != services.AttemptResolvedApplied {
			t.Fatalf("%s %v", d.state(dep), att.ResolvedAs)
		}
	})
	t.Run("no event", func(t *testing.T) {
		_, dep := unknownTag(t, d, "P17TagNoEvent", false)
		d.settleAndResolve(dep)
		if dd := d.deployment(dep); dd.State != models.GovDeployOutcomeUnresolved || !strings.Contains(dd.StateReason, "CloudTrail no event") {
			t.Fatalf("%s %q", dd.State, dd.StateReason)
		}
	})
	t.Run("unreadable trail", func(t *testing.T) {
		_, dep := unknownTag(t, d, "P17TagUnreadable", true)
		d.fake.TrailErr = errors.New("AccessDeniedException: cloudtrail:LookupEvents")
		defer func() { d.fake.TrailErr = nil }()
		d.settleAndResolve(dep)
		if dd := d.deployment(dep); dd.State != models.GovDeployOutcomeUnresolved || !strings.Contains(dd.StateReason, "CloudTrail unreadable") {
			t.Fatalf("%s %q", dd.State, dd.StateReason)
		}
	})
}

// P1-7: an unreadable trail is `unknown`, never not_applied: an observable
// op (PutRolePermissionsBoundary held past the client timeout) whose
// readings say not applied stays unresolved while CloudTrail cannot be
// read; the same readings with the trail readable (no event) resolve it
// not_applied; readings that show the effect resolve applied even when the
// trail is unreadable (the live state itself proves it).
func TestP3FixP17UnreadableTrailIsNeverNotApplied(t *testing.T) {
	d := newDLab(t)
	held := func(name string) uuid.UUID {
		x := d.role(name, "/", nil)
		dep := d.queue(x, d.next(x, "sqs"), igagov.PlanApply)
		d.dep.AttemptLog().CallTimeout = 300 * time.Millisecond
		t.Cleanup(d.fake.HoldNext("iam:PutRolePermissionsBoundary"))
		d.mustRun("deploy", dep)
		if st := d.state(dep); st != models.GovDeployOutcomeUnknown {
			t.Fatalf("setup %s: %s", name, st)
		}
		return dep
	}
	dep := held("P17PutUnreadable")
	d.fake.TrailErr = errors.New("ThrottlingException: Rate exceeded")
	d.settleAndResolve(dep)
	d.fake.TrailErr = nil
	if dd := d.deployment(dep); dd.State != models.GovDeployOutcomeUnresolved || !strings.Contains(dd.StateReason, "CloudTrail unreadable") {
		t.Fatalf("unreadable: %s %q", dd.State, dd.StateReason)
	}
	ev := d.events(dep, services.GovEventUnknownReading)
	if len(ev) != 2 || ev[1]["trail"] != "unknown" || !strings.Contains(fmt.Sprint(ev[1]["trail_detail"]), "Rate exceeded") {
		t.Fatalf("readings: %v", ev)
	}
	dep2 := held("P17PutReadable")
	d.settleAndResolve(dep2)
	if st := d.state(dep2); st != models.GovDeployApplying {
		t.Fatalf("readable, no event: %s %s", st, d.deployment(dep2).StateReason)
	}
	_, _, dep3 := dUnknownApply(t, d, "P17PutAppliedUnreadable")
	d.fake.TrailErr = errors.New("ThrottlingException: Rate exceeded")
	d.settleAndResolve(dep3)
	d.fake.TrailErr = nil
	if st := d.state(dep3); st != models.GovDeployApplying {
		t.Fatalf("applied readings, unreadable trail: %s %s", st, d.deployment(dep3).StateReason)
	}
}

// A58 (a), second half: a `prepared` attempt (the worker lost its lease
// after preparing, before dispatching) is abandoned by the replacement and
// re-prepared as attempt 2; the op is sent once.
func TestP3FixPreparedAttemptAbandonedAndReprepared(t *testing.T) {
	d := newDLab(t)
	x := d.role("P17Prepared", "/", nil)
	dep := d.queue(x, d.next(x, "sqs"), igagov.PlanApply)
	stole := false
	d.beforeDispatch = func() error {
		if !stole {
			stole = true
			d.db.Exec(`UPDATE iga_gov_job SET lease_version = lease_version + 1 WHERE workspace_id = ? AND dedupe_key = ? AND status = 'running'`,
				d.ws, "deployment:"+dep.String())
		}
		return nil
	}
	if err := d.runJob("deploy", dep); err == nil {
		t.Fatal("the run kept going after losing its lease")
	}
	d.mustRun("deploy", dep)
	var atts []models.IGAGovAttempt
	d.db.Where("deployment_id = ? AND op_seq = 0", dep).Order("attempt_no").Find(&atts)
	if len(atts) != 2 || atts[0].Status != models.GovAttemptAbandoned || atts[1].Status != models.GovAttemptCompleted ||
		d.callsFor(x, "iam:CreatePolicy") != 1 || d.state(dep) != models.GovDeployAppliedUnverified {
		t.Fatalf("attempts %+v, CreatePolicy x%d, %s", atts, d.callsFor(x, "iam:CreatePolicy"), d.state(dep))
	}
}

// P1-5: the operator path of a deployment stuck `applying` (§8.1 step 3's
// choices on POST /deployments/:id/resolve, governance:enforce, audited,
// with events). Every op is done, then every discovery read fails (the
// readback never settles), so the deploy job hands itself back forever. While a job holds the deployment's
// lease the route answers 409 deploy_job_running; Re-read re-queues the
// deploy job now; Accept observed state (naming an approved version)
// declares the deployment outcome_unresolved -- the role never released --
// and hands it over atomically to the accepted version's deployment.
//
// Fails on the base: an applying deployment is refused (409 not_unresolved).
func TestP3FixP15StuckApplyingOperatorPath(t *testing.T) {
	d := newDLab(t)
	x := d.role("P15StuckApplying", "/", nil)
	dep := d.queue(x, d.next(x, "sqs"), igagov.PlanApply)
	d.fake.AfterApply["iam:PutRolePermissionsBoundary"] = func(context.Context) error {
		delete(d.fake.AfterApply, "iam:PutRolePermissionsBoundary")
		d.fake.ReadFail["iam:GetRole"] = errors.New("RequestLimitExceeded")
		return nil
	}
	if err := d.runJob("deploy", dep); !isRetryLater(err) || d.state(dep) != models.GovDeployApplying {
		t.Fatalf("setup: %v %s", err, d.state(dep))
	}
	services.SetGovDeployEnv(d.env)
	t.Cleanup(func() { services.SetGovDeployEnv(services.GovDeployEnv{}) })
	api := p3NewOwnersAPI(t, d.db)
	p3Audit(t, d.db, d.ws)
	user, mem := d.memberM("governance:read", "governance:enforce")
	tok := api.token(d.ws, user, mem, "governance:read governance:enforce")
	path := "/deployments/" + dep.String() + "/resolve"

	// A deploy job is running the deployment: refused.
	if err := services.EnqueueDeployTx(d.db, d.ws, dep); err != nil {
		t.Fatal(err)
	}
	j := p3ClaimOwn(t, d.db, d.ws, "fx-stuck", 2*time.Minute, d.now(), repositories.GovJobDeploy)
	if code, body := api.call(http.MethodPost, path, tok, map[string]any{"action": "reread", "reason": "x"}); code != 409 ||
		p3ErrCode(body) != services.GovCodeDeployJobRunning {
		t.Fatalf("while running: %d %v", code, body)
	}
	// It hands itself back (retry later): re-read brings it forward.
	p3exec(t, d.db, `UPDATE iga_gov_job SET status = 'queued', lease_owner = '', lease_expires_at = NULL, run_after = now() + interval '5 minutes' WHERE id = ?`, j.ID)
	code, body := api.call(http.MethodPost, path, tok, map[string]any{"action": "reread", "reason": "the read throttling ended"})
	if code != 200 || digs(body, "data", "state") != models.GovDeployApplying {
		t.Fatalf("reread: %d %v", code, body)
	}
	p3WaitAudit(t, d.db, d.ws, http.MethodPost, "/api/iga/v1/policy"+path)
	if oj := d.openJob(dep, repositories.GovJobDeploy); oj == nil || oj.ID != j.ID || oj.RunAfter.After(time.Now().Add(time.Minute)) {
		t.Fatalf("reread did not bring the deploy job forward: %+v", oj)
	}

	// Accept observed state, naming an approved version.
	delete(d.fake.ReadFail, "iam:GetRole")
	tp2 := d.compile(d.fake.Discovery(), x, "sqs") // from what AWS shows
	plans := []igagov.Plan{tp2.Apply}
	if tp2.Undo != nil {
		plans = append(plans, *tp2.Undo)
	}
	s2 := d.storeApproved(x, plans...)
	var no int
	d.db.Raw(`SELECT version_no FROM iga_gov_policy_version WHERE id = ?`, s2.version).Scan(&no)
	code, body = api.call(http.MethodPost, path, tok, map[string]any{"action": "accept_observed", "reason": "AWS shows the policy created", "version_no": no})
	if code != 200 {
		t.Fatalf("accept_observed: %d %v", code, body)
	}
	old := d.deployment(dep)
	succ := d.deployment(uuid.MustParse(digs(body, "data", "id")))
	if old.State != models.GovDeployRecovered || old.RecoveredByDeploymentID == nil || *old.RecoveredByDeploymentID != succ.ID ||
		succ.RecoversDeploymentID == nil || *succ.RecoversDeploymentID != dep {
		t.Fatalf("handoff: old %s succ %s", old.State, succ.State)
	}
	if ev := d.events(dep, services.GovEventDeploymentUnresolved); len(ev) != 1 || ev[0]["cause"] != services.DepReasonOperatorDeclared ||
		ev[0]["from_state"] != models.GovDeployApplying {
		t.Fatalf("declared: %v", ev)
	}
	if ev := d.events(dep, services.GovEventDeploymentResolveReq); len(ev) != 2 {
		t.Fatalf("resolve events: %v", ev)
	}
	var abandoned int64
	d.db.Raw(`SELECT count(*) FROM iga_gov_job WHERE id = ? AND status = 'abandoned'`, j.ID).Scan(&abandoned)
	if abandoned != 1 {
		t.Fatal("the stuck deployment's queued deploy job was not abandoned")
	}
	d.mustRun("deploy", succ.ID)
	if st := d.state(succ.ID); st != models.GovDeployAppliedUnverified || d.callsFor(x, "iam:CreatePolicy") != 1 {
		t.Fatalf("successor: %s %s, CreatePolicy x%d", st, d.deployment(succ.ID).StateReason, d.callsFor(x, "iam:CreatePolicy"))
	}
}
