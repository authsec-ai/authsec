package integration

// T3.15 rollout (SPEC-iga-phase3-policy.md §2.6, §7.5, §8.6; L-12; A6, A10,
// A16/A49 rollout side, A18, A24, A28, A62) against real PostgreSQL: the P3
// lab (REAL scan worker, projection and evaluation with the observe_tick
// hook), the production /api/iga/v1 routes, the real job worker with the
// rollout's kinds, and FAKE deployment facts -- the deployment and
// verification rows read directly (services.GovRowDeploymentFacts) with
// injected CloudTrail events and reads, standing in for T3.16. Deployment
// state changes T3.16 would make are written to the rows. Prefixed p3r.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

/* --------------------------------- harness -------------------------------- */

type p3rTrail struct {
	mu     sync.Mutex
	events map[uuid.UUID][]igagov.TrailEvent
	reads  map[uuid.UUID][]igagov.TrailRead
}

func (f *p3rTrail) get(_ uuid.UUID, dep uuid.UUID) ([]igagov.TrailEvent, []igagov.TrailRead) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]igagov.TrailEvent(nil), f.events[dep]...), append([]igagov.TrailRead(nil), f.reads[dep]...)
}

func (f *p3rTrail) set(dep uuid.UUID, events []igagov.TrailEvent, reads []igagov.TrailRead) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events[dep], f.reads[dep] = events, reads
}

type p3rLab struct {
	*p3aLab
	trail  *p3rTrail
	worker *services.PolicyJobWorker
}

func newP3rLab(t *testing.T, name string, enforce bool) *p3rLab {
	t.Helper()
	l := &p3rLab{p3aLab: newP3aLab(t, name), trail: &p3rTrail{events: map[uuid.UUID][]igagov.TrailEvent{}, reads: map[uuid.UUID][]igagov.TrailRead{}}}
	t.Cleanup(services.SetGovRolloutDeploymentFacts(&services.GovRowDeploymentFacts{DB: l.db, Trail: l.trail.get}))
	if enforce {
		p3exec(t, l.db, `INSERT INTO iga_gov_settings (workspace_id, enforcement_mode) VALUES (?, 'enforce')`, l.ws)
		l.bind("verified")
	}
	l.worker = services.NewPolicyJobWorker(l.db, "p3r-"+name).WithGate(func() bool { return true })
	services.RegisterRolloutJobs(l.worker, services.NewGovRollout(l.db, l.live))
	return l
}

// bind records the account's enforcement binding in state.
func (l *p3rLab) bind(state string) {
	l.t.Helper()
	p3exec(l.t, l.db, `DELETE FROM cloud_enforcement_binding WHERE workspace_id = ?`, l.ws)
	p3exec(l.t, l.db, `INSERT INTO cloud_enforcement_binding (workspace_id, connector_id, account_id, role_arn, state, consented_by, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, now())`, l.ws, l.a.conn, accountA, "arn:aws:iam::"+accountA+":role/AuthSecEnforcement-p3r", state, l.author.user)
}

// drain runs the rollout's claimable jobs until none is left.
func (l *p3rLab) drain() {
	l.t.Helper()
	for i := 0; i < 50; i++ {
		ok, err := l.worker.RunOnce(context.Background())
		if err != nil {
			l.t.Fatalf("worker: %v", err)
		}
		if !ok {
			return
		}
	}
	l.t.Fatal("the worker did not drain")
}

// tick enqueues a periodic observe_tick for the policy's rollouts and drains.
func (l *p3rLab) tick() {
	l.t.Helper()
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() - interval '1 hour'
		WHERE workspace_id = ? AND kind = 'observe_tick' AND status = 'queued'`, l.ws)
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET completed_at = now() - interval '1 hour' WHERE workspace_id = ? AND kind = 'observe_tick'`, l.ws)
	if _, err := l.worker.Scheduler().RunSchedulesNow(context.Background(), time.Now()); err != nil {
		l.t.Fatal(err)
	}
	l.drain()
}

// prepare proposes and compiles the roles' policy and lets the owner gate
// pass (opened review, approver's exception: the lab's roles have no owners).
func (l *p3rLab) prepare(roleIDs ...string) string {
	l.t.Helper()
	policy, _ := l.proposeTemplate(roleIDs...)
	l.compile(policy, 1)
	svc := services.NewIGAGovOwnerReviewService(l.db)
	s, err := svc.OpenReview(context.Background(), l.ws, l.versionID(policy, 1), l.author.user)
	if err != nil {
		l.t.Fatal(err)
	}
	if _, _, err := svc.Except(context.Background(), l.ws, l.approver.user, s.ReviewID, "the lab's roles have no owners"); err != nil {
		l.t.Fatal(err)
	}
	return policy
}

func (l *p3rLab) start(m p3aMember, policy string) (int, map[string]any) {
	return l.call(m, http.MethodPost, "/policies/"+policy+"/rollout/start", map[string]any{"reason": "go"})
}

func (l *p3rLab) rollout(policy string) map[string]any {
	l.t.Helper()
	code, body := l.call(l.author, http.MethodGet, "/policies/"+policy+"/rollout", nil)
	return l.must(code, body, http.StatusOK, "GET rollout")
}

func p3rStage(v map[string]any) string { return digs(v, "rollout", "stage") }

// observed starts observation, moves observe_until into the past and
// publishes a fresh report so the evaluator's observe_tick completes it.
func (l *p3rLab) observed(policy string) {
	l.t.Helper()
	l.must2(l.start(l.author, policy))
	p3exec(l.t, l.db, `UPDATE iga_gov_rollout SET observe_until = now() - interval '10 hours',
		observe_evidence_required_after = now() - interval '6 hours' WHERE workspace_id = ?`, l.ws)
	l.activity(l.a).completed = time.Now().Add(-time.Hour)
	l.publish()
	l.drain()
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutAwaitingApproval {
		l.t.Fatalf("after a fresh report: stage %s, want awaiting_approval", st)
	}
}

func (l *p3rLab) must2(code int, body map[string]any) map[string]any {
	l.t.Helper()
	return l.must(code, body, http.StatusOK, "rollout call")
}

// toCanary takes the policy through observation and approval to its canary
// and returns the canary deployment id.
func (l *p3rLab) toCanary(policy string) uuid.UUID {
	l.t.Helper()
	l.observed(policy)
	l.approveAll(policy, 1)
	v := l.must2(l.start(l.author, policy))
	if p3rStage(v) != models.GovRolloutCanary {
		l.t.Fatalf("start after approval: %v", v)
	}
	return uuid.MustParse(digs(v, "results", "canary", "deployment_id"))
}

// applied makes a deployment applied (what T3.16 would do) `ago` before now,
// with the artifact dimension passed.
func (l *p3rLab) applied(dep uuid.UUID, state string, ago time.Duration) time.Time {
	l.t.Helper()
	at := time.Now().Add(-ago).UTC()
	p3exec(l.t, l.db, `UPDATE iga_gov_deployment SET state = ?, applied_at = ? WHERE id = ?`, state, at, dep)
	p3exec(l.t, l.db, `INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome) VALUES (?, ?, 'artifact', 'passed')
		ON CONFLICT (deployment_id, dimension) DO UPDATE SET outcome = 'passed'`, l.ws, dep)
	return at
}

// clean is canary traffic with success on every retained service and full
// trail coverage.
func p3rClean(roleID string, at time.Time, retained ...string) ([]igagov.TrailEvent, []igagov.TrailRead) {
	var evs []igagov.TrailEvent
	for _, s := range retained {
		evs = append(evs, igagov.TrailEvent{EventTime: at.Add(time.Hour), PrincipalID: roleID, SessionName: "workload",
			EventSource: s + ".amazonaws.com", EventName: "DescribeP3a"})
	}
	return evs, []igagov.TrailRead{{From: at.Add(-time.Hour), To: time.Now().Add(time.Hour)}}
}

func p3rDenied(roleID, session, svc, name string, at time.Time, cause string) igagov.TrailEvent {
	return igagov.TrailEvent{EventTime: at, PrincipalID: roleID, SessionName: session, EventSource: svc + ".amazonaws.com",
		EventName: name, ErrorCode: "AccessDenied", DenialPolicyType: cause}
}

func (l *p3rLab) resume(policy string) {
	l.t.Helper()
	l.must2(l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/resume", map[string]any{"reason": "investigated"}))
}

// waitAudits polls audit_events (written asynchronously) for n rows of action.
func (l *p3rLab) waitAudits(action string, n int64) int64 {
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := l.audits(action)
		if got >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (l *p3rLab) pauseKind(v map[string]any) string { return digs(v, "results", "pause", "kind") }

/* --------------------------------- tests ---------------------------------- */

// §2.6 / §8.6 the fresh-report rule, end to end: observation does not end on
// elapsed time, nor on a report generated one second before
// observe_until + 4 h; refresh_activity queues a connector scan through the
// scan queue (trigger refresh_activity), whose report -- generated exactly
// at observe_until + 4 h -- arrives as ordinary evidence of the next
// revision, and that revision's observe_tick ends observation.
//
// Mutation-checked: the evaluator's observe_tick hook; the fresh-report
// boundary (observe_until + reporting_lag).
func TestP3T315ObservationFreshReportRule(t *testing.T) {
	l := newP3rLab(t, "p3-t315-fresh", true)
	l.role("FreshRole", "AROAFRESHROLE01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare("AROAFRESHROLE01")

	v := l.must2(l.start(l.author, policy))
	if p3rStage(v) != models.GovRolloutObserve {
		t.Fatalf("start: %v", v)
	}
	var until, after time.Time
	if err := l.db.Raw(`SELECT observe_until FROM iga_gov_rollout WHERE workspace_id = ?`, l.ws).Row().Scan(&until); err != nil {
		t.Fatal(err)
	}
	if err := l.db.Raw(`SELECT observe_evidence_required_after FROM iga_gov_rollout WHERE workspace_id = ?`, l.ws).Row().Scan(&after); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(until); d < 6*24*time.Hour || d > 8*24*time.Hour || !after.Equal(until.Add(4*time.Hour)) {
		t.Fatalf("observe_until %s (in %s), required_after %s", until, d, after)
	}
	if l.events(services.GovEventRolloutObservationStarted) != 1 || l.waitAudits("rollout_start", 1) != 1 {
		t.Fatalf("start events %d audits %d", l.events(services.GovEventRolloutObservationStarted), l.audits("rollout_start"))
	}
	// Starting again while observing is refused.
	if code, body := l.start(l.author, policy); code != http.StatusConflict || p3eErr(body) != services.GovCodeObservationIncomplete {
		t.Fatalf("second start: %d %v", code, body)
	}

	// observe_until passes; a report one second short of +4 h is not fresh.
	p3exec(t, l.db, `UPDATE iga_gov_rollout SET observe_until = now() - interval '10 hours',
		observe_evidence_required_after = now() - interval '6 hours' WHERE workspace_id = ?`, l.ws)
	if err := l.db.Raw(`SELECT observe_evidence_required_after FROM iga_gov_rollout WHERE workspace_id = ?`, l.ws).Row().Scan(&after); err != nil {
		t.Fatal(err)
	}
	after = after.UTC()
	l.activity(l.a).completed = after.Add(-time.Second)
	rev := l.publish()
	_ = rev
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'observe_tick' AND dedupe_key LIKE 'rollout:%:rev:%'`, l.ws); n != 1 {
		t.Fatalf("observe_tick jobs after a publication: %d, want 1 (the evaluator's hook)", n)
	}
	l.drain()
	v = l.rollout(policy)
	if p3rStage(v) != models.GovRolloutObserve {
		t.Fatalf("report 1 s before observe_until + 4 h ended observation: %v", v["rollout"])
	}
	if aw := dig(v, "results", "observation", "result", "awaiting_report"); fmt.Sprint(aw) != "[AROAFRESHROLE01]" ||
		dig(v, "results", "observation", "result", "needs_refresh") != true {
		t.Fatalf("observation %v", dig(v, "results", "observation"))
	}

	// refresh_activity: the scheduler's job queues a scan of the connector.
	if _, err := l.worker.Scheduler().RunSchedulesNow(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	l.drain()
	var trig []string
	l.db.Raw(`SELECT trigger FROM cloud_scan_run WHERE workspace_id = ? AND status = 'queued'`, l.ws).Scan(&trig)
	if len(trig) != 1 || trig[0] != services.RolloutScanTrigger {
		t.Fatalf("queued scans %v, want one refresh_activity scan", trig)
	}
	if l.events(services.GovEventRolloutRefreshQueued) != 1 {
		t.Fatal("no refresh event")
	}
	// The refresh scan runs through the normal pipeline; its report is
	// generated exactly at observe_until + 4 h.
	l.activity(l.a).completed = after
	scanSeq++
	w := services.NewAWSScanWorker(l.db, l.a.svc).WithOwner(fmt.Sprintf("p3r-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithScannerHook(l.hook(l.a))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("refresh scan: %v %v", worked, err)
	}
	var runIDs []uuid.UUID
	l.db.Raw(`SELECT id FROM cloud_scan_run WHERE workspace_id = ? AND trigger = ? AND status = 'published'`, l.ws, services.RolloutScanTrigger).Scan(&runIDs)
	if len(runIDs) != 1 {
		t.Fatal("the refresh scan did not publish")
	}
	runID := runIDs[0]
	p3eCompleteCoverage(t, l.p3eLab, l.a, runID)
	l.projectOnly()
	l.drain()
	if v = l.rollout(policy); p3rStage(v) != models.GovRolloutAwaitingApproval {
		t.Fatalf("report at observe_until + 4 h: stage %s, want awaiting_approval", p3rStage(v))
	}
	if l.events(services.GovEventRolloutObservationCompleted) != 1 {
		t.Fatal("no observation_completed event")
	}
	// The refresh job sees its scan published and completes.
	p3exec(t, l.db, `UPDATE iga_gov_job SET run_after = now() - interval '1 minute' WHERE workspace_id = ? AND kind = 'refresh_activity'`, l.ws)
	l.drain()
	var st []string
	l.db.Raw(`SELECT status FROM iga_gov_job WHERE workspace_id = ? AND kind = 'refresh_activity'`, l.ws).Scan(&st)
	if len(st) != 1 || st[0] != "complete" {
		t.Fatalf("refresh job %v", st)
	}
}

// A6 (observation half): a removed service attempted during observation
// sends the version back to draft -- approval revoked, review cancelled --
// and the rollout pauses naming the attempt; resume refuses; the notice is
// queued.
//
// Mutation-checked: the back-to-draft branch.
func TestP3T315AttemptDuringObservationBackToDraft(t *testing.T) {
	l := newP3rLab(t, "p3-t315-draft", true)
	arn := l.role("DraftRole", "AROADRAFTROLE01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare("AROADRAFTROLE01")
	l.must2(l.start(l.author, policy))
	l.approveAll(policy, 1) // approved while observing: the attempt revokes it

	attempt := time.Now().Add(-30 * time.Minute).UTC()
	l.activity(l.a).set(arn, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": &attempt})
	l.activity(l.a).completed = time.Now().Add(-10 * time.Minute)
	l.publish()
	l.drain()

	if s := l.status(policy, 1); s != "draft" {
		t.Fatalf("version %s, want draft", s)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ? AND revoked_at IS NULL AND decision = 'approve'`, l.ws); n != 0 {
		t.Fatalf("%d live approvals after the attempt", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_owner_review WHERE workspace_id = ? AND status = 'cancelled'`, l.ws); n != 1 {
		t.Fatal("the review was not cancelled")
	}
	v := l.rollout(policy)
	want := "sqs was attempted during observation on " + attempt.Format("2006-01-02")
	if p3rStage(v) != models.GovRolloutPaused || l.pauseKind(v) != services.GovPauseReturnedToDraft ||
		digs(v, "results", "pause", "reason") != want {
		t.Fatalf("rollout %v %v", v["rollout"], dig(v, "results", "pause"))
	}
	if l.events(services.GovEventRolloutReturnedToDraft) != 1 || l.events(services.GovEventRolloutPaused) != 1 {
		t.Fatal("missing events")
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_notification WHERE workspace_id = ? AND subject_kind = 'canary_gate'`, l.ws); n < 1 {
		t.Fatal("no rollout notice queued")
	}
	code, body := l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/resume", map[string]any{"reason": "x"})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeVersionConflict {
		t.Fatalf("resume after draft: %d %v", code, body)
	}
}

// A6 (canary half), A24, A28: every authorization denial in the canary
// window that no declared expected=denied item explains fails
// no_unexpected_failures and pauses the rollout with Undo canary offered:
// a retained service (A6); a removed service nobody expected to be called,
// even boundary-attributed (A24); another session of the role making the
// declared call, and the test session denied on an undeclared action (A28
// a, b). An event of a recreated role (another RoleId) with the test
// session's name is not the role's traffic (A28 c), and the declared call
// itself is exempt; then the single-target canary completes.
//
// Mutation-checked: a failed gate pauses.
func TestP3T315CanaryGateFailurePausesWithUndo(t *testing.T) {
	l := newP3rLab(t, "p3-t315-gates", true)
	const rid = "AROAGATEROLE001"
	l.role("GateRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	dep := l.toCanary(policy)
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'deploy' AND dedupe_key = ?`, l.ws, "deployment:"+dep.String()); n != 1 {
		t.Fatal("no deploy job for the canary")
	}
	var d models.IGAGovDeployment
	l.db.Where("id = ?", dep).Take(&d)
	if d.State != models.GovDeployQueued || d.ApprovalID == nil || d.RevalidationID == nil || d.Kind != "apply" {
		t.Fatalf("canary deployment %+v (want queued, the approval, the unchanged revalidation)", d)
	}
	at := l.applied(dep, models.GovDeployAppliedUnverified, 50*time.Hour)

	type step struct {
		name   string
		extra  []igagov.TrailEvent
		reason string
	}
	val := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_validation (id, workspace_id, deployment_id, created_by, role_id, correlation, session_name, window_start, window_end)
		VALUES (?, ?, ?, ?, ?, 'assumed_session', 'authsec-validate-p3r', ?, ?)`, val, l.ws, dep, l.author.user, rid, at.Add(2*time.Hour), at.Add(3*time.Hour))
	p3exec(t, l.db, `INSERT INTO iga_gov_validation_item (workspace_id, validation_id, action, expected) VALUES (?, ?, 'sqs:ListQueues', 'denied')`, l.ws, val)
	declared := p3rDenied(rid, "authsec-validate-p3r", "sqs", "ListQueues", at.Add(150*time.Minute), igagov.DenialPermissionsBoundary)
	for _, s := range []step{
		{"A6 retained service denied", []igagov.TrailEvent{p3rDenied(rid, "lambda", "s3", "GetObject", at.Add(5*time.Hour), "identity_policy")}, igagov.DeniedRetainedService},
		{"A24 removed service, unexpected", []igagov.TrailEvent{p3rDenied(rid, "lambda", "sqs", "SendMessage", at.Add(5*time.Hour), igagov.DenialPermissionsBoundary)}, igagov.DeniedRemovedService},
		{"A28a another session makes the declared call", []igagov.TrailEvent{declared, p3rDenied(rid, "lambda", "sqs", "ListQueues", at.Add(150*time.Minute), igagov.DenialPermissionsBoundary)}, igagov.DeniedRemovedService},
		{"A28b the test session denied an undeclared action", []igagov.TrailEvent{declared, p3rDenied(rid, "authsec-validate-p3r", "s3", "ListAllMyBuckets", at.Add(150*time.Minute), "identity_policy")}, igagov.DeniedRetainedService},
	} {
		evs, reads := p3rClean(rid, at, "s3")
		l.trail.set(dep, append(evs, s.extra...), reads)
		l.tick()
		v := l.rollout(policy)
		if p3rStage(v) != models.GovRolloutPaused || l.pauseKind(v) != services.GovPauseGateFailed {
			t.Fatalf("%s: rollout %v pause %v canary %v", s.name, v["rollout"], dig(v, "results", "pause"), dig(v, "results", "canary"))
		}
		if !strings.Contains(digs(v, "results", "pause", "reason"), "no_unexpected_failures ("+s.reason+")") {
			t.Fatalf("%s: pause reason %q", s.name, digs(v, "results", "pause", "reason"))
		}
		if digs(v, "results", "undo_offered", 0, "deployment_id") != dep.String() || !strings.Contains(fmt.Sprint(v["actions"]), "undo_canary") {
			t.Fatalf("%s: undo not offered: %v %v", s.name, dig(v, "results", "undo_offered"), v["actions"])
		}
		if s.reason == igagov.DeniedRemovedService && s.name[:3] == "A24" &&
			digs(v, "results", "canary", "restriction", "outcome") != igagov.OutcomePassed {
			// D42: the boundary acts (restriction) and the gate fails, side by side.
			t.Fatalf("A24 restriction %v", dig(v, "results", "canary", "restriction"))
		}
		l.resume(policy)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_notification WHERE workspace_id = ? AND subject_kind = 'canary_gate'`, l.ws); n < 1 {
		t.Fatal("no canary_gate notice")
	}
	// A28c: the recreated role's event is not this role's traffic; the
	// declared call is exempt. Every gate passes: single target -> complete.
	evs, reads := p3rClean(rid, at, "s3")
	l.trail.set(dep, append(evs, declared, p3rDenied("AROARECREATED01", "authsec-validate-p3r", "sqs", "ListQueues", at.Add(150*time.Minute), "unknown")), reads)
	l.tick()
	v := l.rollout(policy)
	if p3rStage(v) != models.GovRolloutComplete {
		t.Fatalf("clean canary: %v %v", v["rollout"], dig(v, "results", "canary", "gates"))
	}
	if l.events(services.GovEventRolloutPaused) != 4 || l.events(services.GovEventRolloutResumed) != 4 || l.events(services.GovEventRolloutCompleted) != 1 ||
		l.waitAudits("rollout_resume", 4) != 4 {
		t.Fatalf("events paused=%d resumed=%d completed=%d", l.events(services.GovEventRolloutPaused), l.events(services.GovEventRolloutResumed),
			l.events(services.GovEventRolloutCompleted))
	}
}

// A18 / A62: a canary with no CloudTrail coverage and no success evidence
// keeps its trail gates not_available: the tick does not move it; expand
// is 409 gates_not_passed naming them; the author cannot accept them; a
// gate that is not unavailable cannot be accepted; the approver accepts
// each by name, one gate_not_available row per gate bound to the rollout,
// stage canary and the canary window; then the single target completes.
//
// Mutation-checked: an unavailable gate needs an acceptance.
func TestP3T315UnavailableGatesNeedAcceptance(t *testing.T) {
	l := newP3rLab(t, "p3-t315-na", true)
	const rid = "AROANOTRAFFIC01"
	l.role("QuietRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	dep := l.toCanary(policy)
	at := l.applied(dep, models.GovDeployVerified, 50*time.Hour)
	l.tick()
	v := l.rollout(policy)
	na := fmt.Sprint(dig(v, "results", "canary", "not_available"))
	if p3rStage(v) != models.GovRolloutCanary || na != "[no_unexpected_failures required_operations window_elapsed]" {
		t.Fatalf("no traffic: stage %s not_available %s", p3rStage(v), na)
	}
	path := "/policies/" + policy + "/rollout/expand"
	code, body := l.call(l.author, http.MethodPost, path, map[string]any{})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeGatesNotPassed {
		t.Fatalf("expand without acceptance: %d %v", code, body)
	}
	accept := map[string]any{"accept_not_available": []map[string]any{
		{"gate": "no_unexpected_failures", "reason": "the account has no trail in us-east-1 yet"},
		{"gate": "required_operations", "reason": "the job runs monthly"},
		{"gate": "window_elapsed", "reason": "trail coverage missing"},
	}}
	if code, body = l.call(l.author, http.MethodPost, path, accept); code != http.StatusForbidden || p3eErr(body) != services.GovCodeSelfApproval {
		t.Fatalf("author accepts: %d %v", code, body)
	}
	bad := map[string]any{"accept_not_available": []map[string]any{{"gate": "no_problem_reports", "reason": "x"}}}
	if code, body = l.call(l.approver, http.MethodPost, path, bad); code != http.StatusBadRequest {
		t.Fatalf("accepting a passed gate: %d %v", code, body)
	}
	partial := map[string]any{"accept_not_available": accept["accept_not_available"].([]map[string]any)[:2]}
	if code, body = l.call(l.approver, http.MethodPost, path, partial); code != http.StatusConflict || p3eErr(body) != services.GovCodeGatesNotPassed {
		t.Fatalf("two of three accepted: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ? AND kind = 'gate_not_available'`, l.ws); n != 0 {
		t.Fatalf("%d acceptances after refusals", n)
	}
	v = l.must2(l.call(l.approver, http.MethodPost, path, accept))
	if p3rStage(v) != models.GovRolloutComplete || len(v["acceptances"].([]any)) != 3 {
		t.Fatalf("expand with acceptances: %v", v)
	}
	var accs []models.IGAGovAcceptance
	l.db.Where("workspace_id = ? AND kind = 'gate_not_available'", l.ws).Order("item_key").Find(&accs)
	ro := uuid.MustParse(digs(v, "rollout", "id"))
	for _, a := range accs {
		if a.RolloutID == nil || *a.RolloutID != ro || a.Stage == nil || *a.Stage != "canary" || a.AcceptedBy != l.approver.user ||
			a.WindowStart == nil || a.WindowStart.Sub(at).Abs() > time.Millisecond || a.WindowEnd == nil ||
			a.WindowEnd.Sub(*a.WindowStart) != 48*time.Hour || !strings.HasPrefix(a.ItemHash, "sha256:") || a.Reason == "" {
			t.Fatalf("acceptance %+v (applied %s)", a, at)
		}
	}
	if l.events(services.GovEventRolloutGateAccepted) != 3 || l.waitAudits("rollout_expand", 1) != 1 {
		t.Fatalf("events %d audits %d", l.events(services.GovEventRolloutGateAccepted), l.audits("rollout_expand"))
	}
}

// A10: a shared role (two workloads) may be the canary only when every
// consumer's owner acknowledged; an exception lets the owner gate pass but
// does not count.
//
// Mutation-checked: the acknowledgement rule.
func TestP3T315CanaryChoiceSharedRole(t *testing.T) {
	l := newP3rLab(t, "p3-t315-shared", true)
	const rid = "AROASHAREDROLE1"
	arn := l.role("SharedRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	p3eAddLambda(l.a, "us-east-1", "shared-batch", arn)
	l.publish()
	u1, u2 := l.member("owner-one", "read"), l.member("owner-two", "read")
	l.owner(models.GovObjectWorkload, l.workloadID("sharedrole-fn"), u1.user)
	l.owner(models.GovObjectWorkload, l.workloadID("shared-batch"), u2.user)
	policy, _ := l.proposeTemplate(rid)
	l.compile(policy, 1)
	svc := services.NewIGAGovOwnerReviewService(l.db)
	ctx := context.Background()
	s, err := svc.OpenReview(ctx, l.ws, l.versionID(policy, 1), l.author.user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Respond(ctx, l.ws, u1.user, s.ReviewID, p3Ack([]string{"sqs"})); err != nil {
		t.Fatal(err)
	}
	// Owner two is silent: the gate refuses observation.
	if code, body := l.start(l.author, policy); code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("start with a silent owner: %d %v", code, body)
	}
	if _, _, err := svc.Except(ctx, l.ws, l.approver.user, s.ReviewID, "owner two is travelling"); err != nil {
		t.Fatal(err)
	}
	l.observed(policy)
	l.approveAll(policy, 1)
	code, body := l.start(l.author, policy)
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeCanaryNotAcknowledged ||
		fmt.Sprint(dig(body, "error", "detail", "missing_user_ids")) != "["+u2.user.String()+"]" {
		t.Fatalf("canary with one acknowledgement: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d deployments after the refusal", n)
	}
	// Owner two acknowledges (the review reopened for them).
	p3exec(t, l.db, `UPDATE iga_gov_owner_review SET status = 'open', exception_by = NULL, exception_reason = '', closed_at = NULL WHERE id = ?`, s.ReviewID)
	if _, err := svc.Respond(ctx, l.ws, u2.user, s.ReviewID, p3Ack([]string{"sqs"})); err != nil {
		t.Fatal(err)
	}
	if v := l.must2(l.start(l.author, policy)); p3rStage(v) != models.GovRolloutCanary {
		t.Fatalf("canary with both acknowledgements: %v", v)
	}
}

// A16 / A49 (rollout side): three roles; the canary passes and the rollout
// expands automatically; one target is refused at creation (another change
// in flight on its role), one deployment fails, the canary verifies: the
// rollout ends partial. Then cross-workspace reads and mutations are 404.
//
// Mutation-checked: refused and failed targets make the rollout partial.
func TestP3T315PartialRollout(t *testing.T) {
	l := newP3rLab(t, "p3-t315-partial", true)
	ids := []string{"AROAPARTIAL0001", "AROAPARTIAL0002", "AROAPARTIAL0003"}
	// Role names of distinct lengths: the lab's fake IAM derives policy ids
	// from the policy ARN's length and last character, so equal lengths
	// collide. One more retained service each, to tell them apart.
	extra := []string{"dynamodb", "sns", "kinesis"}
	names := []string{"AxRole", "BravoRole", "CharlieRole"}
	for i, r := range ids {
		l.role(names[i], r, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, extra[i]: p3eTime(time.Hour)})
	}
	l.publish()
	policy := l.prepare(ids...)
	dep := l.toCanary(policy)
	var canaryRole string
	l.db.Raw(`SELECT c.role_id FROM iga_gov_deployment d JOIN iga_gov_control c ON c.id = d.control_id WHERE d.id = ?`, dep).Scan(&canaryRole)
	// Another change in flight on the third role (not the canary).
	var other struct {
		PlanID, ControlID, ApprovalID uuid.UUID
		RoleID                        string
	}
	l.db.Raw(`SELECT p.id AS plan_id, p.control_id, a.id AS approval_id, c.role_id FROM iga_gov_plan p
		JOIN iga_gov_control c ON c.id = p.control_id
		JOIN iga_gov_approval a ON a.version_id = p.version_id AND a.revoked_at IS NULL
		WHERE p.workspace_id = ? AND p.kind = 'apply' AND p.superseded_at IS NULL AND c.role_id <> ? ORDER BY c.role_id DESC LIMIT 1`,
		l.ws, canaryRole).Scan(&other)
	blocker := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, 'apply', 'direct', 'queued')`, blocker, l.ws, l.versionID(policy, 1), other.PlanID, other.ControlID, other.ApprovalID)

	at := l.applied(dep, models.GovDeployAppliedUnverified, 50*time.Hour)
	evs, reads := p3rClean(canaryRole, at, append([]string{"s3"}, extra...)...)
	l.trail.set(dep, evs, reads)
	l.tick()
	v := l.rollout(policy)
	if p3rStage(v) != models.GovRolloutExpand {
		t.Fatalf("after the canary: %v %v", v["rollout"], dig(v, "results", "canary"))
	}
	refused := dig(v, "results", "expansion", "refused").([]any)
	created := dig(v, "results", "expansion", "deployments").([]any)
	if len(refused) != 1 || digs(refused[0], "code") != services.GovCodeDeploymentInFlight || digs(refused[0], "role_id") != other.RoleID || len(created) != 1 {
		t.Fatalf("expansion %v", dig(v, "results", "expansion"))
	}
	second := uuid.MustParse(created[0].(string))
	// Nothing is final while a deployment is in progress.
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'verified', verified_at = now() WHERE id = ?`, dep)
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'failed', state_reason = 'binding_partial' WHERE id = ?`, blocker)
	l.tick()
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutExpand {
		t.Fatalf("with a deployment queued: %s", st)
	}
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'failed', state_reason = 'binding_partial' WHERE id = ?`, second)
	l.tick()
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutPartial {
		t.Fatalf("one verified, one failed, one refused: %s, want partial", st)
	}
	if l.events(services.GovEventRolloutPartial) != 1 || l.events(services.GovEventRolloutDeploymentRefused) != 1 ||
		l.events(services.GovEventRolloutDeploymentCreated) != 2 {
		t.Fatal("missing partial events")
	}

	// Another workspace's id is 404, for reads and mutations.
	o := p3NewGov(t, l.db, "p3-t315-other")
	tok := l.token(o.ws, p3aMember{user: o.author, membership: o.authorMember}, p3aAllScopes)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/policies/" + policy + "/rollout"},
		{http.MethodPost, "/policies/" + policy + "/rollout/start"},
		{http.MethodPost, "/policies/" + policy + "/rollout/pause"},
		{http.MethodPost, "/policies/" + policy + "/rollout/resume"},
		{http.MethodPost, "/policies/" + policy + "/rollout/expand"},
	} {
		code, body := l.callAs(tok, c.method, c.path, map[string]any{"reason": "x"})
		if code != http.StatusNotFound {
			t.Fatalf("%s %s from another workspace: %d %v", c.method, c.path, code, body)
		}
	}
}

// Journey setup: findings_only refuses a direct rollout
// (enforcement_not_enabled); without a verified binding the canary is
// refused (binding_not_verified, binding_partial) and no deployment is
// written; pause and resume are audited; expand outside canary is 409.
//
// Mutation-checked: findings_only refusal; the binding gate.
func TestP3T315JourneySetupRefusals(t *testing.T) {
	l := newP3rLab(t, "p3-t315-setup", false)
	l.role("SetupRole", "AROASETUPROLE01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare("AROASETUPROLE01")
	code, body := l.start(l.author, policy)
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeEnforcementNotEnabled {
		t.Fatalf("findings_only: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_rollout WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatal("a rollout was written in findings_only")
	}
	p3exec(t, l.db, `INSERT INTO iga_gov_settings (workspace_id, enforcement_mode) VALUES (?, 'enforce')`, l.ws)
	l.must2(l.start(l.author, policy))
	if code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/expand", map[string]any{}); code != http.StatusConflict ||
		p3eErr(body) != services.GovCodeRolloutConflict {
		t.Fatalf("expand while observing: %d %v", code, body)
	}
	if code, _ = l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/pause", map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("pause without a reason: %d", code)
	}
	v := l.must2(l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/pause", map[string]any{"reason": "change freeze"}))
	if p3rStage(v) != models.GovRolloutPaused || l.pauseKind(v) != services.GovPauseManual || digs(v, "results", "pause", "from") != "observe" {
		t.Fatalf("pause: %v", v)
	}
	l.resume(policy)
	if l.waitAudits("rollout_pause", 1) != 1 || l.waitAudits("rollout_resume", 1) != 1 || l.events(services.GovEventRolloutPaused) != 1 {
		t.Fatal("pause/resume not audited")
	}
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutObserve {
		t.Fatalf("resumed to %s", st)
	}
	p3exec(t, l.db, `UPDATE iga_gov_rollout SET observe_until = now() - interval '10 hours',
		observe_evidence_required_after = now() - interval '6 hours' WHERE workspace_id = ?`, l.ws)
	l.activity(l.a).completed = time.Now().Add(-time.Hour)
	l.publish()
	l.drain()
	l.approveAll(policy, 1)
	if code, body = l.start(l.author, policy); code != http.StatusConflict || p3eErr(body) != services.EnfCodeNotVerified {
		t.Fatalf("no binding: %d %v", code, body)
	}
	l.bind("partial")
	if code, body = l.start(l.author, policy); code != http.StatusConflict || p3eErr(body) != services.EnfCodePartial {
		t.Fatalf("partial binding: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d deployments without a verified binding", n)
	}
	l.bind("verified")
	if v := l.must2(l.start(l.author, policy)); p3rStage(v) != models.GovRolloutCanary {
		t.Fatalf("verified binding: %v", v)
	}
}
