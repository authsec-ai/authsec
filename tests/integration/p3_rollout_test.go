package integration

// T3.15 rollout (SPEC-iga-phase3-policy.md §2.6, §7.5, §8.4, §8.6; L-12;
// A6, A10, A16/A49 rollout side, A18, A24, A28, A62) against real
// PostgreSQL, on the REAL path end to end: the P3 lab (REAL scan worker,
// projection and evaluation with the observe_tick hook), the production
// /api/iga/v1 routes, and one job worker running the rollout's jobs AND the
// deployment jobs (T3.16's deploy, verify, drift_check) over an enforcetest
// fake AWS account that mirrors the lab's roles. The rollout reads the
// PRODUCTION deployment facts (InstallGovRolloutWiring: DeploymentGateFacts
// from the verify job's rows). CloudTrail events reach the verify job the
// way the scanner writes them: the scan worker's CloudTrail reader answers
// from a fake trail, attributes each event by its session issuer (T3.04)
// and stores cloud_observation rows and the cloudtrail-events coverage.
// After a deployment, the boundary the deploy job wrote to the fake account
// is mirrored into the scan account's IAM, so the next scan's graph shows
// it (the graph dimension). Time: the deploy, verify and rollout services
// and the scan worker share a lab clock that the test moves forward; the
// job worker runs on real time, and kick() makes every queued job of the
// workspace due. Prefixed p3r.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

/* --------------------------------- harness -------------------------------- */

// p3rCloudTrail is the scan account's CloudTrail: LookupEvents answers the
// events set (or err: the read fails, so the scan has no trail coverage).
type p3rCloudTrail struct {
	mu     sync.Mutex
	events []cttypes.Event
	err    error
}

func (f *p3rCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &cloudtrail.LookupEventsOutput{Events: append([]cttypes.Event(nil), f.events...)}, nil
}

func (f *p3rCloudTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (f *p3rCloudTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
}

func (f *p3rCloudTrail) add(evs ...cttypes.Event) {
	f.mu.Lock()
	f.events = append(f.events, evs...)
	f.mu.Unlock()
}

// p3rAWS is the deployment jobs' AWS access (services.IGAGovAWS) over the
// enforcetest fake account: its discovery reads and the enforcement role
// (every write authorised by the enforcement template's policy).
type p3rAWS struct{ f *enforcetest.FakeAWS }

func (a p3rAWS) DiscoveryIAM(context.Context, uuid.UUID, uuid.UUID) (awsenforce.DiscoveryIAM, error) {
	return a.f.Discovery(), nil
}

func (a p3rAWS) EnforcementIAM(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (awsenforce.IAM, error) {
	return a.f, nil
}

type p3rLab struct {
	*p3aLab
	worker *services.PolicyJobWorker
	fake   *enforcetest.FakeAWS
	reader *services.GovAWSLiveReader
	dep    *services.GovDeployments
	ro     *services.GovRollout
	trail  *p3rCloudTrail
	names  map[string]string // role id -> name

	mu     sync.Mutex
	offset time.Duration
}

func newP3rLab(t *testing.T, name string, enforce bool) *p3rLab {
	t.Helper()
	return p3rOn(t, newP3aLab(t, name), name, enforce)
}

// p3rOn adds the rollout plumbing to an existing T3.11 lab (e.g. the IaC
// lab's, so one workspace has both).
func p3rOn(t *testing.T, a *p3aLab, name string, enforce bool) *p3rLab {
	t.Helper()
	l := &p3rLab{p3aLab: a, trail: &p3rCloudTrail{}, names: map[string]string{}}
	l.a.cloudTrail = l.trail
	f, err := enforcetest.NewFakeAWSFromTemplate(awsdiscovery.EnforcementCloudFormationTemplate, accountA, "p3r", "ext-p3r")
	if err != nil {
		t.Fatal(err)
	}
	l.fake = f
	acc := p3rAWS{f: f}
	// The production live reader over the fake account: what the compiler,
	// the revalidation and the deploy job read is what the executor changes.
	l.reader = services.NewGovAWSLiveReader(acc)
	gin.SetMode(gin.TestMode)
	l.eng = gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey).WithPolicyGate(l.policy).WithGovLiveReader(l.reader)
	routes.SetupIGARoutes(l.eng, platform.NewIGAController(l.db), ctl)

	env := services.GovDeployEnv{AWS: acc,
		Binding: func(context.Context, uuid.UUID, uuid.UUID) error { return nil }}
	l.dep = services.NewGovDeployments(l.db, &env).WithAuthoring(services.NewGovAuthoring(l.db, l.reader)).
		WithClock(l.now).WithSleep(noSleep)
	l.dep.Executor = func(e *services.IGAGovAWSExecutor) { e.WithSleep(noSleep) }
	l.ro = services.NewGovRollout(l.db, l.reader).WithClock(l.now)
	// The production deployment facts (T3.16's DeploymentGateFacts).
	t.Cleanup(services.InstallGovRolloutWiring(l.db))
	if enforce {
		p3exec(t, l.db, `INSERT INTO iga_gov_settings (workspace_id, enforcement_mode, canary_hours) VALUES (?, 'enforce', 1)`, l.ws)
		l.bind("verified")
	}
	l.worker = services.NewPolicyJobWorker(l.db, "p3r-"+name).WithGate(func() bool { return true })
	services.RegisterRolloutJobs(l.worker, l.ro)
	l.dep.Register(l.worker)
	return l
}

func (l *p3rLab) now() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().Add(l.offset)
}

// advance moves the lab clock (deploy, verify, rollout, scans) forward.
func (l *p3rLab) advance(d time.Duration) {
	l.mu.Lock()
	l.offset += d
	l.mu.Unlock()
}

// role adds the role to the scan account (p3aLab.role) and the same role --
// same name, path, RoleId and permissions policy -- to the fake account the
// deployment jobs change.
func (l *p3rLab) role(name, roleID string, report map[string]*time.Time) string {
	l.t.Helper()
	arn := l.p3aLab.role(name, roleID, report)
	var svcs []string
	for s := range report {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	r := l.fake.AddRole(name, "/", nil)
	r.RoleID = roleID
	l.fake.AddPolicy("/", name+"Work", nil, p3aDoc(svcs...))
	l.fake.AttachPermissions(name, l.fake.PolicyARN("/", name+"Work"))
	l.names[roleID] = name
	return arn
}

// mirror copies the boundary the deploy job attached in the fake account
// into the scan account's IAM, so the next scan reads it.
func (l *p3rLab) mirror(roleID string) {
	l.t.Helper()
	name := l.names[roleID]
	arn := l.fake.BoundaryOf(name)
	if arn == "" {
		l.t.Fatalf("%s has no boundary in the fake account", name)
	}
	_, def, doc, _, ok := l.fake.PolicyState(arn)
	if !ok {
		l.t.Fatalf("boundary %s not in the fake account", arn)
	}
	l.a.iam.managedPolicies[arn] = doc
	if l.a.iam.policyVersions == nil {
		l.a.iam.policyVersions = map[string]string{}
	}
	l.a.iam.policyVersions[arn] = def
	s3aEditRole(l.t, l.a, name, func(r *iamtypes.Role) { r.PermissionsBoundary = s3aBoundary(arn) })
}

// scan runs one scan of the account through the REAL worker on the lab
// clock (its run starts at l.now()), gives it complete resource-policy
// coverage and projects it with the evaluation step.
func (l *p3rLab) scan() uuid.UUID {
	l.t.Helper()
	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, l.a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, l.a.svc).WithOwner(fmt.Sprintf("p3r-scan-%d", scanSeq)).
		WithGraphProjection(l.gate).WithScannerHook(l.hook(l.a)).WithClock(l.now)
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("scan run %s: %s %s %v", queued.ID, run.Status, run.LastError, err)
	}
	p3eCompleteCoverage(l.t, l.p3eLab, l.a, run.ID)
	l.projectOnly()
	return run.ID
}

// bind records the account's enforcement binding in state.
func (l *p3rLab) bind(state string) {
	l.t.Helper()
	p3exec(l.t, l.db, `DELETE FROM cloud_enforcement_binding WHERE workspace_id = ?`, l.ws)
	p3exec(l.t, l.db, `INSERT INTO cloud_enforcement_binding (workspace_id, connector_id, account_id, role_arn, state, consented_by, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, now())`, l.ws, l.a.conn, accountA, "arn:aws:iam::"+accountA+":role/AuthSecEnforcement-p3r", state, l.author.user)
}

// kick makes every queued job of the workspace due now (the worker runs on
// real time; the services on the lab clock).
func (l *p3rLab) kick() {
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET run_after = now() - interval '1 second'
		WHERE workspace_id = ? AND status = 'queued' AND run_after > now() - interval '1 second'`, l.ws)
}

// drain kicks and runs the worker's claimable jobs until none is left (a job
// handed back is due again only at its next kick).
func (l *p3rLab) drain() {
	l.t.Helper()
	l.kick()
	for i := 0; i < 100; i++ {
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

// tick enqueues a periodic observe_tick for the rollouts and drains.
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
	l.except(policy, 1)
	return policy
}

func (l *p3rLab) except(policy string, no int) {
	l.t.Helper()
	svc := services.NewIGAGovOwnerReviewService(l.db)
	s, err := svc.OpenReview(context.Background(), l.ws, l.versionID(policy, no), l.author.user)
	if err != nil {
		l.t.Fatal(err)
	}
	if _, _, err := svc.Except(context.Background(), l.ws, l.approver.user, s.ReviewID, "the lab's roles have no owners"); err != nil {
		l.t.Fatal(err)
	}
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

// observed starts observation of each policy, moves observe_until into the
// past and publishes a fresh report so the evaluator's observe_tick
// completes it.
func (l *p3rLab) observed(policies ...string) {
	l.t.Helper()
	for _, p := range policies {
		l.must2(l.start(l.author, p))
	}
	p3exec(l.t, l.db, `UPDATE iga_gov_rollout SET observe_until = now() - interval '10 hours',
		observe_evidence_required_after = now() - interval '6 hours' WHERE workspace_id = ? AND stage = 'observe'`, l.ws)
	l.activity(l.a).completed = time.Now().Add(-time.Hour)
	l.publish()
	l.drain()
	for _, p := range policies {
		if st := p3rStage(l.rollout(p)); st != models.GovRolloutAwaitingApproval {
			l.t.Fatalf("after a fresh report: stage %s, want awaiting_approval", st)
		}
	}
}

func (l *p3rLab) must2(code int, body map[string]any) map[string]any {
	l.t.Helper()
	return l.must(code, body, http.StatusOK, "rollout call")
}

// toCanary approves an observed policy and starts its canary; it returns
// the canary deployment (queued, its deploy job enqueued).
func (l *p3rLab) toCanary(policy string, no int) uuid.UUID {
	l.t.Helper()
	l.approveAll(policy, no)
	v := l.must2(l.start(l.author, policy))
	if p3rStage(v) != models.GovRolloutCanary {
		l.t.Fatalf("start after approval: %v", v)
	}
	return uuid.MustParse(digs(v, "results", "canary", "deployment_id"))
}

func (l *p3rLab) deployment(id uuid.UUID) models.IGAGovDeployment {
	l.t.Helper()
	var d models.IGAGovDeployment
	if err := l.db.First(&d, "id = ?", id).Error; err != nil {
		l.t.Fatal(err)
	}
	return d
}

// applied drains (the REAL deploy job applies the change to the fake
// account, the verify job starts) and returns the deployment's applied_at.
func (l *p3rLab) applied(deps ...uuid.UUID) time.Time {
	l.t.Helper()
	l.drain()
	var at time.Time
	for _, dep := range deps {
		d := l.deployment(dep)
		if d.State != models.GovDeployAppliedUnverified || d.AppliedAt == nil {
			l.t.Fatalf("deployment %s after the deploy job: %s (%s)", dep, d.State, d.StateReason)
		}
		at = d.AppliedAt.UTC()
	}
	return at
}

// gateOf is a gate's outcome in the deployment's last verify run.
func (l *p3rLab) gateOf(dep uuid.UUID, gate string) string {
	l.t.Helper()
	gf, err := l.dep.DeploymentGateFacts(context.Background(), l.ws, dep)
	if err != nil {
		l.t.Fatal(err)
	}
	for _, g := range gf.Gates {
		if g.Gate == gate {
			return g.Outcome
		}
	}
	return ""
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

// jobStatus is the status of the deployment's job of kind.
func (l *p3rLab) jobStatus(kind string, dep uuid.UUID) string {
	var st []string
	l.db.Raw(`SELECT status FROM iga_gov_job WHERE workspace_id = ? AND kind = ? AND subject_id = ? ORDER BY created_at DESC LIMIT 1`,
		l.ws, kind, dep).Scan(&st)
	if len(st) == 0 {
		return ""
	}
	return st[0]
}

/* ------------------------------ CloudTrail -------------------------------- */

var p3rEventSeq int

// p3rEvent is one CloudTrail management event of a session of the role
// (sessionContext.sessionIssuer = the role's ARN and RoleId), as LookupEvents
// returns it. denial "" is a success; otherwise the errorMessage names the
// denying policy type ("permissions boundary", "identity-based policy").
func p3rEvent(roleARN, roleID, session, svc, name string, at time.Time, denial string) cttypes.Event {
	p3rEventSeq++
	rec := map[string]any{"userIdentity": map[string]any{
		"type": "AssumedRole", "principalId": roleID + ":" + session,
		"arn": "arn:aws:sts::" + accountA + ":assumed-role/" + lastSegment(roleARN) + "/" + session, "accountId": accountA,
		"sessionContext": map[string]any{"sessionIssuer": map[string]any{
			"type": "Role", "principalId": roleID, "arn": roleARN, "accountId": accountA}},
	}}
	if denial != "" {
		rec["errorCode"] = "AccessDenied"
		rec["errorMessage"] = "User: arn:aws:sts::" + accountA + ":assumed-role/x/" + session + " is not authorized to perform: " +
			svc + ":" + name + " because no " + denial + " allows the " + svc + ":" + name + " action"
	}
	raw, _ := json.Marshal(rec)
	return cttypes.Event{EventId: aws.String(fmt.Sprintf("p3r-evt-%d", p3rEventSeq)), EventName: aws.String(name),
		EventSource: aws.String(svc + ".amazonaws.com"), Username: aws.String(session), EventTime: aws.Time(at),
		CloudTrailEvent: aws.String(string(raw))}
}

const (
	p3rBoundary = "permissions boundary"
	p3rIdentity = "identity-based policy"
)

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
	l.publish()
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
	p3eCompleteCoverage(t, l.p3eLab, l.a, runIDs[0])
	l.projectOnly()
	l.drain()
	if v = l.rollout(policy); p3rStage(v) != models.GovRolloutAwaitingApproval {
		t.Fatalf("report at observe_until + 4 h: stage %s, want awaiting_approval", p3rStage(v))
	}
	if l.events(services.GovEventRolloutObservationCompleted) != 1 {
		t.Fatal("no observation_completed event")
	}
	// The refresh job sees its scan published and completes.
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

// A6 (canary half), A24, A28 on the real path: five single-target policies,
// each canary APPLIED BY THE DEPLOY JOB to the fake account and verified by
// the VERIFY JOB from CloudTrail events the SCANNER stored. Every
// authorization denial in the canary window that no declared expected=denied
// item explains fails no_unexpected_failures and pauses the rollout with
// Undo canary offered: a retained service (A6); a removed service nobody
// expected to be called, even boundary-attributed (A24: restriction observed
// beside the failed gate); another session of the role making the declared
// call (A28a); the test session denied on an undeclared action (A28b). An
// event of a recreated role (another RoleId) with the test session's name is
// not this role's traffic (A28c: the scanner does not attribute it), and the
// declared call itself is exempt. A manual expand of a paused-then-resumed
// canary whose gate still fails is refused. The clean canary's gates pass
// while its deployment is applied_unverified (the graph has not seen the
// boundary yet): it is NOT complete until the verify job proves it; then it
// completes.
//
// Mutation-checked: a failed gate pauses; single-target completion needs
// verified.
func TestP3T315CanaryGateFailurePausesWithUndo(t *testing.T) {
	l := newP3rLab(t, "p3-t315-gates", true)
	type sc struct {
		name, rid, role, arn, policy, reason string
		dep                                  uuid.UUID
		session                              string
	}
	scs := []*sc{
		// Role names of distinct lengths: the scan fake derives policy ids
		// from the policy ARN's length and last character.
		{name: "A6 retained service denied", rid: "AROAGATEA6ROLE1", role: "G6", reason: igagov.DeniedRetainedService},
		{name: "A24 removed service, unexpected", rid: "AROAGATEA24ROL1", role: "G24x", reason: igagov.DeniedRemovedService},
		{name: "A28a another session makes the declared call", rid: "AROAGATEA28AROL", role: "G28aaa", reason: igagov.DeniedRemovedService},
		{name: "A28b the test session denied an undeclared action", rid: "AROAGATEA28BROL", role: "G28bbbbb", reason: igagov.DeniedRetainedService},
		{name: "A28c clean", rid: "AROAGATECLEAN01", role: "GCleanRole"},
	}
	for _, s := range scs {
		s.arn = l.role(s.role, s.rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	}
	l.publish()
	var policies []string
	for _, s := range scs {
		s.policy = l.prepare(s.rid)
		policies = append(policies, s.policy)
	}
	l.observed(policies...)
	for _, s := range scs {
		s.dep = l.toCanary(s.policy, 1)
		var d models.IGAGovDeployment
		l.db.Where("id = ?", s.dep).Take(&d)
		if d.State != models.GovDeployQueued || d.ApprovalID == nil || d.Kind != "apply" {
			t.Fatalf("%s: canary deployment %+v (want queued, the approval)", s.name, d)
		}
	}
	at := l.applied(scs[0].dep, scs[1].dep, scs[2].dep, scs[3].dep, scs[4].dep)
	for _, s := range scs {
		if l.fake.BoundaryOf(s.role) == "" {
			t.Fatalf("%s: the deploy job attached no boundary in the fake account", s.name)
		}
	}
	// A28: the test sessions are declared before they run.
	for _, s := range scs[2:4] {
		vv, err := l.dep.DeclareValidation(context.Background(), l.ws, l.author.user, s.dep, services.GovValidationRequest{
			Items:       []services.GovValidationItemInput{{Action: "sqs:ListQueues", Expected: igagov.ExpectDenied}},
			Correlation: "assumed_session", WindowStart: at.Add(10 * time.Minute), WindowEnd: at.Add(40 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		s.session = vv.SessionName
	}
	in := func(d time.Duration) time.Time { return at.Add(d) }
	// Ordinary traffic: every role's workload succeeds on s3 (required_operations).
	for _, s := range scs {
		l.trail.add(p3rEvent(s.arn, s.rid, "workload", "s3", "ListBuckets", in(5*time.Minute), ""))
	}
	l.trail.add(
		p3rEvent(scs[0].arn, scs[0].rid, "lambda", "s3", "GetObject", in(20*time.Minute), p3rIdentity),
		p3rEvent(scs[1].arn, scs[1].rid, "lambda", "sqs", "SendMessage", in(20*time.Minute), p3rBoundary),
		p3rEvent(scs[2].arn, scs[2].rid, scs[2].session, "sqs", "ListQueues", in(20*time.Minute), p3rBoundary),
		p3rEvent(scs[2].arn, scs[2].rid, "lambda", "sqs", "ListQueues", in(21*time.Minute), p3rBoundary),
		p3rEvent(scs[3].arn, scs[3].rid, scs[3].session, "sqs", "ListQueues", in(20*time.Minute), p3rBoundary),
		p3rEvent(scs[3].arn, scs[3].rid, scs[3].session, "s3", "ListBuckets", in(21*time.Minute), p3rIdentity),
		// A28c: the clean role's ARN, another incarnation, the clean
		// canary's... session name: not this role.
		p3rEvent(scs[4].arn, "AROARECREATED01", "authsec-validate-recreated", "sqs", "ListQueues", in(20*time.Minute), "unknown policy"),
	)
	// The canary window (1 h, the settings') ends; a scan started after it
	// reads the trail. The graph does not show the boundaries yet.
	l.advance(2 * time.Hour)
	l.scan()
	l.drain()
	l.tick()
	for _, s := range scs[:4] {
		v := l.rollout(s.policy)
		if p3rStage(v) != models.GovRolloutPaused || l.pauseKind(v) != services.GovPauseGateFailed {
			t.Fatalf("%s: rollout %v pause %v canary %v", s.name, v["rollout"], dig(v, "results", "pause"), dig(v, "results", "canary"))
		}
		if !strings.Contains(digs(v, "results", "pause", "reason"), "no_unexpected_failures ("+s.reason+")") {
			t.Fatalf("%s: pause reason %q", s.name, digs(v, "results", "pause", "reason"))
		}
		if digs(v, "results", "undo_offered", 0, "deployment_id") != s.dep.String() || !strings.Contains(fmt.Sprint(v["actions"]), "undo_canary") {
			t.Fatalf("%s: undo not offered: %v %v", s.name, dig(v, "results", "undo_offered"), v["actions"])
		}
	}
	// A24: the boundary acts (restriction, boundary-attributed) AND the gate fails.
	if v := l.rollout(scs[1].policy); digs(v, "results", "canary", "restriction", "outcome") != igagov.OutcomePassed {
		t.Fatalf("A24 restriction %v", dig(v, "results", "canary", "restriction"))
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_notification WHERE workspace_id = ? AND subject_kind = 'canary_gate'`, l.ws); n < 1 {
		t.Fatal("no canary_gate notice")
	}
	// Resumed, the failing gate still refuses a manual expand (the same
	// canary-health rule as the tick).
	l.resume(scs[0].policy)
	code, body := l.call(l.approver, http.MethodPost, "/policies/"+scs[0].policy+"/rollout/expand", map[string]any{"reason": "push on"})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeGatesNotPassed {
		t.Fatalf("expand with a failing gate: %d %v", code, body)
	}

	// The clean canary: every gate passed, but its deployment is applied,
	// not verified (the graph has not shown the boundary): not complete.
	clean := scs[4]
	if st := l.deployment(clean.dep).State; st != models.GovDeployAppliedUnverified {
		t.Fatalf("clean canary %s, want applied_unverified (graph not yet agreeing)", st)
	}
	v := l.rollout(clean.policy)
	if p3rStage(v) != models.GovRolloutCanary || dig(v, "results", "canary", "pass") != true {
		t.Fatalf("clean canary, gates passed, unverified: %v %v", v["rollout"], dig(v, "results", "canary", "gates"))
	}
	// The boundary reaches the graph: verified, then complete.
	l.mirror(clean.rid)
	l.advance(10 * time.Minute)
	l.scan()
	l.drain()
	if st := l.deployment(clean.dep).State; st != models.GovDeployVerified {
		t.Fatalf("clean canary after the graph agrees: %s", st)
	}
	l.tick()
	if v = l.rollout(clean.policy); p3rStage(v) != models.GovRolloutComplete {
		t.Fatalf("verified clean canary: %v %v", v["rollout"], dig(v, "results", "canary", "gates"))
	}
	// 4 gate failures, and the resumed A6 canary paused again by the next
	// tick (its gate still fails, R9).
	if l.events(services.GovEventRolloutPaused) != 5 || l.events(services.GovEventRolloutCompleted) != 1 {
		t.Fatalf("events paused=%d completed=%d", l.events(services.GovEventRolloutPaused), l.events(services.GovEventRolloutCompleted))
	}
}

// A18 / A62: a canary whose account's CloudTrail cannot be read (the scan's
// trail read is refused: no coverage) and with no success evidence keeps its
// trail gates not_available after the window: the tick does not move it;
// expand is 409 gates_not_passed naming them; the author cannot accept
// them; a gate that is not unavailable cannot be accepted; an acceptance of
// the same gate for ANOTHER window of the rollout does not count; the
// approver accepts each by name, one gate_not_available row per gate bound
// to the rollout and its version, stage canary and the canary window; then
// the single (verified) target completes. The schema refuses a second
// acceptance of a gate for the same window and an acceptance naming another
// version than its rollout's (057).
//
// Mutation-checked: an unavailable gate needs an acceptance; acceptances
// match the whole window.
func TestP3T315UnavailableGatesNeedAcceptance(t *testing.T) {
	l := newP3rLab(t, "p3-t315-na", true)
	const rid = "AROANOTRAFFIC01"
	l.role("QuietRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	l.observed(policy)
	dep := l.toCanary(policy, 1)
	at := l.applied(dep)
	l.mirror(rid)
	l.trail.err = enforcetest.APIError("AccessDenied", "cloudtrail:LookupEvents denied")
	l.advance(2 * time.Hour)
	l.scan()
	l.drain()
	if st := l.deployment(dep).State; st != models.GovDeployVerified {
		t.Fatalf("canary %s, want verified", st)
	}
	l.tick()
	v := l.rollout(policy)
	na := fmt.Sprint(dig(v, "results", "canary", "not_available"))
	if p3rStage(v) != models.GovRolloutCanary || na != "[no_unexpected_failures required_operations window_elapsed]" {
		t.Fatalf("no trail: stage %s not_available %s gates %v", p3rStage(v), na, dig(v, "results", "canary", "gates"))
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
	// window_elapsed accepted for another window of this rollout (same start,
	// another end): it is not this window's acceptance.
	ro := uuid.MustParse(digs(v, "rollout", "id"))
	vid := l.versionID(policy, 1)
	p3exec(t, l.db, `INSERT INTO iga_gov_acceptance (workspace_id, kind, item_key, item_hash, version_id, rollout_id, stage, window_start,
		window_end, reason, accepted_by) VALUES (?, 'gate_not_available', 'window_elapsed', 'sha256:other', ?, ?, 'canary', ?, ?, 'an earlier window', ?)`,
		l.ws, vid, ro, at, at.Add(48*time.Hour), l.approver.user)
	partial := map[string]any{"accept_not_available": accept["accept_not_available"].([]map[string]any)[:2]}
	if code, body = l.call(l.approver, http.MethodPost, path, partial); code != http.StatusConflict || p3eErr(body) != services.GovCodeGatesNotPassed ||
		!strings.Contains(fmt.Sprint(dig(body, "error", "detail", "gates")), "window_elapsed") {
		t.Fatalf("two of three accepted (+ another window's): %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ? AND kind = 'gate_not_available'`, l.ws); n != 1 {
		t.Fatalf("%d acceptances after refusals, want only the other window's", n)
	}
	v = l.must2(l.call(l.approver, http.MethodPost, path, accept))
	if p3rStage(v) != models.GovRolloutComplete || len(v["acceptances"].([]any)) != 4 {
		t.Fatalf("expand with acceptances: %v", v)
	}
	var accs []models.IGAGovAcceptance
	l.db.Where("workspace_id = ? AND kind = 'gate_not_available' AND reason <> 'an earlier window'", l.ws).Order("item_key").Find(&accs)
	if len(accs) != 3 {
		t.Fatalf("%d acceptances of this window", len(accs))
	}
	for _, a := range accs {
		if a.RolloutID == nil || *a.RolloutID != ro || a.VersionID != vid || a.Stage == nil || *a.Stage != "canary" || a.AcceptedBy != l.approver.user ||
			a.WindowStart == nil || a.WindowStart.Sub(at).Abs() > time.Millisecond || a.WindowEnd == nil ||
			a.WindowEnd.Sub(*a.WindowStart) != time.Hour || !strings.HasPrefix(a.ItemHash, "sha256:") || a.Reason == "" {
			t.Fatalf("acceptance %+v (applied %s)", a, at)
		}
	}
	if l.events(services.GovEventRolloutGateAccepted) != 3 || l.waitAudits("rollout_expand", 1) != 1 {
		t.Fatalf("events %d audits %d", l.events(services.GovEventRolloutGateAccepted), l.audits("rollout_expand"))
	}
	// 057: one row per (rollout, gate, window); the version is the rollout's.
	a := accs[0]
	if err := l.db.Exec(`INSERT INTO iga_gov_acceptance (workspace_id, kind, item_key, item_hash, version_id, rollout_id, stage, window_start,
		window_end, reason, accepted_by) VALUES (?, 'gate_not_available', ?, 'sha256:dup', ?, ?, 'canary', ?, ?, 'twice', ?)`,
		l.ws, a.ItemKey, vid, ro, *a.WindowStart, *a.WindowEnd, l.approver.user).Error; err == nil || !strings.Contains(err.Error(), "uq_iga_gov_acceptance_gate") {
		t.Fatalf("a second acceptance of %s for the same window: %v", a.ItemKey, err)
	}
	// A second version of the policy, to name.
	v2 := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, status, created_by)
		VALUES (?, ?, ?, 2, '{"kind":"right_size_services"}'::jsonb, 'sha256:p3r-v2', 1, ?, 'draft', ?)`, v2, l.ws, policy, l.latestRev(), l.author.user)
	otherVersion := []uuid.UUID{v2}
	if err := l.db.Exec(`INSERT INTO iga_gov_acceptance (workspace_id, kind, item_key, item_hash, version_id, rollout_id, stage, window_start,
		window_end, reason, accepted_by) VALUES (?, 'gate_not_available', 'window_elapsed', 'sha256:x', ?, ?, 'canary', ?, ?, 'other version', ?)`,
		l.ws, otherVersion[0], ro, at.Add(time.Minute), at.Add(2*time.Hour), l.approver.user).Error; err == nil ||
		!strings.Contains(err.Error(), "iga_gov_acceptance_rollout_version_fkey") {
		t.Fatalf("an acceptance naming another version than its rollout's: %v", err)
	}
}

// Review P1-9: a pause holds queued deployments. The canary's deployment is
// queued with its deploy job when the rollout is paused: the REAL deploy job
// leaves it queued (nothing is written to AWS) and hands itself back, for
// as long as the rollout is paused; resume brings the job forward and the
// deployment applies. An undo of the version is not held.
//
// Mutation-checked: the deploy job's rollout-pause check.
func TestP3T315PauseHoldsQueuedDeployments(t *testing.T) {
	l := newP3rLab(t, "p3-t315-hold", true)
	const rid = "AROAHOLDROLE001"
	l.role("HoldRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	l.observed(policy)
	dep := l.toCanary(policy, 1)
	l.must2(l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/pause", map[string]any{"reason": "change freeze"}))
	for i := 0; i < 2; i++ {
		l.drain()
		if d := l.deployment(dep); d.State != models.GovDeployQueued || d.AppliedAt != nil {
			t.Fatalf("pass %d: a paused rollout's deployment is %s", i, d.State)
		}
		if st := l.jobStatus("deploy", dep); st != "queued" {
			t.Fatalf("pass %d: deploy job %s, want handed back (queued)", i, st)
		}
	}
	if b := l.fake.BoundaryOf("HoldRole"); b != "" || l.fake.Count("iam:CreatePolicy") != 0 {
		t.Fatalf("AWS changed while paused: boundary %q, CreatePolicy x%d", b, l.fake.Count("iam:CreatePolicy"))
	}
	var due time.Time
	l.db.Raw(`SELECT run_after FROM iga_gov_job WHERE workspace_id = ? AND kind = 'deploy' AND subject_id = ?`, l.ws, dep).Row().Scan(&due)
	if !due.After(time.Now()) {
		t.Fatalf("held deploy job due at %s, want later", due)
	}
	l.resume(policy)
	l.db.Raw(`SELECT run_after FROM iga_gov_job WHERE workspace_id = ? AND kind = 'deploy' AND subject_id = ?`, l.ws, dep).Row().Scan(&due)
	if due.After(time.Now()) {
		t.Fatalf("resume left the deploy job due at %s", due)
	}
	ok, err := l.worker.RunOnce(context.Background()) // no kick: resume made it due
	if err != nil || !ok {
		t.Fatalf("worker after resume: %v %v", ok, err)
	}
	l.drain()
	if d := l.deployment(dep); d.State != models.GovDeployAppliedUnverified || l.fake.BoundaryOf("HoldRole") == "" {
		t.Fatalf("after resume: %s (%s), boundary %q", d.State, d.StateReason, l.fake.BoundaryOf("HoldRole"))
	}
	if paused, err := services.RolloutPausedForDeployment(l.db, l.ws, dep); err != nil || paused {
		t.Fatalf("paused for a resumed rollout: %v %v", paused, err)
	}
}

// Review P1-9: the manual expand runs the canary-health check the automatic
// path runs. Two roles; the canary is verified by the jobs with its trail
// gates not_available (the trail cannot be read), so it waits for an
// approver. Then the canary DRIFTS (the boundary is detached in the account;
// the REAL drift_check job records it). Its last verify run's gates still
// read passed / not_available, but the canary is not healthy: the expand,
// with every unavailable gate accepted, is refused, and nothing is accepted
// or deployed.
//
// Mutation-checked: the expand's canary-health check.
func TestP3T315ManualExpandRunsTheCanaryHealthCheck(t *testing.T) {
	l := newP3rLab(t, "p3-t315-expand", true)
	ids := []string{"AROAEXPANDROLE1", "AROAEXPANDROLE2"}
	names := []string{"ExpandOne", "ExpandTwoRole"}
	for i, r := range ids {
		l.role(names[i], r, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	}
	l.publish()
	policy := l.prepare(ids...)
	l.observed(policy)
	dep := l.toCanary(policy, 1)
	l.applied(dep)
	l.mirror(ids[0])
	l.trail.err = enforcetest.APIError("AccessDenied", "cloudtrail:LookupEvents denied")
	l.advance(2 * time.Hour)
	l.scan()
	l.drain()
	l.tick()
	if st := l.deployment(dep).State; st != models.GovDeployVerified {
		t.Fatalf("canary %s", st)
	}
	if v := l.rollout(policy); p3rStage(v) != models.GovRolloutCanary {
		t.Fatalf("canary with unavailable gates: %v", v["rollout"])
	}
	// The canary drifts: detached in AWS, recorded by the drift job.
	if err := l.fake.DeleteRolePermissionsBoundary(context.Background(), names[0]); err != nil {
		t.Fatal(err)
	}
	p3exec(t, l.db, `INSERT INTO iga_gov_job (workspace_id, kind, subject_id, dedupe_key) VALUES (?, 'drift_check', ?, ?)`,
		l.ws, dep, "deployment:"+dep.String())
	l.drain()
	if st := l.deployment(dep).State; st != models.GovDeployDrifted {
		t.Fatalf("after the drift check: %s", st)
	}
	if l.gateOf(dep, igagov.GateArtifactVerified) != igagov.OutcomePassed {
		t.Fatal("the last verify run's artifact gate should still read passed")
	}
	if v := l.rollout(policy); p3rStage(v) != models.GovRolloutCanary {
		t.Fatalf("stage %s before the expand", p3rStage(v))
	}
	accept := map[string]any{"reason": "push on", "accept_not_available": []map[string]any{
		{"gate": "no_unexpected_failures", "reason": "no trail"}, {"gate": "required_operations", "reason": "monthly"},
		{"gate": "window_elapsed", "reason": "no trail"}}}
	code, body := l.call(l.approver, http.MethodPost, "/policies/"+policy+"/rollout/expand", accept)
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeGatesNotPassed || digs(body, "error", "detail", "state") != models.GovDeployDrifted {
		t.Fatalf("expand from a drifted canary: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ? AND kind = 'gate_not_available'`, l.ws); n != 0 {
		t.Fatalf("%d gate acceptances after the refusal", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ? AND id <> ?`, l.ws, dep); n != 0 {
		t.Fatalf("%d deployments created from a drifted canary", n)
	}
}

// Review P1-9: one canary length. The version's intent sets
// rollout.canary_hours = 2 while the workspace setting is 1: the rollout's
// window AND the verify job's window are 2 h. 90 minutes after the change
// (a scan covering it), window_elapsed is still awaiting in the verify
// job's gates; after 3 h it passes.
//
// Mutation-checked: the verify job's canary length.
func TestP3T315CanaryLengthIsTheVersions(t *testing.T) {
	l := newP3rLab(t, "p3-t315-length", true)
	const rid = "AROALENGTHROLE1"
	arn := l.role("LengthRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy, _ := l.proposeTemplate(rid)
	var raw json.RawMessage
	l.db.Raw(`SELECT intent FROM iga_gov_policy_version WHERE id = ?`, l.versionID(policy, 1)).Row().Scan(&raw)
	var intent map[string]any
	if err := json.Unmarshal(raw, &intent); err != nil {
		t.Fatal(err)
	}
	intent["rollout"] = map[string]any{"canary_hours": 2}
	code, body := l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions", map[string]any{"intent": intent, "base_version_no": 1})
	l.must(code, body, http.StatusCreated, "POST versions")
	l.compile(policy, 2)
	l.except(policy, 2)
	l.observed(policy)
	dep := l.toCanary(policy, 2)
	at := l.applied(dep)
	if h, err := services.GovCanaryHours(l.db, l.ws, l.versionID(policy, 2)); err != nil || h != 2 {
		t.Fatalf("GovCanaryHours %d %v", h, err)
	}
	l.mirror(rid)
	l.trail.add(p3rEvent(arn, rid, "workload", "s3", "ListBuckets", at.Add(5*time.Minute), ""))
	l.advance(90 * time.Minute)
	l.scan()
	l.drain()
	if st := l.deployment(dep).State; st != models.GovDeployVerified {
		t.Fatalf("canary %s", st)
	}
	if g := l.gateOf(dep, igagov.GateWindowElapsed); g != igagov.OutcomeAwaitingEvidence {
		t.Fatalf("window_elapsed 90 min into a 2 h canary: %q (the verify job used another length)", g)
	}
	l.tick()
	v := l.rollout(policy)
	we, _ := time.Parse(time.RFC3339Nano, digs(v, "results", "canary", "window_end"))
	if p3rStage(v) != models.GovRolloutCanary || we.Sub(at.Add(2*time.Hour)).Abs() > time.Millisecond {
		t.Fatalf("rollout window end %s (applied %s), stage %s", we, at, p3rStage(v))
	}
	l.advance(90 * time.Minute)
	l.scan()
	l.drain()
	if g := l.gateOf(dep, igagov.GateWindowElapsed); g != igagov.OutcomePassed {
		t.Fatalf("window_elapsed after 3 h: %q", g)
	}
	l.tick()
	if v = l.rollout(policy); p3rStage(v) != models.GovRolloutComplete {
		t.Fatalf("after the 2 h window: %v %v", v["rollout"], dig(v, "results", "canary", "gates"))
	}
}

// Review P1-9: the verify job does not stop at the window's end before a
// CloudTrail read covering the window has arrived. The canary is verified
// within its window; at the window's end the last scan started before it,
// so window_elapsed reads not_available (a coverage gap at the end) -- the
// verify job keeps re-checking instead of finishing; the next scan covers
// the window and window_elapsed passes; then the job finishes. The rollout
// sees the passed gate and completes.
//
// Mutation-checked: the verify job's stop rule.
func TestP3T315VerifyKeepsCheckingUntilTheWindowIsCovered(t *testing.T) {
	l := newP3rLab(t, "p3-t315-window", true)
	const rid = "AROAWINDOWROLE1"
	arn := l.role("WindowRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	l.observed(policy)
	dep := l.toCanary(policy, 1)
	at := l.applied(dep)
	l.mirror(rid)
	l.trail.add(p3rEvent(arn, rid, "workload", "s3", "ListBuckets", at.Add(5*time.Minute), ""))
	l.advance(30 * time.Minute)
	l.scan() // started inside the window
	l.drain()
	if st := l.deployment(dep).State; st != models.GovDeployVerified {
		t.Fatalf("canary %s", st)
	}
	l.advance(40 * time.Minute) // past the 1 h window; no scan since
	l.drain()
	if g := l.gateOf(dep, igagov.GateWindowElapsed); g != igagov.OutcomeNotAvailable {
		t.Fatalf("window_elapsed at the window's end without a covering read: %q", g)
	}
	if st := l.jobStatus("verify", dep); st != "queued" {
		t.Fatalf("verify job %s at the window's end before a covering scan, want still re-checking", st)
	}
	l.advance(10 * time.Minute)
	l.scan() // started after the window's end: covers it
	l.drain()
	if g := l.gateOf(dep, igagov.GateWindowElapsed); g != igagov.OutcomePassed {
		t.Fatalf("window_elapsed after a covering scan: %q", g)
	}
	if st := l.jobStatus("verify", dep); st != "complete" {
		t.Fatalf("verify job %s once window_elapsed is decided", st)
	}
	l.tick()
	if v := l.rollout(policy); p3rStage(v) != models.GovRolloutComplete {
		t.Fatalf("rollout %v %v", v["rollout"], dig(v, "results", "canary", "gates"))
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

// Review P3: the default canary of a multi-target version skips a role
// whose current grants are administration-level (§8.6: it "cannot be the
// canary") at proposal time, instead of choosing it by RoleId order and
// failing at canary start; the canary then starts on the other role.
//
// Mutation-checked: the default canary's admin-level skip.
func TestP3T315DefaultCanarySkipsAdminRole(t *testing.T) {
	l := newP3rLab(t, "p3-t315-admin", true)
	// The admin role sorts first; role names of distinct lengths.
	ids := []string{"AROAADMINROLE01", "AROAPLAINROLE01"}
	l.role("AdminRoleX", ids[0], map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.role("PlainRole", ids[1], map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	adm := l.a.managed("AdminIAM", `{"Version":"2012-10-17","Statement":[{"Sid":"Admin","Effect":"Allow","Action":"iam:*","Resource":"*"}]}`)
	l.a.attach("AdminRoleX", adm)
	l.publish()
	policy := l.prepare(ids...)
	var canary []string
	l.db.Raw(`SELECT c.role_id FROM iga_gov_target t JOIN iga_gov_control c ON c.id = t.control_id
		WHERE t.workspace_id = ? AND t.version_id = ? AND t.is_canary`, l.ws, l.versionID(policy, 1)).Scan(&canary)
	if len(canary) != 1 || canary[0] != ids[1] {
		t.Fatalf("default canary %v, want %s (the admin-level role skipped)", canary, ids[1])
	}
	l.observed(policy)
	dep := l.toCanary(policy, 1)
	var role string
	l.db.Raw(`SELECT c.role_id FROM iga_gov_deployment d JOIN iga_gov_control c ON c.id = d.control_id WHERE d.id = ?`, dep).Scan(&role)
	if role != ids[1] {
		t.Fatalf("canary deployment on %s", role)
	}
}

// A16 / A49 (rollout side), real path: three roles; the canary is applied
// and verified by the jobs and its gates pass, so the rollout expands
// automatically; one target is refused at creation (another change in
// flight on its role); the account then refuses PutRolePermissionsBoundary
// (the binding made partial), so the other deployments FAIL in the deploy
// job: the rollout ends partial. Then cross-workspace reads and mutations
// are 404.
//
// Mutation-checked: refused and failed targets make the rollout partial.
func TestP3T315PartialRollout(t *testing.T) {
	l := newP3rLab(t, "p3-t315-partial", true)
	ids := []string{"AROAPARTIAL0001", "AROAPARTIAL0002", "AROAPARTIAL0003"}
	extra := []string{"dynamodb", "sns", "kinesis"}
	names := []string{"AxRole", "BravoRole", "CharlieRole"}
	arns := map[string]string{}
	for i, r := range ids {
		arns[r] = l.role(names[i], r, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, extra[i]: p3eTime(time.Hour)})
	}
	l.publish()
	policy := l.prepare(ids...)
	l.observed(policy)
	dep := l.toCanary(policy, 1)
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

	at := l.applied(dep)
	l.mirror(canaryRole)
	for _, s := range []string{"s3", "dynamodb", "sns", "kinesis"} {
		l.trail.add(p3rEvent(arns[canaryRole], canaryRole, "workload", s, "ListP3r", at.Add(5*time.Minute), ""))
	}
	// The binding becomes partial: the account refuses the attachment.
	l.fake.Fail["iam:PutRolePermissionsBoundary"] = enforcetest.APIError("AccessDenied", "not authorized to perform: iam:PutRolePermissionsBoundary")
	l.advance(2 * time.Hour)
	l.scan()
	l.drain()
	if st := l.deployment(dep).State; st != models.GovDeployVerified {
		t.Fatalf("canary %s", st)
	}
	// Back to the worker's time before the expansion's deploy jobs run: the
	// executor fences each AWS call against the job lease, which the worker
	// takes on real time.
	l.advance(-2 * time.Hour)
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
	l.drain()
	if d := l.deployment(second); d.State != models.GovDeployFailed {
		t.Fatalf("second deployment %s (%s), want failed (binding partial)", d.State, d.StateReason)
	}
	// Nothing is final while a deployment is in progress (the blocker).
	l.tick()
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutExpand {
		t.Fatalf("with a deployment queued: %s", st)
	}
	if err := l.db.Transaction(func(tx *gorm.DB) error { return services.EnqueueDeployTx(tx, l.ws, blocker) }); err != nil {
		t.Fatal(err)
	}
	l.drain()
	if d := l.deployment(blocker); d.State != models.GovDeployFailed {
		t.Fatalf("blocker %s (%s)", d.State, d.StateReason)
	}
	l.tick()
	if st := p3rStage(l.rollout(policy)); st != models.GovRolloutPartial {
		t.Fatalf("one verified, two failed, one refused: %s, want partial", st)
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

// An approved remove_control version is handed to the remove_control
// starter (no observation, no canary): refused while none is installed.
func TestP3T315RemoveControlStarter(t *testing.T) {
	l := newP3rLab(t, "p3-t315-remove", true)
	const rid = "AROAREMOVEROLE1"
	l.role("RemoveRole", rid, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy := l.prepare(rid)
	var control uuid.UUID
	l.db.Raw(`SELECT control_id FROM iga_gov_target WHERE version_id = ?`, l.versionID(policy, 1)).Scan(&control)
	p3exec(t, l.db, `UPDATE iga_gov_policy_version SET status = 'superseded' WHERE workspace_id = ?`, l.ws)
	v2 := uuid.New()
	intent := `{"kind":"remove_control","control_ids":["` + control.String() + `"],"reason":"hand back to the team"}`
	p3exec(t, l.db, `INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, status, created_by)
		VALUES (?, ?, ?, 2, ?::jsonb, 'sha256:p3r', 1, ?, 'approved', ?)`, v2, l.ws, policy, intent, l.latestRev(), l.author.user)
	restore := services.SetGovRemoveControlStarter(nil)
	code, body := l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/start", map[string]any{"version_no": 2})
	restore()
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeRemoveControlUnavailable {
		t.Fatalf("remove_control without a starter: %d %v", code, body)
	}
	var started []uuid.UUID
	t.Cleanup(services.SetGovRemoveControlStarter(func(_ context.Context, _ *gorm.DB, ws, actor, version uuid.UUID) error {
		if ws != l.ws || actor != l.author.user {
			return fmt.Errorf("unexpected caller %s %s", ws, actor)
		}
		started = append(started, version)
		return nil
	}))
	l.must2(l.call(l.author, http.MethodPost, "/policies/"+policy+"/rollout/start", map[string]any{"version_no": 2}))
	if len(started) != 1 || started[0] != v2 || l.events(services.GovEventRolloutRemoveControlStarted) != 1 {
		t.Fatalf("remove_control started %v", started)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_rollout WHERE workspace_id = ? AND version_id = ?`, l.ws, v2); n != 0 {
		t.Fatal("a remove_control version got a rollout row")
	}
}
