package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// dUnknownApply queues an apply whose PutRolePermissionsBoundary AWS
// applies but whose answer is lost (the client sees a reset): the attempt
// is unknown, the deployment outcome_unknown, resolve_unknown queued.
func dUnknownApply(t *testing.T, d *dLab, name string) (*x3Role, x3Stored, uuid.UUID) {
	t.Helper()
	x := d.role(name, "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	dep := d.queue(x, s, igagov.PlanApply)
	d.fake.AfterApply["iam:PutRolePermissionsBoundary"] = func(context.Context) error {
		delete(d.fake.AfterApply, "iam:PutRolePermissionsBoundary")
		return fmt.Errorf("connection reset by peer")
	}
	d.mustRun("deploy", dep)
	dd := d.deployment(dep)
	if dd.State != "outcome_unknown" || dd.SettleAfter == nil {
		t.Fatalf("after a lost answer: %s %v", dd.State, dd.SettleAfter)
	}
	var n int64
	d.db.Raw(`SELECT count(*) FROM iga_gov_job WHERE subject_id = ? AND kind = 'resolve_unknown' AND status = 'queued'`, dep).Scan(&n)
	if n != 1 {
		t.Fatal("resolve_unknown was not queued at settle_after")
	}
	return x, s, dep
}

// A58 (a)-(c), §8.1 steps 1-2: an unknown outcome holds the role
// (conflicting work 409 outcome_unknown_pending, nothing re-sent); after
// settle_after two readings 5 minutes apart, consistent with CloudTrail,
// resolve the attempt as applied; the deploy job then recognises the op
// and reaches applied_unverified with one PutRolePermissionsBoundary call.
//
// Safeguards (mutation-checked): the settle_after wait; the two-reading
// rule (a single reading never resolves).
func TestP3T316UnknownOutcomeResolvedA58(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x, _, dep := dUnknownApply(t, d, "A58Role")
	puts := d.fake.Count("iam:PutRolePermissionsBoundary")

	// (c) conflicting work is refused while unknown.
	if _, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{}, false); govCode(err) != services.GovCodeOutcomeUnknownPending {
		t.Fatalf("undo while unknown: %v", err)
	}
	if _, err := d.dep.Resolve(ctx, d.ws, d.approver, dep, services.GovResolveRequest{Action: "reread", Reason: "x"}); govCode(err) != services.GovCodeOutcomeUnknownPending {
		t.Fatalf("resolve before settle_after: %v", err)
	}
	if err := d.db.Exec(`INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		SELECT gen_random_uuid(), workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, 'queued' FROM iga_gov_deployment WHERE id = ?`, dep).Error; err == nil {
		t.Fatal("a second deployment started on a held role")
	}
	// Before settle_after: wait.
	if err := d.runJob("resolve_unknown", dep); !isRetryLater(err) {
		t.Fatalf("before settle: %v", err)
	}
	d.advance(16 * time.Minute)
	if err := d.runJob("resolve_unknown", dep); !isRetryLater(err) || d.state(dep) != "outcome_unknown" {
		t.Fatalf("first reading: %v %s", err, d.state(dep))
	}
	d.advance(2 * time.Minute)
	if err := d.runJob("resolve_unknown", dep); !isRetryLater(err) || d.state(dep) != "outcome_unknown" {
		t.Fatalf("a reading under 5 minutes later resolved it: %v %s", err, d.state(dep))
	}
	d.advance(5 * time.Minute)
	d.mustRun("resolve_unknown", dep)
	if st := d.state(dep); st != "applying" {
		t.Fatalf("after two consistent readings: %s %s", st, d.deployment(dep).StateReason)
	}
	d.mustRun("deploy", dep)
	if st := d.state(dep); st != "applied_unverified" || d.fake.Count("iam:PutRolePermissionsBoundary") != puts {
		t.Fatalf("resume: %s, puts %d -> %d (never re-sent)", st, puts, d.fake.Count("iam:PutRolePermissionsBoundary"))
	}
	_ = x
}

// A58 (d), (f), §8.1 steps 3-4: readings that disagree with CloudTrail
// leave the outcome unresolved (the role still held); re-read repeats step
// 2; "accept observed state" names an approved version, and its deployment
// takes over in ONE transaction: the unresolved deployment recovered naming
// its successor, the successor naming it back.
//
// Safeguard (mutation-checked): the handoff's single transaction (the
// in-flight index refuses the successor if the release is not first, and a
// release without a successor fails at commit).
func TestP3T316UnresolvedOperatorAndAtomicHandoffA58(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x, _, dep := dUnknownApply(t, d, "A58dRole")
	// CloudTrail says the call was refused; the readings say applied.
	d.fake.EditTrail(func(rs []enforcetest.TrailRecord) []enforcetest.TrailRecord {
		for i := range rs {
			if rs[i].EventName == "PutRolePermissionsBoundary" {
				rs[i].ErrorCode, rs[i].Response = "AccessDenied", nil
			}
		}
		return rs
	})
	d.advance(16 * time.Minute)
	_ = d.runJob("resolve_unknown", dep)
	d.advance(6 * time.Minute)
	d.mustRun("resolve_unknown", dep)
	if st := d.state(dep); st != "outcome_unresolved" {
		t.Fatalf("readings inconsistent with CloudTrail: %s", st)
	}
	// Re-read: back to outcome_unknown and two NEW readings.
	if _, err := d.dep.Resolve(ctx, d.ws, d.approver, dep, services.GovResolveRequest{Action: "reread", Reason: "check again"}); err != nil {
		t.Fatal(err)
	}
	if st := d.state(dep); st != "outcome_unknown" {
		t.Fatalf("after reread: %s", st)
	}
	if err := d.runJob("resolve_unknown", dep); !isRetryLater(err) {
		t.Fatalf("reread first reading: %v", err)
	}
	d.advance(6 * time.Minute)
	d.mustRun("resolve_unknown", dep)
	if st := d.state(dep); st != "outcome_unresolved" {
		t.Fatalf("still inconsistent: %s", st)
	}
	// Accept observed state: a version compiled from what AWS shows, approved.
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s2 := d.storeApproved(x, tp.Apply, *tp.Undo)
	var no int
	d.db.Raw(`SELECT version_no FROM iga_gov_policy_version WHERE id = ?`, s2.version).Scan(&no)
	if d.state(dep) != "outcome_unresolved" {
		t.Fatal("the role was released before the accepted plan's deployment took over")
	}
	out, err := d.dep.Resolve(ctx, d.ws, d.approver, dep, services.GovResolveRequest{Action: "accept_observed", Reason: "AWS shows it", VersionNo: &no})
	if err != nil {
		t.Fatalf("accept observed: %v", err)
	}
	succ := d.deployment(out.(models.IGAGovDeployment).ID)
	old := d.deployment(dep)
	if old.State != "recovered" || old.RecoveredByDeploymentID == nil || *old.RecoveredByDeploymentID != succ.ID ||
		succ.RecoversDeploymentID == nil || *succ.RecoversDeploymentID != dep || succ.State != "queued" {
		t.Fatalf("handoff: old %+v succ %+v", old, succ)
	}
	d.mustRun("deploy", succ.ID)
	if st := d.state(succ.ID); st != "applied_unverified" {
		t.Fatalf("successor: %s %s", st, d.deployment(succ.ID).StateReason)
	}
	// A release without a successor is refused at commit (051 deferred FK).
	err = d.db.Transaction(func(tx *gorm.DB) error {
		return tx.Exec(`UPDATE iga_gov_deployment SET state = 'recovered', recovered_by_deployment_id = gen_random_uuid() WHERE id = ?`, succ.ID).Error
	})
	if err == nil {
		t.Fatal("a release without a successor committed")
	}
}

// A50 (c): an evaluation-shaped transaction that holds the controls (the
// §8.2 order: controls, posture, findings) and an enforcement observer on
// one of those roles wait for each other instead of deadlocking, in both
// orders; an injected deadlock is retried at most 3 times and then fails
// the job.
//
// Safeguard (mutation-checked): the observer's lock order (control first).
func TestP3T316SharedLockOrderA50(t *testing.T) {
	d := newDLab(t)
	x := d.role("A50Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	d.finding(x, "sqs")
	d.fake.SetBoundary(x.name, "")

	evaluation := func(hold <-chan struct{}, locked chan<- struct{}) error {
		return d.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND state <> 'removed' ORDER BY account_id, role_id FOR UPDATE`, d.ws).Error; err != nil {
				return err
			}
			if locked != nil {
				close(locked)
			}
			if hold != nil {
				<-hold
			}
			if err := tx.Exec(`UPDATE iga_gov_service_posture SET assessed_at = now() WHERE workspace_id = ? AND role_id = ?`, d.ws, x.role.RoleID).Error; err != nil {
				return err
			}
			return tx.Exec(`UPDATE iga_gov_finding SET last_evaluated_at = now() WHERE workspace_id = ? AND role_id = ?`, d.ws, x.role.RoleID).Error
		})
	}

	t.Run("evaluation first", func(t *testing.T) {
		var retries int32
		d.dep.ObserverHook = func(stage string, _ uuid.UUID, _ *gorm.DB) error {
			if strings.HasPrefix(stage, "retry:") {
				atomic.AddInt32(&retries, 1)
			}
			return nil
		}
		defer func() { d.dep.ObserverHook = nil }()
		hold, locked := make(chan struct{}), make(chan struct{})
		evalErr := make(chan error, 1)
		go func() { evalErr <- evaluation(hold, locked) }()
		<-locked
		obsErr := make(chan error, 1)
		go func() { obsErr <- d.runJob("drift_check", dep) }()
		select {
		case err := <-obsErr:
			t.Fatalf("the observer did not wait for the control row: %v", err)
		case <-time.After(400 * time.Millisecond):
		}
		close(hold)
		if err := <-evalErr; err != nil {
			t.Fatalf("evaluation: %v", err)
		}
		if err := <-obsErr; err != nil && !isRetryLater(err) {
			t.Fatalf("observer: %v", err)
		}
		if d.state(dep) != "drifted" || d.posture(x)["sqs"] != "not_applied/not_removed" {
			t.Fatalf("after both: %s %v", d.state(dep), d.posture(x))
		}
		if n := atomic.LoadInt32(&retries); n != 0 {
			t.Fatalf("the observer hit %d deadlock / serialization failures: the shared lock order was not kept", n)
		}
	})

	t.Run("observer first", func(t *testing.T) {
		x2 := d.role("A50bRole", "/", nil)
		tp2 := d.compile(d.fake.Discovery(), x2, "sqs")
		dep2 := d.applyAndVerify(x2, d.storeApproved(x2, tp2.Apply, *tp2.Undo))
		d.fake.SetBoundary(x2.name, "")
		inCAS, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		d.dep.ObserverHook = func(stage string, _ uuid.UUID, _ *gorm.DB) error {
			if stage == "after_cas" {
				once.Do(func() { close(inCAS); <-release })
			}
			return nil
		}
		defer func() { d.dep.ObserverHook = nil }()
		obsErr := make(chan error, 1)
		go func() { obsErr <- d.runJob("drift_check", dep2) }()
		<-inCAS
		evalErr := make(chan error, 1)
		go func() { evalErr <- evaluation(nil, nil) }()
		select {
		case err := <-evalErr:
			t.Fatalf("the evaluation did not wait for the observer's control row: %v", err)
		case <-time.After(400 * time.Millisecond):
		}
		close(release)
		if err := <-obsErr; err != nil && !isRetryLater(err) {
			t.Fatalf("observer: %v", err)
		}
		if err := <-evalErr; err != nil {
			t.Fatalf("evaluation: %v", err)
		}
		if d.state(dep2) != "drifted" {
			t.Fatalf("observer result: %s", d.state(dep2))
		}
	})

	t.Run("injected deadlock is retried 3 times", func(t *testing.T) {
		x3 := d.role("A50cRole", "/", nil)
		tp3 := d.compile(d.fake.Discovery(), x3, "sqs")
		dep3 := d.applyAndVerify(x3, d.storeApproved(x3, tp3.Apply, *tp3.Undo))
		d.fake.SetBoundary(x3.name, "")
		var n int
		d.dep.ObserverHook = func(stage string, _ uuid.UUID, _ *gorm.DB) error {
			if stage == "after_cas" {
				n++
				return sqlStateErr("40P01")
			}
			return nil
		}
		err := d.runJob("drift_check", dep3)
		d.dep.ObserverHook = nil
		if err == nil || !strings.Contains(err.Error(), "after 3 attempts") || n != 3 || d.state(dep3) != "verified" {
			t.Fatalf("deadlock retries: %v, %d attempts, %s", err, n, d.state(dep3))
		}
		n = 0
		d.dep.ObserverHook = func(stage string, _ uuid.UUID, _ *gorm.DB) error {
			if stage == "after_cas" && n < 2 {
				n++
				return sqlStateErr("40001")
			}
			return nil
		}
		err = d.runJob("drift_check", dep3)
		d.dep.ObserverHook = nil
		if err != nil || d.state(dep3) != "drifted" {
			t.Fatalf("after two serialization failures: %v %s", err, d.state(dep3))
		}
	})
}

type sqlStateErr string

func (e sqlStateErr) Error() string    { return "injected " + string(e) }
func (e sqlStateErr) SQLState() string { return string(e) }

// A50 (b): a drift check that read AWS before an undo completed loses the
// control's compare-and-swap, re-reads, and finds the drifting deployment
// undone: it writes nothing of what it saw.
func TestP3T316StaleObserverLosesSwapA50b(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("A50bStale", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	_, seqBefore := d.controlState(x)
	fired := false
	d.dep.ObserverHook = func(stage string, _ uuid.UUID, _ *gorm.DB) error {
		if stage != "before_read" || fired {
			return nil
		}
		fired = true
		// Between the drift check's sequence read and its commit, an undo
		// runs to completion (its own observer moves the sequence).
		d.dep.ObserverHook = nil
		u, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{}, false)
		if err != nil {
			return err
		}
		d.mustRun("deploy", u.ID)
		d.publish(x, d.now().Add(time.Second), "", "")
		d.retirePolicy(*tp.Apply.DesiredBoundaryARN)
		d.mustRun("verify", u.ID)
		return nil
	}
	d.mustRun("drift_check", dep)
	_, seq := d.controlState(x)
	if d.state(dep) != "undone" || seq != seqBefore+1 {
		t.Fatalf("stale observer: dep %s, seq %d -> %d (only the undo's observation)", d.state(dep), seqBefore, seq)
	}
	if p := d.posture(x)["sqs"]; p != "not_applied/not_removed" {
		t.Fatalf("posture: %s", p)
	}
}

// A28 and §8.7 restriction: a declared validation correlates events by
// role incarnation, session, action and window; its expected denial
// (boundary-attributed) passes restriction (validation_request) and marks
// the posture restriction observed; the Lambda's own denial of the same
// call is an unexpected failure; a recreated role's event with the same
// session name matches nothing.
func TestP3T316ValidationsAndRestrictionA28(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("A28Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	if _, err := d.dep.DeclareValidation(ctx, d.ws, d.approver, dep, services.GovValidationRequest{Correlation: "assumed_session",
		Items: []services.GovValidationItemInput{{Action: "sqs:*", Expected: "denied"}}, WindowStart: d.now(), WindowEnd: d.now().Add(time.Hour)}); govCode(err) != services.GovCodeActionNotMappable {
		t.Fatalf("unmappable action: %v", err)
	}
	v, err := d.dep.DeclareValidation(ctx, d.ws, d.approver, dep, services.GovValidationRequest{Correlation: "assumed_session",
		Items:       []services.GovValidationItemInput{{Action: "sqs:ListQueues", Expected: "denied"}, {Action: "s3:ListAllMyBuckets", Expected: "allowed"}},
		WindowStart: d.now().Add(-time.Minute), WindowEnd: d.now().Add(time.Hour)})
	if err != nil || !strings.HasPrefix(v.SessionName, "authsec-validate-") || len(v.SessionName) != len("authsec-validate-")+12 || v.RoleID != x.role.RoleID {
		t.Fatalf("declare: %+v %v", v, err)
	}
	at := d.now()
	ev := func(n int, principal, session, source, name, code, denial string) {
		facts := fmt.Sprintf(`{"event_id":"e%d","event_name":%q,"event_source":%q,"session_name":%q,"session_issuer_principal_id":%q,"error_code":%q,"authorization_denied":%v,"denial_policy_type":%q}`,
			n, name, source, session, principal, code, code != "", denial)
		p3exec(t, d.db, `INSERT INTO cloud_observation (workspace_id, connector_id, scan_run_id, generation, source_api, observed_at, sanitized_facts, content_hash, subject_native_id)
			VALUES (?, ?, ?, 1, 'cloudtrail:LookupEvents', ?, ?::jsonb, ?, ?)`, d.ws, d.conn.ID, d.scanRun, at, facts, "h-"+uuid.NewString(), "evt")
	}
	ev(1, x.role.RoleID, v.SessionName, "sqs.amazonaws.com", "ListQueues", "AccessDenied", "permissions_boundary")
	ev(2, x.role.RoleID, v.SessionName, "s3.amazonaws.com", "ListBuckets", "", "")
	ev(3, x.role.RoleID, "lab-rightsize", "sqs.amazonaws.com", "ListQueues", "AccessDenied", "permissions_boundary")
	ev(4, "AROARECREATED", v.SessionName, "sqs.amazonaws.com", "ListQueues", "", "")
	d.mustRun("verify", dep)
	vs, err := d.dep.ListValidations(ctx, d.ws, dep)
	if err != nil || len(vs) != 1 || vs[0].Result != "matched" {
		t.Fatalf("validation: %+v %v", vs, err)
	}
	gf, _ := d.dep.DeploymentGateFacts(ctx, d.ws, dep)
	if r := gf.Dimensions["restriction"]; r.Outcome != "passed" || r.Attribution != "validation_request" {
		t.Fatalf("restriction: %+v", r)
	}
	nuf := ""
	for _, g := range gf.Gates {
		if g.Gate == igagov.GateNoUnexpectedFailures {
			nuf = g.Outcome
		}
	}
	if nuf != "failed" || len(gf.UnexpectedFailure) != 1 || gf.UnexpectedFailure[0].SessionName != "lab-rightsize" ||
		gf.Dimensions["application_health"].Outcome != "failed" {
		t.Fatalf("A28 unexpected failures: gate %s %+v health %s", nuf, gf.UnexpectedFailure, gf.Dimensions["application_health"].Outcome)
	}
	var restr string
	d.db.Raw(`SELECT restriction FROM iga_gov_service_posture WHERE role_id = ? AND service = 'sqs'`, x.role.RoleID).Scan(&restr)
	if restr != "observed" {
		t.Fatalf("posture restriction: %s", restr)
	}
}

// The §7.6 / §7.7 routes: workspace from the token (another workspace's
// deployment is 404), the permission each route requires, the envelope,
// and every mutation writes iga_gov_event and audit_events.
func TestP3T316DeploymentRoutes(t *testing.T) {
	d := newDLab(t)
	api := p3NewOwnersAPI(t, d.db)
	p3Audit(t, d.db, d.ws)
	env := services.GovDeployEnv{AWS: d.access}
	services.SetGovDeployEnv(env)
	t.Cleanup(func() { services.SetGovDeployEnv(services.GovDeployEnv{}) })
	x := d.role("RouteRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	user, mem := d.memberM("governance:read", "governance:author", "governance:enforce")
	all := "governance:read governance:author governance:enforce"
	tok := api.token(d.ws, user, mem, all)
	base := "/deployments/" + dep.String()

	code, body := api.call(http.MethodGet, "/deployments?policy_id="+x.policy.String(), tok, nil)
	if code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, body)
	}
	if code, body = api.call(http.MethodGet, base, tok, nil); code != 200 || digs(body, "data", "deployment", "state") != "verified" {
		t.Fatalf("get: %d %v", code, body)
	}
	// Another workspace's token: 404.
	other := newWorkspace(t, d.db, "p3dep-other")
	enfPurgeOnCleanup(t, d.db, other)
	if code, _ = api.call(http.MethodGet, base, api.token(other, user, uuid.Nil, all), nil); code != 404 {
		t.Fatalf("another workspace's id: %d", code)
	}
	count := func() int64 {
		var n int64
		d.db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, d.ws).Scan(&n)
		return n
	}
	mut := func(path string, body any, want int) map[string]any {
		t.Helper()
		before := count()
		code, resp := api.call(http.MethodPost, path, tok, body)
		if code != want {
			t.Fatalf("POST %s: %d %v", path, code, resp)
		}
		if want < 300 {
			if count() <= before {
				t.Fatalf("POST %s wrote no iga_gov_event", path)
			}
			p3WaitAudit(t, d.db, d.ws, http.MethodPost, "/api/iga/v1/policy"+path)
		}
		return resp
	}
	mut(base+"/validations", map[string]any{"correlation": "assumed_session", "window_start": time.Now().UTC(),
		"window_end": time.Now().Add(time.Hour).UTC(), "items": []map[string]any{{"action": "sqs:ListQueues", "expected": "denied"}}}, 201)
	mut(base+"/health-reports", map[string]any{"kind": "working", "service": "s3"}, 201)
	if code, body = api.call(http.MethodGet, base+"/health-reports", tok, nil); code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("health reports: %d %v", code, body)
	}
	if code, body = api.call(http.MethodGet, base+"/validations", tok, nil); code != 200 || len(body["data"].([]any)) != 1 {
		t.Fatalf("validations: %d %v", code, body)
	}
	resp := mut(base+"/resolve", map[string]any{"action": "reread", "reason": "x"}, 409)
	if digs(resp, "error", "code") != services.GovCodeNotUnresolved {
		t.Fatalf("resolve of a verified deployment: %v", resp)
	}
	// emergency routes need governance:emergency.
	if code, _ = api.call(http.MethodPost, base+"/emergency-undo", tok, map[string]any{"reason": "x"}); code != 403 {
		t.Fatalf("emergency undo without governance:emergency: %d", code)
	}
	resp = mut(base+"/undo", nil, 201)
	uid := digs(resp, "data", "id")
	if uid == "" {
		t.Fatalf("undo: %v", resp)
	}
	mut("/policies/"+x.policy.String()+"/remove-control", map[string]any{"control_ids": []string{x.control.String()}, "reason": "x"}, 409)
	if code, _ = api.call(http.MethodPost, "/policies/"+x.policy.String()+"/emergency-remove-control", tok,
		map[string]any{"control_ids": []string{x.control.String()}, "reason": "x"}); code != 403 {
		t.Fatalf("emergency removal without governance:emergency: %d", code)
	}

	// Every remaining mutating route answers 2xx with its event and audit row.
	euser, emem := d.memberM("governance:read", "governance:author", "governance:enforce", "governance:emergency")
	tok = api.token(d.ws, euser, emem, all+" governance:emergency")
	x2 := d.role("RouteRole2", "/", nil)
	tp2 := d.compile(d.fake.Discovery(), x2, "sqs")
	dep2 := d.applyAndVerify(x2, d.storeApproved(x2, tp2.Apply, *tp2.Undo))
	mut("/deployments/"+dep2.String()+"/emergency-undo", map[string]any{"reason": "incident"}, 201)
	x3 := d.role("RouteRole3", "/", nil)
	tp3 := d.compile(d.fake.Discovery(), x3, "sqs")
	d.applyAndVerify(x3, d.storeApproved(x3, tp3.Apply, *tp3.Undo))
	resp = mut("/policies/"+x3.policy.String()+"/remove-control", map[string]any{"control_ids": []string{x3.control.String()}, "reason": "done"}, 201)
	if digs(resp, "data", "version_id") == "" {
		t.Fatalf("remove-control: %v", resp)
	}
	x4 := d.role("RouteRole4", "/", nil)
	tp4 := d.compile(d.fake.Discovery(), x4, "sqs")
	d.applyAndVerify(x4, d.storeApproved(x4, tp4.Apply, *tp4.Undo))
	mut("/policies/"+x4.policy.String()+"/emergency-remove-control", map[string]any{"control_ids": []string{x4.control.String()}, "reason": "incident"}, 201)
	_, _, held := dUnknownApply(t, d, "RouteHeld")
	p3exec(t, d.db, `UPDATE iga_gov_deployment SET settle_after = now() - interval '1 minute' WHERE id = ?`, held)
	mut("/deployments/"+held.String()+"/resolve", map[string]any{"action": "reread", "reason": "check"}, 200)
	_ = errors.New
}

// memberM is memberWith returning the membership too (a console token).
func (d *dLab) memberM(perms ...string) (uuid.UUID, uuid.UUID) {
	d.t.Helper()
	user := d.memberWith(perms...)
	var row struct{ ID uuid.UUID }
	d.db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, d.ws, user).Scan(&row)
	return user, row.ID
}
