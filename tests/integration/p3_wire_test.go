package integration

// p3-wire: the integration of the Phase 3 tasks built in parallel
// (SPEC-iga-phase3-policy.md §2.5, §2.8, §3.5, §7.3-§7.5, §8.2, §8.3):
//
//   - GovAWSLiveReader (T3.11's LiveReader over T3.10's discovery reads);
//   - the authsec:workspace tag the executor writes is the compiler's
//     GovWorkspaceRef, and ownership checks compare that value;
//   - T3.12's owner review behind T3.11/T3.13's hooks, end to end through
//     the production routes;
//   - the publication hook (compile_plans after each evaluation) and an
//     A59-style unchanged revalidation through the job;
//   - a broad grant (s3:* on *) no longer fails the whole evaluation.
//
// Safeguards (mutation-checked, see the report): the owner gate hook; the
// review settle never reopening a review the response's hook cancelled; the
// publication hook's enqueue; the broad_grant detail-key escape; the live
// reader's boundary read; GovControlRef's workspace ref.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
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

/* ------------------------------ live reader ------------------------------- */

// Item 1: GovAWSLiveReader reads exactly what the executor's discovery reads
// see; Role nil on NoSuchEntity; the boundary and every PolicyARNs entry are
// keys of Policies (nil = NoSuchEntity); ReadAt set; RoleID never filtered;
// any failure fails the read.
func TestP3WireLiveReaderOverDiscoveryReads(t *testing.T) {
	l := newX3Lab(t)
	ctx := context.Background()
	x := l.role("WireReadRole", "/app/", map[string]string{"team": "wire"})
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	reader := services.NewGovAWSLiveReader(l.access).WithClock(func() time.Time { return at })
	req := services.LiveReadRequest{WorkspaceID: l.ws, ConnectorID: l.conn.ID, AccountID: testAccount, RoleARN: x.arn,
		RoleID: x.role.RoleID, PolicyARNs: []string{x.authsecARN()}}

	got, err := reader.ReadRole(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	want := l.live(l.fake.Discovery(), x)
	if !reflect.DeepEqual(got.Role, want.Role) || !got.ReadAt.Equal(at) {
		t.Fatalf("role read differs from the executor's:\n got %+v\nwant %+v", got.Role, want.Role)
	}
	if p, ok := got.Policies[x.authsecARN()]; !ok || p != nil || len(got.Policies) != 1 {
		t.Fatalf("policies %v: want the AuthSec ARN as a NoSuchEntity key only", got.Policies)
	}

	// A customer boundary is always read, in addition to PolicyARNs.
	b := l.fake.AddPolicy("/", "WireBoundary", nil, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	l.fake.SetBoundary(x.name, b.ARN)
	got, err = reader.ReadRole(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	bp := got.Policies[b.ARN]
	if got.Role == nil || got.Role.BoundaryARN != b.ARN || bp == nil || bp.VersionCount != 1 || len(bp.AttachmentSet) != 1 ||
		bp.AttachmentSet[0].Usage != igagov.UsageBoundary || got.Policies[x.authsecARN()] != nil {
		t.Fatalf("boundary read: role %+v policies %+v", got.Role, got.Policies)
	}
	want = l.live(l.fake.Discovery(), x)
	if !reflect.DeepEqual(got.Policies[b.ARN], want.Policies[b.ARN]) {
		t.Fatalf("boundary read differs from the executor's")
	}

	// Never filtered on RoleID: a recreated role is returned as AWS has it.
	stale := req
	stale.RoleID = "AROAOLDINCARNATION01"
	if got, err := reader.ReadRole(ctx, stale); err != nil || got.Role == nil || got.Role.RoleID != x.role.RoleID {
		t.Fatalf("read with another RoleID: %+v %v", got.Role, err)
	}

	// A failure anywhere fails the whole read.
	l.fake.ReadFail["iam:ListEntitiesForPolicy"] = enforcetest.APIError("Throttling", "slow down")
	if got, err := reader.ReadRole(ctx, req); err == nil || got.Role != nil || got.Policies != nil {
		t.Fatalf("a failed policy read returned %+v %v", got, err)
	}
	delete(l.fake.ReadFail, "iam:ListEntitiesForPolicy")
	// An unusable connector is a failed read (discovery_unavailable).
	other := req
	other.ConnectorID = uuid.New()
	var ee *services.EnforcementError
	if _, err := reader.ReadRole(ctx, other); err == nil || !errors.As(err, &ee) || ee.Code != services.EnfCodeDiscoveryUnavailable {
		t.Fatalf("unknown connector: %v", err)
	}
	// A role answered from another account than the control's is refused.
	wrong := req
	wrong.AccountID = "999999999999"
	if _, err := reader.ReadRole(ctx, wrong); err == nil {
		t.Fatal("a role from another account was accepted")
	}

	// The role is gone: Role nil, the requested policies still read.
	delete(l.fake.Roles, x.name)
	got, err = reader.ReadRole(ctx, req)
	if err != nil || got.Role != nil {
		t.Fatalf("deleted role: %+v %v", got.Role, err)
	}
	if p, ok := got.Policies[x.authsecARN()]; !ok || p != nil {
		t.Fatalf("deleted role: policies %v", got.Policies)
	}
}

/* ----------------------------- workspace tag ------------------------------ */

// Item 2: the executor writes the compiler's GovWorkspaceRef as the
// authsec:workspace tag; the next compile (the production ControlRef)
// recognises the boundary as this workspace's, and a ControlRef of another
// workspace is refused artifact_owned_elsewhere.
func TestP3WireWorkspaceTagIsTheCompilersRef(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("WireTagRole", "/app/", nil)
	ref := services.GovWorkspaceRef(l.ws)
	if x.ref.WorkspaceRef != ref || !strings.HasPrefix(ref, "ws-") || len(ref) != 23 {
		t.Fatalf("control ref %+v, want WorkspaceRef %s", x.ref, ref)
	}
	tp := l.compile(l.fake.Discovery(), x, "ec2", "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	l.mustApply(l.exec, l.claim(dep, "wire-worker", time.Now()), dep)
	_, _, _, tags, ok := l.fake.PolicyState(*tp.Apply.DesiredBoundaryARN)
	if !ok || tags[igagov.TagWorkspace] != ref || tags[igagov.TagControl] != x.control.String() {
		t.Fatalf("AuthSec boundary tags %v, want authsec:workspace=%s", tags, ref)
	}
	l.settle(dep, "verified")

	// The next version compiles against AuthSec's own boundary (a new
	// default version), through the production live reader.
	live, err := services.NewGovAWSLiveReader(l.access).ReadRole(context.Background(), services.LiveReadRequest{WorkspaceID: l.ws,
		ConnectorID: l.conn.ID, AccountID: testAccount, RoleARN: x.arn, RoleID: x.role.RoleID, PolicyARNs: []string{x.authsecARN()}})
	if err != nil {
		t.Fatal(err)
	}
	compile := func(ctl igagov.ControlRef) igagov.TargetPlans {
		tp, err := igagov.CompileTarget(igagov.TargetInput{Control: ctl, Intent: l.intent(x, "ec2", "sqs", "sns"), Live: live,
			Evidence: l.evidence(x, []string{"ec2", "sqs", "sns"}), ScanEvidence: &igagov.ResourcePolicyEvidence{Coverage: x3Coverage()},
			EnabledRegions: []string{"us-east-1"}, AccountServices: []string{"ecr", "sqs"}})
		if err != nil {
			t.Fatal(err)
		}
		return tp
	}
	next := compile(x.ref)
	var ops []string
	for _, op := range next.Apply.Ops {
		ops = append(ops, op.Op)
	}
	if !next.Apply.Eligible() || !p3aHas(ops, igagov.OpCreatePolicyVersion) {
		t.Fatalf("next version on our own boundary: eligible=%v %v ops %v", next.Apply.Eligible(), next.Apply.Refusals, ops)
	}
	foreign := x.ref
	foreign.WorkspaceRef = services.GovWorkspaceRef(uuid.New())
	refused := compile(foreign)
	var codes []string
	for _, r := range refused.Apply.Refusals {
		codes = append(codes, r.Code)
	}
	if refused.Apply.Eligible() || !p3aHas(codes, igagov.RefuseArtifactOwnedElsewhere) {
		t.Fatalf("another workspace's ref: eligible=%v refusals %v", refused.Apply.Eligible(), codes)
	}
}

/* ------------------------------ owner review ------------------------------ */

// wireOwner makes user an accountable manual owner of an identity account or
// a workload.
func wireOwner(t *testing.T, l *p3aLab, kind string, obj, user uuid.UUID) {
	t.Helper()
	o := &models.IGAGovOwner{WorkspaceID: l.ws, ObjectKind: kind, UserID: user, Role: models.GovOwnerAccountable,
		Source: models.GovOwnerSourceManual, CreatedBy: &l.author.user}
	if kind == models.GovObjectWorkload {
		o.WorkloadID = &obj
	} else {
		o.IdentityAccountID = &obj
	}
	if err := repositories.NewIGAGovOwnershipRepository(l.db).AddOwner(o); err != nil {
		t.Fatal(err)
	}
}

func (l *p3aLab) reviewOfVersion(policy string, no int) (uuid.UUID, string) {
	l.t.Helper()
	var rows []struct {
		ID     uuid.UUID
		Status string
	}
	if err := l.db.Raw(`SELECT id, status FROM iga_gov_owner_review WHERE workspace_id = ? AND version_id = ?`,
		l.ws, l.versionID(policy, no)).Scan(&rows).Error; err != nil {
		l.t.Fatal(err)
	}
	if len(rows) != 1 {
		return uuid.Nil, ""
	}
	return rows[0].ID, rows[0].Status
}

// ack acknowledges a review as m with every confirmation the review asks of
// them.
func (l *p3aLab) ack(m p3aMember, review uuid.UUID) map[string]any {
	l.t.Helper()
	code, body := l.call(m, http.MethodGet, "/reviews/"+review.String(), nil)
	v := l.must(code, body, http.StatusOK, "GET review")
	req, _ := v["requested"].(map[string]any)
	in := map[string]any{"response": "acknowledge", "age_confirmations": []any{}, "route_confirmations": []any{}}
	var ages, routes []any
	for _, x := range req["age_confirmations"].([]any) {
		ages = append(ages, map[string]any{"service": x.(map[string]any)["service"], "confirmed": true})
	}
	for _, x := range req["route_confirmations"].([]any) {
		it := x.(map[string]any)
		routes = append(routes, map[string]any{"service": it["service"], "route": it["route"], "confirmed": true})
	}
	if ages != nil {
		in["age_confirmations"] = ages
	}
	if routes != nil {
		in["route_confirmations"] = routes
	}
	code, body = l.call(m, http.MethodPost, "/reviews/"+review.String()+"/respond", in)
	return l.must(code, body, http.StatusOK, "acknowledge")
}

// Item 3, end to end through the production routes with the production
// wiring (InstallGovOwnerReviewWiring): propose opens a review asking the
// role's owner AND the consuming workload's owner; approval is refused
// (409 review_incomplete) while it is incomplete; the role owner retains
// one service, which creates the next version (the reviewed one withdrawn,
// its review cancelled); proposing that version opens its own review; both
// owners acknowledge; approval succeeds.
func TestP3WireOwnerReviewEndToEnd(t *testing.T) {
	l := newP3aLab(t, "p3-wire-review")
	t.Cleanup(services.InstallGovOwnerReviewWiring(l.db))
	roleID := "AROAWIREREVIEW00001"
	l.role("WireReviewRole", roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "sns": nil})
	l.publish()
	identity := bdbID(t, l.p2Lab, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND immutable_key = ?`, l.ws, roleID)
	var workloads []uuid.UUID
	l.db.Raw(`SELECT DISTINCT w.id FROM iga_relationship r
		JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		WHERE r.workspace_id = ? AND r.target_identity_account_id = ?`, l.ws, identity).Scan(&workloads)
	if len(workloads) == 0 {
		t.Fatal("the role has no consuming workload")
	}
	roleOwner := l.member("role-owner", "read")
	appOwner := l.member("app-owner", "read")
	wireOwner(t, l, models.GovObjectIdentityAccount, identity, roleOwner.user)
	for _, w := range workloads {
		wireOwner(t, l, models.GovObjectWorkload, w, appOwner.user)
	}

	policy, _ := l.proposeTemplate(roleID)
	plans := l.compile(policy, 1)
	review, status := l.reviewOfVersion(policy, 1)
	if review == uuid.Nil || status != services.GovReviewOpen {
		t.Fatalf("propose did not open the review: %s %q", review, status)
	}
	var asked []uuid.UUID
	l.db.Raw(`SELECT user_id FROM iga_gov_owner_response WHERE workspace_id = ? AND review_id = ? ORDER BY user_id`, l.ws, review).Scan(&asked)
	wantAsked := []uuid.UUID{roleOwner.user, appOwner.user}
	sort.Slice(wantAsked, func(i, j int) bool { return wantAsked[i].String() < wantAsked[j].String() })
	if !reflect.DeepEqual(asked, wantAsked) {
		t.Fatalf("asked %v, want the role owner and the consumer owner %v", asked, wantAsked)
	}
	if n := l.events(services.GovEventReviewOpened); n != 1 {
		t.Fatalf("review.opened events: %d", n)
	}

	// Silence is not consent: approval refused while the review is incomplete.
	code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("approve with an open review: %d %v", code, body)
	}
	// An objection is recorded (the response row and review.responded) and
	// blocks; the version stays in review and no version is created.
	code, body = l.call(appOwner, http.MethodPost, "/reviews/"+review.String()+"/respond", map[string]any{"response": "object",
		"comment": "the refund agent publishes to sns on every refund"})
	if d := l.must(code, body, http.StatusOK, "object"); d["new_version_id"] != nil {
		t.Fatalf("an objection created a version: %v", d)
	}
	if s := l.status(policy, 1); s != "in_review" || l.count(`SELECT count(*) FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ?`, l.ws, policy) != 1 {
		t.Fatalf("after an objection: version 1 %s", s)
	}
	code, body = l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" || !strings.Contains(fmt.Sprint(body), services.GovBlockObjection) {
		t.Fatalf("approve over an objection: %d %v", code, body)
	}
	// The owner changes their answer; one owner acknowledging is still
	// incomplete.
	l.ack(appOwner, review)
	if code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil)); code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("approve with one owner silent: %d %v", code, body)
	}

	// Both acknowledge: the review is complete (nothing blocks).
	l.ack(roleOwner, review)
	if _, st := l.reviewOfVersion(policy, 1); st != services.GovReviewComplete {
		t.Fatalf("version 1's review is %q after both acknowledged, want complete", st)
	}

	// The role owner changes their answer and keeps sqs: the next version,
	// with sqs retained; version 1 is withdrawn and its (complete) review
	// cancelled -- never moved back to open by the response's own settle.
	code, body = l.call(roleOwner, http.MethodPost, "/reviews/"+review.String()+"/respond", map[string]any{"response": "retain",
		"retain_items": []any{map[string]any{"service": "sqs", "reason": "the nightly refund batch reads the DLQ", "review_by": "2027-06-30"}}})
	d := l.must(code, body, http.StatusOK, "retain")
	if fmt.Sprint(d["new_version_id"]) != l.versionID(policy, 2).String() {
		t.Fatalf("retain response %v, want new_version_id of version 2", d)
	}
	if s := l.status(policy, 1); s != "withdrawn" {
		t.Fatalf("version 1 is %s after the retain, want withdrawn", s)
	}
	if _, st := l.reviewOfVersion(policy, 1); st != services.GovReviewCancelled {
		t.Fatalf("version 1's review is %q, want cancelled", st)
	}
	var v2 models.IGAGovPolicyVersion
	if err := l.db.Where("workspace_id = ? AND id = ?", l.ws, l.versionID(policy, 2)).Take(&v2).Error; err != nil {
		t.Fatal(err)
	}
	parsed, err := igagov.ParseIntent(v2.Intent)
	if err != nil || parsed.RightSize == nil {
		t.Fatal(err)
	}
	in := parsed.RightSize
	var removed []string
	for _, r := range in.Remove {
		removed = append(removed, r.Service)
	}
	retained := map[string]igagov.RetainEntry{}
	for _, r := range in.Retain {
		retained[r.Service] = r
	}
	if p3aHas(removed, "sqs") || retained["sqs"].Basis != igagov.RetainOwner || retained["sqs"].ReviewBy != "2027-06-30" ||
		v2.CreatedBy != roleOwner.user || v2.Status != "draft" {
		t.Fatalf("version 2: status %s by %s, removes %v, retains %+v", v2.Status, v2.CreatedBy, removed, retained)
	}

	// Version 2 proposed: its own review, both owners asked again.
	plans2 := l.compile(policy, 2)
	review2, status2 := l.reviewOfVersion(policy, 2)
	if review2 == uuid.Nil || review2 == review || status2 != services.GovReviewOpen {
		t.Fatalf("version 2's review: %s %q", review2, status2)
	}
	if code, body := l.approve(l.approver, policy, 2, p3aApproveBody(plans2, nil)); code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("approve v2 before the owners answer: %d %v", code, body)
	}
	l.ack(roleOwner, review2)
	l.ack(appOwner, review2)
	if _, st := l.reviewOfVersion(policy, 2); st != services.GovReviewComplete {
		t.Fatalf("version 2's review is %q after both acknowledged, want complete", st)
	}
	code, body = l.approve(l.approver, policy, 2, p3aApproveBody(plans2, nil))
	l.must(code, body, http.StatusOK, "approve v2 after the owners acknowledged")
	if s := l.status(policy, 2); s != "approved" {
		t.Fatalf("version 2 is %s", s)
	}
}

/* --------------------------- publication hook ----------------------------- */

// Item 4 (A59-style): after approval, each published revision's completed
// evaluation queues compile_plans for the approved version (rev = the
// revision); the job revalidates the approved plan as `unchanged` --
// approved plan_hash, approval and version untouched, no owner notice.
func TestP3WirePublicationRevalidatesUnchanged(t *testing.T) {
	l := newP3aLab(t, "p3-wire-publish")
	roleID := "AROAWIREPUBLISH0001"
	l.role("WirePublishRole", roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'compile_plans'`, l.ws); n != 0 {
		t.Fatalf("%d compile_plans jobs with no open version", n)
	}
	policy, _ := l.proposeTemplate(roleID)
	l.compile(policy, 1)
	l.approveAll(policy, 1)
	ap := l.applyPlan(policy, 1)
	approvedHash := ap["plan_hash"].(string)
	vid := l.versionID(policy, 1)
	approvals := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws)
	notices := l.count(`SELECT count(*) FROM iga_gov_notification WHERE workspace_id = ?`, l.ws)

	w := services.NewPolicyJobWorker(l.db, "p3-wire-compile").WithGate(func() bool { return true })
	w.Register(services.PolicyJobKind{Kind: repositories.GovJobCompilePlans, Handler: l.authoring().CompilePlansHandler})
	for i := 1; i <= 2; i++ {
		l.publish()
		rev := l.latestRev()
		var jobs []models.IGAGovJob
		l.db.Where("workspace_id = ? AND kind = 'compile_plans' AND status = 'queued'", l.ws).Find(&jobs)
		if len(jobs) != 1 || jobs[0].SubjectID == nil || *jobs[0].SubjectID != vid || jobs[0].Rev == nil || *jobs[0].Rev != rev ||
			jobs[0].DedupeKey != "version:"+vid.String() {
			t.Fatalf("publication %d: compile_plans jobs %+v, want one for version %s at rev %d", i, jobs, vid, rev)
		}
		var payload string
		l.db.Raw(`SELECT payload::text FROM iga_gov_event WHERE workspace_id = ? AND event = 'evaluation_completed' ORDER BY id DESC LIMIT 1`, l.ws).Scan(&payload)
		if !strings.Contains(payload, `"compile_plans": 1`) && !strings.Contains(payload, `"compile_plans":1`) {
			t.Fatalf("evaluation_completed payload %s does not count the compile job", payload)
		}
		if ran, err := w.RunOnce(context.Background()); !ran || err != nil {
			t.Fatalf("compile_plans job: ran=%v err=%v", ran, err)
		}
		var j models.IGAGovJob
		l.db.First(&j, "id = ?", jobs[0].ID)
		if j.Status != models.GovJobComplete {
			t.Fatalf("job %+v", j)
		}
		var rvs []models.IGAGovRevalidation
		l.db.Where("workspace_id = ?", l.ws).Order("created_at").Find(&rvs)
		if len(rvs) != i || rvs[i-1].Result != models.GovRevalidationUnchanged {
			t.Fatalf("after publication %d: revalidations %+v, want %d unchanged", i, rvs, i)
		}
	}
	if s := l.status(policy, 1); s != "approved" {
		t.Fatalf("version is %s", s)
	}
	if got := l.applyPlan(policy, 1)["plan_hash"]; got != approvedHash {
		t.Fatalf("approved plan_hash changed: %v -> %v", approvedHash, got)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ? AND revoked_at IS NULL`, l.ws); n != approvals {
		t.Fatalf("live approvals %d, want %d", n, approvals)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_notification WHERE workspace_id = ?`, l.ws); n != notices {
		t.Fatalf("notices %d, want %d (no owner notice on an unchanged rescan)", n, notices)
	}
}

/* ------------------------------ broad grant ------------------------------- */

// Item 5: a role granted s3:* on * evaluates (it used to fail the WHOLE
// evaluation: the graph statement key contains U+001F, which Fingerprint
// refuses). The finding's detail_key is the escaped statement key, the raw
// key stays in the detail, and the fingerprint is stable across revisions.
func TestP3WireBroadGrantEvaluates(t *testing.T) {
	l := newP3aLab(t, "p3-wire-broad")
	roleID := "AROAWIREBROAD000001"
	arn := p3eOldRole(l.a, "WireBroadRole", roleID, 200*24*time.Hour, "WireBroadWork",
		`{"Version":"2012-10-17","Statement":[{"Sid":"All","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	p3eAddLambda(l.a, "us-east-1", "wire-broad-fn", arn)
	l.activity(l.a).set(arn, map[string]*time.Time{"s3": p3eTime(time.Hour)})

	var first p3eFinding
	for i := 0; i < 2; i++ {
		l.publish()
		rev := l.latestRev()
		if ev := l.evaluation(rev); ev.Status != models.GovEvalComplete {
			t.Fatalf("evaluation of rev %d is %s (%s), want complete", rev, ev.Status, ev.Error)
		}
		var rows []struct {
			Fingerprint      string
			DetailKey        string
			Severity         string
			StatementKey     string
			LastEvaluatedRev int64
		}
		l.db.Raw(`SELECT fingerprint, detail_key, severity, detail->>'statement_key' AS statement_key, last_evaluated_rev
		            FROM iga_gov_finding WHERE workspace_id = ? AND kind = 'broad_grant' AND role_id = ?`, l.ws, roleID).Scan(&rows)
		if len(rows) != 1 {
			t.Fatalf("rev %d: broad_grant findings %+v, want one", rev, rows)
		}
		f := rows[0]
		fp, err := igagov.Fingerprint(igagov.KindBroadGrant, roleID, igagov.BroadGrantDetailKey(f.StatementKey))
		if err != nil || f.Fingerprint != fp || strings.Contains(f.DetailKey, "\x1f") || !strings.Contains(f.StatementKey, "\x1f") ||
			f.DetailKey != igagov.BroadGrantDetailKey(f.StatementKey) || f.Severity != igagov.SeverityMedium || f.LastEvaluatedRev != rev {
			t.Fatalf("rev %d: finding %+v (fingerprint %s %v)", rev, f, fp, err)
		}
		if i == 0 {
			first = p3eFinding{DetailKey: f.DetailKey, Kind: f.Fingerprint}
		} else if first.Kind != f.Fingerprint || first.DetailKey != f.DetailKey {
			t.Fatalf("fingerprint changed across revisions: %+v -> %+v", first, f)
		}
	}
}

/* ------------------------- notification channels ------------------------- */

// Item 6, without Vault: the legacy copy waits (GET /settings still answers,
// nothing copied, no event), the email switch and URL can be stored, and a
// webhook secret is refused 503 notification_secret_store_unavailable.
func TestP3WireChannelStoreWithoutVault(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3-wire-novault")
	p3Audit(t, db, g.ws)
	t.Cleanup(services.SetGovNotificationChannelStore(services.NewGovDBChannelStore(nil)))
	p3exec(t, db, `INSERT INTO governance_notification_settings (workspace_id, webhook_url, webhook_secret, email_enabled)
		VALUES (?, 'https://hooks.customer.test/legacy', 'legacy-secret', true)`, g.ws)
	reader := api.token(g.ws, g.author, g.authorMember, "governance:read")
	enforcer := api.token(g.ws, g.author, g.authorMember, "governance:read governance:enforce")
	code, body := api.call(http.MethodGet, "/settings", reader, nil)
	if code != http.StatusOK || dig(body, "data", "notifications", "available") != true || digs(body, "data", "notifications", "source") != "default" {
		t.Fatalf("GET without Vault: %d %v", code, body)
	}
	if n := len(g.eventsNamed(services.GovEventSettingsChannelsCopied)); n != 0 {
		t.Fatalf("copied without Vault: %d events", n)
	}
	code, body = api.call(http.MethodPut, "/settings", enforcer, map[string]any{"notifications": map[string]any{
		"webhook_url": "https://hooks.example.test/p3", "webhook_secret": "whsec"}})
	if code != http.StatusServiceUnavailable || errCode(body) != "notification_secret_store_unavailable" {
		t.Fatalf("secret without Vault: %d %v", code, body)
	}
	code, body = api.call(http.MethodPut, "/settings", enforcer, map[string]any{"notifications": map[string]any{
		"email_enabled": false, "webhook_url": "https://hooks.example.test/p3"}})
	if code != http.StatusOK || dig(body, "data", "notifications", "email_enabled") != false ||
		digs(body, "data", "notifications", "source") != "phase3" || dig(body, "data", "notifications", "webhook_secret_set") != false {
		t.Fatalf("channels without a secret: %d %v", code, body)
	}
	var row struct {
		NotifyEmailEnabled     bool
		NotifyWebhookURL       string
		NotifyWebhookSecretRef string
		NotifyChannelsSource   string
	}
	db.Raw(`SELECT notify_email_enabled, notify_webhook_url, notify_webhook_secret_ref, notify_channels_source
	          FROM iga_gov_settings WHERE workspace_id = ?`, g.ws).Scan(&row)
	if row.NotifyEmailEnabled || row.NotifyWebhookURL != "https://hooks.example.test/p3" || row.NotifyWebhookSecretRef != "" ||
		row.NotifyChannelsSource != "phase3" {
		t.Fatalf("row %+v", row)
	}
}
