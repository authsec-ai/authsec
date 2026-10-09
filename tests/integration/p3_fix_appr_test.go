package integration

// fix/p3-appr -- approval integrity (REVIEW-FIXLIST P0-2, P1-4, P1-10;
// SPEC-iga-phase3-policy.md §2.8, §2.10, §8.4, §8.9, §8.10, §11, A59).
// Prefixed fxa.
//
//   - P0-2 (A59): the REAL evaluation lab (scan worker, projection with
//     evaluation, compile_plans job, rollout jobs) over a fake AWS account
//     (T3.16's enforcetest.FakeAWS, read by the production GovAWSLiveReader
//     and written by the real deploy job): approve -> canary deployed and
//     verified -> new publications -> the canary's approved plan is never
//     revalidated or superseded, the not-yet-deployed target gets an
//     `unchanged` revalidation, and expansion proceeds; a genuine material
//     change (a new consumer of the not-yet-deployed target) still needs a
//     new approval, without touching the deployed target's plan.
//   - P1-4: Approve refuses without the owner gate hook; the policy gate
//     reports verified only after the ready hook installed the runtime;
//     the Slack app composes its hooks without an empty window.
//   - P1-10: split / split_revert / remove_control / undo deployments go
//     through the authority checks the spec requires, in the real deploy
//     job; a stale split is revalidated (dedicated-identity recompile).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

/* ------------------------------ fake account ------------------------------ */

// fxaAWS is the deploy job's and the live reader's AWS access over one fake
// account: the discovery role's reads and the enforcement role's writes see
// the same roles and policies.
type fxaAWS struct{ f *enforcetest.FakeAWS }

func (a fxaAWS) DiscoveryIAM(context.Context, uuid.UUID, uuid.UUID) (awsenforce.DiscoveryIAM, error) {
	return a.f.Discovery(), nil
}

func (a fxaAWS) EnforcementIAM(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (awsenforce.IAM, error) {
	return a.f, nil
}

/* ---------------------------------- lab ----------------------------------- */

// fxaLab is the T3.15 rollout lab (real scan, projection, evaluation and
// rollout jobs, production routes) with the REAL T3.16 deployment jobs and
// the compile_plans job on the same worker, the real T3.12 owner review
// wiring, and every live read and write against one fake AWS account.
type fxaLab struct {
	*p3rLab
	fake *enforcetest.FakeAWS
	dep  *services.GovDeployments
}

func newFxaLab(t *testing.T, name string) *fxaLab {
	t.Helper()
	l := &fxaLab{p3rLab: newP3rLab(t, name, true)}
	f, err := enforcetest.NewFakeAWSFromTemplate(awsdiscovery.EnforcementCloudFormationTemplate, accountA, "fxa", "fxa-external-id")
	if err != nil {
		t.Fatal(err)
	}
	l.fake = f
	acc := fxaAWS{f: f}
	// Compile (propose, compile_plans, revalidation, rollout) reads through
	// the production reader over the fake account.
	l.live.delegate = services.NewGovAWSLiveReader(acc)
	// No CloudTrail (the P1-7 fix removed the dTrail stub): these approval
	// tests never resolve an unknown outcome.
	env := services.GovDeployEnv{AWS: acc}
	l.dep = services.NewGovDeployments(l.db, &env).WithAuthoring(services.NewGovAuthoring(l.db, l.live)).WithSleep(noSleep)
	l.dep.Executor = func(e *services.IGAGovAWSExecutor) { e.WithSleep(noSleep) }
	l.dep.Register(l.worker)
	l.worker.Register(services.PolicyJobKind{Kind: repositories.GovJobCompilePlans, Handler: l.authoring().CompilePlansHandler})
	// The real owner review behind the authoring hooks (OwnerGate,
	// OnImpactChanged reopening the review for new owners).
	t.Cleanup(services.InstallGovOwnerReviewWiring(l.db))
	t.Cleanup(func() {
		_ = l.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(`SET LOCAL authsec.workspace_purge = 'on'`).Error; err != nil {
				return err
			}
			for _, table := range []string{"iga_gov_service_outcome", "iga_gov_service_posture", "iga_gov_verification",
				"iga_gov_attempt", "iga_gov_artifact"} {
				if err := tx.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, l.ws).Error; err != nil {
					t.Logf("cleanup %s: %v", table, err)
					return err
				}
			}
			return nil
		})
	})
	return l
}

// role adds the role to the evaluation lab (scan side) AND to the fake
// account (same name, RoleId, ARN and permissions policy).
func (l *fxaLab) role(name, roleID string, report map[string]*time.Time) string {
	l.t.Helper()
	arn := l.p3rLab.role(name, roleID, report)
	var svcs []string
	for s := range report {
		svcs = append(svcs, s)
	}
	sortStrings(svcs)
	r := l.fake.AddRole(name, "/", nil)
	r.RoleID = roleID
	pol := l.fake.AddPolicy("/", name+"Work", nil, p3aDoc(svcs...))
	l.fake.AttachPermissions(name, pol.ARN)
	if pol.ARN != l.a.policyARN(name+"Work") || l.fake.RoleARNOf(r) != arn {
		l.t.Fatalf("fake account and scan disagree: %s / %s, %s / %s", pol.ARN, l.a.policyARN(name+"Work"), l.fake.RoleARNOf(r), arn)
	}
	return arn
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// mirrorBoundary makes the next scan see the boundary the deploy job
// installed on a role (the policy, its default version and the role's
// PermissionsBoundary), as AWS would.
func (l *fxaLab) mirrorBoundary(roleName, arn string) {
	l.t.Helper()
	_, def, doc, _, ok := l.fake.PolicyState(arn)
	if !ok {
		l.t.Fatalf("no policy %s in the fake account", arn)
	}
	l.a.iam.managedPolicies[arn] = doc
	l.a.iam.policyVersions[arn] = def
	l.a.iam.policyIDs[arn] = "ANPAFXABOUNDARY" + strings.ToUpper(roleName[:3])
	p3eTag(l.a, roleName, nil, arn)
}

// runVerifyNow makes the queued verify jobs claimable now.
func (l *fxaLab) runVerifyNow() {
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET run_after = now() - interval '1 second' WHERE workspace_id = ? AND kind = 'verify' AND status = 'queued'`, l.ws)
}

func (l *fxaLab) depRow(id uuid.UUID) models.IGAGovDeployment {
	l.t.Helper()
	var d models.IGAGovDeployment
	if err := l.db.First(&d, "id = ?", id).Error; err != nil {
		l.t.Fatal(err)
	}
	return d
}

// planOfRole is the current (or, with superseded, any) apply plan of the
// version for a role.
func (l *fxaLab) applyPlans(policy string, roleID string) []models.IGAGovPlan {
	l.t.Helper()
	var ps []models.IGAGovPlan
	if err := l.db.Raw(`SELECT p.* FROM iga_gov_plan p JOIN iga_gov_control c ON c.id = p.control_id
		WHERE p.workspace_id = ? AND p.version_id = ? AND p.kind = 'apply' AND c.role_id = ? ORDER BY p.created_at`,
		l.ws, l.versionID(policy, 1), roleID).Scan(&ps).Error; err != nil {
		l.t.Fatal(err)
	}
	return ps
}

func (l *fxaLab) revalidations(planID uuid.UUID) []models.IGAGovRevalidation {
	var rvs []models.IGAGovRevalidation
	l.db.Where("workspace_id = ? AND plan_id = ?", l.ws, planID).Order("created_at, id").Find(&rvs)
	return rvs
}

type fxaA59 struct {
	l                   *fxaLab
	policy              string
	canary              uuid.UUID
	canaryRole, other   string
	canaryName, otherNm string
	otherARN            string
	approval            models.IGAGovApproval
	canaryPlan          models.IGAGovPlan
	otherPlan           models.IGAGovPlan
}

// fxaToVerifiedCanary is A59's start through the real jobs: two roles,
// observed, approved, canary deployed by the deploy job (CreatePolicy +
// PutRolePermissionsBoundary in the fake account), a publication that
// shows the boundary (the evaluation queues compile_plans), and the verify
// job verifies the canary.
func fxaToVerifiedCanary(t *testing.T, name string) *fxaA59 {
	l := newFxaLab(t, name)
	x := &fxaA59{l: l}
	ids := map[string]string{"AxRole": "AROAFXAALPHA00001", "BravoRole": "AROAFXABRAVO00002"}
	arns := map[string]string{}
	arns["AxRole"] = l.role("AxRole", ids["AxRole"], map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "dynamodb": p3eTime(time.Hour)})
	arns["BravoRole"] = l.role("BravoRole", ids["BravoRole"], map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "sns": p3eTime(time.Hour)})
	l.publish()
	x.policy = l.prepare(ids["AxRole"], ids["BravoRole"])
	l.observed(x.policy)
	l.approveAll(x.policy, 1)
	if err := l.db.Where("workspace_id = ? AND version_id = ? AND revoked_at IS NULL", l.ws, l.versionID(x.policy, 1)).Take(&x.approval).Error; err != nil {
		t.Fatal(err)
	}
	v := l.must2(l.start(l.author, x.policy))
	if p3rStage(v) != models.GovRolloutCanary {
		t.Fatalf("start after approval: %v", v)
	}
	x.canary = uuid.MustParse(digs(v, "results", "canary", "deployment_id"))
	l.db.Raw(`SELECT c.role_id FROM iga_gov_deployment d JOIN iga_gov_control c ON c.id = d.control_id WHERE d.id = ?`, x.canary).Scan(&x.canaryRole)
	for n, id := range ids {
		if id == x.canaryRole {
			x.canaryName = n
		} else {
			x.other, x.otherNm, x.otherARN = id, n, arns[n]
		}
	}

	// The REAL deploy job applies the canary in the fake account.
	l.drain()
	if d := l.depRow(x.canary); d.State != models.GovDeployAppliedUnverified {
		t.Fatalf("canary after the deploy job: %s %q", d.State, d.StateReason)
	}
	arn := igagov.AuthSecBoundaryARN("aws", accountA, x.canaryRole)
	if l.fake.BoundaryOf(x.canaryName) != arn {
		t.Fatalf("the canary role's boundary is %q, want %q", l.fake.BoundaryOf(x.canaryName), arn)
	}
	cp := l.applyPlans(x.policy, x.canaryRole)
	op := l.applyPlans(x.policy, x.other)
	x.canaryPlan, x.otherPlan = cp[len(cp)-1], op[len(op)-1]

	// A publication showing the boundary: the evaluation queues
	// compile_plans for the approved version; the verify job verifies.
	l.mirrorBoundary(x.canaryName, arn)
	l.publish()
	l.runVerifyNow()
	l.drain()
	if d := l.depRow(x.canary); d.State != models.GovDeployVerified {
		var dims []struct{ Dimension, Outcome string }
		l.db.Raw(`SELECT dimension, outcome FROM iga_gov_verification WHERE deployment_id = ?`, x.canary).Scan(&dims)
		t.Fatalf("canary after the publication: %s %q %+v", d.State, d.StateReason, dims)
	}
	return x
}

// assertApprovalUntouched: the approval, the version and the canary's
// approved plan are exactly as approved.
func (x *fxaA59) assertApprovalUntouched(t *testing.T, what string) {
	t.Helper()
	l := x.l
	var ap models.IGAGovApproval
	l.db.First(&ap, "id = ?", x.approval.ID)
	if ap.RevokedAt != nil {
		t.Fatalf("%s: the approval was revoked (%v)", what, ap.RevokedReason)
	}
	if s := l.status(x.policy, 1); s != "approved" {
		t.Fatalf("%s: the version is %s, want approved", what, s)
	}
	cp := l.applyPlans(x.policy, x.canaryRole)
	if len(cp) == 0 || cp[len(cp)-1].ID != x.canaryPlan.ID || cp[len(cp)-1].SupersededAt != nil || cp[len(cp)-1].PlanHash != x.canaryPlan.PlanHash {
		t.Fatalf("%s: the deployed canary's approved plan changed: %d plans, last %s superseded %v", what, len(cp), cp[len(cp)-1].ID, cp[len(cp)-1].SupersededAt)
	}
	if rvs := l.revalidations(x.canaryPlan.ID); len(rvs) != 0 {
		t.Fatalf("%s: the deployed canary's plan was revalidated: %+v", what, rvs)
	}
}

// A59, P0-2: rescans after the canary verified never revoke the approval;
// the not-yet-deployed target's plan is revalidated `unchanged` and the
// expansion deploys it on the APPROVED plan, relying on that revalidation.
//
// Fails on the base: the first publication's compile_plans revalidated the
// deployed canary's plan against a role that now carries the AuthSec
// boundary (precondition, ops [], first_attachment differ): material_change,
// approval revoked, version back to in_review.
func TestP3FixApprA59RescanAfterCanaryKeepsApproval(t *testing.T) {
	x := fxaToVerifiedCanary(t, "fxa-a59-unchanged")
	l := x.l
	x.assertApprovalUntouched(t, "after the verifying publication")
	rvs := l.revalidations(x.otherPlan.ID)
	if len(rvs) != 1 || rvs[0].Result != models.GovRevalidationUnchanged {
		t.Fatalf("the not-yet-deployed target's revalidations: %+v, want one unchanged", rvs)
	}

	// Another rescan between canary and expansion.
	l.publish()
	l.drain()
	x.assertApprovalUntouched(t, "after a second rescan")
	rvs = l.revalidations(x.otherPlan.ID)
	if len(rvs) != 2 || rvs[1].Result != models.GovRevalidationUnchanged {
		t.Fatalf("after the second rescan: %+v, want two unchanged", rvs)
	}
	if op := l.applyPlans(x.policy, x.other); op[len(op)-1].ID != x.otherPlan.ID || op[len(op)-1].SupersededAt != nil {
		t.Fatal("the not-yet-deployed target's approved plan was replaced on an unchanged rescan")
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws); n != 1 {
		t.Fatalf("%d approvals, want the one", n)
	}
	if n := l.events("approval_revoked"); n != 0 {
		t.Fatalf("%d approval_revoked events", n)
	}

	// Expansion: the canary window elapsed with clean traffic; the gates
	// pass and the rollout expands to the other target.
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET applied_at = applied_at - interval '50 hours' WHERE id = ?`, x.canary)
	at := *l.depRow(x.canary).AppliedAt
	evs, reads := p3rClean(x.canaryRole, at, "s3", "dynamodb", "sns")
	l.trail.set(x.canary, evs, reads)
	l.tick()
	v := l.rollout(x.policy)
	if p3rStage(v) != models.GovRolloutExpand {
		t.Fatalf("after the canary: stage %s, rollout %v canary %v expansion %v", p3rStage(v), v["rollout"],
			dig(v, "results", "canary"), dig(v, "results", "expansion"))
	}
	created, _ := dig(v, "results", "expansion", "deployments").([]any)
	if len(created) != 1 {
		t.Fatalf("expansion %v", dig(v, "results", "expansion"))
	}
	second := l.depRow(uuid.MustParse(created[0].(string)))
	rvs = l.revalidations(x.otherPlan.ID)
	if second.PlanID != x.otherPlan.ID || second.ApprovalID == nil || *second.ApprovalID != x.approval.ID ||
		second.RevalidationID == nil || *second.RevalidationID != rvs[len(rvs)-1].ID ||
		second.RevalidationResult == nil || *second.RevalidationResult != models.GovRevalidationUnchanged {
		t.Fatalf("expansion deployment %+v; want the approved plan %s, approval %s, the unchanged revalidation %s",
			second, x.otherPlan.ID, x.approval.ID, rvs[len(rvs)-1].ID)
	}
	// The real deploy job applied it on the approved plan.
	if second.State != models.GovDeployAppliedUnverified || l.fake.BoundaryOf(x.otherNm) != igagov.AuthSecBoundaryARN("aws", accountA, x.other) {
		t.Fatalf("expansion deployment: %s %q; boundary %q", second.State, second.StateReason, l.fake.BoundaryOf(x.otherNm))
	}
	x.assertApprovalUntouched(t, "after the expansion")
}

// A59, P0-2: a GENUINE material change -- a new consumer (with its own
// owner) of the not-yet-deployed target -- is still caught: material_change
// naming consumers, the approval revoked, the review reopened for the new
// owner, expansion refused until a new approval. The deployed canary's plan
// is never revalidated or superseded, and the re-approval binds it again.
func TestP3FixApprA59MaterialChangeSparesDeployedTarget(t *testing.T) {
	x := fxaToVerifiedCanary(t, "fxa-a59-material")
	l := x.l
	x.assertApprovalUntouched(t, "after the verifying publication")

	newOwner := l.member("new-owner", "read")
	p3eAddLambda(l.a, "us-east-1", "bravo-batch-fn", x.otherARN)
	run := l.scanOnly(l.a)
	p3eCompleteCoverage(t, l.p3eLab, l.a, run.ID)
	l.projectOnly()
	l.owner(models.GovObjectWorkload, l.workloadID("bravo-batch-fn"), newOwner.user)
	l.drain()

	rvs := l.revalidations(x.otherPlan.ID)
	last := rvs[len(rvs)-1]
	if last.Result != models.GovRevalidationMaterialChange || !strings.Contains(string(last.Changes), `"consumers"`) {
		t.Fatalf("revalidation after the new consumer: %s %s", last.Result, last.Changes)
	}
	var ap models.IGAGovApproval
	l.db.First(&ap, "id = ?", x.approval.ID)
	if ap.RevokedAt == nil || l.status(x.policy, 1) != "in_review" {
		t.Fatalf("material change: approval revoked %v, version %s", ap.RevokedAt, l.status(x.policy, 1))
	}
	// The deployed canary: plan, deployment and revalidations untouched.
	cp := l.applyPlans(x.policy, x.canaryRole)
	if cp[len(cp)-1].ID != x.canaryPlan.ID || cp[len(cp)-1].SupersededAt != nil || len(l.revalidations(x.canaryPlan.ID)) != 0 {
		t.Fatalf("the deployed canary's plan was touched: %d plans, superseded %v", len(cp), cp[len(cp)-1].SupersededAt)
	}
	if d := l.depRow(x.canary); d.State != models.GovDeployVerified {
		t.Fatalf("canary %s", d.State)
	}
	op := l.applyPlans(x.policy, x.other)
	if op[len(op)-1].ID == x.otherPlan.ID {
		t.Fatal("the changed target's plan was not replaced by the recompiled one")
	}
	// The review reopened and asks the new owner.
	var asked int64
	l.db.Raw(`SELECT count(*) FROM iga_gov_owner_response r JOIN iga_gov_owner_review v ON v.id = r.review_id
		WHERE v.workspace_id = ? AND v.version_id = ? AND r.user_id = ?`, l.ws, l.versionID(x.policy, 1), newOwner.user).Scan(&asked)
	if asked == 0 {
		t.Fatal("the new owner was not asked")
	}

	// No expansion without a new approval.
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET applied_at = applied_at - interval '50 hours' WHERE id = ?`, x.canary)
	at := *l.depRow(x.canary).AppliedAt
	evs, reads := p3rClean(x.canaryRole, at, "s3", "dynamodb", "sns")
	l.trail.set(x.canary, evs, reads)
	l.tick()
	if n := l.count(`SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ? AND control_id = ?`, l.ws, op[len(op)-1].ControlID); n != 0 {
		t.Fatalf("%d deployments of the changed target without a new approval", n)
	}
	v := l.rollout(x.policy)
	refused, _ := dig(v, "results", "expansion", "refused").([]any)
	if len(refused) != 1 || digs(refused[0], "code") != services.GovCodeApprovalRequired || digs(refused[0], "role_id") != x.other {
		t.Fatalf("expansion without a new approval: stage %s expansion %v", p3rStage(v), dig(v, "results", "expansion"))
	}

	// Re-approval: the new owner's review is the gate; the new approval
	// binds the canary's original plan and the recompiled one.
	code, body := l.approve(l.approver, x.policy, 1, p3aApproveBody(l.plans(x.policy, 1), nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("re-approval before the new owner answered: %d %v", code, body)
	}
	svc := services.NewIGAGovOwnerReviewService(l.db)
	if _, err := svc.Respond(context.Background(), l.ws, newOwner.user, l.reviewID(x.policy), p3Ack([]string{"sqs"})); err != nil {
		t.Fatal(err)
	}
	// The lab's original workloads have no owners: the approver excepts
	// them again, as prepare did.
	if _, _, err := svc.Except(context.Background(), l.ws, l.approver.user, l.reviewID(x.policy), "the lab's roles have no owners"); err != nil {
		t.Fatal(err)
	}
	l.approveAll(x.policy, 1)
	var nap models.IGAGovApproval
	if err := l.db.Where("workspace_id = ? AND version_id = ? AND revoked_at IS NULL", l.ws, l.versionID(x.policy, 1)).Take(&nap).Error; err != nil {
		t.Fatal(err)
	}
	if !p3iStrHas(nap.PlanHashes, x.canaryPlan.PlanHash) || !p3iStrHas(nap.PlanHashes, op[len(op)-1].PlanHash) {
		t.Fatalf("the new approval's plan hashes %v miss the canary's %s or the recompiled %s", nap.PlanHashes, x.canaryPlan.PlanHash, op[len(op)-1].PlanHash)
	}
	cp = l.applyPlans(x.policy, x.canaryRole)
	if cp[len(cp)-1].ID != x.canaryPlan.ID || cp[len(cp)-1].SupersededAt != nil {
		t.Fatal("the canary's plan changed after the re-approval")
	}
}

// reviewID is the version's owner review.
func (l *fxaLab) reviewID(policy string) uuid.UUID {
	return bdbID(l.t, l.p2Lab, `SELECT id FROM iga_gov_owner_review WHERE workspace_id = ? AND version_id = ?`, l.ws, l.versionID(policy, 1))
}

/* ---------------------------------- P1-4 ---------------------------------- */

// P1-4: with no owner gate hook installed, Approve refuses (503
// owner_gate_unavailable) and writes nothing; with the hook, it approves.
//
// Fails on the base: the approval was recorded with no owner check at all.
func TestP3FixApprApproveRefusedWithoutOwnerGate(t *testing.T) {
	l := newP3aLab(t, "fxa-no-owner-gate")
	l.role("NoGateRole", "AROAFXANOGATE0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy, _ := l.proposeTemplate("AROAFXANOGATE0001")
	plans := l.compile(policy, 1)
	prev := services.SetGovAuthoringHooks(services.GovAuthoringHooks{})
	code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	services.SetGovAuthoringHooks(prev)
	if code != http.StatusServiceUnavailable || p3eErr(body) != services.GovCodeOwnerGateUnavailable {
		t.Fatalf("approve without the owner gate: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws); n != 0 || l.status(policy, 1) != "in_review" {
		t.Fatalf("refused approval wrote %d approvals; version %s", n, l.status(policy, 1))
	}
	l.approveAll(policy, 1)
	if l.status(policy, 1) != "approved" {
		t.Fatal("approval with the hook installed did not approve")
	}
}

// P1-4 startup ordering (cmd/main.go): the policy gate reports verified --
// and serves any policy route -- only AFTER the ready hook installed the
// runtime (InstallGovPolicyStartup: owner review hooks, then the Slack app
// chained onto them). Inside the hook the routes still answer 503
// policy_unavailable; afterwards the real owner gate decides approvals and
// the Slack notices are chained onto the review's OnProposed.
//
// Fails on the base: the gate was verified (routes served) before the hook
// ran, so the in-hook request was served -- and approved with no owner gate.
func TestP3FixApprStartupInstallsHooksBeforeServing(t *testing.T) {
	l := newP3aLab(t, "fxa-startup")
	l.role("StartupRole", "AROAFXASTARTUP001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy, _ := l.proposeTemplate("AROAFXASTARTUP001")
	plans := l.compile(policy, 1)
	// Process start: nothing installed.
	prev := services.SetGovAuthoringHooks(services.GovAuthoringHooks{})
	t.Cleanup(func() { services.SetGovAuthoringHooks(prev) })

	gate := services.NewPolicyGate(true, "", func() *services.GraphProjectionGate { return l.gate })
	eng := gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey).WithPolicyGate(gate).WithGovLiveReader(l.live)
	routes.SetupIGARoutes(eng, platform.NewIGAController(l.db), ctl)
	l.eng = eng
	slack := services.NewSlackIntegrationService(l.db, newMemVault(), nil, services.SlackConfig{SigningSecret: "fxa"})

	var inHook []string
	var restore func()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gate.VerifyUntilReady(ctx, l.db, 10*time.Millisecond, func() {
		state, reason, _ := gate.Status()
		inHook = append(inHook, "before:"+state)
		if !strings.Contains(reason, "being installed") {
			inHook = append(inHook, "reason:"+reason)
		}
		code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
		inHook = append(inHook, fmt.Sprintf("approve:%d:%s", code, p3eErr(body)))
		restore = services.InstallGovPolicyStartup(l.db, nil, "", slack)
		state, _, _ = gate.Status()
		inHook = append(inHook, "after-install:"+state)
	})
	if restore != nil {
		t.Cleanup(restore)
	}
	want := []string{"before:" + services.PolicyMisconfigured, "approve:503:policy_unavailable", "after-install:" + services.PolicyMisconfigured}
	if strings.Join(inHook, ",") != strings.Join(want, ",") {
		t.Fatalf("inside the ready hook: %v, want %v", inHook, want)
	}
	if !gate.Available() {
		t.Fatal("the gate is not available after the ready hook")
	}
	h := services.CurrentGovAuthoringHooks()
	if h.OwnerGate == nil || h.OnProposed == nil || h.OnImpactChanged == nil {
		t.Fatalf("hooks after startup: owner gate %v, on proposed %v", h.OwnerGate != nil, h.OnProposed != nil)
	}
	if ok, _ := services.SlackAvailable(); !ok {
		t.Fatal("the Slack app was not installed")
	}
	// The real owner gate decides now: no review was opened for this
	// version (it was proposed before startup), so the approval is refused.
	code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("approve after startup: %d %v (want the real owner gate's 409 review_incomplete)", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d approvals recorded", n)
	}
}

// P1-4: InstallSlackApp composes its notices onto the installed hooks
// atomically: a concurrent reader never sees the owner gate missing.
//
// Fails on the base (Set(empty) then Set(chained)): the reader catches the
// empty window.
func TestP3FixApprSlackInstallNeverEmptiesHooks(t *testing.T) {
	prev := services.SetGovAuthoringHooks(services.GovAuthoringHooks{
		OwnerGate: func(*gorm.DB, services.GovApprovalCheck) error { return nil }})
	defer services.SetGovAuthoringHooks(prev)
	svc := services.NewSlackIntegrationService(nil, newMemVault(), nil, services.SlackConfig{SigningSecret: "fxa"})
	var stop atomic.Bool
	var missing atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if services.CurrentGovAuthoringHooks().OwnerGate == nil {
					missing.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 20000; i++ {
		services.InstallSlackApp(svc)()
	}
	stop.Store(true)
	wg.Wait()
	if n := missing.Load(); n != 0 {
		t.Fatalf("a reader saw the owner gate missing %d times while the Slack app was installed", n)
	}
	if services.CurrentGovAuthoringHooks().OwnerGate == nil {
		t.Fatal("the owner gate is gone after install + restore")
	}
}

/* ---------------------------------- P1-10 --------------------------------- */

// P1-10, remove_control through the real deploy job: the deployment needs
// the approval IN FORCE (§8.10 "an approval by someone other than the
// requester, like any version"): refused when the approver lost
// governance:approve, is no longer an active member, is the requester, or
// the approval expired; it runs once the approval is in force again.
//
// Fails on the base: only revocation and expiry were checked; the removal
// ran with an approver who no longer held governance:approve.
func TestP3FixApprRemoveControlAuthority(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	t.Cleanup(services.InstallGovOwnerReviewWiring(d.db))
	x := d.role("FxaRCRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	requester := d.memberWith("governance:author")
	res, err := d.dep.RemoveControl(ctx, d.ws, requester, x.policy, services.GovRemoveControlRequest{
		ControlIDs: []string{x.control.String()}, Reason: "decommission"}, false)
	if err != nil || res.VersionID == nil || len(res.Plans) != 1 {
		t.Fatalf("remove control: %+v %v", res, err)
	}
	authoring := services.NewGovAuthoring(d.db, nil)
	if res.Review != nil {
		if _, _, err := services.NewIGAGovOwnerReviewService(d.db).Except(ctx, d.ws, d.approver, res.Review.ReviewID, "lab"); err != nil {
			t.Fatal(err)
		}
	}
	pv, err := authoring.Plans(ctx, d.ws, x.policy, res.VersionNo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authoring.Approve(ctx, d.ws, d.approver, x.policy, res.VersionNo, services.GovApproveRequest{IntentHash: pv.Hashes.IntentHash,
		ImpactHashes: pv.Hashes.ImpactHashes, PlanHashes: pv.Hashes.PlanHashes, MaterialHashes: pv.Hashes.MaterialHashes}); err != nil {
		t.Fatalf("approve removal: %v", err)
	}
	var ap models.IGAGovApproval
	d.db.Where("workspace_id = ? AND version_id = ? AND revoked_at IS NULL", d.ws, *res.VersionID).Take(&ap)
	plan := res.Plans[0]
	queue := func() uuid.UUID {
		id := uuid.New()
		p3exec(t, d.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
			VALUES (?, ?, ?, ?, ?, ?, 'remove_control', 'direct', 'queued')`, id, d.ws, *res.VersionID, plan.ID, x.control, ap.ID)
		return id
	}
	approverRole := bdbIDx(t, d, `SELECT role_id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, d.ws, d.approver)
	calls := len(d.fake.Calls)
	for _, c := range []struct {
		name, code   string
		break_, mend string
		args1, args2 []any
	}{
		{"approver lost governance:approve", services.GovCodeApprovalInvalid,
			`DELETE FROM role_permissions WHERE role_id = ? AND permission_id IN (SELECT id FROM permissions WHERE full_permission_string = 'governance:approve' AND workspace_id IS NULL)`,
			`INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE full_permission_string = 'governance:approve' AND workspace_id IS NULL`,
			[]any{approverRole}, []any{approverRole}},
		{"approver no longer an active member", services.GovCodeApprovalInvalid,
			`UPDATE workspace_memberships SET status = 'suspended' WHERE workspace_id = ? AND user_id = ?`,
			`UPDATE workspace_memberships SET status = 'active' WHERE workspace_id = ? AND user_id = ?`,
			[]any{d.ws, d.approver}, []any{d.ws, d.approver}},
		{"approver is the requester", services.GovCodeApprovalInvalid,
			`UPDATE iga_gov_approval SET decided_by = ? WHERE id = ?`, `UPDATE iga_gov_approval SET decided_by = ? WHERE id = ?`,
			[]any{requester, ap.ID}, []any{d.approver, ap.ID}},
		{"approval expired", services.GovCodeApprovalExpired,
			`UPDATE iga_gov_approval SET expires_at = now() - interval '1 minute' WHERE id = ?`,
			`UPDATE iga_gov_approval SET expires_at = now() + interval '7 days' WHERE id = ?`,
			[]any{ap.ID}, []any{ap.ID}},
	} {
		p3exec(t, d.db, c.break_, c.args1...)
		dep := queue()
		d.mustRun("deploy", dep)
		dd := d.deployment(dep)
		if dd.State != models.GovDeployBlocked || !strings.HasPrefix(dd.StateReason, c.code) {
			t.Fatalf("%s: %s %q, want blocked %s", c.name, dd.State, dd.StateReason, c.code)
		}
		if len(d.fake.Calls) != calls {
			t.Fatalf("%s: AWS was written: %v", c.name, d.fake.Calls[calls:])
		}
		p3exec(t, d.db, c.mend, c.args2...)
	}
	dep := queue()
	d.mustRun("deploy", dep)
	if dd := d.deployment(dep); dd.State != models.GovDeployAppliedUnverified {
		t.Fatalf("removal with the approval in force: %s %q", dd.State, dd.StateReason)
	}
}

func bdbIDx(t *testing.T, d *dLab, q string, args ...any) uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	if err := d.db.Raw(q, args...).Scan(&ids).Error; err != nil || len(ids) != 1 {
		t.Fatalf("%s: %v %v", q, ids, err)
	}
	return ids[0]
}

// P1-10, undo through the real deploy job (§8.9, confirmed and kept):
// "Approval expiry and revocation do not disable undo, because undo
// returns to the state that existed before that approval took effect" --
// nor does the approver later losing governance:approve. The approval must
// still NAME the undo plan.
func TestP3FixApprUndoStaysPossibleAfterExpiry(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("FxaUndoRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	dep := d.applyAndVerify(x, s)
	p3exec(t, d.db, `UPDATE iga_gov_approval SET expires_at = now() - interval '1 day', revoked_at = now(), revoked_reason = 'superseded' WHERE id = ?`, s.approval)
	p3exec(t, d.db, `DELETE FROM role_permissions WHERE role_id IN (SELECT role_id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?)`, d.ws, d.approver)
	u, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{}, false)
	if err != nil {
		t.Fatalf("undo after expiry: %v", err)
	}
	d.mustRun("deploy", u.ID)
	if st := d.state(u.ID); st != models.GovDeployAppliedUnverified {
		t.Fatalf("undo after expiry, revocation and the approver's permission loss: %s %q", st, d.deployment(u.ID).StateReason)
	}
	if d.fake.BoundaryOf(x.name) != "" {
		t.Fatal("the undo did not remove the boundary")
	}
}

// fxaIsolation is a dedicated-identity version (Lambda subject) proposed
// and approved through the production routes (T3.17's lab), with the
// production IaC delivery handler behind the deploy job.
type fxaIsolation struct {
	l        *p3iLab
	policy   string
	version  uuid.UUID
	approval models.IGAGovApproval
	split    models.IGAGovPlan
	revert   models.IGAGovPlan
	dep      *services.GovDeployments
}

func fxaIsolated(t *testing.T, name string) *fxaIsolation {
	l := newP3iLab(t, name)
	srcName, roleID := "FxaSharedRole", "AROAFXASHAREDISO01"
	src := l.role(srcName, roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.live.mu.Lock()
	l.live.roles[src].TrustPolicyHash = p3iTrustHash
	l.live.mu.Unlock()
	l.publish()
	managed := l.a.policyARN(srcName + "Work")
	fn := strings.ToLower(srcName) + "-fn"
	fnARN := "arn:aws:lambda:us-east-1:" + accountA + ":function:" + fn
	workload := bdbID(t, l.p2Lab, `SELECT id FROM iga_workload WHERE workspace_id = ? AND source_key = ?`, l.ws, igagraph.Key("aws", fnARN))
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": fmt.Sprintf(p3iIsoTF, srcName, managed, fn)})
	l.grantWrite()
	policy, _ := l.isolate(srcName, roleID, "fxa-dedicated-role", workload.String(), igagov.BindingLambdaRole, fnARN)
	l.compile(policy, 2)
	l.approveAll(policy, 2)
	x := &fxaIsolation{l: l, policy: policy, version: l.versionID(policy, 2)}
	l.db.Where("workspace_id = ? AND version_id = ? AND revoked_at IS NULL", l.ws, x.version).Take(&x.approval)
	l.db.Where("workspace_id = ? AND version_id = ? AND kind = 'split' AND superseded_at IS NULL", l.ws, x.version).Take(&x.split)
	l.db.Where("workspace_id = ? AND version_id = ? AND kind = 'split_revert' AND superseded_at IS NULL", l.ws, x.version).Take(&x.revert)
	if x.split.ID == uuid.Nil || x.revert.ID == uuid.Nil || x.split.Delivery != igagov.DeliveryIaCPR {
		t.Fatalf("split %+v revert %+v", x.split.ID, x.revert.ID)
	}
	// The production delivery handler behind the real deploy job.
	prevLive := services.DefaultGovLiveReader()
	services.SetGovLiveReader(l.live)
	services.InstallGovIaCDeliveryHandlers(l.db)
	t.Cleanup(func() {
		services.RegisterGovDeliveryHandler(igagov.DeliveryIaCPR, nil)
		services.RegisterGovDeliveryHandler(igagov.DeliveryExport, nil)
		services.SetGovLiveReader(prevLive)
	})
	x.dep = services.NewGovDeployments(l.db, &services.GovDeployEnv{}).WithAuthoring(services.NewGovAuthoring(l.db, l.live))
	return x
}

func (x *fxaIsolation) queue(kind string, plan models.IGAGovPlan) uuid.UUID {
	id := uuid.New()
	p3exec(x.l.t, x.l.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')`, id, x.l.ws, x.version, plan.ID, plan.ControlID, x.approval.ID, kind, plan.Delivery)
	return id
}

// deploy runs the REAL deploy job (DeployHandler) for the deployment.
func (x *fxaIsolation) deploy(dep uuid.UUID) models.IGAGovDeployment {
	x.l.t.Helper()
	if err := x.dep.DeployHandler(context.Background(), x.l.run(repositories.GovJobDeploy, dep)); err != nil && !isRetryLater(err) {
		x.l.t.Fatalf("deploy job: %v", err)
	}
	return x.l.dep(dep)
}

// P1-10, split (a FORWARD plan) and split_revert (its inverse) through the
// real deploy job: a split needs the approval in force -- refused when the
// approver lost governance:approve or the approval expired -- and its
// stale evidence is REVALIDATED (the dedicated-identity version recompiled
// in memory: `unchanged`, recorded on the deployment); a split_revert, like
// any undo, stays possible after expiry.
//
// Fails on the base: the split ran with an approver who had lost
// governance:approve and with an expired approval, and was never
// revalidated (storedRightSize rejected dedicated-identity versions).
func TestP3FixApprSplitAuthorityAndRevalidation(t *testing.T) {
	x := fxaIsolated(t, "fxa-split")
	l := x.l
	approverRole := l.approver.role
	p3exec(t, l.db, `DELETE FROM role_permissions WHERE role_id = ?`, approverRole)
	d := x.deploy(x.queue("split", x.split))
	if d.State != models.GovDeployBlocked || !strings.HasPrefix(d.StateReason, services.GovCodeApprovalInvalid) {
		t.Fatalf("split after the approver lost governance:approve: %s %q", d.State, d.StateReason)
	}
	p3exec(t, l.db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'`, approverRole)

	p3exec(t, l.db, `UPDATE iga_gov_approval SET expires_at = now() - interval '1 minute' WHERE id = ?`, x.approval.ID)
	d = x.deploy(x.queue("split", x.split))
	if d.State != models.GovDeployBlocked || !strings.HasPrefix(d.StateReason, services.GovCodeApprovalExpired) {
		t.Fatalf("split with an expired approval: %s %q", d.State, d.StateReason)
	}
	// The inverse stays possible after expiry (§8.9).
	r := x.deploy(x.queue("split_revert", x.revert))
	if r.State == models.GovDeployBlocked && (strings.HasPrefix(r.StateReason, services.GovCodeApprovalExpired) ||
		strings.HasPrefix(r.StateReason, services.GovCodeApprovalRequired) || strings.HasPrefix(r.StateReason, services.GovCodeApprovalInvalid)) {
		t.Fatalf("split_revert after expiry: %s %q", r.State, r.StateReason)
	}
	p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'failed', state_reason = 'test: released' WHERE id = ?`, r.ID)
	p3exec(t, l.db, `UPDATE iga_gov_approval SET expires_at = now() + interval '7 days' WHERE id = ?`, x.approval.ID)

	// A newer scan makes the split's evidence stale: the deploy job
	// revalidates it (dedicated-identity recompile) as unchanged and
	// proceeds on the APPROVED plan.
	l.publish()
	if ok, reasons, ferr := services.NewGovAuthoring(l.db, l.live).EvidenceFreshness(context.Background(), l.ws, x.split.ID); ferr != nil || ok {
		t.Fatalf("the split's evidence should be stale after a newer scan: %v %v %v", ok, reasons, ferr)
	}
	d = x.deploy(x.queue("split", x.split))
	var rvs []models.IGAGovRevalidation
	l.db.Where("workspace_id = ? AND plan_id = ?", l.ws, x.split.ID).Order("created_at").Find(&rvs)
	if len(rvs) != 1 || rvs[0].Result != models.GovRevalidationUnchanged {
		raw, _ := json.Marshal(rvs)
		t.Fatalf("split revalidations: %s (deployment %s %q)", raw, d.State, d.StateReason)
	}
	if d.RevalidationID == nil || *d.RevalidationID != rvs[0].ID || d.State != models.GovDeployAwaitingMerge {
		t.Fatalf("split after revalidation: %s %q revalidation %v", d.State, d.StateReason, d.RevalidationID)
	}
	var cur models.IGAGovPlan
	l.db.First(&cur, "id = ?", x.split.ID)
	if cur.SupersededAt != nil {
		t.Fatal("an unchanged revalidation superseded the approved split")
	}
}

// p3rClean builds a clean canary window for roleID: one successful
// management event per retained service an hour after `at`, and a trail read
// covering the window. (It lived in p3_rollout_test.go until fix/p3-roll moved
// the rollout tests onto stored CloudTrail; these approval tests still feed
// the facts directly.)
func p3rClean(roleID string, at time.Time, retained ...string) ([]igagov.TrailEvent, []igagov.TrailRead) {
	var evs []igagov.TrailEvent
	for _, s := range retained {
		evs = append(evs, igagov.TrailEvent{EventTime: at.Add(time.Hour), PrincipalID: roleID, SessionName: "workload",
			EventSource: s + ".amazonaws.com", EventName: "DescribeP3a"})
	}
	return evs, []igagov.TrailRead{{From: at.Add(-time.Hour), To: time.Now().Add(time.Hour)}}
}
