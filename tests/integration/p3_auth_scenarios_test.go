package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func p3aGovErr(err error) *services.GovError {
	var ge *services.GovError
	if errors.As(err, &ge) {
		return ge
	}
	return nil
}

func p3aChangeItems(ch []services.GovChange) []string {
	var out []string
	for _, c := range ch {
		out = append(out, c.Item)
	}
	sort.Strings(out)
	return out
}

func p3aHas(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// A53 (b) and A62, from findings: a proposal seeded by the role's
// unused_service findings (which go under review) removes ecr, whose
// policy-bearing forms AuthSec does not collect -- the bundle is partial
// with one gap per form. Approval is refused until every gap is accepted
// (409 evidence_gaps_not_accepted), then stores one row per item. Unchanged
// rescans revalidate as unchanged and keep the approval and its
// acceptances; a new uncollected form (the role gains logs) is a material
// change naming the unanalysed set, revokes the approval, and the new
// approval needs its own acceptances.
//
// Safeguards (mutation-checked): the gap check; the unanalysed set being
// material; revalidation never rewriting the approved plan.
func TestP3T313GapsAcceptancesAndRevalidation(t *testing.T) {
	l := newP3aLab(t, "p3-t313-gaps")
	arn := l.role("GapRole", "AROAGAPROLE0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "ecr": nil})
	l.publish()
	var fids []string
	l.db.Raw(`SELECT id::text FROM iga_gov_finding WHERE workspace_id = ? AND kind = 'unused_service' AND role_id = 'AROAGAPROLE0001'
	           ORDER BY detail_key`, l.ws).Scan(&fids)
	if len(fids) != 2 {
		t.Fatalf("unused_service findings %v, want ecr and sqs", fids)
	}
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"from": map[string]any{"finding_ids": fids}})
	d := l.must(code, body, http.StatusCreated, "proposal from findings")
	policy := d["policy"].(map[string]any)["id"].(string)
	if ev := d["evidence"].(map[string]any); ev["trust"] != igagov.TrustPartial || len(ev["gaps"].([]any)) != 2 {
		t.Fatalf("evidence %v, want partial with the two ecr gaps", ev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND status = 'under_review'`, l.ws); n != 2 {
		t.Fatalf("%d findings under review, want 2", n)
	}
	var intent igagov.RightSizeIntent
	_ = json.Unmarshal(mustJSON(t, d["version"].(map[string]any)["intent"]), &intent)
	if len(intent.FindingIDs) != 2 || len(intent.Remove) != 2 {
		t.Fatalf("intent %+v", intent)
	}

	plans := l.compile(policy, 1)
	if got := p3aItemKeys(plans, services.GovAcceptGap); strings.Join(got, ",") != "unanalysed_form:ecr_registry,unanalysed_form:ecr_repository" {
		t.Fatalf("gap items %v", got)
	}
	if got := p3aItemKeys(plans, services.GovAcceptUnanalysed); strings.Join(got, ",") != "other_accounts" {
		t.Fatalf("unanalysed items %v (the ecr forms are gaps, never asked twice)", got)
	}
	code, body = l.approve(l.approver, policy, 1, p3aApproveBody(plans, func(it map[string]any) bool { return it["kind"] == services.GovAcceptUnanalysed }))
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeGapsNotAccepted {
		t.Fatalf("approve without the gaps: %d %v, want 409 evidence_gaps_not_accepted", code, body)
	}
	l.approveAll(policy, 1)
	if n := l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ? AND kind = 'evidence_gap'`, l.ws); n != 2 {
		t.Fatalf("%d evidence_gap acceptances", n)
	}
	ap := l.applyPlan(policy, 1)
	planID := uuid.MustParse(ap["id"].(string))
	approved := ap["plan_hash"].(string)
	vid := l.versionID(policy, 1)

	// Unchanged rescans (A59 / A62): three revalidations, all unchanged.
	svc := l.authoring()
	var lastRV uuid.UUID
	for i := 0; i < 3; i++ {
		l.publish()
		if fresh, why, _ := svc.EvidenceFreshness(context.Background(), l.ws, planID); fresh || !p3aHas(why, "newer_scan_published") {
			t.Fatalf("after a rescan the evidence reads fresh (%v %v)", fresh, why)
		}
		if _, err := svc.UsableApproval(context.Background(), l.ws, vid, []uuid.UUID{planID}); p3aGovErr(err) == nil ||
			p3aGovErr(err).Code != services.GovCodeRevalidationNeeded {
			t.Fatalf("stale evidence without revalidation: %v, want revalidation_required", err)
		}
		rv, err := svc.Revalidate(context.Background(), l.ws, planID)
		if err != nil {
			t.Fatal(err)
		}
		if rv.Revalidation.Result != models.GovRevalidationUnchanged || len(rv.NewPlanIDs) != 0 {
			t.Fatalf("rescan %d: %s %v", i, rv.Revalidation.Result, p3aChangeItems(rv.Changes))
		}
		lastRV = rv.Revalidation.ID
	}
	u, err := svc.UsableApproval(context.Background(), l.ws, vid, []uuid.UUID{planID})
	if err != nil || u.Revalidations[planID] == nil || *u.Revalidations[planID] != lastRV {
		t.Fatalf("usable after unchanged revalidations: %+v %v", u, err)
	}
	if l.status(policy, 1) != "approved" || l.applyPlan(policy, 1)["plan_hash"] != approved ||
		l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ? AND revoked_at IS NULL`, l.ws) != 1 ||
		l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ?`, l.ws) != 3 {
		t.Fatal("an unchanged revalidation touched the approval, the plan or the acceptances")
	}
	if l.count(`SELECT count(*) FROM iga_gov_revalidation WHERE workspace_id = ? AND result = 'unchanged'`, l.ws) != 3 {
		t.Fatal("want three unchanged revalidation rows")
	}

	// A new uncollected form: the role now uses logs (its forms are not
	// collected), a material change naming the unanalysed set.
	l.a.managed("GapRoleWork", p3aDoc("ecr", "logs", "s3", "sqs"))
	l.activity(l.a).set(arn, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "ecr": nil, "logs": p3eTime(time.Hour)})
	l.publish()
	rv, err := svc.Revalidate(context.Background(), l.ws, planID)
	if err != nil {
		t.Fatal(err)
	}
	items := p3aChangeItems(rv.Changes)
	if rv.Revalidation.Result != models.GovRevalidationMaterialChange || !p3aHas(items, "unanalysed") || len(rv.NewPlanIDs) != 2 {
		t.Fatalf("new form: %s %v %v", rv.Revalidation.Result, items, rv.NewPlanIDs)
	}
	if l.status(policy, 1) != "in_review" || l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ? AND revoked_at IS NULL`, l.ws) != 0 {
		t.Fatal("a material change left the approval in force")
	}
	if l.count(`SELECT count(*) FROM iga_gov_plan WHERE id = ? AND plan_hash = ? AND superseded_at IS NOT NULL`, planID, approved) != 1 {
		t.Fatal("the approved plan was rewritten instead of superseded")
	}
	if _, err := svc.UsableApproval(context.Background(), l.ws, vid, []uuid.UUID{planID}); p3aGovErr(err) == nil ||
		p3aGovErr(err).Code != services.GovCodeApprovalRequired {
		t.Fatalf("usable after material change: %v", err)
	}
	newPlans := l.plans(policy, 1)
	if got := p3aItemKeys(newPlans, services.GovAcceptUnanalysed); !p3aHas(got, "unanalysed_form:logs_destination") {
		t.Fatalf("new unanalysed items %v", got)
	}
	// The old acceptances do not carry over.
	old := p3aApproveBody(plans, nil)
	if code, body = l.approve(l.approver, policy, 1, old); code != http.StatusConflict {
		t.Fatalf("approve with the old plan: %d %v, want 409", code, body)
	}
	l.approveAll(policy, 1)
	if n := l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ?`, l.ws); n != 3+int64(len(newPlans["acceptance_items"].([]any))) {
		t.Fatalf("%d acceptance rows, want the 3 old ones kept and one per new item", n)
	}
	if l.events("plan_revalidated") != 4 || l.events("approval_revoked") != 1 {
		t.Fatalf("events revalidated=%d revoked=%d", l.events("plan_revalidated"), l.events("approval_revoked"))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// p3aQueueObservation records, for a scan, an sqs queue policy granting the
// role ARN sqs:SendMessage (a route the boundary limits, §3.4).
func (l *p3aLab) queueObservation(run uuid.UUID, roleARN string) {
	l.t.Helper()
	doc := `{"Version":"2012-10-17","Statement":[{"Sid":"Refunds","Effect":"Allow","Principal":{"AWS":"` + roleARN +
		`"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:` + accountA + `:refunds"}]}`
	canon, hash, err := igagov.CanonicalDocument(doc)
	if err != nil {
		l.t.Fatal(err)
	}
	p3exec(l.t, l.db, `INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)
	                   ON CONFLICT DO NOTHING`, l.ws, hash, string(canon), string(canon))
	p3exec(l.t, l.db, `INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn,
	                     policy_present, document_hash, parse_state, read_at)
	                   VALUES (?, ?, 'sqs_queue', 'us-east-1', ?, true, ?, 'parsed', now())`,
		l.ws, run, "arn:aws:sqs:us-east-1:"+accountA+":refunds", hash)
}

// publishWith is publish with a hook between the scan and the projection.
func (l *p3aLab) publishWith(between func(run uuid.UUID)) uuid.UUID {
	l.t.Helper()
	run := l.scanOnly(l.a)
	p3eCompleteCoverage(l.t, l.p3eLab, l.a, run.ID)
	if between != nil {
		between(run.ID)
	}
	l.projectOnly()
	return run.ID
}

// A38, A59 (API part) and A23. Compiled against scan N, whose queue policy
// names the role: an unchanged rescan revalidates unchanged; a rescan that
// no longer sees the queue policy is a material change naming the routes,
// the plan keeps reading scan N (whose observations are untouched), and the
// approval is revoked. After re-approval, a new workload running as the
// role is found by the compile_plans job (revalidation of an approved
// version): material change naming the consumers, the owner-review hook is
// called for the impact change, approving the old hashes is 409
// impact_changed, and the approval is no longer usable.
//
// Safeguards (mutation-checked): revalidation compares material hashes, not
// plan hashes; the impact-change hook; approval revocation on material change.
func TestP3T313RevalidationScanRoutesAndConsumers(t *testing.T) {
	l := newP3aLab(t, "p3-t313-reval")
	arn := l.role("QueueRole", "AROAQUEUEROLE01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	runN := l.publishWith(func(run uuid.UUID) { l.queueObservation(run, arn) })
	policy, _ := l.proposeTemplate("AROAQUEUEROLE01")
	l.compile(policy, 1)
	ap := l.applyPlan(policy, 1)
	if ap["resource_policy_scan_run_id"] != runN.String() {
		t.Fatalf("plan scan %v, want %s", ap["resource_policy_scan_run_id"], runN)
	}
	var im igagov.Impact
	_ = json.Unmarshal(mustJSON(t, ap["impact"]), &im)
	if len(im.Routes) != 1 || im.Routes[0].Effect != igagov.RouteEffectLimited {
		t.Fatalf("impact routes %+v, want the queue route (limited by the boundary)", im.Routes)
	}
	l.approveAll(policy, 1)
	planID := uuid.MustParse(ap["id"].(string))
	svc := l.authoring()

	// Unchanged rescan (same queue policy).
	l.publishWith(func(run uuid.UUID) { l.queueObservation(run, arn) })
	rv, err := svc.Revalidate(context.Background(), l.ws, planID)
	if err != nil || rv.Revalidation.Result != models.GovRevalidationUnchanged {
		t.Fatalf("unchanged rescan: %+v %v", rv, err)
	}
	// A38: the next rescan no longer sees the queue policy.
	obsN := l.count(`SELECT count(*) FROM cloud_resource_policy_observation WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, runN)
	l.publish()
	rv, err = svc.Revalidate(context.Background(), l.ws, planID)
	if err != nil {
		t.Fatal(err)
	}
	if rv.Revalidation.Result != models.GovRevalidationMaterialChange || !p3aHas(p3aChangeItems(rv.Changes), "routes") {
		t.Fatalf("queue policy gone: %s %v", rv.Revalidation.Result, p3aChangeItems(rv.Changes))
	}
	if n := l.count(`SELECT count(*) FROM cloud_resource_policy_observation WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, runN); n != obsN || n != 1 {
		t.Fatalf("scan N observations %d, want unchanged (%d)", n, obsN)
	}
	if l.count(`SELECT count(*) FROM iga_gov_plan WHERE id = ? AND resource_policy_scan_run_id = ?`, planID, runN) != 1 {
		t.Fatal("the approved plan stopped naming scan N")
	}
	newApply := l.applyPlan(policy, 1)
	if newApply["plan_hash"] == ap["plan_hash"] || newApply["id"] == ap["id"] {
		t.Fatal("the recompiled plan was not stored as a new plan")
	}
	if l.status(policy, 1) != "in_review" {
		t.Fatalf("status %s after a material change", l.status(policy, 1))
	}

	// Re-approve, then A23: a new workload starts running as the role.
	l.approveAll(policy, 1)
	stale := l.plans(policy, 1)
	owner := l.member("newowner", "read")
	p3eAddLambda(l.a, "us-east-1", "refund-reconciler", arn)
	l.publish()
	l.owner(models.GovObjectWorkload, l.workloadID("refund-reconciler"), owner.user)

	var changes []services.GovImpactChange
	hooked := l.authoring().WithHooks(services.GovAuthoringHooks{OnImpactChanged: func(tx *gorm.DB, c services.GovImpactChange) error {
		changes = append(changes, c)
		return nil
	}})
	if err := l.db.Transaction(func(tx *gorm.DB) error {
		_, err := services.EnqueueCompilePlansTx(tx, l.ws, l.versionID(policy, 1), nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := services.NewPolicyJobWorker(l.db, "p3a-worker").WithGate(func() bool { return true })
	w.Register(services.PolicyJobKind{Kind: repositories.GovJobCompilePlans, Handler: hooked.CompilePlansHandler})
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("compile_plans: worked=%v err=%v", worked, err)
	}
	var job models.IGAGovJob
	l.db.Where("workspace_id = ? AND kind = 'compile_plans'", l.ws).Take(&job)
	if job.Status != models.GovJobComplete {
		t.Fatalf("job %s: %s", job.Status, job.LastError)
	}
	var last models.IGAGovRevalidation
	l.db.Where("workspace_id = ?", l.ws).Order("created_at DESC").Take(&last)
	var lastChanges []services.GovChange
	_ = json.Unmarshal(last.Changes, &lastChanges)
	if last.Result != models.GovRevalidationMaterialChange || !p3aHas(p3aChangeItems(lastChanges), "consumers") {
		t.Fatalf("new consumer: %s %v", last.Result, p3aChangeItems(lastChanges))
	}
	if len(changes) != 1 || changes[0].Source != "revalidation" || len(changes[0].NewImpact.Consumers) != 2 || len(changes[0].OldImpact.Consumers) != 1 {
		t.Fatalf("impact-change hook: %+v", changes)
	}
	code, body := l.approve(l.approver, policy, 1, p3aApproveBody(stale, nil))
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeImpactChanged {
		t.Fatalf("approve the old impact: %d %v, want 409 impact_changed", code, body)
	}
	if _, err := svc.UsableApproval(context.Background(), l.ws, l.versionID(policy, 1), nil); p3aGovErr(err) == nil {
		t.Fatal("the approval stayed usable after the impact changed")
	}

	// The job on an in-review version recompiles (no revalidation row).
	if err := l.db.Transaction(func(tx *gorm.DB) error {
		_, err := services.EnqueueCompilePlansTx(tx, l.ws, l.versionID(policy, 1), nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before := l.count(`SELECT count(*) FROM iga_gov_revalidation WHERE workspace_id = ?`, l.ws)
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("compile_plans (in review): worked=%v err=%v", worked, err)
	}
	if l.events("plans_recompiled") != 1 || l.count(`SELECT count(*) FROM iga_gov_revalidation WHERE workspace_id = ?`, l.ws) != before {
		t.Fatal("an in-review version was not recompiled by the job")
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_plan WHERE workspace_id = ? AND superseded_at IS NULL`, l.ws); n != 2 {
		t.Fatalf("%d current plans, want one apply and one undo", n)
	}
}

// A7 (versions immutable), A20 (one policy per role), concurrency and
// intent validation: editing an approved version creates the next version;
// the old approval is the old version's and never applies to the new one;
// a stale base_version_no is 409 version_conflict; two concurrent edits
// produce one version; two concurrent approvals produce one approval;
// approving the new version supersedes the old one and revokes its approval;
// a role another policy controls is 409 role_controlled_by_policy, both
// for a proposal and for a version of another policy.
//
// Safeguards (mutation-checked): base_version_no; the one-control-per-role
// check; supersession revoking the old approval.
func TestP3T311VersionsControlsAndConcurrency(t *testing.T) {
	l := newP3aLab(t, "p3-t311-versions")
	l.role("LabRightSizeRole", "AROALABRIGHT001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.role("OtherRole", "AROAOTHERROLE01", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	policy, d := l.proposeTemplate("AROALABRIGHT001")
	l.compile(policy, 1)
	l.approveAll(policy, 1)
	v1 := l.versionID(policy, 1)

	// A20: a second policy for the controlled role.
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []map[string]any{{"provider": "aws", "role_id": "AROALABRIGHT001"}}})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeRoleControlled ||
		body["error"].(map[string]any)["detail"].(map[string]any)["policy_id"] != policy {
		t.Fatalf("second policy for a controlled role: %d %v, want 409 role_controlled_by_policy naming %s", code, body, policy)
	}
	other, od := l.proposeTemplate("AROAOTHERROLE01")
	var oi map[string]any
	_ = json.Unmarshal(mustJSON(t, od["version"].(map[string]any)["intent"]), &oi)
	var li map[string]any
	_ = json.Unmarshal(mustJSON(t, d["version"].(map[string]any)["intent"]), &li)
	oi["subjects"] = append(oi["subjects"].([]any), li["subjects"].([]any)...)
	code, body = l.call(l.author, http.MethodPost, "/policies/"+other+"/versions", map[string]any{"intent": oi, "base_version_no": 1})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeRoleControlled {
		t.Fatalf("a version of another policy naming the role: %d %v", code, body)
	}

	// Editing a draft that was never proposed: the new version keeps the
	// planned control (it is not released by the older draft's withdrawal).
	var own map[string]any
	_ = json.Unmarshal(mustJSON(t, od["version"].(map[string]any)["intent"]), &own)
	own["observation_days"] = 10
	code, body = l.call(l.author, http.MethodPost, "/policies/"+other+"/versions", map[string]any{"intent": own, "base_version_no": 1})
	l.must(code, body, http.StatusCreated, "edit a draft")
	if l.status(other, 1) != "withdrawn" || l.count(`SELECT count(*) FROM iga_gov_control c JOIN iga_gov_target t ON t.control_id = c.id
	      WHERE t.version_id = ? AND c.state = 'planned'`, l.versionID(other, 2)) != 1 {
		t.Fatal("editing a draft released the planned control the new version uses")
	}
	// The owner-retain seam T3.12 calls: retaining a removed service makes
	// the next version (the owner its author); retaining every removal is 422.
	// Only an owner of a subject may retain (fix/p3-tidy: the retain is
	// scoped to the subjects the actor owns), so the actor owns OtherRole.
	err := l.db.Transaction(func(tx *gorm.DB) error {
		_, err := l.authoring().RetainVersionTx(tx, l.ws, l.second.user, l.versionID(other, 2),
			[]igagov.RetainEntry{{Service: "s3", Reason: "exports", ReviewBy: "2027-01-15"}})
		return err
	})
	if !errors.Is(err, services.ErrNotReviewOwner) {
		t.Fatalf("retain by a non-owner: %v, want ErrNotReviewOwner", err)
	}
	wireOwner(t, l, models.GovObjectIdentityAccount, bdbIdentity(t, l.p2Lab, "OtherRole"), l.second.user)
	err = l.db.Transaction(func(tx *gorm.DB) error {
		_, err := l.authoring().RetainVersionTx(tx, l.ws, l.second.user, l.versionID(other, 2),
			[]igagov.RetainEntry{{Service: "sqs", Reason: "nightly job", ReviewBy: "2027-01-15"}})
		return err
	})
	if ge := p3aGovErr(err); ge == nil || ge.Code != services.GovCodeNothingToRemove {
		t.Fatalf("retain every removal: %v", err)
	}
	err = l.db.Transaction(func(tx *gorm.DB) error {
		v, err := l.authoring().RetainVersionTx(tx, l.ws, l.second.user, l.versionID(other, 2),
			[]igagov.RetainEntry{{Service: "s3", Reason: "exports", ReviewBy: "2027-01-15"}})
		if err == nil && (v.No != 3 || v.CreatedBy != l.second.user || !strings.Contains(string(v.Intent), `"basis":"owner"`)) {
			return fmt.Errorf("retain version %+v", v)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Intent validation: 422 with field errors.
	bad := map[string]any{}
	_ = json.Unmarshal(mustJSON(t, li), &bad)
	bad["remove"].([]any)[0].(map[string]any)["qualified_days"] = 3
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions", map[string]any{"intent": bad, "base_version_no": 1})
	if code != http.StatusUnprocessableEntity || p3eErr(body) != services.GovCodeInvalidIntent ||
		!strings.Contains(fmt.Sprint(body["error"].(map[string]any)["detail"]), "remove[0].qualified_days") {
		t.Fatalf("invalid intent: %d %v", code, body)
	}

	// A7: editing the approved version creates version 2.
	li["observation_days"] = 14
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions", map[string]any{"intent": li, "base_version_no": 1})
	v2d := l.must(code, body, http.StatusCreated, "new version")
	if v2d["no"] != float64(2) || v2d["status"] != "draft" || v2d["intent_hash"] == d["version"].(map[string]any)["intent_hash"] {
		t.Fatalf("version 2: %v", v2d)
	}
	if l.status(policy, 1) != "approved" {
		t.Fatal("version 1 lost its approval when version 2 was drafted")
	}
	if _, err := l.authoring().UsableApproval(context.Background(), l.ws, l.versionID(policy, 2), nil); p3aGovErr(err) == nil ||
		p3aGovErr(err).Code != services.GovCodeApprovalRequired {
		t.Fatalf("version 1's approval applied to version 2: %v", err)
	}
	if err := l.db.Exec(`UPDATE iga_gov_policy_version SET intent = '{}' WHERE id = ?`, v1).Error; err == nil {
		t.Fatal("an approved version's intent was updated")
	}
	// A stale base.
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions", map[string]any{"intent": li, "base_version_no": 1})
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeVersionConflict {
		t.Fatalf("stale base_version_no: %d %v", code, body)
	}
	// Two concurrent edits of version 2: one version 3.
	li["observation_days"] = 21
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions", map[string]any{"intent": li, "base_version_no": 2})
		}(i)
	}
	wg.Wait()
	sort.Ints(codes)
	if codes[0] != http.StatusCreated || codes[1] != http.StatusConflict {
		t.Fatalf("concurrent edits: %v, want one 201 and one 409", codes)
	}
	if l.status(policy, 2) != "withdrawn" || l.status(policy, 3) != "draft" {
		t.Fatalf("v2 %s v3 %s, want the older draft withdrawn", l.status(policy, 2), l.status(policy, 3))
	}
	// Proposing an approved version is refused: an edit is a new version.
	if code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions/1/propose", nil); code != http.StatusConflict {
		t.Fatalf("propose approved v1: %d %v", code, body)
	}
	plans := l.compile(policy, 3)
	// Two concurrent approvals: one wins.
	for i, m := range []p3aMember{l.approver, l.second} {
		wg.Add(1)
		go func(i int, m p3aMember) {
			defer wg.Done()
			codes[i], _ = l.approve(m, policy, 3, p3aApproveBody(plans, nil))
		}(i, m)
	}
	wg.Wait()
	sort.Ints(codes)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict {
		t.Fatalf("concurrent approvals: %v, want one 200 and one 409", codes)
	}
	if l.status(policy, 1) != "superseded" || l.status(policy, 3) != "approved" {
		t.Fatalf("v1 %s v3 %s", l.status(policy, 1), l.status(policy, 3))
	}
	var reason string
	l.db.Raw(`SELECT revoked_reason FROM iga_gov_approval WHERE version_id = ?`, v1).Row().Scan(&reason)
	if !strings.Contains(reason, "superseded") {
		t.Fatalf("v1 approval revoked_reason %q", reason)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ? AND revoked_at IS NULL`, l.ws); n != 1 {
		t.Fatalf("%d live approvals", n)
	}

	// Reads: list, detail, versions.
	code, body = l.call(l.author, http.MethodGet, "/policies?limit=1", nil)
	if code != http.StatusOK || len(p3eList(body)) != 1 || p3eMeta(body, "next_cursor") == nil {
		t.Fatalf("list page 1: %d %v", code, body)
	}
	code, body = l.call(l.author, http.MethodGet, "/policies?limit=1&cursor="+p3eMeta(body, "next_cursor").(string), nil)
	if code != http.StatusOK || len(p3eList(body)) != 1 || p3eMeta(body, "next_cursor") != nil {
		t.Fatalf("list page 2: %d %v", code, body)
	}
	code, body = l.call(l.author, http.MethodGet, "/policies/"+policy, nil)
	pd := l.must(code, body, http.StatusOK, "policy detail")
	if pd["approved_version_no"] != float64(3) || pd["status"] != "approved" || pd["next_action"] != "rollout" || len(pd["controls"].([]any)) != 1 {
		t.Fatalf("policy detail %v", pd)
	}
	code, body = l.call(l.author, http.MethodGet, "/policies/"+policy+"/versions", nil)
	if code != http.StatusOK || len(p3eList(body)) != 3 {
		t.Fatalf("versions: %d %v", code, body)
	}
}

// A9 and A52: a role granted sqs by two policies (PolicyA sqs:*, PolicyB
// sqs:SendMessage). Opened from the graph assignment of PolicyA, the
// proposal lists PolicyB under independent grants (never PolicyA's edge as
// the only access); the boundary removes sqs whichever policy grants it,
// both grants stay declared (no op touches them) and both statements enter
// the impact.
func TestP3T311IndependentGrantsAndDuplicateGrants(t *testing.T) {
	l := newP3aLab(t, "p3-t311-grants")
	arn := l.role("DupRole", "AROADUPROLE0001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	polA := l.a.managed("PolicyA", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"arn:aws:sqs:us-east-1:`+accountA+`:refunds"}]}`)
	polB := l.a.managed("PolicyB", `{"Version":"2012-10-17","Statement":[{"Sid":"B","Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:`+accountA+`:refunds"}]}`)
	l.a.attach("DupRole", polA)
	l.a.attach("DupRole", polB)
	_ = arn
	l.publish()
	ident := bdbIdentity(t, l.p2Lab, "DupRole")
	assign := bdbID(t, l.p2Lab, `SELECT a.id FROM iga_policy_assignment a JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
	                              WHERE a.workspace_id = ? AND a.holder_identity_account_id = ? AND p.native_ref = ? AND a.state <> 'ended'`, l.ws, ident, polA)
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"context": map[string]any{"object_id": assign.String()}})
	d := l.must(code, body, http.StatusCreated, "proposal from a graph assignment")
	rec := d["recommendation"].(map[string]any)
	if c, _ := rec["context"].(map[string]any); c["policy_arn"] != polA || c["object_kind"] != "assignment" {
		t.Fatalf("context %v", rec["context"])
	}
	var indep []string
	for _, x := range rec["independent_grants"].([]any) {
		g := x.(map[string]any)
		indep = append(indep, g["policy_arn"].(string)+":"+strings.Join(p3aStrings(g["services"]), ","))
	}
	if !p3aHas(indep, polB+":sqs") || strings.Contains(strings.Join(indep, " "), polA) {
		t.Fatalf("independent grants %v, want PolicyB (and the role's own) but never the selected PolicyA", indep)
	}
	policy := d["policy"].(map[string]any)["id"].(string)
	l.compile(policy, 1)
	ap := l.applyPlan(policy, 1)
	var im igagov.Impact
	_ = json.Unmarshal(mustJSON(t, ap["impact"]), &im)
	if len(im.StatementRevisions) < 3 { // the role's own Work statement, A and B
		t.Fatalf("statement revisions %v, want every statement granting sqs", im.StatementRevisions)
	}
	for _, x := range ap["operations"].([]any) {
		if pa := x.(map[string]any)["policy_arn"]; pa == polA || pa == polB {
			t.Fatalf("an op touches a grant: %v", x)
		}
	}
	if !strings.Contains(fmt.Sprint(ap["desired_document"]), "NotAction:[sqs:*]") {
		t.Fatalf("desired document %v", ap["desired_document"])
	}
	facts, err := json.Marshal(d["evidence"])
	if err != nil {
		t.Fatal(err)
	}
	var grants int64
	l.db.Raw(`SELECT count(*) FROM iga_gov_evidence_bundle b, jsonb_array_elements(b.facts->'grants') g
	           WHERE b.workspace_id = ? AND b.id = ?::uuid AND g->>'policy_arn' IN (?, ?)`, l.ws, d["evidence"].(map[string]any)["bundle_id"], polA, polB).Scan(&grants)
	if grants != 2 {
		t.Fatalf("bundle grants of A and B: %d (%s)", grants, facts)
	}
}

// A53 (a, c), live-read failure, withdrawal, archive, permissions and
// workspace isolation: an untrusted (stale) activity report is 422
// evidence_untrusted naming the source with the Connections remedy and
// creates nothing; a Kubernetes key is 422 target_not_supported with K-1;
// a failed live read is 503 discovery_unavailable and writes nothing;
// withdraw returns the findings to open and releases the planned control;
// archive refuses while a control is active; another workspace's ids are 404
// on every route; the author/approve permissions and the verified-human rule
// hold.
func TestP3T311TrustLiveWithdrawArchiveIsolation(t *testing.T) {
	l := newP3aLab(t, "p3-t311-misc")
	l.role("StaleRole", "AROASTALEROLE01", map[string]*time.Time{"s3": p3eTime(40 * time.Hour), "sqs": nil})
	act := l.activity(l.a)
	act.completed = time.Now().Add(-30 * time.Hour)
	l.publish()
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []map[string]any{{"provider": "aws", "role_id": "AROASTALEROLE01"}}})
	if code != http.StatusUnprocessableEntity || p3eErr(body) != services.GovCodeEvidenceUntrusted ||
		!strings.Contains(fmt.Sprint(body), "/iga/connections/"+l.a.conn.String()+"/coverage") {
		t.Fatalf("stale evidence: %d %v", code, body)
	}
	code, body = l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []map[string]any{{"provider": "k8s", "cluster_uid": "c-1", "namespace": "pay", "service_account": "pay"}}})
	if code != http.StatusUnprocessableEntity || p3eErr(body) != services.GovCodeTargetNotSupported ||
		body["error"].(map[string]any)["detail"].(map[string]any)["prerequisite"] != "K-1" {
		t.Fatalf("kubernetes key: %d %v", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_policy WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d policies created by refused proposals", n)
	}

	act.completed = time.Now().Add(-2 * time.Hour)
	l.publish()
	policy, _ := l.proposeTemplate("AROASTALEROLE01")
	l.live.fail = errors.New("AccessDenied: iam:GetRole")
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions/1/propose", nil)
	if code != http.StatusServiceUnavailable || p3eErr(body) != services.GovCodeDiscoveryUnavail {
		t.Fatalf("failed live read: %d %v", code, body)
	}
	if l.status(policy, 1) != "draft" || l.count(`SELECT count(*) FROM iga_gov_plan WHERE workspace_id = ?`, l.ws) != 0 {
		t.Fatal("a failed live read wrote plans or moved the version")
	}
	l.live.fail = nil

	// Permissions and the verified-human rule.
	reader := l.token(l.ws, l.author, "governance:read")
	if code, _ = l.callAs(reader, http.MethodPost, "/policies/"+policy+"/versions/1/propose", nil); code != http.StatusForbidden {
		t.Fatalf("propose without governance:author: %d", code)
	}
	if code, _ = l.callAs(l.token(l.ws, l.approver, "governance:read governance:author"), http.MethodPost,
		"/policies/"+policy+"/versions/1/approve", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("approve without governance:approve: %d", code)
	}
	machine := l.token(l.ws, p3aMember{user: uuid.New()}, p3aAllScopes)
	if code, body = l.callAs(machine, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services"}); code != http.StatusForbidden {
		t.Fatalf("a service token authors: %d %v", code, body)
	}

	// Another workspace: every route 404s, lists are empty.
	ows := newWorkspace(t, l.db, "p3-t311-misc-other")
	om := p3aMember{user: uuid.New(), membership: uuid.New(), role: uuid.New()}
	p3exec(t, l.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, 'other', ?)`, om.user, om.user.String()+"@p3a.test", ows)
	p3exec(t, l.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, 'p3a-other', ?)`, om.role, ows)
	p3exec(t, l.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, 'active')`, om.membership, ows, om.user, om.role)
	t.Cleanup(func() {
		l.db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, ows.String())
		l.db.Exec(`DELETE FROM workspace_memberships WHERE id = ?`, om.membership)
		l.db.Exec(`DELETE FROM users WHERE id = ?`, om.user)
		l.db.Exec(`DELETE FROM roles WHERE id = ?`, om.role)
	})
	ot := l.token(ows, om, p3aAllScopes)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/policies/" + policy}, {http.MethodPatch, "/policies/" + policy},
		{http.MethodGet, "/policies/" + policy + "/versions"}, {http.MethodGet, "/policies/" + policy + "/versions/1"},
		{http.MethodGet, "/policies/" + policy + "/versions/1/plans"}, {http.MethodPost, "/policies/" + policy + "/versions/1/propose"},
		{http.MethodPost, "/policies/" + policy + "/versions/1/approve"}, {http.MethodPost, "/policies/" + policy + "/versions/1/reject"},
		{http.MethodPost, "/policies/" + policy + "/versions/1/withdraw"}, {http.MethodPost, "/policies/" + policy + "/archive"},
		{http.MethodPost, "/policies/" + policy + "/pause"}, {http.MethodPost, "/policies/" + policy + "/versions"},
	} {
		body := map[string]any{"reason": "x", "name": "x", "intent": map[string]any{"kind": "right_size_services"}, "base_version_no": 1,
			"intent_hash": "x", "impact_hashes": []string{}, "plan_hashes": []string{}, "material_hashes": []string{}}
		if r.method == http.MethodPatch {
			body = map[string]any{"name": "x"}
		}
		if r.method == http.MethodPost && strings.HasSuffix(r.path, "/versions") {
			body = map[string]any{"intent": map[string]any{"kind": "right_size_services", "subjects": []any{}}, "base_version_no": 1}
		}
		code, resp := l.callAs(ot, r.method, r.path, body)
		if code != http.StatusNotFound {
			t.Fatalf("other workspace %s %s: %d %v, want 404", r.method, r.path, code, resp)
		}
	}
	if code, body = l.callAs(ot, http.MethodGet, "/policies", nil); code != http.StatusOK || len(p3eList(body)) != 0 {
		t.Fatalf("other workspace list: %d %v", code, body)
	}
	if code, body = l.callAs(ot, http.MethodGet, "/approvals", nil); code != http.StatusOK || len(p3eList(body)) != 0 {
		t.Fatalf("other workspace approvals: %d %v", code, body)
	}

	// PATCH and the policy owner.
	code, body = l.call(l.author, http.MethodPatch, "/policies/"+policy, map[string]any{"name": "Right-size stale", "owner_user_id": l.author.user.String()})
	if pd := l.must(code, body, http.StatusOK, "patch"); pd["name"] != "Right-size stale" {
		t.Fatalf("patch %v", pd)
	}

	// Withdraw: findings back to open, planned control released.
	l.compile(policy, 1)
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND status = 'under_review'`, l.ws); n == 0 {
		t.Fatal("no finding under review")
	}
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/versions/1/withdraw", map[string]any{"reason": "not now"})
	l.must(code, body, http.StatusOK, "withdraw")
	if l.status(policy, 1) != "withdrawn" ||
		l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND status = 'under_review'`, l.ws) != 0 ||
		l.count(`SELECT count(*) FROM iga_gov_control WHERE workspace_id = ? AND state <> 'removed'`, l.ws) != 0 {
		t.Fatal("withdraw left findings under review or a planned control")
	}

	// Archive refuses while a control is active.
	policy2, _ := l.proposeTemplate("AROASTALEROLE01")
	p3exec(t, l.db, `UPDATE iga_gov_control SET state = 'active', baseline_captured_at = now() WHERE workspace_id = ? AND policy_id = ?`, l.ws, policy2)
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy2+"/archive", nil)
	if code != http.StatusConflict || p3eErr(body) != services.GovCodePolicyControlsRoles {
		t.Fatalf("archive with an active control: %d %v", code, body)
	}
	code, body = l.call(l.author, http.MethodPost, "/policies/"+policy+"/archive", map[string]any{"reason": "done"})
	l.must(code, body, http.StatusOK, "archive")
	if code, body = l.call(l.author, http.MethodPatch, "/policies/"+policy, map[string]any{"name": "again"}); code != http.StatusConflict ||
		p3eErr(body) != services.GovCodePolicyArchived {
		t.Fatalf("patch an archived policy: %d %v", code, body)
	}
	for _, a := range []string{"withdraw", "archive", "update"} {
		if l.audits(a) < 1 {
			t.Fatalf("no %s audit row", a)
		}
	}
}
