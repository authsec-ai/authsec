package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

// T3.11 / T3.13 end to end (SPEC-iga-phase3-policy.md §7.3, §7.5): a
// template proposal for a role with no boundary, compiled from a fresh
// bundle and a live read into a first-attachment apply plan and its undo
// plan (documents archived first), then approval: the author can never
// approve (403 self_approval), every unanalysed item must be accepted (A34:
// 409 residuals_not_accepted naming each), a stale hash is 409, and the
// approval stores the bound hashes and one acceptance row per item, with
// events and audit rows.
//
// Safeguards (mutation-checked): self-approval refusal; the residual check;
// the hash comparison; documents inserted before plans.
func TestP3T311ProposeCompileApprove(t *testing.T) {
	l := newP3aLab(t, "p3-t311-e2e")
	l.role("RefundTaskRole", "AROAREFUND00001", map[string]*time.Time{
		"s3": p3eTime(time.Hour), "sqs": nil, "ecr": p3eTime(2 * time.Hour)})
	l.publish()

	policy, d := l.proposeTemplate("AROAREFUND00001")
	rec := d["recommendation"].(map[string]any)
	var removed, retained []string
	for _, x := range rec["remove"].([]any) {
		removed = append(removed, x.(map[string]any)["service"].(string))
	}
	for _, x := range rec["retain"].([]any) {
		retained = append(retained, x.(map[string]any)["service"].(string)+":"+x.(map[string]any)["basis"].(string))
	}
	if strings.Join(removed, ",") != "sqs" || strings.Join(retained, ",") != "ecr:observed,s3:observed" {
		t.Fatalf("recommendation remove %v retain %v", removed, retained)
	}
	if ev := d["evidence"].(map[string]any); ev["trust"] != igagov.TrustTrusted || ev["bundle_id"] == "" {
		t.Fatalf("evidence %v", ev)
	}
	if v := d["version"].(map[string]any); v["no"] != float64(1) || v["status"] != "draft" {
		t.Fatalf("version %v", v)
	}
	if l.count(`SELECT count(*) FROM iga_gov_control WHERE workspace_id = ? AND policy_id = ? AND state = 'planned'`, l.ws, policy) != 1 {
		t.Fatal("no planned control")
	}

	plans := l.compile(policy, 1)
	ps := plans["plans"].([]any)
	if len(ps) != 2 {
		t.Fatalf("%d plans, want apply + undo", len(ps))
	}
	ap, up := ps[0].(map[string]any), ps[1].(map[string]any)
	if ap["kind"] != "apply" || up["kind"] != "undo" || ap["first_attachment"] != true || ap["eligibility"] != "eligible" ||
		up["desired_attachment"] != "absent" || up["artifact_disposition"] != "delete" || up["replaced_boundary_arn"] != ap["desired_boundary_arn"] {
		t.Fatalf("apply %v\nundo %v", ap, up)
	}
	if !strings.Contains(fmt.Sprint(ap["desired_document"]), "NotAction:[sqs:*]") {
		t.Fatalf("desired document %v", ap["desired_document"])
	}
	if got := p3aItemKeys(plans, services.GovAcceptUnanalysed); strings.Join(got, ",") != "other_accounts,unanalysed_form:ecr_registry,unanalysed_form:ecr_repository" {
		t.Fatalf("unanalysed items %v", got)
	}
	if got := p3aItemKeys(plans, services.GovAcceptGap); len(got) != 0 {
		t.Fatalf("gaps %v, want none (coverage complete)", got)
	}
	if l.status(policy, 1) != "in_review" {
		t.Fatalf("status %s", l.status(policy, 1))
	}
	// Documents first: every document a plan names is archived.
	if n := l.count(`SELECT count(*) FROM iga_gov_plan p WHERE p.workspace_id = ? AND p.desired_document_hash IS NOT NULL
	                   AND NOT EXISTS (SELECT 1 FROM iga_gov_document d WHERE d.workspace_id = p.workspace_id AND d.document_hash = p.desired_document_hash)`, l.ws); n != 0 {
		t.Fatalf("%d plans name an unarchived document", n)
	}

	// The author can never approve (§2.10), whatever their permissions.
	code, body := l.approve(l.author, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusForbidden || p3eErr(body) != services.GovCodeSelfApproval {
		t.Fatalf("author approves: %d %v, want 403 self_approval", code, body)
	}
	// A34: every unanalysed item must be accepted, each by name.
	code, body = l.approve(l.approver, policy, 1, p3aApproveBody(plans, func(it map[string]any) bool {
		return it["item_key"] == "other_accounts"
	}))
	if code != http.StatusConflict || p3eErr(body) != services.GovCodeResidualsNotAccept {
		t.Fatalf("approve without the ecr residuals: %d %v, want 409 residuals_not_accepted", code, body)
	}
	if miss := body["error"].(map[string]any)["detail"].(map[string]any)["missing"].([]any); len(miss) != 2 {
		t.Fatalf("missing %v, want both ecr forms", miss)
	}
	// A stale plan hash.
	stale := p3aApproveBody(plans, nil)
	stale["plan_hashes"] = []string{"sha256:" + strings.Repeat("0", 64), ap["plan_hash"].(string)}
	if code, body = l.approve(l.approver, policy, 1, stale); code != http.StatusConflict || p3eErr(body) != services.GovCodePlanChanged {
		t.Fatalf("stale plan hash: %d %v, want 409 plan_changed", code, body)
	}
	// A wrong item hash is a changed plan, never a silent acceptance.
	bad := p3aApproveBody(plans, nil)
	bad["acceptances"].([]map[string]any)[0]["item_hash"] = "sha256:" + strings.Repeat("1", 64)
	if code, body = l.approve(l.approver, policy, 1, bad); code != http.StatusConflict || p3eErr(body) != services.GovCodePlanChanged {
		t.Fatalf("wrong item hash: %d %v, want 409 plan_changed", code, body)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws); n != 0 {
		t.Fatalf("%d approvals after refusals", n)
	}

	res := l.approveAll(policy, 1)
	apr := res["approval"].(map[string]any)
	if apr["decided_by"] != l.approver.user.String() || apr["channel"] != "ui" || len(apr["plan_hashes"].([]any)) != 2 ||
		len(apr["material_hashes"].([]any)) != 2 || len(apr["impact_hashes"].([]any)) != 1 {
		t.Fatalf("approval %v", apr)
	}
	if l.status(policy, 1) != "approved" {
		t.Fatalf("status %s", l.status(policy, 1))
	}
	var accs []struct {
		Kind, ItemKey, ItemHash, Reason string
		PlanID, EvidenceBundleID        uuid.UUID
		AcceptedBy                      uuid.UUID
	}
	l.db.Raw(`SELECT kind, item_key, item_hash, reason, plan_id, evidence_bundle_id, accepted_by FROM iga_gov_acceptance WHERE workspace_id = ? ORDER BY item_key`, l.ws).Scan(&accs)
	if len(accs) != 3 {
		t.Fatalf("acceptances %+v", accs)
	}
	for _, x := range accs {
		if x.Kind != services.GovAcceptUnanalysed || x.PlanID.String() != ap["id"] || x.EvidenceBundleID.String() != ap["evidence_bundle_id"] ||
			x.AcceptedBy != l.approver.user || !strings.Contains(x.Reason, x.ItemKey) {
			t.Fatalf("acceptance %+v", x)
		}
	}
	if l.events("version_approved") != 1 || l.events("acceptance_recorded") != 3 || l.events("version_proposed") != 1 ||
		l.events("proposal_created") != 1 || l.events("policy_created") != 1 {
		t.Fatalf("events approved=%d acceptances=%d proposed=%d", l.events("version_approved"), l.events("acceptance_recorded"), l.events("version_proposed"))
	}
	for _, a := range []string{"create_proposal", "propose", "approve"} {
		if l.audits(a) != 1 {
			t.Fatalf("audit %s: %d rows", a, l.audits(a))
		}
	}

	// §2.8: the approval is usable while its approver may approve; a
	// departed approver (membership left) invalidates it.
	vid := l.versionID(policy, 1)
	pid := uuid.MustParse(ap["id"].(string))
	ok, err := l.authoring().UsableApproval(context.Background(), l.ws, vid, []uuid.UUID{pid})
	if err != nil || ok.Approval.ID.String() != apr["id"] || ok.Revalidations[pid] != nil {
		t.Fatalf("usable approval: %+v %v", ok, err)
	}
	p3exec(t, l.db, `UPDATE workspace_memberships SET status = 'left' WHERE id = ?`, l.approver.membership)
	_, err = l.authoring().UsableApproval(context.Background(), l.ws, vid, []uuid.UUID{pid})
	if ge, isGov := err.(*services.GovError); !isGov || ge.Code != services.GovCodeApprovalInvalid ||
		!strings.Contains(fmt.Sprint(ge.Detail["reasons"]), "approver_not_active_member") {
		t.Fatalf("departed approver: %v, want 409 approval_invalid", err)
	}
	p3exec(t, l.db, `UPDATE workspace_memberships SET status = 'active' WHERE id = ?`, l.approver.membership)
	// Approving twice is a conflict.
	if code, body = l.approve(l.second, policy, 1, p3aApproveBody(plans, nil)); code != http.StatusConflict || p3eErr(body) != services.GovCodeVersionConflict {
		t.Fatalf("second approval: %d %v", code, body)
	}
	// The pending queue: the approved version is gone; the author never sees
	// their own version.
	code, body = l.call(l.second, http.MethodGet, "/approvals", nil)
	if code != http.StatusOK || len(p3eList(body)) != 0 {
		t.Fatalf("approvals queue: %d %v", code, body)
	}
	code, body = l.call(l.approver, http.MethodGet, "/approvals?status=decided", nil)
	if code != http.StatusOK || len(p3eList(body)) != 1 {
		t.Fatalf("decided queue: %d %v", code, body)
	}
}

// The seams T3.12 fills (A5's owner gate is T3.12's; this proves what it
// needs): OnProposed runs in the propose transaction with the apply plans;
// OwnerGate runs inside the approval transaction and its 409 refuses the
// approval with nothing written; OnVersionClosed runs when a version leaves
// review. Rejection needs a reason, is refused to the author, binds the
// current hashes and returns the findings to open.
//
// Safeguard (mutation-checked): the OwnerGate call in Approve.
func TestP3T313OwnerGateHookAndReject(t *testing.T) {
	l := newP3aLab(t, "p3-t313-hooks")
	l.role("HookRole", "AROAHOOKROLE001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	var proposed []services.GovProposedVersion
	var closed []string
	gate := true
	prev := services.SetGovAuthoringHooks(services.GovAuthoringHooks{
		OnProposed: func(tx *gorm.DB, p services.GovProposedVersion) error { proposed = append(proposed, p); return nil },
		OwnerGate: func(tx *gorm.DB, c services.GovApprovalCheck) error {
			if gate {
				return &services.GovError{Status: http.StatusConflict, Code: "review_incomplete", Message: "owners have not responded",
					Detail: map[string]any{"version_id": c.VersionID, "plans": len(c.ApplyPlans)}}
			}
			return nil
		},
		OnVersionClosed: func(tx *gorm.DB, ws, v uuid.UUID, status string) error { closed = append(closed, status); return nil },
	})
	t.Cleanup(func() { services.SetGovAuthoringHooks(prev) })

	policy, _ := l.proposeTemplate("AROAHOOKROLE001")
	plans := l.compile(policy, 1)
	if len(proposed) != 1 || len(proposed[0].ApplyPlans) != 1 || proposed[0].Reproposed || proposed[0].ActorID != l.author.user {
		t.Fatalf("OnProposed %+v", proposed)
	}
	code, body := l.approve(l.approver, policy, 1, p3aApproveBody(plans, nil))
	if code != http.StatusConflict || p3eErr(body) != "review_incomplete" {
		t.Fatalf("owner gate: %d %v, want 409 review_incomplete", code, body)
	}
	if l.count(`SELECT count(*) FROM iga_gov_approval WHERE workspace_id = ?`, l.ws) != 0 ||
		l.count(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = ?`, l.ws) != 0 || l.status(policy, 1) != "in_review" {
		t.Fatal("a refused approval wrote rows")
	}
	gate = false
	path := "/policies/" + policy + "/versions/1/reject"
	if code, body = l.call(l.approver, http.MethodPost, path, map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("reject without a reason: %d %v", code, body)
	}
	if code, body = l.call(l.author, http.MethodPost, path, map[string]any{"reason": "mine"}); code != http.StatusForbidden ||
		p3eErr(body) != services.GovCodeSelfApproval {
		t.Fatalf("author rejects: %d %v", code, body)
	}
	code, body = l.call(l.approver, http.MethodPost, path, map[string]any{"reason": "sqs is used by the nightly job"})
	rj := l.must(code, body, http.StatusOK, "reject")
	h := plans["hashes"].(map[string]any)
	if rj["decision"] != "reject" || rj["intent_hash"] != h["intent_hash"] || len(rj["plan_hashes"].([]any)) != 2 {
		t.Fatalf("rejection %v", rj)
	}
	if l.status(policy, 1) != "rejected" || len(closed) != 1 || closed[0] != "rejected" ||
		l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'version_rejected' AND actor_id = ?`, l.ws, l.approver.user.String()) != 1 {
		t.Fatalf("after reject: status %s closed %v", l.status(policy, 1), closed)
	}
	if l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND status = 'under_review'`, l.ws) != 0 {
		t.Fatal("a rejected version left its findings under review")
	}
}
