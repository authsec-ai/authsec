package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Removing AuthSec control (SPEC-iga-phase3-policy.md §7.7, §8.10; T3.16).
//
// POST /policies/:id/remove-control creates a version whose intent is
// remove_control for the chosen controls, compiles one remove_control plan
// per control with igagov.CompileRemoveControl (restore the control's
// recorded baseline; never write a document other entities use; blocked
// when the role's boundary is not what AuthSec last deployed), and opens
// the owner review (T3.12) whose impact is the access that returns. The
// version then follows approve (T3.13) -> StartRemoveControlDeployments.
//
// POST /policies/:id/emergency-remove-control (governance:emergency) does
// the same without review or approval: the deployments are created at once
// with emergency_by and the reason, and their deploy jobs queued. The live
// classification is never skipped (the executor runs it).
//
// DECISIONs (T3.16): the evidence of a remove_control plan is the bundle of
// the deployment that installed the boundary now in force (a removal
// restores a recorded baseline; it is not a new right-sizing and needs no
// new activity evidence); "what AuthSec last deployed" is the ledger's live
// boundary_policy row; a control with no artifact in AWS (never applied, or
// undone to no boundary) is retired at once with no plan (igagov D45); an
// emergency removal's version is recorded with status `superseded` (it was
// executed without a decision and can never be approved or proposed).

// GovRemoveControlRequest is the body of both routes.
type GovRemoveControlRequest struct {
	ControlIDs []string `json:"control_ids"`
	Reason     string   `json:"reason"`
	Delivery   string   `json:"delivery"`
}

// GovRemoveControlResult is what the routes return.
type GovRemoveControlResult struct {
	VersionID   *uuid.UUID                `json:"version_id,omitempty"`
	VersionNo   int                       `json:"version_no,omitempty"`
	Plans       []models.IGAGovPlan       `json:"plans"`
	Retired     []uuid.UUID               `json:"retired_without_plan"`
	Deployments []models.IGAGovDeployment `json:"deployments"`
	Review      *GovReviewSync            `json:"review,omitempty"`
}

// RemoveControl implements both routes (emergency: no review, deployments now).
func (s *GovDeployments) RemoveControl(ctx context.Context, ws, actor, policyID uuid.UUID, req GovRemoveControlRequest, emergency bool) (*GovRemoveControlResult, error) {
	db := s.db.WithContext(ctx)
	pol, err := s.authoring.loadPolicy(db, ws, policyID, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Reason) == "" && emergency {
		return nil, GovBadParam("reason", "An emergency removal needs a reason.")
	}
	if len(req.ControlIDs) == 0 {
		return nil, GovBadParam("control_ids", "Name the controls to remove.")
	}
	if req.Delivery == "" {
		req.Delivery = igagov.DeliveryDirect
	}
	var ctls []models.IGAGovControl
	seen := map[uuid.UUID]bool{}
	for _, raw := range req.ControlIDs {
		id, err := uuid.Parse(raw)
		if err != nil || seen[id] {
			return nil, GovBadParam("control_ids", "control_ids are distinct uuids.")
		}
		seen[id] = true
		c, err := s.loadControl(db, ws, id)
		if err != nil || c.PolicyID != pol.ID || c.State == "removed" {
			return nil, govUnprocessable(GovCodeControlNotInPolicy, "Each control must be a live control of this policy.", map[string]any{"control_id": raw})
		}
		if err := inFlightCheck(db, ws, c.ID); err != nil {
			return nil, err
		}
		ctls = append(ctls, *c)
	}
	sort.Slice(ctls, func(i, j int) bool { return ctls[i].AccountID+ctls[i].RoleID < ctls[j].AccountID+ctls[j].RoleID })
	type compiled struct {
		ctl    models.IGAGovControl
		plan   igagov.Plan
		bundle uuid.UUID
		rev    int64
	}
	var plans []compiled
	var retire []models.IGAGovControl
	for _, c := range ctls {
		p, bundle, rev, err := s.compileRemoval(ctx, c, req.Delivery)
		var ce *igagov.CompileError
		switch {
		case errors.As(err, &ce) && ce.Code == igagov.ErrCodeNoArtifact:
			retire = append(retire, c)
		case err != nil:
			return nil, err
		default:
			plans = append(plans, compiled{c, *p, bundle, rev})
		}
	}
	out := &GovRemoveControlResult{Plans: []models.IGAGovPlan{}, Retired: []uuid.UUID{}, Deployments: []models.IGAGovDeployment{}}
	k, a := userActor(actor)
	err = db.Transaction(func(tx *gorm.DB) error {
		for _, c := range retire {
			res := tx.Exec(`UPDATE iga_gov_control SET enforcement_seq = enforcement_seq + 1, state = 'removed', updated_at = now()
				WHERE workspace_id = ? AND id = ? AND state <> 'removed'`, ws, c.ID)
			if res.Error != nil {
				return res.Error
			}
			out.Retired = append(out.Retired, c.ID)
			pid := pol.ID
			if err := appendGovEvent(tx, ws, GovEventControlRemoved, k, a, govEventRefs{PolicyID: &pid}, map[string]any{"control_id": c.ID,
				"reason": "no AuthSec artifact in AWS; retired without a plan", "request_reason": req.Reason}); err != nil {
				return err
			}
		}
		if len(plans) == 0 {
			return nil
		}
		ids := make([]string, 0, len(plans))
		var rev int64
		for _, p := range plans {
			ids = append(ids, p.ctl.ID.String())
			if p.rev > rev {
				rev = p.rev
			}
		}
		canon, hash, err := igagov.CanonicalIntent(igagov.Intent{Kind: igagov.IntentRemoveControl,
			RemoveControl: &igagov.RemoveControlIntent{Kind: igagov.IntentRemoveControl, ControlIDs: ids, Reason: strings.TrimSpace(req.Reason)}})
		if err != nil {
			return GovBadParam("control_ids", err.Error())
		}
		var maxNo int
		if err := tx.Raw(`SELECT COALESCE(max(version_no), 0) FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ?`, ws, pol.ID).
			Scan(&maxNo).Error; err != nil {
			return err
		}
		status := "in_review"
		if emergency {
			status = "superseded"
		}
		v := models.IGAGovPolicyVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: pol.ID, VersionNo: maxNo + 1, Intent: json.RawMessage(canon),
			IntentHash: hash, CatalogVersion: igagov.CatalogVersion, EvidenceRev: rev, Status: status, CreatedBy: actor,
			CreatedAt: s.now(), StatusChangedAt: s.now()}
		if err := tx.Create(&v).Error; err != nil {
			return err
		}
		out.VersionID, out.VersionNo = &v.ID, v.VersionNo
		for _, p := range plans {
			t := models.IGAGovTarget{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, PolicyID: pol.ID, ControlID: p.ctl.ID}
			if err := tx.Create(&t).Error; err != nil {
				return err
			}
			row, err := storeSidePlanTx(tx, ws, v.ID, t.ID, p.ctl.ID, p.bundle, p.plan, s.now(), true)
			if err != nil {
				return err
			}
			out.Plans = append(out.Plans, *row)
			if !emergency || !p.plan.Eligible() || p.plan.Eligibility == igagov.EligibilityIaCOnly && req.Delivery == igagov.DeliveryDirect {
				continue
			}
			d := models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, PlanID: row.ID, ControlID: p.ctl.ID,
				EmergencyBy: &actor, EmergencyReason: strings.TrimSpace(req.Reason), Kind: igagov.PlanRemoveControl, Delivery: row.Delivery,
				State: models.GovDeployQueued, CompletedOps: json.RawMessage("[]")}
			if err := tx.Create(&d).Error; err != nil {
				if isUniqueViolation(err, "uq_iga_gov_deployment_inflight") {
					return govConflict(GovCodeDeploymentInFlight, "Another change on this role started meanwhile.", nil)
				}
				return err
			}
			if err := EnqueueDeployTx(tx, ws, d.ID); err != nil {
				return err
			}
			out.Deployments = append(out.Deployments, d)
		}
		pid := pol.ID
		payload := map[string]any{"version_no": v.VersionNo, "control_ids": ids, "reason": req.Reason, "emergency": emergency,
			"plans": len(out.Plans), "deployments": len(out.Deployments)}
		if emergency {
			payload["notify"] = "approvers and owners"
		}
		if err := appendGovEvent(tx, ws, GovEventControlRemovalReq, k, a, govEventRefs{PolicyID: &pid, VersionID: &v.ID}, payload); err != nil {
			return err
		}
		if !emergency {
			rv, err := NewIGAGovOwnerReviewService(s.db).OpenReviewTx(tx, ws, v.ID, actor)
			if err != nil {
				return err
			}
			out.Review = rv
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// compileRemoval compiles one control's remove_control plan from a live read.
func (s *GovDeployments) compileRemoval(ctx context.Context, c models.IGAGovControl, delivery string) (*igagov.Plan, uuid.UUID, int64, error) {
	db := s.db.WithContext(ctx)
	ws := c.WorkspaceID
	var deps []models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND control_id = ?", ws, c.ID).Find(&deps).Error; err != nil {
		return nil, uuid.Nil, 0, err
	}
	var src *models.IGAGovDeployment
	for i := range deps {
		x := &deps[i]
		if x.AppliedAt == nil || x.State == models.GovDeployUndone || x.State == models.GovDeployFailed || x.State == models.GovDeployBlocked {
			continue
		}
		if src == nil || x.AppliedAt.After(*src.AppliedAt) {
			src = x
		}
	}
	var ledger []models.IGAGovArtifact
	if err := db.Where("workspace_id = ? AND control_id = ? AND kind = 'boundary_policy' AND state IN ('present','drifted')", ws, c.ID).
		Find(&ledger).Error; err != nil {
		return nil, uuid.Nil, 0, err
	}
	if src == nil || len(ledger) == 0 {
		return nil, uuid.Nil, 0, &igagov.CompileError{Code: igagov.ErrCodeNoArtifact, Reasons: []string{"no AuthSec artifact recorded"}}
	}
	sp, err := s.loadPlanRow(db, ws, src.PlanID)
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	ev, err := evidenceOf(db, ws, *sp)
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	base := igagov.Baseline{}
	if c.BaselineBoundaryARN != nil && c.BaselineDocumentHash != nil {
		base.BoundaryARN, base.DocumentHash = c.BaselineBoundaryARN, c.BaselineDocumentHash
		var docs []string
		_ = db.Raw(`SELECT canonical FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, ws, *c.BaselineDocumentHash).Scan(&docs)
		if len(docs) == 1 {
			base.Document = docs[0]
		}
	}
	last := igagov.BoundaryRef{ARN: ledger[0].NativeARN}
	if ledger[0].DocumentHash != nil {
		last.DocumentHash = *ledger[0].DocumentHash
	}
	var excluded []string
	if err := db.Raw(`SELECT service FROM iga_gov_service_posture WHERE workspace_id = ? AND account_id = ? AND role_id = ? AND exclusion = 'applied'
		ORDER BY service`, ws, c.AccountID, c.RoleID).Scan(&excluded).Error; err != nil {
		return nil, uuid.Nil, 0, err
	}
	extra := []string{last.ARN}
	if base.BoundaryARN != nil {
		extra = append(extra, *base.BoundaryARN)
	}
	live, err := s.liveForControl(ctx, c, extra...)
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	owned, err := s.authoring.ownedPolicyARNs(db, ws, c.ID)
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	ref := igagov.ControlRef{ID: c.ID.String(), PolicyID: c.PolicyID.String(), AccountID: c.AccountID, RoleID: c.RoleID,
		WorkspaceRef: GovWorkspaceRef(ws), OwnedPolicyARNs: owned}
	p, err := igagov.CompileRemoveControl(igagov.RemoveControlInput{Control: ref, Baseline: base, LastDeployed: last, Delivery: delivery,
		Live: live, Evidence: ev, ExcludedServices: excluded})
	if err != nil {
		return nil, uuid.Nil, 0, err
	}
	return &p, sp.EvidenceBundleID, sp.EvidenceRev, nil
}

// liveForControl reads the role, its boundary and extra policies.
func (s *GovDeployments) liveForControl(ctx context.Context, c models.IGAGovControl, extra ...string) (igagov.LiveRead, error) {
	env := s.envNow()
	unavailable := func(why string) error {
		return govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "AWS cannot be read through the discovery role right now.",
			map[string]any{"reason": why})
	}
	if env.AWS == nil {
		return igagov.LiveRead{}, unavailable("AWS access is not configured in this build")
	}
	disc, err := env.AWS.DiscoveryIAM(ctx, c.WorkspaceID, c.ConnectorID)
	if err != nil {
		return igagov.LiveRead{}, unavailable(err.Error())
	}
	role, err := awsenforce.ReadRole(ctx, disc, roleNameOfARN(c.RoleARN))
	if err != nil {
		return igagov.LiveRead{}, unavailable(err.Error())
	}
	live := igagov.LiveRead{ReadAt: s.now().UTC(), Role: role, Policies: map[string]*igagov.LivePolicy{}}
	arns := append([]string{}, extra...)
	if role != nil && role.BoundaryARN != "" {
		arns = append(arns, role.BoundaryARN)
	}
	for _, a := range arns {
		if _, done := live.Policies[a]; done || a == "" {
			continue
		}
		p, _, err := awsenforce.ReadPolicy(ctx, disc, a)
		if err != nil {
			return igagov.LiveRead{}, unavailable(err.Error())
		}
		live.Policies[a] = p
	}
	return live, nil
}

// StartRemoveControlDeployments creates the queued remove_control
// deployments of an APPROVED remove_control version (one per eligible plan
// whose control has nothing in flight) and queues their deploy jobs. It is
// the "approve -> deploy" step of §8.10 for whoever starts deployments of an
// approved version (T3.15's rollout start; DECISION: a control removal has
// no canary, every control is deployed at once).
func (s *GovDeployments) StartRemoveControlDeployments(ctx context.Context, ws, actor, policyID uuid.UUID, versionNo int) ([]models.IGAGovDeployment, error) {
	db := s.db.WithContext(ctx)
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND policy_id = ? AND version_no = ?", ws, policyID, versionNo).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	ap, err := liveApproval(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || ap == nil || !s.now().Before(ap.ExpiresAt) {
		return nil, govConflict(GovCodeApprovalRequired, "This removal has no approval in force.", map[string]any{"status": v.Status})
	}
	var ps []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND kind = 'remove_control' AND superseded_at IS NULL", ws, v.ID).
		Order("control_id").Find(&ps).Error; err != nil {
		return nil, err
	}
	out := []models.IGAGovDeployment{}
	err = db.Transaction(func(tx *gorm.DB) error {
		for _, p := range ps {
			if p.Eligibility == igagov.EligibilityIneligible || !containsStr(ap.PlanHashes, p.PlanHash) {
				continue
			}
			if err := inFlightCheck(tx, ws, p.ControlID); err != nil {
				return err
			}
			d := models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, PlanID: p.ID, ControlID: p.ControlID,
				ApprovalID: &ap.ID, Kind: igagov.PlanRemoveControl, Delivery: p.Delivery, State: models.GovDeployQueued,
				CompletedOps: json.RawMessage("[]")}
			if err := tx.Create(&d).Error; err != nil {
				return err
			}
			if err := EnqueueDeployTx(tx, ws, d.ID); err != nil {
				return err
			}
			out = append(out, d)
		}
		k, a := userActor(actor)
		pid := policyID
		return appendGovEvent(tx, ws, GovEventControlRemovalReq, k, a, govEventRefs{PolicyID: &pid, VersionID: &v.ID},
			map[string]any{"version_no": versionNo, "deployments": len(out), "approved": true})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
