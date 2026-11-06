package services

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Approval of a role-only recovery plan (§8.9, §7.6). A blocked undo
// (artifact_consumers_changed) compiles a recovery plan whose hash is not in
// the deployment's approval, so it needs its own: a second approver, or
// governance:emergency. The approval is a scope = 'recovery' row of
// iga_gov_approval (migration 138): one plan, its hash, never the version's
// approval. Undo then names it as the deployment's approval; the executor's
// undo rule (the approval names the plan's hash) is unchanged.

// GovRecoveryApprovalTTL is how long a recovery approval can be used to
// request the undo. It is not re-checked by the executor, like any undo.
const GovRecoveryApprovalTTL = 24 * time.Hour

// GovEventRecoveryApproved is recorded when a recovery plan is approved.
const GovEventRecoveryApproved = "undo.role_only_recovery_approved"

// GovRecoveryApproveRequest is POST /deployments/:id/recovery-plans/:plan_id/approve.
type GovRecoveryApproveRequest struct {
	// PlanHash must equal the stored plan's hash: the approver approves what
	// they were shown.
	PlanHash string `json:"plan_hash"`
	Reason   string `json:"reason"`
}

// GovRecoveryPlanView is a role-only recovery plan of a deployment, with the
// approval it holds, if any.
type GovRecoveryPlanView struct {
	PlanID              uuid.UUID  `json:"plan_id"`
	PlanHash            string     `json:"plan_hash"`
	DesiredAttachment   string     `json:"desired_attachment"`
	ArtifactDisposition string     `json:"artifact_disposition"`
	CreatedAt           time.Time  `json:"created_at"`
	ApprovalID          *uuid.UUID `json:"approval_id,omitempty"`
	ApprovedBy          *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt          *time.Time `json:"approved_at,omitempty"`
	ApprovalExpiresAt   *time.Time `json:"approval_expires_at,omitempty"`
}

// recoveryApproval is the plan's unrevoked approval, or nil. Callers check expiry.
func recoveryApproval(db *gorm.DB, ws uuid.UUID, plan models.IGAGovPlan) (*models.IGAGovApproval, error) {
	var as []models.IGAGovApproval
	if err := db.Where(`workspace_id = ? AND recovery_plan_id = ? AND scope = 'recovery' AND decision = 'approve' AND revoked_at IS NULL`,
		ws, plan.ID).Limit(1).Find(&as).Error; err != nil {
		return nil, err
	}
	if len(as) == 0 {
		return nil, nil
	}
	return &as[0], nil
}

// recoveryPlanOf loads a stored role-only recovery plan of the deployment's
// control and version, or 404.
func recoveryPlanOf(db *gorm.DB, ws uuid.UUID, d models.IGAGovDeployment, planID uuid.UUID) (*models.IGAGovPlan, error) {
	var p models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ? AND version_id = ? AND control_id = ? AND kind = 'undo' AND artifact_disposition = ?",
		ws, planID, d.VersionID, d.ControlID, igagov.DispositionRetainShared).Take(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &p, nil
}

// ApproveRecoveryPlan records the approval of one recovery plan of an apply
// deployment. The approver is not the version's author (403 self_approval,
// as for any version) and holds governance:approve (the route). Approving a
// plan that already holds an approval answers 409 version_conflict.
func (s *GovDeployments) ApproveRecoveryPlan(ctx context.Context, ws, approver, depID, planID uuid.UUID, req GovRecoveryApproveRequest) (*models.IGAGovApproval, error) {
	if strings.TrimSpace(req.PlanHash) == "" {
		return nil, GovBadParam("plan_hash", "plan_hash is required (GET /deployments/:id lists the recovery plans).")
	}
	var out models.IGAGovApproval
	err := s.write(ctx, ws, func(tx *gorm.DB) error {
		d, err := s.loadDeployment(tx, ws, depID)
		if err != nil {
			return err
		}
		if d.Kind != igagov.PlanApply {
			return govConflict(GovCodeNotUndoable, "Only an apply deployment has recovery plans.", map[string]any{"kind": d.Kind})
		}
		if err := tenancy.GormRaw(inWorkspace(ctx, ws), tx, `SELECT id FROM iga_gov_control WHERE workspace_id = $1 AND id = $2 FOR UPDATE`, d.ControlID).Scan(&struct{ ID uuid.UUID }{}).Error; err != nil {
			return err
		}
		if err := inFlightCheck(tx, ws, d.ControlID); err != nil {
			return err
		}
		var deps []models.IGAGovDeployment
		if err := tx.Where("workspace_id = ? AND control_id = ?", ws, d.ControlID).Find(&deps).Error; err != nil {
			return err
		}
		if latest := latestUndoable(deps); latest == nil || latest.ID != d.ID {
			return govConflict(GovCodeNotLatestDeployment, "Only the latest deployment of this role can be undone; undo in order.",
				map[string]any{"deployment_id": d.ID})
		}
		plan, err := recoveryPlanOf(tx, ws, *d, planID)
		if err != nil {
			return err
		}
		if plan.PlanHash != req.PlanHash {
			return govConflict(GovCodePlanChanged, "The recovery plan changed since you loaded it; review the current one.", map[string]any{"plan_id": plan.ID})
		}
		var v models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, d.VersionID).Take(&v).Error; err != nil {
			return err
		}
		if v.CreatedBy == approver {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must decide.", nil)
		}
		if ex, err := recoveryApproval(tx, ws, *plan); err != nil {
			return err
		} else if ex != nil {
			if ex.ExpiresAt.After(s.now()) {
				return govConflict(GovCodeVersionConflict, "This recovery plan already has an approval.", map[string]any{"approval_id": ex.ID})
			}
			// The control lock serializes renewal with undo and other approvers.
			if err := tx.Model(&models.IGAGovApproval{}).Where("workspace_id = ? AND id = ? AND revoked_at IS NULL", ws, ex.ID).
				Update("revoked_at", s.now()).Error; err != nil {
				return err
			}
		}
		now := s.now()
		out = models.IGAGovApproval{ID: uuid.New(), WorkspaceID: ws, VersionID: d.VersionID, Decision: "approve", DecidedBy: approver,
			Channel: "ui", IntentHash: v.IntentHash, ImpactHashes: []string{plan.ImpactHash}, PlanHashes: []string{plan.PlanHash},
			MaterialHashes: []string{plan.MaterialHash}, EvidenceRev: plan.EvidenceRev, Reason: strings.TrimSpace(req.Reason),
			ExpiresAt: now.Add(GovRecoveryApprovalTTL), DecidedAt: now, Scope: "recovery", RecoveryPlanID: &plan.ID}
		if err := tx.Create(&out).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_approval_recovery") {
				return govConflict(GovCodeVersionConflict, "This recovery plan already has an approval.", nil)
			}
			return err
		}
		pol, _, err := s.policyOfVersion(tx, ws, d.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(approver)
		return appendGovEvent(tx, ws, GovEventRecoveryApproved, k, a, depRefs(*d, pol), map[string]any{"plan_id": plan.ID,
			"plan_hash": plan.PlanHash, "approval_id": out.ID, "expires_at": out.ExpiresAt, "reason": out.Reason})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// recoveryPlansOf lists the role-only recovery plans stored for a
// deployment's control and version, newest first, each with its approval.
func recoveryPlansOf(db *gorm.DB, ws uuid.UUID, d models.IGAGovDeployment) ([]GovRecoveryPlanView, error) {
	var ps []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND control_id = ? AND kind = 'undo' AND artifact_disposition = ?",
		ws, d.VersionID, d.ControlID, igagov.DispositionRetainShared).Order("created_at DESC, id DESC").Find(&ps).Error; err != nil {
		return nil, err
	}
	out := []GovRecoveryPlanView{}
	for _, p := range ps {
		v := GovRecoveryPlanView{PlanID: p.ID, PlanHash: p.PlanHash, DesiredAttachment: p.DesiredAttachment,
			ArtifactDisposition: p.ArtifactDisposition, CreatedAt: p.CreatedAt}
		ap, err := recoveryApproval(db, ws, p)
		if err != nil {
			return nil, err
		}
		if ap != nil {
			v.ApprovalID, v.ApprovedBy, v.ApprovedAt, v.ApprovalExpiresAt = &ap.ID, &ap.DecidedBy, &ap.DecidedAt, &ap.ExpiresAt
		}
		out = append(out, v)
	}
	return out, nil
}
