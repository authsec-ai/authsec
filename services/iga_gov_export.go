package services

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// GET /policies/:id/versions/:no/export (SPEC-iga-phase3-policy.md §7.3, J1;
// T3.17): for each approved target, the boundary document plus AWS CLI and
// Terraform snippets -- one downloadable artifact per plan. An export
// deployment (§8.4: export -> awaiting_apply) of the same plan has its
// deployment id substituted into the authsec:change tag.
//
// DECISION (T3.17, review P2): "approved" is an approval in force
// (UsableApproval: not revoked, not expired, approver still valid); a
// version without one answers 409 version_not_approved, an expired one 409
// approval_expired. Every current eligible plan is exported, whatever
// its delivery: J1 is available for eligible and iac_only plans (§3.4).

// GovCodeVersionNotApproved: export needs an approved version.
const GovCodeVersionNotApproved = "version_not_approved"

// GovExportPlan is one plan's artifact.
type GovExportPlan struct {
	PlanID       uuid.UUID      `json:"plan_id"`
	Kind         string         `json:"kind"`
	Delivery     string         `json:"delivery"`
	PlanHash     string         `json:"plan_hash"`
	DeploymentID *uuid.UUID     `json:"deployment_id,omitempty"`
	State        string         `json:"deployment_state,omitempty"`
	Artifact     iacpr.Artifact `json:"artifact"`
}

// GovExportView is the export response.
type GovExportView struct {
	VersionNo int             `json:"version_no"`
	Plans     []GovExportPlan `json:"plans"`
}

// ExportVersion is GET .../export.
func (a *GovAuthoring) ExportVersion(ctx context.Context, ws, policyID uuid.UUID, no int) (*GovExportView, error) {
	db := a.db.WithContext(ctx)
	v, err := a.loadVersion(db, ws, policyID, no, false)
	if err != nil {
		return nil, err
	}
	// Review P2: the approval must be IN FORCE with the same semantics a
	// deployment relies on (UsableApproval): approved, not revoked, not
	// expired (409 approval_expired), the intent unchanged and the approver
	// still able to approve -- export is the J1 delivery, the customer applies
	// what it shows. DECISION: evidence freshness (revalidation) is a check
	// at deployment start, not at download, so the approval-level rules are
	// applied here and each exported plan must be one the approval names.
	ua, err := a.UsableApproval(ctx, ws, v.ID, nil)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Code == GovCodeApprovalRequired {
			return nil, govErr(http.StatusConflict, GovCodeVersionNotApproved, "Only an approved version can be exported.",
				map[string]any{"status": v.Status})
		}
		return nil, err
	}
	plans, err := currentPlans(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	out := &GovExportView{VersionNo: v.VersionNo, Plans: []GovExportPlan{}}
	for _, pr := range plans {
		if pr.Eligibility == igagov.EligibilityIneligible {
			continue
		}
		if !containsStr(ua.Approval.PlanHashes, pr.PlanHash) {
			return nil, govConflict(GovCodePlanChanged, "This plan is not the approved plan.", map[string]any{"plan_id": pr.ID})
		}
		p, err := PlanFromRow(pr.IGAGovPlan)
		if err != nil {
			return nil, err
		}
		docs, err := planDocuments(db, ws, p)
		if err != nil {
			return nil, err
		}
		var c models.IGAGovControl
		if err := db.Where("workspace_id = ? AND id = ?", ws, pr.ControlID).Take(&c).Error; err != nil {
			return nil, err
		}
		ep := GovExportPlan{PlanID: pr.ID, Kind: pr.Kind, Delivery: pr.Delivery, PlanHash: pr.PlanHash}
		var deps []models.IGAGovDeployment
		if err := db.Where("workspace_id = ? AND plan_id = ?", ws, pr.ID).Order("created_at DESC").Limit(1).Find(&deps).Error; err != nil {
			return nil, err
		}
		depID := ""
		if len(deps) == 1 {
			ep.DeploymentID, ep.State = &deps[0].ID, deps[0].State
			depID = deps[0].ID.String()
		}
		art, err := iacpr.Export(p, roleTarget(c), docs, depID)
		if err != nil {
			return nil, err
		}
		art.Fallback = IaCFallbackOf(p)
		ep.Artifact = art
		out.Plans = append(out.Plans, ep)
	}
	return out, nil
}
