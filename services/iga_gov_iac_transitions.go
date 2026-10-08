package services

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The deployment state transitions IaC and export delivery make (§8.4, the
// iac_pr and export branches; T3.17). The deployment state machine is
// T3.16's; this is the NARROW seam T3.17 needs from it, with a default
// implementation so J1/J2 work before T3.16 lands. At merge, T3.16 either
// keeps this implementation or installs its own through
// GovIaCDelivery.WithStates.
//
// The transitions T3.17 makes, all compare-and-swap on the current state:
//
//	queued         -> awaiting_merge      iac_pr, PR opened
//	queued         -> awaiting_apply      export (J1), or iac_pr whose source already holds the change
//	queued         -> blocked             iac_pr whose source no longer renders (iac_form_changed)
//	awaiting_merge -> awaiting_apply      PR merged; apply_deadline_at = merged_at + iac_apply_hours
//	awaiting_merge -> failed              PR closed unmerged
//	awaiting_apply -> applied_unverified  desired state read back (incl. disposition); applied_at,
//	                                      verify_deadline_at = applied_at + 60 min; verify enqueued
//	awaiting_apply -> failed              conflict or recreated role: unexpected_state, with the diff
//
// "Overdue" is not a state (§8.4: "overdue shown, stays"): an
// awaiting_apply deployment past apply_deadline_at keeps its state, and the
// artifact verification row says overdue.

// GovDeploymentTransition is one compare-and-swap state change.
type GovDeploymentTransition struct {
	WorkspaceID  uuid.UUID
	DeploymentID uuid.UUID
	From         []string
	To           string
	Reason       string
	// Optional timestamps written with the state.
	ApplyDeadlineAt  *time.Time
	AppliedAt        *time.Time
	VerifyDeadlineAt *time.Time
}

// GovDeploymentStates makes deployment state transitions inside the
// caller's (fenced) transaction.
type GovDeploymentStates interface {
	TransitionTx(tx *gorm.DB, t GovDeploymentTransition) error
}

// ErrGovDeploymentStateChanged: the deployment was not in any From state.
var ErrGovDeploymentStateChanged = errors.New("deployment state changed")

// GovVerifyDeadline is §8.5's verify_deadline_at = applied_at + 60 min.
const GovVerifyDeadline = 60 * time.Minute

// DefaultGovDeploymentStates is T3.17's implementation.
type DefaultGovDeploymentStates struct{}

// TransitionTx implements GovDeploymentStates.
func (DefaultGovDeploymentStates) TransitionTx(tx *gorm.DB, t GovDeploymentTransition) error {
	set := map[string]any{"state": t.To, "state_reason": t.Reason, "updated_at": gorm.Expr("now()")}
	if t.ApplyDeadlineAt != nil {
		set["apply_deadline_at"] = t.ApplyDeadlineAt.UTC()
	}
	if t.AppliedAt != nil {
		set["applied_at"] = t.AppliedAt.UTC()
	}
	if t.VerifyDeadlineAt != nil {
		set["verify_deadline_at"] = t.VerifyDeadlineAt.UTC()
	}
	res := tx.Model(&models.IGAGovDeployment{}).Where("workspace_id = ? AND id = ? AND state IN ?", t.WorkspaceID, t.DeploymentID, t.From).
		Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrGovDeploymentStateChanged
	}
	var d models.IGAGovDeployment
	if err := tx.Where("workspace_id = ? AND id = ?", t.WorkspaceID, t.DeploymentID).Take(&d).Error; err != nil {
		return err
	}
	if t.To == "applied_unverified" {
		id := d.ID
		if _, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: t.WorkspaceID,
			Kind: repositories.GovJobVerify, DedupeKey: "deployment:" + id.String(), SubjectID: &id, RunAfter: time.Now().UTC()}); err != nil {
			return err
		}
	}
	return nil
}

// govDeploymentRefs are a deployment's event references (policy, version,
// deployment); the caller appends its event with appendGovEvent in the same
// transaction as the transition.
func govDeploymentRefs(tx *gorm.DB, ws uuid.UUID, d models.IGAGovDeployment) (govEventRefs, error) {
	refs := govEventRefs{VersionID: &d.VersionID, DeploymentID: &d.ID}
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT policy_id FROM iga_gov_policy_version WHERE workspace_id = ? AND id = ?`, ws, d.VersionID).
		Scan(&ids).Error; err != nil {
		return refs, err
	}
	if len(ids) == 1 {
		refs.PolicyID = &ids[0]
	}
	return refs, nil
}
