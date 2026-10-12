package services

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// The rollout (T3.15) over the deployments (T3.16), connected at the
// integration merge:
//
//   - gate facts: the rollout's RolloutDeploymentFacts reads T3.16's
//     DeploymentGateFacts (the five §8.6 gates from the last verify run,
//     the four §8.7 dimensions, the unexpected failures). Canary is left nil:
//     with no verify run yet Gates is empty and the canary waits, instead of
//     falling back to the built-in row reader, which has no CloudTrail;
//   - remove_control: starting an approved remove_control version hands it
//     to T3.16's StartRemoveControlDeployments (§8.10: no observation, no
//     canary).
//
// The deploy job itself is queued by enqueueRolloutDeployTx through
// EnqueueDeployTx. InstallGovPolicyRuntime calls InstallGovRolloutWiring.

type govDeploymentRolloutFacts struct{ db *gorm.DB }

// DeploymentGateFacts implements RolloutDeploymentFacts. Another
// workspace's deployment is T3.16's 404 GovError, passed through.
func (f govDeploymentRolloutFacts) DeploymentGateFacts(ctx context.Context, db *gorm.DB, ws, deploymentID uuid.UUID) (*RolloutDeploymentGateFacts, error) {
	if db == nil {
		db = f.db
	}
	d, err := NewGovDeployments(db, nil).DeploymentGateFacts(ctx, ws, deploymentID)
	if err != nil {
		return nil, err
	}
	dims := make(map[string]igagov.DimensionResult, len(d.Dimensions))
	for k, v := range d.Dimensions {
		dims[k] = igagov.DimensionResult{Outcome: v.Outcome, Attribution: v.Attribution, Reason: v.Reason}
	}
	return &RolloutDeploymentGateFacts{
		DeploymentID:       d.DeploymentID,
		State:              d.State,
		StateReason:        d.StateReason,
		AppliedAt:          d.AppliedAt,
		Dimensions:         dims,
		Gates:              d.Gates,
		UnexpectedFailures: d.UnexpectedFailure,
	}, nil
}

// startRemoveControl adapts T3.16's StartRemoveControlDeployments, which
// takes the policy and version number, to the rollout's starter, which has
// the version id.
func startRemoveControl(ctx context.Context, db *gorm.DB, ws, actor, versionID uuid.UUID) error {
	var v models.IGAGovPolicyVersion
	if err := db.WithContext(ctx).Where("workspace_id = ? AND id = ?", ws, versionID).Take(&v).Error; err != nil {
		return err
	}
	_, err := NewGovDeployments(db, nil).StartRemoveControlDeployments(ctx, ws, actor, v.PolicyID, v.VersionNo)
	return err
}

// InstallGovRolloutWiring installs both connections process-wide and
// returns a function restoring the previous ones (tests).
func InstallGovRolloutWiring(db *gorm.DB) (restore func()) {
	r1 := SetGovRolloutDeploymentFacts(govDeploymentRolloutFacts{db: db})
	r2 := SetGovRemoveControlStarter(startRemoveControl)
	return func() { r2(); r1() }
}
