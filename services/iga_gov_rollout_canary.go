package services

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Rollout control rules shared by the rollout (T3.15) and the deployment
// jobs (T3.16), SPEC-iga-phase3-policy.md §8.6 (review P1-9). They live
// here so the deploy and verify jobs reach them through one-line hooks:
//
//   - GovCanaryHours: the ONE canary length of a version. The rollout's gate
//     window and the verify job's application-health window both read it,
//     so they can never disagree (the intent's rollout.canary_hours, else
//     the workspace setting, else 48).
//   - rolloutHoldsDeploymentTx: a paused rollout holds its queued apply
//     deployments; the deploy job leaves them queued and retries later.
//   - govCanaryWindowUndecided: the verify job keeps re-checking a verified
//     deployment past the window's end until window_elapsed can be decided.
//   - canaryHealthy / lockCanaryFactsTx: the canary-health rule the
//     automatic tick and the manual expand share, decided on facts read
//     under lock in the transaction that acts on them.

// DepReasonRolloutPaused is why a queued deployment waits: its rollout is
// paused (§8.6 "paused on a failed gate or manual pause").
const DepReasonRolloutPaused = "rollout_paused"

// RolloutHoldRecheck is how soon a deployment held by a paused rollout is
// looked at again (resume also brings its deploy job forward).
const RolloutHoldRecheck = 5 * time.Minute

var errGovRolloutPaused = errors.New("the deployment's rollout is paused")

// GovCanaryHours is the canary window length of a version (§8.6; DECISION
// R10): the intent's rollout.canary_hours, else the workspace's
// canary_hours setting, else 48. Any intent kind is read leniently: a
// version without a rollout section (undo, remove_control) uses the
// setting.
func GovCanaryHours(db *gorm.DB, ws, versionID uuid.UUID) (int, error) {
	var raw []json.RawMessage
	if err := db.Raw(`SELECT intent FROM iga_gov_policy_version WHERE workspace_id = ? AND id = ?`, ws, versionID).
		Scan(&raw).Error; err != nil {
		return 0, err
	}
	if len(raw) == 1 {
		var in struct {
			Rollout *igagov.RolloutIntent `json:"rollout"`
		}
		if json.Unmarshal(raw[0], &in) == nil && in.Rollout != nil && in.Rollout.CanaryHours > 0 {
			return in.Rollout.CanaryHours, nil
		}
	}
	set, err := repositories.NewIGAGovSettingsRepository(db).Get(ws)
	if err != nil {
		return 0, err
	}
	if set.CanaryHours < 1 {
		return 48, nil
	}
	return set.CanaryHours, nil
}

// rolloutHoldsDeploymentTx is the deploy job's rollout-pause check inside
// the transaction that moves a deployment out of queued: the version's
// rollout row is read FOR SHARE, so a pause committing concurrently either
// precedes this read (the deployment stays queued) or waits for the start
// to commit. Only apply deployments are held: an undo (Undo canary is
// offered precisely while paused) or a control removal is not the
// rollout's to hold.
func rolloutHoldsDeploymentTx(tx *gorm.DB, d models.IGAGovDeployment) error {
	if d.Kind != igagov.PlanApply {
		return nil
	}
	var stages []string
	if err := tx.Raw(`SELECT stage FROM iga_gov_rollout WHERE workspace_id = ? AND version_id = ? FOR SHARE`,
		d.WorkspaceID, d.VersionID).Scan(&stages).Error; err != nil {
		return err
	}
	if len(stages) == 1 && stages[0] == models.GovRolloutPaused {
		return errGovRolloutPaused
	}
	return nil
}

// govRolloutHold is the deploy job's answer for a held deployment: it stays
// queued and the job is handed back without spending an attempt.
func govRolloutHold() error {
	return PolicyJobRetryLater(RolloutHoldRecheck, DepReasonRolloutPaused)
}

// govCanaryWindowUndecided reports whether the verify job must keep
// re-checking a verified deployment's canary window (§8.6 window_elapsed).
// It must while the window is open; after it, while window_elapsed has not
// passed and no CloudTrail read can have covered the window's end yet --
// that is, until a scan of the connector that STARTED at or after the
// window end has been published (published by now, so this run's gates
// already read it) -- but no longer than MaxTrailScanGap past the window's
// end: a later scan reads back only 48 h and can no longer cover any of the
// window, so the gate's answer cannot change. Stopping at the window's end
// instead froze window_elapsed at not_available whenever the covering scan
// came after it.
func govCanaryWindowUndecided(db *gorm.DB, ws, connectorID uuid.UUID, appliedAt time.Time, hours int, now time.Time,
	cr igagov.CanaryResult) (bool, error) {
	end := appliedAt.Add(time.Duration(hours) * time.Hour)
	if now.Before(end) {
		return true, nil
	}
	for _, g := range cr.Gates {
		if g.Gate == igagov.GateWindowElapsed && g.Outcome == igagov.OutcomePassed {
			return false, nil
		}
	}
	if !now.Before(end.Add(igagov.MaxTrailScanGap)) {
		return false, nil
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM cloud_scan_run WHERE workspace_id = ? AND connector_id = ? AND status = 'published'
		AND COALESCE(started_at, requested_at) >= ? AND published_at <= ?`, ws, connectorID, end, now).Scan(&n).Error; err != nil {
		return false, err
	}
	return n == 0, nil
}

// canaryHealthy is the one canary-health rule of §8.6, shared by the
// automatic tick and the manual expand: the canary is applied and still
// healthy (applied_unverified or verified; never failed, drifted, undone,
// superseded or blocked), no gate failed, and every gate passed or is
// not_available and accepted -- by a stored acceptance of this window, or
// in extra (the gates being accepted now).
func canaryHealthy(ev *gateEval, extra map[string]bool) bool {
	return ev.facts.AppliedAt != nil && healthyState(ev.facts.State) && !ev.result.Pause && ev.passes(extra)
}

// lockCanaryFactsTx locks the canary deployment and its verification rows
// FOR SHARE in tx, before the gates are read from them: a deploy, verify or
// drift job that would change them waits until the rollout's decision has
// committed, so the decision is taken on exactly the facts it read.
func lockCanaryFactsTx(tx *gorm.DB, ws, depID uuid.UUID) error {
	if err := tx.Exec(`SELECT id FROM iga_gov_deployment WHERE workspace_id = ? AND id = ? FOR SHARE`, ws, depID).Error; err != nil {
		return err
	}
	return tx.Exec(`SELECT deployment_id FROM iga_gov_verification WHERE workspace_id = ? AND deployment_id = ? ORDER BY dimension FOR SHARE`,
		ws, depID).Error
}
