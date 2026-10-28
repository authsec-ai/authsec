package services

import (
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func upsertWorkloadPolicyBindings(tx *gorm.DB, wsID, policyID uuid.UUID, revision int, delivery int64, targets []publicationTarget) error {
	seen := map[uuid.UUID]bool{}
	for _, t := range targets {
		if seen[t.WorkloadID] {
			continue
		}
		seen[t.WorkloadID] = true
		now := time.Now()
		err := tx.Exec(`INSERT INTO workload_policy_bindings
			(id, workspace_id, workload_id, policy_id, revision, state, delivery_cursor, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, workload_id, policy_id) DO UPDATE SET
			  revision = EXCLUDED.revision,
			  state = EXCLUDED.state,
			  delivery_cursor = EXCLUDED.delivery_cursor,
			  updated_at = EXCLUDED.updated_at`,
			uuid.New(), wsID, t.WorkloadID, policyID, revision,
			models.WPBStateActive, delivery, now, now).Error
		if err != nil {
			return err
		}
	}
	return nil
}

func revokeWorkloadPolicyBindings(tx *gorm.DB, wsID, policyID uuid.UUID) error {
	return tx.Model(&models.WorkloadPolicyBinding{}).
		Where("workspace_id = ? AND policy_id = ? AND state = ?",
			wsID, policyID, models.WPBStateActive).
		Updates(map[string]any{
			"state":      models.WPBStateRevoked,
			"updated_at": time.Now(),
		}).Error
}
