package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RolloutWorker advances canary publications. Tick claims one row with
// FOR UPDATE SKIP LOCKED and returns. It does not sleep. Run is the process
// loop and is the only place that waits.
type RolloutWorker struct {
	db    *gorm.DB
	now   func() time.Time
	owner string
}

// NewRolloutWorker builds the worker. Tests call Tick directly.
func NewRolloutWorker(db *gorm.DB) *RolloutWorker {
	return &RolloutWorker{db: db, now: time.Now, owner: "rollout"}
}

// Run ticks every five seconds until ctx is cancelled.
func (w *RolloutWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.Tick(ctx)
		}
	}
}

// Tick claims one due canary publication. A failing receipt at or above the
// threshold pauses it. After the window with fewer failures, the rest of the
// targets become desired.
func (w *RolloutWorker) Tick(ctx context.Context) error {
	if w == nil || w.db == nil {
		return nil
	}
	now := time.Now().UTC()
	if w.now != nil {
		now = w.now().UTC()
	}
	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []struct {
			ID   uuid.UUID
			WS   uuid.UUID
			Plan string
		}
		err := tx.Raw(`SELECT id, workspace_id AS ws, rollout_plan::text AS plan
			FROM runtime_policy_publications
			WHERE rollout_plan->>'phase' = 'canary'
			  AND (
			    COALESCE(rollout_plan->>'leased_until', '') = ''
			    OR (rollout_plan->>'leased_until')::timestamptz <= ?
			  )
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED`, now).Scan(&rows).Error
		if err != nil || len(rows) == 0 {
			return err
		}
		row := rows[0]
		var plan rolloutPlan
		if err := json.Unmarshal([]byte(row.Plan), &plan); err != nil {
			return err
		}
		if plan.Threshold <= 0 {
			plan.Threshold = 1
		}
		if plan.Window <= 0 {
			plan.Window = int(CanaryWindow() / time.Second)
		}
		var failed int64
		if len(plan.Canary) > 0 {
			err := tx.Raw(`SELECT count(*) FROM runtime_policy_receipts r
				JOIN runtime_policy_targets t ON t.workspace_id = r.workspace_id AND t.id = r.target_id
				WHERE r.workspace_id = ? AND r.publication_id = ? AND r.delivery_revision = t.desired_delivery_revision
				  AND t.workload_id::text IN ?
				  AND (r.error <> '' OR r.control_status::text LIKE '%"failed"%')`,
				row.WS, row.ID, plan.Canary).Scan(&failed).Error
			if err != nil {
				return err
			}
		}
		phase := "canary"
		lease := now.Add(30 * time.Second)
		if failed >= int64(plan.Threshold) {
			phase = "paused"
			lease = now
		} else if started, err := time.Parse(time.RFC3339, plan.Started); err == nil && !now.Before(started.Add(time.Duration(plan.Window)*time.Second)) {
			phase = "rest"
			lease = now
		}
		plan.Phase = phase
		plan.LeasedUntil = lease.Format(time.RFC3339)
		plan.LeaseOwner = w.owner
		raw, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		return tx.Exec(`UPDATE runtime_policy_publications SET rollout_plan = CAST(? AS jsonb)
			WHERE workspace_id = ? AND id = ?`,
			string(raw), row.WS, row.ID).Error
	})
}
