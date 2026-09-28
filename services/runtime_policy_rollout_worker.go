package services

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RolloutWorker advances canary publications. Tick claims up to 20 rows, each
// in its own transaction with FOR UPDATE SKIP LOCKED, and returns. It does
// not sleep. Run is the process loop and is the only place that waits.
//
// A paused publication has no resume. The next step is rollback or a new
// publish. Each claim rewrites rollout_plan, including the base64 artifact
// bodies, to refresh the lease. That TOAST churn is accepted: moving the
// lease columns out would be more than the index-only 048 migration.
type RolloutWorker struct {
	db    *gorm.DB
	now   func() time.Time
	owner string
}

// NewRolloutWorker builds the worker. Tests call Tick directly.
func NewRolloutWorker(db *gorm.DB) *RolloutWorker {
	return &RolloutWorker{db: db, now: time.Now, owner: "rollout"}
}

// SetClock replaces the clock Tick uses. Production leaves it at time.Now.
func (w *RolloutWorker) SetClock(now func() time.Time) {
	if w != nil && now != nil {
		w.now = now
	}
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

// Tick claims up to 20 due canary publications. A canary target whose latest
// receipt for the current delivery revision is failed counts once toward the
// threshold. The publication stays in canary when the window ends with no
// receipts at all.
func (w *RolloutWorker) Tick(ctx context.Context) error {
	if w == nil || w.db == nil {
		return nil
	}
	for i := 0; i < 20; i++ {
		claimed, err := w.claimOne(ctx)
		if err != nil || !claimed {
			return err
		}
	}
	return nil
}

func (w *RolloutWorker) claimOne(ctx context.Context) (bool, error) {
	now := time.Now().UTC()
	if w.now != nil {
		now = w.now().UTC()
	}
	claimed := false
	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		failed, reported := int64(0), int64(0)
		if len(plan.Canary) > 0 {
			var counts []struct {
				Failed   int64
				Reported int64
			}
			err := tx.Raw(`SELECT
				count(DISTINCT t.id) FILTER (
					WHERE latest.error <> '' OR latest.status LIKE '%"failed"%'
				) AS failed,
				count(DISTINCT t.id) AS reported
				FROM runtime_policy_targets t
				JOIN LATERAL (
					SELECT r.error, r.control_status::text AS status
					FROM runtime_policy_receipts r
					WHERE r.workspace_id = t.workspace_id AND r.target_id = t.id
					  AND r.delivery_revision = t.desired_delivery_revision
					ORDER BY r.observed_at DESC
					LIMIT 1
				) latest ON true
				WHERE t.workspace_id = ? AND t.publication_id = ? AND t.workload_id::text IN ?`,
				row.WS, row.ID, plan.Canary).Scan(&counts).Error
			if err != nil {
				return err
			}
			if len(counts) == 1 {
				failed, reported = counts[0].Failed, counts[0].Reported
			}
		}
		windowElapsed := false
		if started, err := time.Parse(time.RFC3339, plan.Started); err == nil && !now.Before(started.Add(time.Duration(plan.Window)*time.Second)) {
			windowElapsed = true
		}
		phase, reason := nextCanaryPhase(failed, reported, plan.Threshold, windowElapsed)
		lease := now.Add(30 * time.Second)
		if phase != "canary" {
			lease = now
		}
		plan.Phase = phase
		plan.Reason = reason
		plan.LeasedUntil = lease.Format(time.RFC3339)
		plan.LeaseOwner = w.owner
		raw, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		claimed = true
		return tx.Exec(`UPDATE runtime_policy_publications SET rollout_plan = CAST(? AS jsonb)
			WHERE workspace_id = ? AND id = ?`,
			string(raw), row.WS, row.ID).Error
	})
	return claimed, err
}

// nextCanaryPhase decides the phase from failing targets and whether any
// canary target has reported. No receipts at the end of the window keeps
// canary and records no_canary_receipts. There is no resume from paused.
func nextCanaryPhase(failed, reported int64, threshold int, windowElapsed bool) (phase, reason string) {
	if threshold <= 0 {
		threshold = 1
	}
	if failed >= int64(threshold) {
		return "paused", ""
	}
	if windowElapsed && reported == 0 {
		return "canary", "no_canary_receipts"
	}
	if windowElapsed {
		return "rest", ""
	}
	return "canary", ""
}
