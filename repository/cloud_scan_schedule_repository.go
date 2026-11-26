package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrCloudScanScheduleNotFound = errors.New("cloud scan schedule not found")

// DueSchedule is one schedule ClaimDue took for this scheduler instance.
type DueSchedule struct {
	ConnectorID     uuid.UUID
	WorkspaceID     uuid.UUID
	IntervalMinutes int
	// The chosen time, when there is one (see models.CloudScanSchedule).
	TimeOfDayMinutes *int
	Timezone         string
	DayOfWeek        *int
	// PrevDueAt is the due time the schedule had BEFORE the claim moved it
	// forward. The next slot is anchored on it so the schedule does not drift.
	PrevDueAt time.Time
	// ClaimedUntil is the due time the claim wrote (its lease). Advance only
	// moves a row that still holds it: anything else means an administrator
	// changed or turned off the schedule since the claim.
	ClaimedUntil time.Time
}

// ErrScheduleChanged: the schedule was changed, turned off or paused after it
// was claimed; the claim's slot is dropped.
var ErrScheduleChanged = errors.New("the scan schedule changed after it was claimed")

// CloudScanScheduleRepository stores the per-connector rescan schedule.
//
// Every method except ClaimDue takes the transaction to run on: the callers
// open it with tenancy.InWorkspace, so each statement is under row-level
// security for one workspace. ClaimDue is the one deliberately cross-workspace
// statement, like the scan worker's claim.
type CloudScanScheduleRepository interface {
	Get(tx *gorm.DB, workspaceID, connectorID uuid.UUID) (*models.CloudScanSchedule, error)
	// GetForUpdate is Get that also locks the row until the transaction ends, so
	// a read-then-write (Put) cannot overwrite a slot the scheduler claimed in
	// between.
	GetForUpdate(tx *gorm.DB, workspaceID, connectorID uuid.UUID) (*models.CloudScanSchedule, error)
	Upsert(tx *gorm.DB, s *models.CloudScanSchedule) error

	// ClaimDue atomically takes up to `limit` schedules that are on, not
	// paused and due, and moves each one's next_due_at to now+lease so no other
	// scheduler instance (another backend replica) takes it. If the caller
	// crashes before it sets the real next slot, the schedule is due again in
	// `lease`, not a whole interval later.
	ClaimDue(now time.Time, limit int, lease time.Duration) ([]DueSchedule, error)

	// Advance moves the schedule to its next slot. It does not say a scan was
	// queued: the slot may be skipped (a scan already running), so
	// last_enqueued_at is written separately by MarkEnqueued.
	Advance(tx *gorm.DB, workspaceID, connectorID uuid.UUID, now, nextDue, claimedUntil time.Time) error
	MarkEnqueued(tx *gorm.DB, workspaceID, connectorID uuid.UUID, at time.Time) error
	RetrySoon(tx *gorm.DB, workspaceID, connectorID uuid.UUID, at time.Time) error
	Pause(tx *gorm.DB, workspaceID, connectorID uuid.UUID, reason string, now time.Time) error
	// Disable turns a connector's schedule off, if it has one. No row is not
	// an error.
	Disable(tx *gorm.DB, workspaceID, connectorID uuid.UUID, now time.Time) error

	// RecentScheduledRuns returns the newest scheduled runs of a connector,
	// newest first, ignoring runs requested at or before `since` when set.
	RecentScheduledRuns(tx *gorm.DB, workspaceID, connectorID uuid.UUID, since *time.Time, n int) ([]models.CloudScanRun, error)
}

type cloudScanScheduleRepository struct{ db *gorm.DB }

func NewCloudScanScheduleRepository(db *gorm.DB) CloudScanScheduleRepository {
	return &cloudScanScheduleRepository{db: db}
}

func (r *cloudScanScheduleRepository) Get(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID,
) (*models.CloudScanSchedule, error) {
	return r.get(tx, workspaceID, connectorID, false)
}

func (r *cloudScanScheduleRepository) GetForUpdate(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID,
) (*models.CloudScanSchedule, error) {
	return r.get(tx, workspaceID, connectorID, true)
}

func (r *cloudScanScheduleRepository) get(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, lock bool,
) (*models.CloudScanSchedule, error) {
	var s models.CloudScanSchedule
	q := tx.Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := q.First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudScanScheduleNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *cloudScanScheduleRepository) Upsert(tx *gorm.DB, s *models.CloudScanSchedule) error {
	tz := s.Timezone
	if tz == "" {
		tz = "UTC"
	}
	return tx.Exec(`
		INSERT INTO cloud_scan_schedule
			(connector_id, workspace_id, enabled, interval_minutes, next_due_at,
			 last_enqueued_at, streak_since, paused_reason, updated_by,
			 time_of_day_minutes, timezone, day_of_week, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now(), now())
		ON CONFLICT (connector_id) DO UPDATE SET
			enabled             = EXCLUDED.enabled,
			interval_minutes    = EXCLUDED.interval_minutes,
			next_due_at         = EXCLUDED.next_due_at,
			streak_since        = EXCLUDED.streak_since,
			paused_reason       = EXCLUDED.paused_reason,
			updated_by          = EXCLUDED.updated_by,
			time_of_day_minutes = EXCLUDED.time_of_day_minutes,
			timezone            = EXCLUDED.timezone,
			day_of_week         = EXCLUDED.day_of_week,
			updated_at          = now()`,
		s.ConnectorID, s.WorkspaceID, s.Enabled, s.IntervalMinutes, s.NextDueAt,
		s.LastEnqueuedAt, s.StreakSince, s.PausedReason, s.UpdatedBy,
		s.TimeOfDayMinutes, tz, s.DayOfWeek,
	).Error
}

func (r *cloudScanScheduleRepository) ClaimDue(
	now time.Time, limit int, lease time.Duration,
) ([]DueSchedule, error) {
	var out []DueSchedule
	// TENANT-EXEMPT: the scheduler's claim takes due schedules of any workspace, like the scan worker's claim; each row names its workspace and everything that follows runs scoped to it.
	err := r.db.Raw(`
		WITH due AS (
			-- TENANT-EXEMPT: part of the cross-workspace claim above.
			SELECT s.connector_id, s.next_due_at AS prev_due_at
			  FROM cloud_scan_schedule s
			  JOIN cloud_connector c
			    ON c.workspace_id = s.workspace_id AND c.id = s.connector_id
			 WHERE s.enabled
			   AND s.paused_reason = ''
			   AND s.next_due_at <= ?
			   AND c.provider = 'aws'
			   AND c.status <> 'revoked'
			 ORDER BY s.next_due_at
			 FOR UPDATE OF s SKIP LOCKED
			 LIMIT ?
		)
		UPDATE cloud_scan_schedule t
		   SET next_due_at = ?, updated_at = ?
		  FROM due
		 WHERE t.connector_id = due.connector_id
		RETURNING t.connector_id, t.workspace_id, t.interval_minutes,
		          t.time_of_day_minutes, t.timezone, t.day_of_week, due.prev_due_at,
		          t.next_due_at AS claimed_until`,
		now, limit, now.Add(lease), now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudScanScheduleRepository) update(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, cols map[string]any,
) error {
	return tx.Model(&models.CloudScanSchedule{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Updates(cols).Error
}

func (r *cloudScanScheduleRepository) Advance(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, now, nextDue, claimedUntil time.Time,
) error {
	res := tx.Model(&models.CloudScanSchedule{}).
		Where("workspace_id = ? AND connector_id = ? AND enabled AND paused_reason = '' AND next_due_at = ?",
			workspaceID, connectorID, claimedUntil).
		Updates(map[string]any{"next_due_at": nextDue, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return ErrScheduleChanged
	}
	return nil
}

func (r *cloudScanScheduleRepository) MarkEnqueued(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, at time.Time,
) error {
	return r.update(tx, workspaceID, connectorID, map[string]any{
		"last_enqueued_at": at,
		"updated_at":       at,
	})
}

func (r *cloudScanScheduleRepository) RetrySoon(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, at time.Time,
) error {
	return r.update(tx, workspaceID, connectorID, map[string]any{
		"next_due_at": at,
		"updated_at":  time.Now(),
	})
}

func (r *cloudScanScheduleRepository) Pause(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, reason string, now time.Time,
) error {
	return r.update(tx, workspaceID, connectorID, map[string]any{
		"paused_reason": reason,
		"updated_at":    now,
	})
}

func (r *cloudScanScheduleRepository) Disable(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, now time.Time,
) error {
	return r.update(tx, workspaceID, connectorID, map[string]any{
		"enabled":       false,
		"paused_reason": "",
		"updated_at":    now,
	})
}

func (r *cloudScanScheduleRepository) RecentScheduledRuns(
	tx *gorm.DB, workspaceID, connectorID uuid.UUID, since *time.Time, n int,
) ([]models.CloudScanRun, error) {
	q := tx.Where(`workspace_id = ? AND connector_id = ? AND "trigger" = ?`,
		workspaceID, connectorID, models.CloudScanTriggerScheduled)
	if since != nil {
		q = q.Where("requested_at > ?", *since)
	}
	var runs []models.CloudScanRun
	if err := q.Order("requested_at DESC").Limit(n).Find(&runs).Error; err != nil {
		return nil, err
	}
	return runs, nil
}
