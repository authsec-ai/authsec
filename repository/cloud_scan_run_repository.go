package repositories

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	// ErrScanAlreadyLive is returned when a connector already has a queued or
	// running scan. Not a failure: it is the overlapping-scan protection doing
	// its job, and the caller should report the existing run rather than retry.
	ErrScanAlreadyLive = errors.New("a scan is already queued or running for this connector")

	// ErrLeaseLost is returned when an operation's fence token no longer
	// matches the row. The worker was superseded; its results are stale and
	// must not be written.
	ErrLeaseLost = errors.New("scan run lease no longer held")

	ErrCloudScanRunNotFound = errors.New("cloud scan run not found")
)

// CloudScanRunRepository owns the lifecycle of an AWS scan attempt.
//
// Every state change here is a single conditional UPDATE. That is the point:
// two workers racing must be resolved by the database, because a read followed
// by a write leaves a window in which both see the same thing and both proceed.
type CloudScanRunRepository interface {
	// Enqueue records a scan request. Refuses with ErrScanAlreadyLive when the
	// connector already has one in flight.
	Enqueue(workspaceID, connectorID uuid.UUID, trigger string) (*models.CloudScanRun, error)

	// Claim takes ownership of one claimable run for `owner`, for `lease`.
	// Returns nil when there is nothing to claim.
	Claim(owner string, lease time.Duration, now time.Time) (*models.CloudScanRun, error)

	// Renew extends a lease the caller still holds. ErrLeaseLost otherwise.
	Renew(runID uuid.UUID, owner string, version int64, lease time.Duration) error

	// Publish marks a run finished and authoritative, but only if the caller
	// still holds the fence token it claimed.
	Publish(runID uuid.UUID, owner string, version int64) error

	// Fail marks a run finished without publishing, under the same fence.
	Fail(runID uuid.UUID, owner string, version int64, reason string) error

	Get(runID uuid.UUID) (*models.CloudScanRun, error)
	Latest(workspaceID, connectorID uuid.UUID) (*models.CloudScanRun, error)
}

type cloudScanRunRepository struct{ db *gorm.DB }

func NewCloudScanRunRepository(db *gorm.DB) CloudScanRunRepository {
	return &cloudScanRunRepository{db: db}
}

func (r *cloudScanRunRepository) Enqueue(
	workspaceID, connectorID uuid.UUID, trigger string,
) (*models.CloudScanRun, error) {
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return nil, errors.New("workspace_id and connector_id are required")
	}
	run := &models.CloudScanRun{
		WorkspaceID: workspaceID,
		ConnectorID: connectorID,
		Status:      models.CloudScanRunQueued,
		Trigger:     trigger,
		RequestedAt: time.Now(),
	}
	// The partial unique index on (connector_id) WHERE status IN
	// ('queued','running') is what refuses a second live run. Relying on it
	// rather than a SELECT-then-INSERT is deliberate: two processes both see no
	// live run and both insert, and only the index can arbitrate.
	if err := r.db.Create(run).Error; err != nil {
		if isUniqueViolation(err) {
			return nil, ErrScanAlreadyLive
		}
		return nil, err
	}
	return run, nil
}

func (r *cloudScanRunRepository) Claim(
	owner string, lease time.Duration, now time.Time,
) (*models.CloudScanRun, error) {
	if owner == "" {
		return nil, errors.New("a claim needs an owner")
	}
	expires := now.Add(lease)

	// One statement, so the claim is atomic.
	//
	// Claimable is either a queued run, or a running one whose lease lapsed --
	// the crashed-worker case. `generation` is assigned here rather than at
	// enqueue: it is the number this pass stamps its rows with, and a run that
	// never started must not consume one.
	//
	// lease_version is bumped on every claim. That increment is what invalidates
	// the previous holder: it recorded the old value, and every later operation
	// of its own demands the row still carry it.
	var out []models.CloudScanRun
	err := r.db.Raw(`
		UPDATE cloud_scan_run SET
			status           = ?,
			lease_owner      = ?,
			lease_expires_at = ?,
			lease_version    = lease_version + 1,
			attempts         = attempts + 1,
			started_at       = COALESCE(started_at, ?),
			generation       = CASE WHEN generation > 0 THEN generation
			                        ELSE (SELECT COALESCE(c.scan_generation, 0) + 1
			                                FROM cloud_connector c
			                               WHERE c.id = cloud_scan_run.connector_id)
			                   END,
			updated_at       = ?
		WHERE id = (
			SELECT id FROM cloud_scan_run
			 WHERE status = ?
			    OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?))
			 ORDER BY requested_at
			 FOR UPDATE SKIP LOCKED
			 LIMIT 1
		)
		RETURNING *`,
		models.CloudScanRunRunning, owner, expires, now,
		now,
		models.CloudScanRunQueued,
		models.CloudScanRunRunning, now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil // nothing to claim
	}
	return &out[0], nil
}

func (r *cloudScanRunRepository) Renew(
	runID uuid.UUID, owner string, version int64, lease time.Duration,
) error {
	return r.fenced(runID, owner, version, map[string]any{
		"lease_expires_at": time.Now().Add(lease),
		"updated_at":       time.Now(),
	})
}

func (r *cloudScanRunRepository) Publish(runID uuid.UUID, owner string, version int64) error {
	now := time.Now()
	return r.fenced(runID, owner, version, map[string]any{
		"status":           models.CloudScanRunPublished,
		"published_at":     now,
		"lease_owner":      "",
		"lease_expires_at": nil,
		"updated_at":       now,
	})
}

func (r *cloudScanRunRepository) Fail(
	runID uuid.UUID, owner string, version int64, reason string,
) error {
	now := time.Now()
	return r.fenced(runID, owner, version, map[string]any{
		"status":           models.CloudScanRunFailed,
		"last_error":       truncateError(reason),
		"lease_owner":      "",
		"lease_expires_at": nil,
		"updated_at":       now,
	})
}

// fenced applies an update only if the row still carries the caller's owner and
// lease version.
//
// The WHERE clause is the whole safety property. It consults no clock: a worker
// that slept past its expiry is refused because the version moved on, not
// because we compared timestamps and decided it was late. Clock skew between
// two hosts therefore cannot let a superseded worker publish.
func (r *cloudScanRunRepository) fenced(
	runID uuid.UUID, owner string, version int64, updates map[string]any,
) error {
	res := r.db.Model(&models.CloudScanRun{}).
		Where("id = ? AND lease_owner = ? AND lease_version = ?", runID, owner, version).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: run=%s owner=%s version=%d", ErrLeaseLost, runID, owner, version)
	}
	return nil
}

func (r *cloudScanRunRepository) Get(runID uuid.UUID) (*models.CloudScanRun, error) {
	var run models.CloudScanRun
	err := r.db.Where("id = ?", runID).First(&run).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudScanRunNotFound
	}
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func (r *cloudScanRunRepository) Latest(
	workspaceID, connectorID uuid.UUID,
) (*models.CloudScanRun, error) {
	var run models.CloudScanRun
	err := r.db.Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Order("requested_at DESC").First(&run).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudScanRunNotFound
	}
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// truncateError keeps a provider's message without letting a pathological one
// bloat every row that reads the table.
func truncateError(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + "… (truncated)"
}
