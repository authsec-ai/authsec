package repositories

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// IGAPipelineLeaseRepository owns the workspace-wide barrier between
// collection and projection (SPEC-iga-phase2-graph.md §2.10A).
//
// WHY A ROW AND NOT A LOCK. A published run's inventory must not change while
// its projection reads it, and pg_advisory_xact_lock is released when its
// transaction commits. Publication and projection are NECESSARILY different
// transactions -- projection is a durable job claimed later -- and the window
// between them is exactly where a second connector's scan overwrites a shared
// resource row. A committed row spans that window; a session lock cannot.
//
// COST, STATED PLAINLY: scanning is serialized per WORKSPACE, not per
// connector. A customer with five AWS accounts scans them one at a time.
//
// Every transition is ONE CONDITIONAL UPDATE that demands the version it read,
// so a worker that slept past its expiry is refused because the version moved
// on -- never because a clock was consulted.
type IGAPipelineLeaseRepository interface {
	// ClaimForCollection takes an idle (or expired) pipeline for a scan.
	// Returns the new version, or ErrPipelineLost when someone else holds it.
	ClaimForCollection(ws uuid.UUID, holder string, runID uuid.UUID, lease time.Duration, now time.Time) (int64, error)

	// ToProjectingTx flips collecting -> projecting IN THE PUBLISH
	// TRANSACTION, so the barrier is never released between the two.
	ToProjectingTx(tx *gorm.DB, ws uuid.UUID, holder string, version int64, lease time.Duration) (int64, error)

	// Release returns the pipeline to idle after projection completes.
	Release(ws uuid.UUID, version int64) error

	// Sweep returns expired pipelines to idle. Recovery, so a dead worker
	// cannot wedge a workspace permanently.
	Sweep(now time.Time) (int64, error)

	Get(ws uuid.UUID) (*models.IGAPipelineLease, error)
}

type igaPipelineLeaseRepository struct{ db *gorm.DB }

func NewIGAPipelineLeaseRepository(db *gorm.DB) IGAPipelineLeaseRepository {
	return &igaPipelineLeaseRepository{db: db}
}

// ClaimForCollection is the transition a later scan COLLIDES WITH while a
// projection is in flight: state='projecting' is not claimable, and because it
// is a committed row rather than a session lock it survives the gap between
// the publish transaction and the projection transaction.
func (r *igaPipelineLeaseRepository) ClaimForCollection(
	ws uuid.UUID, holder string, runID uuid.UUID, lease time.Duration, now time.Time,
) (int64, error) {
	var out []models.IGAPipelineLease
	// INSERT ... ON CONFLICT so the first scan in a workspace does not need a
	// separate row-creation step that could race with itself.
	err := r.db.Raw(`
		INSERT INTO iga_pipeline_lease
			(workspace_id, state, holder, scan_run_id, expires_at, version, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT (workspace_id) DO UPDATE SET
			state       = EXCLUDED.state,
			holder      = EXCLUDED.holder,
			scan_run_id = EXCLUDED.scan_run_id,
			expires_at  = EXCLUDED.expires_at,
			version     = iga_pipeline_lease.version + 1,
			updated_at  = EXCLUDED.updated_at
		WHERE iga_pipeline_lease.state = ?
		   OR iga_pipeline_lease.expires_at IS NULL
		   OR iga_pipeline_lease.expires_at <= ?
		RETURNING *`,
		ws, models.PipelineCollecting, holder, runID, now.Add(lease), now,
		models.PipelineIdle, now,
	).Scan(&out).Error
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("%w: workspace=%s is busy", ErrPipelineLost, ws)
	}
	return out[0].Version, nil
}

// ToProjectingTx runs INSIDE the publish transaction. If publication rolls
// back so does this, and the pipeline is never left claiming to be projecting
// a run that was never published.
func (r *igaPipelineLeaseRepository) ToProjectingTx(
	tx *gorm.DB, ws uuid.UUID, holder string, version int64, lease time.Duration,
) (int64, error) {
	var out []models.IGAPipelineLease
	err := tx.Raw(`
		UPDATE iga_pipeline_lease SET
			state      = ?,
			expires_at = ?,
			version    = version + 1,
			updated_at = now()
		 WHERE workspace_id = ? AND state = ? AND holder = ? AND version = ?
		RETURNING *`,
		models.PipelineProjecting, time.Now().Add(lease),
		ws, models.PipelineCollecting, holder, version,
	).Scan(&out).Error
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("%w: workspace=%s not collecting at version %d", ErrPipelineLost, ws, version)
	}
	return out[0].Version, nil
}

// Release returns the pipeline to idle.
//
// iga_pipeline_lease_busy_chk requires holder=” and scan_run_id IS NULL
// exactly when state='idle', so all three move together or the row is refused.
func (r *igaPipelineLeaseRepository) Release(ws uuid.UUID, version int64) error {
	res := r.db.Exec(`
		UPDATE iga_pipeline_lease SET
			state = ?, holder = '', scan_run_id = NULL, expires_at = NULL,
			version = version + 1, updated_at = now()
		 WHERE workspace_id = ? AND version = ?`,
		models.PipelineIdle, ws, version)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: workspace=%s version=%d", ErrPipelineLost, ws, version)
	}
	return nil
}

// Sweep is the recovery path. Without it a worker that died holding
// 'projecting' would block every future scan in that workspace forever.
func (r *igaPipelineLeaseRepository) Sweep(now time.Time) (int64, error) {
	res := r.db.Exec(`
		UPDATE iga_pipeline_lease SET
			state = ?, holder = '', scan_run_id = NULL, expires_at = NULL,
			version = version + 1, updated_at = now()
		 WHERE state <> ? AND expires_at IS NOT NULL AND expires_at <= ?`,
		models.PipelineIdle, models.PipelineIdle, now)
	return res.RowsAffected, res.Error
}

func (r *igaPipelineLeaseRepository) Get(ws uuid.UUID) (*models.IGAPipelineLease, error) {
	var l models.IGAPipelineLease
	if err := r.db.First(&l, "workspace_id = ?", ws).Error; err != nil {
		return nil, err
	}
	return &l, nil
}
