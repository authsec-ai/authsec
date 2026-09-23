package repositories

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

var (
	// ErrProjectionLeaseLost is the projection analogue of ErrLeaseLost: the
	// worker was superseded and must write nothing further.
	ErrProjectionLeaseLost = errors.New("projection job lease no longer held")

	// ErrPipelineLost means this worker no longer holds the workspace's
	// pipeline in the state it claimed.
	ErrPipelineLost = errors.New("pipeline lease no longer held")
)

// MaxProjectionAttempts bounds retries.
//
// A job that fails DETERMINISTICALLY -- a bad source_key, a CHECK it cannot
// satisfy -- must stop and be VISIBLE, not spin against production forever.
// Past this ceiling the job stays failed with its last error.
const MaxProjectionAttempts = 5

// IGAProjectionJobRepository owns the projection job's lifecycle.
//
// It mirrors CloudScanRunRepository deliberately: one worker shape in the
// codebase, not two. Every state change is a single conditional UPDATE whose
// WHERE clause CONSULTS NO CLOCK -- a worker that slept past its expiry is
// refused because the fence version moved on.
type IGAProjectionJobRepository interface {
	// Enqueue records a projection job. Called in the SAME TRANSACTION as
	// Publish(), so a published run always has a job and a crash between the
	// two is impossible rather than recovered.
	EnqueueTx(tx *gorm.DB, job *models.IGAProjectionJob) error

	Claim(owner string, lease time.Duration, now time.Time) (*models.IGAProjectionJob, error)
	Renew(jobID uuid.UUID, owner string, version int64, lease time.Duration) error
	Complete(jobID uuid.UUID, owner string, version int64) error
	Fail(jobID uuid.UUID, owner string, version int64, reason string) error
	Abandon(jobID uuid.UUID, owner string, version int64, reason string) error

	// AssertOwnedTx locks the job row and proves ownership INSIDE the caller's
	// transaction.
	AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64) error

<<<<<<< HEAD
	// CompleteTx and AbandonTx are the transactional terminals, for the
	// *AndRelease exits that must move the job and the barrier together.
	CompleteTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64) error
	AbandonTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64, reason string) error
=======
	// AssertProjectingTx proves this worker still holds the workspace pipeline
	// in 'projecting'.
	AssertProjectingTx(tx *gorm.DB, ws uuid.UUID, version int64) error
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e

	Get(jobID uuid.UUID) (*models.IGAProjectionJob, error)
}

type igaProjectionJobRepository struct{ db *gorm.DB }

func NewIGAProjectionJobRepository(db *gorm.DB) IGAProjectionJobRepository {
	return &igaProjectionJobRepository{db: db}
}

func (r *igaProjectionJobRepository) EnqueueTx(tx *gorm.DB, job *models.IGAProjectionJob) error {
<<<<<<< HEAD
	// One job per scan run (033's UNIQUE). A retried publish must not enqueue
=======
	// One job per scan run (032's UNIQUE). A retried publish must not enqueue
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
	// a second.
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_run_id"}},
		DoNothing: true,
	}).Create(job).Error
}

// Claim takes one claimable job. Claimable is a queued job, or a running one
// whose lease lapsed -- the crashed-worker case.
//
// The attempts ceiling is in the predicate, so an exhausted job stops being
// claimed rather than being claimed and immediately failed.
func (r *igaProjectionJobRepository) Claim(
	owner string, lease time.Duration, now time.Time,
) (*models.IGAProjectionJob, error) {
	if owner == "" {
		return nil, errors.New("a claim needs an owner")
	}
	var out []models.IGAProjectionJob
	err := r.db.Raw(`
		UPDATE iga_projection_job SET
			status           = ?,
			lease_owner      = ?,
			lease_expires_at = ?,
			lease_version    = lease_version + 1,
			attempts         = attempts + 1
		WHERE id = (
			SELECT id FROM iga_projection_job
			 WHERE attempts < ?
			   AND (status = ?
			     OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)))
			 ORDER BY requested_at
			 FOR UPDATE SKIP LOCKED
			 LIMIT 1
		)
		RETURNING *`,
		models.ProjectionRunning, owner, now.Add(lease),
		MaxProjectionAttempts,
		models.ProjectionQueued,
		models.ProjectionRunning, now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

func (r *igaProjectionJobRepository) Renew(
	jobID uuid.UUID, owner string, version int64, lease time.Duration,
) error {
	return r.fenced(jobID, owner, version, map[string]any{
		"lease_expires_at": time.Now().Add(lease),
	})
}

func (r *igaProjectionJobRepository) Complete(jobID uuid.UUID, owner string, version int64) error {
	now := time.Now()
	return r.fenced(jobID, owner, version, map[string]any{
		"status":           models.ProjectionComplete,
		"completed_at":     now,
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

func (r *igaProjectionJobRepository) Fail(
	jobID uuid.UUID, owner string, version int64, reason string,
) error {
	return r.fenced(jobID, owner, version, map[string]any{
		"status":           models.ProjectionFailed,
		"last_error":       truncateError(reason),
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

// Abandon records that a newer generation superseded this job.
//
// Distinct from Fail: nothing went wrong with the work. A permanently-losing
// job must not look like one that never ran, which is why this is RECORDED
// rather than silent.
func (r *igaProjectionJobRepository) Abandon(
	jobID uuid.UUID, owner string, version int64, reason string,
) error {
	now := time.Now()
	return r.fenced(jobID, owner, version, map[string]any{
		"status":           models.ProjectionAbandoned,
		"last_error":       truncateError(reason),
		"completed_at":     now,
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

func (r *igaProjectionJobRepository) fenced(
	jobID uuid.UUID, owner string, version int64, updates map[string]any,
) error {
	res := r.db.Model(&models.IGAProjectionJob{}).
		Where("id = ? AND lease_owner = ? AND lease_version = ?", jobID, owner, version).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: job=%s owner=%s version=%d", ErrProjectionLeaseLost, jobID, owner, version)
	}
	return nil
}

// AssertOwnedTx locks the job row FOR UPDATE and proves the caller still holds
// the lease version it claimed.
//
// The lock is the point, not just the check: it is held for the transaction's
// life, so a reclaiming worker BLOCKS rather than writing concurrently. A
// check before the transaction would prove nothing -- the lease can be lost
// while writes are in flight, and a Complete() rejected afterwards cannot
// un-commit a graph mutation.
func (r *igaProjectionJobRepository) AssertOwnedTx(
	tx *gorm.DB, jobID uuid.UUID, owner string, version int64,
) error {
	var job models.IGAProjectionJob
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", jobID).First(&job).Error
	if err != nil {
		return err
	}
	if job.LeaseOwner != owner || job.LeaseVersion != version {
		return fmt.Errorf("%w: job=%s owner=%s version=%d", ErrProjectionLeaseLost, jobID, owner, version)
	}
	return nil
}

<<<<<<< HEAD
// fencedTx is fenced() against a caller-supplied transaction, so a job
// terminal can share one transaction with the barrier release.
func (r *igaProjectionJobRepository) fencedTx(
	tx *gorm.DB, jobID uuid.UUID, owner string, version int64, updates map[string]any,
) error {
	res := tx.Model(&models.IGAProjectionJob{}).
		Where("id = ? AND lease_owner = ? AND lease_version = ?", jobID, owner, version).
		Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: job=%s owner=%s version=%d", ErrProjectionLeaseLost, jobID, owner, version)
=======
func (r *igaProjectionJobRepository) AssertProjectingTx(
	tx *gorm.DB, ws uuid.UUID, version int64,
) error {
	var lease models.IGAPipelineLease
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("workspace_id = ?", ws).First(&lease).Error
	if err != nil {
		return err
	}
	if lease.State != models.PipelineProjecting || lease.Version != version {
		return fmt.Errorf("%w: workspace=%s state=%s version=%d (wanted projecting/%d)",
			ErrPipelineLost, ws, lease.State, lease.Version, version)
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
	}
	return nil
}

<<<<<<< HEAD
func (r *igaProjectionJobRepository) CompleteTx(
	tx *gorm.DB, jobID uuid.UUID, owner string, version int64,
) error {
	return r.fencedTx(tx, jobID, owner, version, map[string]any{
		"status":           models.ProjectionComplete,
		"completed_at":     time.Now(),
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

func (r *igaProjectionJobRepository) AbandonTx(
	tx *gorm.DB, jobID uuid.UUID, owner string, version int64, reason string,
) error {
	return r.fencedTx(tx, jobID, owner, version, map[string]any{
		"status":           models.ProjectionAbandoned,
		"last_error":       truncateError(reason),
		"completed_at":     time.Now(),
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

=======
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
func (r *igaProjectionJobRepository) Get(jobID uuid.UUID) (*models.IGAProjectionJob, error) {
	var job models.IGAProjectionJob
	if err := r.db.First(&job, "id = ?", jobID).Error; err != nil {
		return nil, err
	}
	return &job, nil
}
