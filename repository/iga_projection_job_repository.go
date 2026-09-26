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

// ProjectionRetryBackoff is how long a FAILED job waits before it may be
// claimed again.
//
// A failed job stays claimable (see Claim) because the barrier it holds is not
// released on failure -- failKeepBarrier keeps the workspace frozen so the
// pending projection's inventory cannot change. If `failed` were terminal, the
// job would never be retried, the escalation to the attempts ceiling would be
// unreachable, and the workspace would be frozen FOREVER. The backoff is what
// stops that retry becoming a hot loop.
const ProjectionRetryBackoff = 30 * time.Second

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
	// ClaimCollector takes one job on the iga_scan_run_id arm. The cloud Claim
	// never returns those rows, so a flag-off worker leaves them queued.
	ClaimCollector(owner string, lease time.Duration, now time.Time) (*models.IGAProjectionJob, error)
	// ClaimCollectorRun claims the job for one iga_scan_run, including a queued
	// job and a running or failed job whose lease has expired.
	ClaimCollectorRun(owner string, igaRunID uuid.UUID, lease time.Duration, now time.Time) (*models.IGAProjectionJob, error)
	Renew(jobID uuid.UUID, owner string, version int64, lease time.Duration) error
	Complete(jobID uuid.UUID, owner string, version int64) error
	Fail(jobID uuid.UUID, owner string, version int64, reason string) error
	Abandon(jobID uuid.UUID, owner string, version int64, reason string) error

	// AssertOwnedTx locks the job row and proves ownership INSIDE the caller's
	// transaction.
	AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64) error

	// Requeue hands a claimed job back WITHOUT counting the attempt. Used when
	// the worker cannot proceed for a reason that is not the job's fault --
	// e.g. another live worker holds the workspace barrier.
	Requeue(jobID uuid.UUID, owner string, version int64) error

	// CompleteTx and AbandonTx are the transactional terminals, for the
	// *AndRelease exits that must move the job and the barrier together.
	CompleteTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64) error
	AbandonTx(tx *gorm.DB, jobID uuid.UUID, owner string, version int64, reason string) error

	Get(jobID uuid.UUID) (*models.IGAProjectionJob, error)
}

type igaProjectionJobRepository struct{ db *gorm.DB }

func NewIGAProjectionJobRepository(db *gorm.DB) IGAProjectionJobRepository {
	return &igaProjectionJobRepository{db: db}
}

func (r *igaProjectionJobRepository) EnqueueTx(tx *gorm.DB, job *models.IGAProjectionJob) error {
	// One job per run. A cloud job conflicts on scan_run_id (033's UNIQUE).
	// A collector job conflicts on the partial unique index and leaves
	// scan_run_id and connector_id NULL.
	if job.IGAScanRunID != nil {
		if job.ScanRunID != uuid.Nil || job.ConnectorID != uuid.Nil {
			return fmt.Errorf("collector projection job must not name a cloud run or connector")
		}
		if err := tx.Omit("ScanRunID", "ConnectorID").Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "iga_scan_run_id"}},
			TargetWhere: clause.Where{Exprs: []clause.Expression{
				clause.Expr{SQL: "iga_scan_run_id IS NOT NULL"},
			}},
			DoNothing: true,
		}).Create(job).Error; err != nil {
			return err
		}
		return tx.Raw(`SELECT id FROM iga_projection_job WHERE workspace_id = ? AND iga_scan_run_id = ?`,
			job.WorkspaceID, *job.IGAScanRunID).Row().Scan(&job.ID)
	}
	// One job per scan run (033's UNIQUE). A retried publish must not enqueue
	// a second.
	if err := tx.Omit("IGAScanRunID").Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "scan_run_id"}},
		DoNothing: true,
	}).Create(job).Error; err != nil {
		return err
	}
	// READ BACK THE STORED ID. On a conflict DO NOTHING leaves the struct
	// holding the id GORM generated, which names no row -- and the publish
	// transaction hands the barrier to job:<that id>, a holder no worker could
	// ever match. The barrier would then wait out its whole lease.
	return tx.Raw(`SELECT id FROM iga_projection_job WHERE workspace_id = ? AND scan_run_id = ?`,
		job.WorkspaceID, job.ScanRunID).Row().Scan(&job.ID)
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
			   AND scan_run_id IS NOT NULL
			   AND (status = ?
			     -- A running job whose worker died.
			     OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?))
			     -- A FAILED job past its backoff. Not terminal below the
			     -- attempts ceiling: its barrier is still held, so if it were
			     -- never reclaimed the workspace would never be released.
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
		models.ProjectionFailed, now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

// ClaimCollector is Claim restricted to the collector arm.
func (r *igaProjectionJobRepository) ClaimCollector(
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
			   AND iga_scan_run_id IS NOT NULL
			   AND (status = ?
			     OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?))
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
		models.ProjectionFailed, now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

// ClaimCollectorRun is ClaimCollector for one iga_scan_run. The coordinator
// enqueues that run's job and then claims it, so a replica cannot take a
// different workspace's collector job while it holds this run's outbox.
func (r *igaProjectionJobRepository) ClaimCollectorRun(
	owner string, igaRunID uuid.UUID, lease time.Duration, now time.Time,
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
			 WHERE iga_scan_run_id = ?
			   AND attempts < ?
			   AND (status = ?
			     OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?))
			     OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)))
			 FOR UPDATE SKIP LOCKED
			 LIMIT 1
		)
		RETURNING *`,
		models.ProjectionRunning, owner, now.Add(lease),
		igaRunID,
		MaxProjectionAttempts,
		models.ProjectionQueued,
		models.ProjectionRunning, now,
		models.ProjectionFailed, now,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

func (r *igaProjectionJobRepository) Requeue(jobID uuid.UUID, owner string, version int64) error {
	return r.fenced(jobID, owner, version, map[string]any{
		"status":      models.ProjectionQueued,
		"lease_owner": "",
		// attempts is given back: this worker never got to try.
		"attempts":         gorm.Expr("GREATEST(attempts - 1, 0)"),
		"lease_expires_at": nil,
		// To the back of the queue, for the same reason a refused scan run
		// goes there (§2.10A): an oldest-first claim would re-take it at once.
		"requested_at": time.Now(),
	})
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
		"status":      models.ProjectionFailed,
		"last_error":  truncateError(reason),
		"lease_owner": "",
		// A BACKOFF, not nil. Claim admits a failed job once this passes, so
		// the retry happens without spinning. Clearing it would make the job
		// instantly claimable in a tight loop; leaving it terminal would
		// freeze the workspace forever.
		"lease_expires_at": time.Now().Add(ProjectionRetryBackoff),
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
	}
	return nil
}

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

func (r *igaProjectionJobRepository) Get(jobID uuid.UUID) (*models.IGAProjectionJob, error) {
	var job models.IGAProjectionJob
	if err := r.db.First(&job, "id = ?", jobID).Error; err != nil {
		return nil, err
	}
	return &job, nil
}
