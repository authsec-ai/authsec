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
// THE STATE MACHINE, and the one rule that shapes all of it:
//
//	           expired                    expired
//	  ┌──────────────────────┐  ┌─────────────────────────┐
//	  ▼                      │  ▼                         │
//	collecting ──publish──▶ projecting ──done──▶ idle ──claim─┘
//	  │                      │                    ▲
//	  └──── abandon ─────────┴────────────────────┘
//	        (terminalize run + job first)
//
// EXPIRY ALONE MUST NEVER RETURN THE BARRIER TO idle. A projecting lease whose
// worker died still has a published run whose inventory is being read;
// releasing the barrier lets the next scan rewrite a shared resource row
// underneath it -- the exact overwrite this barrier exists to prevent.
// Recovery therefore RECLAIMS THE SAME PHASE under a new fencing version: the
// dead worker is fenced out by the version, and the phase invariant holds
// throughout. Only Abandon returns to idle, and it is not a timeout -- it
// fires past the attempts ceiling and first drives both the scan run and the
// projection job to a terminal state in the same transaction, so nothing is
// admitted while either could still commit.
//
// Every ownership check binds (workspace, phase, run-or-job id, version), not
// the version alone. A worker holding collecting@v7 cannot perform a
// projecting transition even if the version happens to match.
//
// COST, STATED PLAINLY: scanning is serialized per WORKSPACE, not per
// connector. A customer with five AWS accounts scans them one at a time.
type IGAPipelineLeaseRepository interface {
	// AcquireForCollection takes the barrier for a scan.
	//
	// Claims ONLY from idle, or recovers an expired COLLECTING lease held for
	// this same run (the reclaimed-run case) -- never an expired projecting
	// one. Returns the new version, or ErrPipelineLost when the workspace is
	// busy.
	AcquireForCollection(ws uuid.UUID, holder string, runID uuid.UUID, lease time.Duration, now time.Time) (int64, error)

	// AcquireForCollectorProjection takes an idle barrier for a collector run.
	// It refuses a barrier that already names a cloud run.
	AcquireForCollectorProjection(ws, igaRunID, jobID uuid.UUID, lease time.Duration, now time.Time) (int64, error)

	// ToProjectingTx flips collecting -> projecting IN THE PUBLISH
	// TRANSACTION, so the barrier is never released between the two, and
	// hands it to the JOB: holder becomes job:<jobID> (§2.10A). Whoever holds
	// that job's lease may then proceed at once -- there is no worker name to
	// match and no expiry to wait out.
	ToProjectingTx(tx *gorm.DB, ws uuid.UUID, scanHolder string, runID uuid.UUID, version int64, jobID uuid.UUID, lease time.Duration) (int64, error)

	// RenewHeld extends the barrier's expiry WITHOUT bumping the version, so
	// the holder's fence stays valid. A projection longer than the barrier
	// lease would otherwise appear in ExpiredCandidates while perfectly
	// healthy, and the recovery loop could abandon live work.
	RenewHeld(f PipelineFence, lease time.Duration, now time.Time) error

	// AssertHeldTx proves, inside the caller's transaction, that this worker
	// still holds the barrier in the phase it thinks it does -- and LOCKS the
	// row FOR UPDATE for the transaction's life, which is what makes
	// rev = max(rev)+1 safe in InsertPublication.
	AssertHeldTx(tx *gorm.DB, f PipelineFence) error

	// ReleaseTx returns the barrier to idle, bound to phase, run and version.
	// Runs in the caller's transaction so it commits atomically with the job's
	// completion.
	ReleaseTx(tx *gorm.DB, f PipelineFence) error

	// AbandonTx terminalizes the scan run and its projection job and THEN
	// returns the barrier to idle -- all in the caller's transaction.
	AbandonTx(tx *gorm.DB, f PipelineFence, reason string) error

	// ExpiredCandidates lists leases whose holder is gone, for the recovery
	// loop. It changes nothing: recovery is phase-specific and is performed by
	// the worker that takes the work over.
	ExpiredCandidates(now time.Time, limit int) ([]models.IGAPipelineLease, error)

	Get(ws uuid.UUID) (*models.IGAPipelineLease, error)
}

// PipelineFence binds a barrier operation to (workspace, phase, run, version).
//
// THE PHASE IS PART OF THE PREDICATE, not decoration: a worker holding
// collecting@v7 must not be able to perform a projecting transition even if
// the version happens to match.
//
// Holder binds the holder too (§2.10A): the scan worker's owner while
// collecting, models.PipelineJobHolder(job) while projecting. Empty means "any
// holder", which only the recovery loop uses -- it acts on the row it read.
type PipelineFence struct {
	WorkspaceID uuid.UUID
	Phase       string
	RunID       uuid.UUID
	Version     int64
	Holder      string
	// RunKind is empty for a cloud_scan_run. models.RunKindCollector means
	// RunID is an iga_scan_runs id and the cloud column must be null.
	RunKind string
}

// holderClause adds the holder predicate when the fence names one.
func (f PipelineFence) holderClause() (string, []any) {
	if f.Holder == "" {
		return "", nil
	}
	return " AND holder = ?", []any{f.Holder}
}

type igaPipelineLeaseRepository struct{ db *gorm.DB }

func NewIGAPipelineLeaseRepository(db *gorm.DB) IGAPipelineLeaseRepository {
	return &igaPipelineLeaseRepository{db: db}
}

// AcquireForCollection is the transition a later scan COLLIDES WITH while a
// projection is in flight: projecting is not claimable here at all, expired or
// not, and because the barrier is a committed row rather than a session lock
// it survives the gap between the publish transaction and the projection
// transaction.
func (r *igaPipelineLeaseRepository) AcquireForCollection(
	ws uuid.UUID, holder string, runID uuid.UUID, lease time.Duration, now time.Time,
) (int64, error) {
	var out []models.IGAPipelineLease
	// INSERT ... ON CONFLICT so the first scan in a workspace does not need a
	// separate row-creation step that could race with itself.
	//
	// The WHERE admits exactly two cases:
	//   * idle -- an ordinary claim;
	//   * collecting, EXPIRED, and for THIS run -- recovery of a dead
	//     collector, staying in the same phase for the same run.
	// An expired PROJECTING lease matches neither, which is the whole point.
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
		   OR (iga_pipeline_lease.state = ?
		       AND iga_pipeline_lease.scan_run_id = ?
		       AND iga_pipeline_lease.expires_at IS NOT NULL
		       AND iga_pipeline_lease.expires_at <= ?)
		RETURNING *`,
		ws, models.PipelineCollecting, holder, runID, now.Add(lease), now,
		models.PipelineIdle,
		models.PipelineCollecting, runID, now,
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
// back so does this, and the barrier is never left claiming to be projecting a
// run that was never published.
func (r *igaPipelineLeaseRepository) ToProjectingTx(
	tx *gorm.DB, ws uuid.UUID, scanHolder string, runID uuid.UUID, version int64,
	jobID uuid.UUID, lease time.Duration,
) (int64, error) {
	var out []models.IGAPipelineLease
	err := tx.Raw(`
		UPDATE iga_pipeline_lease SET
			state      = ?,
			holder     = ?,
			expires_at = ?,
			version    = version + 1,
			updated_at = now()
		 WHERE workspace_id = ? AND state = ? AND holder = ?
		   AND scan_run_id = ? AND version = ?
		RETURNING *`,
		models.PipelineProjecting, models.PipelineJobHolder(jobID), time.Now().Add(lease),
		ws, models.PipelineCollecting, scanHolder, runID, version,
	).Scan(&out).Error
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("%w: workspace=%s not collecting run %s at version %d",
			ErrPipelineLost, ws, runID, version)
	}
	return out[0].Version, nil
}

// AcquireForCollectorProjection moves idle -> projecting for one iga_scan_run,
// or reclaims an expired projecting barrier for that same run. The barrier
// stays projecting, the run does not change, and version increments so the
// dead worker's fence fails. scan_run_id stays NULL. A live barrier, or one
// that names a different run, is not stolen.
func (r *igaPipelineLeaseRepository) AcquireForCollectorProjection(
	ws, igaRunID, jobID uuid.UUID, lease time.Duration, now time.Time,
) (int64, error) {
	var out []models.IGAPipelineLease
	err := r.db.Raw(`
		INSERT INTO iga_pipeline_lease
			(workspace_id, state, holder, iga_scan_run_id, expires_at, version, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, ?)
		ON CONFLICT (workspace_id) DO UPDATE SET
			state = EXCLUDED.state,
			holder = EXCLUDED.holder,
			scan_run_id = NULL,
			iga_scan_run_id = EXCLUDED.iga_scan_run_id,
			expires_at = EXCLUDED.expires_at,
			version = iga_pipeline_lease.version + 1,
			updated_at = EXCLUDED.updated_at
		 WHERE iga_pipeline_lease.state = ?
		    OR (iga_pipeline_lease.state = ?
		        AND iga_pipeline_lease.iga_scan_run_id = EXCLUDED.iga_scan_run_id
		        AND iga_pipeline_lease.scan_run_id IS NULL
		        AND iga_pipeline_lease.expires_at IS NOT NULL
		        AND iga_pipeline_lease.expires_at <= ?)
		RETURNING *`,
		ws, models.PipelineProjecting, models.PipelineJobHolder(jobID), igaRunID, now.Add(lease), now,
		models.PipelineIdle,
		models.PipelineProjecting, now,
	).Scan(&out).Error
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("%w: workspace=%s is busy", ErrPipelineLost, ws)
	}
	return out[0].Version, nil
}

// RenewHeld is the heartbeat for EITHER phase: it extends the expiry and
// leaves the version alone, so the holder's fence stays valid.
func (r *igaPipelineLeaseRepository) RenewHeld(
	f PipelineFence, lease time.Duration, now time.Time,
) error {
	hc, hargs := f.holderClause()
	runCol := "scan_run_id"
	if f.RunKind == models.RunKindCollector {
		runCol = "iga_scan_run_id"
	}
	args := append([]any{now.Add(lease), f.WorkspaceID, f.Phase, f.RunID, f.Version}, hargs...)
	res := r.db.Exec(`
		UPDATE iga_pipeline_lease SET expires_at = ?, updated_at = now()
		 WHERE workspace_id = ? AND state = ? AND `+runCol+` = ? AND version = ?`+hc,
		args...)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: workspace=%s run=%s version=%d not in %s",
			ErrPipelineLost, f.WorkspaceID, f.RunID, f.Version, f.Phase)
	}
	return nil
}

func (r *igaPipelineLeaseRepository) AssertHeldTx(tx *gorm.DB, f PipelineFence) error {
	var lease models.IGAPipelineLease
	// FOR UPDATE, not a bare read: the lock is held for the transaction's
	// life, so the barrier serializes projection per workspace and
	// rev = max(rev)+1 in InsertPublication cannot race.
	err := tx.Raw(`SELECT * FROM iga_pipeline_lease WHERE workspace_id = ? FOR UPDATE`,
		f.WorkspaceID).Scan(&lease).Error
	if err != nil {
		return err
	}
	if lease.WorkspaceID == uuid.Nil {
		return fmt.Errorf("%w: workspace=%s has no barrier row", ErrPipelineLost, f.WorkspaceID)
	}
	if f.RunKind == models.RunKindCollector {
		if lease.State != f.Phase || lease.Version != f.Version ||
			lease.IGAScanRunID == nil || *lease.IGAScanRunID != f.RunID ||
			lease.ScanRunID != nil ||
			(f.Holder != "" && lease.Holder != f.Holder) {
			return fmt.Errorf("%w: workspace=%s wanted collector %s/run=%s/v%d, found %s/iga=%v/cloud=%v/v%d",
				ErrPipelineLost, f.WorkspaceID, f.Phase, f.RunID, f.Version,
				lease.State, lease.IGAScanRunID, lease.ScanRunID, lease.Version)
		}
		return nil
	}
	if lease.State != f.Phase || lease.Version != f.Version ||
		lease.ScanRunID == nil || *lease.ScanRunID != f.RunID ||
		lease.IGAScanRunID != nil ||
		(f.Holder != "" && lease.Holder != f.Holder) {
		return fmt.Errorf("%w: workspace=%s wanted %s/run=%s/v%d, found %s/run=%v/v%d",
			ErrPipelineLost, f.WorkspaceID, f.Phase, f.RunID, f.Version,
			lease.State, lease.ScanRunID, lease.Version)
	}
	return nil
}

// ReleaseTx is the only non-abandon path back to idle, bound to phase, run,
// version and -- when the fence names one -- holder.
//
// iga_pipeline_lease_busy_chk requires an empty holder and a NULL scan_run_id
// exactly when state='idle', so all three move together or the row is refused.
func (r *igaPipelineLeaseRepository) ReleaseTx(tx *gorm.DB, f PipelineFence) error {
	hc, hargs := f.holderClause()
	if f.RunKind == models.RunKindCollector {
		args := append([]any{models.PipelineIdle, f.WorkspaceID, f.Phase, f.RunID, f.Version}, hargs...)
		res := tx.Exec(`
			UPDATE iga_pipeline_lease SET
				state = ?, holder = '', scan_run_id = NULL, iga_scan_run_id = NULL, expires_at = NULL,
				version = version + 1, updated_at = now()
			 WHERE workspace_id = ? AND state = ? AND iga_scan_run_id = ? AND version = ?`+hc,
			args...)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: workspace=%s run=%s version=%d not in %s",
				ErrPipelineLost, f.WorkspaceID, f.RunID, f.Version, f.Phase)
		}
		return nil
	}
	args := append([]any{models.PipelineIdle, f.WorkspaceID, f.Phase, f.RunID, f.Version}, hargs...)
	res := tx.Exec(`
		UPDATE iga_pipeline_lease SET
			state = ?, holder = '', scan_run_id = NULL, expires_at = NULL,
			version = version + 1, updated_at = now()
		 WHERE workspace_id = ? AND state = ? AND scan_run_id = ? AND version = ?`+hc,
		args...)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: workspace=%s run=%s version=%d not in %s",
			ErrPipelineLost, f.WorkspaceID, f.RunID, f.Version, f.Phase)
	}
	return nil
}

// AbandonTx gives up on a run entirely: the scan run and its projection job go
// terminal FIRST, and only then does the barrier return to idle.
//
// The ordering is the guarantee -- nothing is admitted while either could
// still commit. An ALREADY-PUBLISHED run is left alone: published is already
// terminal, and cloud_scan_run_published_chk would reject
// status='abandoned' on a row that still carries published_at.
func (r *igaPipelineLeaseRepository) AbandonTx(
	tx *gorm.DB, f PipelineFence, reason string,
) error {
	ws, runID, version := f.WorkspaceID, f.RunID, f.Version
	if f.RunKind == models.RunKindCollector {
		if err := tx.Exec(`
			UPDATE iga_scan_runs
			   SET status = 'failed', failure_code = ?, completed_at = now()
			 WHERE workspace_id = ? AND id = ? AND status IN ('pending', 'running')`,
			truncateError(reason), ws, runID).Error; err != nil {
			return err
		}
		if err := tx.Exec(`
			UPDATE iga_projection_job
			   SET status = ?, lease_owner = '', lease_expires_at = NULL,
			       last_error = ?, completed_at = now()
			 WHERE workspace_id = ? AND iga_scan_run_id = ? AND status IN (?, ?)`,
			models.ProjectionAbandoned, truncateError(reason),
			ws, runID, models.ProjectionQueued, models.ProjectionRunning).Error; err != nil {
			return err
		}
		res := tx.Exec(`
			UPDATE iga_pipeline_lease SET
				state = ?, holder = '', scan_run_id = NULL, iga_scan_run_id = NULL, expires_at = NULL,
				version = version + 1, updated_at = now()
			 WHERE workspace_id = ? AND version = ? AND iga_scan_run_id = ?`,
			models.PipelineIdle, ws, version, runID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: workspace=%s version=%d", ErrPipelineLost, ws, version)
		}
		return nil
	}
	if err := tx.Exec(`
		UPDATE cloud_scan_run
		   SET status = ?, lease_owner = '', lease_expires_at = NULL,
		       last_error = ?, updated_at = now()
		 WHERE workspace_id = ? AND id = ? AND status IN (?, ?)`,
		models.CloudScanRunAbandoned, truncateError(reason),
		ws, runID, models.CloudScanRunQueued, models.CloudScanRunRunning).Error; err != nil {
		return err
	}
	if err := tx.Exec(`
		UPDATE iga_projection_job
		   SET status = ?, lease_owner = '', lease_expires_at = NULL,
		       last_error = ?, completed_at = now()
		 WHERE workspace_id = ? AND scan_run_id = ? AND status IN (?, ?)`,
		models.ProjectionAbandoned, truncateError(reason),
		ws, runID, models.ProjectionQueued, models.ProjectionRunning).Error; err != nil {
		return err
	}
	res := tx.Exec(`
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

// ExpiredCandidates is read-only on purpose. There is no blind sweep: the
// phase decides what recovery means, and only the worker that takes the work
// over can perform it.
func (r *igaPipelineLeaseRepository) ExpiredCandidates(
	now time.Time, limit int,
) ([]models.IGAPipelineLease, error) {
	if limit <= 0 {
		limit = 50
	}
	var out []models.IGAPipelineLease
	err := r.db.Raw(`
		SELECT * FROM iga_pipeline_lease
		 WHERE state <> ? AND expires_at IS NOT NULL AND expires_at <= ?
		 ORDER BY updated_at
		 LIMIT ?`, models.PipelineIdle, now, limit).Scan(&out).Error
	return out, err
}

func (r *igaPipelineLeaseRepository) Get(ws uuid.UUID) (*models.IGAPipelineLease, error) {
	var l models.IGAPipelineLease
	if err := r.db.First(&l, "workspace_id = ?", ws).Error; err != nil {
		return nil, err
	}
	return &l, nil
}
