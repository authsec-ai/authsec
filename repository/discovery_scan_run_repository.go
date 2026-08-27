package repositories

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrScanRunNotFound is returned when a run id does not resolve inside the
// caller's workspace. A run belonging to another workspace is reported as
// missing rather than forbidden — an id is not a capability, and confirming
// that someone else's id exists is itself a disclosure.
var ErrScanRunNotFound = errors.New("scan run not found")

// ErrScanAlreadyActive is returned when a source already has a queued or
// running scan. The caller should surface the existing run rather than starting
// a second one: two workers on the same repositories would race on identical
// fingerprints and spend the installation's rate limit twice for one answer.
var ErrScanAlreadyActive = errors.New("a scan is already queued or running for this source")

// ErrScanRunNotClaimable is returned when a run cannot be transitioned because
// another worker holds it or it has already finished.
var ErrScanRunNotClaimable = errors.New("scan run is not claimable")

// DiscoveryScanRunRepository persists GitHub scan runs, which double as the
// scan work queue. See 007_discovery_scan_runs.sql for why one table serves
// both roles.
type DiscoveryScanRunRepository interface {
	// Enqueue creates a queued run. Returns ErrScanAlreadyActive together with
	// the run already in flight, so the caller can point the console at it.
	Enqueue(run *models.DiscoveryScanRun) (*models.DiscoveryScanRun, error)

	Get(workspaceID, id uuid.UUID) (*models.DiscoveryScanRun, error)
	ListForSource(workspaceID, sourceID uuid.UUID, limit int) ([]models.DiscoveryScanRun, error)
	Latest(workspaceID, sourceID uuid.UUID) (*models.DiscoveryScanRun, error)
	ActiveForSource(workspaceID, sourceID uuid.UUID) (*models.DiscoveryScanRun, error)

	// ClaimNext leases the oldest runnable run to worker. Runs whose lease has
	// expired are reclaimable: a worker that died mid-scan must not strand its
	// run forever.
	ClaimNext(worker string, lease time.Duration) (*models.DiscoveryScanRun, error)

	// SaveProgress writes counters, warnings and the resume cursor, and extends
	// the lease. Called between repositories so the console sees movement and a
	// long scan does not look hung.
	SaveProgress(run *models.DiscoveryScanRun, lease time.Duration) error

	// Finish moves a run to a terminal state exactly once.
	Finish(run *models.DiscoveryScanRun, status, failure string) error

	// Requeue returns a run to the queue after a recoverable worker failure,
	// preserving its cursor so the retry resumes. Marks the run failed instead
	// once attempts reach max_attempts.
	Requeue(run *models.DiscoveryScanRun, failure string) error

	Cancel(workspaceID, id uuid.UUID) (*models.DiscoveryScanRun, error)
}

type discoveryScanRunRepository struct{ db *gorm.DB }

// NewDiscoveryScanRunRepository constructs a DiscoveryScanRunRepository.
func NewDiscoveryScanRunRepository(db *gorm.DB) DiscoveryScanRunRepository {
	return &discoveryScanRunRepository{db}
}

// isUniqueViolation matches the codebase's existing convention for spotting a
// duplicate-key error without a driver-specific dependency.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505")
}

func scanRunNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrScanRunNotFound
	}
	return err
}

func (r *discoveryScanRunRepository) Enqueue(run *models.DiscoveryScanRun) (*models.DiscoveryScanRun, error) {
	if run.WorkspaceID == uuid.Nil || run.SourceID == uuid.Nil {
		return nil, errors.New("workspace and source are required to queue a scan")
	}
	run.Status = models.ScanRunQueued
	run.QueuedAt = time.Now()
	if run.MaxAttempts <= 0 {
		run.MaxAttempts = 3
	}
	if len(run.Cursor) == 0 {
		run.Cursor = []byte(`{}`)
	}
	if len(run.Warnings) == 0 {
		run.Warnings = []byte(`[]`)
	}
	if len(run.ExcludedRepositories) == 0 {
		run.ExcludedRepositories = []byte(`[]`)
	}

	err := r.db.Create(run).Error
	if err == nil {
		return run, nil
	}
	// The partial unique index fired: something is already in flight. Hand back
	// the run that won so the caller can watch it instead of erroring blindly.
	if isUniqueViolation(err) {
		if active, aerr := r.ActiveForSource(run.WorkspaceID, run.SourceID); aerr == nil {
			return active, ErrScanAlreadyActive
		}
		return nil, ErrScanAlreadyActive
	}
	return nil, err
}

func (r *discoveryScanRunRepository) Get(workspaceID, id uuid.UUID) (*models.DiscoveryScanRun, error) {
	var run models.DiscoveryScanRun
	if err := r.db.First(&run, "workspace_id = ? AND id = ?", workspaceID, id).Error; err != nil {
		return nil, scanRunNotFound(err)
	}
	return &run, nil
}

func (r *discoveryScanRunRepository) ListForSource(workspaceID, sourceID uuid.UUID, limit int) ([]models.DiscoveryScanRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var runs []models.DiscoveryScanRun
	err := r.db.Where("workspace_id = ? AND source_id = ?", workspaceID, sourceID).
		Order("queued_at DESC").Limit(limit).Find(&runs).Error
	return runs, err
}

func (r *discoveryScanRunRepository) Latest(workspaceID, sourceID uuid.UUID) (*models.DiscoveryScanRun, error) {
	var run models.DiscoveryScanRun
	err := r.db.Where("workspace_id = ? AND source_id = ?", workspaceID, sourceID).
		Order("queued_at DESC").First(&run).Error
	if err != nil {
		return nil, scanRunNotFound(err)
	}
	return &run, nil
}

func (r *discoveryScanRunRepository) ActiveForSource(workspaceID, sourceID uuid.UUID) (*models.DiscoveryScanRun, error) {
	var run models.DiscoveryScanRun
	err := r.db.Where("workspace_id = ? AND source_id = ? AND status IN ?",
		workspaceID, sourceID, []string{models.ScanRunQueued, models.ScanRunRunning}).
		Order("queued_at DESC").First(&run).Error
	if err != nil {
		return nil, scanRunNotFound(err)
	}
	return &run, nil
}

func (r *discoveryScanRunRepository) ClaimNext(worker string, lease time.Duration) (*models.DiscoveryScanRun, error) {
	var claimed models.DiscoveryScanRun
	now := time.Now()
	until := now.Add(lease)

	err := r.db.Transaction(func(tx *gorm.DB) error {
		var candidate models.DiscoveryScanRun
		// Two things are claimable: a queued run, and a running run whose lease
		// expired because the worker holding it died. SKIP LOCKED lets a second
		// replica move past a row another replica is already claiming instead of
		// blocking behind it.
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", models.ScanRunQueued).
			Or("status = ? AND (leased_until IS NULL OR leased_until < ?)", models.ScanRunRunning, now).
			Order("queued_at").First(&candidate).Error
		if err != nil {
			return err
		}
		res := tx.Model(&models.DiscoveryScanRun{}).
			Where("id = ?", candidate.ID).
			Updates(map[string]interface{}{
				"status":       models.ScanRunRunning,
				"leased_by":    worker,
				"leased_until": until,
				"heartbeat_at": now,
				"attempts":     candidate.Attempts + 1,
				"started_at":   gorm.Expr("COALESCE(started_at, ?)", now),
				"updated_at":   now,
			})
		if res.Error != nil {
			return res.Error
		}
		return tx.First(&claimed, "id = ?", candidate.ID).Error
	})
	if err != nil {
		return nil, scanRunNotFound(err)
	}
	return &claimed, nil
}

func (r *discoveryScanRunRepository) SaveProgress(run *models.DiscoveryScanRun, lease time.Duration) error {
	now := time.Now()
	res := r.db.Model(&models.DiscoveryScanRun{}).
		// Guarded on the lease: a worker whose lease was stolen after it stalled
		// must not keep writing progress over the worker that took the run on.
		Where("id = ? AND leased_by = ?", run.ID, run.LeasedBy).
		Updates(map[string]interface{}{
			"repos_selected":        run.ReposSelected,
			"repos_scanned":         run.ReposScanned,
			"repos_failed":          run.ReposFailed,
			"repos_excluded":        run.ReposExcluded,
			"repos_truncated":       run.ReposTruncated,
			"branches_scanned":      run.BranchesScanned,
			"branches_skipped":      run.BranchesSkipped,
			"files_fetched":         run.FilesFetched,
			"files_failed":          run.FilesFailed,
			"sightings_new":         run.SightingsNew,
			"sightings_bumped":      run.SightingsBumped,
			"excluded_repositories": run.ExcludedRepositories,
			"warnings":              run.Warnings,
			"cursor":                run.Cursor,
			// Monotonic: once we know a gap exists, no later write clears it.
			"degraded":     gorm.Expr("discovery_scan_runs.degraded OR ?", run.Degraded),
			"heartbeat_at": now,
			"leased_until": now.Add(lease),
			"updated_at":   now,
		})
	if res.Error != nil {
		return res.Error
	}
	// No row matched, so the lease guard rejected us: this run was taken over
	// while we were working. Report it so the worker stops immediately instead
	// of continuing to spend API budget on a scan that now belongs to someone
	// else and whose result it will never be allowed to write.
	if res.RowsAffected == 0 {
		return ErrScanRunNotClaimable
	}
	return nil
}

func (r *discoveryScanRunRepository) Finish(run *models.DiscoveryScanRun, status, failure string) error {
	now := time.Now()
	// Completeness is DERIVED, never taken on trust: the run must have finished
	// successfully, and no attempt of it may have recorded a gap. Deriving it
	// here is what makes a resumed scan honest — attempt one's 403 is still
	// remembered in `degraded` when attempt two finishes cleanly.
	complete := status == models.ScanRunSucceeded && run.Complete && !run.Degraded
	res := r.db.Model(&models.DiscoveryScanRun{}).
		Where("id = ? AND status = ?", run.ID, models.ScanRunRunning).
		Updates(map[string]interface{}{
			"status":                status,
			"complete":              complete,
			"degraded":              gorm.Expr("discovery_scan_runs.degraded OR ?", run.Degraded),
			"error":                 failure,
			"repos_selected":        run.ReposSelected,
			"repos_scanned":         run.ReposScanned,
			"repos_failed":          run.ReposFailed,
			"repos_excluded":        run.ReposExcluded,
			"repos_truncated":       run.ReposTruncated,
			"branches_scanned":      run.BranchesScanned,
			"branches_skipped":      run.BranchesSkipped,
			"files_fetched":         run.FilesFetched,
			"files_failed":          run.FilesFailed,
			"sightings_new":         run.SightingsNew,
			"sightings_bumped":      run.SightingsBumped,
			"excluded_repositories": run.ExcludedRepositories,
			"warnings":              run.Warnings,
			"cursor":                run.Cursor,
			"leased_by":             "",
			"leased_until":          nil,
			"finished_at":           now,
			"updated_at":            now,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrScanRunNotClaimable
	}
	return nil
}

func (r *discoveryScanRunRepository) Requeue(run *models.DiscoveryScanRun, failure string) error {
	now := time.Now()
	// Out of attempts: stop retrying and record why. A run that kills the worker
	// on every attempt would otherwise cycle forever, and each cycle costs real
	// GitHub API budget.
	if run.Attempts >= run.MaxAttempts {
		return r.Finish(run, models.ScanRunFailed,
			failure+" (giving up after "+strconv.Itoa(run.Attempts)+" attempts)")
	}
	return r.db.Model(&models.DiscoveryScanRun{}).
		Where("id = ?", run.ID).
		Updates(map[string]interface{}{
			"status": models.ScanRunQueued,
			"error":  failure,
			// The cursor survives, so the retry skips what this attempt finished.
			"cursor":       run.Cursor,
			"warnings":     run.Warnings,
			"leased_by":    "",
			"leased_until": nil,
			"updated_at":   now,
		}).Error
}

func (r *discoveryScanRunRepository) Cancel(workspaceID, id uuid.UUID) (*models.DiscoveryScanRun, error) {
	now := time.Now()
	res := r.db.Model(&models.DiscoveryScanRun{}).
		Where("workspace_id = ? AND id = ? AND status IN ?", workspaceID, id,
			[]string{models.ScanRunQueued, models.ScanRunRunning}).
		Updates(map[string]interface{}{
			"status": models.ScanRunCancelled,
			// A cancelled run keeps its counters: work already done was still
			// done, and the sightings it reported are already in the inventory.
			"finished_at":  now,
			"leased_by":    "",
			"leased_until": nil,
			"updated_at":   now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrScanRunNotClaimable
	}
	return r.Get(workspaceID, id)
}
