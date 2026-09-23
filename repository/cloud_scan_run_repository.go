package repositories

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
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

	// PublishWithCoverage persists this run's coverage, publishes it, and runs
	// `after` -- ALL IN ONE TRANSACTION, under the caller's fence.
	//
	// This reverses the previous ordering deliberately. The old sequence was
	// Publish -> FinalizeCoverage -> SetCoverage (best effort), and the comment
	// there argued publication must come first so a superseded worker could not
	// overwrite the winner's coverage. THE FENCE ALREADY GUARANTEES THAT, and
	// inside one transaction the ordering of the two writes is not observable.
	//
	// What the old sequence could not guarantee is that a published run always
	// has its coverage. A crash in the gap made the loss permanent -- and the
	// projection job would then read absent coverage, canEnd would refuse every
	// partition, and the graph would silently never close anything.
	//
	// `after` is where the projection job is enqueued and the pipeline flips to
	// projecting. Both must be atomic with publication: a published run that
	// never got a job is work that silently never happens.
	//
	// COVERAGE STOPS BEING BEST-EFFORT: a scan whose coverage cannot be stored
	// has not published.
	PublishWithCoverage(
		runID uuid.UUID, owner string, version int64,
		coverage models.ScanCoverage,
		after func(tx *gorm.DB, run *models.CloudScanRun) error,
	) error

	// Fail marks a run finished without publishing, under the same fence.
	Fail(runID uuid.UUID, owner string, version int64, reason string) error

	// FailTx is Fail in the caller's transaction, so a run's failure and the
	// pipeline barrier's release commit together (§2.10A: nothing returns the
	// barrier to idle without the run already being terminal).
	FailTx(tx *gorm.DB, runID uuid.UUID, owner string, version int64, reason string) error

	// Requeue returns a claimed run to the queue WITHOUT counting it as a
	// failure.
	//
	// Used when the workspace pipeline barrier (§2.10A) is held by another
	// connector: nothing went wrong with this run, it simply cannot start yet.
	// Marking it failed would burn an attempt and eventually give up on a scan
	// that was only ever waiting its turn.
	Requeue(runID uuid.UUID, owner string, version int64) error

	// SetCoverage stamps this run's own final coverage report. Not fenced by
	// lease version: Publish already cleared lease_owner on success, so the
	// caller has nothing left to fence with by the time it knows the final
	// coverage. Guarded instead by status = published -- coverage may only ever
	// attach to a run that is already the authoritative one, never to a run
	// still in flight or one that lost the race.
	SetCoverage(runID uuid.UUID, coverage models.ScanCoverage) error

	Get(runID uuid.UUID) (*models.CloudScanRun, error)
	Latest(workspaceID, connectorID uuid.UUID) (*models.CloudScanRun, error)
}

type cloudScanRunRepository struct {
	db *gorm.DB

	// projectionJobsOnce caches whether iga_projection_job exists. The answer
	// only changes when a migration runs, which does not happen under a live
	// worker, so probing once per process is enough -- and it keeps Claim from
	// paying for a catalogue lookup on every poll.
	projectionJobsOnce sync.Once
	projectionJobs     bool
}

// hasProjectionJobs reports whether the projection job table exists yet.
func (r *cloudScanRunRepository) hasProjectionJobs() bool {
	r.projectionJobsOnce.Do(func() {
		ok, err := HasRelation(r.db, "iga_projection_job")
		// On error, assume ABSENT: the predicate is an extra guard, and the
		// workspace barrier is what actually prevents the overwrite. Losing it
		// degrades throughput protection; wrongly including it would break
		// scanning outright.
		r.projectionJobs = err == nil && ok
	})
	return r.projectionJobs
}

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

	// The projection predicate names iga_projection_job, which does not exist
	// until migration 033. Referencing it unconditionally makes this statement
	// fail at PLAN time on a database at 026 -- so a binary carrying Phase 2
	// could not claim a scan at all during the window between the two
	// releases, which is exactly the S0 state the staged rollout exists to
	// keep working. Include the predicate only once the table is there.
	projectionPredicate := ""
	if r.hasProjectionJobs() {
		// A connector whose previous run is still being projected is not
		// claimable (SPEC §4.5). The projection reads that run's inventory,
		// and a new scan would rewrite it underneath.
		//
		// TWO CONSEQUENCES, ACCEPTED DELIBERATELY:
		//   * a WEDGED PROJECTION BLOCKS SCANNING for that connector. That is
		//     why iga_projection_job has an attempts ceiling and terminal
		//     states, and why RecoverStalled exists. ALERT ON queued/running
		//     JOBS OLDER THAN ONE LEASE.
		//   * scan throughput is bounded by projection. Acceptable at one
		//     connector per customer and a projection measured in seconds.
		projectionPredicate = `AND NOT EXISTS (
			       SELECT 1 FROM iga_projection_job j
			        WHERE j.connector_id = cloud_scan_run.connector_id
			          AND j.status IN (?, ?))`
	}

	query := `
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
			 WHERE (status = ?
			    OR (status = ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)))
			   ` + projectionPredicate + `
			 ORDER BY requested_at
			 FOR UPDATE SKIP LOCKED
			 LIMIT 1
		)
		RETURNING *`

	args := []any{
		models.CloudScanRunRunning, owner, expires, now,
		now,
		models.CloudScanRunQueued,
		models.CloudScanRunRunning, now,
	}
	if projectionPredicate != "" {
		args = append(args, models.ProjectionQueued, models.ProjectionRunning)
	}
	err := r.db.Raw(query, args...).Scan(&out).Error
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

func (r *cloudScanRunRepository) PublishWithCoverage(
	runID uuid.UUID, owner string, version int64,
	coverage models.ScanCoverage,
	after func(tx *gorm.DB, run *models.CloudScanRun) error,
) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return fmt.Errorf("encode coverage: %w", err)
	}
	now := time.Now()

	return r.db.Transaction(func(tx *gorm.DB) error {
		// One fenced UPDATE doing both writes. RowsAffected == 0 means the
		// lease moved on, and the whole transaction rolls back -- so a
		// superseded worker writes neither coverage nor publication.
		res := tx.Model(&models.CloudScanRun{}).
			Where("id = ? AND lease_owner = ? AND lease_version = ?", runID, owner, version).
			Updates(map[string]any{
				"coverage":         raw,
				"status":           models.CloudScanRunPublished,
				"published_at":     now,
				"lease_owner":      "",
				"lease_expires_at": nil,
				"updated_at":       now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: run=%s owner=%s version=%d", ErrLeaseLost, runID, owner, version)
		}

		if after == nil {
			return nil
		}
		var run models.CloudScanRun
		if err := tx.First(&run, "id = ?", runID).Error; err != nil {
			return err
		}
		return after(tx, &run)
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
func (r *cloudScanRunRepository) FailTx(
	tx *gorm.DB, runID uuid.UUID, owner string, version int64, reason string,
) error {
	now := time.Now()
	res := tx.Model(&models.CloudScanRun{}).
		Where("id = ? AND lease_owner = ? AND lease_version = ?", runID, owner, version).
		Updates(map[string]any{
			"status":           models.CloudScanRunFailed,
			"last_error":       truncateError(reason),
			"lease_owner":      "",
			"lease_expires_at": nil,
			"updated_at":       now,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: run=%s owner=%s version=%d", ErrLeaseLost, runID, owner, version)
	}
	return nil
}

func (r *cloudScanRunRepository) Requeue(runID uuid.UUID, owner string, version int64) error {
	now := time.Now()
	// attempts is decremented back: Claim incremented it, and a run that never
	// got to start must not be charged an attempt against scanMaxAttempts.
	return r.fenced(runID, owner, version, map[string]any{
		"status":           models.CloudScanRunQueued,
		"lease_owner":      "",
		"lease_expires_at": nil,
		"attempts":         gorm.Expr("GREATEST(attempts - 1, 0)"),
		"updated_at":       now,
	})
}

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

func (r *cloudScanRunRepository) SetCoverage(runID uuid.UUID, coverage models.ScanCoverage) error {
	raw, err := json.Marshal(coverage)
	if err != nil {
		return err
	}
	res := r.db.Model(&models.CloudScanRun{}).
		Where("id = ? AND status = ?", runID, models.CloudScanRunPublished).
		Updates(map[string]any{
			"coverage":   raw,
			"updated_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: run=%s is not published", ErrCloudScanRunNotFound, runID)
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
