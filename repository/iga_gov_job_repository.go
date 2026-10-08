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

// ErrPolicyJobLeaseLost is SPEC-iga-phase3-policy.md §8.1's fence error: the
// worker no longer holds the iga_gov_job lease it claimed (another worker
// reclaimed it, or it was completed, failed or abandoned under it) and must
// write nothing further and send nothing further.
var ErrPolicyJobLeaseLost = errors.New("policy job lease no longer held")

// ErrPolicyJobLeaseShort means the lease is still held but has less time left
// than the caller required: an external call must not start (§8.1, "the lease
// must have at least 60 s left or the worker stops before sending").
var ErrPolicyJobLeaseShort = errors.New("policy job lease has too little time left")

// Job kinds (052 iga_gov_job.kind CHECK). resolve_unknown (§8.1 step 2) is NOT
// in 052's CHECK, so it cannot be enqueued until the DDL is widened (reported
// by T3.08); the constant exists so the gap is named in one place.
const (
	GovJobEvaluateOwnerRules = "evaluate_owner_rules"
	GovJobCompilePlans       = "compile_plans"
	GovJobNotify             = "notify"
	GovJobRefreshActivity    = "refresh_activity"
	GovJobObserveTick        = "observe_tick"
	GovJobDeploy             = "deploy"
	GovJobVerify             = "verify"
	GovJobDriftCheck         = "drift_check"
	GovJobVerifyBinding      = "verify_binding"
	GovJobIaCSync            = "iac_sync"
	GovJobPruneEvidence      = "prune_evidence"
	GovJobMetricsRollup      = "metrics_rollup"
	// GovJobResolveUnknown is not accepted by 052's CHECK (see above).
	GovJobResolveUnknown = "resolve_unknown"
)

// GovJobKinds are the kinds 052 accepts.
var GovJobKinds = []string{
	GovJobEvaluateOwnerRules, GovJobCompilePlans, GovJobNotify, GovJobRefreshActivity,
	GovJobObserveTick, GovJobDeploy, GovJobVerify, GovJobDriftCheck, GovJobVerifyBinding,
	GovJobIaCSync, GovJobPruneEvidence, GovJobMetricsRollup,
}

// MaxConcurrentDeploysPerWorkspace is §8.1's "at most 10 deployments per
// workspace run concurrently", applied in Claim to running deploy jobs.
const MaxConcurrentDeploysPerWorkspace = 10

// PolicyJobFence is what one claim holds: the job and the lease version it was
// claimed at. Every write the job makes is fenced on (id, owner, version).
type PolicyJobFence struct {
	JobID   uuid.UUID
	Owner   string
	Version int64
}

// IGAGovJobRepository owns iga_gov_job's lifecycle (§8.1).
//
// It copies IGAProjectionJobRepository's shape on purpose -- one fenced worker
// shape in the codebase: Claim is ONE `UPDATE ... WHERE id = (SELECT ... FOR
// UPDATE SKIP LOCKED LIMIT 1) RETURNING *` that bumps lease_version and
// attempts, and every later state change is a single conditional UPDATE on
// (id, lease_owner, lease_version) that returns ErrPolicyJobLeaseLost on zero
// rows. Those fenced UPDATEs consult NO CLOCK: a worker that slept past its
// expiry is refused because a reclaim moved the version on, not because a
// clock said so. Every lease and run_after VALUE is written from the worker's
// clock (time.Now, or the now a caller passes), and Claim, LeaseRemaining and
// the dispatch margin compare against that same clock -- never the database's
// now() against a value the worker wrote (DECISION: one clock for leases;
// completed_at, a record only, is the database's).
type IGAGovJobRepository interface {
	// EnqueueTx records a job in the caller's transaction, or returns the open
	// (queued or running) job with the same (workspace, kind, dedupe_key):
	// uq_iga_gov_job_open makes a second open job impossible, so a retried
	// enqueue is a no-op. created reports whether this call inserted it.
	EnqueueTx(tx *gorm.DB, job *models.IGAGovJob) (created bool, err error)
	// EnqueuePeriodicTx enqueues the job unless one with the same
	// (workspace, kind, dedupe_key) is open, or completed less than every ago.
	// It is how the scheduler runs "every N minutes per subject" on any number
	// of replicas without a leader: the open index and the completed_at
	// window, not a timer, decide.
	EnqueuePeriodicTx(tx *gorm.DB, job *models.IGAGovJob, every time.Duration) (created bool, err error)
	// EnqueueOnceTx enqueues the job unless ANY job with the same
	// (workspace, kind, dedupe_key) exists, whatever its status: for a
	// one-shot key such as refresh_activity's connector:<id>:after:<ts>,
	// which must not run again after it completed or failed.
	EnqueueOnceTx(tx *gorm.DB, job *models.IGAGovJob) (created bool, err error)

	// Claim takes one claimable job of the given kinds (all of 052's when
	// none are given): a queued job whose run_after has passed, or a running
	// one whose lease lapsed (the crashed-worker case), below its
	// max_attempts. now is the claim time; the lease runs to now+lease.
	Claim(owner string, lease time.Duration, now time.Time, kinds []string) (*models.IGAGovJob, error)
	Renew(f PolicyJobFence, lease time.Duration) error
	// LeaseRemaining is how long the lease has left at now, or
	// ErrPolicyJobLeaseLost when it is no longer held.
	LeaseRemaining(f PolicyJobFence, now time.Time) (time.Duration, error)
	// AssertOwnedTx locks the job row FOR UPDATE inside the caller's
	// transaction and proves the fence still holds. The lock is held to
	// commit, so a reclaiming worker BLOCKS instead of writing concurrently.
	AssertOwnedTx(tx *gorm.DB, f PolicyJobFence) error

	Complete(f PolicyJobFence) error
	CompleteTx(tx *gorm.DB, f PolicyJobFence) error
	// Fail records a failed try. Below max_attempts the job is queued again
	// with run_after = now + retryAfter (the attempt is counted); at the
	// ceiling it is terminal `failed` and stays visible with its last error.
	Fail(f PolicyJobFence, reason string, retryAfter time.Duration) error
	// Abandon records that the job no longer applies (superseded, subject
	// gone). Terminal, and recorded rather than silent.
	Abandon(f PolicyJobFence, reason string) error
	// Requeue hands the job back WITHOUT counting the attempt: the worker
	// could not proceed for a reason that is not the job's (shutdown,
	// another job holds what it needs).
	Requeue(f PolicyJobFence, after time.Duration) error

	// FailExhausted makes terminal every running job whose lease lapsed with
	// no attempts left: Claim no longer admits it, and without this it would
	// read `running` forever.
	FailExhausted(now time.Time) (int64, error)
	// FailExhaustedJobs is FailExhausted returning the jobs it failed, so
	// the worker can run each kind's exhaustion hook (review P1-5).
	FailExhaustedJobs(now time.Time) ([]models.IGAGovJob, error)
	// PruneFinished deletes complete and abandoned jobs that finished before
	// the cutoff (periodic jobs leave one row per run). Failed jobs are kept.
	PruneFinished(before time.Time) (int64, error)

	Get(id uuid.UUID) (*models.IGAGovJob, error)
}

type igaGovJobRepository struct{ db *gorm.DB }

func NewIGAGovJobRepository(db *gorm.DB) IGAGovJobRepository {
	return &igaGovJobRepository{db: db}
}

func (r *igaGovJobRepository) EnqueueTx(tx *gorm.DB, job *models.IGAGovJob) (bool, error) {
	return r.enqueue(tx, job, 0, false)
}

func (r *igaGovJobRepository) EnqueuePeriodicTx(tx *gorm.DB, job *models.IGAGovJob, every time.Duration) (bool, error) {
	if every <= 0 {
		return false, errors.New("a periodic job needs a positive interval")
	}
	return r.enqueue(tx, job, every, false)
}

func (r *igaGovJobRepository) EnqueueOnceTx(tx *gorm.DB, job *models.IGAGovJob) (bool, error) {
	return r.enqueue(tx, job, 0, true)
}

func (r *igaGovJobRepository) enqueue(tx *gorm.DB, job *models.IGAGovJob, every time.Duration, once bool) (bool, error) {
	if job.WorkspaceID == uuid.Nil || job.Kind == "" || job.DedupeKey == "" {
		return false, errors.New("a policy job needs a workspace, a kind and a dedupe key")
	}
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	if job.RunAfter.IsZero() {
		job.RunAfter = time.Now()
	}
	if job.MaxAttempts == 0 {
		job.MaxAttempts = 5
	}
	// ONE statement: the periodic window is checked in the INSERT's own
	// SELECT, and the open-job conflict is the partial unique index's. Two
	// replicas enqueueing the same subject at once insert one row.
	var inserted []uuid.UUID
	err := tx.Raw(`
		INSERT INTO iga_gov_job (id, workspace_id, kind, subject_id, rev, dedupe_key, status, run_after, max_attempts)
		SELECT ?, ?, ?, ?, ?, ?, 'queued', ?, ?
		 WHERE NOT EXISTS (
		       SELECT 1 FROM iga_gov_job p
		        WHERE p.workspace_id = ? AND p.kind = ? AND p.dedupe_key = ?
		          AND (?::boolean
		               OR (?::float8 > 0 AND p.status = 'complete' AND p.completed_at > now() - make_interval(secs => ?::float8))))
		ON CONFLICT (workspace_id, kind, dedupe_key) WHERE status IN ('queued','running') DO NOTHING
		RETURNING id`,
		job.ID, job.WorkspaceID, job.Kind, job.SubjectID, job.Rev, job.DedupeKey, job.RunAfter, job.MaxAttempts,
		job.WorkspaceID, job.Kind, job.DedupeKey, once, every.Seconds(), every.Seconds(),
	).Scan(&inserted).Error
	if err != nil {
		return false, err
	}
	if len(inserted) == 1 {
		return true, nil
	}
	// Not inserted: READ BACK the open job, so the caller never holds an id
	// that names no row (the projection job's EnqueueTx lesson). None open
	// means the periodic window or the once rule suppressed it; job.ID is
	// then cleared.
	var open models.IGAGovJob
	res := tx.Where("workspace_id = ? AND kind = ? AND dedupe_key = ? AND status IN ?",
		job.WorkspaceID, job.Kind, job.DedupeKey, []string{models.GovJobQueued, models.GovJobRunning}).
		Limit(1).Find(&open)
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		job.ID = uuid.Nil
		return false, nil
	}
	*job = open
	return false, nil
}

func (r *igaGovJobRepository) Claim(owner string, lease time.Duration, now time.Time, kinds []string) (*models.IGAGovJob, error) {
	if owner == "" {
		return nil, errors.New("a claim needs an owner")
	}
	if lease <= 0 {
		return nil, errors.New("a claim needs a positive lease")
	}
	if len(kinds) == 0 {
		kinds = GovJobKinds
	}
	var out []models.IGAGovJob
	err := r.db.Raw(`
		UPDATE iga_gov_job SET
			status           = 'running',
			lease_owner      = ?,
			lease_expires_at = ?,
			lease_version    = lease_version + 1,
			attempts         = attempts + 1
		WHERE id = (
			SELECT j.id FROM iga_gov_job j
			 WHERE j.kind IN ?
			   AND j.attempts < j.max_attempts
			   AND ((j.status = 'queued' AND j.run_after <= ?)
			     -- A running job whose worker died or stalled past its lease.
			     OR (j.status = 'running' AND (j.lease_expires_at IS NULL OR j.lease_expires_at <= ?)))
			   -- §8.1: at most 10 deployments per workspace run at once. A soft
			   -- cap: two claims racing at 9 can both pass (SKIP LOCKED does
			   -- not serialise them); the one-deployment-per-role index is the
			   -- hard guarantee, this only bounds load.
			   AND (j.kind <> 'deploy' OR (
			        SELECT count(*) FROM iga_gov_job d
			         WHERE d.workspace_id = j.workspace_id AND d.kind = 'deploy' AND d.id <> j.id
			           AND d.status = 'running' AND d.lease_expires_at > ?) < ?)
			 ORDER BY j.run_after, j.created_at
			 FOR UPDATE SKIP LOCKED
			 LIMIT 1
		)
		RETURNING *`,
		owner, now.Add(lease), kinds, now, now, now, MaxConcurrentDeploysPerWorkspace,
	).Scan(&out).Error
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return &out[0], nil
}

func (r *igaGovJobRepository) Renew(f PolicyJobFence, lease time.Duration) error {
	return fencedJob(r.db, f, map[string]any{"lease_expires_at": time.Now().Add(lease)})
}

func (r *igaGovJobRepository) LeaseRemaining(f PolicyJobFence, now time.Time) (time.Duration, error) {
	var exp []time.Time
	err := r.db.Raw(`SELECT lease_expires_at FROM iga_gov_job
		WHERE id = ? AND lease_owner = ? AND lease_version = ? AND status = 'running' AND lease_expires_at IS NOT NULL`,
		f.JobID, f.Owner, f.Version).Scan(&exp).Error
	if err != nil {
		return 0, err
	}
	if len(exp) == 0 {
		return 0, leaseLost(f)
	}
	return exp[0].Sub(now), nil
}

func (r *igaGovJobRepository) AssertOwnedTx(tx *gorm.DB, f PolicyJobFence) error {
	var job []models.IGAGovJob
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", f.JobID).Limit(1).Find(&job).Error; err != nil {
		return err
	}
	if len(job) == 0 || job[0].LeaseOwner != f.Owner || job[0].LeaseVersion != f.Version || job[0].Status != models.GovJobRunning {
		return leaseLost(f)
	}
	return nil
}

func (r *igaGovJobRepository) Complete(f PolicyJobFence) error { return r.CompleteTx(r.db, f) }

func (r *igaGovJobRepository) CompleteTx(tx *gorm.DB, f PolicyJobFence) error {
	return fencedJob(tx, f, map[string]any{
		"status":           models.GovJobComplete,
		"completed_at":     gorm.Expr("now()"),
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

func (r *igaGovJobRepository) Fail(f PolicyJobFence, reason string, retryAfter time.Duration) error {
	if retryAfter < 0 {
		retryAfter = 0
	}
	// One statement decides retry or terminal from the row's own counters, so
	// no read-then-write window exists.
	res := r.db.Exec(`
		UPDATE iga_gov_job SET
			status           = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
			run_after        = CASE WHEN attempts < max_attempts THEN ?::timestamptz ELSE run_after END,
			completed_at     = CASE WHEN attempts < max_attempts THEN NULL ELSE now() END,
			last_error       = ?,
			lease_owner      = '',
			lease_expires_at = NULL
		WHERE id = ? AND lease_owner = ? AND lease_version = ? AND status = 'running'`,
		time.Now().Add(retryAfter), truncateError(reason), f.JobID, f.Owner, f.Version)
	return affectedFence(res, f)
}

func (r *igaGovJobRepository) Abandon(f PolicyJobFence, reason string) error {
	return fencedJob(r.db, f, map[string]any{
		"status":           models.GovJobAbandoned,
		"last_error":       truncateError(reason),
		"completed_at":     gorm.Expr("now()"),
		"lease_owner":      "",
		"lease_expires_at": nil,
	})
}

func (r *igaGovJobRepository) Requeue(f PolicyJobFence, after time.Duration) error {
	if after < 0 {
		after = 0
	}
	return fencedJob(r.db, f, map[string]any{
		"status":           models.GovJobQueued,
		"lease_owner":      "",
		"lease_expires_at": nil,
		// The worker never got to try: the attempt is given back.
		"attempts":  gorm.Expr("GREATEST(attempts - 1, 0)"),
		"run_after": time.Now().Add(after),
	})
}

func (r *igaGovJobRepository) FailExhausted(now time.Time) (int64, error) {
	jobs, err := r.FailExhaustedJobs(now)
	return int64(len(jobs)), err
}

func (r *igaGovJobRepository) FailExhaustedJobs(now time.Time) ([]models.IGAGovJob, error) {
	var out []models.IGAGovJob
	err := r.db.Raw(`
		UPDATE iga_gov_job SET status = 'failed', completed_at = now(), lease_owner = '', lease_expires_at = NULL,
		       last_error = CASE WHEN last_error = '' THEN 'lease expired with no attempts left'
		                         ELSE last_error || ' (lease expired with no attempts left)' END
		 WHERE status = 'running' AND attempts >= max_attempts
		   AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
		RETURNING *`, now).Scan(&out).Error
	return out, err
}

func (r *igaGovJobRepository) PruneFinished(before time.Time) (int64, error) {
	res := r.db.Exec(`DELETE FROM iga_gov_job WHERE status IN ('complete','abandoned') AND completed_at < ?`, before)
	return res.RowsAffected, res.Error
}

func (r *igaGovJobRepository) Get(id uuid.UUID) (*models.IGAGovJob, error) {
	var job models.IGAGovJob
	if err := r.db.First(&job, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// fencedJob is the one fenced write: (id, lease_owner, lease_version) and
// still running, or ErrPolicyJobLeaseLost.
func fencedJob(db *gorm.DB, f PolicyJobFence, updates map[string]any) error {
	res := db.Model(&models.IGAGovJob{}).
		Where("id = ? AND lease_owner = ? AND lease_version = ? AND status = ?", f.JobID, f.Owner, f.Version, models.GovJobRunning).
		Updates(updates)
	return affectedFence(res, f)
}

func affectedFence(res *gorm.DB, f PolicyJobFence) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return leaseLost(f)
	}
	return nil
}

func leaseLost(f PolicyJobFence) error {
	return fmt.Errorf("%w: job=%s owner=%s version=%d", ErrPolicyJobLeaseLost, f.JobID, f.Owner, f.Version)
}
