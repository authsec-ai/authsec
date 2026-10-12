package repositories

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// IGAGovEvaluationRepository is the data access of finding evaluation (048,
// SPEC-iga-phase3-policy.md §2.5, §8.2): the per-revision evaluation row, its
// frozen activity evidence and finding results, and the findings themselves.
//
// The schema owns every rule that matters here, and this repository only
// speaks it: the evaluation's state machine (trigger
// iga_gov_evaluation_transition: running -> complete | failed | superseded,
// failed -> running with attempts + 1, failed -> superseded), evidence and
// results writable only while their evaluation is running (trigger
// iga_gov_evaluation_rows_frozen), and a finding's last_evaluated_rev never
// moving backwards (trigger iga_gov_finding_monotonic). Each transition below
// is a guarded UPDATE whose WHERE names the state it leaves, so a replay or a
// race changes nothing and reports false instead of tripping the trigger.
//
// Every *Tx method runs in the caller's transaction: the evaluation step
// writes evidence, posture route facts, findings, results and the complete
// status in ONE transaction (§8.2), fenced on the projection job.
type IGAGovEvaluationRepository interface {
	// InsertRunningTx inserts iga_gov_evaluation(rev, running, attempts 1)
	// unless the row exists; it reports whether it inserted.
	InsertRunningTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error)
	// GetTx reads the evaluation row (nil when absent); lock takes it FOR
	// UPDATE.
	GetTx(tx *gorm.DB, ws uuid.UUID, rev int64, lock bool) (*models.IGAGovEvaluation, error)
	// RetryTx is the fenced failed -> running transition with attempts + 1.
	RetryTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error)
	// CompleteTx is running -> complete.
	CompleteTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error)
	// FailTx is running -> failed with the reason.
	FailTx(tx *gorm.DB, ws uuid.UUID, rev int64, reason string) (bool, error)
	// SupersedeTx is running | failed -> superseded.
	SupersedeTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error)
	// NewerCompleteTx reports whether an evaluation of a revision newer than
	// rev is complete.
	NewerCompleteTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error)

	// LatestComplete is the newest complete evaluation (nil when none).
	LatestComplete(db *gorm.DB, ws uuid.UUID) (*models.IGAGovEvaluation, error)
	// Latest is the newest evaluation row of any status (nil when none).
	Latest(db *gorm.DB, ws uuid.UUID) (*models.IGAGovEvaluation, error)

	// InsertEvidenceTx inserts activity evidence rows (new rows only).
	InsertEvidenceTx(tx *gorm.DB, rows []models.IGAGovActivityEvidence) error
	// LockFindingsTx reads every finding of the workspace FOR UPDATE, in
	// fingerprint order (§8.7 lock order, step 4).
	LockFindingsTx(tx *gorm.DB, ws uuid.UUID) ([]models.IGAGovFinding, error)
	// InsertFindingTx inserts a new finding and sets its id.
	InsertFindingTx(tx *gorm.DB, f *models.IGAGovFinding) error
	// UpdateFindingTx applies one planned update to a finding evaluated at
	// an older revision; ErrIGAGovNotFound when no such row (or the stored
	// revision is not older).
	UpdateFindingTx(tx *gorm.DB, ws, id uuid.UUID, u FindingEvalUpdate) error
	// InsertResultsTx inserts finding results.
	InsertResultsTx(tx *gorm.DB, rows []models.IGAGovFindingResult) error

	// RetainedRevs are the complete evaluations whose evidence and results
	// are kept: the newest `retention` complete revisions and every revision
	// a policy version's evidence_rev names (§2.5).
	RetainedRevs(db *gorm.DB, ws uuid.UUID, retention int) (map[int64]bool, error)
	// PruneTx deletes the evidence and results of complete evaluations
	// outside RetainedRevs and records each such revision in
	// iga_gov_evaluation_pruned (057) in the same transaction. The
	// evaluation rows stay, so a read at a pruned revision is 410
	// revision_not_retained, never "unknown".
	PruneTx(tx *gorm.DB, ws uuid.UUID, retention int) (int64, error)
	// Pruned reports whether rev's evidence and results were pruned
	// (057's record). It never infers pruning from the retention setting:
	// raising the setting after a prune does not bring the rows back.
	Pruned(db *gorm.DB, ws uuid.UUID, rev int64) (bool, error)
}

// FindingEvalUpdate is one evaluation's write to an existing finding.
type FindingEvalUpdate struct {
	Rev           int64
	Status        string
	StatusChanged bool
	// ClearException drops excepted_until and exception_reason (leaving
	// excepted, 048 iga_gov_finding_exception_chk).
	ClearException bool
	// Condition, when set, refreshes the finding's latest condition.
	Condition *FindingCondition
	At        time.Time
}

// FindingCondition is the latest condition copied onto iga_gov_finding.
type FindingCondition struct {
	Severity   string
	Confidence string
	Detail     []byte
}

// evalInsertBatch bounds one batch insert.
const evalInsertBatch = 500

type igaGovEvaluationRepository struct{}

func NewIGAGovEvaluationRepository() IGAGovEvaluationRepository { return igaGovEvaluationRepository{} }

func (igaGovEvaluationRepository) InsertRunningTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	res := tx.Exec(`INSERT INTO iga_gov_evaluation (workspace_id, rev, status, attempts)
	                VALUES (?, ?, 'running', 1) ON CONFLICT (workspace_id, rev) DO NOTHING`, ws, rev)
	return res.RowsAffected == 1, res.Error
}

func (igaGovEvaluationRepository) GetTx(tx *gorm.DB, ws uuid.UUID, rev int64, lock bool) (*models.IGAGovEvaluation, error) {
	q := tx
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var e models.IGAGovEvaluation
	err := q.Where("workspace_id = ? AND rev = ?", ws, rev).Take(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (igaGovEvaluationRepository) RetryTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	res := tx.Exec(`UPDATE iga_gov_evaluation SET status = 'running', attempts = attempts + 1,
	                       started_at = now(), finished_at = NULL, error = ''
	                 WHERE workspace_id = ? AND rev = ? AND status = 'failed'`, ws, rev)
	return res.RowsAffected == 1, res.Error
}

func (igaGovEvaluationRepository) CompleteTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	res := tx.Exec(`UPDATE iga_gov_evaluation SET status = 'complete', finished_at = now(), error = ''
	                 WHERE workspace_id = ? AND rev = ? AND status = 'running'`, ws, rev)
	return res.RowsAffected == 1, res.Error
}

func (igaGovEvaluationRepository) FailTx(tx *gorm.DB, ws uuid.UUID, rev int64, reason string) (bool, error) {
	if reason == "" {
		reason = "evaluation failed"
	}
	res := tx.Exec(`UPDATE iga_gov_evaluation SET status = 'failed', finished_at = now(), error = ?
	                 WHERE workspace_id = ? AND rev = ? AND status = 'running'`, reason, ws, rev)
	return res.RowsAffected == 1, res.Error
}

func (igaGovEvaluationRepository) SupersedeTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	res := tx.Exec(`UPDATE iga_gov_evaluation SET status = 'superseded', finished_at = now()
	                 WHERE workspace_id = ? AND rev = ? AND status IN ('running','failed')`, ws, rev)
	return res.RowsAffected == 1, res.Error
}

func (igaGovEvaluationRepository) NewerCompleteTx(tx *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	var n int64
	err := tx.Raw(`SELECT count(*) FROM iga_gov_evaluation WHERE workspace_id = ? AND rev > ? AND status = 'complete'`,
		ws, rev).Scan(&n).Error
	return n > 0, err
}

func (igaGovEvaluationRepository) LatestComplete(db *gorm.DB, ws uuid.UUID) (*models.IGAGovEvaluation, error) {
	return latestEval(db.Where("workspace_id = ? AND status = 'complete'", ws))
}

func (igaGovEvaluationRepository) Latest(db *gorm.DB, ws uuid.UUID) (*models.IGAGovEvaluation, error) {
	return latestEval(db.Where("workspace_id = ?", ws))
}

func latestEval(q *gorm.DB) (*models.IGAGovEvaluation, error) {
	var e models.IGAGovEvaluation
	err := q.Order("rev DESC").Take(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (igaGovEvaluationRepository) InsertEvidenceTx(tx *gorm.DB, rows []models.IGAGovActivityEvidence) error {
	if len(rows) == 0 {
		return nil
	}
	return tx.CreateInBatches(rows, evalInsertBatch).Error
}

func (igaGovEvaluationRepository) LockFindingsTx(tx *gorm.DB, ws uuid.UUID) ([]models.IGAGovFinding, error) {
	var out []models.IGAGovFinding
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("workspace_id = ?", ws).Order("fingerprint").Find(&out).Error
	return out, err
}

func (igaGovEvaluationRepository) InsertFindingTx(tx *gorm.DB, f *models.IGAGovFinding) error {
	return tx.Create(f).Error
}

func (igaGovEvaluationRepository) UpdateFindingTx(tx *gorm.DB, ws, id uuid.UUID, u FindingEvalUpdate) error {
	set := map[string]any{
		"status":             u.Status,
		"last_evaluated_rev": u.Rev,
		"last_evaluated_at":  u.At,
	}
	if u.StatusChanged {
		set["status_changed_at"] = u.At
	}
	if u.ClearException {
		set["excepted_until"] = nil
		set["exception_reason"] = ""
	}
	if c := u.Condition; c != nil {
		set["severity"] = c.Severity
		set["confidence"] = c.Confidence
		set["detail"] = gorm.Expr("?::jsonb", string(c.Detail))
	}
	return affectedOne(tx.Model(&models.IGAGovFinding{}).
		Where("workspace_id = ? AND id = ? AND last_evaluated_rev < ?", ws, id, u.Rev).Updates(set))
}

func (igaGovEvaluationRepository) InsertResultsTx(tx *gorm.DB, rows []models.IGAGovFindingResult) error {
	if len(rows) == 0 {
		return nil
	}
	return tx.CreateInBatches(rows, evalInsertBatch).Error
}

func (igaGovEvaluationRepository) RetainedRevs(db *gorm.DB, ws uuid.UUID, retention int) (map[int64]bool, error) {
	var revs []int64
	if err := db.Raw(`(SELECT rev FROM iga_gov_evaluation WHERE workspace_id = ? AND status = 'complete'
	                    ORDER BY rev DESC LIMIT ?)
	                  UNION
	                  SELECT DISTINCT evidence_rev FROM iga_gov_policy_version WHERE workspace_id = ?`,
		ws, retention, ws).Scan(&revs).Error; err != nil {
		return nil, err
	}
	out := make(map[int64]bool, len(revs))
	for _, r := range revs {
		out[r] = true
	}
	return out, nil
}

func (igaGovEvaluationRepository) PruneTx(tx *gorm.DB, ws uuid.UUID, retention int) (int64, error) {
	// The prunable set is computed once, in the statement, by the same rule
	// RetainedRevs reads with: complete, not among the newest `retention`,
	// not pinned by a version.
	const prunable = `SELECT e.rev FROM iga_gov_evaluation e
	                   WHERE e.workspace_id = ? AND e.status = 'complete'
	                     AND e.rev NOT IN (SELECT rev FROM iga_gov_evaluation WHERE workspace_id = ? AND status = 'complete'
	                                        ORDER BY rev DESC LIMIT ?)
	                     AND e.rev NOT IN (SELECT evidence_rev FROM iga_gov_policy_version WHERE workspace_id = ?)`
	// Record the pruning first, by the same rule, so a later read knows
	// these revisions are gone whatever the retention setting becomes.
	if err := tx.Exec(`INSERT INTO iga_gov_evaluation_pruned (workspace_id, rev)
	                   SELECT ?, rev FROM (`+prunable+`) p
	                   ON CONFLICT (workspace_id, rev) DO NOTHING`, ws, ws, ws, retention, ws).Error; err != nil {
		return 0, err
	}
	var total int64
	for _, table := range []string{"iga_gov_finding_result", "iga_gov_activity_evidence"} {
		res := tx.Exec(`DELETE FROM `+table+` WHERE workspace_id = ? AND rev IN (`+prunable+`)`,
			ws, ws, ws, retention, ws)
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
	}
	return total, nil
}

func (igaGovEvaluationRepository) Pruned(db *gorm.DB, ws uuid.UUID, rev int64) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM iga_gov_evaluation_pruned WHERE workspace_id = ? AND rev = ?`, ws, rev).Scan(&n).Error
	return n > 0, err
}
