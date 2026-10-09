package igaread

// Classification (§2.14.3, §5.5): the shapes and reads every classification
// response shares -- the POST outcome and its 409, the decision history, the
// latest decision on the workload detail, meta.capabilities.can_classify --
// and the classification clock that classification lists bind their cursors
// to.
//
// This package never writes. The decision transaction itself is
// services.ClassificationService; it calls DisplayNames, LatestDecisionRow and
// the renderers below from inside its own read-write transaction, which is why
// those take a *gorm.DB rather than a *Query.
//
// Display names live here for a reason beyond sharing: they come from the
// users table, and no iga_*.go file may name a legacy table
// (scripts/ci-iga-isolation-check.sh). The read side's reads outside iga_* are
// sanctioned in this package and nowhere else (D-25, D-32).

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// DecidedBy names who made a decision: the stable user id, always, and beside
// it a display name resolved at read time (§5.5 "Display names"). The id is
// what the record means; the name is only how it reads today.
type DecidedBy struct {
	UserID  string `json:"user_id"`
	Display string `json:"display"`
}

// notProvided is the users.name column default (001_bootstrap): a row nobody
// named, not a person called "Not Provided".
const notProvided = "Not Provided"

// DisplayNames resolves user ids to the names decisions are shown with (D-32):
// users.name unless it is empty or the column default, else the email, else
// the user id itself. Every id asked for is in the result -- a user id with no
// user record resolves to the id, never to nothing -- so a decision always
// names its decider.
//
// Soft-deleted users are resolved like any other: the decision was theirs, and
// the name is how the record read when they made it.
func DisplayNames(db *gorm.DB, ids ...uuid.UUID) (map[uuid.UUID]string, error) {
	out := make(map[uuid.UUID]string, len(ids))
	want := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, seen := out[id]; !seen {
			out[id] = id.String()
			want = append(want, id)
		}
	}
	if len(want) == 0 {
		return out, nil
	}
	var rows []struct {
		ID    uuid.UUID
		Name  *string
		Email string
	}
	if err := db.Raw(`SELECT id, name, email FROM users WHERE id IN ?`, want).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = displayOf(r.ID, r.Name, r.Email)
	}
	return out, nil
}

// displayOf is D-32's precedence for one user record.
func displayOf(id uuid.UUID, name *string, email string) string {
	if name != nil {
		if n := strings.TrimSpace(*name); n != "" && n != notProvided {
			return n
		}
	}
	if e := strings.TrimSpace(email); e != "" {
		return e
	}
	return id.String()
}

func decidedBy(names map[uuid.UUID]string, id uuid.UUID) DecidedBy {
	d, ok := names[id]
	if !ok || d == "" {
		d = id.String()
	}
	return DecidedBy{UserID: id.String(), Display: d}
}

// optText renders an optional free-text field: the column is NOT NULL with
// the empty string as its default, and the empty string means none was given,
// so it is JSON null rather than a string that claims an answer was recorded.
func optText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

/* ------------------------------- POST outcome ------------------------------ */

// DecisionView is data.decision in the POST 200 (§5.5).
type DecisionView struct {
	ID          uuid.UUID `json:"id"`
	OperationID uuid.UUID `json:"operation_id"`
	DecidedBy   DecidedBy `json:"decided_by"`
	DecidedAt   any       `json:"decided_at"`
	Reason      string    `json:"reason"`
	Purpose     *string   `json:"purpose"`
}

// ClassifyResult is data in the POST 200 (§5.5). For a replay it is the
// STORED outcome -- the classification and version that decision produced --
// even when the workload has moved on since (§2.14.3 "Retries").
type ClassifyResult struct {
	Classification        string       `json:"classification"`
	ClassificationVersion int64        `json:"classification_version"`
	Decision              DecisionView `json:"decision"`
	Replayed              bool         `json:"replayed"`
}

// RenderClassifyResult renders one decision row as the POST outcome, with its
// decider's display name resolved now.
func RenderClassifyResult(db *gorm.DB, row models.IGAWorkloadClassification, replayed bool) (ClassifyResult, error) {
	names, err := DisplayNames(db, row.DecidedByUserID)
	if err != nil {
		return ClassifyResult{}, err
	}
	return ClassifyResult{
		Classification:        row.Decision,
		ClassificationVersion: row.ResultVersion,
		Decision: DecisionView{
			ID: row.ID, OperationID: row.OperationID,
			DecidedBy: decidedBy(names, row.DecidedByUserID),
			DecidedAt: T(row.DecidedAt),
			Reason:    row.Reason, Purpose: optText(row.Purpose),
		},
		Replayed: replayed,
	}, nil
}

/* -------------------------------- the 409 --------------------------------- */

// CurrentDecision is error.current in the 409 classification_conflict (§5.5):
// the workload's classification and version as they stand, and who made the
// decision that put them there, so the second person sees the first person's
// decision instead of overwriting it (§2.14.3 "Concurrent edits").
//
// decided_by, decided_at and reason are null when no decision exists -- a
// workload still at version 0 that a client sent a wrong expected_version for.
// Nothing is claimed that no record says.
type CurrentDecision struct {
	Classification        string     `json:"classification"`
	ClassificationVersion int64      `json:"classification_version"`
	DecidedBy             *DecidedBy `json:"decided_by"`
	DecidedAt             any        `json:"decided_at"`
	Reason                *string    `json:"reason"`
}

// LatestDecisionRow is the workload's latest decision, or nil when it has
// none.
//
// Latest by result_version, never decided_at: result_version is assigned under
// the workload's row lock, so it is strictly increasing per workload, while
// decided_at is DEFAULT now() -- the transaction's START -- and two decisions
// serialized on the lock can carry start times in either order.
func LatestDecisionRow(db *gorm.DB, ws, workloadID uuid.UUID) (*models.IGAWorkloadClassification, error) {
	var rows []models.IGAWorkloadClassification
	if err := db.Raw(`SELECT * FROM iga_workload_classification
		WHERE workspace_id = ? AND workload_id = ?
		ORDER BY result_version DESC, id DESC LIMIT 1`, ws, workloadID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// ClassificationConflict builds the 409 classification_conflict for a
// workload whose version is not the one the request was made against.
// classification and version are the workload's own, as the caller holds them
// (locked); the decider comes from the latest decision row.
func ClassificationConflict(db *gorm.DB, ws, workloadID uuid.UUID, classification string, version int64) (*Error, error) {
	cur := CurrentDecision{Classification: classification, ClassificationVersion: version}
	latest, err := LatestDecisionRow(db, ws, workloadID)
	if err != nil {
		return nil, err
	}
	if latest != nil {
		names, err := DisplayNames(db, latest.DecidedByUserID)
		if err != nil {
			return nil, err
		}
		by := decidedBy(names, latest.DecidedByUserID)
		reason := latest.Reason
		cur.DecidedBy, cur.DecidedAt, cur.Reason = &by, T(latest.DecidedAt), &reason
	}
	return Conflict("classification_conflict",
		"The classification changed since it was loaded.").With("current", cur), nil
}

/* ------------------------ the workload detail's decision ------------------- */

// LatestDecision is the latest classification decision on the workload detail
// (§5.3 `GET /workloads/:id`: {decision, purpose, reason, decided_by,
// decided_at}), plus its id and operation_id: the id is what an Undo sends as
// undoes_decision_id (§2.14.6 "Undo").
type LatestDecision struct {
	ID          uuid.UUID `json:"id"`
	OperationID uuid.UUID `json:"operation_id"`
	Decision    string    `json:"decision"`
	Purpose     *string   `json:"purpose"`
	Reason      string    `json:"reason"`
	DecidedBy   DecidedBy `json:"decided_by"`
	DecidedAt   any       `json:"decided_at"`
}

// LatestClassification is the workload's latest decision in the request's
// snapshot, or nil (JSON null) when nobody has decided anything about it --
// which includes every provider-native agent, since those are not
// human-editable.
//
// The caller has already found the workload in this workspace; this does not
// re-check it. Classification is not part of a revision (§5.5), so this is the
// decision as of the snapshot, like the row's own classification column.
func LatestClassification(q *Query, workloadID uuid.UUID) (*LatestDecision, error) {
	row, err := LatestDecisionRow(q.DB(), q.WS, workloadID)
	if err != nil || row == nil {
		return nil, err
	}
	names, err := DisplayNames(q.DB(), row.DecidedByUserID)
	if err != nil {
		return nil, err
	}
	return &LatestDecision{
		ID: row.ID, OperationID: row.OperationID, Decision: row.Decision,
		Purpose: optText(row.Purpose), Reason: row.Reason,
		DecidedBy: decidedBy(names, row.DecidedByUserID), DecidedAt: T(row.DecidedAt),
	}, nil
}

/* --------------------------------- history -------------------------------- */

// HistoryItem is one decision in GET /workloads/:id/classification: the whole
// audit record (§2.14.3 "Audit") -- what was decided, over what, by whom, why,
// and the version it was made against and produced.
type HistoryItem struct {
	ID               uuid.UUID  `json:"id"`
	OperationID      uuid.UUID  `json:"operation_id"`
	Decision         string     `json:"decision"`
	Previous         string     `json:"previous"`
	Purpose          *string    `json:"purpose"`
	Reason           string     `json:"reason"`
	DecidedBy        DecidedBy  `json:"decided_by"`
	DecidedAt        any        `json:"decided_at"`
	AgainstVersion   int64      `json:"against_version"`
	ResultVersion    int64      `json:"result_version"`
	UndoesDecisionID *uuid.UUID `json:"undoes_decision_id"`
}

// HistoryKey is a history page position: the last item's result_version and
// id. History is keyset-paged on (result_version, id) descending.
type HistoryKey struct {
	ResultVersion int64
	ID            uuid.UUID
}

// HistoryRoute is the cursor route of one workload's history. It carries the
// workload (D-62), so a cursor from another workload's history is
// cursor_invalid, not a position in this one. The history has no filters.
func HistoryRoute(workloadID uuid.UUID) string {
	return "workloads/" + workloadID.String() + "/classification"
}

// HistoryCursorContext is what a history cursor must match.
func HistoryCursorContext(ws, workloadID uuid.UUID) CursorContext {
	return CursorContext{WS: ws, Route: HistoryRoute(workloadID), Filter: "", Sort: "-result_version"}
}

// HistoryCursor issues the cursor after the page ending at k, read at
// revision rev.
//
// The history runs under §5.1 like every route (D-33): the cursor carries the
// revision it was issued at, and the next page passes it as Pin.CursorRev, so
// a publication between pages is 409 revision_stale -- the one stale status --
// even though no decision is part of a revision. It carries no
// classification_seq: the history neither filters nor sorts on
// classification, and a new decision's result_version is higher than every
// existing one, so it lands above page one and never shifts a later page.
func (r *Reader) HistoryCursor(ws, workloadID uuid.UUID, rev int64, k HistoryKey) string {
	cc := HistoryCursorContext(ws, workloadID)
	key, _ := json.Marshal(k.ResultVersion)
	return r.SignCursor(Cursor{WS: ws, Rev: rev, Route: cc.Route, Filter: cc.Filter, Sort: cc.Sort, Key: key, ID: k.ID})
}

// OpenHistoryCursor verifies a history cursor for this workload and returns
// its position and the revision it was issued at (for Pin.CursorRev).
func (r *Reader) OpenHistoryCursor(token string, ws, workloadID uuid.UUID) (*HistoryKey, int64, *Error) {
	c, e := r.OpenCursor(token, HistoryCursorContext(ws, workloadID))
	if e != nil {
		return nil, 0, e
	}
	var v int64
	if err := json.Unmarshal(c.Key, &v); err != nil {
		return nil, 0, CursorInvalid("Malformed cursor.")
	}
	return &HistoryKey{ResultVersion: v, ID: c.ID}, c.Rev, nil
}

// ClassificationWorkloadReadable reports whether workloadID is a workload the
// classification routes may serve in this snapshot: this workspace's, an AWS
// row the projector owns -- with at least one support row (D-6) -- in any
// lifecycle (§5.2 "Retired objects": a detail route returns retired objects).
// Anything else is 404 with no hint. It is the read-side twin of the
// decision transaction's locking SELECT, which applies the same condition.
func ClassificationWorkloadReadable(q *Query, workloadID uuid.UUID) (bool, error) {
	var found []uuid.UUID
	if err := q.DB().Raw(`SELECT w.id FROM iga_workload w
		WHERE w.workspace_id = ? AND w.id = ? AND w.provider = 'aws'
		  AND EXISTS (SELECT 1 FROM iga_object_support s
		               WHERE s.workspace_id = w.workspace_id AND s.workload_id = w.id)`,
		q.WS, workloadID).Scan(&found).Error; err != nil {
		return false, err
	}
	return len(found) == 1, nil
}

// ClassificationHistory reads one page of a workload's decisions, newest
// first by result_version (D-33), after the position `after` (nil: the first
// page). next is the position to continue from, nil on the last page.
func ClassificationHistory(q *Query, workloadID uuid.UUID, after *HistoryKey, limit int) (items []HistoryItem, next *HistoryKey, err error) {
	db := q.DB().Table("iga_workload_classification").
		Where("workspace_id = ? AND workload_id = ?", q.WS, workloadID)
	if after != nil {
		db = db.Where("(result_version, id) < (?, ?)", after.ResultVersion, after.ID)
	}
	var rows []models.IGAWorkloadClassification
	if err := db.Order("result_version DESC, id DESC").Limit(limit + 1).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = &HistoryKey{ResultVersion: last.ResultVersion, ID: last.ID}
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.DecidedByUserID)
	}
	names, err := DisplayNames(q.DB(), ids...)
	if err != nil {
		return nil, nil, err
	}
	items = make([]HistoryItem, 0, len(rows))
	for _, r := range rows {
		items = append(items, HistoryItem{
			ID: r.ID, OperationID: r.OperationID, Decision: r.Decision, Previous: r.Previous,
			Purpose: optText(r.Purpose), Reason: r.Reason,
			DecidedBy: decidedBy(names, r.DecidedByUserID), DecidedAt: T(r.DecidedAt),
			AgainstVersion: r.AgainstVersion, ResultVersion: r.ResultVersion,
			UndoesDecisionID: r.UndoesDecisionID,
		})
	}
	return items, next, nil
}

/* ------------------------- the classification clock ----------------------- */

// ClassificationSeq is the workspace's classification clock in the request's
// snapshot: 0 before the first decision (no clock row yet). Every decision
// transaction bumps it (§5.5).
//
// A list whose filter or sort involves classification reads it on its FIRST
// page and puts it in the cursor (Cursor.ClassSeq); later pages carry that
// same value forward after CheckClassificationSeq accepts it. Read in the same
// snapshot as the page, so the seq and the rows agree.
func ClassificationSeq(q *Query) (int64, error) {
	var seq []int64
	if err := q.DB().Raw(`SELECT seq FROM iga_classification_clock WHERE workspace_id = ?`, q.WS).
		Scan(&seq).Error; err != nil {
		return 0, err
	}
	if len(seq) == 0 {
		return 0, nil
	}
	return seq[0], nil
}

// CheckClassificationSeq enforces §5.5's list consistency for a later page of
// a classification list: if a decision landed since the first page, the page
// boundaries the client holds no longer describe the list, so the request is
// 409 listing_changed with reason "classification_changed" and the console
// restarts from page one (§2.14.6).
//
// A nil cursor is a first page and always passes. A cursor for a
// classification list that carries no clock was not issued by one -- it cannot
// prove the list is unchanged -- so it is 400 cursor_invalid, never accepted
// as current.
//
// Lists that neither filter nor sort on classification must NOT call this:
// they show each row's classification as of the request and are unaffected by
// decisions. A classification FACET alone does not bind either (D-83): its
// counts are as of each page's snapshot, and a decision between pages moves
// no row across a page boundary unless the rows are chosen or ordered by it.
//
// How a list uses the pair:
//
//	first page (no cursor):  seq, err := ClassificationSeq(q)   -> next cursor's ClassSeq = &seq
//	later page (cursor c):   err := CheckClassificationSeq(q, c) -> next cursor's ClassSeq = c.ClassSeq
func CheckClassificationSeq(q *Query, c *Cursor) error {
	if c == nil {
		return nil
	}
	if c.ClassSeq == nil {
		return CursorInvalid("Cursor carries no classification clock.")
	}
	seq, err := ClassificationSeq(q)
	if err != nil {
		return err
	}
	if seq != *c.ClassSeq {
		return ListingChanged("classification_changed")
	}
	return nil
}

/* ------------------------------- capability ------------------------------- */

// ClassifyCaller is what the handler established about the caller, for
// meta.capabilities.can_classify: whether the token is a verified human
// workspace member (the actor rule, §2.14.3 -- humanActor in
// controllers/platform) and whether it carries iga:review (authz.Allows,
// the same test the POST route's Require middleware applies).
type ClassifyCaller struct {
	Human     bool
	CanReview bool
}

// CanClassify is meta.capabilities.can_classify on a workload detail (§5.2,
// §2.14.6 "Offered"): true exactly when THIS caller could make a
// classification decision on THIS workload now -- classify it, or undo a
// classification -- so the console offers the action only where the POST
// could succeed:
//
//   - a verified human with iga:review (both are required by the POST);
//   - on an active workload (a retired one is 422 invalid_decision, D-30);
//   - that is not provider-native (422 provider_native, never human-editable).
//
// Anything else -- including a classification value this build does not
// know -- is false, and it is always stated, never absent (D-83). It belongs
// on the workload detail only. The POST remains the enforcement; this only
// decides whether to offer.
func CanClassify(caller ClassifyCaller, classification, lifecycle string) bool {
	if !caller.Human || !caller.CanReview || lifecycle != models.IGALifecycleActive {
		return false
	}
	switch classification {
	case models.ClassificationUnclassified, models.ClassificationClassified:
		return true
	}
	return false
}
