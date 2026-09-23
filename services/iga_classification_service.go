package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// ClassificationService records a human's classification decision on a
// workload (SPEC-iga-phase2-graph.md §2.14.3 "The classification contract",
// §5.5, T6.6).
//
// The whole contract is one transaction whose ORDER is the point, so its SQL
// is written out here, step by step, rather than spread over a repository
// where the order would be implicit in who calls what:
//
//  1. lock the workload row;
//  2. THEN look the operation up -- a retry that waited on the lock now sees
//     the original's committed decision and replays it;
//  3. then refuse provider-native, retired and stale-version requests;
//  4. insert the decision, 5. update the workload and bump the clock, 6. commit.
//
// Looking the operation up BEFORE the lock is the defect this ordering exists
// to prevent (B22): two concurrent retries both miss it, and the second fails
// with a 409 or a unique violation although its intent had landed. The same
// is true of IGAController.idempotent, which is why it is not reused here.
//
// Outcomes are the §5.2 error vocabulary (*igaread.Error), so the handler
// renders them as they are.
type ClassificationService struct {
	db          *gorm.DB
	lockTimeout time.Duration
	// beforeCommit runs after every write of a decision, while the workload
	// row is still locked and nothing is committed. Tests only: it is how
	// B22 holds one request inside its transaction while another arrives.
	beforeCommit func()
}

// ClassificationLockTimeout bounds the wait for the workload's row lock
// (D-31). The projector holds workload row locks for a whole projection
// transaction, so an unbounded wait would hang the console's Save behind a
// scan. A timeout is 504 query_timeout: the outcome is unknown to the client,
// which retries with the same operation_id (§2.14.6 "Network failure").
const ClassificationLockTimeout = 3 * time.Second

// NewClassificationService builds the decision service over db.
func NewClassificationService(db *gorm.DB) *ClassificationService {
	return &ClassificationService{db: db, lockTimeout: ClassificationLockTimeout}
}

// WithLockTimeout returns a copy with a different lock wait. Tests use it to
// make the timeout bind without waiting the full three seconds.
func (s *ClassificationService) WithLockTimeout(d time.Duration) *ClassificationService {
	cp := *s
	cp.lockTimeout = d
	return &cp
}

// WithBeforeCommit returns a copy that calls fn after a decision's writes and
// before its commit, with the workload row locked. Tests only.
func (s *ClassificationService) WithBeforeCommit(fn func()) *ClassificationService {
	cp := *s
	cp.beforeCommit = fn
	return &cp
}

// ClassifyRequest is one classification intent, as the handler parsed it.
// ActorUserID is the VERIFIED human (humanActor), never a claim taken on
// trust; OperationID is the client's, one per intent, reused on every retry.
type ClassifyRequest struct {
	WorkloadID       uuid.UUID
	ActorUserID      uuid.UUID
	OperationID      uuid.UUID
	Decision         string
	Purpose          string
	Reason           string
	ExpectedVersion  int64
	UndoesDecisionID *uuid.UUID
}

// normalized trims the free text -- the hash is over trimmed strings (D-29),
// so the stored row must be too, or a replay would return text that differs
// from what was hashed -- and validates what can be validated without the
// database. Every failure is 400 invalid_parameter (D-30).
//
// An undo must name the decision it undoes, and only an undo may: §2.14.3
// defines undo as "a new decision (unclassified) with undoes_decision_id set",
// and unclassified is reachable only by undo, so an unlinked unclassified or a
// linked classified_agent would be a record that claims something about its
// history that is not so.
func (r ClassifyRequest) normalized() (ClassifyRequest, *igaread.Error) {
	r.Purpose = strings.TrimSpace(r.Purpose)
	r.Reason = strings.TrimSpace(r.Reason)
	switch {
	case r.WorkloadID == uuid.Nil:
		return r, igaread.NotFound()
	case r.ActorUserID == uuid.Nil:
		return r, igaread.Forbidden("Classification requires a verified workspace member.")
	case r.OperationID == uuid.Nil:
		return r, igaread.InvalidParameter("operation_id", "operation_id must be a client-generated UUID")
	case r.Decision != models.ClassificationClassified && r.Decision != models.ClassificationUnclassified:
		return r, igaread.InvalidParameter("decision", "decision must be classified_agent or unclassified")
	case r.Reason == "":
		return r, igaread.InvalidParameter("reason", "reason is required: it is the audit record")
	case r.ExpectedVersion < 0:
		return r, igaread.InvalidParameter("expected_version", "expected_version must be a non-negative integer")
	case r.Decision == models.ClassificationUnclassified && r.UndoesDecisionID == nil:
		return r, igaread.InvalidParameter("undoes_decision_id", "an unclassified decision is an undo and must name the decision it undoes")
	case r.Decision == models.ClassificationClassified && r.UndoesDecisionID != nil:
		return r, igaread.InvalidParameter("undoes_decision_id", "only an unclassified decision (an undo) may name a decision it undoes")
	}
	return r, nil
}

// ClassificationRequestHash binds an operation to its request (D-29): SHA-256
// over the canonical JSON of the workload, the actor and every request field,
// strings trimmed, null for no undo. The same operation_id arriving with any
// of these different is 422 operation_id_reused, not a replay.
//
// Canonical because encoding/json writes struct fields in declaration order
// and UUIDs in their one lower-case form: a byte-identical retry always hashes
// the same, whatever the client's key order or whitespace.
func ClassificationRequestHash(r ClassifyRequest) string {
	var undoes *string
	if r.UndoesDecisionID != nil {
		s := r.UndoesDecisionID.String()
		undoes = &s
	}
	canon, _ := json.Marshal(struct {
		WorkloadID       string  `json:"workload_id"`
		ActorUserID      string  `json:"actor_user_id"`
		Decision         string  `json:"decision"`
		Purpose          string  `json:"purpose"`
		Reason           string  `json:"reason"`
		ExpectedVersion  int64   `json:"expected_version"`
		UndoesDecisionID *string `json:"undoes_decision_id"`
	}{
		WorkloadID:  r.WorkloadID.String(),
		ActorUserID: r.ActorUserID.String(),
		Decision:    strings.TrimSpace(r.Decision),
		Purpose:     strings.TrimSpace(r.Purpose),
		Reason:      strings.TrimSpace(r.Reason),
		// The version the intent was formed against is part of the intent: the
		// same words against another version are a different decision.
		ExpectedVersion:  r.ExpectedVersion,
		UndoesDecisionID: undoes,
	})
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// lockedWorkload is what step 1 reads under the lock.
type lockedWorkload struct {
	ID                    uuid.UUID
	Classification        string
	ClassificationVersion int64
	Lifecycle             string
}

// Classify runs the §5.5 transaction for one request in workspace ws and
// returns the POST 200's data. Every refusal is an *igaread.Error: 404
// not_found, 409 classification_conflict (with the current decision), 422
// provider_native / invalid_decision / operation_id_reused, 504 query_timeout
// on a lock wait past ClassificationLockTimeout; any other database error is
// 500 internal.
//
// Classification is not part of a graph revision: nothing here writes
// iga_publication, so a decision never triggers the revision-moved banner
// (§2.14.6). Lists that involve classification see it through the clock.
func (s *ClassificationService) Classify(ctx context.Context, ws uuid.UUID, in ClassifyRequest) (*igaread.ClassifyResult, error) {
	req, verr := in.normalized()
	if verr != nil {
		return nil, verr
	}
	hash := ClassificationRequestHash(req)

	var out igaread.ClassifyResult
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// D-31: a bounded wait for every lock this transaction takes -- the
		// workload row, the operation key's unique index entry, the clock row.
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", s.lockTimeout.Milliseconds())).Error; err != nil {
			return err
		}

		// 1. THE LOCK COMES FIRST. Every request for this workload serializes
		// here, so step 2 runs only after any concurrent decision on it has
		// committed or rolled back -- and at READ COMMITTED it sees that
		// commit.
		var locked []lockedWorkload
		if err := tx.Raw(`SELECT id, classification, classification_version, lifecycle
			FROM iga_workload
			WHERE workspace_id = ? AND id = ? AND provider = 'aws'
			FOR UPDATE`, ws, req.WorkloadID).Scan(&locked).Error; err != nil {
			return err
		}
		if len(locked) == 0 {
			// Not in this table in this workspace: no hint whether it exists
			// elsewhere (§5.2).
			return igaread.NotFound()
		}
		w := locked[0]

		// 2. THEN the operation. Found with the same hash: this intent already
		// landed, and its STORED outcome is the answer, even if the version has
		// moved since. Found with a different hash: the id is being reused for
		// another workload, actor or content.
		var prior []models.IGAWorkloadClassification
		if err := tx.Raw(`SELECT * FROM iga_workload_classification
			WHERE workspace_id = ? AND operation_id = ?`, ws, req.OperationID).Scan(&prior).Error; err != nil {
			return err
		}
		if len(prior) > 0 {
			if prior[0].RequestHash != hash {
				return operationReused()
			}
			res, err := igaread.RenderClassifyResult(tx, prior[0], true)
			if err != nil {
				return err
			}
			out = res
			return nil
		}

		// 3. The rules, against the locked row.
		if w.Classification == models.ClassificationProviderAgent {
			// The provider's own API calls it an agent; not human-editable.
			return igaread.Unprocessable("provider_native", "AWS reports this workload as an agent; its classification is not editable.")
		}
		if w.Lifecycle != models.IGALifecycleActive {
			// Recreation does not carry classification (§2.14.3): a retired row
			// keeps the decisions it had, and nothing new is decided about an
			// object no longer observed (D-30).
			return igaread.Unprocessable("invalid_decision", "The workload is retired; its classification can no longer change.")
		}
		if w.ClassificationVersion != req.ExpectedVersion {
			// Checked before the transition rules: a client with a stale view
			// is told what changed and by whom, not that its (stale) request
			// makes no sense.
			conflict, err := igaread.ClassificationConflict(tx, ws, w.ID, w.Classification, w.ClassificationVersion)
			if err != nil {
				return err
			}
			return conflict
		}
		if e := s.checkTransition(tx, ws, w, req); e != nil {
			return e
		}

		// 4. The decision row: the audit record (§2.14.3 "Audit").
		row := models.IGAWorkloadClassification{
			WorkspaceID: ws, WorkloadID: w.ID, OperationID: req.OperationID,
			Decision: req.Decision, Previous: w.Classification,
			Purpose: req.Purpose, Reason: req.Reason,
			DecidedByUserID: req.ActorUserID,
			AgainstVersion:  req.ExpectedVersion, RequestHash: hash,
			ResultVersion:    w.ClassificationVersion + 1,
			UndoesDecisionID: req.UndoesDecisionID,
		}
		var ins []struct {
			ID        uuid.UUID
			DecidedAt time.Time
		}
		if err := tx.Raw(`INSERT INTO iga_workload_classification
			(workspace_id, workload_id, operation_id, decision, previous, purpose, reason,
			 decided_by_user_id, against_version, request_hash, result_version, undoes_decision_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id, decided_at`,
			row.WorkspaceID, row.WorkloadID, row.OperationID, row.Decision, row.Previous, row.Purpose, row.Reason,
			row.DecidedByUserID, row.AgainstVersion, row.RequestHash, row.ResultVersion, row.UndoesDecisionID,
		).Scan(&ins).Error; err != nil {
			// 6 (early). The lock serializes ONE workload, so a duplicate
			// operation id can only be the same id used concurrently on a
			// DIFFERENT workload, whose transaction committed first while this
			// one waited on the index entry. Returning the error rolls back.
			if isOperationKeyViolation(err) {
				return operationReused()
			}
			return err
		}
		if len(ins) != 1 {
			return fmt.Errorf("classification insert returned %d rows", len(ins))
		}
		row.ID, row.DecidedAt = ins[0].ID, ins[0].DecidedAt

		// 5. The workload and the workspace's classification clock, in the same
		// transaction: either all of it lands or none does.
		upd := tx.Exec(`UPDATE iga_workload
			SET classification = ?, classification_version = classification_version + 1
			WHERE workspace_id = ? AND id = ?`, req.Decision, ws, w.ID)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected != 1 {
			return fmt.Errorf("classification update touched %d workload rows", upd.RowsAffected)
		}
		if err := tx.Exec(`INSERT INTO iga_classification_clock (workspace_id, seq) VALUES (?, 1)
			ON CONFLICT (workspace_id) DO UPDATE SET seq = iga_classification_clock.seq + 1`, ws).Error; err != nil {
			return err
		}

		res, err := igaread.RenderClassifyResult(tx, row, false)
		if err != nil {
			return err
		}
		out = res
		if s.beforeCommit != nil {
			s.beforeCommit()
		}
		// 6. Commit: the Transaction wrapper commits when this returns nil.
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		if isLockTimeout(err) {
			return nil, igaread.QueryTimeout(err)
		}
		return nil, igaread.AsError(err)
	}
	return &out, nil
}

// checkTransition enforces the decision rules that depend on the locked
// workload (D-30). Only two transitions exist: unclassified -> classified_agent
// (classify) and classified_agent -> unclassified (undo, §2.14.3). Deciding
// what the workload already is, or undoing anything but its latest decision,
// is 422 invalid_decision.
func (s *ClassificationService) checkTransition(tx *gorm.DB, ws uuid.UUID, w lockedWorkload, req ClassifyRequest) error {
	if req.Decision == w.Classification {
		return igaread.Unprocessable("invalid_decision", "The workload is already "+w.Classification+".")
	}
	if req.Decision != models.ClassificationUnclassified {
		return nil
	}
	// An undo. normalized() guarantees it names a decision; it must be the
	// one that made this workload classified_agent -- its latest -- or the
	// record would say it undid something it did not.
	latest, err := igaread.LatestDecisionRow(tx, ws, w.ID)
	if err != nil {
		return err
	}
	if latest == nil || latest.ID != *req.UndoesDecisionID || latest.Decision != models.ClassificationClassified {
		return igaread.Unprocessable("invalid_decision", "undoes_decision_id must be this workload's latest classification decision.")
	}
	return nil
}

func operationReused() *igaread.Error {
	return igaread.Unprocessable("operation_id_reused",
		"This operation_id was already used for a different request; a new intent needs a new operation_id.")
}

// sqlState is the SQLSTATE of a driver error, or "". Asserting the method
// keeps the driver out of this file's imports (pgconn.PgError and lib/pq's
// Error both have it).
func sqlState(err error) string {
	var st interface{ SQLState() string }
	if errors.As(err, &st) {
		return st.SQLState()
	}
	return ""
}

// isOperationKeyViolation is a unique violation (23505) on iga_wc_operation_key
// specifically -- not any duplicate, so a violation of some other constraint
// is reported as the database error it is, never as a reused operation.
func isOperationKeyViolation(err error) bool {
	return sqlState(err) == "23505" && strings.Contains(err.Error(), "iga_wc_operation_key")
}

// isLockTimeout is lock_timeout firing (55P03 lock_not_available).
func isLockTimeout(err error) bool { return sqlState(err) == "55P03" }
