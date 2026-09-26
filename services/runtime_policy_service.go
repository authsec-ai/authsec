package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Actor is the human or system account on a runtime-policy mutation.
type Actor struct {
	UserID      uuid.UUID
	WorkspaceID uuid.UUID
	Kind        string
}

// StatusError is an HTTP failure with a stable code. The message is safe to
// return; it does not include SQL or document bodies.
type StatusError struct {
	Status  int
	Code    string
	Message string
	Extra   map[string]any
}

func (e *StatusError) Error() string { return e.Code + ": " + e.Message }

func statusErr(status int, code, msg string) *StatusError {
	return &StatusError{Status: status, Code: code, Message: msg}
}

// RuntimePolicyService is the M5 admin API. Publications, simulation and
// rollout stay unimplemented for the later delivery package.
type RuntimePolicyService struct {
	db   *gorm.DB
	reg  *profiles.Registry
	lock time.Duration
}

// NewRuntimePolicyService builds the service. A nil registry falls back to the
// embedded certified profiles.
func NewRuntimePolicyService(db *gorm.DB) *RuntimePolicyService {
	reg, err := profiles.Load()
	if err != nil {
		reg = &profiles.Registry{}
	}
	return &RuntimePolicyService{db: db, reg: reg, lock: ClassificationLockTimeout}
}

type policyHead struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	OwnerUserID          uuid.UUID `json:"owner_user_id"`
	CurrentDraftRevision int       `json:"current_draft_revision"`
	Lifecycle            string    `json:"lifecycle"`
}

type revisionHead struct {
	Revision      int       `json:"revision"`
	Document      string    `json:"document"`
	ContentHash   string    `json:"content_hash"`
	AuthorUserID  uuid.UUID `json:"author_user_id"`
	State         string    `json:"state"`
	GraphRevision int64     `json:"graph_revision"`
}

func (s *RuntimePolicyService) Create(ctx context.Context, actor Actor, key string, body []byte) (int, []byte, error) {
	doc, err := compile.Parse(body)
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	return s.once(ctx, actor, key, "POST /api/iga/v2/runtime-policies", "", body, func(tx *gorm.DB) (int, []byte, error) {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM runtime_policies WHERE workspace_id = ? AND name = ?`,
			actor.WorkspaceID, doc.Name).Scan(&n).Error; err != nil {
			return 0, nil, err
		}
		if n > 0 {
			return 0, nil, statusErr(http.StatusConflict, "name_taken", "A runtime policy with this name already exists.")
		}
		canonical, hash, err := compile.Canonical(doc)
		if err != nil {
			return 0, nil, err
		}
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO runtime_policies
			(id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
			VALUES (?, ?, ?, ?, 1, 'draft')`,
			id, actor.WorkspaceID, doc.Name, actor.UserID).Error; err != nil {
			return 0, nil, err
		}
		if err := insertRevision(tx, actor, id, 1, canonical, hash, doc.EvidenceGraphRevision, models.RuntimePolicyStateDraft); err != nil {
			return 0, nil, err
		}
		if err := writeAudit(tx, actor, &id, "create", "", requestHash("POST /api/iga/v2/runtime-policies", "", body),
			doc.Targets.WorkloadIDs, map[string]any{}, map[string]any{"revision": 1, "state": "draft"}); err != nil {
			return 0, nil, err
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(1, hash),
			"data": map[string]any{"policy_id": id, "revision": 1, "lifecycle": models.RuntimePolicyStateDraft, "content_hash": hash},
		})
		return http.StatusCreated, out, nil
	})
}

func (s *RuntimePolicyService) List(ctx context.Context, ws uuid.UUID) (int, []byte, error) {
	var rows []policyHead
	err := s.db.WithContext(ctx).Raw(`SELECT id, name, owner_user_id, current_draft_revision, lifecycle
		FROM runtime_policies WHERE workspace_id = ? ORDER BY name`, ws).Scan(&rows).Error
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	if rows == nil {
		rows = []policyHead{}
	}
	out, _ := json.Marshal(map[string]any{"data": rows})
	return http.StatusOK, out, nil
}

func (s *RuntimePolicyService) Get(ctx context.Context, ws, id uuid.UUID) (int, []byte, error) {
	var heads []policyHead
	err := s.db.WithContext(ctx).Raw(`SELECT id, name, owner_user_id, current_draft_revision, lifecycle
		FROM runtime_policies WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&heads).Error
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	if len(heads) == 0 {
		return 0, nil, statusErr(http.StatusNotFound, "not_found", "Not found.")
	}
	var revs []revisionHead
	if err := s.db.WithContext(ctx).Raw(`SELECT revision, document::text AS document, content_hash, author_user_id, state, graph_revision
		FROM runtime_policy_revisions WHERE workspace_id = ? AND policy_id = ? ORDER BY revision`,
		ws, id).Scan(&revs).Error; err != nil {
		return 0, nil, statusFrom(err)
	}
	etagValue := ""
	if len(revs) > 0 {
		last := revs[len(revs)-1]
		etagValue = etag(last.Revision, last.ContentHash)
	}
	out, _ := json.Marshal(map[string]any{"etag": etagValue, "data": map[string]any{"policy": heads[0], "revisions": revs}})
	return http.StatusOK, out, nil
}

func (s *RuntimePolicyService) PutDraft(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	doc, err := compile.Parse(body)
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	route := "PUT /api/iga/v2/runtime-policies/:id/draft"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		canonical, hash, err := compile.Canonical(doc)
		if err != nil {
			return 0, nil, err
		}
		next := cur.Revision + 1
		if err := insertRevision(tx, actor, id, next, canonical, hash, doc.EvidenceGraphRevision, models.RuntimePolicyStateDraft); err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policies SET name = ?, current_draft_revision = ?, lifecycle = 'draft', updated_at = now()
			WHERE workspace_id = ? AND id = ?`, doc.Name, next, actor.WorkspaceID, id).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policy_approvals
			SET invalidated_at = now(), invalidated_reason = 'content_changed'
			WHERE workspace_id = ? AND policy_id = ? AND invalidated_at IS NULL AND revision_hash <> ?`,
			actor.WorkspaceID, id, hash).Error; err != nil {
			return 0, nil, err
		}
		diff := ruleDiff(cur.Document, doc, cur.Revision, next)
		if err := writeAudit(tx, actor, &id, "draft", "", requestHash(route, ifMatch, body),
			doc.Targets.WorkloadIDs, map[string]any{"revision": cur.Revision, "state": cur.State},
			map[string]any{"revision": next, "state": "draft"}); err != nil {
			return 0, nil, err
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(next, hash),
			"data": map[string]any{"policy_id": id, "revision": next, "lifecycle": "draft", "content_hash": hash, "diff": diff},
		})
		return http.StatusOK, out, nil
	})
}

func (s *RuntimePolicyService) Validate(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	route := "POST /api/iga/v2/runtime-policies/:id/validate"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		if !RuntimePolicyTransitionAllowed(cur.State, models.RuntimePolicyStateValidated) {
			return 0, nil, statusErr(http.StatusConflict, "invalid_transition", "Only a draft revision can be validated.")
		}
		doc, err := compile.Parse([]byte(cur.Document))
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		cat := dbCatalog{tx: tx}
		result, err := compile.Compile(ctx, s.reg, cat, actor.WorkspaceID, cur.Revision, doc)
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		targets, err := capabilityTargets(tx, actor.WorkspaceID, doc)
		if err != nil {
			return 0, nil, err
		}
		report, err := compile.CheckEnforceable(s.reg, doc, targets)
		result.Semantic.Unsupported = report.Unsupported
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'validated' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, id, cur.Revision).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policies SET lifecycle = 'validated', updated_at = now() WHERE workspace_id = ? AND id = ?`,
			actor.WorkspaceID, id).Error; err != nil {
			return 0, nil, err
		}
		if err := writeAudit(tx, actor, &id, "validate", "", requestHash(route, ifMatch, body),
			doc.Targets.WorkloadIDs, map[string]any{"state": cur.State}, map[string]any{"state": "validated"}); err != nil {
			return 0, nil, err
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(cur.Revision, cur.ContentHash),
			"data": map[string]any{
				"policy_id": id, "revision": cur.Revision, "state": "validated",
				"content_hash": cur.ContentHash, "target_digest": result.TargetDigest,
				"semantic_report": result.Semantic, "controls": json.RawMessage(result.Controls),
			},
		})
		return http.StatusOK, out, nil
	})
}

type approvalRequest struct {
	RevisionHash string          `json:"revision_hash"`
	SimulationID uuid.UUID       `json:"simulation_id"`
	TargetDigest string          `json:"target_digest"`
	Reason       string          `json:"reason"`
	MFAContext   json.RawMessage `json:"mfa_context"`
	ExpiresAt    *time.Time      `json:"expires_at"`
}

func (s *RuntimePolicyService) Approve(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	if models.IsRuntimePolicyCandidateSystem(actor.UserID, actor.Kind) {
		return 0, nil, statusErr(http.StatusForbidden, "candidate_system_forbidden", "The candidate generator cannot approve or enforce.")
	}
	var req approvalRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "The approval body is not JSON.")
	}
	if req.Reason == "" || req.RevisionHash == "" || req.TargetDigest == "" || req.SimulationID == uuid.Nil {
		return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "revision_hash, simulation_id, target_digest and reason are required.")
	}
	if len(req.MFAContext) == 0 {
		req.MFAContext = []byte(`{}`)
	}
	route := "POST /api/iga/v2/runtime-policies/:id/approvals"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		if !RuntimePolicyTransitionAllowed(cur.State, models.RuntimePolicyStateApproved) {
			return 0, nil, statusErr(http.StatusConflict, "invalid_transition", "Approval requires a simulated revision.")
		}
		if req.RevisionHash != cur.ContentHash {
			return 0, nil, statusErr(http.StatusConflict, "content_hash_mismatch", "The revision content hash does not match this draft.")
		}
		var second bool
		if err := tx.Raw(`SELECT COALESCE((SELECT second_approver_required FROM runtime_policy_settings WHERE workspace_id = ?), false)`,
			actor.WorkspaceID).Scan(&second).Error; err != nil {
			return 0, nil, err
		}
		if second && actor.UserID == cur.AuthorUserID {
			return 0, nil, statusErr(http.StatusForbidden, "second_approver_required", "The author cannot approve their own revision.")
		}
		doc, err := compile.Parse([]byte(cur.Document))
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		cat := dbCatalog{tx: tx}
		result, err := compile.Compile(ctx, s.reg, cat, actor.WorkspaceID, cur.Revision, doc)
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		if req.TargetDigest != result.TargetDigest {
			return 0, nil, statusErr(http.StatusConflict, "target_digest_mismatch", "The target digest does not match the expanded incarnations.")
		}
		var sims []struct{ N int }
		if err := tx.Raw(`SELECT 1 AS n FROM runtime_policy_simulations
			WHERE workspace_id = ? AND id = ? AND policy_id = ? AND revision_hash = ? AND target_digest = ?`,
			actor.WorkspaceID, req.SimulationID, id, cur.ContentHash, req.TargetDigest).Scan(&sims).Error; err != nil {
			return 0, nil, err
		}
		if len(sims) == 0 {
			return 0, nil, statusErr(http.StatusUnprocessableEntity, "simulation_required", "No simulation exists for this revision hash and target digest.")
		}
		targets, err := capabilityTargets(tx, actor.WorkspaceID, doc)
		if err != nil {
			return 0, nil, err
		}
		if _, err := compile.CheckEnforceable(s.reg, doc, targets); err != nil {
			return 0, nil, statusFrom(err)
		}
		approvalID := uuid.New()
		if err := tx.Exec(`INSERT INTO runtime_policy_approvals
			(id, workspace_id, policy_id, revision, revision_hash, simulation_id, target_digest, actor_user_id, mfa_context, reason, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?)`,
			approvalID, actor.WorkspaceID, id, cur.Revision, cur.ContentHash, req.SimulationID, req.TargetDigest,
			actor.UserID, string(req.MFAContext), req.Reason, req.ExpiresAt).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'approved' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, id, cur.Revision).Error; err != nil {
			return 0, nil, err
		}
		if err := tx.Exec(`UPDATE runtime_policies SET lifecycle = 'approved', updated_at = now() WHERE workspace_id = ? AND id = ?`,
			actor.WorkspaceID, id).Error; err != nil {
			return 0, nil, err
		}
		if err := writeAudit(tx, actor, &id, "approve", req.Reason, requestHash(route, ifMatch, body),
			doc.Targets.WorkloadIDs, map[string]any{"state": cur.State}, map[string]any{"state": "approved", "approval_id": approvalID}); err != nil {
			return 0, nil, err
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(cur.Revision, cur.ContentHash),
			"data": map[string]any{"policy_id": id, "approval_id": approvalID, "revision": cur.Revision, "state": "approved"},
		})
		return http.StatusCreated, out, nil
	})
}

func (s *RuntimePolicyService) once(ctx context.Context, actor Actor, key, route, ifMatch string, body []byte, fn func(tx *gorm.DB) (int, []byte, error)) (int, []byte, error) {
	if err := checkKey(key); err != nil {
		return 0, nil, err
	}
	hash := requestHash(route, ifMatch, body)
	var status int
	var out []byte
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", s.lock.Milliseconds())).Error; err != nil {
			return err
		}
		if replay, ok, err := readIdempotent(tx, actor.WorkspaceID, key, hash); err != nil || ok {
			if err != nil {
				return err
			}
			status, out = replay.status, replay.body
			return nil
		}
		st, payload, err := fn(tx)
		if err != nil {
			return err
		}
		stored, err := storeIdempotent(tx, actor.WorkspaceID, key, route, hash, st, payload)
		if err != nil {
			return err
		}
		status, out = stored.status, stored.body
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	return status, out, nil
}

func (s *RuntimePolicyService) onceLocked(ctx context.Context, actor Actor, id uuid.UUID, key, route, ifMatch string, body []byte, fn func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error)) (int, []byte, error) {
	if ifMatch == "" {
		return 0, nil, statusErr(http.StatusPreconditionRequired, "precondition_required", "If-Match is required.")
	}
	if err := checkKey(key); err != nil {
		return 0, nil, err
	}
	hash := requestHash(route, ifMatch, body)
	var status int
	var out []byte
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(fmt.Sprintf("SET LOCAL lock_timeout = %d", s.lock.Milliseconds())).Error; err != nil {
			return err
		}
		var heads []policyHead
		if err := tx.Raw(`SELECT id, name, owner_user_id, current_draft_revision, lifecycle
			FROM runtime_policies WHERE workspace_id = ? AND id = ? FOR UPDATE`,
			actor.WorkspaceID, id).Scan(&heads).Error; err != nil {
			return err
		}
		if len(heads) == 0 {
			return statusErr(http.StatusNotFound, "not_found", "Not found.")
		}
		if replay, ok, err := readIdempotent(tx, actor.WorkspaceID, key, hash); err != nil || ok {
			if err != nil {
				return err
			}
			status, out = replay.status, replay.body
			return nil
		}
		var revs []revisionHead
		if err := tx.Raw(`SELECT revision, document::text AS document, content_hash, author_user_id, state, graph_revision
			FROM runtime_policy_revisions WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
			actor.WorkspaceID, id, heads[0].CurrentDraftRevision).Scan(&revs).Error; err != nil {
			return err
		}
		if len(revs) == 0 {
			return statusErr(http.StatusConflict, "invalid_transition", "The policy has no current revision.")
		}
		st, payload, err := fn(tx, heads[0], revs[0])
		if err != nil {
			return err
		}
		stored, err := storeIdempotent(tx, actor.WorkspaceID, key, route, hash, st, payload)
		if err != nil {
			return err
		}
		status, out = stored.status, stored.body
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	return status, out, nil
}

type idemRow struct {
	status int
	body   []byte
}

func readIdempotent(tx *gorm.DB, ws uuid.UUID, key, hash string) (idemRow, bool, error) {
	var prior []struct {
		Hash   string
		Status int
		Body   string
	}
	if err := tx.Raw(`SELECT request_hash AS hash, response_status AS status, response_body::text AS body
		FROM iga_idempotency_keys WHERE workspace_id = ? AND idempotency_key = ?`, ws, key).Scan(&prior).Error; err != nil {
		return idemRow{}, false, err
	}
	if len(prior) == 0 {
		return idemRow{}, false, nil
	}
	if prior[0].Hash != hash {
		return idemRow{}, false, statusErr(http.StatusConflict, "idempotency_key_reused", "This Idempotency-Key was already used for a different request.")
	}
	return idemRow{status: prior[0].Status, body: []byte(prior[0].Body)}, true, nil
}

func storeIdempotent(tx *gorm.DB, ws uuid.UUID, key, route, hash string, status int, payload []byte) (idemRow, error) {
	var inserted []struct {
		Status int
		Body   string
	}
	err := tx.Raw(`INSERT INTO iga_idempotency_keys
		(workspace_id, idempotency_key, route, request_hash, response_status, response_body)
		VALUES (?, ?, ?, ?, ?, CAST(? AS jsonb))
		ON CONFLICT (workspace_id, idempotency_key) DO NOTHING
		RETURNING response_status AS status, response_body::text AS body`,
		ws, key, route, hash, status, string(payload)).Scan(&inserted).Error
	if err != nil {
		return idemRow{}, err
	}
	if len(inserted) == 1 {
		return idemRow{status: inserted[0].Status, body: []byte(inserted[0].Body)}, nil
	}
	row, ok, err := readIdempotent(tx, ws, key, hash)
	if err != nil || !ok {
		if err == nil {
			err = statusErr(http.StatusConflict, "idempotency_key_reused", "This Idempotency-Key was already used for a different request.")
		}
		return idemRow{}, err
	}
	return row, nil
}

func insertRevision(tx *gorm.DB, actor Actor, policyID uuid.UUID, revision int, document []byte, hash string, graph int64, state string) error {
	return tx.Exec(`INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES (?, ?, ?, ?, CAST(? AS jsonb), ?, ?, ?, ?, ?)`,
		uuid.New(), actor.WorkspaceID, policyID, revision, string(document), hash, actor.UserID, state, graph, models.RuntimePolicyFormatV1).Error
}

func writeAudit(tx *gorm.DB, actor Actor, policyID *uuid.UUID, action, reason, hash string, targets []string, before, after any) error {
	if targets == nil {
		targets = []string{}
	}
	tb, _ := json.Marshal(targets)
	bb, _ := json.Marshal(before)
	ab, _ := json.Marshal(after)
	return tx.Exec(`INSERT INTO runtime_policy_audit
		(id, workspace_id, policy_id, actor_user_id, action, reason, request_hash, affected_targets, before_state, after_state)
		VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), CAST(? AS jsonb), CAST(? AS jsonb))`,
		uuid.New(), actor.WorkspaceID, policyID, actor.UserID, action, reason, hash, string(tb), string(bb), string(ab)).Error
}

func capabilityTargets(tx *gorm.DB, ws uuid.UUID, doc compile.Document) ([]compile.TargetRef, error) {
	var digests []string
	if err := tx.Raw(`SELECT DISTINCT capability_digest FROM collector_capability_reports WHERE workspace_id = ?`, ws).Scan(&digests).Error; err != nil {
		return nil, err
	}
	out := make([]compile.TargetRef, 0, len(digests))
	for _, d := range digests {
		out = append(out, compile.TargetRef{Profile: doc.Profile, CapabilityDigest: d})
	}
	return out, nil
}

func checkKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return statusErr(http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required.")
	}
	if len(key) > 200 {
		return statusErr(http.StatusBadRequest, "invalid_parameter", "Idempotency-Key must be at most 200 characters.")
	}
	return nil
}

func requestHash(route, ifMatch string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(route))
	h.Write([]byte{0})
	h.Write([]byte(ifMatch))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func etag(revision int, hash string) string {
	return fmt.Sprintf("%d-%s", revision, hash)
}

func ruleDiff(previous string, next compile.Document, from, to int) map[string]any {
	var old compile.Document
	_ = json.Unmarshal([]byte(previous), &old)
	oldIDs := map[string]bool{}
	for _, r := range old.Rules {
		oldIDs[r.ID] = true
	}
	newIDs := map[string]bool{}
	var added, removed []string
	for _, r := range next.Rules {
		newIDs[r.ID] = true
		if !oldIDs[r.ID] {
			added = append(added, r.ID)
		}
	}
	for id := range oldIDs {
		if !newIDs[id] {
			removed = append(removed, id)
		}
	}
	if added == nil {
		added = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	return map[string]any{"from_revision": from, "to_revision": to, "added_rules": added, "removed_rules": removed}
}

func statusFrom(err error) error {
	if err == nil {
		return nil
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se
	}
	var ce *compile.Error
	if errors.As(err, &ce) {
		extra := ce.Details
		return &StatusError{Status: http.StatusUnprocessableEntity, Code: ce.Code, Message: ce.Message, Extra: extra}
	}
	if isLockTimeout(err) {
		return statusErr(http.StatusGatewayTimeout, "query_timeout", "The request did not finish within its deadline.")
	}
	return statusErr(http.StatusInternalServerError, "internal", "Internal error.")
}

// dbCatalog resolves runtime-policy targets inside the caller's transaction.
type dbCatalog struct{ tx *gorm.DB }

func (c dbCatalog) ResolveResource(_ context.Context, ws, id uuid.UUID) (compile.NativeResource, error) {
	var rows []struct {
		WorkspaceID     uuid.UUID
		ReferenceStatus string
		NativeKind      string
		Meta            string
	}
	err := c.tx.Raw(`SELECT workspace_id, reference_status, native_kind, kind_metadata::text AS meta
		FROM iga_resources WHERE id = ?`, id).Scan(&rows).Error
	if err != nil {
		return compile.NativeResource{}, err
	}
	if len(rows) == 0 {
		return compile.NativeResource{}, compile.ErrUnresolved
	}
	if rows[0].WorkspaceID != ws {
		return compile.NativeResource{}, compile.ErrCrossWorkspace
	}
	var meta struct {
		Address    string `json:"address"`
		Port       int    `json:"port"`
		Protocol   string `json:"protocol"`
		BrokerPath string `json:"broker_path"`
	}
	_ = json.Unmarshal([]byte(rows[0].Meta), &meta)
	if rows[0].ReferenceStatus == "referenced" {
		return compile.NativeResource{}, compile.ErrNoNative
	}
	return compile.NativeResource{
		ID: id, ReferenceStatus: rows[0].ReferenceStatus, NativeKind: rows[0].NativeKind,
		Address: meta.Address, Port: meta.Port, Protocol: meta.Protocol, BrokerPath: meta.BrokerPath,
	}, nil
}

func (c dbCatalog) ResolveWorkload(_ context.Context, ws, id uuid.UUID) (compile.WorkloadTarget, error) {
	var rows []struct{ WorkspaceID uuid.UUID }
	if err := c.tx.Raw(`SELECT workspace_id FROM iga_workload WHERE id = ?`, id).Scan(&rows).Error; err != nil {
		return compile.WorkloadTarget{}, err
	}
	if len(rows) == 0 {
		return compile.WorkloadTarget{}, compile.ErrUnresolved
	}
	if rows[0].WorkspaceID != ws {
		return compile.WorkloadTarget{}, compile.ErrCrossWorkspace
	}
	var inst []uuid.UUID
	if err := c.tx.Raw(`SELECT id FROM iga_runtime_instances WHERE workspace_id = ? AND workload_id = ? ORDER BY id`,
		ws, id).Scan(&inst).Error; err != nil {
		return compile.WorkloadTarget{}, err
	}
	return compile.WorkloadTarget{ID: id, RuntimeInstanceIDs: inst}, nil
}

func (c dbCatalog) BrokerConfigured(_ context.Context, ws uuid.UUID, adapter string) (bool, error) {
	var raw []string
	if err := c.tx.Raw(`SELECT configured_brokers::text FROM runtime_policy_settings WHERE workspace_id = ?`, ws).Scan(&raw).Error; err != nil {
		return false, err
	}
	if len(raw) == 0 {
		return false, nil
	}
	var brokers []string
	if err := json.Unmarshal([]byte(raw[0]), &brokers); err != nil {
		return false, err
	}
	for _, b := range brokers {
		if b == adapter {
			return true, nil
		}
	}
	return false, nil
}

func (c dbCatalog) Guardrails(_ context.Context, ws uuid.UUID, _ []uuid.UUID) ([]string, error) {
	var names []string
	if err := c.tx.Raw(`SELECT name FROM agent_policies WHERE workspace_id = ? AND enabled AND desired_state = 'quarantined' ORDER BY name`,
		ws).Scan(&names).Error; err != nil {
		return nil, err
	}
	var plans int64
	if err := c.tx.Raw(`SELECT count(*) FROM enforcement_plans WHERE workspace_id = ?`, ws).Scan(&plans).Error; err != nil {
		return nil, err
	}
	if plans > 0 {
		names = append(names, fmt.Sprintf("%d enforcement plan(s) remain in force", plans))
	}
	return names, nil
}
