package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Pending changes (pending_change, migration 163): the generic two-person
// rule for tier-3 actions (SPEC-secops-backend-upgrade.md, P3, decision 4).
// A loosening change is not applied by its requester; it is stored with its
// payload, and another workspace member who holds governance:approve NOW
// (read from the database, not the token) approves it, which applies it in
// the same transaction through the applier registered for its kind. The
// approver is never the requester (403 self_approval, and a CHECK). The
// requester may withdraw (reject) their own request. A request expires
// after PendingChangeTTL. When the workspace has no second approver the
// caller may apply alone as break-glass (insertBreakGlassChangeTx): the row
// is written applied, break_glass, with a review due within 24 h.
//
// Every statement runs under row-level security for the token's workspace;
// another workspace's change is 404.

// Pending change states.
const (
	PendingChangePending  = "pending"
	PendingChangeApproved = "approved"
	PendingChangeRejected = "rejected"
	PendingChangeApplied  = "applied"
	PendingChangeExpired  = "expired"
)

// Pending change limits.
const (
	PendingChangeTTL         = 7 * 24 * time.Hour
	PendingChangeReviewDue   = SecondPersonReviewWindow
	MaxPendingChangeReason   = 2000
	GovCodeChangePending     = "change_pending"
	GovCodeChangeNotPending  = "change_not_pending"
	GovCodeChangeExpired     = "change_expired"
	GovCodeApproverRequired  = "approval_permission_required"
	pendingChangeDefaultPage = 50
)

// pendingChangeApplier applies an approved change inside the approving
// transaction (tx is under RLS for ws). The returned func, if any, runs
// after commit (cache invalidation).
type pendingChangeApplier func(tx *gorm.DB, ws uuid.UUID, pc *pendingChangeRow) (func(), error)

var (
	pendingChangeKindsMu sync.RWMutex
	pendingChangeKinds   = map[string]pendingChangeApplier{}
)

// registerPendingChangeKind registers the applier of a kind (init time).
func registerPendingChangeKind(kind string, a pendingChangeApplier) {
	pendingChangeKindsMu.Lock()
	defer pendingChangeKindsMu.Unlock()
	if _, dup := pendingChangeKinds[kind]; dup {
		panic("pending change kind registered twice: " + kind)
	}
	pendingChangeKinds[kind] = a
}

func pendingChangeApplierFor(kind string) pendingChangeApplier {
	pendingChangeKindsMu.RLock()
	defer pendingChangeKindsMu.RUnlock()
	return pendingChangeKinds[kind]
}

// PendingChangeView is a change as the API shows it.
type PendingChangeView struct {
	ID             uuid.UUID       `json:"id"`
	Kind           string          `json:"kind"`
	TargetRef      string          `json:"target_ref"`
	Payload        json.RawMessage `json:"payload"`
	Reason         string          `json:"reason"`
	State          string          `json:"state"`
	RequestedBy    uuid.UUID       `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	ApprovedBy     *uuid.UUID      `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time      `json:"approved_at,omitempty"`
	RejectedBy     *uuid.UUID      `json:"rejected_by,omitempty"`
	RejectedAt     *time.Time      `json:"rejected_at,omitempty"`
	DecisionReason string          `json:"decision_reason,omitempty"`
	AppliedAt      *time.Time      `json:"applied_at,omitempty"`
	BreakGlass     bool            `json:"break_glass"`
	ReviewDueAt    *time.Time      `json:"review_due_at,omitempty"`
}

type pendingChangeRow struct {
	ID             uuid.UUID
	Kind           string
	TargetRef      string
	Payload        string
	Reason         string
	State          string
	RequestedBy    uuid.UUID
	RequestedAt    time.Time
	ExpiresAt      time.Time
	ApprovedBy     *uuid.UUID
	ApprovedAt     *time.Time
	RejectedBy     *uuid.UUID
	RejectedAt     *time.Time
	DecisionReason string
	AppliedAt      *time.Time
	BreakGlass     bool
	ReviewDueAt    *time.Time
}

const pendingChangeCols = `id, kind, target_ref, payload::text AS payload, reason, state, requested_by, requested_at,
	expires_at, approved_by, approved_at, rejected_by, rejected_at, decision_reason, applied_at, break_glass, review_due_at`

func (r pendingChangeRow) view() PendingChangeView {
	return PendingChangeView{ID: r.ID, Kind: r.Kind, TargetRef: r.TargetRef, Payload: json.RawMessage(r.Payload),
		Reason: r.Reason, State: r.State, RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt.UTC(),
		ExpiresAt: r.ExpiresAt.UTC(), ApprovedBy: r.ApprovedBy, ApprovedAt: utcPtr(r.ApprovedAt), RejectedBy: r.RejectedBy,
		RejectedAt: utcPtr(r.RejectedAt), DecisionReason: r.DecisionReason, AppliedAt: utcPtr(r.AppliedAt),
		BreakGlass: r.BreakGlass, ReviewDueAt: utcPtr(r.ReviewDueAt)}
}

func readPendingChange(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*pendingChangeRow, error) {
	q := `SELECT ` + pendingChangeCols + ` FROM pending_change WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var row pendingChangeRow
	res := tx.Raw(q, ws, id).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, GovNotFound()
	}
	return &row, nil
}

func insertChangeTx(tx *gorm.DB, ws uuid.UUID, kind, target string, payload any, reason string, actor uuid.UUID,
	now time.Time, breakGlass bool) (*pendingChangeRow, error) {
	if pendingChangeApplierFor(kind) == nil {
		return nil, fmt.Errorf("pending change kind %q is not registered", kind)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	if breakGlass {
		err = tx.Exec(`INSERT INTO pending_change (id, workspace_id, kind, target_ref, payload, reason, state, requested_by,
			    requested_at, expires_at, applied_at, break_glass, review_due_at)
			VALUES (?, ?, ?, ?, ?::jsonb, ?, 'applied', ?, ?, ?, ?, true, ?)`,
			id, ws, kind, target, string(raw), reason, actor, now, now, now, ReviewDue(now)).Error
	} else {
		err = tx.Exec(`INSERT INTO pending_change (id, workspace_id, kind, target_ref, payload, reason, requested_by,
			    requested_at, expires_at)
			VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)`,
			id, ws, kind, target, string(raw), reason, actor, now, now.Add(PendingChangeTTL)).Error
	}
	if isUniqueViolation(err, "uq_pending_change_open") {
		return nil, govConflict(GovCodeChangePending, "A change of this kind is already waiting for approval on this target.", nil)
	}
	if err != nil {
		return nil, err
	}
	return readPendingChange(tx, ws, id, false)
}

// insertPendingChangeTx records a change awaiting a second person.
func insertPendingChangeTx(tx *gorm.DB, ws uuid.UUID, kind, target string, payload any, reason string, actor uuid.UUID, now time.Time) (*pendingChangeRow, error) {
	return insertChangeTx(tx, ws, kind, target, payload, reason, actor, now, false)
}

// insertBreakGlassChangeTx records a change the caller already applied
// alone because no second approver exists.
func insertBreakGlassChangeTx(tx *gorm.DB, ws uuid.UUID, kind, target string, payload any, reason string, actor uuid.UUID, now time.Time) (*pendingChangeRow, error) {
	log.Printf("[pending-change] BREAK-GLASS workspace=%s kind=%s target=%s actor=%s: applied without a second approver; review due in 24h",
		ws, kind, target, actor)
	return insertChangeTx(tx, ws, kind, target, payload, reason, actor, now, true)
}

// PendingChangeService reads and decides pending changes.
type PendingChangeService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewPendingChangeService builds the service.
func NewPendingChangeService(db *gorm.DB) *PendingChangeService {
	return &PendingChangeService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *PendingChangeService) WithClock(now func() time.Time) *PendingChangeService {
	s.now = now
	return s
}

// PendingChangeFilter narrows a listing.
type PendingChangeFilter struct {
	State string
	Kind  string
	Limit int
}

// List lists the workspace's changes, newest first.
func (s *PendingChangeService) List(ctx context.Context, ws uuid.UUID, f PendingChangeFilter) ([]PendingChangeView, error) {
	switch f.State {
	case "", PendingChangePending, PendingChangeApproved, PendingChangeRejected, PendingChangeApplied, PendingChangeExpired:
	default:
		return nil, GovBadParam("state", "state must be pending, approved, rejected, applied or expired.")
	}
	if f.Limit <= 0 || f.Limit > MaxGovPage {
		f.Limit = pendingChangeDefaultPage
	}
	var rows []pendingChangeRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT ` + pendingChangeCols + ` FROM pending_change WHERE workspace_id = ?`
		args := []any{ws}
		if f.State != "" {
			q += ` AND state = ?`
			args = append(args, f.State)
		}
		if f.Kind != "" {
			q += ` AND kind = ?`
			args = append(args, f.Kind)
		}
		q += ` ORDER BY requested_at DESC, id LIMIT ?`
		args = append(args, f.Limit)
		return tx.Raw(q, args...).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingChangeView, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.view())
	}
	return out, nil
}

// Get reads one change; another workspace's is 404.
func (s *PendingChangeService) Get(ctx context.Context, ws, id uuid.UUID) (PendingChangeView, error) {
	var row *pendingChangeRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		row, err = readPendingChange(tx, ws, id, false)
		return err
	})
	if err != nil {
		return PendingChangeView{}, err
	}
	return row.view(), nil
}

// expireIfDue marks a pending change past its expiry as expired (in tx)
// and reports whether it did.
func expireIfDue(tx *gorm.DB, ws uuid.UUID, row *pendingChangeRow, now time.Time) (bool, error) {
	if row.State != PendingChangePending || now.Before(row.ExpiresAt) {
		return false, nil
	}
	return true, tx.Exec(`UPDATE pending_change SET state = 'expired', updated_at = now() WHERE workspace_id = ? AND id = ?`,
		ws, row.ID).Error
}

// Approve applies a pending change as approver: approver must hold
// governance:approve now and must not be the requester.
func (s *PendingChangeService) Approve(ctx context.Context, ws, id, approver uuid.UUID) (PendingChangeView, PendingChangeView, error) {
	now := s.now().UTC()
	var before, after *pendingChangeRow
	var after2 func()
	expired := false
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readPendingChange(tx, ws, id, true); err != nil {
			return err
		}
		if err := CheckApprover(ctx, tx, ws, before.RequestedBy, approver); err != nil {
			return err
		}
		if expired, err = expireIfDue(tx, ws, before, now); err != nil || expired {
			return err
		}
		if before.State != PendingChangePending {
			return govConflict(GovCodeChangeNotPending, "Only a pending change can be approved.", map[string]any{"state": before.State})
		}
		apply := pendingChangeApplierFor(before.Kind)
		if apply == nil {
			return govConflict("change_kind_unknown", "This kind of change cannot be applied by this server.", map[string]any{"kind": before.Kind})
		}
		if after2, err = apply(tx, ws, before); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE pending_change SET state = 'applied', approved_by = ?, approved_at = ?, applied_at = ?,
			    updated_at = now() WHERE workspace_id = ? AND id = ? AND state = 'pending'`, approver, now, now, ws, id).Error; err != nil {
			return err
		}
		after, err = readPendingChange(tx, ws, id, false)
		return err
	})
	if err != nil {
		return PendingChangeView{}, PendingChangeView{}, err
	}
	if expired {
		return PendingChangeView{}, PendingChangeView{}, govConflict(GovCodeChangeExpired, "This change expired; request it again.", nil)
	}
	if after2 != nil {
		after2()
	}
	return before.view(), after.view(), nil
}

// Reject closes a pending change unapplied: a holder of governance:approve
// rejects it, or its requester withdraws it.
func (s *PendingChangeService) Reject(ctx context.Context, ws, id, actor uuid.UUID, reason string) (PendingChangeView, PendingChangeView, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > MaxPendingChangeReason {
		return PendingChangeView{}, PendingChangeView{}, GovBadParam("reason", "reason is too long.")
	}
	now := s.now().UTC()
	var before, after *pendingChangeRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readPendingChange(tx, ws, id, true); err != nil {
			return err
		}
		if err := CheckRejecter(ctx, tx, ws, before.RequestedBy, actor); err != nil {
			return err
		}
		if before.State != PendingChangePending {
			return govConflict(GovCodeChangeNotPending, "Only a pending change can be rejected.", map[string]any{"state": before.State})
		}
		if err := tx.Exec(`UPDATE pending_change SET state = 'rejected', rejected_by = ?, rejected_at = ?, decision_reason = ?,
			    updated_at = now() WHERE workspace_id = ? AND id = ? AND state = 'pending'`, actor, now, reason, ws, id).Error; err != nil {
			return err
		}
		after, err = readPendingChange(tx, ws, id, false)
		return err
	})
	if err != nil {
		return PendingChangeView{}, PendingChangeView{}, err
	}
	return before.view(), after.view(), nil
}
