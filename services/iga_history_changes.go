package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Legal holds, redaction, second-person changes and bulk exports of the
// history surface (SPEC-secops-backend-upgrade.md P3, P9 / W9; migrations
// 200, 201).
//
// Tiers (P3): placing a hold only keeps more, so it applies at once; releasing
// a hold, redacting a snapshot and a bulk export are tier 3 -- loosening --
// and need a second member holding governance:approve (iga_history_approval;
// the approver is never the requester, re-read from the database). In a
// workspace whose only holder of governance:approve is the requester,
// break_glass applies the change alone, is logged as an alert, and is due a
// review by another member within 24 hours (decision 4).

// History change actions.
const (
	HistoryActionHoldRelease    = "hold_release"
	HistoryActionSnapshotRedact = "snapshot_redact"
	HistoryActionBulkExport     = "bulk_export"
)

// historyApprovalTTL is how long a request waits for a second person.
const historyApprovalTTL = 7 * 24 * time.Hour

// historyBreakGlassReview is when a break-glass change must be reviewed.
const historyBreakGlassReview = SecondPersonReviewWindow

// historyExportTTL is how long an export's bytes are kept.
const historyExportTTL = 7 * 24 * time.Hour

// historyExportMaxItems bounds one export; a larger window is refused.
const historyExportMaxItems = 20000

// HistoryHold is one legal hold.
type HistoryHold struct {
	ID                uuid.UUID  `json:"id"`
	FromDate          time.Time  `json:"-"`
	ToDate            time.Time  `json:"-"`
	From              string     `json:"from" gorm:"-"`
	To                string     `json:"to" gorm:"-"`
	Kinds             []string   `json:"kinds" gorm:"-"`
	KindsText         string     `json:"-"`
	Reason            string     `json:"reason"`
	PlacedBy          uuid.UUID  `json:"placed_by"`
	PlacedAt          time.Time  `json:"placed_at"`
	ReleasedAt        *time.Time `json:"released_at"`
	ReleasedBy        *uuid.UUID `json:"released_by"`
	ReleaseApprovalID *uuid.UUID `json:"release_approval_id"`
}

const historyHoldColumns = `id, from_date, to_date, array_to_string(kinds, ',') AS kinds_text, reason, placed_by, placed_at,
	released_at, released_by, release_approval_id`

func (h *HistoryHold) fill() {
	h.From, h.To = h.FromDate.Format("2006-01-02"), h.ToDate.Format("2006-01-02")
	h.Kinds = strings.Split(h.KindsText, ",")
}

// HistoryApproval is one tier-3 request.
type HistoryApproval struct {
	ID             uuid.UUID       `json:"id"`
	Action         string          `json:"action"`
	SubjectID      *uuid.UUID      `json:"subject_id"`
	Params         json.RawMessage `json:"params"`
	ParamsHash     string          `json:"params_hash"`
	Reason         string          `json:"reason"`
	RequestedBy    uuid.UUID       `json:"requested_by"`
	RequestedAt    time.Time       `json:"requested_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	State          string          `json:"state"`
	BreakGlass     bool            `json:"break_glass"`
	DecidedBy      *uuid.UUID      `json:"decided_by"`
	DecidedAt      *time.Time      `json:"decided_at"`
	DecisionReason string          `json:"decision_reason"`
	ReviewDueAt    *time.Time      `json:"review_due_at"`
	ReviewedBy     *uuid.UUID      `json:"reviewed_by"`
	ReviewedAt     *time.Time      `json:"reviewed_at"`
	ReviewNote     string          `json:"review_note"`
	Result         json.RawMessage `json:"result"`
}

const historyApprovalColumns = `id, action, subject_id, params, params_hash, reason, requested_by, requested_at, expires_at, state,
	break_glass, decided_by, decided_at, decision_reason, review_due_at, reviewed_by, reviewed_at, review_note, result`

// HistoryChangeRequest asks for a tier-3 change.
type HistoryChangeRequest struct {
	Action     string
	SubjectID  *uuid.UUID
	Params     map[string]any
	Reason     string
	BreakGlass bool
}

/* ----------------------------------- holds ---------------------------------- */

// PlaceHold places a legal hold over [from, to] and kinds (all when empty).
func (s *HistoryService) PlaceHold(ctx context.Context, ws, actor uuid.UUID, from, to time.Time, kinds []string, reason string) (*HistoryHold, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return nil, GovBadParam("reason", "A reason of at most 1000 characters is required.")
	}
	from, to = dateOnly(from), dateOnly(to)
	if to.Before(from) {
		return nil, GovBadParam("to", "to must not be before from.")
	}
	if len(kinds) == 0 {
		kinds = SnapshotKinds
	}
	for _, k := range kinds {
		if !validSnapshotKind(k) {
			return nil, GovBadParam("kinds", "kinds must be among "+strings.Join(SnapshotKinds, ", ")+".")
		}
	}
	var out HistoryHold
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO iga_snapshot_hold (id, workspace_id, from_date, to_date, kinds, reason, placed_by, placed_at)
		                   VALUES (?, ?, ?, ?, string_to_array(?, ','), ?, ?, ?)`,
			id, ws, from, to, strings.Join(kinds, ","), reason, actor, s.now().UTC()).Error; err != nil {
			return err
		}
		if err := refreshHoldFlags(tx, ws); err != nil {
			return err
		}
		h, err := loadHold(tx, ws, id, false)
		if err != nil {
			return err
		}
		out = *h
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func loadHold(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*HistoryHold, error) {
	q := `SELECT ` + historyHoldColumns + ` FROM iga_snapshot_hold WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []HistoryHold
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	rows[0].fill()
	return &rows[0], nil
}

// ListHolds lists the workspace's holds, live first.
func (s *HistoryService) ListHolds(ctx context.Context, ws uuid.UUID) ([]HistoryHold, error) {
	var rows []HistoryHold
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+historyHoldColumns+` FROM iga_snapshot_hold WHERE workspace_id = ?
		                ORDER BY released_at IS NOT NULL, placed_at DESC LIMIT 500`, ws).Scan(&rows).Error
	})
	for i := range rows {
		rows[i].fill()
	}
	if rows == nil {
		rows = []HistoryHold{}
	}
	return rows, err
}

/* --------------------------------- requests --------------------------------- */

// RequestChange records a tier-3 request; with BreakGlass, in a workspace
// whose only approver is the requester, it applies it at once.
func (s *HistoryService) RequestChange(ctx context.Context, ws, actor uuid.UUID, req HistoryChangeRequest) (*HistoryApproval, error) {
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 1000 {
		return nil, GovBadParam("reason", "A reason of at most 1000 characters is required.")
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	if err := CheckTier3Requester(ctx); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var out *HistoryApproval
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := s.validateChange(tx, ws, req); err != nil {
			return err
		}
		canon, err := igagov.CanonicalizeValue(req.Params)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(canon)
		if req.BreakGlass {
			ok, err := BreakGlassAllowed(ctx, tx, ws, actor)
			if err != nil {
				return err
			}
			if !ok {
				return govConflict(GovCodeBreakGlassNotAllowed,
					"Break-glass is only for a workspace whose one holder of governance:approve is you; ask another approver instead.", nil)
			}
		}
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO iga_history_approval (id, workspace_id, action, subject_id, params, params_hash, reason, requested_by, requested_at, expires_at)
		                   VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?)`,
			id, ws, req.Action, req.SubjectID, string(canon), hex.EncodeToString(sum[:]), req.Reason, actor, now, now.Add(historyApprovalTTL)).Error; err != nil {
			if strings.Contains(err.Error(), "uq_iga_history_approval_pending") {
				return govConflict("change_pending", "A request for this change is already waiting for a second person.", nil)
			}
			return err
		}
		a, err := loadApproval(tx, ws, id, true)
		if err != nil {
			return err
		}
		if req.BreakGlass {
			result, err := s.applyChange(tx, ws, a, actor)
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(result)
			if err := tx.Exec(`UPDATE iga_history_approval SET state = 'applied', break_glass = true, decided_by = ?, decided_at = ?,
			                     decision_reason = 'break-glass: the only approver in the workspace', review_due_at = ?, result = ?::jsonb
			                   WHERE workspace_id = ? AND id = ?`,
				actor, now, ReviewDue(now), string(raw), ws, id).Error; err != nil {
				return err
			}
			log.Printf("[history] ALERT break-glass %s applied alone in workspace %s by %s (approval %s); review due within 24h",
				req.Action, ws, actor, id)
		}
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

func (s *HistoryService) validateChange(tx *gorm.DB, ws uuid.UUID, req HistoryChangeRequest) error {
	switch req.Action {
	case HistoryActionHoldRelease:
		if req.SubjectID == nil {
			return GovNotFound()
		}
		h, err := loadHold(tx, ws, *req.SubjectID, false)
		if err != nil {
			return err
		}
		if h.ReleasedAt != nil {
			return govConflict("hold_released", "The hold is already released.", nil)
		}
	case HistoryActionSnapshotRedact:
		if req.SubjectID == nil {
			return GovNotFound()
		}
		sn, err := loadSnapshot(tx, ws, *req.SubjectID, false)
		if err != nil {
			return err
		}
		if sn.Redacted {
			return govConflict("snapshot_redacted", "The snapshot is already redacted.", nil)
		}
		if sn.LegalHold {
			return govConflict("snapshot_held", "The snapshot is under a legal hold; release the hold first.", nil)
		}
	case HistoryActionBulkExport:
		if req.SubjectID != nil {
			return GovBadParam("subject_id", "A bulk export names no subject.")
		}
		if _, err := exportParams(req.Params); err != nil {
			return err
		}
	default:
		return GovBadParam("action", "Unknown change.")
	}
	return nil
}

func loadApproval(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*HistoryApproval, error) {
	q := `SELECT ` + historyApprovalColumns + ` FROM iga_history_approval WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []HistoryApproval
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func loadSnapshot(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*HistorySnapshot, error) {
	q := `SELECT ` + historySnapshotColumns + ` FROM iga_snapshot WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []HistorySnapshot
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	rows[0].fill()
	return &rows[0], nil
}

// Approve applies a pending request as a second person: never the
// requester, and holding governance:approve now.
func (s *HistoryService) Approve(ctx context.Context, ws, approver, id uuid.UUID, reason string) (*HistoryApproval, error) {
	now := s.now().UTC()
	var out *HistoryApproval
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		a, err := loadApproval(tx, ws, id, true)
		if err != nil {
			return err
		}
		if err := s.decidable(ctx, tx, ws, a, approver, now); err != nil {
			return err
		}
		result, err := s.applyChange(tx, ws, a, approver)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(result)
		if err := tx.Exec(`UPDATE iga_history_approval SET state = 'applied', decided_by = ?, decided_at = ?, decision_reason = ?, result = ?::jsonb
		                   WHERE workspace_id = ? AND id = ?`, approver, now, strings.TrimSpace(reason), string(raw), ws, id).Error; err != nil {
			return err
		}
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

// Reject closes a pending request without applying it (second person).
func (s *HistoryService) Reject(ctx context.Context, ws, approver, id uuid.UUID, reason string) (*HistoryApproval, error) {
	now := s.now().UTC()
	var out *HistoryApproval
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		a, err := loadApproval(tx, ws, id, true)
		if err != nil {
			return err
		}
		if err := s.decidable(ctx, tx, ws, a, approver, now); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_history_approval SET state = 'rejected', decided_by = ?, decided_at = ?, decision_reason = ?
		                   WHERE workspace_id = ? AND id = ?`, approver, now, strings.TrimSpace(reason), ws, id).Error; err != nil {
			return err
		}
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

// Withdraw closes the requester's own pending request.
func (s *HistoryService) Withdraw(ctx context.Context, ws, actor, id uuid.UUID) (*HistoryApproval, error) {
	now := s.now().UTC()
	var out *HistoryApproval
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		a, err := loadApproval(tx, ws, id, true)
		if err != nil {
			return err
		}
		if a.RequestedBy != actor {
			return GovForbidden("Only the requester can withdraw a request.")
		}
		if a.State != "pending" {
			return govConflict("invalid_state", "Only a pending request can be withdrawn.", map[string]any{"state": a.State})
		}
		if err := tx.Exec(`UPDATE iga_history_approval SET state = 'withdrawn', decided_at = ? WHERE workspace_id = ? AND id = ?`, now, ws, id).Error; err != nil {
			return err
		}
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

// Review records the after-the-fact review of a break-glass change by a
// member other than the requester who holds governance:approve.
func (s *HistoryService) Review(ctx context.Context, ws, reviewer, id uuid.UUID, note string) (*HistoryApproval, error) {
	now := s.now().UTC()
	var out *HistoryApproval
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		a, err := loadApproval(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !a.BreakGlass {
			return govConflict("not_break_glass", "Only a break-glass change is reviewed after the fact.", nil)
		}
		if a.ReviewedAt != nil {
			return govConflict("already_reviewed", "The change was already reviewed.", nil)
		}
		if err := CheckApprover(ctx, tx, ws, a.RequestedBy, reviewer); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_history_approval SET reviewed_by = ?, reviewed_at = ?, review_note = ? WHERE workspace_id = ? AND id = ?`,
			reviewer, now, strings.TrimSpace(note), ws, id).Error; err != nil {
			return err
		}
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

func (s *HistoryService) decidable(ctx context.Context, tx *gorm.DB, ws uuid.UUID, a *HistoryApproval, approver uuid.UUID, now time.Time) error {
	if a.State != "pending" {
		return govConflict("invalid_state", "Only a pending request can be decided.", map[string]any{"state": a.State})
	}
	if now.After(a.ExpiresAt) {
		return govConflict("request_expired", "The request expired; ask again.", nil)
	}
	return CheckApprover(ctx, tx, ws, a.RequestedBy, approver)
}

// ListApprovals lists requests; state filters, reviewDue keeps break-glass
// changes not yet reviewed.
func (s *HistoryService) ListApprovals(ctx context.Context, ws uuid.UUID, state string, reviewDue bool) ([]HistoryApproval, error) {
	var rows []HistoryApproval
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT ` + historyApprovalColumns + ` FROM iga_history_approval WHERE workspace_id = ?`
		args := []any{ws}
		if state != "" {
			q += ` AND state = ?`
			args = append(args, state)
		}
		if reviewDue {
			q += ` AND break_glass AND reviewed_at IS NULL`
		}
		q += ` ORDER BY requested_at DESC LIMIT 500`
		return tx.Raw(q, args...).Scan(&rows).Error
	})
	if rows == nil {
		rows = []HistoryApproval{}
	}
	return rows, err
}

// GetApproval returns one request.
func (s *HistoryService) GetApproval(ctx context.Context, ws, id uuid.UUID) (*HistoryApproval, error) {
	var out *HistoryApproval
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = loadApproval(tx, ws, id, false)
		return err
	})
	return out, err
}

/* ---------------------------------- apply ----------------------------------- */

func (s *HistoryService) applyChange(tx *gorm.DB, ws uuid.UUID, a *HistoryApproval, decider uuid.UUID) (map[string]any, error) {
	now := s.now().UTC()
	switch a.Action {
	case HistoryActionHoldRelease:
		h, err := loadHold(tx, ws, *a.SubjectID, true)
		if err != nil {
			return nil, err
		}
		if h.ReleasedAt != nil {
			return nil, govConflict("hold_released", "The hold is already released.", nil)
		}
		if err := tx.Exec(`UPDATE iga_snapshot_hold SET released_at = ?, released_by = ?, release_approval_id = ? WHERE workspace_id = ? AND id = ?`,
			now, a.RequestedBy, a.ID, ws, h.ID).Error; err != nil {
			return nil, err
		}
		if err := refreshHoldFlags(tx, ws); err != nil {
			return nil, err
		}
		return map[string]any{"hold_id": h.ID, "released_at": now}, nil
	case HistoryActionSnapshotRedact:
		sn, err := loadSnapshot(tx, ws, *a.SubjectID, true)
		if err != nil {
			return nil, err
		}
		if sn.Redacted {
			return nil, govConflict("snapshot_redacted", "The snapshot is already redacted.", nil)
		}
		if sn.LegalHold {
			return nil, govConflict("snapshot_held", "The snapshot is under a legal hold; release the hold first.", nil)
		}
		tomb, _ := json.Marshal(map[string]any{"redacted": true, "hash": sn.Hash, "reason": a.Reason,
			"redacted_at": now.Format(time.RFC3339), "approval_id": a.ID})
		if err := tx.Exec(`UPDATE iga_snapshot SET body = ?::jsonb, redacted = true, redacted_at = ?, redacted_by = ?, redaction_reason = ?
		                   WHERE workspace_id = ? AND id = ?`, string(tomb), now, a.RequestedBy, a.Reason, ws, sn.ID).Error; err != nil {
			return nil, err
		}
		return map[string]any{"snapshot_id": sn.ID, "hash": sn.Hash, "redacted_at": now}, nil
	case HistoryActionBulkExport:
		p, err := exportParams(json.RawMessage(a.Params))
		if err != nil {
			return nil, err
		}
		return s.buildExport(tx, ws, a, decider, p, now)
	}
	return nil, GovBadParam("action", "Unknown change.")
}

/* ---------------------------------- exports --------------------------------- */

// ExportParams is a bulk export's window and kinds.
type ExportParams struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Kinds []string  `json:"kinds"`
}

// exportParams validates params (a map from a request or stored JSON).
func exportParams(raw any) (ExportParams, error) {
	var b []byte
	switch v := raw.(type) {
	case json.RawMessage:
		b = v
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return ExportParams{}, err
		}
	}
	var p struct {
		From  string   `json:"from"`
		To    string   `json:"to"`
		Kinds []string `json:"kinds"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return ExportParams{}, GovBadParam("params", "params must be {from, to, kinds}.")
	}
	from, err := parseHistoryTime(p.From)
	if err != nil {
		return ExportParams{}, GovBadParam("from", "from must be a date or an RFC 3339 time.")
	}
	to, err := parseHistoryTime(p.To)
	if err != nil {
		return ExportParams{}, GovBadParam("to", "to must be a date or an RFC 3339 time.")
	}
	if !from.Before(to) || to.Sub(from) > 400*24*time.Hour {
		return ExportParams{}, GovBadParam("to", "The window must be non-empty and at most 400 days.")
	}
	kinds := p.Kinds
	if len(kinds) == 0 {
		kinds = PopulationKinds
	}
	for _, k := range kinds {
		if !validPopulationKind(k) && k != "snapshot_days" {
			return ExportParams{}, GovBadParam("kinds", "kinds must be among "+strings.Join(PopulationKinds, ", ")+", snapshot_days.")
		}
	}
	sort.Strings(kinds)
	return ExportParams{From: from, To: to, Kinds: kinds}, nil
}

// parseHistoryTime accepts YYYY-MM-DD (UTC midnight) or RFC 3339.
func parseHistoryTime(v string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	return t.UTC(), err
}

// HistoryExport is an export's metadata.
type HistoryExport struct {
	ID               uuid.UUID       `json:"id"`
	ApprovalID       uuid.UUID       `json:"approval_id"`
	RequestedBy      uuid.UUID       `json:"requested_by"`
	Params           json.RawMessage `json:"params"`
	SHA256           string          `json:"sha256" gorm:"column:sha256"`
	SizeBytes        int64           `json:"size_bytes"`
	ItemCount        int             `json:"item_count"`
	Available        bool            `json:"available"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	DownloadCount    int             `json:"download_count"`
	LastDownloadedAt *time.Time      `json:"last_downloaded_at"`
}

const historyExportColumns = `id, approval_id, requested_by, params, sha256, size_bytes, item_count, content IS NOT NULL AS available,
	created_at, expires_at, download_count, last_downloaded_at`

func (s *HistoryService) buildExport(tx *gorm.DB, ws uuid.UUID, a *HistoryApproval, decider uuid.UUID, p ExportParams, now time.Time) (map[string]any, error) {
	var items []PopulationItem
	var days []SnapshotDay
	for _, k := range p.Kinds {
		if k == "snapshot_days" {
			if err := tx.Raw(`SELECT snapshot_date, kinds, rows_written, content_hash, prev_chain_hash, chain_hash, purged, created_at
			                    FROM iga_snapshot_day WHERE workspace_id = ? AND snapshot_date >= ? AND snapshot_date < ? ORDER BY snapshot_date`,
				ws, dateOnly(p.From), p.To).Scan(&days).Error; err != nil {
				return nil, err
			}
			for i := range days {
				days[i].Date = days[i].SnapshotDate.Format("2006-01-02")
			}
			continue
		}
		rows, err := populationRows(tx, ws, newSchemaProbe(tx), []string{k}, p.From, p.To, nil, historyExportMaxItems+1, true)
		if err != nil {
			return nil, err
		}
		items = append(items, rows...)
		if len(items) > historyExportMaxItems {
			return nil, govUnprocessable("export_too_large",
				"The window holds more than 20000 records; export a shorter window or fewer kinds.", map[string]any{"limit": historyExportMaxItems})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if !items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].OccurredAt.Before(items[j].OccurredAt)
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].ID < items[j].ID
	})
	if items == nil {
		items = []PopulationItem{}
	}
	if days == nil {
		days = []SnapshotDay{}
	}
	exportID := uuid.New()
	bundle := map[string]any{
		"format":        "authsec.history-export/v1",
		"export_id":     exportID,
		"workspace_id":  ws,
		"approval_id":   a.ID,
		"requested_by":  a.RequestedBy,
		"approved_by":   decider,
		"break_glass":   decider == a.RequestedBy,
		"reason":        a.Reason,
		"generated_at":  now.Format(time.RFC3339Nano),
		"window":        map[string]any{"from": p.From, "to": p.To},
		"kinds":         p.Kinds,
		"items":         items,
		"snapshot_days": days,
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	params, _ := json.Marshal(map[string]any{"from": p.From, "to": p.To, "kinds": p.Kinds})
	if err := tx.Exec(`INSERT INTO iga_export (id, workspace_id, approval_id, requested_by, params, sha256, size_bytes, item_count, content, created_at, expires_at)
	                   VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?)`,
		exportID, ws, a.ID, a.RequestedBy, string(params), hash, len(body), len(items), body, now, now.Add(historyExportTTL)).Error; err != nil {
		return nil, err
	}
	return map[string]any{"export_id": exportID, "sha256": hash, "size_bytes": len(body), "item_count": len(items)}, nil
}

// ListExports lists the workspace's exports (metadata only).
func (s *HistoryService) ListExports(ctx context.Context, ws uuid.UUID) ([]HistoryExport, error) {
	var rows []HistoryExport
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+historyExportColumns+` FROM iga_export WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 200`, ws).Scan(&rows).Error
	})
	if rows == nil {
		rows = []HistoryExport{}
	}
	return rows, err
}

// DownloadExport returns an export's bytes to its requester or approver
// (anyone else: not found) and counts the download.
func (s *HistoryService) DownloadExport(ctx context.Context, ws, actor, id uuid.UUID) (*HistoryExport, []byte, error) {
	var meta HistoryExport
	var content []byte
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []struct {
			HistoryExport
			Content   []byte
			DecidedBy *uuid.UUID
		}
		if err := tx.Raw(`SELECT e.id, e.approval_id, e.requested_by, e.params, e.sha256, e.size_bytes, e.item_count, e.content IS NOT NULL AS available,
		                         e.created_at, e.expires_at, e.download_count, e.last_downloaded_at, e.content, a.decided_by
		                    FROM iga_export e JOIN iga_history_approval a ON a.workspace_id = e.workspace_id AND a.id = e.approval_id
		                   WHERE e.workspace_id = ? AND e.id = ? FOR UPDATE OF e`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		r := rows[0]
		if r.RequestedBy != actor && (r.DecidedBy == nil || *r.DecidedBy != actor) {
			return GovNotFound()
		}
		if r.Content == nil {
			return govErr(http.StatusGone, "export_expired", "The export's content has expired; its hash is kept.", map[string]any{"sha256": r.SHA256})
		}
		if err := tx.Exec(`UPDATE iga_export SET download_count = download_count + 1, last_downloaded_at = ? WHERE workspace_id = ? AND id = ?`,
			s.now().UTC(), ws, id).Error; err != nil {
			return err
		}
		meta, content = r.HistoryExport, r.Content
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &meta, content, nil
}
