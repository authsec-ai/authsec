package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
)

// Audit governance (SPEC-secops-backend-upgrade.md F7 and P18 / W5, AS-177;
// migrations 167-169):
//
//   - retention per workspace and record class (audit_retention_policy),
//     legal holds (audit_legal_hold), and the per-workspace retention purge
//     that replaces the old cross-workspace 90-day DELETE
//     (audit_governance_chain.go);
//   - the hash chain: anchors, gaps and verification
//     (audit_governance_chain.go, internal/auditchain);
//   - tier-3 changes that need a second person (audit_governance_change):
//     shortening a retention, releasing a hold, lifting a suspension;
//   - operator governance: the per-operator audit view, the hourly operator
//     baseline and its out-of-pattern alerts, suspension, and the read-only
//     list of an operator's reversible decisions (audit_governance_operators.go).
//
// Every statement runs in a transaction under row-level security for one
// workspace (tenancy.InWorkspace / InWorkspaceRead / RLSTransaction); the
// only exceptions are the jobs' listings of chains and the platform chain
// (audit events with no workspace), each marked TENANT-EXEMPT.

// Event names (iga_gov_event, category audit_governance).
const (
	GovEventAuditRetentionChanged   = "audit.retention_changed"
	GovEventAuditChangeRequested    = "audit.change_requested"
	GovEventAuditChangeApplied      = "audit.change_applied"
	GovEventAuditChangeRejected     = "audit.change_rejected"
	GovEventAuditBreakGlass         = "audit.break_glass_applied"
	GovEventAuditBreakGlassReviewed = "audit.break_glass_reviewed"
	GovEventAuditLegalHoldPlaced    = "audit.legal_hold_placed"
	GovEventAuditAnchored           = "audit.anchored"
	GovEventAuditRetentionPurged    = "audit.retention_purged"
	GovEventAuditWriteFailed        = "audit.write_failed"
	GovEventOperatorOutOfPattern    = "operator.out_of_pattern"
	GovEventOperatorSuspended       = "operator.suspended"
	GovEventOperatorUnsuspended     = "operator.unsuspended"
)

// Retention bounds (DECISION 5: 90 d / 1 y / 7 y, configurable per workspace).
const (
	MinAuditRetentionDays = 7
	MaxAuditRetentionDays = 2557
)

// DefaultAuditRetentionDays is the retention of a record class a workspace
// has not set: 90 days, 365 for admin changes, access decisions and exports
// (the records an investigation of an operator needs a year later).
var DefaultAuditRetentionDays = map[string]int{
	monitoring.AuditClassAdminChange:    365,
	monitoring.AuditClassAuth:           90,
	monitoring.AuditClassAccessDecision: 365,
	monitoring.AuditClassExport:         365,
	monitoring.AuditClassDefault:        90,
}

// Change kinds and states (audit_governance_change).
const (
	AuditChangeRetentionShorten = "retention_shorten"
	AuditChangeHoldRelease      = "legal_hold_release"
	AuditChangeUnsuspend        = "operator_unsuspend"

	auditChangeTTL      = 7 * 24 * time.Hour
	auditBreakGlassDue  = SecondPersonReviewWindow
	auditSystemActor    = "system"
	auditRealmSystem    = "system"
	auditRealmAdmin     = "admin"
	auditResourceChange = "audit_governance_change"
)

// AuditGovService is the audit governance service.
type AuditGovService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAuditGovService builds the service over db.
func NewAuditGovService(db *gorm.DB) *AuditGovService {
	return &AuditGovService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *AuditGovService) WithClock(now func() time.Time) *AuditGovService {
	s.now = now
	return s
}

// RequireAuditGovernance is nil once migrations 167-169 are in place, else a
// 503 naming what is missing. It reads the Postgres catalog only.
func RequireAuditGovernance(db *gorm.DB) error {
	var missing []string
	// TENANT-EXEMPT: reads the Postgres catalog only.
	if err := db.Raw(`SELECT t FROM unnest(ARRAY['audit_chain_anchor','audit_chain_gap','audit_write_failure',
	        'audit_retention_policy','audit_legal_hold','audit_governance_change',
	        'operator_activity_hour','operator_alert','operator_suspension']) t
	        WHERE to_regclass('public.' || t) IS NULL`).Scan(&missing).Error; err != nil {
		return err
	}
	if len(missing) > 0 {
		return govErr(http.StatusServiceUnavailable, "audit_governance_unavailable",
			"Audit governance needs migrations 167-169.", map[string]any{"missing": missing})
	}
	return nil
}

// AuditActor is who makes a request (for the audit row written in the
// change's own transaction).
type AuditActor struct {
	UserID    uuid.UUID
	RequestID string
	Method    string
	Path      string
	ClientIP  string
	UserAgent string
}

// writeAudit writes the audit_events row of a change in tx (the change's own
// transaction: the change and its audit record commit together).
func writeAudit(tx *gorm.DB, ws uuid.UUID, a AuditActor, action, resource, resourceID string, status int, oldV, newV any) error {
	ev := &monitoring.AuditEvent{RequestID: a.RequestID, WorkspaceID: ws.String(), ActorRealm: auditRealmAdmin,
		UserID: a.UserID.String(), Action: action, Resource: resource, ResourceID: resourceID,
		Method: a.Method, Path: a.Path, ClientIP: a.ClientIP, UserAgent: a.UserAgent, StatusCode: status}
	if a.UserID == uuid.Nil {
		ev.UserID, ev.ActorRealm = auditSystemActor, auditRealmSystem
	}
	if oldV != nil {
		if raw, err := json.Marshal(oldV); err == nil {
			s := string(raw)
			ev.OldValues = &s
		}
	}
	if newV != nil {
		if raw, err := json.Marshal(newV); err == nil {
			s := string(raw)
			ev.NewValues = &s
		}
	}
	return monitoring.WriteAuditTx(tx, ev)
}

/* -------------------------------- retention -------------------------------- */

// AuditRetentionView is one record class's retention in a workspace.
type AuditRetentionView struct {
	RecordClass     string     `json:"record_class"`
	RetainDays      int        `json:"retain_days"`
	DefaultDays     int        `json:"default_days"`
	Source          string     `json:"source"` // "default" or "workspace"
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
	PendingChangeID *uuid.UUID `json:"pending_change_id,omitempty"`
}

type auditPolicyRow struct {
	RecordClass string
	RetainDays  int
	UpdatedAt   time.Time
	UpdatedBy   *uuid.UUID
}

// readAuditRetention is the workspace's retention per class (defaults filled).
func readAuditRetention(tx *gorm.DB, ws uuid.UUID) (map[string]int, []auditPolicyRow, error) {
	var rows []auditPolicyRow
	if err := tx.Raw(`SELECT record_class, retain_days, updated_at, updated_by FROM audit_retention_policy WHERE workspace_id = ?`, ws).
		Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	out := map[string]int{}
	for k, v := range DefaultAuditRetentionDays {
		out[k] = v
	}
	for _, r := range rows {
		out[r.RecordClass] = r.RetainDays
	}
	return out, rows, nil
}

// Retention lists every record class with its retention.
func (s *AuditGovService) Retention(ctx context.Context, ws uuid.UUID) ([]AuditRetentionView, error) {
	var out []AuditRetentionView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		days, rows, err := readAuditRetention(tx, ws)
		if err != nil {
			return err
		}
		byClass := map[string]auditPolicyRow{}
		for _, r := range rows {
			byClass[r.RecordClass] = r
		}
		var pending []struct {
			ID     uuid.UUID
			Target string
		}
		if err := tx.Raw(`SELECT id, target FROM audit_governance_change WHERE workspace_id = ? AND kind = ? AND status = 'pending'`,
			ws, AuditChangeRetentionShorten).Scan(&pending).Error; err != nil {
			return err
		}
		for _, c := range monitoring.AuditRecordClasses {
			v := AuditRetentionView{RecordClass: c, RetainDays: days[c], DefaultDays: DefaultAuditRetentionDays[c], Source: "default"}
			if r, ok := byClass[c]; ok {
				t := r.UpdatedAt
				v.Source, v.UpdatedAt, v.UpdatedBy = "workspace", &t, r.UpdatedBy
			}
			for _, p := range pending {
				if p.Target == c {
					id := p.ID
					v.PendingChangeID = &id
				}
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

func validAuditClass(c string) bool {
	for _, x := range monitoring.AuditRecordClasses {
		if x == c {
			return true
		}
	}
	return false
}

// AuditChangeResult is the outcome of a request that may need a second
// person: Applied (at once: tightening, or break-glass) or a pending Change.
type AuditChangeResult struct {
	Applied bool                `json:"applied"`
	Change  *AuditChangeView    `json:"change,omitempty"`
	Policy  *AuditRetentionView `json:"retention,omitempty"`
}

// SetRetention sets a record class's retention. The same or a longer period
// applies at once; a shorter one is tier 3: a pending change that a second
// person with governance:approve applies, or break-glass when nobody else in
// the workspace holds governance:approve.
func (s *AuditGovService) SetRetention(ctx context.Context, ws uuid.UUID, a AuditActor, class string, days int, reason string, breakGlass bool) (*AuditChangeResult, error) {
	if !validAuditClass(class) {
		return nil, GovBadParam("record_class", "record_class must be one of "+strings.Join(monitoring.AuditRecordClasses, ", ")+".")
	}
	if days < MinAuditRetentionDays || days > MaxAuditRetentionDays {
		return nil, GovBadParam("retain_days", fmt.Sprintf("retain_days must be between %d and %d.", MinAuditRetentionDays, MaxAuditRetentionDays))
	}
	var out AuditChangeResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, _, err := readAuditRetention(tx, ws)
		if err != nil {
			return err
		}
		if days >= cur[class] {
			if err := upsertAuditRetention(tx, ws, class, days, a.UserID, nil); err != nil {
				return err
			}
			if err := writeAudit(tx, ws, a, "audit.retention_set", "audit_retention_policy", class, http.StatusOK,
				map[string]any{"retain_days": cur[class]}, map[string]any{"retain_days": days}); err != nil {
				return err
			}
			out.Applied = true
			out.Policy = &AuditRetentionView{RecordClass: class, RetainDays: days, DefaultDays: DefaultAuditRetentionDays[class], Source: "workspace"}
			return appendGovEvent(tx, ws, GovEventAuditRetentionChanged, models.GovActorUser, a.UserID.String(), govEventRefs{},
				map[string]any{"record_class": class, "from_days": cur[class], "to_days": days})
		}
		ch, err := s.requestChange(ctx, tx, ws, a, AuditChangeRetentionShorten, class,
			map[string]any{"record_class": class, "from_days": cur[class], "to_days": days}, reason, breakGlass, uuid.Nil)
		if err != nil {
			return err
		}
		out.Change, out.Applied = ch, ch.Status == "applied"
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func upsertAuditRetention(tx *gorm.DB, ws uuid.UUID, class string, days int, by uuid.UUID, change *uuid.UUID) error {
	return tx.Exec(`INSERT INTO audit_retention_policy (workspace_id, record_class, retain_days, updated_by, change_id, updated_at)
	                VALUES (?, ?, ?, ?, ?, now())
	                ON CONFLICT (workspace_id, record_class) DO UPDATE SET retain_days = EXCLUDED.retain_days,
	                    updated_by = EXCLUDED.updated_by, change_id = EXCLUDED.change_id, updated_at = now()`,
		ws, class, days, by, change).Error
}

/* ------------------------------- legal holds ------------------------------- */

// AuditLegalHold is a hold on a window of audit events.
type AuditLegalHold struct {
	ID          uuid.UUID  `json:"id"`
	FromTS      time.Time  `json:"from"`
	ToTS        time.Time  `json:"to"`
	Reason      string     `json:"reason"`
	CreatedBy   uuid.UUID  `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ReleasedAt  *time.Time `json:"released_at,omitempty"`
	ReleasedBy  *uuid.UUID `json:"released_by,omitempty"`
	ReleaseChID *uuid.UUID `json:"release_change_id,omitempty" gorm:"column:release_change_id"`
}

const auditHoldCols = `id, from_ts, to_ts, reason, created_by, created_at, released_at, released_by, release_change_id`

// LegalHolds lists the workspace's holds, live first.
func (s *AuditGovService) LegalHolds(ctx context.Context, ws uuid.UUID) ([]AuditLegalHold, error) {
	var out []AuditLegalHold
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+auditHoldCols+` FROM audit_legal_hold WHERE workspace_id = ?
		               ORDER BY released_at IS NOT NULL, created_at DESC`, ws).Scan(&out).Error
	})
	return out, err
}

// PlaceLegalHold holds [from, to) of the workspace's audit events (tightening:
// applied at once).
func (s *AuditGovService) PlaceLegalHold(ctx context.Context, ws uuid.UUID, a AuditActor, from, to time.Time, reason string) (*AuditLegalHold, error) {
	if !to.After(from) {
		return nil, GovBadParam("to", "to must be after from.")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return nil, GovBadParam("reason", "A legal hold needs a reason (at most 1000 characters).")
	}
	var h AuditLegalHold
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Raw(`INSERT INTO audit_legal_hold (workspace_id, from_ts, to_ts, reason, created_by)
		                  VALUES (?, ?, ?, ?, ?) RETURNING `+auditHoldCols, ws, from.UTC(), to.UTC(), reason, a.UserID).Scan(&h).Error; err != nil {
			return err
		}
		if err := writeAudit(tx, ws, a, "audit.legal_hold_placed", "audit_legal_hold", h.ID.String(), http.StatusCreated, nil, h); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventAuditLegalHoldPlaced, models.GovActorUser, a.UserID.String(), govEventRefs{},
			map[string]any{"hold_id": h.ID, "from": h.FromTS, "to": h.ToTS})
	})
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// RequestLegalHoldRelease asks for a hold to be released (tier 3).
func (s *AuditGovService) RequestLegalHoldRelease(ctx context.Context, ws uuid.UUID, a AuditActor, id uuid.UUID, reason string, breakGlass bool) (*AuditChangeResult, error) {
	var out AuditChangeResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM audit_legal_hold WHERE workspace_id = ? AND id = ? AND released_at IS NULL`, ws, id).
			Scan(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return GovNotFound()
		}
		ch, err := s.requestChange(ctx, tx, ws, a, AuditChangeHoldRelease, id.String(), map[string]any{"hold_id": id}, reason, breakGlass, uuid.Nil)
		if err != nil {
			return err
		}
		out.Change, out.Applied = ch, ch.Status == "applied"
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

/* ----------------------------- second person ------------------------------ */

// AuditChangeView is a tier-3 change.
type AuditChangeView struct {
	ID             uuid.UUID  `json:"id"`
	Kind           string     `json:"kind"`
	Target         string     `json:"target"`
	Payload        JSONText   `json:"payload"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status"`
	RequestedBy    uuid.UUID  `json:"requested_by"`
	RequestedAt    time.Time  `json:"requested_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	DecidedBy      *uuid.UUID `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecisionReason *string    `json:"decision_reason,omitempty"`
	BreakGlass     bool       `json:"break_glass"`
	ReviewDueAt    *time.Time `json:"review_due_at,omitempty"`
	ReviewedBy     *uuid.UUID `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
}

const auditChangeCols = `id, kind, target, payload, reason, status, requested_by, requested_at, expires_at, decided_by, decided_at,
	decision_reason, break_glass, review_due_at, reviewed_by, reviewed_at`

// Gov error codes of second-person changes (change_pending, change_not_pending
// and change_expired are shared with pending_change.go).
const (
	GovCodeSecondPersonAvailable = "second_person_available"
	GovCodeNotBreakGlass         = "not_break_glass"
)

// requestChange records a tier-3 change: pending (a second person applies
// it) or, with breakGlass and nobody else holding governance:approve,
// applied now with a review due within 24 hours (DECISION 4). subject is a
// user the change is about who cannot count as the second person (the
// suspended operator), or uuid.Nil.
func (s *AuditGovService) requestChange(ctx context.Context, tx *gorm.DB, ws uuid.UUID, a AuditActor, kind, target string, payload map[string]any,
	reason string, breakGlass bool, subject uuid.UUID) (*AuditChangeView, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return nil, GovBadParam("reason", "A tier-3 change needs a reason (at most 1000 characters).")
	}
	if err := CheckTier3Requester(ctx); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var pending int64
	if err := tx.Raw(`SELECT count(*) FROM audit_governance_change WHERE workspace_id = ? AND kind = ? AND target = ? AND status = 'pending'`,
		ws, kind, target).Scan(&pending).Error; err != nil {
		return nil, err
	}
	if pending > 0 {
		return nil, govConflict(GovCodeChangePending, "A change of this kind is already waiting for a second person.", nil)
	}
	var ch AuditChangeView
	if breakGlass {
		if err := BreakGlassRefusal(ctx, tx, ws, a.UserID, ExcludingUsers(subject)); err != nil {
			return nil, err
		}
		due := ReviewDue(now)
		if err := tx.Raw(`INSERT INTO audit_governance_change (workspace_id, kind, target, payload, reason, status, requested_by,
		                     requested_at, expires_at, decided_by, decided_at, break_glass, review_due_at)
		                  VALUES (?, ?, ?, ?::jsonb, ?, 'applied', ?, ?, ?, ?, ?, true, ?) RETURNING `+auditChangeCols,
			ws, kind, target, string(raw), reason, a.UserID, now, now.Add(auditChangeTTL), a.UserID, now, due).Scan(&ch).Error; err != nil {
			return nil, err
		}
		if err := s.applyChange(tx, ws, a, &ch); err != nil {
			return nil, err
		}
		if err := writeAudit(tx, ws, a, "audit.break_glass_applied", auditResourceChange, ch.ID.String(), http.StatusOK, nil, ch); err != nil {
			return nil, err
		}
		if err := appendGovEvent(tx, ws, GovEventAuditBreakGlass, models.GovActorUser, a.UserID.String(), govEventRefs{},
			map[string]any{"change_id": ch.ID, "kind": kind, "target": target, "review_due_at": due}); err != nil {
			return nil, err
		}
		return &ch, nil
	}
	if err := tx.Raw(`INSERT INTO audit_governance_change (workspace_id, kind, target, payload, reason, requested_by, requested_at, expires_at)
	                  VALUES (?, ?, ?, ?::jsonb, ?, ?, ?, ?) RETURNING `+auditChangeCols,
		ws, kind, target, string(raw), reason, a.UserID, now, now.Add(auditChangeTTL)).Scan(&ch).Error; err != nil {
		return nil, err
	}
	if err := writeAudit(tx, ws, a, "audit.change_requested", auditResourceChange, ch.ID.String(), http.StatusAccepted, nil, ch); err != nil {
		return nil, err
	}
	if err := appendGovEvent(tx, ws, GovEventAuditChangeRequested, models.GovActorUser, a.UserID.String(), govEventRefs{},
		map[string]any{"change_id": ch.ID, "kind": kind, "target": target}); err != nil {
		return nil, err
	}
	return &ch, nil
}

// applyChange performs a change (pending approved, or break-glass).
func (s *AuditGovService) applyChange(tx *gorm.DB, ws uuid.UUID, a AuditActor, ch *AuditChangeView) error {
	var p map[string]any
	_ = json.Unmarshal([]byte(ch.Payload), &p)
	switch ch.Kind {
	case AuditChangeRetentionShorten:
		days, _ := p["to_days"].(float64)
		if days < MinAuditRetentionDays {
			return fmt.Errorf("audit change %s: bad to_days", ch.ID)
		}
		id := ch.ID
		return upsertAuditRetention(tx, ws, ch.Target, int(days), a.UserID, &id)
	case AuditChangeHoldRelease:
		res := tx.Exec(`UPDATE audit_legal_hold SET released_at = now(), released_by = ?, release_change_id = ?
		                WHERE workspace_id = ? AND id = ? AND released_at IS NULL`, a.UserID, ch.ID, ws, ch.Target)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return govConflict(GovCodeChangeNotPending, "The legal hold is already released.", nil)
		}
		return nil
	case AuditChangeUnsuspend:
		return liftSuspension(tx, ws, a, ch)
	}
	return fmt.Errorf("audit change %s: unknown kind %q", ch.ID, ch.Kind)
}

// Changes lists the workspace's tier-3 changes (status: pending, applied,
// rejected, withdrawn, expired, or "" for all), newest first.
func (s *AuditGovService) Changes(ctx context.Context, ws uuid.UUID, status string) ([]AuditChangeView, error) {
	switch status {
	case "", "pending", "applied", "rejected", "withdrawn", "expired", "review_due":
	default:
		return nil, GovBadParam("status", "status must be pending, applied, rejected, withdrawn, expired or review_due.")
	}
	var out []AuditChangeView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Raw(`SELECT `+auditChangeCols+` FROM audit_governance_change WHERE workspace_id = ? ORDER BY requested_at DESC LIMIT 500`, ws)
		switch status {
		case "review_due":
			q = tx.Raw(`SELECT `+auditChangeCols+` FROM audit_governance_change WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL
			            ORDER BY review_due_at LIMIT 500`, ws)
		case "":
		default:
			q = tx.Raw(`SELECT `+auditChangeCols+` FROM audit_governance_change WHERE workspace_id = ? AND status = ?
			            ORDER BY requested_at DESC LIMIT 500`, ws, status)
		}
		return q.Scan(&out).Error
	})
	return out, err
}

func loadAuditChange(tx *gorm.DB, ws, id uuid.UUID) (*AuditChangeView, error) {
	var rows []AuditChangeView
	if err := tx.Raw(`SELECT `+auditChangeCols+` FROM audit_governance_change WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// decideChange is approve (apply=true) or reject: the decider holds
// governance:approve now and is not the requester (403 self_approval).
func (s *AuditGovService) decideChange(ctx context.Context, ws uuid.UUID, a AuditActor, id uuid.UUID, apply bool, reason string) (*AuditChangeView, error) {
	var out *AuditChangeView
	var expired bool
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		ch, err := loadAuditChange(tx, ws, id)
		if err != nil {
			return err
		}
		if ch.Status != "pending" {
			return govConflict(GovCodeChangeNotPending, "The change is "+ch.Status+".", map[string]any{"status": ch.Status})
		}
		if err := CheckApprover(ctx, tx, ws, ch.RequestedBy, a.UserID, auditChangeSubjects(ch)...); err != nil {
			return err
		}
		now := s.now().UTC()
		if apply && now.After(ch.ExpiresAt) {
			expired = true
			return tx.Exec(`UPDATE audit_governance_change SET status = 'expired', decided_at = ? WHERE workspace_id = ? AND id = ?`, now, ws, id).Error
		}
		status, ev, action := "rejected", GovEventAuditChangeRejected, "audit.change_rejected"
		if apply {
			status, ev, action = "applied", GovEventAuditChangeApplied, "audit.change_applied"
		}
		var dr *string
		if r := strings.TrimSpace(reason); r != "" {
			dr = &r
		}
		if err := tx.Exec(`UPDATE audit_governance_change SET status = ?, decided_by = ?, decided_at = ?, decision_reason = ?
		                   WHERE workspace_id = ? AND id = ?`, status, a.UserID, now, dr, ws, id).Error; err != nil {
			return err
		}
		ch.Status, ch.DecidedBy, ch.DecidedAt, ch.DecisionReason = status, &a.UserID, &now, dr
		if apply {
			if err := s.applyChange(tx, ws, a, ch); err != nil {
				return err
			}
		}
		if err := writeAudit(tx, ws, a, action, auditResourceChange, id.String(), http.StatusOK, nil, ch); err != nil {
			return err
		}
		out = ch
		return appendGovEvent(tx, ws, ev, models.GovActorUser, a.UserID.String(), govEventRefs{},
			map[string]any{"change_id": id, "kind": ch.Kind, "target": ch.Target, "requested_by": ch.RequestedBy})
	})
	if err != nil {
		return nil, err
	}
	if expired {
		return nil, govConflict(GovCodeChangeExpired, "The change expired before it was approved; request it again.", nil)
	}
	return out, nil
}

// ApproveChange applies a pending change as its second person.
func (s *AuditGovService) ApproveChange(ctx context.Context, ws uuid.UUID, a AuditActor, id uuid.UUID, reason string) (*AuditChangeView, error) {
	return s.decideChange(ctx, ws, a, id, true, reason)
}

// RejectChange rejects a pending change.
func (s *AuditGovService) RejectChange(ctx context.Context, ws uuid.UUID, a AuditActor, id uuid.UUID, reason string) (*AuditChangeView, error) {
	return s.decideChange(ctx, ws, a, id, false, reason)
}

// ReviewBreakGlass records another person's review of a break-glass change.
func (s *AuditGovService) ReviewBreakGlass(ctx context.Context, ws uuid.UUID, a AuditActor, id uuid.UUID, note string) (*AuditChangeView, error) {
	var out *AuditChangeView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		ch, err := loadAuditChange(tx, ws, id)
		if err != nil {
			return err
		}
		if !ch.BreakGlass || ch.ReviewedAt != nil {
			return govConflict(GovCodeNotBreakGlass, "Only an unreviewed break-glass change can be reviewed.", nil)
		}
		if err := CheckApprover(ctx, tx, ws, ch.RequestedBy, a.UserID, auditChangeSubjects(ch)...); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := tx.Exec(`UPDATE audit_governance_change SET reviewed_by = ?, reviewed_at = ? WHERE workspace_id = ? AND id = ?`,
			a.UserID, now, ws, id).Error; err != nil {
			return err
		}
		ch.ReviewedBy, ch.ReviewedAt = &a.UserID, &now
		if err := writeAudit(tx, ws, a, "audit.break_glass_reviewed", auditResourceChange, id.String(), http.StatusOK, nil,
			map[string]any{"note": strings.TrimSpace(note)}); err != nil {
			return err
		}
		out = ch
		return appendGovEvent(tx, ws, GovEventAuditBreakGlassReviewed, models.GovActorUser, a.UserID.String(), govEventRefs{},
			map[string]any{"change_id": id, "kind": ch.Kind})
	})
	return out, err
}

// isGovError reports whether err is a *GovError with the code.
func isGovError(err error, code string) bool {
	var ge *GovError
	return errors.As(err, &ge) && ge.Code == code
}

// JSONText is a JSON column read as text (jsonb::text): served as the JSON
// it holds, or null when empty.
type JSONText string

// MarshalJSON emits the JSON itself.
func (j JSONText) MarshalJSON() ([]byte, error) {
	if j == "" {
		return []byte("null"), nil
	}
	return []byte(j), nil
}

// auditChangeSubjects names the user a change is about (the operator an
// unsuspension lifts): they never decide or review it.
func auditChangeSubjects(ch *AuditChangeView) []SecondPersonOption {
	if ch.Kind != AuditChangeUnsuspend {
		return nil
	}
	if u, err := uuid.Parse(ch.Target); err == nil {
		return []SecondPersonOption{ExcludingUsers(u)}
	}
	return nil
}
