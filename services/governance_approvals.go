package services

import (
	"context"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// One approvals inbox (SPEC-secops-backend-upgrade.md P3, W5) over the seven
// second-person mechanisms, each of which keeps its own table and its own
// approve / reject routes (second_person.go lists them):
//
//	GET  /api/iga/v1/approvals                    pending requests of every kind
//	GET  /api/iga/v1/approvals/reviews            break-glass changes whose review is due or overdue
//	POST /api/iga/v1/approvals/reviews/:kind/:id  record the review (a second person)
//
// Every statement runs under row-level security for the token's workspace;
// another workspace's request is never listed and its id is 404.
//
// RunBreakGlassReviewWorker raises one governance.review_overdue event (and
// one operator alert for the person who applied it) per break-glass change
// whose review is overdue, of every kind.

// Approval kinds (the inbox's "kind").
const (
	ApprovalKindPendingChange   = "pending_change"
	ApprovalKindRuleVersion     = "detection_rule_version"
	ApprovalKindSuppression     = "alert_suppression"
	ApprovalKindCoverageDeclare = "coverage_declaration"
	ApprovalKindAuditChange     = "audit_change"
	ApprovalKindAgentChange     = "agent_change"
	ApprovalKindHistoryChange   = "history_change"
)

// Events of the inbox and the worker.
const (
	GovCatSecondPerson         = "second_person"
	GovEventReviewOverdue      = "governance.review_overdue"
	GovEventBreakGlassReviewed = "governance.break_glass_reviewed"
	BreakGlassReviewInterval   = 15 * time.Minute
	breakGlassReviewWorkerName = "breakglass-review-worker"
	breakGlassReviewKillSwitch = "AUTHSEC_DISABLE_BREAKGLASS_REVIEW_WORKER"
)

func init() {
	GovEventVocabulary = append(GovEventVocabulary,
		GovEventKind{GovEventReviewOverdue, GovCatSecondPerson, "", "A break-glass change (applied alone by the workspace's only approver) was not reviewed by a second person within 24 hours."},
		GovEventKind{GovEventBreakGlassReviewed, GovCatSecondPerson, "", "A second person reviewed a break-glass change."},
	)
}

// approvalKindSpec says where a kind lives and how its rows read.
type approvalKindSpec struct {
	table string
	// pending selects the kind's open requests: kind, subkind, id, target,
	// reason, requested_by, requested_at, expires_at (ws, now bound).
	pending string
	// breakGlass selects the kind's unreviewed break-glass rows: kind,
	// subkind, id, target, reason, requested_by, requested_at, review_due_at
	// (ws bound).
	breakGlass string
	// requester is the requester's column.
	requester string
	approve   string // route of the kind's own approve (and reject) under /api/iga/v1
	reject    string
}

var approvalKinds = map[string]approvalKindSpec{
	ApprovalKindPendingChange: {
		table: "pending_change", requester: "requested_by",
		pending: `SELECT 'pending_change' AS kind, kind AS subkind, id, target_ref AS target, reason, requested_by, requested_at, expires_at
		            FROM pending_change WHERE workspace_id = ? AND state = 'pending' AND expires_at > ?`,
		breakGlass: `SELECT 'pending_change' AS kind, kind AS subkind, id, target_ref AS target, reason, requested_by, requested_at, review_due_at
		               FROM pending_change WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/pending-changes/%s/approve", reject: "/pending-changes/%s/reject",
	},
	ApprovalKindRuleVersion: {
		table: "agent_detection_rule_version", requester: "proposed_by",
		pending: `SELECT 'detection_rule_version' AS kind, 'rule_change' AS subkind, id, 'alert-settings v' || version_no AS target,
		                 reason, proposed_by AS requested_by, proposed_at AS requested_at, NULL::timestamptz AS expires_at
		            FROM agent_detection_rule_version WHERE workspace_id = ? AND state = 'proposed' AND ?::timestamptz IS NOT NULL`,
		breakGlass: `SELECT 'detection_rule_version' AS kind, 'rule_change' AS subkind, id, 'alert-settings v' || version_no AS target,
		                    reason, proposed_by AS requested_by, proposed_at AS requested_at, review_due_at
		               FROM agent_detection_rule_version WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/agent-runtime/alert-settings/versions/%s/approve", reject: "/agent-runtime/alert-settings/versions/%s/reject",
	},
	ApprovalKindSuppression: {
		table: "agent_alert_suppression", requester: "requested_by",
		pending: `SELECT 'alert_suppression' AS kind, CASE WHEN renewal_of IS NULL THEN 'suppression' ELSE 'renewal' END AS subkind, id,
		                 identity_id::text || '/' || detection AS target, reason, requested_by, requested_at, NULL::timestamptz AS expires_at
		            FROM agent_alert_suppression WHERE workspace_id = ? AND state = 'proposed' AND ?::timestamptz IS NOT NULL`,
		breakGlass: `SELECT 'alert_suppression' AS kind, CASE WHEN renewal_of IS NULL THEN 'suppression' ELSE 'renewal' END AS subkind, id,
		                    identity_id::text || '/' || detection AS target, reason, requested_by, requested_at, review_due_at
		               FROM agent_alert_suppression WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/agent-runtime/suppressions/%s/approve", reject: "/agent-runtime/suppressions/%s/reject",
	},
	ApprovalKindCoverageDeclare: {
		table: "agent_capability_declaration", requester: "requested_by",
		pending: `SELECT 'coverage_declaration' AS kind, 'gap_declaration' AS subkind, id, capability_state_id::text AS target, reason,
		                 requested_by, requested_at, NULL::timestamptz AS expires_at
		            FROM agent_capability_declaration WHERE workspace_id = ? AND state = 'pending' AND ?::timestamptz IS NOT NULL`,
		breakGlass: `SELECT 'coverage_declaration' AS kind, 'gap_declaration' AS subkind, id, capability_state_id::text AS target, reason,
		                    requested_by, requested_at, review_due_at
		               FROM agent_capability_declaration WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/coverage/declarations/%s/approve", reject: "/coverage/declarations/%s/reject",
	},
	ApprovalKindAuditChange: {
		table: "audit_governance_change", requester: "requested_by",
		pending: `SELECT 'audit_change' AS kind, kind AS subkind, id, target, reason, requested_by, requested_at, expires_at
		            FROM audit_governance_change WHERE workspace_id = ? AND status = 'pending' AND expires_at > ?`,
		breakGlass: `SELECT 'audit_change' AS kind, kind AS subkind, id, target, reason, requested_by, requested_at, review_due_at
		               FROM audit_governance_change WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/audit/changes/%s/approve", reject: "/audit/changes/%s/reject",
	},
	ApprovalKindAgentChange: {
		table: "agent_pending_change", requester: "requested_by",
		pending: `SELECT 'agent_change' AS kind, kind AS subkind, id, subject_id::text AS target, reason, requested_by, requested_at,
		                 NULL::timestamptz AS expires_at
		            FROM agent_pending_change WHERE workspace_id = ? AND state = 'pending' AND ?::timestamptz IS NOT NULL`,
		breakGlass: `SELECT 'agent_change' AS kind, kind AS subkind, id, subject_id::text AS target, reason, requested_by, requested_at, review_due_at
		               FROM agent_pending_change WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/agent-changes/%s/approve", reject: "/agent-changes/%s/reject",
	},
	ApprovalKindHistoryChange: {
		table: "iga_history_approval", requester: "requested_by",
		pending: `SELECT 'history_change' AS kind, action AS subkind, id, COALESCE(subject_id::text, '') AS target, reason, requested_by,
		                 requested_at, expires_at
		            FROM iga_history_approval WHERE workspace_id = ? AND state = 'pending' AND expires_at > ?`,
		breakGlass: `SELECT 'history_change' AS kind, action AS subkind, id, COALESCE(subject_id::text, '') AS target, reason, requested_by,
		                    requested_at, review_due_at
		               FROM iga_history_approval WHERE workspace_id = ? AND break_glass AND reviewed_at IS NULL AND review_due_at IS NOT NULL`,
		approve: "/history-approvals/%s/approve", reject: "/history-approvals/%s/reject",
	},
}

// approvalKindOrder is the order kinds are read in (stable output).
var approvalKindOrder = []string{ApprovalKindPendingChange, ApprovalKindRuleVersion, ApprovalKindSuppression,
	ApprovalKindCoverageDeclare, ApprovalKindAuditChange, ApprovalKindAgentChange, ApprovalKindHistoryChange}

// ApprovalKinds lists the inbox's kinds.
func ApprovalKinds() []string { return append([]string(nil), approvalKindOrder...) }

const approvalsBase = "/api/iga/v1"

func approvalLink(pattern string, id uuid.UUID) string {
	return approvalsBase + strings.Replace(pattern, "%s", id.String(), 1)
}

// ApprovalReviewLink is the shared review route of a break-glass item.
func ApprovalReviewLink(kind string, id uuid.UUID) string {
	return approvalsBase + "/approvals/reviews/" + kind + "/" + id.String()
}

// ApprovalLinks are the routes that act on an item.
type ApprovalLinks struct {
	Approve string `json:"approve,omitempty"`
	Reject  string `json:"reject,omitempty"`
	Review  string `json:"review,omitempty"`
}

// ApprovalItem is a pending second-person request in the inbox.
type ApprovalItem struct {
	Kind        string        `json:"kind"`
	Subkind     string        `json:"subkind"`
	ID          uuid.UUID     `json:"id"`
	Target      string        `json:"target"`
	Reason      string        `json:"reason"`
	RequestedBy *uuid.UUID    `json:"requested_by"`
	RequestedAt time.Time     `json:"requested_at"`
	ExpiresAt   *time.Time    `json:"expires_at"`
	Links       ApprovalLinks `json:"links"`
}

// BreakGlassReviewItem is a break-glass change awaiting its review.
type BreakGlassReviewItem struct {
	Kind        string        `json:"kind"`
	Subkind     string        `json:"subkind"`
	ID          uuid.UUID     `json:"id"`
	Target      string        `json:"target"`
	Reason      string        `json:"reason"`
	RequestedBy *uuid.UUID    `json:"requested_by"`
	RequestedAt time.Time     `json:"requested_at"`
	ReviewDueAt time.Time     `json:"review_due_at"`
	Overdue     bool          `json:"overdue"`
	Links       ApprovalLinks `json:"links"`
}

type approvalRow struct {
	Kind        string
	Subkind     string
	ID          uuid.UUID
	Target      string
	Reason      string
	RequestedBy *uuid.UUID
	RequestedAt time.Time
	ExpiresAt   *time.Time
	ReviewDueAt *time.Time
}

// ApprovalsService reads the inbox and records reviews.
type ApprovalsService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewApprovalsService builds the service.
func NewApprovalsService(db *gorm.DB) *ApprovalsService {
	return &ApprovalsService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *ApprovalsService) WithClock(now func() time.Time) *ApprovalsService {
	s.now = now
	return s
}

func approvalKindFilter(kind string) ([]string, error) {
	if kind == "" {
		return approvalKindOrder, nil
	}
	if _, ok := approvalKinds[kind]; !ok {
		return nil, GovBadParam("kind", "kind must be one of "+strings.Join(approvalKindOrder, ", ")+".")
	}
	return []string{kind}, nil
}

// Pending lists ws's open second-person requests of every kind (or one),
// oldest first: what a holder of governance:approve has to decide.
// Requests past their expiry are not listed (they can no longer be approved).
func (s *ApprovalsService) Pending(ctx context.Context, ws uuid.UUID, kind string) ([]ApprovalItem, error) {
	kinds, err := approvalKindFilter(kind)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var rows []approvalRow
	err = tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		for _, k := range kinds {
			var part []approvalRow
			if err := tx.Raw(approvalKinds[k].pending, ws, now).Scan(&part).Error; err != nil {
				return err
			}
			rows = append(rows, part...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].RequestedAt.Before(rows[j].RequestedAt) })
	out := make([]ApprovalItem, 0, len(rows))
	for _, r := range rows {
		spec := approvalKinds[r.Kind]
		out = append(out, ApprovalItem{Kind: r.Kind, Subkind: r.Subkind, ID: r.ID, Target: r.Target, Reason: r.Reason,
			RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt.UTC(), ExpiresAt: utcPtr(r.ExpiresAt),
			Links: ApprovalLinks{Approve: approvalLink(spec.approve, r.ID), Reject: approvalLink(spec.reject, r.ID)}})
	}
	return out, nil
}

func (s *ApprovalsService) breakGlassRows(tx *gorm.DB, ws uuid.UUID, kinds []string) ([]approvalRow, error) {
	var rows []approvalRow
	for _, k := range kinds {
		var part []approvalRow
		if err := tx.Raw(approvalKinds[k].breakGlass, ws).Scan(&part).Error; err != nil {
			return nil, err
		}
		rows = append(rows, part...)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ReviewDueAt.Before(*rows[j].ReviewDueAt) })
	return rows, nil
}

// Reviews lists ws's break-glass changes not yet reviewed, earliest due
// first; overdueOnly keeps those past their due time.
func (s *ApprovalsService) Reviews(ctx context.Context, ws uuid.UUID, kind string, overdueOnly bool) ([]BreakGlassReviewItem, error) {
	kinds, err := approvalKindFilter(kind)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	var rows []approvalRow
	err = tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		rows, err = s.breakGlassRows(tx, ws, kinds)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]BreakGlassReviewItem, 0, len(rows))
	for _, r := range rows {
		overdue := r.ReviewDueAt.Before(now)
		if overdueOnly && !overdue {
			continue
		}
		out = append(out, BreakGlassReviewItem{Kind: r.Kind, Subkind: r.Subkind, ID: r.ID, Target: r.Target, Reason: r.Reason,
			RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt.UTC(), ReviewDueAt: r.ReviewDueAt.UTC(), Overdue: overdue,
			Links: ApprovalLinks{Review: ApprovalReviewLink(r.Kind, r.ID)}})
	}
	return out, nil
}

// ReviewKindHasOwnRoute reports whether a kind's break-glass review is
// recorded by its own service (coverage, audit, history), which the shared
// route delegates to.
func ReviewKindHasOwnRoute(kind string) bool {
	switch kind {
	case ApprovalKindCoverageDeclare, ApprovalKindAuditChange, ApprovalKindHistoryChange:
		return true
	}
	return false
}

// IsApprovalKind reports whether kind is one of the inbox's kinds.
func IsApprovalKind(kind string) bool {
	_, ok := approvalKinds[kind]
	return ok
}

// ReviewBreakGlass records a second person's review of a break-glass change
// of a kind that has no review route of its own (pending_change,
// detection_rule_version, alert_suppression, agent_change). The reviewer
// passes CheckApprover; another workspace's id is 404.
func (s *ApprovalsService) ReviewBreakGlass(ctx context.Context, ws uuid.UUID, kind string, id, reviewer uuid.UUID, note string) (*BreakGlassReviewItem, error) {
	spec, ok := approvalKinds[kind]
	if !ok || ReviewKindHasOwnRoute(kind) {
		return nil, GovNotFound()
	}
	note = strings.TrimSpace(note)
	if len(note) > 1000 {
		return nil, GovBadParam("note", "note must be at most 1000 characters.")
	}
	now := s.now().UTC()
	var out *BreakGlassReviewItem
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var cur []struct {
			BreakGlass  bool
			ReviewedAt  *time.Time
			RequestedBy *uuid.UUID
			IdentityID  *uuid.UUID
		}
		identity := "NULL::uuid"
		if kind == ApprovalKindSuppression {
			identity = "identity_id"
		}
		// The table and columns come from approvalKinds, never the request.
		if err := tx.Raw(`SELECT break_glass, reviewed_at, `+spec.requester+` AS requested_by, `+identity+` AS identity_id
		                    FROM `+spec.table+` WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&cur).Error; err != nil {
			return err
		}
		if len(cur) == 0 {
			return GovNotFound()
		}
		c := cur[0]
		if !c.BreakGlass {
			return govConflict(GovCodeNotBreakGlass, "Only a break-glass change is reviewed after the fact.", nil)
		}
		if c.ReviewedAt != nil {
			return govConflict("already_reviewed", "The change was already reviewed.", nil)
		}
		var opts []SecondPersonOption
		if c.IdentityID != nil {
			opts = append(opts, ConcerningIdentities(*c.IdentityID))
		}
		if err := CheckApprover(ctx, tx, ws, uuidOrNil(c.RequestedBy), reviewer, opts...); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE `+spec.table+` SET reviewed_by = ?, reviewed_at = ? WHERE workspace_id = ? AND id = ?`,
			reviewer, now, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventBreakGlassReviewed, models.GovActorUser, reviewer.String(), govEventRefs{},
			map[string]any{"kind": kind, "item_id": id, "requested_by": c.RequestedBy, "note": note}); err != nil {
			return err
		}
		rows, err := s.breakGlassRowsAll(tx, ws, kind, id)
		if err != nil {
			return err
		}
		out = &BreakGlassReviewItem{Kind: kind, ID: id, RequestedBy: c.RequestedBy}
		if len(rows) == 1 {
			r := rows[0]
			out.Subkind, out.Target, out.Reason, out.RequestedAt = r.Subkind, r.Target, r.Reason, r.RequestedAt.UTC()
			if r.ReviewDueAt != nil {
				out.ReviewDueAt = r.ReviewDueAt.UTC()
				out.Overdue = r.ReviewDueAt.Before(now)
			}
		}
		return nil
	})
	return out, err
}

// breakGlassRowsAll reads one break-glass row whatever its review state.
func (s *ApprovalsService) breakGlassRowsAll(tx *gorm.DB, ws uuid.UUID, kind string, id uuid.UUID) ([]approvalRow, error) {
	q := strings.Replace(approvalKinds[kind].breakGlass, "reviewed_at IS NULL", "id = ?", 1)
	var rows []approvalRow
	return rows, tx.Raw(q, ws, id).Scan(&rows).Error
}

/* ------------------------------------------------------------------------- */
/*                               Overdue reviews                              */
/* ------------------------------------------------------------------------- */

// RaiseOverdueReviews raises, for every break-glass change of ws whose
// review is overdue and was not raised before, one governance.review_overdue
// event and one operator alert (metric review_overdue) for the person who
// applied it. It returns the items raised.
func RaiseOverdueReviews(ctx context.Context, db *gorm.DB, ws uuid.UUID, now time.Time) ([]BreakGlassReviewItem, error) {
	s := NewApprovalsService(db)
	now = now.UTC()
	var raised []BreakGlassReviewItem
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		rows, err := s.breakGlassRows(tx, ws, approvalKindOrder)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.ReviewDueAt == nil || !r.ReviewDueAt.Before(now) {
				continue
			}
			var ins []uuid.UUID
			if err := tx.Raw(`INSERT INTO governance_review_overdue (workspace_id, kind, item_id, requested_by, review_due_at, raised_at)
			                  VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING item_id`,
				ws, r.Kind, r.ID, r.RequestedBy, *r.ReviewDueAt, now).Scan(&ins).Error; err != nil {
				return err
			}
			if len(ins) == 0 {
				continue
			}
			link := ApprovalReviewLink(r.Kind, r.ID)
			if err := appendGovEvent(tx, ws, GovEventReviewOverdue, models.GovActorSystem, breakGlassReviewWorkerName, govEventRefs{},
				map[string]any{"kind": r.Kind, "subkind": r.Subkind, "item_id": r.ID, "target": r.Target,
					"requested_by": r.RequestedBy, "requested_at": r.RequestedAt.UTC(), "review_due_at": r.ReviewDueAt.UTC(),
					"review_link": link}); err != nil {
				return err
			}
			if r.RequestedBy != nil {
				if err := tx.Exec(`INSERT INTO operator_alert (workspace_id, user_id, hour, metric, observed, baseline_p95, threshold)
				                   VALUES (?, ?, date_trunc('hour', ?::timestamptz), 'review_overdue', 1, 0, 0)
				                   ON CONFLICT (workspace_id, user_id, hour, metric) DO NOTHING`,
					ws, r.RequestedBy.String(), r.ReviewDueAt.UTC()).Error; err != nil {
					return err
				}
			}
			log.Printf("[second-person] ALERT workspace=%s %s %s applied alone by %v: review overdue since %s",
				ws, r.Kind, r.ID, r.RequestedBy, r.ReviewDueAt.UTC().Format(time.RFC3339))
			raised = append(raised, BreakGlassReviewItem{Kind: r.Kind, Subkind: r.Subkind, ID: r.ID, Target: r.Target,
				Reason: r.Reason, RequestedBy: r.RequestedBy, RequestedAt: r.RequestedAt.UTC(), ReviewDueAt: r.ReviewDueAt.UTC(),
				Overdue: true, Links: ApprovalLinks{Review: link}})
		}
		return nil
	})
	return raised, err
}

// RunBreakGlassReviewWorker raises overdue break-glass reviews in every
// workspace every BreakGlassReviewInterval until ctx ends
// (AUTHSEC_DISABLE_BREAKGLASS_REVIEW_WORKER=true turns it off).
func RunBreakGlassReviewWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv(breakGlassReviewKillSwitch) == "true" {
		log.Printf("[second-person] break-glass review worker not started: %s=true", breakGlassReviewKillSwitch)
		return
	}
	for {
		var wss []uuid.UUID
		// TENANT-EXEMPT: the worker runs across workspaces (no request tenant) and lists workspace ids only; each workspace is read and written in its own workspace-bound transaction (tenancy.InWorkspace).
		if err := db.WithContext(ctx).Raw(`SELECT id FROM workspaces ORDER BY id`).Scan(&wss).Error; err != nil && ctx.Err() == nil {
			log.Printf("[second-person] list workspaces: %v", err)
		}
		for _, ws := range wss {
			if ctx.Err() != nil {
				return
			}
			if _, err := RaiseOverdueReviews(ctx, db, ws, time.Now()); err != nil {
				log.Printf("[second-person] overdue reviews of workspace %s: %v", ws, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(BreakGlassReviewInterval):
		}
	}
}

// ApprovalKindError is the error a route answers for an unknown kind (404).
func ApprovalKindError() error { return govErr(http.StatusNotFound, "not_found", "Not found.", nil) }
