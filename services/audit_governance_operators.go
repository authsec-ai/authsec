package services

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Operator governance (P18): the per-operator audit view, the hourly
// baseline and out-of-pattern alerts, suspension, and the list of an
// operator's reversible decisions (never reversed automatically).

/* --------------------------------- events --------------------------------- */

// AuditEventFilter narrows GET /audit/events.
type AuditEventFilter struct {
	Actor  string
	Action string
	From   *time.Time
	To     *time.Time
}

// AuditEventView is one audit_events row as the operator view serves it.
type AuditEventView struct {
	ID          int64     `json:"id"`
	Seq         *int64    `json:"seq,omitempty"`
	Hash        *string   `json:"hash,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	RequestID   string    `json:"request_id"`
	ActorRealm  string    `json:"actor_realm"`
	UserID      string    `json:"user_id"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	ResourceID  string    `json:"resource_id"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	StatusCode  *int64    `json:"status_code,omitempty"`
	ClientIP    string    `json:"client_ip"`
	RecordClass *string   `json:"record_class,omitempty"`
	OldValues   JSONText  `json:"old_values,omitempty"`
	NewValues   JSONText  `json:"new_values,omitempty"`
	Error       string    `json:"error,omitempty"`
}

const auditEventViewCols = `id, seq, hash, COALESCE("timestamp", created_at) AS timestamp, COALESCE(request_id, '') AS request_id,
	COALESCE(actor_realm, '') AS actor_realm, COALESCE(user_id, '') AS user_id, COALESCE(action, '') AS action,
	COALESCE(resource, '') AS resource, COALESCE(resource_id, '') AS resource_id, COALESCE(method, '') AS method,
	COALESCE(path, '') AS path, status_code, COALESCE(client_ip, '') AS client_ip, record_class,
	old_values::text AS old_values, new_values::text AS new_values, COALESCE(error, '') AS error`

// Events lists the workspace's audit events, newest first, filtered by
// operator (actor), action and time; cursor is the last id of the previous
// page. Another workspace's operator matches nothing.
func (s *AuditGovService) Events(ctx context.Context, ws uuid.UUID, f AuditEventFilter, cursor string, limit int) ([]AuditEventView, string, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = 50
	}
	where := `workspace_id = ?`
	args := []any{ws.String()}
	if f.Actor != "" {
		where += ` AND user_id = ?`
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.From != nil {
		where += ` AND "timestamp" >= ?`
		args = append(args, *f.From)
	}
	if f.To != nil {
		where += ` AND "timestamp" < ?`
		args = append(args, *f.To)
	}
	if cursor != "" {
		id, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || id <= 0 {
			return nil, "", GovBadParam("cursor", "cursor is not valid.")
		}
		where += ` AND id < ?`
		args = append(args, id)
	}
	args = append(args, limit+1)
	var rows []AuditEventView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+auditEventViewCols+` FROM audit_events WHERE `+where+` ORDER BY id DESC LIMIT ?`, args...).Scan(&rows).Error
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = strconv.FormatInt(rows[limit-1].ID, 10)
	}
	if rows == nil {
		rows = []AuditEventView{}
	}
	return rows, next, nil
}

/* ------------------------------ tiers (P3) ------------------------------- */

// OperatorActionTier is the provisional tier of an audited console write,
// from its action and method, until W5's static action -> tier map lands:
// 3 = loosening (settings, suppressions, releases, unsuspensions, retention,
// disabling or deleting a control, bulk exports), 2 = side effects beyond a
// stop (approvals, grants, rotations, emergency acts, suspensions), 1 for
// other writes, 0 for reads.
func OperatorActionTier(action, method string) int {
	a := strings.ToLower(action)
	for _, k := range []string{"settings_update", "suppress", "release", "unsuspend", "retention", "disable",
		"siem_endpoint_delete", "tool_policy.delete", "exception", "break_glass", "export"} {
		if strings.Contains(a, k) {
			return 3
		}
	}
	for _, k := range []string{"approve", "grant", "assignment_created", "rotate", "emergency", "suspend", "contain",
		"credential_created", "otlp_token_create"} {
		if strings.Contains(a, k) {
			return 2
		}
	}
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return 1
	}
	if a != "" {
		return 1
	}
	return 0
}

func isExport(action, resource string) bool {
	return strings.Contains(strings.ToLower(action), "export") || strings.Contains(strings.ToLower(resource), "export")
}

/* -------------------------------- baseline -------------------------------- */

const (
	operatorBaselineWindow = 14 * 24 * time.Hour
	operatorRecentHours    = 3
	operatorMinThreshold   = 10
	operatorFactor         = 3.0
)

// OperatorAlert is an out-of-pattern hour.
type OperatorAlert struct {
	ID          uuid.UUID `json:"id"`
	UserID      string    `json:"user_id"`
	Hour        time.Time `json:"hour"`
	Metric      string    `json:"metric"`
	Observed    int       `json:"observed"`
	BaselineP95 float64   `json:"baseline_p95"`
	Threshold   int       `json:"threshold"`
	CreatedAt   time.Time `json:"created_at"`
}

type operatorHour struct {
	UserID   string
	Hour     time.Time
	Writes   int
	Elevated int
	Exports  int
}

// p95 of the hourly values over the window (missing hours are zero).
func hourlyP95(values []int, hours int) float64 {
	if hours <= 0 {
		return 0
	}
	all := make([]int, hours)
	copy(all, values)
	sort.Ints(all)
	idx := int(math.Ceil(0.95*float64(hours))) - 1
	if idx < 0 {
		idx = 0
	}
	return float64(all[idx])
}

// OperatorThreshold is max(10, 3 x p95), rounded up.
func OperatorThreshold(p95 float64) int {
	t := int(math.Ceil(operatorFactor * p95))
	if t < operatorMinThreshold {
		t = operatorMinThreshold
	}
	return t
}

// BaselineWorkspace counts each operator's writes, elevated (tier 2/3)
// writes and exports per hour for the last completed hours (the last 14
// days on a workspace's first run) and raises an alert, with a governance
// event, for each count in the last 3 hours above max(10, 3 x the
// operator's trailing 14-day hourly p95). It returns the alerts raised.
// Reads are not counted: audit_events records writes only.
func (s *AuditGovService) BaselineWorkspace(ctx context.Context, ws uuid.UUID) ([]OperatorAlert, error) {
	now := s.now().UTC()
	end := now.Truncate(time.Hour) // the current hour is not complete
	var raised []OperatorAlert
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var seen int64
		if err := tx.Raw(`SELECT count(*) FROM operator_activity_hour WHERE workspace_id = ?`, ws).Scan(&seen).Error; err != nil {
			return err
		}
		start := end.Add(-operatorRecentHours * time.Hour)
		if seen == 0 {
			start = end.Add(-operatorBaselineWindow)
		}
		var raw []struct {
			UserID   string
			Hour     time.Time
			Action   string
			Resource string
			Method   string
			N        int
		}
		if err := tx.Raw(`SELECT user_id, date_trunc('hour', "timestamp") AS hour, COALESCE(action, '') AS action,
		                         COALESCE(resource, '') AS resource, COALESCE(method, '') AS method, count(*) AS n
		                    FROM audit_events
		                   WHERE workspace_id = ? AND "timestamp" >= ? AND "timestamp" < ?
		                     AND COALESCE(user_id, '') NOT IN ('', 'system')
		                   GROUP BY 1, 2, 3, 4, 5`, ws.String(), start, end).Scan(&raw).Error; err != nil {
			return err
		}
		agg := map[string]*operatorHour{}
		for _, r := range raw {
			k := r.UserID + "|" + r.Hour.UTC().Format(time.RFC3339)
			h := agg[k]
			if h == nil {
				h = &operatorHour{UserID: r.UserID, Hour: r.Hour.UTC()}
				agg[k] = h
			}
			tier := OperatorActionTier(r.Action, r.Method)
			if tier >= 1 {
				h.Writes += r.N
			}
			if tier >= 2 {
				h.Elevated += r.N
			}
			if isExport(r.Action, r.Resource) {
				h.Exports += r.N
			}
		}
		keys := make([]string, 0, len(agg))
		for k := range agg {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h := agg[k]
			if err := tx.Exec(`INSERT INTO operator_activity_hour (workspace_id, user_id, hour, writes, elevated, exports, computed_at)
			                   VALUES (?, ?, ?, ?, ?, ?, now())
			                   ON CONFLICT (workspace_id, user_id, hour) DO UPDATE SET writes = EXCLUDED.writes,
			                       elevated = EXCLUDED.elevated, exports = EXCLUDED.exports, computed_at = now()`,
				ws, h.UserID, h.Hour, h.Writes, h.Elevated, h.Exports).Error; err != nil {
				return err
			}
		}
		recent := end.Add(-operatorRecentHours * time.Hour)
		for _, k := range keys {
			h := agg[k]
			if h.Hour.Before(recent) {
				continue
			}
			var hist []operatorHour
			if err := tx.Raw(`SELECT user_id, hour, writes, elevated, exports FROM operator_activity_hour
			                  WHERE workspace_id = ? AND user_id = ? AND hour >= ? AND hour < ?`,
				ws, h.UserID, h.Hour.Add(-operatorBaselineWindow), h.Hour).Scan(&hist).Error; err != nil {
				return err
			}
			hours := int(operatorBaselineWindow / time.Hour)
			for _, m := range []struct {
				name     string
				observed int
				pick     func(operatorHour) int
			}{
				{"writes", h.Writes, func(x operatorHour) int { return x.Writes }},
				{"elevated", h.Elevated, func(x operatorHour) int { return x.Elevated }},
				{"exports", h.Exports, func(x operatorHour) int { return x.Exports }},
			} {
				vals := make([]int, 0, len(hist))
				for _, x := range hist {
					vals = append(vals, m.pick(x))
				}
				p95 := hourlyP95(vals, hours)
				thr := OperatorThreshold(p95)
				if m.observed <= thr {
					continue
				}
				var got []OperatorAlert
				if err := tx.Raw(`INSERT INTO operator_alert (workspace_id, user_id, hour, metric, observed, baseline_p95, threshold)
				                  VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (workspace_id, user_id, hour, metric) DO NOTHING
				                  RETURNING id, user_id, hour, metric, observed, baseline_p95, threshold, created_at`,
					ws, h.UserID, h.Hour, m.name, m.observed, p95, thr).Scan(&got).Error; err != nil {
					return err
				}
				if len(got) == 0 {
					continue
				}
				raised = append(raised, got[0])
				if err := appendGovEvent(tx, ws, GovEventOperatorOutOfPattern, models.GovActorSystem, "", govEventRefs{},
					map[string]any{"operator_id": h.UserID, "hour": h.Hour, "metric": m.name, "observed": m.observed,
						"baseline_p95": p95, "threshold": thr}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return raised, err
}

// OperatorAlerts lists the workspace's out-of-pattern alerts, newest first.
func (s *AuditGovService) OperatorAlerts(ctx context.Context, ws uuid.UUID, actor string) ([]OperatorAlert, error) {
	var out []OperatorAlert
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT id, user_id, hour, metric, observed, baseline_p95, threshold, created_at FROM operator_alert WHERE workspace_id = ?`
		args := []any{ws}
		if actor != "" {
			q += ` AND user_id = ?`
			args = append(args, actor)
		}
		return tx.Raw(q+` ORDER BY created_at DESC LIMIT 500`, args...).Scan(&out).Error
	})
	if out == nil {
		out = []OperatorAlert{}
	}
	return out, err
}

/* -------------------------------- decisions ------------------------------- */

// OperatorDecision is one of an operator's audited writes with how it would
// be reversed. Nothing is reversed automatically: a person performs the
// reversal through the route it names.
type OperatorDecision struct {
	AuditEventView
	Tier       int    `json:"tier"`
	Reversible bool   `json:"reversible"`
	Reversal   string `json:"reversal"`
}

// reversalOf describes how to undo an audited write.
func reversalOf(e AuditEventView) (bool, string) {
	a := strings.ToLower(e.Action)
	hasOld := e.OldValues != "" && e.OldValues != "null"
	switch {
	case strings.Contains(a, "revoke") || strings.Contains(a, "rotate") || strings.Contains(a, "token_create") ||
		strings.Contains(a, "credential_created"):
		return false, "A credential issued or revoked is not restored: issue a new one (and revoke the issued one) instead."
	case strings.Contains(a, "retention_purged"):
		return false, "Purged audit events cannot be restored (the chain records the gap)."
	case strings.Contains(a, "approve") || strings.Contains(a, "approved") || strings.Contains(a, "grant") ||
		strings.Contains(a, "assignment_created"):
		return true, "Revoke what was granted: remove " + e.Resource + " " + e.ResourceID + "."
	case strings.Contains(a, "suspend") && !strings.Contains(a, "unsuspend"):
		return true, "Request an unsuspension (POST /authsec/admin/operators/" + e.ResourceID + "/unsuspend; a second person approves)."
	case strings.Contains(a, "legal_hold_placed"):
		return true, "Request the hold's release (tier 3, a second person approves)."
	}
	switch strings.ToUpper(e.Method) {
	case "DELETE":
		if hasOld {
			return true, "Recreate " + e.Resource + " " + e.ResourceID + " from old_values."
		}
		return false, "The deleted " + e.Resource + " was not recorded (no old_values); it cannot be rebuilt from the audit."
	case "PUT", "PATCH":
		if hasOld {
			return true, "Restore " + e.Resource + " " + e.ResourceID + " to old_values."
		}
		return false, "The previous value was not recorded (no old_values)."
	case "POST":
		if e.ResourceID != "" {
			return true, "Delete or disable the " + e.Resource + " it created or changed (" + e.ResourceID + "), or restore old_values."
		}
	}
	return false, "No reversal is known for this action."
}

// OperatorDecisions lists the operator's audited writes in [from, to) with
// their reversal. The operator must be a member (or a home user) of the
// workspace; any other id is 404.
func (s *AuditGovService) OperatorDecisions(ctx context.Context, ws, user uuid.UUID, from, to time.Time) ([]OperatorDecision, error) {
	if !to.After(from) {
		return nil, GovBadParam("to", "to must be after from.")
	}
	var rows []AuditEventView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		ok, err := workspaceOperatorExists(tx, ws, user)
		if err != nil {
			return err
		}
		if !ok {
			return GovNotFound()
		}
		return tx.Raw(`SELECT `+auditEventViewCols+` FROM audit_events
		               WHERE workspace_id = ? AND user_id = ? AND "timestamp" >= ? AND "timestamp" < ?
		                 AND upper(COALESCE(method, '')) IN ('POST', 'PUT', 'PATCH', 'DELETE')
		                 AND (status_code IS NULL OR status_code < 400)
		               ORDER BY "timestamp", id LIMIT 2000`, ws.String(), user.String(), from, to).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]OperatorDecision, 0, len(rows))
	for _, r := range rows {
		rev, how := reversalOf(r)
		out = append(out, OperatorDecision{AuditEventView: r, Tier: OperatorActionTier(r.Action, r.Method), Reversible: rev, Reversal: how})
	}
	return out, nil
}

func workspaceOperatorExists(tx *gorm.DB, ws, user uuid.UUID) (bool, error) {
	var n int64
	err := tx.Raw(`SELECT (SELECT count(*) FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?)
	                    + (SELECT count(*) FROM users WHERE workspace_id = ? AND id = ? AND deleted_at IS NULL)`,
		ws, user, ws, user).Scan(&n).Error
	return n > 0, err
}

/* ------------------------------- suspension ------------------------------- */

// Gov error codes of suspension.
const (
	GovCodeCannotSuspendSelf = "cannot_suspend_self"
	GovCodeAlreadySuspended  = "already_suspended"
	GovCodeNotSuspended      = "not_suspended"
)

// OperatorSuspension is a suspension.
type OperatorSuspension struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	Mechanism    string     `json:"mechanism"`
	MembershipID *uuid.UUID `json:"membership_id,omitempty"`
	Reason       string     `json:"reason"`
	SuspendedBy  uuid.UUID  `json:"suspended_by"`
	SuspendedAt  time.Time  `json:"suspended_at"`
	LiftedAt     *time.Time `json:"lifted_at,omitempty"`
	LiftedBy     *uuid.UUID `json:"lifted_by,omitempty"`
}

const suspensionCols = `id, user_id, mechanism, membership_id, reason, suspended_by, suspended_at, lifted_at, lifted_by`

// Suspend suspends an operator in the workspace (governance:emergency): the
// membership becomes 'suspended' (or, for a home user with no membership
// row, the user is deactivated). AuthMiddleware re-checks membership on
// every request, so the operator's next request fails.
func (s *AuditGovService) Suspend(ctx context.Context, ws uuid.UUID, a AuditActor, user uuid.UUID, reason string) (*OperatorSuspension, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return nil, GovBadParam("reason", "A suspension needs a reason (at most 1000 characters).")
	}
	if user == a.UserID {
		return nil, govConflict(GovCodeCannotSuspendSelf, "An operator cannot suspend themselves.", nil)
	}
	var out OperatorSuspension
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var mem []struct {
			ID     uuid.UUID
			Status string
		}
		if err := tx.Raw(`SELECT id, status FROM workspace_memberships WHERE workspace_id = ? AND user_id = ? FOR UPDATE`, ws, user).
			Scan(&mem).Error; err != nil {
			return err
		}
		mechanism := "membership"
		var membershipID *uuid.UUID
		if len(mem) == 1 {
			if mem[0].Status == "suspended" {
				return govConflict(GovCodeAlreadySuspended, "The operator is already suspended.", nil)
			}
			if mem[0].Status != "active" {
				return govConflict(GovCodeNotSuspended, "The membership is "+mem[0].Status+", not active.", nil)
			}
			if err := tx.Exec(`UPDATE workspace_memberships SET status = 'suspended', updated_at = now() WHERE workspace_id = ? AND id = ?`,
				ws, mem[0].ID).Error; err != nil {
				return err
			}
			id := mem[0].ID
			membershipID = &id
		} else {
			res := tx.Exec(`UPDATE users SET active = false, updated_at = now()
			                WHERE workspace_id = ? AND id = ? AND deleted_at IS NULL AND COALESCE(active, true)`, ws, user)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return GovNotFound()
			}
			mechanism = "user"
		}
		if err := tx.Raw(`INSERT INTO operator_suspension (workspace_id, user_id, mechanism, membership_id, reason, suspended_by)
		                  VALUES (?, ?, ?, ?, ?, ?) RETURNING `+suspensionCols,
			ws, user, mechanism, membershipID, reason, a.UserID).Scan(&out).Error; err != nil {
			if strings.Contains(err.Error(), "uq_operator_suspension_live") {
				return govConflict(GovCodeAlreadySuspended, "The operator is already suspended.", nil)
			}
			return err
		}
		if err := writeAudit(tx, ws, a, "operator.suspend", "operator", user.String(), http.StatusOK, nil, out); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventOperatorSuspended, models.GovActorUser, a.UserID.String(), govEventRefs{},
			map[string]any{"operator_id": user, "suspension_id": out.ID, "mechanism": mechanism})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RequestUnsuspend asks for a suspension to be lifted (tier 3: a second
// person with governance:approve applies it; break-glass when nobody else
// holds it). The suspended operator never counts as the second person.
func (s *AuditGovService) RequestUnsuspend(ctx context.Context, ws uuid.UUID, a AuditActor, user uuid.UUID, reason string, breakGlass bool) (*AuditChangeResult, error) {
	var out AuditChangeResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM operator_suspension WHERE workspace_id = ? AND user_id = ? AND lifted_at IS NULL`, ws, user).
			Scan(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			ok, err := workspaceOperatorExists(tx, ws, user)
			if err != nil {
				return err
			}
			if !ok {
				return GovNotFound()
			}
			return govConflict(GovCodeNotSuspended, "The operator is not suspended.", nil)
		}
		ch, err := s.requestChange(tx, ws, a, AuditChangeUnsuspend, user.String(), map[string]any{"operator_id": user}, reason, breakGlass, user)
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

// liftSuspension applies an operator_unsuspend change.
func liftSuspension(tx *gorm.DB, ws uuid.UUID, a AuditActor, ch *AuditChangeView) error {
	user, err := uuid.Parse(ch.Target)
	if err != nil {
		return err
	}
	var sus []OperatorSuspension
	if err := tx.Raw(`SELECT `+suspensionCols+` FROM operator_suspension WHERE workspace_id = ? AND user_id = ? AND lifted_at IS NULL FOR UPDATE`,
		ws, user).Scan(&sus).Error; err != nil {
		return err
	}
	if len(sus) == 0 {
		return govConflict(GovCodeNotSuspended, "The operator is no longer suspended.", nil)
	}
	sp := sus[0]
	if sp.Mechanism == "membership" && sp.MembershipID != nil {
		if err := tx.Exec(`UPDATE workspace_memberships SET status = 'active', updated_at = now()
		                   WHERE workspace_id = ? AND id = ? AND status = 'suspended'`, ws, *sp.MembershipID).Error; err != nil {
			return err
		}
	} else {
		if err := tx.Exec(`UPDATE users SET active = true, updated_at = now() WHERE workspace_id = ? AND id = ?`, ws, user).Error; err != nil {
			return err
		}
	}
	if err := tx.Exec(`UPDATE operator_suspension SET lifted_at = now(), lifted_by = ?, lift_change_id = ? WHERE workspace_id = ? AND id = ?`,
		a.UserID, ch.ID, ws, sp.ID).Error; err != nil {
		return err
	}
	if err := writeAudit(tx, ws, a, "operator.unsuspend", "operator", user.String(), http.StatusOK, nil,
		map[string]any{"suspension_id": sp.ID, "change_id": ch.ID}); err != nil {
		return err
	}
	return appendGovEvent(tx, ws, GovEventOperatorUnsuspended, models.GovActorUser, a.UserID.String(), govEventRefs{},
		map[string]any{"operator_id": user, "suspension_id": sp.ID, "change_id": ch.ID})
}

// Suspensions lists the workspace's suspensions, live first.
func (s *AuditGovService) Suspensions(ctx context.Context, ws uuid.UUID) ([]OperatorSuspension, error) {
	var out []OperatorSuspension
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+suspensionCols+` FROM operator_suspension WHERE workspace_id = ?
		               ORDER BY lifted_at IS NOT NULL, suspended_at DESC LIMIT 500`, ws).Scan(&out).Error
	})
	if out == nil {
		out = []OperatorSuspension{}
	}
	return out, err
}
