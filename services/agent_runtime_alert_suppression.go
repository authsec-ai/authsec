package services

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Alert suppressions (SecOps P6; migration 166).
//
// A suppression names one agent identity (the alert's identity_id), one
// detection and, optionally, one instance digest, and keeps the matching NEW
// alerts from Slack and SIEM for at most 90 days. The alerts are still
// stored, with suppressed_by set (GET /alerts?suppressed=true lists them);
// they are not shown as open on the graph.
//
// Requesting and renewing are tier 3 (as rule changes,
// agent_runtime_alert_rules.go): a different member holding
// governance:approve approves; the workspace's only governance:approve
// holder applies alone as break-glass (review due within 24 hours). Ending
// a suppression early only tightens and applies at once.
//
// Renewals are counted per agent x rule: a suppression's renewals is the
// number of earlier suppressions of the same identity and detection that
// came into force, however they were requested (a new request does not
// reset the count).
//
// DECISION (P6, "never silence a succeeded harmful outcome"): CloudTrail
// says per event whether the call succeeded (errorCode) or was refused.
// D1-D4 and D7 fire only on a call that SUCCEEDED and record a harmful
// outcome (detect.HarmfulOnSuccess): a suppression may not name them (400
// suppression_not_allowed). D5 counts refused calls (attempts); D6 and D8
// flag unusual but permitted model use. As defence in depth the sink never
// suppresses a finding detect.SucceededHarm marks, and a suppressed alert
// extended by one is delivered after all ("agent_alert.unsuppressed").
//
// The instance digest narrows a suppression to one agent instance (P12).
// Alerts carry no instance digest in this build, so a suppression naming
// one matches nothing yet: it never widens.

// Suppression states (agent_alert_suppression.state).
const (
	AgentSuppressionProposed = "proposed"
	AgentSuppressionActive   = "active"
	AgentSuppressionRejected = "rejected"
	AgentSuppressionEnded    = "ended"
	AgentSuppressionExpired  = "expired"

	// AgentSuppressionMaxDays caps a suppression; AgentSuppressionDefaultDays
	// applies when a request names none.
	AgentSuppressionMaxDays     = 90
	AgentSuppressionDefaultDays = 30
)

// iga_gov_event names of suppressions (iga_gov_event_vocabulary.go).
const (
	GovEventAgentAlertSuppressionRequested  = "agent_alert.suppression_requested"
	GovEventAgentAlertSuppressionApproved   = "agent_alert.suppression_approved"
	GovEventAgentAlertSuppressionRejected   = "agent_alert.suppression_rejected"
	GovEventAgentAlertSuppressionBreakGlass = "agent_alert.suppression_break_glass"
	GovEventAgentAlertSuppressionEnded      = "agent_alert.suppression_ended"
	GovEventAgentAlertSuppressionExpired    = "agent_alert.suppression_expired"
	GovEventAgentAlertUnsuppressed          = "agent_alert.unsuppressed"
)

// Suppression error codes.
const (
	GovCodeSuppressionNotAllowed = "suppression_not_allowed"
	GovCodeSuppressionPending    = "suppression_pending"
	GovCodeSuppressionExists     = "suppression_exists"
)

var agentInstanceDigestRe = regexp.MustCompile(`^[A-Za-z0-9._:/+=-]{1,200}$`)

// AgentAlertSuppression is one agent_alert_suppression row. State reads
// "expired" once ends_at has passed, before the next write records it.
type AgentAlertSuppression struct {
	ID             uuid.UUID  `json:"id" gorm:"column:id"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"column:workspace_id"`
	IdentityID     uuid.UUID  `json:"identity_id" gorm:"column:identity_id"`
	Detection      string     `json:"detection" gorm:"column:detection"`
	InstanceDigest string     `json:"instance_digest" gorm:"column:instance_digest"`
	Reason         string     `json:"reason" gorm:"column:reason"`
	DurationDays   int        `json:"duration_days" gorm:"column:duration_days"`
	State          string     `json:"state" gorm:"column:state"`
	RenewalOf      *uuid.UUID `json:"renewal_of" gorm:"column:renewal_of"`
	Renewals       int        `json:"renewals" gorm:"column:renewals"`
	RequestedBy    uuid.UUID  `json:"requested_by" gorm:"column:requested_by"`
	RequestedAt    time.Time  `json:"requested_at" gorm:"column:requested_at"`
	ApprovedBy     *uuid.UUID `json:"approved_by" gorm:"column:approved_by"`
	ApprovedAt     *time.Time `json:"approved_at" gorm:"column:approved_at"`
	RejectedBy     *uuid.UUID `json:"rejected_by" gorm:"column:rejected_by"`
	RejectedAt     *time.Time `json:"rejected_at" gorm:"column:rejected_at"`
	StartsAt       *time.Time `json:"starts_at" gorm:"column:starts_at"`
	EndsAt         *time.Time `json:"ends_at" gorm:"column:ends_at"`
	EndedBy        *uuid.UUID `json:"ended_by" gorm:"column:ended_by"`
	EndedAt        *time.Time `json:"ended_at" gorm:"column:ended_at"`
	EndReason      string     `json:"end_reason" gorm:"column:end_reason"`
	BreakGlass     bool       `json:"break_glass" gorm:"column:break_glass"`
	ReviewDueAt    *time.Time `json:"review_due_at" gorm:"column:review_due_at"`
}

const agentSuppressionColumns = `id, workspace_id, identity_id, detection, instance_digest, reason, duration_days, state, renewal_of,
	renewals, requested_by, requested_at, approved_by, approved_at, rejected_by, rejected_at, starts_at, ends_at, ended_by, ended_at,
	end_reason, break_glass, review_due_at`

func (s *AgentAlertSuppression) normalise(now time.Time) {
	if s.State == AgentSuppressionActive && s.EndsAt != nil && !now.Before(*s.EndsAt) {
		s.State = AgentSuppressionExpired
	}
}

// AgentAlertSuppressionRequest is POST /suppressions and, without the
// scope, POST /suppressions/:id/renew.
type AgentAlertSuppressionRequest struct {
	IdentityID     uuid.UUID `json:"identity_id"`
	Detection      string    `json:"detection"`
	InstanceDigest string    `json:"instance_digest"`
	Reason         string    `json:"reason"`
	// Days is the suppression's length once in force (1..90, default 30).
	Days int `json:"days"`
}

// AgentAlertSuppressionResult is a write's answer: the row and whether it is
// in force (applied) or waits for a second person (pending).
type AgentAlertSuppressionResult struct {
	Suppression *AgentAlertSuppression `json:"suppression"`
	Applied     bool                   `json:"applied"`
	Pending     bool                   `json:"pending"`
	BreakGlass  bool                   `json:"break_glass"`
}

func validateSuppressionTerms(reason string, days int) (string, int, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", 0, GovBadParam("reason", "reason is required.")
	}
	if len(reason) > 1000 {
		return "", 0, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	if days == 0 {
		days = AgentSuppressionDefaultDays
	}
	if days < 1 || days > AgentSuppressionMaxDays {
		return "", 0, GovBadParam("days", "days must be between 1 and 90.")
	}
	return reason, days, nil
}

// validate checks the request's scope and terms.
func (r *AgentAlertSuppressionRequest) validate() error {
	if r.IdentityID == uuid.Nil {
		return GovBadParam("identity_id", "identity_id is required.")
	}
	if !detect.Valid(detect.ID(r.Detection)) {
		return GovBadParam("detection", "detection must be one of D1..D8.")
	}
	if detect.HarmfulOnSuccess(detect.ID(r.Detection)) {
		return govErr(http.StatusBadRequest, GovCodeSuppressionNotAllowed,
			"This detection fires only on a harmful call that succeeded (a secret read, credentials created, IAM changed, logging weakened or a new role assumed); it is never suppressed.",
			map[string]any{"detection": r.Detection})
	}
	r.InstanceDigest = strings.TrimSpace(r.InstanceDigest)
	if r.InstanceDigest != "" && !agentInstanceDigestRe.MatchString(r.InstanceDigest) {
		return GovBadParam("instance_digest", "instance_digest must be at most 200 characters of letters, digits and ._:/+=-.")
	}
	var err error
	r.Reason, r.Days, err = validateSuppressionTerms(r.Reason, r.Days)
	return err
}

/* ------------------------------------------------------------------------- */
/*                                  The sink                                  */
/* ------------------------------------------------------------------------- */

// matchAgentAlertSuppression is the active suppression of (identity,
// detection) in force at now that a new alert falls under (nil: none). A
// detection that records a succeeded harmful outcome never matches.
func matchAgentAlertSuppression(tx *gorm.DB, ws, identity uuid.UUID, d detect.ID, digest string, now time.Time) (*uuid.UUID, error) {
	if detect.HarmfulOnSuccess(d) {
		return nil, nil
	}
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT id FROM agent_alert_suppression
	                   WHERE workspace_id = ? AND identity_id = ? AND detection = ? AND state = 'active'
	                     AND starts_at <= ? AND ends_at > ? AND (instance_digest = '' OR instance_digest = ?)
	                   ORDER BY ends_at DESC LIMIT 1`, ws, identity, string(d), now, now, digest).Scan(&ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return &ids[0], nil
}

/* ------------------------------------------------------------------------- */
/*                                   Service                                  */
/* ------------------------------------------------------------------------- */

// expireAgentSuppressions records every active suppression of ws past its
// end as expired, with a log entry each.
func expireAgentSuppressions(tx *gorm.DB, ws uuid.UUID, now time.Time) error {
	var rows []AgentAlertSuppression
	if err := tx.Raw(`UPDATE agent_alert_suppression SET state = 'expired'
	                   WHERE workspace_id = ? AND state = 'active' AND ends_at <= ?
	                   RETURNING `+agentSuppressionColumns, ws, now).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionExpired, models.GovActorSystem, AgentAlertSinkName, govEventRefs{},
			map[string]any{"suppression_id": r.ID, "identity_id": r.IdentityID, "detection": r.Detection, "ends_at": r.EndsAt}); err != nil {
			return err
		}
	}
	return nil
}

func lockedAgentSuppression(tx *gorm.DB, ws, id uuid.UUID) (*AgentAlertSuppression, error) {
	var rows []AgentAlertSuppression
	if err := tx.Raw(`SELECT `+agentSuppressionColumns+` FROM agent_alert_suppression WHERE workspace_id = ? AND id = ? FOR UPDATE`,
		ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func lockAgentSuppressionScope(tx *gorm.DB, ws, identity uuid.UUID, d string) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_alert_suppression:"+ws.String()+":"+identity.String()+":"+d).Error
}

// ListSuppressions is GET /suppressions: newest first, optionally one state
// (an "expired" filter also lists active rows past their end), limit
// 1..200 (default 50).
func (s *AgentAlertService) ListSuppressions(ctx context.Context, ws uuid.UUID, state string, identity *uuid.UUID, limit int) ([]AgentAlertSuppression, error) {
	switch state {
	case "", AgentSuppressionProposed, AgentSuppressionActive, AgentSuppressionRejected, AgentSuppressionEnded, AgentSuppressionExpired:
	default:
		return nil, GovBadParam("state", "state must be proposed, active, rejected, ended or expired.")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	now := s.now().UTC()
	q := `SELECT ` + agentSuppressionColumns + ` FROM agent_alert_suppression WHERE workspace_id = ?`
	args := []any{ws}
	switch state {
	case "":
	case AgentSuppressionActive:
		q += ` AND state = 'active' AND ends_at > ?`
		args = append(args, now)
	case AgentSuppressionExpired:
		q += ` AND (state = 'expired' OR (state = 'active' AND ends_at <= ?))`
		args = append(args, now)
	default:
		q += ` AND state = ?`
		args = append(args, state)
	}
	if identity != nil {
		q += ` AND identity_id = ?`
		args = append(args, *identity)
	}
	q += ` ORDER BY requested_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	var rows []AgentAlertSuppression
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].normalise(now)
	}
	if rows == nil {
		rows = []AgentAlertSuppression{}
	}
	return rows, nil
}

// GetSuppression is one suppression; another workspace's is not found.
func (s *AgentAlertService) GetSuppression(ctx context.Context, ws, id uuid.UUID) (*AgentAlertSuppression, error) {
	var out *AgentAlertSuppression
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []AgentAlertSuppression
		if err := tx.Raw(`SELECT `+agentSuppressionColumns+` FROM agent_alert_suppression WHERE workspace_id = ? AND id = ?`, ws, id).
			Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		out = &rows[0]
		out.normalise(s.now().UTC())
		return nil
	})
	return out, err
}

// RequestSuppression is POST /suppressions (tier 3).
func (s *AgentAlertService) RequestSuppression(ctx context.Context, ws, actor uuid.UUID, req AgentAlertSuppressionRequest) (*AgentAlertSuppressionResult, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	var out *AgentAlertSuppressionResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := lockAgentSuppressionScope(tx, ws, req.IdentityID, req.Detection); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := expireAgentSuppressions(tx, ws, now); err != nil {
			return err
		}
		// The identity must be this workspace's: an inventory identity or
		// one its alerts name. Another workspace's id is not found.
		var known bool
		if err := tx.Raw(`SELECT EXISTS (SELECT 1 FROM cloud_identity WHERE workspace_id = ? AND id = ?)
		                       OR EXISTS (SELECT 1 FROM agent_alert WHERE workspace_id = ? AND identity_id = ?)`,
			ws, req.IdentityID, ws, req.IdentityID).Scan(&known).Error; err != nil {
			return err
		}
		if !known {
			return GovNotFound()
		}
		var active []uuid.UUID
		if err := tx.Raw(`SELECT id FROM agent_alert_suppression WHERE workspace_id = ? AND identity_id = ? AND detection = ?
		                     AND instance_digest = ? AND state = 'active'`, ws, req.IdentityID, req.Detection, req.InstanceDigest).
			Scan(&active).Error; err != nil {
			return err
		}
		if len(active) > 0 {
			return govErr(http.StatusConflict, GovCodeSuppressionExists,
				"A suppression of this scope is in force: renew it instead.", map[string]any{"suppression_id": active[0]})
		}
		var err error
		out, err = s.requestSuppressionTx(tx, ws, actor, req, nil, now)
		return err
	})
	return out, err
}

// requestSuppressionTx writes a request (renewalOf: the suppression it
// renews) and, when actor may apply it alone (break-glass), brings it into
// force.
func (s *AgentAlertService) requestSuppressionTx(tx *gorm.DB, ws, actor uuid.UUID, req AgentAlertSuppressionRequest, renewalOf *uuid.UUID, now time.Time) (*AgentAlertSuppressionResult, error) {
	var pending []uuid.UUID
	if err := tx.Raw(`SELECT id FROM agent_alert_suppression WHERE workspace_id = ? AND identity_id = ? AND detection = ?
	                     AND instance_digest = ? AND state = 'proposed'`, ws, req.IdentityID, req.Detection, req.InstanceDigest).
		Scan(&pending).Error; err != nil {
		return nil, err
	}
	if len(pending) > 0 {
		return nil, govErr(http.StatusConflict, GovCodeSuppressionPending,
			"A request for this scope is already waiting for approval.", map[string]any{"suppression_id": pending[0]})
	}
	var renewals int64
	if err := tx.Raw(`SELECT count(*) FROM agent_alert_suppression WHERE workspace_id = ? AND identity_id = ? AND detection = ?
	                     AND starts_at IS NOT NULL`, ws, req.IdentityID, req.Detection).Scan(&renewals).Error; err != nil {
		return nil, err
	}
	var rows []AgentAlertSuppression
	if err := tx.Raw(`INSERT INTO agent_alert_suppression (workspace_id, identity_id, detection, instance_digest, reason, duration_days,
	                         state, renewal_of, renewals, requested_by, requested_at)
	                  VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?, ?, ?, ?)
	                  RETURNING `+agentSuppressionColumns,
		ws, req.IdentityID, req.Detection, req.InstanceDigest, req.Reason, req.Days, renewalOf, renewals, actor, now).Scan(&rows).Error; err != nil {
		return nil, err
	}
	sup := &rows[0]
	payload := map[string]any{"suppression_id": sup.ID, "identity_id": sup.IdentityID, "detection": sup.Detection,
		"instance_digest": sup.InstanceDigest, "days": sup.DurationDays, "renewals": sup.Renewals, "reason": sup.Reason}
	if renewalOf != nil {
		payload["renewal_of"] = *renewalOf
	}
	breakGlass, err := agentTier3BreakGlass(tx, ws, actor)
	if err != nil {
		return nil, err
	}
	if !breakGlass {
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionRequested, models.GovActorUser, actor.String(), govEventRefs{}, payload); err != nil {
			return nil, err
		}
		return &AgentAlertSuppressionResult{Suppression: sup, Pending: true}, nil
	}
	if err := activateAgentSuppression(tx, ws, sup, actor, nil, now, true); err != nil {
		return nil, err
	}
	payload["starts_at"], payload["ends_at"], payload["review_due_at"] = sup.StartsAt, sup.EndsAt, sup.ReviewDueAt
	if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionBreakGlass, models.GovActorUser, actor.String(), govEventRefs{}, payload); err != nil {
		return nil, err
	}
	return &AgentAlertSuppressionResult{Suppression: sup, Applied: true, BreakGlass: true}, nil
}

// activateAgentSuppression brings sup into force from now for its
// duration: the suppression of the same scope in force (the one it renews)
// ends first. approver is nil for break-glass.
func activateAgentSuppression(tx *gorm.DB, ws uuid.UUID, sup *AgentAlertSuppression, actor uuid.UUID, approver *uuid.UUID, now time.Time, breakGlass bool) error {
	var replaced []uuid.UUID
	if err := tx.Raw(`UPDATE agent_alert_suppression SET state = 'ended', ended_by = ?, ended_at = ?, end_reason = ?
	                   WHERE workspace_id = ? AND identity_id = ? AND detection = ? AND instance_digest = ? AND state = 'active'
	                   RETURNING id`, actor, now, "replaced by "+sup.ID.String(), ws, sup.IdentityID, sup.Detection, sup.InstanceDigest).
		Scan(&replaced).Error; err != nil {
		return err
	}
	for _, id := range replaced {
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionEnded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"suppression_id": id, "identity_id": sup.IdentityID, "detection": sup.Detection,
				"reason": "replaced by its renewal", "replaced_by": sup.ID}); err != nil {
			return err
		}
	}
	ends := now.AddDate(0, 0, sup.DurationDays)
	var reviewDue *time.Time
	if breakGlass {
		d := now.Add(agentTier3BreakGlassReviewDue)
		reviewDue = &d
	}
	var approvedAt *time.Time
	if approver != nil {
		approvedAt = &now
	}
	if err := tx.Exec(`UPDATE agent_alert_suppression SET state = 'active', approved_by = ?, approved_at = ?, starts_at = ?, ends_at = ?,
	                       break_glass = ?, review_due_at = ?
	                    WHERE workspace_id = ? AND id = ?`, approver, approvedAt, now, ends, breakGlass, reviewDue, ws, sup.ID).Error; err != nil {
		return err
	}
	sup.State, sup.ApprovedBy, sup.ApprovedAt, sup.StartsAt, sup.EndsAt = AgentSuppressionActive, approver, approvedAt, &now, &ends
	sup.BreakGlass, sup.ReviewDueAt = breakGlass, reviewDue
	return nil
}

// ApproveSuppression is POST /suppressions/:id/approve: a second person
// holding governance:approve brings a request into force.
func (s *AgentAlertService) ApproveSuppression(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlertSuppressionResult, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentAlertSuppressionResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		sup, err := lockedAgentSuppression(tx, ws, id)
		if err != nil {
			return err
		}
		if err := lockAgentSuppressionScope(tx, ws, sup.IdentityID, sup.Detection); err != nil {
			return err
		}
		if sup.State != AgentSuppressionProposed {
			return govErr(http.StatusConflict, "invalid_state", "Only a requested suppression can be approved.", map[string]any{"state": sup.State})
		}
		requester := sup.RequestedBy
		if err := agentTier3CheckApprover(tx, ws, &requester, actor); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := expireAgentSuppressions(tx, ws, now); err != nil {
			return err
		}
		if err := activateAgentSuppression(tx, ws, sup, actor, &actor, now, false); err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionApproved, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"suppression_id": sup.ID, "identity_id": sup.IdentityID, "detection": sup.Detection,
				"requested_by": sup.RequestedBy, "starts_at": sup.StartsAt, "ends_at": sup.EndsAt, "renewals": sup.Renewals,
				"reason": reason}); err != nil {
			return err
		}
		out = &AgentAlertSuppressionResult{Suppression: sup, Applied: true}
		return nil
	})
	return out, err
}

// RejectSuppression is POST /suppressions/:id/reject: the requester
// (withdrawing) or a holder of governance:approve, with a reason.
func (s *AgentAlertService) RejectSuppression(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlertSuppression, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, GovBadParam("reason", "reason is required to reject a suppression.")
	}
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentAlertSuppression
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		sup, err := lockedAgentSuppression(tx, ws, id)
		if err != nil {
			return err
		}
		if sup.State != AgentSuppressionProposed {
			return govErr(http.StatusConflict, "invalid_state", "Only a requested suppression can be rejected.", map[string]any{"state": sup.State})
		}
		requester := sup.RequestedBy
		if err := agentTier3CheckRejecter(tx, ws, &requester, actor); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := tx.Exec(`UPDATE agent_alert_suppression SET state = 'rejected', rejected_by = ?, rejected_at = ?, end_reason = ?
		                    WHERE workspace_id = ? AND id = ?`, actor, now, reason, ws, id).Error; err != nil {
			return err
		}
		sup.State, sup.RejectedBy, sup.RejectedAt, sup.EndReason = AgentSuppressionRejected, &actor, &now, reason
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionRejected, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"suppression_id": sup.ID, "identity_id": sup.IdentityID, "detection": sup.Detection,
				"requested_by": sup.RequestedBy, "reason": reason}); err != nil {
			return err
		}
		out = sup
		return nil
	})
	return out, err
}

// RenewSuppression is POST /suppressions/:id/renew: a new request (tier 3)
// for the same scope, of a suppression in force or expired. It comes into
// force on approval and replaces the one it renews.
func (s *AgentAlertService) RenewSuppression(ctx context.Context, ws, id, actor uuid.UUID, reason string, days int) (*AgentAlertSuppressionResult, error) {
	reason, days, err := validateSuppressionTerms(reason, days)
	if err != nil {
		return nil, err
	}
	var out *AgentAlertSuppressionResult
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		prev, err := lockedAgentSuppression(tx, ws, id)
		if err != nil {
			return err
		}
		if err := lockAgentSuppressionScope(tx, ws, prev.IdentityID, prev.Detection); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := expireAgentSuppressions(tx, ws, now); err != nil {
			return err
		}
		prev.normalise(now)
		if prev.State != AgentSuppressionActive && prev.State != AgentSuppressionExpired {
			return govErr(http.StatusConflict, "invalid_state", "Only a suppression in force or expired can be renewed.", map[string]any{"state": prev.State})
		}
		if detect.HarmfulOnSuccess(detect.ID(prev.Detection)) {
			return govErr(http.StatusBadRequest, GovCodeSuppressionNotAllowed, "This detection is never suppressed.", nil)
		}
		req := AgentAlertSuppressionRequest{IdentityID: prev.IdentityID, Detection: prev.Detection, InstanceDigest: prev.InstanceDigest,
			Reason: reason, Days: days}
		prevID := prev.ID
		out, err = s.requestSuppressionTx(tx, ws, actor, req, &prevID, now)
		return err
	})
	return out, err
}

// EndSuppression is POST /suppressions/:id/end: a suppression in force ends
// now (tightening: applies at once), with a reason.
func (s *AgentAlertService) EndSuppression(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlertSuppression, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, GovBadParam("reason", "reason is required to end a suppression.")
	}
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentAlertSuppression
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		sup, err := lockedAgentSuppression(tx, ws, id)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if err := expireAgentSuppressions(tx, ws, now); err != nil {
			return err
		}
		sup.normalise(now)
		if sup.State != AgentSuppressionActive {
			return govErr(http.StatusConflict, "invalid_state", "Only a suppression in force can be ended.", map[string]any{"state": sup.State})
		}
		if err := tx.Exec(`UPDATE agent_alert_suppression SET state = 'ended', ended_by = ?, ended_at = ?, end_reason = ?
		                    WHERE workspace_id = ? AND id = ?`, actor, now, reason, ws, id).Error; err != nil {
			return err
		}
		sup.State, sup.EndedBy, sup.EndedAt, sup.EndReason = AgentSuppressionEnded, &actor, &now, reason
		if err := appendGovEvent(tx, ws, GovEventAgentAlertSuppressionEnded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"suppression_id": sup.ID, "identity_id": sup.IdentityID, "detection": sup.Detection, "reason": reason}); err != nil {
			return err
		}
		out = sup
		return nil
	})
	return out, err
}
