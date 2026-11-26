package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Versioned detection rules (SecOps F6, AS-179; migration 164).
//
// A workspace's alert settings (detection switches, thresholds, severities,
// Slack, dedupe window, retention) are rows of agent_detection_rule_version;
// the detections read the ACTIVE one. PUT /alert-settings proposes a new
// version over the active one:
//
//   - a change that only tightens (turns a detection on, lowers a threshold,
//     raises a severity, turns Slack on, shortens the dedupe window, keeps
//     alerts longer) is active at once;
//   - a change that loosens anything (agentAlertLoosening) is tier 3: the
//     version is proposed and a DIFFERENT member holding governance:approve
//     approves it (POST /alert-settings/versions/:id/approve) or anyone of
//     them, or its proposer, rejects it. A proposer never approves their own
//     proposal (403 self_approval; the table's CHECK enforces it too).
//   - break-glass (SecOps decision 4): when the proposer is the workspace's
//     ONLY member holding governance:approve, nobody else could approve, so
//     the loosening applies alone, is marked break_glass and is due a review
//     within 24 hours (review_due_at), with its own log entry.
//
// Every change writes an iga_gov_event with the settings before and after.
// A version becoming active supersedes the previous active version and any
// proposal made against an older version (the proposal would otherwise undo
// the newer change on approval). At most one proposal waits at a time
// (409 rule_change_pending).
//
// DECISION (F6): a change mixing tightening and loosening is proposed whole;
// nothing of it applies until it is approved. Turning Slack off, a longer
// dedupe window and a shorter retention count as loosening: each means
// fewer alerts seen or less evidence kept.

// Rule version states (agent_detection_rule_version.state).
const (
	AgentRuleProposed   = "proposed"
	AgentRuleActive     = "active"
	AgentRuleRejected   = "rejected"
	AgentRuleSuperseded = "superseded"
)

// iga_gov_event names of rule changes (iga_gov_event_vocabulary.go).
const (
	GovEventAgentAlertRulesApplied    = "agent_alert.rules_applied"
	GovEventAgentAlertRulesProposed   = "agent_alert.rules_proposed"
	GovEventAgentAlertRulesApproved   = "agent_alert.rules_approved"
	GovEventAgentAlertRulesRejected   = "agent_alert.rules_rejected"
	GovEventAgentAlertRulesBreakGlass = "agent_alert.rules_break_glass"
	GovEventAgentAlertRulesSuperseded = "agent_alert.rules_superseded"
)

// Tier-3 error codes.
const (
	GovCodeRuleChangePending      = "rule_change_pending"
	GovCodeApproverNotAuthorized  = "approver_not_authorized"
	GovCodeRuleVersionStale       = "rule_version_stale"
)

// AgentDetectionRuleVersion is one agent_detection_rule_version row.
type AgentDetectionRuleVersion struct {
	ID                  uuid.UUID       `json:"id" gorm:"column:id"`
	WorkspaceID         uuid.UUID       `json:"workspace_id" gorm:"column:workspace_id"`
	VersionNo           int             `json:"version" gorm:"column:version_no"`
	BaseVersionNo       *int            `json:"base_version" gorm:"column:base_version_no"`
	Detections          json.RawMessage `json:"detections" gorm:"column:detections"`
	SlackEnabled        bool            `json:"slack_enabled" gorm:"column:slack_enabled"`
	DedupeWindowMinutes int             `json:"dedupe_window_minutes" gorm:"column:dedupe_window_minutes"`
	RetentionDays       int             `json:"retention_days" gorm:"column:retention_days"`
	Loosening           json.RawMessage `json:"loosening" gorm:"column:loosening"`
	State               string          `json:"state" gorm:"column:state"`
	ProposedBy          *uuid.UUID      `json:"proposed_by" gorm:"column:proposed_by"`
	ProposedAt          time.Time       `json:"proposed_at" gorm:"column:proposed_at"`
	ApprovedBy          *uuid.UUID      `json:"approved_by" gorm:"column:approved_by"`
	ApprovedAt          *time.Time      `json:"approved_at" gorm:"column:approved_at"`
	RejectedBy          *uuid.UUID      `json:"rejected_by" gorm:"column:rejected_by"`
	RejectedAt          *time.Time      `json:"rejected_at" gorm:"column:rejected_at"`
	ActivatedAt         *time.Time      `json:"activated_at" gorm:"column:activated_at"`
	SupersededAt        *time.Time      `json:"superseded_at" gorm:"column:superseded_at"`
	Reason              string          `json:"reason" gorm:"column:reason"`
	BreakGlass          bool            `json:"break_glass" gorm:"column:break_glass"`
	ReviewDueAt         *time.Time      `json:"review_due_at" gorm:"column:review_due_at"`
}

const agentRuleVersionColumns = `id, workspace_id, version_no, base_version_no, detections, slack_enabled, dedupe_window_minutes,
	retention_days, loosening, state, proposed_by, proposed_at, approved_by, approved_at, rejected_by, rejected_at, activated_at,
	superseded_at, reason, break_glass, review_due_at`

// settings is the version as AgentAlertSettings.
func (v *AgentDetectionRuleVersion) settings(ws uuid.UUID) AgentAlertSettings {
	s := settingsFromStored(ws, v.Detections, v.SlackEnabled, v.DedupeWindowMinutes, v.RetentionDays)
	s.Saved = true
	t := v.ProposedAt
	if v.ActivatedAt != nil {
		t = *v.ActivatedAt
	}
	s.UpdatedAt = &t
	s.Version = v.VersionNo
	id := v.ID
	s.VersionID = &id
	return s
}

func scanAgentRuleVersion(tx *gorm.DB, q string, args ...any) (*AgentDetectionRuleVersion, error) {
	var rows []AgentDetectionRuleVersion
	if err := tx.Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// activeAgentRuleVersion is ws's active version (nil: none), locked when
// lock is set.
func activeAgentRuleVersion(tx *gorm.DB, ws uuid.UUID, lock bool) (*AgentDetectionRuleVersion, error) {
	q := `SELECT ` + agentRuleVersionColumns + ` FROM agent_detection_rule_version WHERE workspace_id = ? AND state = 'active'`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanAgentRuleVersion(tx, q, ws)
}

// readAgentAlertSettingsWithPending is readAgentAlertSettings plus the
// pending proposal's id.
func readAgentAlertSettingsWithPending(tx *gorm.DB, ws uuid.UUID) (AgentAlertSettings, error) {
	s, err := readAgentAlertSettings(tx, ws)
	if err != nil {
		return s, err
	}
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT id FROM agent_detection_rule_version WHERE workspace_id = ? AND state = 'proposed'`, ws).Scan(&ids).Error; err != nil {
		return s, err
	}
	if len(ids) == 1 {
		s.PendingVersionID = &ids[0]
	}
	return s, nil
}

/* ------------------------------------------------------------------------- */
/*                               Classification                               */
/* ------------------------------------------------------------------------- */

// agentAlertLoosening lists what next loosens compared with cur, in a stable
// order ([] = next only tightens or changes nothing).
func agentAlertLoosening(cur, next AgentAlertSettings) []string {
	var out []string
	for _, id := range detect.All {
		k := string(id)
		c, n := cur.Detections[k], next.Detections[k]
		if c.Enabled && !n.Enabled {
			out = append(out, k+": disabled")
		}
		if id == detect.D5 {
			if n.N > c.N {
				out = append(out, fmt.Sprintf("%s: n raised from %d to %d", k, c.N, n.N))
			}
			// N denials within a SHORTER window is harder to reach.
			if n.Minutes < c.Minutes {
				out = append(out, fmt.Sprintf("%s: minutes lowered from %d to %d", k, c.Minutes, n.Minutes))
			}
		}
		if id == detect.D6 && n.K > c.K {
			out = append(out, fmt.Sprintf("%s: k raised from %g to %g", k, c.K, n.K))
		}
		cs, ns := c.effectiveSeverity(id), n.effectiveSeverity(id)
		if detect.SeverityRank(ns) < detect.SeverityRank(cs) {
			out = append(out, fmt.Sprintf("%s: severity lowered from %s to %s", k, cs, ns))
		}
	}
	if cur.SlackEnabled && !next.SlackEnabled {
		out = append(out, "slack: disabled")
	}
	if next.DedupeWindowMinutes > cur.DedupeWindowMinutes {
		out = append(out, fmt.Sprintf("dedupe_window_minutes raised from %d to %d", cur.DedupeWindowMinutes, next.DedupeWindowMinutes))
	}
	if next.RetentionDays < cur.RetentionDays {
		out = append(out, fmt.Sprintf("retention_days lowered from %d to %d", cur.RetentionDays, next.RetentionDays))
	}
	return out
}

// agentAlertSettingsEqual reports whether a and b configure the same rules.
func agentAlertSettingsEqual(a, b AgentAlertSettings) bool {
	return reflect.DeepEqual(a.Detections, b.Detections) && a.SlackEnabled == b.SlackEnabled &&
		a.DedupeWindowMinutes == b.DedupeWindowMinutes && a.RetentionDays == b.RetentionDays
}

// agentRuleSnapshot is the settings as a log payload ("before" / "after").
func agentRuleSnapshot(s AgentAlertSettings) map[string]any {
	return map[string]any{"version": s.Version, "detections": s.Detections, "slack_enabled": s.SlackEnabled,
		"dedupe_window_minutes": s.DedupeWindowMinutes, "retention_days": s.RetentionDays}
}

/* ------------------------------------------------------------------------- */
/*                         Tier 3: second person, break-glass                 */
/* ------------------------------------------------------------------------- */

// The second-person rule itself (approver != requester, governance:approve
// re-read from the database, break-glass only for the workspace's only
// approver, review due in 24 h, no automation identity) is second_person.go's.

/* ------------------------------------------------------------------------- */
/*                                   Writes                                   */
/* ------------------------------------------------------------------------- */

// AgentAlertSettingsChange is the answer to PUT /alert-settings and to an
// approval: the active settings after it, whether the change applied or
// waits for approval, and the version written.
type AgentAlertSettingsChange struct {
	Settings   AgentAlertSettings         `json:"settings"`
	Changed    bool                       `json:"changed"`
	Applied    bool                       `json:"applied"`
	Pending    bool                       `json:"pending"`
	BreakGlass bool                       `json:"break_glass"`
	Loosening  []string                   `json:"loosening"`
	Version    *AgentDetectionRuleVersion `json:"version,omitempty"`
}

func lockAgentRules(tx *gorm.DB, ws uuid.UUID) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_alert_rules:"+ws.String()).Error
}

// ProposeSettings is PUT /alert-settings: a new detection rule version over
// the active one, applied at once when it only tightens, else proposed for a
// second person (or applied as break-glass). See the file comment.
func (s *AgentAlertService) ProposeSettings(ctx context.Context, ws, actor uuid.UUID, u AgentAlertSettingsUpdate) (*AgentAlertSettingsChange, error) {
	var out *AgentAlertSettingsChange
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := lockAgentRules(tx, ws); err != nil {
			return err
		}
		active, err := activeAgentRuleVersion(tx, ws, true)
		if err != nil {
			return err
		}
		cur := DefaultAgentAlertSettings()
		var base *int
		if active != nil {
			cur = active.settings(ws)
			no := active.VersionNo
			base = &no
		}
		next, err := u.apply(cur)
		if err != nil {
			return err
		}
		loosening := agentAlertLoosening(cur, next)
		if agentAlertSettingsEqual(cur, next) {
			settings, err := readAgentAlertSettingsWithPending(tx, ws)
			out = &AgentAlertSettingsChange{Settings: settings, Applied: true, Loosening: []string{}}
			return err
		}
		now := s.now().UTC()
		reason := strings.TrimSpace(u.Reason)
		before := agentRuleSnapshot(cur)
		if len(loosening) == 0 {
			v, err := activateNewAgentRuleVersion(tx, ws, base, next, loosening, actor, now, reason, false)
			if err != nil {
				return err
			}
			after := v.settings(ws)
			if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesApplied, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"rule_version_id": v.ID, "version": v.VersionNo, "before": before, "after": agentRuleSnapshot(after),
					"reason": reason}); err != nil {
				return err
			}
			settings, err := readAgentAlertSettingsWithPending(tx, ws)
			out = &AgentAlertSettingsChange{Settings: settings, Changed: true, Applied: true, Loosening: []string{}, Version: v}
			return err
		}
		if err := CheckTier3Requester(ctx); err != nil {
			return err
		}
		breakGlass, err := BreakGlassAllowed(ctx, tx, ws, actor)
		if err != nil {
			return err
		}
		if breakGlass {
			v, err := activateNewAgentRuleVersion(tx, ws, base, next, loosening, actor, now, reason, true)
			if err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesBreakGlass, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"rule_version_id": v.ID, "version": v.VersionNo, "before": before, "after": agentRuleSnapshot(v.settings(ws)),
					"loosening": loosening, "reason": reason, "review_due_at": v.ReviewDueAt}); err != nil {
				return err
			}
			settings, err := readAgentAlertSettingsWithPending(tx, ws)
			out = &AgentAlertSettingsChange{Settings: settings, Changed: true, Applied: true, BreakGlass: true, Loosening: loosening, Version: v}
			return err
		}
		var pending int64
		if err := tx.Raw(`SELECT count(*) FROM agent_detection_rule_version WHERE workspace_id = ? AND state = 'proposed'`, ws).Scan(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return govErr(http.StatusConflict, GovCodeRuleChangePending,
				"A rule change is already waiting for approval: approve or reject it first.", nil)
		}
		v, err := insertAgentRuleVersion(tx, ws, base, next, loosening, AgentRuleProposed, actor, now, reason, false)
		if err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesProposed, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"rule_version_id": v.ID, "version": v.VersionNo, "before": before, "after": agentRuleSnapshot(v.settings(ws)),
				"loosening": loosening, "reason": reason}); err != nil {
			return err
		}
		settings, err := readAgentAlertSettingsWithPending(tx, ws)
		out = &AgentAlertSettingsChange{Settings: settings, Changed: true, Pending: true, Loosening: loosening, Version: v}
		return err
	})
	return out, err
}

// insertAgentRuleVersion writes the next version number for ws.
func insertAgentRuleVersion(tx *gorm.DB, ws uuid.UUID, base *int, next AgentAlertSettings, loosening []string, state string,
	actor uuid.UUID, now time.Time, reason string, breakGlass bool) (*AgentDetectionRuleVersion, error) {
	det, err := json.Marshal(next.Detections)
	if err != nil {
		return nil, err
	}
	if loosening == nil {
		loosening = []string{}
	}
	loose, err := json.Marshal(loosening)
	if err != nil {
		return nil, err
	}
	var activated, reviewDue *time.Time
	if state == AgentRuleActive {
		activated = &now
	}
	if breakGlass {
		due := ReviewDue(now)
		reviewDue = &due
	}
	v, err := scanAgentRuleVersion(tx, `INSERT INTO agent_detection_rule_version (workspace_id, version_no, base_version_no, detections,
	        slack_enabled, dedupe_window_minutes, retention_days, loosening, state, proposed_by, proposed_at, activated_at, reason,
	        break_glass, review_due_at)
	    SELECT ?, COALESCE(max(version_no), 0) + 1, ?, ?::jsonb, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?
	      FROM agent_detection_rule_version WHERE workspace_id = ?
	    RETURNING `+agentRuleVersionColumns,
		ws, base, string(det), next.SlackEnabled, next.DedupeWindowMinutes, next.RetentionDays, string(loose), state, actor, now,
		activated, reason, breakGlass, reviewDue, ws)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("agent rule version insert returned no row")
	}
	return v, nil
}

// supersedeActiveAgentRule ends ws's active version.
func supersedeActiveAgentRule(tx *gorm.DB, ws uuid.UUID, now time.Time) error {
	return tx.Exec(`UPDATE agent_detection_rule_version SET state = 'superseded', superseded_at = ?
	                 WHERE workspace_id = ? AND state = 'active'`, now, ws).Error
}

// activateNewAgentRuleVersion supersedes the active version and inserts next
// as active.
func activateNewAgentRuleVersion(tx *gorm.DB, ws uuid.UUID, base *int, next AgentAlertSettings, loosening []string,
	actor uuid.UUID, now time.Time, reason string, breakGlass bool) (*AgentDetectionRuleVersion, error) {
	if err := supersedeActiveAgentRule(tx, ws, now); err != nil {
		return nil, err
	}
	v, err := insertAgentRuleVersion(tx, ws, base, next, loosening, AgentRuleActive, actor, now, reason, breakGlass)
	if err != nil {
		return nil, err
	}
	return v, afterAgentRuleActivated(tx, ws, v, actor, now)
}

// afterAgentRuleActivated supersedes every other proposal (made against an
// older version) and mirrors v into agent_alert_setting.
func afterAgentRuleActivated(tx *gorm.DB, ws uuid.UUID, v *AgentDetectionRuleVersion, actor uuid.UUID, now time.Time) error {
	var stale []AgentDetectionRuleVersion
	if err := tx.Raw(`UPDATE agent_detection_rule_version SET state = 'superseded', superseded_at = ?
	                   WHERE workspace_id = ? AND state = 'proposed' AND id <> ?
	                   RETURNING id, version_no`, now, ws, v.ID).Scan(&stale).Error; err != nil {
		return err
	}
	for _, p := range stale {
		if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesSuperseded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"rule_version_id": p.ID, "version": p.VersionNo, "by_version": v.VersionNo,
				"reason": "a newer version became active; propose the change again over it"}); err != nil {
			return err
		}
	}
	// agent_alert_setting mirrors the active version (read by nothing in this
	// build; kept consistent until a contract migration retires it).
	return tx.Exec(`INSERT INTO agent_alert_setting (workspace_id, detections, slack_enabled, dedupe_window_minutes, retention_days, updated_by, updated_at)
	                VALUES (?, ?::jsonb, ?, ?, ?, ?, ?)
	                ON CONFLICT (workspace_id) DO UPDATE SET detections = EXCLUDED.detections,
	                  slack_enabled = EXCLUDED.slack_enabled, dedupe_window_minutes = EXCLUDED.dedupe_window_minutes,
	                  retention_days = EXCLUDED.retention_days, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		ws, string(v.Detections), v.SlackEnabled, v.DedupeWindowMinutes, v.RetentionDays, actor, now).Error
}

// lockedAgentRuleVersion is ws's version id, locked; another workspace's is
// not found.
func lockedAgentRuleVersion(tx *gorm.DB, ws, id uuid.UUID) (*AgentDetectionRuleVersion, error) {
	v, err := scanAgentRuleVersion(tx, `SELECT `+agentRuleVersionColumns+` FROM agent_detection_rule_version
	                                     WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, GovNotFound()
	}
	return v, nil
}

// ApproveRuleVersion is POST /alert-settings/versions/:id/approve: a second
// person holding governance:approve makes a proposed version active.
func (s *AgentAlertService) ApproveRuleVersion(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAlertSettingsChange, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentAlertSettingsChange
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := lockAgentRules(tx, ws); err != nil {
			return err
		}
		v, err := lockedAgentRuleVersion(tx, ws, id)
		if err != nil {
			return err
		}
		if v.State != AgentRuleProposed {
			return govErr(http.StatusConflict, "invalid_state", "Only a proposed version can be approved.", map[string]any{"state": v.State})
		}
		if err := CheckApprover(ctx, tx, ws, uuidOrNil(v.ProposedBy), actor); err != nil {
			return err
		}
		active, err := activeAgentRuleVersion(tx, ws, true)
		if err != nil {
			return err
		}
		cur := DefaultAgentAlertSettings()
		activeNo := 0
		if active != nil {
			cur, activeNo = active.settings(ws), active.VersionNo
		}
		baseNo := 0
		if v.BaseVersionNo != nil {
			baseNo = *v.BaseVersionNo
		}
		if baseNo != activeNo {
			return govErr(http.StatusConflict, GovCodeRuleVersionStale,
				"The version was proposed over an older version; reject it and propose the change again.", nil)
		}
		now := s.now().UTC()
		if err := supersedeActiveAgentRule(tx, ws, now); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_detection_rule_version SET state = 'active', approved_by = ?, approved_at = ?, activated_at = ?
		                    WHERE workspace_id = ? AND id = ?`, actor, now, now, ws, id).Error; err != nil {
			return err
		}
		v.State, v.ApprovedBy, v.ApprovedAt, v.ActivatedAt = AgentRuleActive, &actor, &now, &now
		if err := afterAgentRuleActivated(tx, ws, v, actor, now); err != nil {
			return err
		}
		var loosening []string
		_ = json.Unmarshal(v.Loosening, &loosening)
		if loosening == nil {
			loosening = []string{}
		}
		if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesApproved, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"rule_version_id": v.ID, "version": v.VersionNo, "proposed_by": v.ProposedBy,
				"before": agentRuleSnapshot(cur), "after": agentRuleSnapshot(v.settings(ws)), "loosening": loosening,
				"reason": reason}); err != nil {
			return err
		}
		settings, err := readAgentAlertSettingsWithPending(tx, ws)
		out = &AgentAlertSettingsChange{Settings: settings, Changed: true, Applied: true, Loosening: loosening, Version: v}
		return err
	})
	return out, err
}

// RejectRuleVersion is POST /alert-settings/versions/:id/reject: the
// proposer (withdrawing) or a holder of governance:approve turns a proposal
// down, with a reason.
func (s *AgentAlertService) RejectRuleVersion(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentDetectionRuleVersion, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, GovBadParam("reason", "reason is required to reject a rule change.")
	}
	if len(reason) > 1000 {
		return nil, GovBadParam("reason", "reason must be at most 1000 characters.")
	}
	var out *AgentDetectionRuleVersion
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		v, err := lockedAgentRuleVersion(tx, ws, id)
		if err != nil {
			return err
		}
		if v.State != AgentRuleProposed {
			return govErr(http.StatusConflict, "invalid_state", "Only a proposed version can be rejected.", map[string]any{"state": v.State})
		}
		if err := CheckRejecter(ctx, tx, ws, uuidOrNil(v.ProposedBy), actor); err != nil {
			return err
		}
		now := s.now().UTC()
		if err := tx.Exec(`UPDATE agent_detection_rule_version SET state = 'rejected', rejected_by = ?, rejected_at = ?
		                    WHERE workspace_id = ? AND id = ?`, actor, now, ws, id).Error; err != nil {
			return err
		}
		v.State, v.RejectedBy, v.RejectedAt = AgentRuleRejected, &actor, &now
		if err := appendGovEvent(tx, ws, GovEventAgentAlertRulesRejected, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"rule_version_id": v.ID, "version": v.VersionNo, "proposed_by": v.ProposedBy, "reason": reason}); err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}

// ListRuleVersions is GET /alert-settings/versions: newest first, limit
// 1..200 (default 50), optionally one state.
func (s *AgentAlertService) ListRuleVersions(ctx context.Context, ws uuid.UUID, state string, limit int) ([]AgentDetectionRuleVersion, error) {
	switch state {
	case "", AgentRuleProposed, AgentRuleActive, AgentRuleRejected, AgentRuleSuperseded:
	default:
		return nil, GovBadParam("state", "state must be proposed, active, rejected or superseded.")
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	q := `SELECT ` + agentRuleVersionColumns + ` FROM agent_detection_rule_version WHERE workspace_id = ?`
	args := []any{ws}
	if state != "" {
		q += ` AND state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY version_no DESC LIMIT ?`
	args = append(args, limit)
	var rows []AgentDetectionRuleVersion
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []AgentDetectionRuleVersion{}
	}
	return rows, nil
}

// uuidOrNil is *p, or uuid.Nil.
func uuidOrNil(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}
