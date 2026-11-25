package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// The ask policy (GET/PUT /agent-runtime/asks/policy). Tightening (shorter
// due times, a shorter escalation step, a channel turned on) applies at once.
// Loosening (any longer due time or step, a channel turned off) is tier 3:
// it becomes a pending_change of kind agent_ask_policy that another member
// holding governance:approve approves -- unless no other member holds it,
// when it applies alone as break-glass with a review due in 24 h
// (decision 4), as the gateway runtime settings do.

// PendingChangeKindAgentAskPolicy is the pending change kind of a loosening.
const PendingChangeKindAgentAskPolicy = "agent_ask_policy"

// agentAskPolicyValues is what a change compares and writes.
type agentAskPolicyValues struct {
	DueHighHours   int  `json:"due_high_hours"`
	DueMediumHours int  `json:"due_medium_hours"`
	DueLowHours    int  `json:"due_low_hours"`
	HoursPerStep   int  `json:"hours_per_step"`
	ChannelSlack   bool `json:"channel_slack"`
	ChannelEmail   bool `json:"channel_email"`
	ChannelWebhook bool `json:"channel_webhook"`
}

func (p AgentAskPolicy) values() agentAskPolicyValues {
	return agentAskPolicyValues{p.DueHighHours, p.DueMediumHours, p.DueLowHours, p.HoursPerStep, p.ChannelSlack, p.ChannelEmail, p.ChannelWebhook}
}

// AgentAskPolicyLoosens reports whether going from a to b loosens: any due
// time or escalation step longer, or a channel turned off.
func AgentAskPolicyLoosens(a, b agentAskPolicyValues) bool {
	return b.DueHighHours > a.DueHighHours || b.DueMediumHours > a.DueMediumHours || b.DueLowHours > a.DueLowHours ||
		b.HoursPerStep > a.HoursPerStep || (a.ChannelSlack && !b.ChannelSlack) || (a.ChannelEmail && !b.ChannelEmail) ||
		(a.ChannelWebhook && !b.ChannelWebhook)
}

// AgentAskPolicyUpdate is PUT /asks/policy: the expected version and the
// fields to change.
type AgentAskPolicyUpdate struct {
	Version        *int64
	DueHighHours   *int
	DueMediumHours *int
	DueLowHours    *int
	HoursPerStep   *int
	ChannelSlack   *bool
	ChannelEmail   *bool
	ChannelWebhook *bool
	Reason         string
}

// AgentAskPolicyResult is what PUT did.
type AgentAskPolicyResult struct {
	Policy        AgentAskPolicy     `json:"policy"`
	Applied       bool               `json:"applied"`
	BreakGlass    bool               `json:"break_glass"`
	PendingChange *PendingChangeView `json:"pending_change,omitempty"`
}

type agentAskPolicyPayload struct {
	FromVersion int64                `json:"from_version"`
	From        agentAskPolicyValues `json:"from"`
	To          agentAskPolicyValues `json:"to"`
}

func validateAskPolicyValues(v agentAskPolicyValues) error {
	for name, h := range map[string]int{"due_high_hours": v.DueHighHours, "due_medium_hours": v.DueMediumHours, "due_low_hours": v.DueLowHours} {
		if h < 1 || h > 720 {
			return GovBadParam(name, name+" is 1 to 720 hours.")
		}
	}
	if v.HoursPerStep < 1 || v.HoursPerStep > 168 {
		return GovBadParam("hours_per_step", "hours_per_step is 1 to 168 hours.")
	}
	return nil
}

// GetPolicy is GET /asks/policy.
func (s *AgentAskService) GetPolicy(ctx context.Context, ws uuid.UUID) (AgentAskPolicy, error) {
	var p AgentAskPolicy
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		p, err = readAgentAskPolicy(tx, ws)
		return err
	})
	return p, err
}

func writeAgentAskPolicy(tx *gorm.DB, ws uuid.UUID, v agentAskPolicyValues, actor uuid.UUID) error {
	return tx.Exec(`INSERT INTO agent_ask_policy (workspace_id, due_high_hours, due_medium_hours, due_low_hours, hours_per_step,
	        channel_slack, channel_email, channel_webhook, version, updated_by, updated_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, now())
	        ON CONFLICT (workspace_id) DO UPDATE SET due_high_hours = EXCLUDED.due_high_hours, due_medium_hours = EXCLUDED.due_medium_hours,
	          due_low_hours = EXCLUDED.due_low_hours, hours_per_step = EXCLUDED.hours_per_step, channel_slack = EXCLUDED.channel_slack,
	          channel_email = EXCLUDED.channel_email, channel_webhook = EXCLUDED.channel_webhook,
	          version = agent_ask_policy.version + 1, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		ws, v.DueHighHours, v.DueMediumHours, v.DueLowHours, v.HoursPerStep, v.ChannelSlack, v.ChannelEmail, v.ChannelWebhook, actor).Error
}

// UpdatePolicy is PUT /asks/policy.
func (s *AgentAskService) UpdatePolicy(ctx context.Context, ws, actor uuid.UUID, u AgentAskPolicyUpdate) (AgentAskPolicyResult, error) {
	var res AgentAskPolicyResult
	if u.Version == nil {
		return res, GovBadParam("version", "version (from GET /asks/policy) is required.")
	}
	u.Reason = strings.TrimSpace(u.Reason)
	if len(u.Reason) > MaxPendingChangeReason {
		return res, GovBadParam("reason", "reason is too long.")
	}
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// One writer at a time per workspace (the row may not exist yet).
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_ask_policy:"+ws.String()).Error; err != nil {
			return err
		}
		cur, err := readAgentAskPolicy(tx, ws)
		if err != nil {
			return err
		}
		if cur.Version != *u.Version {
			return govConflict(GovCodeVersionConflict, "The ask policy changed since you opened it.", map[string]any{"version": cur.Version})
		}
		from := cur.values()
		to := from
		set := func(dst *int, v *int) {
			if v != nil {
				*dst = *v
			}
		}
		setb := func(dst *bool, v *bool) {
			if v != nil {
				*dst = *v
			}
		}
		set(&to.DueHighHours, u.DueHighHours)
		set(&to.DueMediumHours, u.DueMediumHours)
		set(&to.DueLowHours, u.DueLowHours)
		set(&to.HoursPerStep, u.HoursPerStep)
		setb(&to.ChannelSlack, u.ChannelSlack)
		setb(&to.ChannelEmail, u.ChannelEmail)
		setb(&to.ChannelWebhook, u.ChannelWebhook)
		if err := validateAskPolicyValues(to); err != nil {
			return err
		}
		if to == from {
			res.Policy, res.Applied = cur, true
			return nil
		}
		payload := agentAskPolicyPayload{FromVersion: cur.Version, From: from, To: to}
		loosens := AgentAskPolicyLoosens(from, to)
		if loosens {
			approvers, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
			if err != nil {
				return err
			}
			second := false
			for _, a := range approvers {
				if a != actor {
					second = true
				}
			}
			if second {
				pc, err := insertPendingChangeTx(tx, ws, PendingChangeKindAgentAskPolicy, "agent_ask_policy", payload, u.Reason, actor, now)
				if err != nil {
					return err
				}
				v := pc.view()
				res.PendingChange, res.Policy = &v, cur
				return appendGovEvent(tx, ws, GovEventAskPolicyRequested, models.GovActorUser, actor.String(), govEventRefs{},
					map[string]any{"change_id": pc.ID, "from": from, "to": to})
			}
		}
		if err := writeAgentAskPolicy(tx, ws, to, actor); err != nil {
			return err
		}
		if loosens {
			pc, err := insertBreakGlassChangeTx(tx, ws, PendingChangeKindAgentAskPolicy, "agent_ask_policy", payload, u.Reason, actor, now)
			if err != nil {
				return err
			}
			v := pc.view()
			res.PendingChange, res.BreakGlass = &v, true
		}
		if err := appendGovEvent(tx, ws, GovEventAskPolicyChanged, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"from": from, "to": to, "loosened": loosens, "break_glass": res.BreakGlass}); err != nil {
			return err
		}
		res.Applied = true
		res.Policy, err = readAgentAskPolicy(tx, ws)
		return err
	})
	return res, err
}

// applyAgentAskPolicyChange applies an approved loosening when the policy is
// still at the version it was requested against.
func applyAgentAskPolicyChange(tx *gorm.DB, ws uuid.UUID, pc *pendingChangeRow) (func(), error) {
	var p agentAskPolicyPayload
	if err := json.Unmarshal([]byte(pc.Payload), &p); err != nil {
		return nil, fmt.Errorf("pending change %s: payload: %w", pc.ID, err)
	}
	if err := validateAskPolicyValues(p.To); err != nil {
		return nil, govConflict("change_invalid", "The requested values are no longer valid.", nil)
	}
	if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_ask_policy:"+ws.String()).Error; err != nil {
		return nil, err
	}
	cur, err := readAgentAskPolicy(tx, ws)
	if err != nil {
		return nil, err
	}
	if cur.Version != p.FromVersion || cur.values() != p.From {
		return nil, govConflict("change_stale", "The ask policy changed since this was requested; reject it and request again.",
			map[string]any{"version": cur.Version})
	}
	if err := writeAgentAskPolicy(tx, ws, p.To, pc.RequestedBy); err != nil {
		return nil, err
	}
	return nil, appendGovEvent(tx, ws, GovEventAskPolicyChanged, models.GovActorSystem, "pending-change", govEventRefs{},
		map[string]any{"from": p.From, "to": p.To, "loosened": true, "change_id": pc.ID})
}

func init() {
	registerPendingChangeKind(PendingChangeKindAgentAskPolicy, applyAgentAskPolicyChange)
}
