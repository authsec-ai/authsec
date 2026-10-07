package services

import (
	"encoding/json"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The legacy agent-policy compatibility read (PLAN-existing-policy-code-
// disposition.md §3.1, SPEC-iga-phase3-policy.md §7.10).
//
// LEGACY CODE, ON PURPOSE. This is the legacy service answering for its own
// tables: it is the only thing behind /api/iga/v1/legacy/agent-policies, and
// no Phase 3 code reads or writes agent_policies. It lists a workspace's
// legacy policies with what the reconciler last did and the next destructive
// deadline, and offers two operations through the legacy manager -- pause
// (enabled = false) and remove (the legacy delete). It never creates or edits
// a policy.

// LegacyAgentPolicyTarget is what a policy covers: one named agent, or a
// selector the legacy reconciler expands.
type LegacyAgentPolicyTarget struct {
	Kind              string          `json:"kind"` // "agent" | "selector"
	DiscoveredAgentID *uuid.UUID      `json:"discovered_agent_id,omitempty"`
	AgentLabel        string          `json:"agent_label,omitempty"`
	Selector          json.RawMessage `json:"selector,omitempty"`
}

// LegacyReconcileOutcome is the newest agent_policy_actions row attributed to a
// policy: what the reconciler last did (or planned, or refused) because of it.
type LegacyReconcileOutcome struct {
	Action  string    `json:"action"`
	Arm     string    `json:"arm"`
	Outcome string    `json:"outcome"`
	DryRun  bool      `json:"dry_run"`
	Detail  string    `json:"detail"`
	At      time.Time `json:"at"`
}

// LegacyAgentPolicyView is one row of the compatibility list.
type LegacyAgentPolicyView struct {
	ID           uuid.UUID               `json:"id"`
	Name         string                  `json:"name"`
	Description  string                  `json:"description"`
	Target       LegacyAgentPolicyTarget `json:"target"`
	Enabled      bool                    `json:"enabled"`
	DesiredState string                  `json:"desired_state"`
	OnExpiry     string                  `json:"on_expiry"`
	// EffectiveExpiry is the policy's clock resolved (expires_at, or created_at
	// plus duration); null when it has none.
	EffectiveExpiry *time.Time `json:"effective_expiry"`
	// PendingDestructiveDeadline is when the legacy reconciler will act
	// destructively (on_expiry = evict) for an ENABLED policy; null otherwise.
	// A deadline in the past means the reconciler acts on its next pass.
	PendingDestructiveDeadline *time.Time `json:"pending_destructive_deadline"`
	// LastReconcile is null when the reconciler has recorded nothing for it.
	LastReconcile *LegacyReconcileOutcome `json:"last_reconcile"`
	CreatedBy     string                  `json:"created_by"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
}

// LegacyAgentPolicyPosition is a keyset position in the list's order,
// (created_at DESC, id DESC).
type LegacyAgentPolicyPosition struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// LegacyAgentPolicyCompat is the compatibility read and its two operations.
type LegacyAgentPolicyCompat struct {
	db       *gorm.DB
	policies AgentPolicyManager
}

// NewLegacyAgentPolicyCompat constructs the compatibility service over the
// legacy manager.
func NewLegacyAgentPolicyCompat(db *gorm.DB) *LegacyAgentPolicyCompat {
	return &LegacyAgentPolicyCompat{db: db, policies: NewAgentPolicyManager(db)}
}

// HasPolicies reports whether the workspace has any legacy policy, enabled or
// not. With IGA_LEGACY_AGENT_POLICY off, the compatibility routes exist only
// for a workspace where this is true.
func (s *LegacyAgentPolicyCompat) HasPolicies(workspaceID uuid.UUID) (bool, error) {
	var found bool
	err := s.db.Raw(`SELECT EXISTS (SELECT 1 FROM agent_policies WHERE workspace_id = ?)`,
		workspaceID).Scan(&found).Error
	return found, err
}

// Page returns up to limit policies after the position, newest first, and
// whether more follow.
func (s *LegacyAgentPolicyCompat) Page(workspaceID uuid.UUID, after *LegacyAgentPolicyPosition,
	limit int) ([]LegacyAgentPolicyView, bool, error) {

	q := s.db.Where("workspace_id = ?", workspaceID)
	if after != nil {
		q = q.Where("(created_at, id) < (?, ?)", after.CreatedAt, after.ID)
	}
	var rows []models.AgentPolicy
	if err := q.Order("created_at DESC").Order("id DESC").Limit(limit + 1).
		Find(&rows).Error; err != nil {
		return nil, false, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	views, err := s.views(workspaceID, rows)
	return views, more, err
}

// View is one policy of the workspace; gorm.ErrRecordNotFound for an id that
// is not this workspace's.
func (s *LegacyAgentPolicyCompat) View(workspaceID, id uuid.UUID) (*LegacyAgentPolicyView, error) {
	var p models.AgentPolicy
	if err := s.db.First(&p, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	views, err := s.views(workspaceID, []models.AgentPolicy{p})
	if err != nil {
		return nil, err
	}
	return &views[0], nil
}

// Pause sets the policy disabled through the legacy manager, returning it
// before and after. Pausing a paused policy changes nothing.
func (s *LegacyAgentPolicyCompat) Pause(workspaceID, id uuid.UUID) (before, after *LegacyAgentPolicyView, err error) {
	if before, err = s.View(workspaceID, id); err != nil {
		return nil, nil, err
	}
	if _, err = s.policies.Pause(workspaceID, id); err != nil {
		return nil, nil, err
	}
	if after, err = s.View(workspaceID, id); err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// Remove deletes the policy through the legacy manager (the same delete as
// DELETE /authsec/governance/agent-policies/:id), returning what was removed.
func (s *LegacyAgentPolicyCompat) Remove(workspaceID, id uuid.UUID) (*LegacyAgentPolicyView, error) {
	before, err := s.View(workspaceID, id)
	if err != nil {
		return nil, err
	}
	if err := s.policies.Delete(workspaceID, id); err != nil {
		return nil, err
	}
	return before, nil
}

// views resolves rows into the list shape: target labels and each policy's
// newest recorded action, in two queries for the whole page.
func (s *LegacyAgentPolicyCompat) views(workspaceID uuid.UUID, rows []models.AgentPolicy) ([]LegacyAgentPolicyView, error) {
	out := make([]LegacyAgentPolicyView, 0, len(rows))
	if len(rows) == 0 {
		return out, nil
	}

	policyIDs := make([]uuid.UUID, 0, len(rows))
	var agentIDs []uuid.UUID
	for i := range rows {
		policyIDs = append(policyIDs, rows[i].ID)
		if rows[i].DiscoveredAgentID != nil {
			agentIDs = append(agentIDs, *rows[i].DiscoveredAgentID)
		}
	}

	labels := map[uuid.UUID]string{}
	if len(agentIDs) > 0 {
		var agents []struct {
			ID          uuid.UUID
			DisplayName string
		}
		if err := s.db.Model(&models.DiscoveredAgent{}).Select("id, display_name").
			Where("workspace_id = ? AND id IN ?", workspaceID, agentIDs).
			Scan(&agents).Error; err != nil {
			return nil, err
		}
		for _, a := range agents {
			labels[a.ID] = a.DisplayName
		}
	}

	var last []struct {
		PolicyID uuid.UUID
		Action   string
		Arm      string
		Outcome  string
		DryRun   bool
		Detail   string
		ActedAt  time.Time
	}
	if err := s.db.Raw(`
		SELECT DISTINCT ON (policy_id) policy_id, action, arm, outcome, dry_run, detail, acted_at
		  FROM agent_policy_actions
		 WHERE workspace_id = ? AND policy_id IN ?
		 ORDER BY policy_id, acted_at DESC, id DESC`, workspaceID, policyIDs).
		Scan(&last).Error; err != nil {
		return nil, err
	}
	outcomes := make(map[uuid.UUID]*LegacyReconcileOutcome, len(last))
	for i := range last {
		l := last[i]
		outcomes[l.PolicyID] = &LegacyReconcileOutcome{
			Action: l.Action, Arm: l.Arm, Outcome: l.Outcome, DryRun: l.DryRun,
			Detail: l.Detail, At: l.ActedAt,
		}
	}

	for i := range rows {
		p := &rows[i]
		p.Resolve()
		v := LegacyAgentPolicyView{
			ID: p.ID, Name: p.Name, Description: p.Description,
			Enabled: p.Enabled, DesiredState: p.DesiredState, OnExpiry: p.OnExpiry,
			EffectiveExpiry: p.EffectiveExpiry,
			LastReconcile:   outcomes[p.ID],
			CreatedBy:       p.CreatedBy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		}
		if p.DiscoveredAgentID != nil {
			v.Target = LegacyAgentPolicyTarget{Kind: "agent",
				DiscoveredAgentID: p.DiscoveredAgentID, AgentLabel: labels[*p.DiscoveredAgentID]}
		} else {
			v.Target = LegacyAgentPolicyTarget{Kind: "selector", Selector: p.Selector}
		}
		if p.Enabled && p.Destructive && p.EffectiveExpiry != nil {
			v.PendingDestructiveDeadline = p.EffectiveExpiry
		}
		out = append(out, v)
	}
	return out, nil
}

/* ------------------------- the legacy manager's pause ------------------------ */

// Pause sets a policy disabled. Every legacy consumer -- the reconcile worker,
// the warning scheduler, the enforcement plan, the lookahead -- reads enabled
// policies only, so a paused policy stops acting on its next pass. Nothing it
// already did is undone, and its recorded actions are kept.
//
// Idempotent: a policy already disabled is returned unchanged (updated_at is
// not bumped). gorm.ErrRecordNotFound for an id that is not this workspace's.
func (m *agentPolicyManager) Pause(workspaceID, id uuid.UUID) (*models.AgentPolicy, error) {
	res := m.db.Model(&models.AgentPolicy{}).
		Where("id = ? AND workspace_id = ? AND enabled", id, workspaceID).
		Updates(map[string]interface{}{"enabled": false, "updated_at": time.Now()})
	if res.Error != nil {
		return nil, res.Error
	}
	return m.Get(workspaceID, id)
}
