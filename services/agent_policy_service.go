package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// AgentPolicyManager is the declarative layer above enforcement.
//
// An operator attaches a policy to a claimed agent -- or to a selector matching many
// -- stating the end state they want. This reconciles toward it. Nothing here fires
// an action directly, which is the point: enforcement becomes the difference between
// what a policy says and what is true, so it works no matter how the state drifted
// and self-heals if something changed out of band.
//
// PHASE 1 IS DRY-RUN ONLY. Reconcile computes and records what it WOULD do and
// changes nothing. That is deliberate: the plan's correctness has to be provable
// against real data before anything acts on it.
type AgentPolicyManager interface {
	Create(workspaceID uuid.UUID, createdBy string, in AgentPolicyInput) (*models.AgentPolicy, error)
	Get(workspaceID, id uuid.UUID) (*models.AgentPolicy, error)
	List(workspaceID uuid.UUID, enabledOnly bool) ([]models.AgentPolicy, error)
	Delete(workspaceID, id uuid.UUID) error

	// Expand resolves a policy to the agents it currently covers. A direct policy
	// expands to one; a selector expands to whatever matches right now.
	Expand(workspaceID uuid.UUID, p *models.AgentPolicy) ([]models.DiscoveredAgent, error)

	// Effective resolves every policy matching one agent into a single desired state,
	// using the most-restrictive lattice.
	Effective(workspaceID, agentID uuid.UUID) (*EffectivePolicy, error)

	// Reconcile computes desired-vs-actual across the workspace. dryRun=false is not
	// yet implemented -- see the phase order in ENFORCEMENT-ARCHITECTURE.md §7.
	Reconcile(workspaceID uuid.UUID, dryRun bool) (*PolicyReconcileResult, error)

	// Upcoming is the lookahead: what this system will do to the cluster in the next
	// N days. A pull, so there is no delivery to fail -- it is the system of record
	// for scheduled destruction, and notification is escalation on top of it.
	Upcoming(workspaceID uuid.UUID, days int) ([]UpcomingAction, error)
}

// AgentPolicyInput is the validated create payload.
type AgentPolicyInput struct {
	Name              string
	Description       string
	DiscoveredAgentID *uuid.UUID
	Selector          *models.AgentPolicySelector
	ScopeCeiling      []string
	RoleCeilingID     *uuid.UUID
	DesiredState      string
	Duration          string // Go duration, e.g. "720h"
	ExpiresAt         *time.Time
	OnExpiry          string
	Reason            string
	ConfirmedBy       *uuid.UUID
	// ConfirmAgentIDs is the expansion the operator confirmed against. Required for a
	// destructive selector policy: one typed confirmation must not authorize deleting
	// workloads nobody enumerated.
	ConfirmAgentIDs []uuid.UUID
}

// EffectivePolicy is what all matching policies add up to for one agent.
type EffectivePolicy struct {
	AgentID uuid.UUID `json:"agent_id"`
	// DesiredState is the most restrictive across matching policies.
	DesiredState string `json:"desired_state"`
	// ScopeCeiling is the INTERSECTION of every ceiling that applies. nil means no
	// policy constrains scope.
	ScopeCeiling []string `json:"scope_ceiling,omitempty"`
	// RoleCeilingID is the NARROWEST role any matching policy names — the one
	// granting the fewest permissions. nil means no policy caps the role.
	RoleCeilingID *uuid.UUID `json:"role_ceiling_id,omitempty"`
	// Ambiguous is set when two policies name role ceilings that are INCOMPARABLE
	// (neither grants a subset of the other). Applying an arbitrary one would be a
	// coin flip on somebody's access, so nothing is applied and this says why.
	Ambiguous string `json:"ambiguous,omitempty"`
	// Policies that contributed, for explainability -- a reviewer must be able to see
	// which policy caused a state, not just the state.
	PolicyIDs []uuid.UUID `json:"policy_ids"`
}

// PolicyReconcileResult reports what a pass did, or would do.
type PolicyReconcileResult struct {
	DryRun          bool `json:"dry_run"`
	PoliciesActive  int  `json:"policies_active"`
	AgentsCovered   int  `json:"agents_covered"`
	WouldNarrow     int  `json:"would_narrow"`
	WouldQuarantine int  `json:"would_quarantine"`
	WouldRelease    int  `json:"would_release"`
	WouldRevoke     int  `json:"would_revoke"`
	WouldEvict      int  `json:"would_evict"`
	Refused         int  `json:"refused"`
	// Applied counts, non-zero only on a live run.
	BindingsNarrowed int      `json:"bindings_narrowed"`
	GrantsLapsed     int64    `json:"grants_lapsed"`
	Errors           []string `json:"errors,omitempty"`
}

// UpcomingAction is one scheduled effect, for the lookahead.
type UpcomingAction struct {
	PolicyID    uuid.UUID `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	AgentID     uuid.UUID `json:"discovered_agent_id"`
	AgentLabel  string    `json:"agent_label"`
	Action      string    `json:"action"`
	Destructive bool      `json:"destructive"`
	At          time.Time `json:"at"`
	Reason      string    `json:"reason"`
	// Confirmed reports whether THIS agent is covered by a confirmation. A
	// destructive action on an unconfirmed agent will be refused, and the lookahead
	// is where an operator should see that before the deadline rather than after.
	Confirmed bool `json:"confirmed"`
	// GitOpsManaged means deleting this workload will not stick -- a reconciler
	// recreates it. Surfaced here because a policy that cannot do what it says is
	// worth knowing about while there is still time to change it.
	GitOpsManaged bool   `json:"gitops_managed"`
	AuthorActive  bool   `json:"author_active"`
	CreatedBy     string `json:"created_by"`
}

type agentPolicyManager struct{ db *gorm.DB }

// NewAgentPolicyManager constructs an AgentPolicyManager.
func NewAgentPolicyManager(db *gorm.DB) AgentPolicyManager { return &agentPolicyManager{db: db} }

/* --------------------------------- create -------------------------------- */

func (m *agentPolicyManager) Create(workspaceID uuid.UUID, createdBy string,
	in AgentPolicyInput) (*models.AgentPolicy, error) {

	if strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("name is required")
	}
	// Exactly one target. The DB enforces this too; catching it here yields a usable
	// message instead of a constraint violation.
	if (in.DiscoveredAgentID == nil) == (in.Selector == nil) {
		return nil, errors.New("give either discovered_agent_id or selector, not both and not neither")
	}
	if in.Selector != nil && in.Selector.IsEmpty() {
		return nil, errors.New("an empty selector would match every agent in the workspace; " +
			"name at least one of cluster, namespace, labels, archetype, deployment_origin, framework")
	}

	state := in.DesiredState
	if state == "" {
		state = models.AgentPolicyStateActive
	}
	if !containsString(models.ValidAgentPolicyStates(), state) {
		return nil, fmt.Errorf("desired_state must be one of %v", models.ValidAgentPolicyStates())
	}

	onExpiry := in.OnExpiry
	if onExpiry == "" {
		onExpiry = models.OnExpiryRevoke
	}
	if !containsString(models.ValidOnExpiry(), onExpiry) {
		return nil, fmt.Errorf("on_expiry must be one of %v", models.ValidOnExpiry())
	}

	// One clock, or none.
	if in.Duration != "" && in.ExpiresAt != nil {
		return nil, errors.New("give either duration or expires_at, not both")
	}
	var dur *models.PGInterval
	if in.Duration != "" {
		d, err := time.ParseDuration(in.Duration)
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
		if d <= 0 {
			return nil, errors.New("duration must be positive")
		}
		iv := models.PGInterval(d)
		dur = &iv
	}
	if onExpiry != models.OnExpiryRevoke && dur == nil && in.ExpiresAt == nil {
		return nil, fmt.Errorf("on_expiry=%q needs a clock: set duration or expires_at, "+
			"or it can never fire", onExpiry)
	}

	// Pre-authorization for a destructive expiry.
	destructive := models.OnExpiryIsDestructive(onExpiry)
	if destructive {
		if strings.TrimSpace(in.Reason) == "" {
			return nil, errors.New("a destructive on_expiry requires a reason: it executes " +
				"unattended, so this is the only explanation anyone will have")
		}
		if in.ConfirmedBy == nil {
			return nil, errors.New("a destructive on_expiry requires an attributable confirmation")
		}
		if in.Selector != nil && len(in.ConfirmAgentIDs) == 0 {
			return nil, errors.New("a destructive selector policy must confirm against the " +
				"EXPANSION: pass the agent ids you are authorizing. One confirmation must not " +
				"delete workloads nobody enumerated")
		}
	}

	var selectorJSON json.RawMessage
	if in.Selector != nil {
		b, err := json.Marshal(in.Selector)
		if err != nil {
			return nil, fmt.Errorf("marshal selector: %w", err)
		}
		selectorJSON = b
	}

	now := time.Now()
	p := &models.AgentPolicy{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		Name:              strings.TrimSpace(in.Name),
		Description:       in.Description,
		DiscoveredAgentID: in.DiscoveredAgentID,
		Selector:          selectorJSON,
		ScopeCeiling:      pq.StringArray(in.ScopeCeiling),
		RoleCeilingID:     in.RoleCeilingID,
		DesiredState:      state,
		Duration:          dur,
		ExpiresAt:         in.ExpiresAt,
		OnExpiry:          onExpiry,
		Reason:            in.Reason,
		ConfirmedBy:       in.ConfirmedBy,
		Enabled:           true,
		CreatedBy:         createdBy,
	}
	if destructive {
		p.ConfirmedAt = &now
	}

	// One transaction: a destructive policy must never exist without the
	// confirmation that authorizes it.
	err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(p).Error; err != nil {
			return err
		}
		if destructive {
			ids := make(pq.StringArray, 0, len(in.ConfirmAgentIDs))
			if in.DiscoveredAgentID != nil {
				ids = append(ids, in.DiscoveredAgentID.String())
			}
			for _, id := range in.ConfirmAgentIDs {
				ids = append(ids, id.String())
			}
			return tx.Create(&models.AgentPolicyConfirmation{
				ID:               uuid.New(),
				WorkspaceID:      workspaceID,
				PolicyID:         p.ID,
				ExpandedAgentIDs: ids,
				OnExpiry:         onExpiry,
				Reason:           in.Reason,
				ConfirmedBy:      *in.ConfirmedBy,
				ConfirmedAt:      now,
			}).Error
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m.Get(workspaceID, p.ID)
}

/* ---------------------------------- read --------------------------------- */

func (m *agentPolicyManager) Get(workspaceID, id uuid.UUID) (*models.AgentPolicy, error) {
	var p models.AgentPolicy
	if err := m.db.First(&p, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	p.Resolve()
	if p.Selector != nil {
		if agents, err := m.Expand(workspaceID, &p); err == nil {
			n := len(agents)
			p.MatchedAgents = &n
		}
	}
	return &p, nil
}

func (m *agentPolicyManager) List(workspaceID uuid.UUID, enabledOnly bool) ([]models.AgentPolicy, error) {
	q := m.db.Where("workspace_id = ?", workspaceID)
	if enabledOnly {
		q = q.Where("enabled")
	}
	var out []models.AgentPolicy
	if err := q.Order("created_at DESC").Find(&out).Error; err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Resolve()
		if out[i].Selector != nil {
			if agents, err := m.Expand(workspaceID, &out[i]); err == nil {
				n := len(agents)
				out[i].MatchedAgents = &n
			}
		}
	}
	return out, nil
}

func (m *agentPolicyManager) Delete(workspaceID, id uuid.UUID) error {
	res := m.db.Where("id = ? AND workspace_id = ?", id, workspaceID).
		Delete(&models.AgentPolicy{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

/* -------------------------------- expansion ------------------------------ */

// Expand resolves a policy to the agents it covers right now.
//
// The selector is evaluated HERE, in the control plane. The in-cluster agent only
// ever receives an explicit fingerprint list, so a broad selector produces a longer
// list but never a broader predicate -- which is what keeps a detection bug from
// becoming a cluster-wide denial.
func (m *agentPolicyManager) Expand(workspaceID uuid.UUID,
	p *models.AgentPolicy) ([]models.DiscoveredAgent, error) {

	if p.DiscoveredAgentID != nil {
		var a models.DiscoveredAgent
		if err := m.db.First(&a, "id = ? AND workspace_id = ?",
			*p.DiscoveredAgentID, workspaceID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil // the agent was deleted; the policy covers nothing
			}
			return nil, err
		}
		return []models.DiscoveredAgent{a}, nil
	}
	if p.Selector == nil {
		return nil, nil
	}

	var sel models.AgentPolicySelector
	if err := json.Unmarshal(p.Selector, &sel); err != nil {
		return nil, fmt.Errorf("undecodable selector on policy %s: %w", p.ID, err)
	}
	if sel.IsEmpty() {
		// Refuse rather than match everything. A stored empty selector means someone
		// bypassed Create, and treating it as "all agents" would be the worst
		// possible interpretation.
		return nil, fmt.Errorf("policy %s has an empty selector; refusing to treat that "+
			"as every agent in the workspace", p.ID)
	}

	q := m.db.Model(&models.DiscoveredAgent{}).Where("workspace_id = ?", workspaceID)

	// Only agents under management. An unclaimed sighting has no owner and no
	// entitlements, so there is nothing for a policy to narrow or revoke.
	q = q.Where("status IN ?", []string{
		models.DiscoveredAgentRegistered, models.DiscoveredAgentQuarantined,
	})

	if sel.Namespace != "" {
		q = q.Where("metadata->'kubernetes'->>'namespace' = ?", sel.Namespace)
	}
	if sel.Cluster != "" {
		q = q.Where("metadata->'cluster'->>'name' = ?", sel.Cluster)
	}
	if sel.Archetype != "" {
		q = q.Where("archetype = ?", sel.Archetype)
	}
	if sel.DeploymentOrigin != "" {
		q = q.Where("deployment_origin = ?", sel.DeploymentOrigin)
	}
	if sel.Framework != "" {
		// jsonb containment against the detected framework array.
		q = q.Where("metadata->'detection'->'frameworks' @> ?",
			fmt.Sprintf(`["%s"]`, sel.Framework))
	}
	for k, v := range sel.Labels {
		q = q.Where("metadata->'kubernetes'->'labels'->>? = ?", k, v)
	}

	var out []models.DiscoveredAgent
	if err := q.Order("created_at ASC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

/* --------------------------- the lattice --------------------------------- */

// Effective resolves every policy matching one agent into a single desired state.
//
// Most-restrictive wins, per field, so the outcome is computable rather than
// dependent on evaluation order:
//
//   - desired_state: 'quarantined' beats 'active'
//   - scope_ceiling: set INTERSECTION
//
// That is PG-5 at the policy layer -- overlapping policies fail toward LESS access,
// and a policy bug can never widen anything.
//
// on_expiry is deliberately NOT resolved here. It is the one field where "more
// restrictive" means "more destructive", so escalating to evict because some broad
// policy said so would be backwards. Each policy's expiry acts on its own clock, with
// its own confirmation.
func (m *agentPolicyManager) Effective(workspaceID, agentID uuid.UUID) (*EffectivePolicy, error) {
	policies, err := m.List(workspaceID, true)
	if err != nil {
		return nil, err
	}

	eff := &EffectivePolicy{
		AgentID:      agentID,
		DesiredState: models.AgentPolicyStateActive,
		PolicyIDs:    []uuid.UUID{},
	}
	var ceilings [][]string
	var roleCeilings []uuid.UUID

	for i := range policies {
		p := &policies[i]
		agents, err := m.Expand(workspaceID, p)
		if err != nil {
			continue // a broken selector must not take out the whole resolution
		}
		covered := false
		for _, a := range agents {
			if a.ID == agentID {
				covered = true
				break
			}
		}
		if !covered {
			continue
		}
		eff.PolicyIDs = append(eff.PolicyIDs, p.ID)

		if p.DesiredState == models.AgentPolicyStateQuarantined {
			eff.DesiredState = models.AgentPolicyStateQuarantined
		}
		if len(p.ScopeCeiling) > 0 {
			ceilings = append(ceilings, []string(p.ScopeCeiling))
		}
		if p.RoleCeilingID != nil {
			roleCeilings = append(roleCeilings, *p.RoleCeilingID)
		}
	}

	// Narrowest role ceiling wins, by permission-set containment. Two ceilings that
	// are incomparable are NOT silently resolved: picking one would decide somebody's
	// access by evaluation order.
	if len(roleCeilings) > 0 {
		winner, amb, err := m.narrowestRole(roleCeilings)
		if err != nil {
			return nil, err
		}
		if amb != "" {
			eff.Ambiguous = amb
		} else {
			eff.RoleCeilingID = &winner
		}
	}

	if len(ceilings) > 0 {
		eff.ScopeCeiling = intersectScopes(ceilings)
	}
	return eff, nil
}

// intersectScopes returns the scopes present in EVERY ceiling. Sorted, so the result
// is stable and comparable across runs.
func intersectScopes(sets [][]string) []string {
	counts := map[string]int{}
	for _, s := range sets {
		seen := map[string]bool{}
		for _, v := range s {
			if seen[v] {
				continue // a ceiling listing a scope twice must not count twice
			}
			seen[v] = true
			counts[v]++
		}
	}
	out := []string{}
	for v, n := range counts {
		if n == len(sets) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

/* ------------------------------ reconciliation --------------------------- */

// Reconcile computes desired-vs-actual across the workspace and records what it
// would do.
//
// PHASE 1: dryRun=false is refused. The plan's correctness has to be provable against
// real data before anything acts on it, and every action this would take is either
// reversible-but-disruptive (quarantine) or irreversible (evict). See the phase order
// in ENFORCEMENT-ARCHITECTURE.md §7.
func (m *agentPolicyManager) Reconcile(workspaceID uuid.UUID,
	dryRun bool) (*PolicyReconcileResult, error) {

	// PHASE 2: a live run executes the ENTITLEMENT arm only — scope/role narrowing
	// and revoke-on-expiry. Those are control-plane effects: nothing is written to a
	// cluster, no reconciler can undo them, and editing the policy reverses them.
	//
	// The CLUSTER arm still only plans. Quarantine, eviction and deletion arrive in
	// phases 5-7, on machinery this phase is proving first.

	policies, err := m.List(workspaceID, true)
	if err != nil {
		return nil, err
	}
	res := &PolicyReconcileResult{DryRun: dryRun, PoliciesActive: len(policies)}

	// Every agent any policy touches, so an agent covered by two policies is counted
	// and resolved once rather than twice.
	covered := map[uuid.UUID]bool{}
	for i := range policies {
		agents, err := m.Expand(workspaceID, &policies[i])
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("policy %s: %v", policies[i].ID, err))
			continue
		}
		for _, a := range agents {
			covered[a.ID] = true
		}
	}
	res.AgentsCovered = len(covered)

	now := time.Now()
	for agentID := range covered {
		var agent models.DiscoveredAgent
		if err := m.db.First(&agent, "id = ? AND workspace_id = ?", agentID, workspaceID).Error; err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("agent %s: %v", agentID, err))
			continue
		}
		eff, err := m.Effective(workspaceID, agentID)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("agent %s: %v", agentID, err))
			continue
		}

		// --- the cluster arm: containment state ---
		switch {
		case eff.DesiredState == models.AgentPolicyStateQuarantined &&
			agent.Status != models.DiscoveredAgentQuarantined:
			res.WouldQuarantine++
			m.clusterPlanned(workspaceID, eff, &agent, dryRun, models.PolicyActionQuarantined,
				"policy asks for quarantined; agent is "+agent.Status)

		case eff.DesiredState == models.AgentPolicyStateActive &&
			agent.Status == models.DiscoveredAgentQuarantined:
			// Drift the other way: something quarantined this agent out of band and
			// no policy asks for it. Reconciliation is symmetric by design -- it
			// converges, it does not only tighten.
			res.WouldRelease++
			m.clusterPlanned(workspaceID, eff, &agent, dryRun, models.PolicyActionReleased,
				"no active policy asks for quarantine")
		}

		// --- the entitlement arm ---
		//
		// An ambiguous role ceiling applies NOTHING. Two policies naming incomparable
		// ceilings is a question for a human, not a coin flip on someone's access.
		if eff.Ambiguous != "" {
			res.Refused++
			m.record(&models.AgentPolicyAction{
				WorkspaceID: workspaceID, DiscoveredAgentID: &agent.ID,
				Action: models.PolicyActionNoop, Arm: models.PolicyArmEntitlement,
				DryRun: dryRun, Outcome: models.PolicyOutcomeRefused,
				Detail: "REFUSED: " + eff.Ambiguous,
			})
			continue
		}

		// A scope ceiling is EVALUATED, never applied: scopes derive from a role's
		// permissions, so honouring an arbitrary one would mean synthesising a role,
		// which is a widen arrived at from the other direction. Report the excess.
		if len(eff.ScopeCeiling) > 0 {
			over, serr := m.evaluateScopeCeiling(workspaceID, &agent, eff.ScopeCeiling)
			if serr != nil {
				res.Errors = append(res.Errors, serr.Error())
			} else if len(over) > 0 {
				res.Refused++
				m.record(&models.AgentPolicyAction{
					WorkspaceID: workspaceID, DiscoveredAgentID: &agent.ID,
					Action: models.PolicyActionNoop, Arm: models.PolicyArmEntitlement,
					DryRun: dryRun, Outcome: models.PolicyOutcomeRefused,
					Detail: "scopes held beyond the ceiling: " + strings.Join(over, ",") +
						" — bind a narrower role (role_ceiling_id) or revoke; a scope " +
						"ceiling alone cannot narrow a role",
				})
			}
		}

		if eff.RoleCeilingID != nil {
			if dryRun {
				res.WouldNarrow++
				m.clusterOrEntitlementPlanned(workspaceID, eff, &agent,
					models.PolicyActionNarrowed, models.PolicyArmEntitlement,
					"would bind to ceiling role "+eff.RoleCeilingID.String())
			} else {
				out, aerr := m.applyEntitlementArm(workspaceID, &agent, eff, nil)
				if aerr != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("agent %s: %v", agent.ID, aerr))
				} else {
					res.BindingsNarrowed += out.Narrowed
					if out.Narrowed > 0 {
						res.WouldNarrow++
						m.applied(workspaceID, eff, &agent, models.PolicyActionNarrowed,
							models.PolicyArmEntitlement,
							fmt.Sprintf("bound %d binding(s) to ceiling role %s",
								out.Narrowed, eff.RoleCeilingID))
					}
					if out.Refusal != "" {
						res.Refused++
						m.record(&models.AgentPolicyAction{
							WorkspaceID: workspaceID, DiscoveredAgentID: &agent.ID,
							Action: models.PolicyActionNoop, Arm: models.PolicyArmEntitlement,
							DryRun: false, Outcome: models.PolicyOutcomeRefused,
							Detail: "REFUSED: " + out.Refusal,
						})
					}
				}
			}
		}
	}

	// --- expiry, per policy, on its own clock ---
	//
	// Not resolved through the lattice: on_expiry is the one field where "more
	// restrictive" means "more destructive", so each policy acts on its own terms
	// with its own confirmation rather than escalating one another.
	for i := range policies {
		p := &policies[i]
		if p.EffectiveExpiry == nil || p.EffectiveExpiry.After(now) {
			continue
		}
		agents, err := m.Expand(workspaceID, p)
		if err != nil {
			continue
		}
		for j := range agents {
			a := &agents[j]
			switch p.OnExpiry {
			case models.OnExpiryRevoke:
				res.WouldRevoke++
				if dryRun {
					m.plannedFor(workspaceID, p, a, models.PolicyActionRevoked,
						models.PolicyArmEntitlement, "policy expired")
					continue
				}
				// Live: make the grants lapse. The EXPIRY WORKER does the actual
				// revocation on its next pass (1m) -- closing provenance, killing
				// live tokens, deleting the binding, in one transaction.
				//
				// That indirection is PG-6, not laziness: revocation has exactly one
				// implementation, and a second one here would be two places that
				// must stay in step forever.
				out, aerr := m.applyEntitlementArm(workspaceID, a, nil,
					[]*models.AgentPolicy{p})
				if aerr != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("agent %s: %v", a.ID, aerr))
					continue
				}
				res.GrantsLapsed += out.Lapsed
				m.appliedFor(workspaceID, p, a, models.PolicyActionRevoked,
					models.PolicyArmEntitlement,
					fmt.Sprintf("%d grant(s) lapsed; the expiry worker revokes them on "+
						"its next pass", out.Lapsed))
			case models.OnExpiryQuarantine:
				res.WouldQuarantine++
				m.plannedFor(workspaceID, p, a, models.PolicyActionQuarantined,
					models.PolicyArmCluster, "policy expired")
			case models.OnExpiryEvict:
				// A destructive action is REFUSED for any agent the confirmation
				// does not name. This is the rule that stops an agent which started
				// matching a selector later from being deleted under an older
				// authorization.
				ok, cerr := m.confirmationCovers(workspaceID, p.ID, a.ID)
				if cerr != nil {
					res.Errors = append(res.Errors, cerr.Error())
					continue
				}
				if !ok {
					res.Refused++
					m.refusedFor(workspaceID, p, a,
						"not covered by the confirmation on this policy: it was authorized "+
							"against a different expansion, so deleting this agent needs a "+
							"fresh confirmation naming it")
					continue
				}
				res.WouldEvict++
				m.plannedFor(workspaceID, p, a, models.PolicyActionEvicted,
					models.PolicyArmCluster, "policy expired: "+p.Reason)
			}
		}
	}
	return res, nil
}

// confirmationCovers reports whether a stored confirmation on this policy names this
// agent. Snapshotted expansions, not a recomputed selector -- the question is what
// the operator actually authorized, not what the selector matches today.
func (m *agentPolicyManager) confirmationCovers(workspaceID, policyID, agentID uuid.UUID) (bool, error) {
	var n int64
	err := m.db.Model(&models.AgentPolicyConfirmation{}).
		Where(`workspace_id = ? AND policy_id = ? AND ? = ANY(expanded_agent_ids)`,
			workspaceID, policyID, agentID.String()).
		Count(&n).Error
	if err != nil {
		return false, fmt.Errorf("check confirmation for policy %s: %w", policyID, err)
	}
	return n > 0, nil
}

// clusterPlanned records a cluster-arm action that was computed but not executed.
//
// On a LIVE run this is 'refused', not 'planned', and the distinction is the honest
// one: the plan was correct and the capability does not exist yet. Recording it as
// planned would let an operator read a live reconcile as having done something.
func (m *agentPolicyManager) clusterPlanned(workspaceID uuid.UUID, eff *EffectivePolicy,
	agent *models.DiscoveredAgent, dryRun bool, action, detail string) {

	outcome, prefix := models.PolicyOutcomePlanned, ""
	if !dryRun {
		outcome = models.PolicyOutcomeRefused
		prefix = "cluster arm not implemented until phase 5: "
	}
	var policyID *uuid.UUID
	if len(eff.PolicyIDs) > 0 {
		policyID = &eff.PolicyIDs[0]
	}
	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: policyID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: models.PolicyArmCluster, DryRun: dryRun,
		Outcome: outcome, Detail: prefix + detail,
	})
}

// clusterOrEntitlementPlanned records a dry-run intent on either arm.
func (m *agentPolicyManager) clusterOrEntitlementPlanned(workspaceID uuid.UUID,
	eff *EffectivePolicy, agent *models.DiscoveredAgent, action, arm, detail string) {

	var policyID *uuid.UUID
	if len(eff.PolicyIDs) > 0 {
		policyID = &eff.PolicyIDs[0]
	}
	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: policyID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: arm, DryRun: true,
		Outcome: models.PolicyOutcomePlanned, Detail: detail,
	})
}

// applied records an entitlement-arm change that actually happened.
func (m *agentPolicyManager) applied(workspaceID uuid.UUID, eff *EffectivePolicy,
	agent *models.DiscoveredAgent, action, arm, detail string) {

	var policyID *uuid.UUID
	if len(eff.PolicyIDs) > 0 {
		policyID = &eff.PolicyIDs[0]
	}
	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: policyID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: arm, DryRun: false,
		Outcome: models.PolicyOutcomeApplied, Detail: detail,
	})
}

// planned records an intended action from a resolved effective policy.
func (m *agentPolicyManager) planned(workspaceID uuid.UUID, eff *EffectivePolicy,
	agent *models.DiscoveredAgent, action, arm, detail string) {

	var policyID *uuid.UUID
	if len(eff.PolicyIDs) > 0 {
		// Attribute to the first contributing policy; PolicyIDs carries the rest for
		// explainability.
		policyID = &eff.PolicyIDs[0]
	}
	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: policyID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: arm, DryRun: true,
		Outcome: models.PolicyOutcomePlanned, Detail: detail,
	})
}

func (m *agentPolicyManager) plannedFor(workspaceID uuid.UUID, p *models.AgentPolicy,
	agent *models.DiscoveredAgent, action, arm, detail string) {

	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: &p.ID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: arm, Reason: p.Reason, DryRun: true,
		Outcome: models.PolicyOutcomePlanned, Detail: detail,
	})
}

func (m *agentPolicyManager) refusedFor(workspaceID uuid.UUID, p *models.AgentPolicy,
	agent *models.DiscoveredAgent, detail string) {

	// Refusals are recorded even in a dry run: "this policy will not do what it says"
	// is exactly what an operator needs to see BEFORE the deadline.
	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: &p.ID, DiscoveredAgentID: &agent.ID,
		Action: models.PolicyActionNoop, Arm: models.PolicyArmCluster,
		Reason: p.Reason, DryRun: true,
		Outcome: models.PolicyOutcomePlanned, Detail: "REFUSED: " + detail,
	})
}

// record is best-effort. Losing an audit row must not fail the reconcile pass, which
// would leave the workspace un-reconciled over a logging problem.
func (m *agentPolicyManager) record(a *models.AgentPolicyAction) {
	a.ID = uuid.New()
	a.ActedAt = time.Now()
	if err := m.db.Create(a).Error; err != nil {
		// Deliberately swallowed after logging: see above.
		fmt.Printf("[agent-policy] could not record action %s/%s: %v\n", a.Action, a.Arm, err)
	}
}

/* -------------------------------- lookahead ------------------------------ */

// Upcoming answers "what will this system do to my cluster in the next N days".
//
// This is the system of record for scheduled destruction, not the notification.
// It is a pull, so there is nothing to deliver and nothing to fail -- email and
// webhooks are escalation layered on top of it.
func (m *agentPolicyManager) Upcoming(workspaceID uuid.UUID, days int) ([]UpcomingAction, error) {
	if days <= 0 || days > 365 {
		days = 7
	}
	horizon := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	policies, err := m.List(workspaceID, true)
	if err != nil {
		return nil, err
	}

	out := []UpcomingAction{}
	for i := range policies {
		p := &policies[i]
		if p.EffectiveExpiry == nil || p.EffectiveExpiry.After(horizon) {
			continue
		}
		agents, err := m.Expand(workspaceID, p)
		if err != nil {
			continue
		}
		authorActive := m.authorIsActive(p.CreatedBy)
		for j := range agents {
			a := &agents[j]
			confirmed := true
			if models.OnExpiryIsDestructive(p.OnExpiry) {
				confirmed, _ = m.confirmationCovers(workspaceID, p.ID, a.ID)
			}
			out = append(out, UpcomingAction{
				PolicyID: p.ID, PolicyName: p.Name,
				AgentID: a.ID, AgentLabel: a.DisplayName,
				Action:        p.OnExpiry,
				Destructive:   models.OnExpiryIsDestructive(p.OnExpiry),
				At:            *p.EffectiveExpiry,
				Reason:        p.Reason,
				Confirmed:     confirmed,
				GitOpsManaged: gitOpsManaged(a.Metadata),
				AuthorActive:  authorActive,
				CreatedBy:     p.CreatedBy,
			})
		}
	}
	// Soonest first: the lookahead is a queue of things about to happen.
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// authorIsActive reports whether the policy's author is still an active user.
//
// A destructive policy whose author has since left still executes -- the decision was
// validly made and recorded at the time, and auto-cancelling it would be the same
// silent-non-execution failure the pre-authorization model exists to avoid. But it is
// worth a reviewer's attention, so the lookahead surfaces it.
func (m *agentPolicyManager) authorIsActive(createdBy string) bool {
	if createdBy == "" {
		return false
	}
	id, err := uuid.Parse(createdBy)
	if err != nil {
		return true // not a user id (a service principal); nothing to check
	}
	var n int64
	// `active` is the authoritative column. `is_active` is a vestigial duplicate with
	// no writer, and reading it would make every departed author look present.
	if err := m.db.Table("users").Where("id = ? AND active", id).Count(&n).Error; err != nil {
		return true // unknown is not evidence of absence
	}
	return n > 0
}

// gitOpsManaged reports whether a reconciler owns this workload, in which case
// deleting it will not stick.
//
// Read from the labels discovery already captures. Surfaced in the lookahead because
// a policy that cannot do what it says is worth knowing about while there is still
// time to change it.
func gitOpsManaged(metadata json.RawMessage) bool {
	if len(metadata) == 0 {
		return false
	}
	var m struct {
		Kubernetes struct {
			Labels map[string]string `json:"labels"`
		} `json:"kubernetes"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return false
	}
	for k, v := range m.Kubernetes.Labels {
		if strings.HasPrefix(k, "argocd.argoproj.io/") ||
			strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") {
			return true
		}
		if k == "app.kubernetes.io/managed-by" {
			switch strings.ToLower(v) {
			case "helm", "argocd", "flux", "kustomize", "terraform", "pulumi":
				return true
			}
		}
	}
	return false
}

// narrowestRole picks the role granting the fewest permissions among the ceilings a
// set of policies names, and reports ambiguity rather than guessing.
//
// "Narrowest" is containment, not cardinality: role A beats role B only if A's
// permissions are a strict subset of B's. Two roles that merely differ in size are
// incomparable — a 3-permission role granting deletes is not narrower than a
// 5-permission read-only one — and resolving that by count would quietly pick the
// more dangerous role about as often as not.
func (m *agentPolicyManager) narrowestRole(ids []uuid.UUID) (uuid.UUID, string, error) {
	perms := map[uuid.UUID]map[uuid.UUID]bool{}
	for _, id := range ids {
		if _, seen := perms[id]; seen {
			continue
		}
		p, err := rolePermissionIDs(m.db, id)
		if err != nil {
			return uuid.Nil, "", err
		}
		perms[id] = p
	}

	best := ids[0]
	for _, id := range ids {
		if id == best {
			continue
		}
		switch {
		case len(notSubset(perms[id], perms[best])) == 0:
			// id grants nothing beyond best -> id is narrower (or equal).
			best = id
		case len(notSubset(perms[best], perms[id])) == 0:
			// best is already the narrower one.
		default:
			return uuid.Nil, fmt.Sprintf(
				"role ceilings %s and %s are incomparable — neither grants a subset of "+
					"the other, so no ceiling was applied. Resolve the overlap before "+
					"either can take effect", best, id), nil
		}
	}
	return best, "", nil
}

// appliedFor records an executed action attributed to one specific policy.
func (m *agentPolicyManager) appliedFor(workspaceID uuid.UUID, p *models.AgentPolicy,
	agent *models.DiscoveredAgent, action, arm, detail string) {

	m.record(&models.AgentPolicyAction{
		WorkspaceID: workspaceID, PolicyID: &p.ID, DiscoveredAgentID: &agent.ID,
		Action: action, Arm: arm, Reason: p.Reason, DryRun: false,
		Outcome: models.PolicyOutcomeApplied, Detail: detail,
	})
}
