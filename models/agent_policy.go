package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Desired cluster state a policy asks for.
const (
	AgentPolicyStateActive      = "active"
	AgentPolicyStateQuarantined = "quarantined"
)

// What happens when a policy's clock runs out.
//
// 'revoke' is the default deliberately: it is today's behaviour -- entitlements lapse
// and the workload is untouched -- so the blast radius of a mis-set expiry is lost
// access rather than a deleted production workload.
const (
	OnExpiryRevoke     = "revoke"
	OnExpiryQuarantine = "quarantine"
	OnExpiryEvict      = "evict"
)

// Which arm of the policy an action belongs to. The distinction is the point: the
// entitlement arm never reaches the cluster and is instantly reversible; the cluster
// arm carries every caveat in ENFORCEMENT-ARCHITECTURE.md §3.
const (
	PolicyArmEntitlement = "entitlement"
	PolicyArmCluster     = "cluster"
)

// What the reconciler did.
const (
	PolicyActionNarrowed    = "narrowed"
	PolicyActionRevoked     = "revoked"
	PolicyActionQuarantined = "quarantined"
	PolicyActionReleased    = "released"
	PolicyActionEvicted     = "evicted"
	PolicyActionNoop        = "noop"
)

// How it went. 'planned' is what a dry run records -- a DB CHECK forbids a dry run
// from claiming it applied anything.
const (
	PolicyOutcomeApplied = "applied"
	PolicyOutcomeFailed  = "failed"
	PolicyOutcomeRefused = "refused"
	PolicyOutcomePlanned = "planned"
)

// ValidAgentPolicyStates returns the desired states a policy may ask for.
func ValidAgentPolicyStates() []string {
	return []string{AgentPolicyStateActive, AgentPolicyStateQuarantined}
}

// ValidOnExpiry returns the expiry actions a policy may declare.
func ValidOnExpiry() []string {
	return []string{OnExpiryRevoke, OnExpiryQuarantine, OnExpiryEvict}
}

// OnExpiryIsDestructive reports whether an expiry action removes the workload, and
// therefore requires a reason plus a recorded confirmation (enforced by
// agent_policies_destructive_chk as well as here).
func OnExpiryIsDestructive(a string) bool { return a == OnExpiryEvict }

// AgentPolicySelector is the match expression the RECONCILER expands. It never
// reaches the in-cluster agent, which only ever receives an explicit fingerprint
// list -- so a broad selector can produce a longer list but never a broader
// predicate.
//
// Declared dimensions (Cluster, Namespace, Labels) are stable. Inferred ones
// (DeploymentOrigin, Framework) shift membership when classification or the detection
// vocabulary changes, which means a policy nobody re-read can quietly cover new
// workloads. The console marks those as inferred; the lookahead is what makes a
// membership change visible before it acts.
type AgentPolicySelector struct {
	Cluster   string            `json:"cluster,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Archetype string            `json:"archetype,omitempty"`
	// Inferred — see above.
	DeploymentOrigin string `json:"deployment_origin,omitempty"`
	Framework        string `json:"framework,omitempty"`
}

// IsEmpty reports whether a selector would match everything. A policy with an empty
// selector is refused rather than silently applied to the whole workspace.
func (s AgentPolicySelector) IsEmpty() bool {
	return s.Cluster == "" && s.Namespace == "" && len(s.Labels) == 0 &&
		s.Archetype == "" && s.DeploymentOrigin == "" && s.Framework == ""
}

// UsesInferredFields reports whether this selector matches on classification output
// rather than declared facts, so callers can warn.
func (s AgentPolicySelector) UsesInferredFields() bool {
	return s.DeploymentOrigin != "" || s.Framework != ""
}

// AgentPolicy is the declarative statement of what an operator wants true of an
// agent. The reconciler works toward it on a timer; nothing here fires an action
// directly.
//
// Deliberately the same shape as BirthrightPolicy, which established the pattern for
// humans: a duration, an action on a condition, a justification, an enabled flag.
type AgentPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description" gorm:"not null;default:''"`

	// Target: exactly one of these. A DB CHECK makes "both" and "neither"
	// unrepresentable rather than merely discouraged.
	DiscoveredAgentID *uuid.UUID      `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`
	Selector          json.RawMessage `json:"selector,omitempty" gorm:"type:jsonb"`

	// Arm 1: entitlement. A CEILING, never a grant -- effective access is the
	// intersection of this and what was provisioned (PG-5).
	ScopeCeiling  pq.StringArray `json:"scope_ceiling,omitempty" gorm:"type:text[]"`
	RoleCeilingID *uuid.UUID     `json:"role_ceiling_id,omitempty" gorm:"type:uuid"`

	// Arm 2: cluster.
	DesiredState string `json:"desired_state" gorm:"not null;default:'active'"`

	// Clock. One or the other, never both.
	Duration  *PGInterval `json:"duration,omitempty" gorm:"type:interval"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`

	OnExpiry string `json:"on_expiry" gorm:"not null;default:'revoke'"`

	// Pre-authorization. A destructive on_expiry executes unattended, so the reason
	// and confirmation are captured at AUTHORING time -- the policy is the
	// authorization.
	Reason      string     `json:"reason" gorm:"not null;default:''"`
	ConfirmedBy *uuid.UUID `json:"confirmed_by,omitempty" gorm:"type:uuid"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`

	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Computed on read, never stored.
	//
	// EffectiveExpiry resolves Duration against CreatedAt so callers do not each
	// reimplement it, and Destructive saves every caller from knowing which expiry
	// actions remove a workload.
	EffectiveExpiry *time.Time `json:"effective_expiry,omitempty" gorm:"-"`
	Destructive     bool       `json:"destructive" gorm:"-"`
	// MatchedAgents is populated by the reconciler and the lookahead: how many agents
	// a selector currently expands to. Absent for a direct policy.
	MatchedAgents *int `json:"matched_agents,omitempty" gorm:"-"`
}

func (AgentPolicy) TableName() string { return "agent_policies" }

// Resolve fills the computed fields. Called on every read path.
func (p *AgentPolicy) Resolve() {
	p.Destructive = OnExpiryIsDestructive(p.OnExpiry)
	switch {
	case p.ExpiresAt != nil:
		p.EffectiveExpiry = p.ExpiresAt
	case p.Duration != nil && time.Duration(*p.Duration) > 0:
		// Measured from creation, not from "now": otherwise a policy's deadline would
		// slide forward every time anybody read it.
		t := p.CreatedAt.Add(time.Duration(*p.Duration))
		p.EffectiveExpiry = &t
	default:
		p.EffectiveExpiry = nil
	}
}

// AgentPolicyConfirmation records what a confirmation was actually bound to.
//
// A selector policy carrying a destructive on_expiry confirms against the EXPANSION
// -- these named agents -- never against the selector. One typed confirmation must
// not authorize deleting workloads nobody enumerated, and an agent that starts
// matching the selector later is not covered by an earlier confirmation.
type AgentPolicyConfirmation struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID    uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`

	// Snapshotted, not recomputed: "what did you actually confirm" must stay
	// answerable after the selector's membership has moved on.
	ExpandedAgentIDs pq.StringArray `json:"expanded_agent_ids" gorm:"type:uuid[]"`

	OnExpiry    string    `json:"on_expiry" gorm:"not null"`
	Reason      string    `json:"reason" gorm:"not null"`
	ConfirmedBy uuid.UUID `json:"confirmed_by" gorm:"type:uuid;not null"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

func (AgentPolicyConfirmation) TableName() string { return "agent_policy_confirmations" }

// AgentPolicyAction is one thing the reconciler did, or would have done. Append-only.
type AgentPolicyAction struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID          *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`
	DiscoveredAgentID *uuid.UUID `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`

	Action string `json:"action" gorm:"not null"`
	Arm    string `json:"arm" gorm:"not null"`
	Reason string `json:"reason" gorm:"not null;default:''"`

	DryRun  bool   `json:"dry_run" gorm:"not null;default:false"`
	Outcome string `json:"outcome" gorm:"not null;default:'applied'"`
	Detail  string `json:"detail" gorm:"not null;default:''"`

	// Was the operator warned before this happened? Nil for a non-destructive
	// action. FALSE is a governance exception: the action executed and nobody was
	// told. A failed warning deliberately does not block execution.
	WarningDelivered *bool `json:"warning_delivered,omitempty"`

	ActedAt time.Time `json:"acted_at"`
}

func (AgentPolicyAction) TableName() string { return "agent_policy_actions" }
