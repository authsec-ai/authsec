package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Discovery connector kinds — the channel a sighting came from. k8s_webhook and
// repo_scan are the active channels; the rest are designed but deferred and need
// no schema change to enable.
const (
	DiscoverySourceK8sWebhook = "k8s_webhook"
	DiscoverySourceAWS        = "aws"
	DiscoverySourceAzure      = "azure"
	DiscoverySourceGCP        = "gcp"
	DiscoverySourceVMSensor   = "vm_sensor"
	DiscoverySourceRepoScan   = "repo_scan"
)

// Deployment origin. A manually run agent is the higher-risk, harder-to-attribute
// case — its permissions are typically whatever the developer's own credentials
// allow — so the Unregistered Agents report surfaces manual first.
const (
	DeploymentOriginManual    = "manual"
	DeploymentOriginAutomated = "automated"
	DeploymentOriginUnknown   = "unknown"
)

// Discovered-agent lifecycle status. Moves forward only; never returns to
// unregistered. 'ignored' is the keep-the-row-but-stop-surfacing-it state, which
// is why there is no soft-delete column.
const (
	DiscoveredAgentUnregistered = "unregistered"
	DiscoveredAgentRegistered   = "registered"
	DiscoveredAgentQuarantined  = "quarantined"
	DiscoveredAgentIgnored      = "ignored"
)

// Observed runtime status of the workload behind a sighting.
//
// Deliberately a SEPARATE axis from DiscoveredAgent*.Status: that one records what
// a human decided, this one records what we saw. Status is forward-only; this
// moves both ways. An agent that was claimed and later deleted stays 'registered'
// — losing that would throw away the audit trail — while its runtime status
// becomes 'gone'.
//
// 'unknown' is not a failure state, it is honesty: an agent whose lifecycle we
// have never observed, or whose last observation is too old to trust. Silence is
// never treated as deletion.
const (
	RuntimeStatusRunning = "running"
	RuntimeStatusStopped = "stopped"
	RuntimeStatusGone    = "gone"
	RuntimeStatusUnknown = "unknown"
)

// Lifecycle event kinds recorded in discovered_agent_events.
//
//   - observed        — seen present, by admission CREATE or a resync sweep
//   - deleted         — the workload object was deleted; sets 'gone', and from
//     admission it carries the principal the API server attributed it to
//   - pod_terminated  — a controller-owned pod died. Informational ONLY: a
//     rollout, eviction, or node drain kills pods without removing the agent, so
//     this must never set 'gone'
//   - absent          — missing from a COMPLETE resync manifest. The
//     agent-was-destroyed-while-we-were-not-looking case
//   - reappeared      — observed again after being marked gone or stopped
const (
	AgentEventObserved      = "observed"
	AgentEventDeleted       = "deleted"
	AgentEventPodTerminated = "pod_terminated"
	AgentEventAbsent        = "absent"
	AgentEventReappeared    = "reappeared"
)

// Channel a lifecycle event was observed through. It bounds how much the event
// can claim: admission carries an API-server-asserted actor, a resync never can.
const (
	DiscoveryChannelAdmission    = "admission"
	DiscoveryChannelResync       = "resync"
	DiscoveryChannelControlPlane = "control_plane"
)

// ValidRuntimeStatuses returns the allowed observed runtime statuses.
func ValidRuntimeStatuses() []string {
	return []string{
		RuntimeStatusRunning, RuntimeStatusStopped,
		RuntimeStatusGone, RuntimeStatusUnknown,
	}
}

// ValidAgentEvents returns the allowed lifecycle event kinds.
func ValidAgentEvents() []string {
	return []string{
		AgentEventObserved, AgentEventDeleted, AgentEventPodTerminated,
		AgentEventAbsent, AgentEventReappeared,
	}
}

// Agent archetype — where the agent's authority comes from. An autonomous agent
// holds its own entitlements and is capped by them. A user-delegated agent
// borrows a scoped, time-boxed slice of a user's authority and can never exceed
// the delegating user.
const (
	AgentArchetypeAutonomous = "autonomous"
	AgentArchetypeDelegated  = "user_delegated"
	AgentArchetypeHybrid     = "hybrid"
)

// ValidDiscoverySourceKinds returns the allowed connector kinds.
func ValidDiscoverySourceKinds() []string {
	return []string{
		DiscoverySourceK8sWebhook, DiscoverySourceAWS, DiscoverySourceAzure,
		DiscoverySourceGCP, DiscoverySourceVMSensor, DiscoverySourceRepoScan,
	}
}

// ValidDeploymentOrigins returns the allowed deployment origins.
func ValidDeploymentOrigins() []string {
	return []string{DeploymentOriginManual, DeploymentOriginAutomated, DeploymentOriginUnknown}
}

// ValidDiscoveredAgentStatuses returns the allowed inventory statuses.
func ValidDiscoveredAgentStatuses() []string {
	return []string{
		DiscoveredAgentUnregistered, DiscoveredAgentRegistered,
		DiscoveredAgentQuarantined, DiscoveredAgentIgnored,
	}
}

// ValidAgentArchetypes returns the allowed archetypes; empty means not yet known.
func ValidAgentArchetypes() []string {
	return []string{AgentArchetypeAutonomous, AgentArchetypeDelegated, AgentArchetypeHybrid}
}

// DiscoverySource is a workspace-scoped connector that produces agent sightings.
// Non-secret settings live in Config; any credential belongs in Vault.
//
// A connector arrives one of two ways. An admin configures it in the console, or
// a deployed agent SELF-REGISTERS: one control plane serves discovery agents in
// many clusters, so it needs a first-class record of each one. Without it,
// cluster identity exists only inside sighting metadata, and there is no way to
// list connected clusters, see which agent version each runs, or distinguish a
// live agent from one that stopped reporting a week ago.
//
// The self-registration fields are machine-owned: every heartbeat overwrites
// them. The admin-owned fields (DisplayName once set, Enabled, Config) are not.
type DiscoverySource struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Kind        string          `json:"kind" gorm:"not null"`
	DisplayName string          `json:"display_name" gorm:"not null"`
	Config      json.RawMessage `json:"config" gorm:"type:jsonb;not null;default:'{}'"`
	Enabled     bool            `json:"enabled" gorm:"not null;default:true"`
	LastSyncAt  *time.Time      `json:"last_sync_at,omitempty"`
	LastStatus  string          `json:"last_status" gorm:"not null;default:''"`
	LastError   string          `json:"last_error" gorm:"not null;default:''"`
	// InstanceID is the stable key a self-registering agent asserts, and the
	// conflict target for its upsert. Empty for admin-configured connectors,
	// which is why the unique index over it is partial.
	//
	// For the Kubernetes connector it derives from cluster.name, which is already
	// a fingerprint component — so renaming a cluster re-mints this row at exactly
	// the moment it re-mints the agent rows. Keying on DisplayName instead would
	// fork the row the first time an admin renamed the connector.
	InstanceID  string `json:"instance_id" gorm:"not null;default:''"`
	ClusterName string `json:"cluster_name" gorm:"not null;default:''"`
	// ClusterUID is a corroborating fact, never a key: the kube-system namespace
	// UID, which is immutable per cluster. A changed UID under an unchanged
	// InstanceID means two DIFFERENT clusters were installed with the same
	// cluster.name — a misconfiguration that silently merges two inventories.
	// Empty when the agent has no RBAC to read it, which is the default.
	ClusterUID   string `json:"cluster_uid" gorm:"not null;default:''"`
	AgentVersion string `json:"agent_version" gorm:"not null;default:''"`
	// LastHeartbeatAt is liveness, distinct from LastSyncAt (which means "last did
	// useful work"). An agent in an idle cluster heartbeats without syncing, and
	// conflating the two would make a healthy agent look dead.
	LastHeartbeatAt *time.Time      `json:"last_heartbeat_at,omitempty"`
	SelfRegistered  bool            `json:"self_registered" gorm:"not null;default:false"`
	Runtime         json.RawMessage `json:"runtime" gorm:"type:jsonb;not null;default:'{}'"`

	// ActuationTokenHash is the HASH of the per-connector actuation credential. The
	// plaintext is returned once at enable time and never stored, so a leaked backup
	// yields nothing usable. Empty means actuation is not enabled for this cluster.
	//
	// json:"-" deliberately: this must never appear in an API response, not even to an
	// admin listing connectors.
	ActuationTokenHash string     `json:"-" gorm:"not null;default:''"`
	ActuationEnabledAt *time.Time `json:"actuation_enabled_at,omitempty"`

	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Connected is derived at read time, not stored — a stored boolean would need
	// a sweeper to flip it and would be wrong between sweeps.
	Connected bool `json:"connected" gorm:"-"`
	// SecondsSinceHeartbeat is nil when the connector has never heartbeated.
	SecondsSinceHeartbeat *int64 `json:"seconds_since_heartbeat,omitempty" gorm:"-"`

	// AgentCount is how many discovered agents this source has produced. Computed
	// on read, not stored — a count that can drift from the rows it counts is
	// worse than no count. gorm:"-" keeps it out of every write.
	AgentCount int64 `json:"agent_count" gorm:"-"`
}

func (DiscoverySource) TableName() string { return "discovery_sources" }

// HeartbeatGracePeriod is how long after its last heartbeat a connector is still
// considered connected.
//
// Set to several times the agent's default 60s heartbeat so one dropped request,
// a rolling restart, or a brief network partition does not show up as an outage.
const HeartbeatGracePeriod = 5 * time.Minute

// AfterFind derives the liveness fields on every read.
//
// A GORM hook rather than a call in each service method on purpose: Connected is
// only meaningful if it is populated on EVERY path that returns a source to a
// caller, and "remember to call DeriveConnected" is exactly the kind of invariant a
// later read path forgets — leaving a live connector rendered as disconnected. The
// hook makes it structural.
//
// It does not fire for a Create with a RETURNING clause, so the self-registration
// path derives explicitly.
func (s *DiscoverySource) AfterFind(*gorm.DB) error {
	s.DeriveConnected(time.Now())
	return nil
}

// DeriveConnected fills the read-time liveness fields from LastHeartbeatAt.
//
// A connector that has never heartbeated is not "disconnected" — it may simply be
// an admin-configured connector that no agent backs. Only self-registered rows
// can meaningfully be connected.
func (s *DiscoverySource) DeriveConnected(now time.Time) {
	if s.LastHeartbeatAt == nil {
		s.Connected = false
		return
	}
	age := int64(now.Sub(*s.LastHeartbeatAt).Seconds())
	if age < 0 {
		// Clock skew between the agent's host and ours. Clamp rather than report a
		// negative age, which would read as nonsense in the console.
		age = 0
	}
	s.SecondsSinceHeartbeat = &age
	s.Connected = now.Sub(*s.LastHeartbeatAt) <= HeartbeatGracePeriod
}

// DiscoveredAgent is one row per distinct agent sighting, keyed by a stable
// Fingerprint. UNIQUE(workspace_id, source, fingerprint) makes a repeated
// sighting an upsert — a LastSeenAt / SightingCount bump — never a duplicate row.
//
// A sighting by itself grants nothing: the row lands as unregistered and only
// becomes a governed principal when a human claims it, which sets both
// MatchedClientID (the identity every token traces to) and OwnerUserID (the
// accountable human). The alternative to a claim is quarantine.
type DiscoveredAgent struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Source            string          `json:"source" gorm:"not null"`
	DiscoverySourceID *uuid.UUID      `json:"discovery_source_id,omitempty" gorm:"type:uuid"`
	Fingerprint       string          `json:"fingerprint" gorm:"not null"`
	DisplayName       string          `json:"display_name" gorm:"not null;default:''"`
	Metadata          json.RawMessage `json:"metadata" gorm:"type:jsonb;not null;default:'{}'"`
	DeploymentOrigin  string          `json:"deployment_origin" gorm:"not null;default:'unknown'"`
	Archetype         string          `json:"archetype" gorm:"not null;default:''"`
	MatchedClientID   *uuid.UUID      `json:"matched_client_id,omitempty" gorm:"type:uuid"`
	OwnerUserID       *uuid.UUID      `json:"owner_user_id,omitempty" gorm:"type:uuid"`
	Status            string          `json:"status" gorm:"not null;default:'unregistered'"`
	ClaimedBy         *uuid.UUID      `json:"claimed_by,omitempty" gorm:"type:uuid"`
	ClaimedAt         *time.Time      `json:"claimed_at,omitempty"`
	QuarantinedBy     *uuid.UUID      `json:"quarantined_by,omitempty" gorm:"type:uuid"`
	QuarantinedAt     *time.Time      `json:"quarantined_at,omitempty"`
	QuarantineReason  string          `json:"quarantine_reason" gorm:"not null;default:''"`
	FirstSeenAt       time.Time       `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt        time.Time       `json:"last_seen_at" gorm:"not null;default:now()"`
	SightingCount     int             `json:"sighting_count" gorm:"not null;default:1"`

	// RuntimeStatus is what we OBSERVED about the workload, orthogonal to Status
	// (what a human decided). See the RuntimeStatus* constants for why the two must
	// not be collapsed.
	RuntimeStatus string `json:"runtime_status" gorm:"not null;default:'unknown'"`
	// RuntimeReason is the agent's own words for why RuntimeStatus holds its value
	// ("deleted by alice@corp via Deployment DELETE"). Displayed verbatim so a
	// reviewer never has to guess how we concluded an agent was gone.
	RuntimeReason string `json:"runtime_reason" gorm:"not null;default:''"`
	// RuntimeObservedAt is when the setting event was OBSERVED, not when we
	// received it. It is the monotonic guard: a sighting stuck in a retry queue
	// must not resurrect an agent deleted after that sighting was enqueued.
	RuntimeObservedAt *time.Time `json:"runtime_observed_at,omitempty"`
	TerminatedAt      *time.Time `json:"terminated_at,omitempty"`
	// TerminatedBy is the principal the API SERVER attributed the delete to — the
	// answer to "who destroyed this agent". Only admission can supply it; a resync
	// can prove absence but never attribute it.
	TerminatedBy string `json:"terminated_by" gorm:"not null;default:''"`

	// Whether the quarantine DECISION has actually been enforced in the cluster. The
	// same decision-versus-observation split as Status vs RuntimeStatus: an admin needs
	// to distinguish "I quarantined it" from "it is actually blocked", and
	// quarantined-but-not-blocked is the dangerous state.
	QuarantineEnforcedAt       *time.Time `json:"quarantine_enforced_at,omitempty"`
	QuarantineEnforcementError string     `json:"quarantine_enforcement_error" gorm:"not null;default:''"`
	// When the quarantine was LIFTED. QuarantinedAt/By/Reason deliberately survive a
	// release as the record that it happened, so this is what distinguishes a live
	// quarantine from a historical one: set means the quarantine is over.
	QuarantineReleasedAt *time.Time `json:"quarantine_released_at,omitempty"`
	QuarantineReleasedBy *uuid.UUID `json:"quarantine_released_by,omitempty"`
	// ObservedServiceAccount is the workload identity actually seen running. When it
	// disagrees with the provisioned anchor, the entitlement is bound to an identity the
	// workload does not have.
	ObservedServiceAccount string     `json:"observed_service_account" gorm:"not null;default:''"`
	IdentityVerifiedAt     *time.Time `json:"identity_verified_at,omitempty"`

	CreatedBy string    `json:"created_by" gorm:"not null;default:''"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (DiscoveredAgent) TableName() string { return "discovered_agents" }

// DiscoveredAgentEvent is one observation of an agent's runtime lifecycle.
//
// Append-only. The inventory row holds only the CURRENT runtime state; this table
// is the history behind it, which is what turns "it is gone now" into "it was
// deleted at 14:02 by alice@corp, seen via a Deployment DELETE in cluster prod-1".
//
// Not folded into audit_events on purpose: these are machine observations of
// third-party workloads rather than administrator actions on AuthSec objects.
// They carry no acting AuthSec user, they are far higher volume, and they can be
// pruned on a shorter retention — all of which would be wrong for the admin log.
type DiscoveredAgentEvent struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	// DiscoveredAgentID is nullable because an event can legitimately arrive for a
	// fingerprint we hold no sighting for — an agent created and destroyed between
	// two resyncs, or deleted while the reporting queue was backed up. Discarding
	// such an event would throw away the only evidence that agent ever existed.
	DiscoveredAgentID *uuid.UUID      `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`
	DiscoverySourceID *uuid.UUID      `json:"discovery_source_id,omitempty" gorm:"type:uuid"`
	Source            string          `json:"source" gorm:"not null"`
	Fingerprint       string          `json:"fingerprint" gorm:"not null"`
	Event             string          `json:"event" gorm:"not null"`
	RuntimeStatus     string          `json:"runtime_status" gorm:"not null;default:''"`
	Reason            string          `json:"reason" gorm:"not null;default:''"`
	Actor             string          `json:"actor" gorm:"not null;default:''"`
	Channel           string          `json:"channel" gorm:"not null;default:''"`
	ClusterName       string          `json:"cluster_name" gorm:"not null;default:''"`
	Metadata          json.RawMessage `json:"metadata" gorm:"type:jsonb;not null;default:'{}'"`
	ObservedAt        time.Time       `json:"observed_at" gorm:"not null;default:now()"`
	CreatedAt         time.Time       `json:"created_at"`
}

func (DiscoveredAgentEvent) TableName() string { return "discovered_agent_events" }

// AgentCoverage is the headline governance metric: what share of the agents
// discovered in a workspace have been brought under management. Discovery makes
// it measurable; claiming moves it. Segmented by origin because manual agents
// are the ones that matter most.
type AgentCoverage struct {
	WorkspaceID     uuid.UUID                  `json:"workspace_id"`
	Total           int64                      `json:"total"`
	Registered      int64                      `json:"registered"`
	Unregistered    int64                      `json:"unregistered"`
	Quarantined     int64                      `json:"quarantined"`
	Ignored         int64                      `json:"ignored"`
	CoveragePercent float64                    `json:"coverage_percent"`
	UnownedAgents   int64                      `json:"unowned_agents"`
	ByOrigin        map[string]*CoverageBucket `json:"by_origin"`
	BySource        map[string]int64           `json:"by_source"`
	// ByRuntimeStatus splits the inventory by what is actually still running.
	// Without it, coverage silently counts long-deleted agents as ungoverned and
	// the KPI never reaches 100% however diligently a team claims.
	ByRuntimeStatus map[string]int64 `json:"by_runtime_status"`
	// LiveUnregistered is the number that actually needs action: unregistered AND
	// not known to be gone. This is the queue length for the Unregistered Agents
	// report, as opposed to Unregistered, which includes historical rows.
	LiveUnregistered int64     `json:"live_unregistered"`
	GeneratedAt      time.Time `json:"generated_at"`
}

// CoverageBucket is the coverage split for one deployment origin.
type CoverageBucket struct {
	Total           int64   `json:"total"`
	Registered      int64   `json:"registered"`
	CoveragePercent float64 `json:"coverage_percent"`
}
