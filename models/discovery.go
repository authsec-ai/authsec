package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
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

// DiscoverySource is a workspace-scoped configured connector that produces agent
// sightings. Non-secret settings live in Config; any credential belongs in Vault.
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
	CreatedBy   string          `json:"created_by" gorm:"not null;default:''"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func (DiscoverySource) TableName() string { return "discovery_sources" }

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
	CreatedBy         string          `json:"created_by" gorm:"not null;default:''"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func (DiscoveredAgent) TableName() string { return "discovered_agents" }

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
	GeneratedAt     time.Time                  `json:"generated_at"`
}

// CoverageBucket is the coverage split for one deployment origin.
type CoverageBucket struct {
	Total           int64   `json:"total"`
	Registered      int64   `json:"registered"`
	CoveragePercent float64 `json:"coverage_percent"`
}
