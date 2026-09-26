package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Agentic IGA canonical model. Mirrors the iga_* tables in 001_bootstrap.sql.
//
// The layering is load-bearing and worth stating once: evidence is preserved
// before it is interpreted.
//
//	IGASourceObject   what the provider showed us (provider payload lives here)
//	IGAObservation    a versioned fact + provenance (append-only)
//	IGACandidate      a proposal that some source object is an agent
//	IGAAgent etc.     the canonical graph (provider-neutral; no GitHub columns)
//
// Nothing is promoted silently between those layers.

// Coverage states. "unknown" must never be rendered as zero: not looking and
// finding nothing are different answers.
const (
	CoverageComplete      = "complete_for_selected_scope"
	CoveragePartial       = "partial"
	CoverageUnknown       = "unknown"
	CoverageNotConfigured = "not_configured"
	CoverageUnsupported   = "unsupported"
	CoverageFailed        = "failed"
	CoverageStale         = "stale"
)

// Evidence modes, in descending semantic strength. This is the ceiling on what
// a rule may conclude: a dependency or a secret name can never on its own
// produce a confirmed agent.
const (
	EvidencePlatformDeclared   = "platform_declared"
	EvidenceDeploymentDeclared = "deployment_declared"
	EvidenceInvocationDeclared = "invocation_declared"
	EvidenceFrameworkDep       = "framework_dependency"
	EvidenceToolConfiguration  = "tool_configuration"
	EvidenceSecretReference    = "secret_reference"
	EvidenceIdentityGrant      = "identity_grant"
	EvidenceAuditEvent         = "audit_event"
	// Directory reads use models.EvidenceObserved ("observed"), declared with
	// the discovery evidence kinds. It is not platform_declared, so it cannot
	// auto-confirm an agent.
)

// EvidenceRank orders evidence by strength. Only platform_declared may
// auto-confirm; everything below it produces a candidate for a human.
func EvidenceRank(mode string) int {
	switch mode {
	case EvidencePlatformDeclared:
		return 100
	case EvidenceDeploymentDeclared:
		return 80
	case EvidenceInvocationDeclared:
		return 60
	case EvidenceToolConfiguration:
		return 40
	case EvidenceFrameworkDep:
		return 20
	case EvidenceSecretReference:
		return 10
	default:
		return 0
	}
}

// CanAutoConfirm reports whether evidence of this mode may become a confirmed
// agent without human review. Only the provider explicitly declaring an agent
// qualifies.
func CanAutoConfirm(mode string) bool { return mode == EvidencePlatformDeclared }

// Scan, candidate, correlation and rollup vocabularies.
const (
	ScanModeFull        = "full"
	ScanModeIncremental = "incremental"
	ScanModeTargeted    = "targeted"

	ScanPending   = "pending"
	ScanRunning   = "running"
	ScanSucceeded = "succeeded"
	ScanFailed    = "failed"
	ScanCancelled = "cancelled"

	CandidatePending      = "pending"
	CandidateConfirmed    = "confirmed"
	CandidateRejected     = "rejected"
	CandidateInsufficient = "insufficient_evidence"
	CandidateSuperseded   = "superseded"

	CorrelationStrong   = "strong"
	CorrelationWeak     = "weak"
	CorrelationProposed = "proposed"
	CorrelationAccepted = "accepted"
	CorrelationRejected = "rejected"
	CorrelationSplit    = "split"

	RollupConfirmed = "confirmed"
	RollupContested = "contested"
	RollupUnknown   = "unknown"
	RollupStale     = "stale"

	CalcComplete = "complete"
	CalcPartial  = "partial"
	CalcUnknown  = "unknown"

	ConclusionEffective    = "effective"
	ConclusionNotEffective = "not_effective"
	ConclusionUnknown      = "unknown"

	JobReady  = "ready"
	JobLeased = "leased"
	JobDone   = "done"
	JobFailed = "failed"
	JobDead   = "dead"

	DeliveryReceived          = "received"
	DeliveryRejectedSignature = "rejected_signature"
	DeliveryRejectedBinding   = "rejected_binding"
	DeliveryAccepted          = "accepted"
	DeliveryProcessed         = "processed"

	LifecycleActive     = "active"
	LifecycleTombstoned = "tombstoned"
	LifecycleRedacted   = "redacted"
)

// Object classes enumerated independently, because each has its own permission
// and its own failure mode. Coverage is tracked per class.
const (
	ClassRepository      = "repository"
	ClassAgentProfile    = "agent_profile"
	ClassAppInstallation = "app_installation"
	ClassFineGrainedPAT  = "fine_grained_pat"
	ClassDeployKey       = "deploy_key"
	ClassWebhook         = "webhook"
	ClassSecretRef       = "secret_reference"
	ClassSBOMComponent   = "sbom_component"
	ClassRepoDeclaration = "repo_declaration"
	ClassAuditEvent      = "audit_event"
)

/* ---------------------------- control plane ---------------------------- */

// IGAIntegration is one verified binding between a workspace and a provider
// installation. requested vs granted permissions are kept apart on purpose:
// the gap between them is the honest basis for every coverage claim.
type IGAIntegration struct {
	ID                   uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID          uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Provider             string          `json:"provider" gorm:"not null"`
	ProviderHost         string          `json:"provider_host" gorm:"not null"`
	AppRegistrationID    string          `json:"app_registration_id" gorm:"not null"`
	InstallationID       *string         `json:"installation_id,omitempty"`
	AccountNativeID      *string         `json:"account_native_id,omitempty"`
	CapabilityProfile    json.RawMessage `json:"capability_profile" gorm:"type:jsonb;not null;default:'{}'"`
	RequestedPermissions json.RawMessage `json:"requested_permissions" gorm:"type:jsonb;not null;default:'{}'"`
	GrantedPermissions   json.RawMessage `json:"granted_permissions" gorm:"type:jsonb;not null;default:'{}'"`
	Status               string          `json:"status" gorm:"not null;default:'pending'"`
	SecretRef            string          `json:"-" gorm:"not null;default:''"` // pointer only; never serialized
	VerifiedAt           *time.Time      `json:"verified_at,omitempty"`
	Version              int64           `json:"version" gorm:"not null;default:1"`
	CreatedBy            string          `json:"created_by" gorm:"not null;default:''"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

func (IGAIntegration) TableName() string { return "iga_integrations" }

// IGAIntegrationScope is one selected, excluded or denied piece of estate. It
// stays on the books even when excluded, because "not selected" and "could not
// read" are different answers and neither is zero.
type IGAIntegrationScope struct {
	ID                   uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID          uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID        uuid.UUID       `json:"integration_id" gorm:"type:uuid;not null"`
	EstateScopeID        *uuid.UUID      `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	NativeScopeKind      string          `json:"native_scope_kind" gorm:"not null"`
	NativeScopeID        string          `json:"native_scope_id" gorm:"not null"`
	SelectionState       string          `json:"selection_state" gorm:"not null;default:'selected'"`
	Filters              json.RawMessage `json:"filters" gorm:"type:jsonb;not null;default:'{}'"`
	EffectivePermissions json.RawMessage `json:"effective_permissions" gorm:"type:jsonb;not null;default:'{}'"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

func (IGAIntegrationScope) TableName() string { return "iga_integration_scopes" }

// IGAScanRun is one enumeration attempt. IsAuthoritative may only be set on a
// succeeded run — the database enforces it — so an interrupted scan can never
// be used to prove something was deleted.
type IGAScanRun struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID      uuid.UUID       `json:"integration_id" gorm:"type:uuid;not null"`
	Mode               string          `json:"mode" gorm:"not null"`
	Generation         int64           `json:"generation" gorm:"not null"`
	Status             string          `json:"status" gorm:"not null;default:'pending'"`
	RequestedBy        string          `json:"requested_by" gorm:"not null;default:''"`
	NormalizerVersion  string          `json:"normalizer_version" gorm:"not null;default:''"`
	RuleCatalogVersion string          `json:"rule_catalog_version" gorm:"not null;default:''"`
	StartedAt          *time.Time      `json:"started_at,omitempty"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	Counters           json.RawMessage `json:"counters" gorm:"type:jsonb;not null;default:'{}'"`
	FailureCode        string          `json:"failure_code" gorm:"not null;default:''"`
	IsAuthoritative    bool            `json:"is_authoritative" gorm:"not null;default:false"`
	CreatedAt          time.Time       `json:"created_at"`
}

func (IGAScanRun) TableName() string { return "iga_scan_runs" }

// IGAScanCheckpoint is a resumable cursor. A killed worker leaves a reclaimable
// lease and a cursor, so a restart costs one page rather than one scan.
type IGAScanCheckpoint struct {
	WorkspaceID  uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ScanRunID    uuid.UUID  `json:"scan_run_id" gorm:"type:uuid;primaryKey"`
	ObjectClass  string     `json:"object_class" gorm:"primaryKey"`
	PartitionKey string     `json:"partition_key" gorm:"primaryKey"`
	Cursor       string     `json:"cursor" gorm:"not null;default:''"`
	Watermark    *time.Time `json:"watermark,omitempty"`
	LeaseOwner   *string    `json:"lease_owner,omitempty"`
	LeasedUntil  *time.Time `json:"leased_until,omitempty"`
	AttemptCount int        `json:"attempt_count" gorm:"not null;default:0"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (IGAScanCheckpoint) TableName() string { return "iga_scan_checkpoints" }

// IGACoverageState is what could actually be inspected, per scope and object
// class. There is deliberately no percentage column: averaging these into one
// reassuring number is the exact failure this table exists to prevent.
type IGACoverageState struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID      uuid.UUID  `json:"integration_id" gorm:"type:uuid;not null"`
	IntegrationScopeID uuid.UUID  `json:"integration_scope_id" gorm:"type:uuid;not null"`
	ObjectClass        string     `json:"object_class" gorm:"not null"`
	State              string     `json:"state" gorm:"not null;default:'unknown'"`
	ReasonCode         string     `json:"reason_code" gorm:"not null;default:''"`
	LastSuccessAt      *time.Time `json:"last_success_at,omitempty"`
	LastAttemptAt      *time.Time `json:"last_attempt_at,omitempty"`
	Watermark          *time.Time `json:"watermark,omitempty"`
	InspectedCount     int64      `json:"inspected_count" gorm:"not null;default:0"`
	DeniedCount        int64      `json:"denied_count" gorm:"not null;default:0"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (IGACoverageState) TableName() string { return "iga_coverage_states" }

// IGAWebhookDelivery is the provider ingress ledger. WorkspaceID is nullable
// because a delivery is recorded when it arrives, BEFORE the binding has been
// resolved server-side — the payload's own installation id is never sufficient
// to establish a workspace.
type IGAWebhookDelivery struct {
	ID                   uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppRegistrationID    string     `json:"app_registration_id" gorm:"not null"`
	DeliveryID           string     `json:"delivery_id" gorm:"not null"`
	WorkspaceID          *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid"`
	IntegrationID        *uuid.UUID `json:"integration_id,omitempty" gorm:"type:uuid"`
	EventType            string     `json:"event_type" gorm:"not null;default:''"`
	Action               string     `json:"action" gorm:"not null;default:''"`
	BodyHash             string     `json:"body_hash" gorm:"not null;default:''"`
	ReceivedAt           time.Time  `json:"received_at"`
	SignatureValidatedAt *time.Time `json:"signature_validated_at,omitempty"`
	State                string     `json:"state" gorm:"not null;default:'received'"`
}

func (IGAWebhookDelivery) TableName() string { return "iga_webhook_deliveries" }

// IGADurableJob is work accepted but not yet done. The webhook route commits a
// delivery row and a job row in ONE transaction and only then returns 2xx.
type IGADurableJob struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID uuid.UUID  `json:"integration_id" gorm:"type:uuid;not null"`
	JobKind       string     `json:"job_kind" gorm:"not null"`
	DedupeKey     string     `json:"dedupe_key" gorm:"not null"`
	PayloadRef    string     `json:"payload_ref" gorm:"not null;default:''"`
	State         string     `json:"state" gorm:"not null;default:'ready'"`
	AvailableAt   time.Time  `json:"available_at"`
	LeaseOwner    *string    `json:"lease_owner,omitempty"`
	LeasedUntil   *time.Time `json:"leased_until,omitempty"`
	AttemptCount  int        `json:"attempt_count" gorm:"not null;default:0"`
	LastError     string     `json:"last_error" gorm:"not null;default:''"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (IGADurableJob) TableName() string { return "iga_durable_jobs" }

/* ---------------------------- source evidence --------------------------- */

// IGASourceObject is what the provider showed us, keyed by a recognition key
// built from immutable identifiers. Locator (owner/name/path) is descriptive:
// a rename changes the locator and must NOT create a new object.
type IGASourceObject struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID uuid.UUID `json:"integration_id" gorm:"type:uuid;not null"`
	// IntegrationScopeID is where this object was observed. NULL on rows written
	// before migration 018, which makes them permanently ineligible for the
	// absence sweep rather than sweepable on a guess.
	IntegrationScopeID *uuid.UUID      `json:"integration_scope_id,omitempty" gorm:"type:uuid"`
	ObjectType         string          `json:"object_type" gorm:"not null"`
	RecognitionKey     string          `json:"recognition_key" gorm:"not null"`
	NativeID           string          `json:"native_id" gorm:"not null;default:''"`
	Locator            json.RawMessage `json:"locator" gorm:"type:jsonb;not null;default:'{}'"`
	NormalizedPayload  json.RawMessage `json:"normalized_payload" gorm:"type:jsonb;not null;default:'{}'"`
	RawHash            string          `json:"raw_hash" gorm:"not null;default:''"`
	SourceVersion      string          `json:"source_version" gorm:"not null;default:''"`
	SourceSubjectKey   string          `json:"source_subject_key" gorm:"not null;default:''"`
	ScanGeneration     *int64          `json:"scan_generation,omitempty"`
	Lifecycle          string          `json:"lifecycle" gorm:"not null;default:'active'"`
	FirstSeenAt        time.Time       `json:"first_seen_at"`
	LastSeenAt         time.Time       `json:"last_seen_at"`
	TombstonedAt       *time.Time      `json:"tombstoned_at,omitempty"`
}

func (IGASourceObject) TableName() string { return "iga_source_objects" }

// IGAObservation is a versioned fact with provenance. Append-preserving: a
// later scan adds a row rather than rewriting an earlier one, which is what
// makes contradiction visible instead of silently overwritten.
type IGAObservation struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SourceObjectID    uuid.UUID       `json:"source_object_id" gorm:"type:uuid;not null"`
	ScanRunID         *uuid.UUID      `json:"scan_run_id,omitempty" gorm:"type:uuid"`
	DeliveryID        *uuid.UUID      `json:"delivery_id,omitempty" gorm:"type:uuid"`
	Mode              string          `json:"mode" gorm:"not null"`
	FactPayload       json.RawMessage `json:"fact_payload" gorm:"type:jsonb;not null;default:'{}'"`
	EvidenceRef       string          `json:"evidence_ref" gorm:"not null;default:''"`
	ObservedAt        time.Time       `json:"observed_at" gorm:"not null"`
	IngestedAt        time.Time       `json:"ingested_at"`
	NormalizerVersion string          `json:"normalizer_version" gorm:"not null;default:''"`
	RuleID            string          `json:"rule_id" gorm:"not null;default:''"`
	RuleVersion       string          `json:"rule_version" gorm:"not null;default:''"`
	DedupeKey         string          `json:"dedupe_key" gorm:"not null"`
}

func (IGAObservation) TableName() string { return "iga_observations" }

// IGACandidate is a proposal that a source object is an agent. Nothing is
// promoted silently: it carries the rule that produced it and waits.
type IGACandidate struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SourceObjectID     uuid.UUID  `json:"source_object_id" gorm:"type:uuid;not null"`
	ProposedObjectKind string     `json:"proposed_object_kind" gorm:"not null"`
	ProposalSignature  string     `json:"proposal_signature" gorm:"not null"`
	RuleID             string     `json:"rule_id" gorm:"not null;default:''"`
	RuleVersion        string     `json:"rule_version" gorm:"not null;default:''"`
	EvidenceMode       string     `json:"evidence_mode" gorm:"not null;default:''"`
	State              string     `json:"state" gorm:"not null;default:'pending'"`
	DecidedBy          *string    `json:"decided_by,omitempty"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	Reason             string     `json:"reason" gorm:"not null;default:''"`
	Version            int64      `json:"version" gorm:"not null;default:1"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (IGACandidate) TableName() string { return "iga_classification_candidates" }

// IGACorrelation is the reversible mapping from a source object to a canonical
// object. Weak joins stay proposals; a split flips state without deleting
// observations.
type IGACorrelation struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SourceObjectID uuid.UUID  `json:"source_object_id" gorm:"type:uuid;not null"`
	CanonicalKind  string     `json:"canonical_kind" gorm:"not null"`
	CanonicalID    uuid.UUID  `json:"canonical_id" gorm:"type:uuid;not null"`
	JoinKey        string     `json:"join_key" gorm:"not null;default:''"`
	Strength       string     `json:"strength" gorm:"not null;default:'weak'"`
	State          string     `json:"state" gorm:"not null;default:'proposed'"`
	DecidedBy      *string    `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Version        int64      `json:"version" gorm:"not null;default:1"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (IGACorrelation) TableName() string { return "iga_correlations" }

/* ---------------------------- canonical graph --------------------------- */

// IGAEstateScope is containment only. Containment confers NO access
// inheritance; an access path must be evidenced.
type IGAEstateScope struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ScopeKind   string    `json:"scope_kind" gorm:"not null"`
	// SourceKey is the scope's recognition key (028). For AWS this is the
	// connected account; nothing else in the tree writes this table.
	SourceKey     string     `json:"source_key" gorm:"not null;default:''"`
	DisplayName   string     `json:"display_name" gorm:"not null;default:''"`
	ParentScopeID *uuid.UUID `json:"parent_scope_id,omitempty" gorm:"type:uuid"`
	Stage         string     `json:"stage" gorm:"not null;default:'unknown'"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (IGAEstateScope) TableName() string { return "iga_estate_scopes" }

// IGAAgent is the LOGICAL agent only. Candidates live elsewhere until
// confirmed. RollupState carries the honesty of the record and is separate
// from any displayed value.
//
// GitHub-confirmed agents only. The AWS projection writes NO row here (§2.2):
// the Kubernetes bridge name-matches every sighting against all active agents,
// so an AWS row would silently change another product's behaviour.
type IGAAgent struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID  *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	DisplayName    string     `json:"display_name" gorm:"not null;default:''"`
	Classification string     `json:"classification" gorm:"not null;default:'unknown'"`
	Status         string     `json:"status" gorm:"not null;default:'active'"`
	RollupState    string     `json:"rollup_state" gorm:"not null;default:'unknown'"`
	Lifecycle      string     `json:"lifecycle" gorm:"not null;default:'active'"`
	Version        int64      `json:"version" gorm:"not null;default:1"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (IGAAgent) TableName() string { return "iga_agents" }

// WorkloadLinkBasisHuman is the only basis that may set
// iga_agent_instances.workload_id. A weak name match or a candidate join
// is not authority.
const WorkloadLinkBasisHuman = "human_registration"

// IGAAgentInstance is a realization proven by a source that can prove
// deployment. A repository declaration alone never produces one of these.
//
// WorkloadID is set only by a human registration (042). ObservationID and
// CloudObservationID are the two evidence arms; at most one is set. LinkedBy
// and OwnerUserID are recorded user ids with no foreign key, matching
// iga_workload_classification.decided_by_user_id.
type IGAAgentInstance struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	AgentID          uuid.UUID  `json:"agent_id" gorm:"type:uuid;not null"`
	EstateScopeID    *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	NativeWorkloadID string     `json:"native_workload_id" gorm:"not null;default:''"`
	RuntimeKind      string     `json:"runtime_kind" gorm:"not null;default:''"`
	Stage            string     `json:"stage" gorm:"not null;default:'unknown'"`
	Lifecycle        string     `json:"lifecycle" gorm:"not null;default:'active'"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`

	WorkloadID            *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	ObservationID         *uuid.UUID `json:"observation_id,omitempty" gorm:"type:uuid"`
	CloudObservationID    *uuid.UUID `json:"cloud_observation_id,omitempty" gorm:"type:uuid"`
	WorkloadLinkBasis     *string    `json:"workload_link_basis,omitempty"`
	LinkedBy              *uuid.UUID `json:"linked_by,omitempty" gorm:"type:uuid"`
	OwnerUserID           *uuid.UUID `json:"owner_user_id,omitempty" gorm:"type:uuid"`
	LinkPurpose           string     `json:"link_purpose" gorm:"not null;default:''"`
	ClassificationVersion *int64     `json:"classification_version,omitempty"`
}

func (IGAAgentInstance) TableName() string { return "iga_agent_instances" }

// DiscoveredAgentWorkload is a candidate or weak join from a legacy
// discovered_agents row to a canonical workload (042). LinkStrength is only
// weak or candidate: this row never sets an authoritative workload_id.
type DiscoveredAgentWorkload struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	DiscoveredAgentID  uuid.UUID  `json:"discovered_agent_id" gorm:"type:uuid;not null"`
	WorkloadID         uuid.UUID  `json:"workload_id" gorm:"type:uuid;not null"`
	ObservationID      *uuid.UUID `json:"observation_id,omitempty" gorm:"type:uuid"`
	CloudObservationID *uuid.UUID `json:"cloud_observation_id,omitempty" gorm:"type:uuid"`
	LinkStrength       string     `json:"link_strength" gorm:"not null;default:'candidate'"`
	LinkState          string     `json:"link_state" gorm:"not null;default:'proposed'"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (DiscoveredAgentWorkload) TableName() string { return "discovered_agent_workloads" }

// Providers of the shared canonical tables (028). Existing rows are GitHub's;
// the AWS projector writes ProviderAWS. Every GitHub reader filters on
// ProviderGitHub, or AWS identities appear in the GitHub lists (§1.5).
const (
	ProviderGitHub     = "github"
	ProviderAWS        = "aws"
	ProviderLinux      = "linux"
	ProviderKubernetes = "kubernetes"
	ProviderAD         = "ad"
)

// Account kinds the provider/kind check accepts. AWS and GitHub kinds are
// not closed by that check.
const (
	AccountKindLocalUser       = "local_user"
	AccountKindLocalGroup      = "local_group"
	AccountKindK8sSA           = "k8s_service_account"
	AccountKindK8sGroup        = "k8s_group"
	AccountKindADUser          = "ad_user"
	AccountKindADGroup         = "ad_group"
	AccountKindADComputer      = "ad_computer"
	AccountKindADManagedSA     = "ad_managed_service_account"
	AccountStateEnabled        = "enabled"
	AccountStateDisabled       = "disabled"
	AccountStateUnknown        = "unknown"
	ReferenceStatusReferenced  = "referenced"
	ReferenceStatusObserved    = "observed"
	ReferenceStatusInventoried = "inventoried"
)

// ValidIntegrationProviders is the iga_integrations.provider vocabulary.
// github is the original value. linux, kubernetes and ad are additive (TRD 2).
// ProviderAWS is a canonical-graph provider, not an integration provider, and
// is intentionally absent here.
func ValidIntegrationProviders() []string {
	return []string{ProviderGitHub, ProviderLinux, ProviderKubernetes, ProviderAD}
}

// IGAIdentityAccount is a programmatic principal. Never a credential, and never
// automatically an agent.
type IGAIdentityAccount struct {
	ID              uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID   *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	DisplayName     string     `json:"display_name" gorm:"not null;default:''"`
	AccountKind     string     `json:"account_kind" gorm:"not null"`
	IdentityBacking string     `json:"identity_backing" gorm:"not null;default:'unknown'"`
	Lifecycle       string     `json:"lifecycle" gorm:"not null;default:'active'"`
	RollupState     string     `json:"rollup_state" gorm:"not null;default:'unknown'"`

	// Provider separates GitHub's rows from the AWS projector's (028).
	Provider string `json:"provider" gorm:"not null;default:''"`

	// Recognition and continuity (028). source_key is namespaced and built
	// only by internal/igagraph.Key; a retired row KEEPS its key, which is what
	// makes delete-and-recreate expressible against the partial unique index.
	// GitHub rows keep source_key = '' and stay outside every unique index.
	SourceKey     string `json:"source_key" gorm:"not null;default:''"`
	Continuity    string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey  string `json:"immutable_key" gorm:"not null;default:''"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`
	// AccountState is enabled, disabled or unknown. It is not lifecycle.
	// The parentheses keep GORM from substituting the default on a zero value,
	// so a projection against a schema from before 041 does not name the column.
	AccountState string `json:"account_state" gorm:"not null;default:('enabled')"`

	// ProviderAttrs is display-only provider fact -- tags, path, boundary ARN
	// -- so the read APIs never read cloud_*. Never identity, never a filter.
	ProviderAttrs json.RawMessage `json:"provider_attrs" gorm:"type:jsonb;not null;default:'{}'"`

	// FirstSeenAt is never advanced by an upsert. It is the honest age of the
	// object and the exit gate tests it directly.
	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (IGAIdentityAccount) TableName() string { return "iga_identity_accounts" }

// IGACredential is NON-SECRET metadata about how an identity authenticates.
// No value, no token, no private key, ever.
type IGACredential struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IdentityAccountID uuid.UUID  `json:"identity_account_id" gorm:"type:uuid;not null"`
	CredentialType    string     `json:"credential_type" gorm:"not null"`
	Issuer            string     `json:"issuer" gorm:"not null;default:''"`
	KeyIdentifier     string     `json:"key_identifier" gorm:"not null;default:''"`
	SecretRef         string     `json:"-" gorm:"not null;default:''"`
	IssuedAt          *time.Time `json:"issued_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
	RotationPosture   string     `json:"rotation_posture" gorm:"not null;default:'unknown'"`
	Lifecycle         string     `json:"lifecycle" gorm:"not null;default:'active'"`

	Provider string `json:"provider" gorm:"not null;default:''"`

	// Recognition and continuity (028). A credential's key is "gone" when
	// revoked or expired, not retired -- see uq_iga_credentials_source_key.
	SourceKey     string `json:"source_key" gorm:"not null;default:''"`
	Continuity    string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey  string `json:"immutable_key" gorm:"not null;default:''"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (IGACredential) TableName() string { return "iga_credentials" }

// IGAResource is the protected thing: repository, API, tool, model. For AWS it
// is a RESOURCE REFERENCE -- an exact ARN or a selector pattern a statement
// names -- never a discovered resource (§1.4, §2.14.12).
type IGAResource struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	ResourceKind  string     `json:"resource_kind" gorm:"not null"`
	DisplayName   string     `json:"display_name" gorm:"not null;default:''"`
	Stage         string     `json:"stage" gorm:"not null;default:'unknown'"`
	Lifecycle     string     `json:"lifecycle" gorm:"not null;default:'active'"`

	Provider string `json:"provider" gorm:"not null;default:''"`

	SourceKey     string `json:"source_key" gorm:"not null;default:''"`
	Continuity    string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey  string `json:"immutable_key" gorm:"not null;default:''"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	// ProviderAttrs: account and region ONLY when the ARN carries them, and
	// account_connected. An S3 reference states neither and is never assigned
	// the scanning account (§1.4). Display only. Not an authorization filter.
	ProviderAttrs   json.RawMessage `json:"provider_attrs" gorm:"type:jsonb;not null;default:'{}'"`
	ReferenceStatus string          `json:"reference_status" gorm:"not null;default:('referenced')"`
	NativeKind      string          `json:"native_kind" gorm:"not null;default:('')"`
	KindMetadata    json.RawMessage `json:"kind_metadata" gorm:"type:jsonb;not null;default:'{}'"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (IGAResource) TableName() string { return "iga_resources" }

// IGAEntitlement is one native access unit. For AWS it is ONE STATEMENT of one
// policy document (036); for GitHub it is a grant, and every statement column
// below stays at its default.
//
// NativeRights preserves the provider's own wording; NormalizedRights is our
// derived reading. Both are kept so a reviewer can see what the provider said.
type IGAEntitlement struct {
	ID               uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ResourceID       *uuid.UUID      `json:"resource_id,omitempty" gorm:"type:uuid"`
	NativeGrantKind  string          `json:"native_grant_kind" gorm:"not null"`
	NativeRights     json.RawMessage `json:"native_rights" gorm:"type:jsonb;not null;default:'{}'"`
	NormalizedRights json.RawMessage `json:"normalized_rights" gorm:"type:jsonb;not null;default:'{}'"`
	NativeScope      string          `json:"native_scope" gorm:"not null;default:''"`
	Remediable       bool            `json:"remediable" gorm:"not null;default:false"`

	// Lifecycle did not exist on this table before 028.
	Lifecycle string `json:"lifecycle" gorm:"not null;default:'active'"`

	Provider string `json:"provider" gorm:"not null;default:''"`

	SourceKey     string `json:"source_key" gorm:"not null;default:''"`
	Continuity    string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey  string `json:"immutable_key" gorm:"not null;default:''"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	// The statement (036). iga_entitlements_aws_statement_chk requires, for
	// provider='aws': a policy, a statement key, a lowercase effect and a
	// content hash. StatementIndex is DESCRIPTIVE and never identity (§2.6).
	PolicyID       *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`
	StatementKey   string     `json:"statement_key" gorm:"not null;default:''"`
	Sid            string     `json:"sid" gorm:"not null;default:''"`
	StatementIndex *int       `json:"statement_index,omitempty"`
	Effect         string     `json:"effect" gorm:"not null;default:''"`
	ContentHash    string     `json:"content_hash" gorm:"not null;default:''"`
	Negated        bool       `json:"negated" gorm:"not null;default:false"`
	Conditional    bool       `json:"conditional" gorm:"not null;default:false"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (IGAEntitlement) TableName() string { return "iga_entitlements" }

// Statement effects, LOWERCASE -- the parser stores strings.ToLower
// (internal/awsdiscovery/policy_statements.go). Every comparison is against
// these constants; a capitalised literal is always false.
const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

// IGAAccessEdge is subject -> entitlement -> resource. For AWS it is a GRANT:
// a holder identity -> one Allow statement, through exactly one assignment
// (036). CalculationState is the load-bearing column: a source grant is not
// automatically effective access, and the database refuses a decided
// conclusion on incomplete evidence.
type IGAAccessEdge struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	// THE LEGACY PAIR, KEPT AND STILL WRITTEN until 037 (030 is expand only).
	// The 0e75ad7 binary's GitHub writer and GET .../agents/:id/access-paths
	// read and write these; dropping them makes rollback impossible.
	SubjectKind string    `json:"subject_kind" gorm:"not null"`
	SubjectID   uuid.UUID `json:"subject_id" gorm:"type:uuid;not null"`

	// The TYPED subject (030), composite-FK'd to (workspace_id, id).
	// iga_access_edges_subject_agree_chk requires it to agree with the legacy
	// pair whenever set. No workload subject: a workload holds nothing, it runs
	// AS an identity that does.
	SubjectIdentityAccountID *uuid.UUID `json:"subject_identity_account_id,omitempty" gorm:"type:uuid"`

	Provider string `json:"provider" gorm:"not null;default:''"`

	// Nullable here (030); 036's check requires it for AWS rows.
	EntitlementID *uuid.UUID `json:"entitlement_id,omitempty" gorm:"type:uuid"`
	// The assignment this grant is reached through (036). Required for AWS.
	AssignmentID *uuid.UUID `json:"assignment_id,omitempty" gorm:"type:uuid"`
	// ResourceID is the GitHub path's denormalized single resource. NULL on
	// every AWS grant: a statement names several targets, read through
	// iga_entitlement_target.
	ResourceID *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`

	Direction string `json:"direction" gorm:"not null"`
	PathKind  string `json:"path_kind" gorm:"not null;default:''"`

	// Phase 2 runs no evaluator, so these are always partial/unknown for AWS.
	CalculationState    string `json:"calculation_state" gorm:"not null;default:'unknown'"`
	EffectiveConclusion string `json:"effective_conclusion" gorm:"not null;default:'unknown'"`
	NativeScope         string `json:"native_scope" gorm:"not null;default:''"`

	// Lifecycle (030), identical in meaning to IGARelationship's.
	Basis           string     `json:"basis" gorm:"not null;default:'declared'"`
	DerivationRule  string     `json:"derivation_rule" gorm:"not null;default:''"`
	State           string     `json:"state" gorm:"not null;default:'current'"`
	ValidFrom       time.Time  `json:"valid_from" gorm:"not null;default:now()"`
	ValidTo         *time.Time `json:"valid_to,omitempty"`
	LastConfirmedAt time.Time  `json:"last_confirmed_at" gorm:"not null;default:now()"`
	LastConfirmedBy *uuid.UUID `json:"last_confirmed_by,omitempty" gorm:"type:uuid"`
	EndedReason     string     `json:"ended_reason" gorm:"not null;default:''"`
	SourceKey       string     `json:"source_key" gorm:"not null;default:''"`

	// Partition membership. An edge written without these is invisible to
	// reconciliation and never ends.
	PartitionKey           string     `json:"partition_key" gorm:"not null;default:''"`
	ConnectorID            *uuid.UUID `json:"connector_id,omitempty" gorm:"type:uuid"`
	IntegrationID          *uuid.UUID `json:"integration_id,omitempty" gorm:"type:uuid"`
	ConfirmingIGAScanRunID *uuid.UUID `json:"confirming_iga_scan_run_id,omitempty" gorm:"type:uuid"`

	ObservedAt *time.Time `json:"observed_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (IGAAccessEdge) TableName() string { return "iga_access_edges" }

// IGAAttributeValue is survivorship. When sources disagree, both values are
// kept with their authority rank; the winner is a decision, not an accident.
type IGAAttributeValue struct {
	ID             uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EntityKind     string          `json:"entity_kind" gorm:"not null"`
	EntityID       uuid.UUID       `json:"entity_id" gorm:"type:uuid;not null"`
	Attribute      string          `json:"attribute" gorm:"not null"`
	Value          json.RawMessage `json:"value" gorm:"type:jsonb"`
	ObservationID  *uuid.UUID      `json:"observation_id,omitempty" gorm:"type:uuid"`
	AuthorityRank  int             `json:"authority_rank" gorm:"not null;default:0"`
	State          string          `json:"state" gorm:"not null;default:'surviving'"`
	ValidFrom      *time.Time      `json:"valid_from,omitempty"`
	ValidTo        *time.Time      `json:"valid_to,omitempty"`
	FallbackReason string          `json:"fallback_reason" gorm:"not null;default:''"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (IGAAttributeValue) TableName() string { return "iga_canonical_attribute_values" }

// IGAAuthorityPolicy decides which source wins for which attribute.
type IGAAuthorityPolicy struct {
	ID                     uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID            uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EntityKind             string    `json:"entity_kind" gorm:"not null"`
	Attribute              string    `json:"attribute" gorm:"not null"`
	Provider               string    `json:"provider" gorm:"not null;default:''"`
	AuthorityRank          int       `json:"authority_rank" gorm:"not null;default:0"`
	AllowAuthoritativeNull bool      `json:"allow_authoritative_null" gorm:"not null;default:false"`
	Version                int64     `json:"version" gorm:"not null;default:1"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func (IGAAuthorityPolicy) TableName() string { return "iga_attribute_authority_policies" }

// IGAObservationLink is the drill-down path. Every canonical value must resolve
// to the observations that support it and, crucially, those that contradict it.
type IGAObservationLink struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ObservationID uuid.UUID `json:"observation_id" gorm:"type:uuid;not null"`
	TargetKind    string    `json:"target_kind" gorm:"not null"`
	TargetID      uuid.UUID `json:"target_id" gorm:"type:uuid;not null"`
	Relation      string    `json:"relation" gorm:"not null"`
	CreatedAt     time.Time `json:"created_at"`
}

func (IGAObservationLink) TableName() string { return "iga_observation_links" }

// IGAOwnershipCandidate is a proposed TECHNICAL owner. A code owner is not a
// business sponsor; no row here may silently populate sponsorship.
type IGAOwnershipCandidate struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SubjectKind    string     `json:"subject_kind" gorm:"not null"`
	SubjectID      uuid.UUID  `json:"subject_id" gorm:"type:uuid;not null"`
	CandidateKind  string     `json:"candidate_kind" gorm:"not null"`
	CandidateRef   string     `json:"candidate_ref" gorm:"not null"`
	EvidenceSource string     `json:"evidence_source" gorm:"not null;default:''"`
	Rank           int        `json:"rank" gorm:"not null;default:0"`
	State          string     `json:"state" gorm:"not null;default:'proposed'"`
	DecidedBy      *string    `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Version        int64      `json:"version" gorm:"not null;default:1"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (IGAOwnershipCandidate) TableName() string { return "iga_ownership_candidates" }

// IGAOperationalIssue is permission loss, staleness, truncation, API failure.
// Kept strictly separate from agent-risk findings.
type IGAOperationalIssue struct {
	ID            uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IntegrationID *uuid.UUID      `json:"integration_id,omitempty" gorm:"type:uuid"`
	IssueKind     string          `json:"issue_kind" gorm:"not null"`
	Severity      string          `json:"severity" gorm:"not null;default:'info'"`
	ObjectClass   string          `json:"object_class" gorm:"not null;default:''"`
	ScopeRef      string          `json:"scope_ref" gorm:"not null;default:''"`
	Detail        json.RawMessage `json:"detail" gorm:"type:jsonb;not null;default:'{}'"`
	State         string          `json:"state" gorm:"not null;default:'open'"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	ResolvedAt    *time.Time      `json:"resolved_at,omitempty"`
}

func (IGAOperationalIssue) TableName() string { return "iga_operational_issues" }
