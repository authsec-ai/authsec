package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// This file holds the Phase 2 identity-graph types: the canonical runtime, the
// binary structural edge, per-source support, and the projection's own durable
// job and watermark. SPEC-iga-phase2-graph.md §2 and §3 (migrations 026-033).
//
// The vocabularies below are duplicated as CHECK constraints in the
// migrations. That duplication is deliberate and one-directional: the database
// is the authority, and these constants exist so Go code cannot spell a legal
// value wrongly. When they disagree, the migration wins and the constant is
// the bug.

// Relationship and access-edge lifecycle (§2.7).
//
// Collapsing RelStale into RelEnded lets a permissions outage read as a
// cleanup, which is the single most expensive mistake available in this model.
const (
	// RelCurrent means a recent authoritative read confirmed it.
	RelCurrent = "current"
	// RelStale means we could not look. Still believed, with its last
	// confirmation time shown. A failed, denied or throttled scan produces
	// this and NEVER RelEnded.
	RelStale = "stale"
	// RelEnded means an authoritative read of the owning scope and class did
	// not see it. Ended rows are never deleted: a review decision made last
	// quarter must remain explicable against the access that existed then.
	RelEnded = "ended"
)

// What kind of claim an edge makes (§2.3).
const (
	// BasisDeclared -- provider configuration says so. Everything Phase 2
	// projects is this.
	BasisDeclared = "declared"
	// BasisObserved -- we saw it happen, with attribution. NOTHING produces
	// this today; no CloudTrail collector exists.
	BasisObserved = "observed"
	// BasisDerived -- we computed it, naming the rule and its inputs. Requires
	// a non-empty derivation rule, enforced by CHECK.
	BasisDerived = "derived"
	// BasisAsserted -- a human decided it, with authority recorded.
	BasisAsserted = "asserted"
)

// Relationship types. The legal (source, type, target) triples are enumerated
// in iga_relationship_pair_chk, whose ELSE false arm means a fourth type
// cannot be inserted until someone widens the constraint deliberately.
const (
	// RelTypeExecutesAs is workload -> identity account, from
	// cloud_workload.identity_id. Means a CONFIGURED execution identity --
	// never that it ran, or ran as that.
	RelTypeExecutesAs = "executes_as"
	// RelTypeCanAssume is identity -> identity (or external principal ->
	// identity), from cloud_assume_edge. Means trust PERMITS assumption --
	// never that assumption succeeds.
	RelTypeCanAssume = "can_assume"
	// RelTypeRealizes is agent instance -> workload.
	RelTypeRealizes = "realizes"
)

// Continuity (§2.4). Mirrors internal/igagraph's constants; kept here too so
// model code does not have to import the projection package.
const (
	ContinuityImmutable       = "immutable"
	ContinuityRecognitionOnly = "recognition_only"
)

// Node lifecycle, shared by the canonical node tables.
const (
	IGALifecycleActive     = "active"
	IGALifecycleRetired    = "retired"
	IGALifecycleTombstoned = "tombstoned"
)

// Why a node was retired. Never an empty string on a retired row.
const (
	// RetiredRecreated -- same recognition key, different creation boundary.
	// A different principal wearing the old name.
	RetiredRecreated = "recreated"
	// RetiredUnsupported -- every source that vouched for this object has
	// ended its support (§2.10B).
	RetiredUnsupported = "unsupported"
	// RetiredPreGraph -- a legacy row with no recognition key, retired by 034.
	RetiredPreGraph = "pre_graph"
)

// Why an edge ended.
const (
	EndedNotSeen         = "not_seen"
	EndedSubjectRetired  = "subject_retired"
	EndedSubjectRecreate = "subject_recreated"
)

// Agent origin (§3, 032). The exit gate's "a registered agent is distinguished
// from native discovery": the two get different review treatment and must
// never silently merge.
const (
	OriginRegistered = "registered"
	OriginDiscovered = "discovered"
)

// Access-edge calculation honesty is already spelled in iga.go as
// CalcComplete/CalcPartial/CalcUnknown and Conclusion*; they are not restated
// here. iga_access_edges_honesty_chk (004) refuses a decided conclusion on an
// incomplete calculation, and Phase 2 writes CalcPartial/ConclusionUnknown
// unconditionally because it runs no evaluator.

// Object classes for iga_object_support.
const (
	ObjectIdentity    = "identity"
	ObjectWorkload    = "workload"
	ObjectResource    = "resource"
	ObjectEntitlement = "entitlement"
	ObjectAgent       = "agent"
)

// Projection job status.
const (
	ProjectionQueued    = "queued"
	ProjectionRunning   = "running"
	ProjectionComplete  = "complete"
	ProjectionFailed    = "failed"
	ProjectionAbandoned = "abandoned"
)

// Pipeline lease states (§2.10A).
const (
	PipelineIdle       = "idle"
	PipelineCollecting = "collecting"
	PipelineProjecting = "projecting"
)

/* -------------------------------- iga_workload ---------------------------- */

// IGAWorkload is the canonical runtime, projected one-way from cloud_workload.
//
// NOT an agent instance: an instance may not be compute at all (a published
// SaaS agent, a Bedrock alias). Where a Bedrock agent IS the runtime, the
// projector writes both rows and links them with a realizes relationship.
type IGAWorkload struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`

	RuntimeKind   string `json:"runtime_kind" gorm:"not null"`
	DisplayName   string `json:"display_name" gorm:"not null;default:''"`
	Stage         string `json:"stage" gorm:"not null;default:'unknown'"`
	Lifecycle     string `json:"lifecycle" gorm:"not null;default:'active'"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	SourceKey    string `json:"source_key" gorm:"not null"`
	Continuity   string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey string `json:"immutable_key" gorm:"not null;default:''"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (IGAWorkload) TableName() string { return "iga_workload" }

/* ------------------------------ iga_relationship -------------------------- */

// IGARelationship is a binary structural edge with typed endpoints on BOTH
// ends. Exactly one source and exactly one target are set, always, and which
// pair is legal depends on RelationshipType.
type IGARelationship struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	RelationshipType string    `json:"relationship_type" gorm:"not null"`

	SourceIdentityAccountID   *uuid.UUID `json:"source_identity_account_id,omitempty" gorm:"type:uuid"`
	SourceWorkloadID          *uuid.UUID `json:"source_workload_id,omitempty" gorm:"type:uuid"`
	SourceAgentInstanceID     *uuid.UUID `json:"source_agent_instance_id,omitempty" gorm:"type:uuid"`
	SourceExternalPrincipalID *uuid.UUID `json:"source_external_principal_id,omitempty" gorm:"type:uuid"`

	TargetIdentityAccountID *uuid.UUID `json:"target_identity_account_id,omitempty" gorm:"type:uuid"`
	TargetWorkloadID        *uuid.UUID `json:"target_workload_id,omitempty" gorm:"type:uuid"`
	TargetAgentID           *uuid.UUID `json:"target_agent_id,omitempty" gorm:"type:uuid"`

	Basis           string     `json:"basis" gorm:"not null;default:'declared'"`
	DerivationRule  string     `json:"derivation_rule" gorm:"not null;default:''"`
	State           string     `json:"state" gorm:"not null;default:'current'"`
	ValidFrom       time.Time  `json:"valid_from" gorm:"not null;default:now()"`
	ValidTo         *time.Time `json:"valid_to,omitempty"`
	LastConfirmedAt time.Time  `json:"last_confirmed_at" gorm:"not null;default:now()"`
	LastConfirmedBy *uuid.UUID `json:"last_confirmed_by,omitempty" gorm:"type:uuid"`
	EndedReason     string     `json:"ended_reason" gorm:"not null;default:''"`
	SourceKey       string     `json:"source_key" gorm:"not null"`

	// PartitionKey and ConnectorID are the membership reconciliation selects
	// on. An edge written without them is invisible to reconciliation and
	// never ends -- see §4.10.
	PartitionKey string     `json:"partition_key" gorm:"not null;default:''"`
	ConnectorID  *uuid.UUID `json:"connector_id,omitempty" gorm:"type:uuid"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (IGARelationship) TableName() string { return "iga_relationship" }

// Source returns the one endpoint that is set, as (kind, id). Keeps the
// multi-column awkwardness out of read call sites; WRITES NAME THE COLUMN.
func (r IGARelationship) Source() (string, uuid.UUID) {
	switch {
	case r.SourceIdentityAccountID != nil:
		return "identity_account", *r.SourceIdentityAccountID
	case r.SourceWorkloadID != nil:
		return "workload", *r.SourceWorkloadID
	case r.SourceAgentInstanceID != nil:
		return "agent_instance", *r.SourceAgentInstanceID
	case r.SourceExternalPrincipalID != nil:
		return "external_principal", *r.SourceExternalPrincipalID
	}
	return "", uuid.Nil
}

// Target returns the one target endpoint that is set, as (kind, id).
func (r IGARelationship) Target() (string, uuid.UUID) {
	switch {
	case r.TargetIdentityAccountID != nil:
		return "identity_account", *r.TargetIdentityAccountID
	case r.TargetWorkloadID != nil:
		return "workload", *r.TargetWorkloadID
	case r.TargetAgentID != nil:
		return "agent", *r.TargetAgentID
	}
	return "", uuid.Nil
}

/* --------------------------- iga_external_principal ----------------------- */

// IGAExternalPrincipal is the far end of a cross-provider trust, recorded by
// the side that declares it (§2.12).
//
// A node and not a string on the edge: when the far provider connects later,
// resolution UPGRADES THIS ROW and the relationship keeps its identity and its
// whole history. A string endpoint would force delete-and-recreate, destroying
// "this access has existed since March".
type IGAExternalPrincipal struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Issuer       string    `json:"issuer" gorm:"not null"`
	SubjectClaim string    `json:"subject_claim" gorm:"not null"`
	Mechanism    string    `json:"mechanism" gorm:"not null"`
	SourceKey    string    `json:"source_key" gorm:"not null"`

	// Nullable forever when the claim is wildcarded or the far provider is not
	// connected. That is an honest state, not a gap to fill with a guess.
	ResolvedObjectType string     `json:"resolved_object_type" gorm:"not null;default:''"`
	ResolvedObjectID   *uuid.UUID `json:"resolved_object_id,omitempty" gorm:"type:uuid"`
	ResolutionBasis    string     `json:"resolution_basis" gorm:"not null;default:''"`
	ResolutionRule     string     `json:"resolution_rule" gorm:"not null;default:''"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
}

func (IGAExternalPrincipal) TableName() string { return "iga_external_principal" }

/* ------------------------------ evidence junctions ------------------------ */

// IGAAccessEdgeEvidence links an access edge to the observation supporting it.
// Both endpoints typed and FK'd, unlike iga_observation_links.
type IGAAccessEdgeEvidence struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	AccessEdgeID  uuid.UUID `json:"access_edge_id" gorm:"type:uuid;not null"`
	ObservationID uuid.UUID `json:"observation_id" gorm:"type:uuid;not null"`
	Relation      string    `json:"relation" gorm:"not null;default:'supports'"`
	CreatedAt     time.Time `json:"created_at"`
}

func (IGAAccessEdgeEvidence) TableName() string { return "iga_access_edge_evidence" }

// IGARelationshipEvidence is the same junction against iga_relationship.
type IGARelationshipEvidence struct {
	ID             uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	RelationshipID uuid.UUID `json:"relationship_id" gorm:"type:uuid;not null"`
	ObservationID  uuid.UUID `json:"observation_id" gorm:"type:uuid;not null"`
	Relation       string    `json:"relation" gorm:"not null;default:'supports'"`
	CreatedAt      time.Time `json:"created_at"`
}

func (IGARelationshipEvidence) TableName() string { return "iga_relationship_evidence" }

/* ----------------------------- iga_object_support ------------------------- */

// IGAObjectSupport is one row per (object, connector, partition): who still
// vouches for this node (§2.10B).
//
// Reconciliation ends SUPPORT, never a node directly. A node retires only when
// every support of it has ended -- which is what stops account B's scan
// retiring a bucket account A still holds.
type IGAObjectSupport struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ObjectType   string    `json:"object_type" gorm:"not null"`
	ObjectID     uuid.UUID `json:"object_id" gorm:"type:uuid;not null"`
	ConnectorID  uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	PartitionKey string    `json:"partition_key" gorm:"not null"`

	State              string     `json:"state" gorm:"not null;default:'current'"`
	FirstSeenAt        time.Time  `json:"first_seen_at" gorm:"not null;default:now()"`
	LastConfirmedRunID *uuid.UUID `json:"last_confirmed_run_id,omitempty" gorm:"type:uuid"`
	LastConfirmedAt    *time.Time `json:"last_confirmed_at,omitempty"`
	EndedReason        string     `json:"ended_reason" gorm:"not null;default:''"`
}

func (IGAObjectSupport) TableName() string { return "iga_object_support" }

/* --------------------------- projection job and state --------------------- */

// IGAProjectionJob is the durable, separately-fenced unit of projection work.
//
// It cannot run under the scan lease: Publish() releases that lease, so any
// fenced call after publication returns ErrLeaseLost and affects zero rows.
// This mirrors cloud_scan_run's pattern exactly rather than inventing a second
// ownership notion.
type IGAProjectionJob struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ScanRunID   uuid.UUID `json:"scan_run_id" gorm:"type:uuid;not null"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	Generation  int       `json:"generation" gorm:"not null"`
	Status      string    `json:"status" gorm:"not null;default:'queued'"`

	LeaseOwner     string     `json:"lease_owner" gorm:"not null;default:''"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	// LeaseVersion is the fence token, never a clock.
	LeaseVersion int64 `json:"lease_version" gorm:"not null;default:0"`

	Attempts    int        `json:"attempts" gorm:"not null;default:0"`
	LastError   string     `json:"last_error" gorm:"not null;default:''"`
	RequestedAt time.Time  `json:"requested_at" gorm:"not null;default:now()"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

func (IGAProjectionJob) TableName() string { return "iga_projection_job" }

// IGAProjectionState is the per-partition watermark.
//
// Reconciled stays false until the Reconciler commits, so a pass interrupted
// between projection and reconciliation is visible as exactly that.
type IGAProjectionState struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID    uuid.UUID `json:"estate_scope_id" gorm:"type:uuid;not null"`
	ConnectorID      uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	ObjectClass      string    `json:"object_class" gorm:"not null;default:''"`
	RelationshipType string    `json:"relationship_type" gorm:"not null;default:''"`
	PartitionKey     string    `json:"partition_key" gorm:"not null"`
	LastRunID        uuid.UUID `json:"last_run_id" gorm:"type:uuid;not null"`
	LastGeneration   int64     `json:"last_generation" gorm:"not null"`
	CoverageState    string    `json:"coverage_state" gorm:"not null"`
	Reconciled       bool      `json:"reconciled" gorm:"not null;default:false"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (IGAProjectionState) TableName() string { return "iga_projection_state" }

/* ----------------------------- iga_pipeline_lease ------------------------- */

// IGAPipelineLease is the workspace-wide barrier between collection and
// projection (§2.10A).
//
// A durable ROW and not an advisory lock, because publication and projection
// are necessarily different transactions and pg_advisory_xact_lock dies at
// commit -- the window between them is exactly where a second connector's scan
// overwrites a shared resource row.
//
// The cost is stated plainly: scanning serializes per WORKSPACE, not per
// connector.
type IGAPipelineLease struct {
	WorkspaceID uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	State       string     `json:"state" gorm:"not null;default:'idle'"`
	Holder      string     `json:"holder" gorm:"not null;default:''"`
	ScanRunID   *uuid.UUID `json:"scan_run_id,omitempty" gorm:"type:uuid"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Version     int64      `json:"version" gorm:"not null;default:0"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAPipelineLease) TableName() string { return "iga_pipeline_lease" }

/* --------------------------------- helpers -------------------------------- */

// NativeRights is the provider's own wording for a grant, preserved verbatim.
//
// NotActions and NotResources are NOT optional extras: a NotAction-only
// statement is a real grant shape (019 relaxed cloud_permission_actions_chk
// precisely to allow it), and an entitlement that silently loses the negation
// reads as BROADER access than exists.
type NativeRights struct {
	Effect       string          `json:"effect"`
	Actions      []string        `json:"actions,omitempty"`
	NotActions   []string        `json:"not_actions,omitempty"`
	NotResources []string        `json:"not_resources,omitempty"`
	Condition    json.RawMessage `json:"condition,omitempty"`
}

// NormalizedRights is our reading, kept beside the native form and never
// instead of it. A customer must always be able to see what AWS actually said.
type NormalizedRights struct {
	Verbs       []string `json:"verbs,omitempty"`
	Constrained bool     `json:"constrained"`
}
