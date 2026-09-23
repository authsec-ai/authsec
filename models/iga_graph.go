package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// This file holds the Phase 2 identity-graph types: the canonical runtime, the
// binary structural edge, the permission model, per-source support, and the
// projection's own durable job and watermark. SPEC-iga-phase2-graph.md §2 and
// §3 (migrations 027-036).
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
	// BasisDeclared -- provider configuration says so. Everything this
	// milestone projects from AWS is this.
	BasisDeclared = "declared"
	// BasisObserved -- we saw it happen, with attribution. NOTHING produces
	// this; no CloudTrail attribution exists (§1.2).
	BasisObserved = "observed"
	// BasisDerived -- we computed it, naming the rule and its inputs. Requires
	// a non-empty derivation rule, enforced by CHECK.
	BasisDerived = "derived"
	// BasisAsserted -- a human decided it, with authority recorded.
	BasisAsserted = "asserted"
)

// Relationship types (031). The legal (source, type, target) triples are
// iga_relationship_pair_chk, whose ELSE false arm means a fifth type cannot be
// inserted until someone widens the constraint deliberately.
const (
	// RelTypeExecutesAs is workload -> identity: the role the workload is
	// CONFIGURED to act as. Never that it ran, or ran as that.
	RelTypeExecutesAs = "executes_as"
	// RelTypeTaskExecutionRole is ECS workload -> identity: the role ECS itself
	// uses to pull images and fetch secrets. NOT the task's own identity.
	RelTypeTaskExecutionRole = "task_execution_role"
	// RelTypeMemberOf is user -> group. The group's policies apply to the user
	// by traversal; nothing is copied onto the user (§2.6).
	RelTypeMemberOf = "member_of"
	// RelTypeCanAssume is identity or external principal -> role, from an
	// Allow statement of the role's trust policy. Trust PERMITS assumption --
	// never that assumption succeeds.
	RelTypeCanAssume = "can_assume"
)

// Trust mechanisms (iga_relationship.mechanism, required exactly for
// can_assume by iga_relationship_trust_chk).
const (
	MechanismSTSAssumeRole  = "sts_assume_role"
	MechanismOIDCFederation = "oidc_federation"
	MechanismSAMLFederation = "saml_federation"
	MechanismEKSPodIdentity = "eks_pod_identity"
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
	// RetiredPolicyRecreated -- a statement of a policy incarnation that was
	// itself recreated (§4.7).
	RetiredPolicyRecreated = "policy_recreated"
)

// Why an edge, assignment or support row ended.
const (
	EndedNotSeen          = "not_seen"
	EndedSubjectRetired   = "subject_retired"
	EndedSubjectRecreate  = "subject_recreated"
	EndedPolicyRecreated  = "policy_recreated"
	EndedPolicyRetired    = "policy_retired"
	EndedStatementRetired = "statement_retired"
)

// Workload classification (§2.14.3).
const (
	ClassificationUnclassified  = "unclassified"
	ClassificationProviderAgent = "provider_native_agent"
	ClassificationClassified    = "classified_agent"
)

// Execution-role state (§4.6). Read INSTEAD of inferring from the absence of
// an executes_as edge -- the absence cannot tell "no role configured" from
// "configured, but its identity was not in this scan", and those are opposite
// findings.
const (
	ExecRoleResolved       = "resolved"
	ExecRoleNotInScan      = "not_in_scan"
	ExecRoleNotInInventory = "not_in_inventory"
	ExecRoleNone           = "none"
)

// External-principal resolution lifecycle (§2.12).
//
// A DERIVED resolution is re-derived every pass, so it needs no lifecycle. An
// ASSERTED one is a person's decision: it is preserved when its target retires
// but stops being in force, and NEVER returns to active automatically -- the
// same UniqueID coming back is a reason to ask, not to assume.
const (
	ResolutionActive                = "active"
	ResolutionSuspended             = "suspended"
	ResolutionPendingReconfirmation = "pending_reconfirmation"
)

// Access-edge calculation honesty is already spelled in iga.go as
// CalcComplete/CalcPartial/CalcUnknown and Conclusion*; they are not restated
// here. iga_access_edges_honesty_chk (004) refuses a decided conclusion on an
// incomplete calculation, and this milestone writes CalcPartial /
// ConclusionUnknown unconditionally because it runs no evaluator.

// Node classes: the typed columns of iga_object_support and the tables the
// reconciler derives lifecycle for.
const (
	ObjectIdentity    = "identity"
	ObjectWorkload    = "workload"
	ObjectResource    = "resource"
	ObjectEntitlement = "entitlement"
	ObjectPolicy      = "policy"
)

// NodeClasses is every class with a support column. retireUnsupported walks
// it, and a unit test asserts each resolves in both SupportColumn and
// NodeTable -- adding a class is one edit in two adjacent functions.
var NodeClasses = []string{
	ObjectIdentity, ObjectWorkload, ObjectResource, ObjectEntitlement, ObjectPolicy,
}

// Policy kinds (iga_policy.policy_kind).
const (
	PolicyKindAWSManaged      = "aws_managed"
	PolicyKindCustomerManaged = "customer_managed"
	PolicyKindInline          = "inline"
)

// Assignment kinds: how a policy applies to a holder. A boundary LIMITS and
// never grants (§2.6).
const (
	AssignmentAttached = "attached"
	AssignmentInline   = "inline"
	AssignmentBoundary = "boundary"
)

// Target modes: a statement's Resource list, or its NotResource list. A
// NotResource entry is an EXCLUSION, never a destination.
const (
	TargetResource    = "resource"
	TargetNotResource = "not_resource"
)

// Lifecycle events (036): the append-only history the node row cannot keep.
const (
	LifecycleFirstSeen = "first_seen"
	LifecycleRetired   = "retired"
	LifecycleRestored  = "restored"
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

// PipelineJobHolder is the barrier holder while projecting: the JOB, not a
// worker (§2.10A). Whoever holds that job's lease may proceed at once; a worker
// that lost the job lease is fenced out by the job, not by a timer.
func PipelineJobHolder(jobID uuid.UUID) string { return "job:" + jobID.String() }

/* -------------------------------- iga_workload ---------------------------- */

// IGAWorkload is the canonical runtime, projected one-way from cloud_workload.
//
// ONLY WORKLOADS are materialized for AWS in this milestone (§2.2). A Bedrock
// agent or AgentCore runtime is a workload classified provider_native_agent;
// nothing is written to iga_agents or iga_agent_instances.
type IGAWorkload struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EstateScopeID *uuid.UUID `json:"estate_scope_id,omitempty" gorm:"type:uuid"`

	Provider    string `json:"provider" gorm:"not null;default:'aws'"`
	RuntimeKind string `json:"runtime_kind" gorm:"not null"`
	DisplayName string `json:"display_name" gorm:"not null;default:''"`
	// Region is the COLLECTED region (cloud_workload.region), never parsed
	// from the ARN: EC2 instance ids carry none.
	Region        string `json:"region" gorm:"not null;default:''"`
	Stage         string `json:"stage" gorm:"not null;default:'unknown'"`
	Lifecycle     string `json:"lifecycle" gorm:"not null;default:'active'"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	SourceKey    string `json:"source_key" gorm:"not null"`
	Continuity   string `json:"continuity" gorm:"not null;default:'recognition_only'"`
	ImmutableKey string `json:"immutable_key" gorm:"not null;default:''"`

	ProviderAttrs json.RawMessage `json:"provider_attrs" gorm:"type:jsonb;not null;default:'{}'"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// ExecutionRoleState says what we know about the role this workload acts
	// as when no executes_as edge records it. ExecutionRoleARN is set exactly
	// for the two middle states, where it is the only place the role is named.
	ExecutionRoleState string `json:"execution_role_state" gorm:"not null;default:'none'"`
	ExecutionRoleARN   string `json:"execution_role_arn" gorm:"not null;default:''"`

	// Classification is what this workload IS. provider_native_agent is
	// written by the projector ON INSERT ONLY; classified_agent is a person's
	// decision. ClassificationVersion is the optimistic-concurrency token.
	Classification        string `json:"classification" gorm:"not null;default:'unclassified'"`
	ClassificationVersion int64  `json:"classification_version" gorm:"not null;default:0"`
}

func (IGAWorkload) TableName() string { return "iga_workload" }

// IGAWorkloadClassification is the decision record behind a classification
// (029, §5.5). Human decisions are never rows the projector writes.
type IGAWorkloadClassification struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	WorkloadID  uuid.UUID `json:"workload_id" gorm:"type:uuid;not null"`
	// OperationID is client-generated, one per intent: a retry of the same
	// operation replays, a different operation against a stale version is a
	// conflict (§5.5).
	OperationID uuid.UUID `json:"operation_id" gorm:"type:uuid;not null"`
	Decision    string    `json:"decision" gorm:"not null"`
	Previous    string    `json:"previous" gorm:"not null"`
	Purpose     string    `json:"purpose" gorm:"not null;default:''"`
	Reason      string    `json:"reason" gorm:"not null"`
	// DecidedByUserID is the stable identity, never an email.
	DecidedByUserID  uuid.UUID  `json:"decided_by_user_id" gorm:"type:uuid;not null"`
	AgainstVersion   int64      `json:"against_version" gorm:"not null"`
	RequestHash      string     `json:"request_hash" gorm:"not null"`
	ResultVersion    int64      `json:"result_version" gorm:"not null"`
	UndoesDecisionID *uuid.UUID `json:"undoes_decision_id,omitempty" gorm:"type:uuid"`
	DecidedAt        time.Time  `json:"decided_at" gorm:"not null;default:now()"`
}

func (IGAWorkloadClassification) TableName() string { return "iga_workload_classification" }

// IGAClassificationClock is one counter per workspace, bumped in every
// decision transaction; list cursors that filter on classification bind to it.
type IGAClassificationClock struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Seq         int64     `json:"seq" gorm:"not null;default:0"`
}

func (IGAClassificationClock) TableName() string { return "iga_classification_clock" }

/* ------------------------------ iga_relationship -------------------------- */

// IGARelationship is a binary structural edge with typed endpoints on BOTH
// ends. Exactly one source is set, always; every type this milestone writes
// targets an identity account, so the target is one column.
type IGARelationship struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	RelationshipType string    `json:"relationship_type" gorm:"not null"`

	SourceIdentityAccountID   *uuid.UUID `json:"source_identity_account_id,omitempty" gorm:"type:uuid"`
	SourceWorkloadID          *uuid.UUID `json:"source_workload_id,omitempty" gorm:"type:uuid"`
	SourceExternalPrincipalID *uuid.UUID `json:"source_external_principal_id,omitempty" gorm:"type:uuid"`

	TargetIdentityAccountID *uuid.UUID `json:"target_identity_account_id,omitempty" gorm:"type:uuid"`

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

	// can_assume only: the trust statement that declared it, verbatim facts.
	// Conditions are RECORDED, NEVER EVALUATED; nil means no Condition.
	StatementKey string          `json:"statement_key" gorm:"not null;default:''"`
	Conditions   json.RawMessage `json:"conditions,omitempty" gorm:"type:jsonb"`
	Mechanism    string          `json:"mechanism" gorm:"not null;default:''"`

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
	case r.SourceExternalPrincipalID != nil:
		return "external_principal", *r.SourceExternalPrincipalID
	}
	return "", uuid.Nil
}

/* ----------------------------- the permission model ----------------------- */

// IGAPolicy is a managed policy (AWS- or customer-managed), or one holder's
// inline policy (036, §2.6). A managed policy attached in two accounts is ONE
// policy with one support row per account.
type IGAPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Provider    string    `json:"provider" gorm:"not null"`
	PolicyKind  string    `json:"policy_kind" gorm:"not null"`
	DisplayName string    `json:"display_name" gorm:"not null"`
	// NativeRef is the ARN for a managed policy, '' for inline.
	NativeRef string `json:"native_ref" gorm:"not null;default:''"`

	SourceKey  string `json:"source_key" gorm:"not null"`
	Continuity string `json:"continuity" gorm:"not null"`
	// ImmutableKey is the PolicyId (ANPA...) for managed; the holder's
	// immutable key for inline, because an inline policy lives and dies with
	// its holder.
	ImmutableKey string `json:"immutable_key" gorm:"not null;default:''"`

	VersionID     string `json:"version_id" gorm:"not null;default:''"`
	DocumentHash  string `json:"document_hash" gorm:"not null;default:''"`
	Lifecycle     string `json:"lifecycle" gorm:"not null;default:'active'"`
	RetiredReason string `json:"retired_reason" gorm:"not null;default:''"`

	FirstSeenAt time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt  time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
}

func (IGAPolicy) TableName() string { return "iga_policy" }

// IGAStatementRevision is the content history of a Sid-keyed statement (036).
// One live revision (valid_to IS NULL) per statement; a closed revision is
// never rewritten.
type IGAStatementRevision struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EntitlementID   uuid.UUID       `json:"entitlement_id" gorm:"type:uuid;not null"`
	ContentHash     string          `json:"content_hash" gorm:"not null"`
	Statement       json.RawMessage `json:"statement" gorm:"type:jsonb;not null"`
	PolicyVersionID string          `json:"policy_version_id" gorm:"not null;default:''"`
	ValidFrom       time.Time       `json:"valid_from" gorm:"not null"`
	ValidTo         *time.Time      `json:"valid_to,omitempty"`
	FirstSeenRunID  uuid.UUID       `json:"first_seen_run_id" gorm:"type:uuid;not null"`
}

func (IGAStatementRevision) TableName() string { return "iga_statement_revision" }

// IGAEntitlementTarget is statement -> resource reference: what the
// statement's Resource or NotResource names (036). Derived from content, so a
// statement's target set is replaced only when its content hash changes.
type IGAEntitlementTarget struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	EntitlementID uuid.UUID `json:"entitlement_id" gorm:"type:uuid;not null"`
	ResourceID    uuid.UUID `json:"resource_id" gorm:"type:uuid;not null"`
	TargetMode    string    `json:"target_mode" gorm:"not null"`
	Ordinal       int       `json:"ordinal" gorm:"not null"`
}

func (IGAEntitlementTarget) TableName() string { return "iga_entitlement_target" }

// IGAPolicyAssignment is policy -> holder: attached, embedded inline, or set
// as a permissions boundary (036). A PERIOD, not a flag: detach ends the row,
// and a later reattach creates a NEW row, so "was this attached on 1 March?"
// is answerable and a reattach never rewrites the earlier period.
type IGAPolicyAssignment struct {
	ID                      uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID             uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	PolicyID                uuid.UUID  `json:"policy_id" gorm:"type:uuid;not null"`
	HolderIdentityAccountID uuid.UUID  `json:"holder_identity_account_id" gorm:"type:uuid;not null"`
	AssignmentKind          string     `json:"assignment_kind" gorm:"not null"`
	Basis                   string     `json:"basis" gorm:"not null;default:'declared'"`
	State                   string     `json:"state" gorm:"not null;default:'current'"`
	ValidFrom               time.Time  `json:"valid_from" gorm:"not null;default:now()"`
	ValidTo                 *time.Time `json:"valid_to,omitempty"`
	LastConfirmedAt         time.Time  `json:"last_confirmed_at" gorm:"not null;default:now()"`
	LastConfirmedBy         *uuid.UUID `json:"last_confirmed_by,omitempty" gorm:"type:uuid"`
	EndedReason             string     `json:"ended_reason" gorm:"not null;default:''"`
	SourceKey               string     `json:"source_key" gorm:"not null"`
	PartitionKey            string     `json:"partition_key" gorm:"not null"`
	ConnectorID             *uuid.UUID `json:"connector_id,omitempty" gorm:"type:uuid"`
}

func (IGAPolicyAssignment) TableName() string { return "iga_policy_assignment" }

// IGAAssignmentEvidence links an assignment to the observations supporting it.
type IGAAssignmentEvidence struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	AssignmentID  uuid.UUID `json:"assignment_id" gorm:"type:uuid;not null"`
	ObservationID uuid.UUID `json:"observation_id" gorm:"type:uuid;not null"`
	Relation      string    `json:"relation" gorm:"not null;default:'supports'"`
	CreatedAt     time.Time `json:"created_at"`
}

func (IGAAssignmentEvidence) TableName() string { return "iga_assignment_evidence" }

// IGALifecycleEvent is the append-only node history (036). Node and support
// updates overwrite lifecycle, and a restoration clears retired_reason, so the
// row alone cannot answer "when was this retired, and why". Its FK to the
// publication is DEFERRED: an event exists only together with the publication
// it belongs to.
type IGALifecycleEvent struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Rev               int64      `json:"rev" gorm:"not null"`
	ScanRunID         uuid.UUID  `json:"scan_run_id" gorm:"type:uuid;not null"`
	OccurredAt        time.Time  `json:"occurred_at" gorm:"not null"`
	Event             string     `json:"event" gorm:"not null"`
	Reason            string     `json:"reason" gorm:"not null;default:''"`
	IdentityAccountID *uuid.UUID `json:"identity_account_id,omitempty" gorm:"type:uuid"`
	WorkloadID        *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	ResourceID        *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	EntitlementID     *uuid.UUID `json:"entitlement_id,omitempty" gorm:"type:uuid"`
	PolicyID          *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`
}

func (IGALifecycleEvent) TableName() string { return "iga_lifecycle_event" }

// SetObject points the event at one node, by class. False for an unknown class.
func (e *IGALifecycleEvent) SetObject(class string, id uuid.UUID) bool {
	switch class {
	case ObjectIdentity:
		e.IdentityAccountID = &id
	case ObjectWorkload:
		e.WorkloadID = &id
	case ObjectResource:
		e.ResourceID = &id
	case ObjectEntitlement:
		e.EntitlementID = &id
	case ObjectPolicy:
		e.PolicyID = &id
	default:
		return false
	}
	return true
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
	// TYPED: a text kind beside a bare uuid is not a foreign key.
	ResolvedIdentityAccountID *uuid.UUID `json:"resolved_identity_account_id,omitempty" gorm:"type:uuid"`
	ResolvedWorkloadID        *uuid.UUID `json:"resolved_workload_id,omitempty" gorm:"type:uuid"`
	ResolutionBasis           string     `json:"resolution_basis" gorm:"not null;default:''"`
	ResolutionRule            string     `json:"resolution_rule" gorm:"not null;default:''"`
	// ResolvedBy is required when the basis is asserted: a human's resolution
	// must be explicable and reversible.
	ResolvedBy string `json:"resolved_by" gorm:"not null;default:''"`
	// ResolutionState is whether the resolution currently APPLIES, separate
	// from whether it exists.
	ResolutionState string `json:"resolution_state" gorm:"not null;default:'active'"`

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
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	// TYPED endpoints, exactly one set. A text kind beside a bare uuid is not
	// a foreign key -- it is the A3 pattern §2.9 exists to eliminate, and it
	// would let a support row in workspace A claim workspace B's object.
	IdentityAccountID *uuid.UUID `json:"identity_account_id,omitempty" gorm:"type:uuid"`
	WorkloadID        *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	ResourceID        *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	EntitlementID     *uuid.UUID `json:"entitlement_id,omitempty" gorm:"type:uuid"`
	PolicyID          *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`

	ConnectorID  uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	PartitionKey string    `json:"partition_key" gorm:"not null"`

	State              string     `json:"state" gorm:"not null;default:'current'"`
	FirstSeenAt        time.Time  `json:"first_seen_at" gorm:"not null;default:now()"`
	LastConfirmedRunID *uuid.UUID `json:"last_confirmed_run_id,omitempty" gorm:"type:uuid"`
	LastConfirmedAt    *time.Time `json:"last_confirmed_at,omitempty"`
	EndedReason        string     `json:"ended_reason" gorm:"not null;default:''"`
}

func (IGAObjectSupport) TableName() string { return "iga_object_support" }

// SetObject points this support row at one object, by class. Returns false for
// an unknown class rather than leaving every column nil, which the
// exactly-one CHECK would reject at the end of a long scan instead of here.
func (s *IGAObjectSupport) SetObject(class string, id uuid.UUID) bool {
	switch class {
	case ObjectIdentity:
		s.IdentityAccountID = &id
	case ObjectWorkload:
		s.WorkloadID = &id
	case ObjectResource:
		s.ResourceID = &id
	case ObjectEntitlement:
		s.EntitlementID = &id
	case ObjectPolicy:
		s.PolicyID = &id
	default:
		return false
	}
	return true
}

// SupportColumn maps a node class to its typed column on iga_object_support.
// ONE mapping, used by the upsert conflict target and by both reconciliation
// steps, so a row cannot be written against one column and reconciled against
// another.
func SupportColumn(class string) string {
	switch class {
	case ObjectIdentity:
		return "identity_account_id"
	case ObjectWorkload:
		return "workload_id"
	case ObjectResource:
		return "resource_id"
	case ObjectEntitlement:
		return "entitlement_id"
	case ObjectPolicy:
		return "policy_id"
	}
	return ""
}

// NodeTable is SupportColumn's partner: the table a node class lives in.
func NodeTable(class string) string {
	switch class {
	case ObjectIdentity:
		return "iga_identity_accounts"
	case ObjectWorkload:
		return "iga_workload"
	case ObjectResource:
		return "iga_resources"
	case ObjectEntitlement:
		return "iga_entitlements"
	case ObjectPolicy:
		return "iga_policy"
	}
	return ""
}

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

/* ------------------------------ iga_publication --------------------------- */

// IGAPublication is the durable record that one run's projection COMMITTED.
//
// Written inside the graph transaction (§4.6 step 6), so "the graph changed"
// and "a publication exists for this run" can never disagree. That is what
// lets a replayed job distinguish two opposite situations that a generation
// comparison cannot: its own committed pass (finish the job) from a newer run
// having published over it (abandon).
type IGAPublication struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	// Rev is per-workspace, monotonic and gap-free. Readers pin to it.
	Rev         int64     `json:"rev" gorm:"primaryKey"`
	PublishedAt time.Time `json:"published_at" gorm:"not null"`
	ScanRunID   uuid.UUID `json:"scan_run_id" gorm:"type:uuid;not null"`
	// Manifest maps partition_key -> run_id as of this revision, so a reader
	// can see exactly which run each part of the graph came from.
	Manifest json.RawMessage `json:"manifest" gorm:"type:jsonb;not null;default:'{}'"`
}

func (IGAPublication) TableName() string { return "iga_publication" }

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
	Resources    []string        `json:"resources,omitempty"`
	NotResources []string        `json:"not_resources,omitempty"`
	Condition    json.RawMessage `json:"condition,omitempty"`
}

// NormalizedRights is our reading, kept beside the native form and never
// instead of it. A customer must always be able to see what AWS actually said.
type NormalizedRights struct {
	Verbs       []string `json:"verbs,omitempty"`
	Constrained bool     `json:"constrained"`
}
