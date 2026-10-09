package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// This file holds the Phase 3 policy model: ownership, findings and their
// per-revision evaluation, policies with immutable versions, role controls,
// targets, the boundary-document archive, evidence bundles, plans, owner
// review, approvals and revalidations. SPEC-iga-phase3-policy.md §2 and §6.2
// (migrations 047-050).
//
// As in iga_graph.go, the vocabularies below duplicate CHECK constraints and
// the database is the authority: when they disagree, the migration wins and
// the constant is the bug. Several tables are insert-once or guarded by
// triggers (noted per type); a model is a row shape, never permission to
// update it.

/* -------------------------------- ownership ------------------------------- */

// Owner roles and sources (047).
const (
	GovOwnerAccountable = "accountable"
	GovOwnerTechnical   = "technical"

	GovOwnerSourceManual  = "manual"
	GovOwnerSourceTagRule = "tag_rule"

	GovObjectWorkload        = "workload"
	GovObjectIdentityAccount = "identity_account"
)

// IGAGovOwnerRule maps an AWS tag key to workspace members (§2.9).
type IGAGovOwnerRule struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	TagKey      string    `json:"tag_key" gorm:"not null"`
	// AppliesTo is workload, identity_account or both.
	AppliesTo string    `json:"applies_to" gorm:"not null;default:'both'"`
	Role      string    `json:"role" gorm:"not null;default:'accountable'"`
	Enabled   bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt time.Time `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovOwnerRule) TableName() string { return "iga_gov_owner_rule" }

// IGAGovOwner is one accountable or technical owner of exactly one workload
// or identity (iga_gov_owner_one_chk). RuleID is set exactly when the owner
// came from a tag rule.
type IGAGovOwner struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	ObjectKind        string     `json:"object_kind" gorm:"not null"`
	WorkloadID        *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	IdentityAccountID *uuid.UUID `json:"identity_account_id,omitempty" gorm:"type:uuid"`
	UserID            uuid.UUID  `json:"user_id" gorm:"type:uuid;not null"`
	Role              string     `json:"role" gorm:"not null;default:'accountable'"`
	Source            string     `json:"source" gorm:"not null"`
	RuleID            *uuid.UUID `json:"rule_id,omitempty" gorm:"type:uuid"`
	ReviewDueAt       *time.Time `json:"review_due_at,omitempty"`
	CreatedBy         *uuid.UUID `json:"created_by,omitempty" gorm:"type:uuid"`
	CreatedAt         time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt         time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovOwner) TableName() string { return "iga_gov_owner" }

/* -------------------------------- findings -------------------------------- */

// Evaluation states (048). running -> complete | failed | superseded;
// failed -> running with attempts + 1, or superseded. complete and
// superseded are terminal (trigger iga_gov_evaluation_transition).
const (
	GovEvalRunning    = "running"
	GovEvalComplete   = "complete"
	GovEvalFailed     = "failed"
	GovEvalSuperseded = "superseded"
)

// Finding kinds (§2.5).
const (
	GovFindingUnusedService     = "unused_service"
	GovFindingBroadGrant        = "broad_grant"
	GovFindingSharedRole        = "shared_role"
	GovFindingMissingOwner      = "missing_owner"
	GovFindingMissingReviewDate = "missing_review_date"
	GovFindingActivityNotRead   = "activity_not_read"
)

// Finding lifecycle (§2.5). There is no hide or dismiss.
const (
	GovFindingOpen        = "open"
	GovFindingUnderReview = "under_review"
	GovFindingExcepted    = "excepted"
	GovFindingMitigated   = "mitigated"
	GovFindingResolved    = "resolved"
	GovFindingCleared     = "cleared"
	GovFindingSuperseded  = "superseded"
	GovFindingReopened    = "reopened"
)

// Confidence of a finding (§2.6) and the basis of a grant's age.
const (
	GovConfidenceQualified     = "qualified"
	GovConfidenceAgeUnverified = "age_unverified"
	GovConfidenceNotApplicable = "not_applicable"

	GovGrantAgeObservedSinceChange = "observed_since_change"
	GovGrantAgePredatesObservation = "predates_observation"
	GovGrantAgeUnknown             = "unknown"
)

// IGAGovEvaluation is one evaluation of one published revision. Evidence and
// results can be written only while it is running.
type IGAGovEvaluation struct {
	WorkspaceID uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Rev         int64      `json:"rev" gorm:"primaryKey"`
	Status      string     `json:"status" gorm:"not null"`
	Attempts    int        `json:"attempts" gorm:"not null;default:1"`
	StartedAt   time.Time  `json:"started_at" gorm:"not null;default:now()"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error" gorm:"not null;default:''"`
}

func (IGAGovEvaluation) TableName() string { return "iga_gov_evaluation" }

// IGAGovEvaluationPruned records that an evaluation's evidence and results
// were pruned (057): a read at that revision is 410 revision_not_retained
// whatever the retention setting has become since.
type IGAGovEvaluationPruned struct {
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Rev         int64     `json:"rev" gorm:"primaryKey"`
	PrunedAt    time.Time `json:"pruned_at" gorm:"not null;default:now()"`
}

func (IGAGovEvaluationPruned) TableName() string { return "iga_gov_evaluation_pruned" }

// IGAGovActivityEvidence is the activity fact the evaluator relied on for one
// role and service at one revision, copied out of the mutable cloud_usage.
// ScanRunID is the role connector's run named in the revision's manifest;
// required for any collected fact or route conclusion. Frozen once the
// evaluation leaves running.
type IGAGovActivityEvidence struct {
	WorkspaceID         uuid.UUID  `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Rev                 int64      `json:"rev" gorm:"primaryKey"`
	IdentityAccountID   uuid.UUID  `json:"identity_account_id" gorm:"type:uuid;primaryKey"`
	RoleID              string     `json:"role_id" gorm:"not null"`
	Service             string     `json:"service" gorm:"primaryKey"`
	State               string     `json:"state" gorm:"not null"`
	Reason              string     `json:"reason" gorm:"not null;default:''"`
	LastAuthenticatedAt *time.Time `json:"last_authenticated_at,omitempty"`
	ReportGeneratedAt   *time.Time `json:"report_generated_at,omitempty"`
	GrantObservedSince  *time.Time `json:"grant_observed_since,omitempty"`
	GrantAgeBasis       string     `json:"grant_age_basis" gorm:"not null"`
	TrackingFrom        *time.Time `json:"tracking_from,omitempty"`
	ScanRunID           *uuid.UUID `json:"scan_run_id,omitempty" gorm:"type:uuid"`
	RouteUsage          string     `json:"route_usage" gorm:"not null;default:'confirm_required'"`
}

func (IGAGovActivityEvidence) TableName() string { return "iga_gov_activity_evidence" }

// IGAGovFinding is a finding's identity and CURRENT workflow status. Its
// condition at a revision is IGAGovFindingResult. LastEvaluatedRev never
// moves backwards (trigger iga_gov_finding_monotonic).
type IGAGovFinding struct {
	ID                     uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID            uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	Fingerprint            string          `json:"fingerprint" gorm:"not null"`
	Kind                   string          `json:"kind" gorm:"not null"`
	Family                 string          `json:"family" gorm:"not null"`
	Severity               string          `json:"severity" gorm:"not null"`
	Confidence             string          `json:"confidence" gorm:"not null;default:'not_applicable'"`
	IdentityAccountID      *uuid.UUID      `json:"identity_account_id,omitempty" gorm:"type:uuid"`
	WorkloadID             *uuid.UUID      `json:"workload_id,omitempty" gorm:"type:uuid"`
	RoleID                 *string         `json:"role_id,omitempty"`
	ConnectorID            *uuid.UUID      `json:"connector_id,omitempty" gorm:"type:uuid"`
	DetailKey              string          `json:"detail_key" gorm:"not null;default:''"`
	Detail                 json.RawMessage `json:"detail" gorm:"type:jsonb;not null;default:'{}'"`
	Status                 string          `json:"status" gorm:"not null;default:'open'"`
	ExceptedUntil          *time.Time      `json:"excepted_until,omitempty"`
	ExceptionReason        string          `json:"exception_reason" gorm:"not null;default:''"`
	FirstSeenRev           int64           `json:"first_seen_rev" gorm:"not null"`
	LastEvaluatedRev       int64           `json:"last_evaluated_rev" gorm:"not null"`
	ResolvedByDeploymentID *uuid.UUID      `json:"resolved_by_deployment_id,omitempty" gorm:"type:uuid"`
	FirstSeenAt            time.Time       `json:"first_seen_at" gorm:"not null;default:now()"`
	LastEvaluatedAt        time.Time       `json:"last_evaluated_at" gorm:"not null;default:now()"`
	StatusChangedAt        time.Time       `json:"status_changed_at" gorm:"not null;default:now()"`
}

func (IGAGovFinding) TableName() string { return "iga_gov_finding" }

// IGAGovFindingResult is a finding's condition AT one revision; frozen once
// that evaluation completes, so a read at rev N is reproducible.
type IGAGovFindingResult struct {
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	Rev               int64           `json:"rev" gorm:"primaryKey"`
	FindingID         uuid.UUID       `json:"finding_id" gorm:"type:uuid;primaryKey"`
	Severity          string          `json:"severity" gorm:"not null"`
	Confidence        string          `json:"confidence" gorm:"not null"`
	Detail            json.RawMessage `json:"detail" gorm:"type:jsonb;not null;default:'{}'"`
	EvidenceScanRunID *uuid.UUID      `json:"evidence_scan_run_id,omitempty" gorm:"type:uuid"`
}

func (IGAGovFindingResult) TableName() string { return "iga_gov_finding_result" }

// IGAGovFindingRule configures a finding (require_review_date, unused_window).
type IGAGovFindingRule struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	Kind        string          `json:"kind" gorm:"not null"`
	Scope       json.RawMessage `json:"scope" gorm:"type:jsonb;not null;default:'{}'"`
	Params      json.RawMessage `json:"params" gorm:"type:jsonb;not null;default:'{}'"`
	Enabled     bool            `json:"enabled" gorm:"not null;default:true"`
	CreatedBy   uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt   time.Time       `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovFindingRule) TableName() string { return "iga_gov_finding_rule" }

/* ------------------------------ policy, control ---------------------------- */

// Policy families, providers and lifecycle (§2.4).
const (
	GovFamilyGovernance  = "governance"
	GovFamilyCloudAccess = "cloud_access"
	GovFamilyTimeBound   = "time_bound"
	GovFamilyRuntime     = "runtime"

	GovProviderAWS = "aws" // R1k adds k8s in its own migration

	GovLifecycleActive   = "active"
	GovLifecyclePaused   = "paused"
	GovLifecycleArchived = "archived"
)

// Version status (§2.7). At most one approved version per policy.
const (
	GovVersionDraft      = "draft"
	GovVersionInReview   = "in_review"
	GovVersionApproved   = "approved"
	GovVersionSuperseded = "superseded"
	GovVersionWithdrawn  = "withdrawn"
	GovVersionRejected   = "rejected"
)

// Control states (§2.3). removed is terminal and fences the sequence.
const (
	GovControlPlanned  = "planned"
	GovControlActive   = "active"
	GovControlRemoving = "removing"
	GovControlRemoved  = "removed"
)

// IGAGovPolicy is durable customer intent. CurrentVersionID must point at a
// version of the same policy (deferred composite FK).
type IGAGovPolicy struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	Name             string     `json:"name" gorm:"not null"`
	Purpose          string     `json:"purpose" gorm:"not null;default:''"`
	Family           string     `json:"family" gorm:"not null"`
	Provider         string     `json:"provider" gorm:"not null"`
	Lifecycle        string     `json:"lifecycle" gorm:"not null;default:'active'"`
	OwnerUserID      *uuid.UUID `json:"owner_user_id,omitempty" gorm:"type:uuid"`
	CurrentVersionID *uuid.UUID `json:"current_version_id,omitempty" gorm:"type:uuid"`
	CreatedBy        uuid.UUID  `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovPolicy) TableName() string { return "iga_gov_policy" }

// IGAGovPolicyVersion is immutable typed intent: only Status and
// StatusChangedAt may change (trigger iga_gov_policy_version_immutable).
type IGAGovPolicyVersion struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID        uuid.UUID       `json:"policy_id" gorm:"type:uuid;not null"`
	VersionNo       int             `json:"version_no" gorm:"not null"`
	Intent          json.RawMessage `json:"intent" gorm:"type:jsonb;not null"`
	IntentHash      string          `json:"intent_hash" gorm:"not null"`
	CatalogVersion  int             `json:"catalog_version" gorm:"not null"`
	EvidenceRev     int64           `json:"evidence_rev" gorm:"not null"`
	Status          string          `json:"status" gorm:"not null;default:'draft'"`
	CreatedBy       uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt       time.Time       `json:"created_at" gorm:"not null;default:now()"`
	StatusChangedAt time.Time       `json:"status_changed_at" gorm:"not null;default:now()"`
}

func (IGAGovPolicyVersion) TableName() string { return "iga_gov_policy_version" }

// IGAGovDocument is the insert-once, content-addressed archive of every
// boundary document AuthSec read or wrote. DocumentHash is
// "sha256:" + hex(sha256(Canonical)) and Document equals Canonical (trigger
// authsec_document_insert_check); rows are never updated.
type IGAGovDocument struct {
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	DocumentHash string          `json:"document_hash" gorm:"primaryKey"`
	Canonical    string          `json:"canonical" gorm:"not null"`
	Document     json.RawMessage `json:"document" gorm:"type:jsonb;not null"`
	FirstSeenAt  time.Time       `json:"first_seen_at" gorm:"not null;default:now()"`
}

func (IGAGovDocument) TableName() string { return "iga_gov_document" }

// IGAGovControl is the physical AWS role a policy controls: one live control
// per (account, RoleId), its baseline, and the epoch of its posture.
// EnforcementSeq is compare-and-swapped by every enforcement observer and is
// fenced once the control is removed (trigger iga_gov_control_fence).
type IGAGovControl struct {
	ID                   uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID          uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID          uuid.UUID  `json:"connector_id" gorm:"type:uuid;not null"`
	AccountID            string     `json:"account_id" gorm:"not null"`
	RoleID               string     `json:"role_id" gorm:"not null"`
	RoleARN              string     `json:"role_arn" gorm:"column:role_arn;not null"`
	IdentityAccountID    uuid.UUID  `json:"identity_account_id" gorm:"type:uuid;not null"`
	PolicyID             uuid.UUID  `json:"policy_id" gorm:"type:uuid;not null"`
	BoundaryPolicyARN    string     `json:"boundary_policy_arn" gorm:"column:boundary_policy_arn;not null"`
	BaselineCapturedAt   *time.Time `json:"baseline_captured_at,omitempty"`
	BaselineBoundaryARN  *string    `json:"baseline_boundary_arn,omitempty" gorm:"column:baseline_boundary_arn"`
	BaselineDocumentHash *string    `json:"baseline_document_hash,omitempty"`
	EnforcementSeq       int64      `json:"enforcement_seq" gorm:"not null;default:0"`
	State                string     `json:"state" gorm:"not null;default:'planned'"`
	CreatedAt            time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt            time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovControl) TableName() string { return "iga_gov_control" }

// IGAGovTarget is a version's reference to a control of the same policy.
type IGAGovTarget struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID   uuid.UUID `json:"version_id" gorm:"type:uuid;not null"`
	PolicyID    uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	ControlID   uuid.UUID `json:"control_id" gorm:"type:uuid;not null"`
	Provider    string    `json:"provider" gorm:"not null;default:'aws'"`
	IsCanary    bool      `json:"is_canary" gorm:"not null;default:false"`
	CreatedAt   time.Time `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovTarget) TableName() string { return "iga_gov_target" }

/* ------------------------- bundles, plans, approvals ----------------------- */

// Evidence trust (§2.11).
const (
	GovTrustTrusted   = "trusted"
	GovTrustPartial   = "partial"
	GovTrustUntrusted = "untrusted"
)

// Plan and deployment kinds, deliveries, attachments and dispositions (§2.8).
const (
	GovPlanApply         = "apply"
	GovPlanUndo          = "undo"
	GovPlanRemoveControl = "remove_control"
	GovPlanSplit         = "split"
	GovPlanSplitRevert   = "split_revert"

	GovDeliveryDirect = "direct"
	GovDeliveryIaCPR  = "iac_pr"
	GovDeliveryExport = "export"

	GovAttachmentPresent   = "present"
	GovAttachmentAbsent    = "absent"
	GovAttachmentUnchanged = "unchanged"

	GovDispositionKeep         = "keep"
	GovDispositionDelete       = "delete"
	GovDispositionRetainShared = "retain_shared"
)

// Revalidation results (§2.8). Only unchanged lets a deployment proceed on
// the approved plan.
const (
	GovRevalidationUnchanged      = "unchanged"
	GovRevalidationMaterialChange = "material_change"
	GovRevalidationBlocked        = "blocked"
)

// IGAGovEvidenceBundle is the insert-once, hash-verified basis of a plan
// (§2.11). BundleHash is the sha256 of Canonical, Facts equals Canonical and
// names at least one source (trigger iga_gov_bundle_insert_check).
type IGAGovEvidenceBundle struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	Provider    string          `json:"provider" gorm:"not null"`
	Trust       string          `json:"trust" gorm:"not null"`
	BundleHash  string          `json:"bundle_hash" gorm:"not null"`
	Canonical   string          `json:"canonical" gorm:"not null"`
	Facts       json.RawMessage `json:"facts" gorm:"type:jsonb;not null"`
	CreatedAt   time.Time       `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovEvidenceBundle) TableName() string { return "iga_gov_evidence_bundle" }

// IGAGovPlan is the compiled native change for one target, from one live read
// and one evidence bundle. At most one current (SupersededAt nil) plan per
// (target, kind).
type IGAGovPlan struct {
	ID                      uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID             uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID               uuid.UUID       `json:"version_id" gorm:"type:uuid;not null"`
	TargetID                uuid.UUID       `json:"target_id" gorm:"type:uuid;not null"`
	ControlID               uuid.UUID       `json:"control_id" gorm:"type:uuid;not null"`
	Kind                    string          `json:"kind" gorm:"not null"`
	Delivery                string          `json:"delivery" gorm:"not null"`
	Eligibility             string          `json:"eligibility" gorm:"not null"`
	IneligibleReason        string          `json:"ineligible_reason" gorm:"not null;default:''"`
	Basis                   string          `json:"basis" gorm:"not null"`
	BasisReadAt             time.Time       `json:"basis_read_at" gorm:"not null"`
	Precondition            json.RawMessage `json:"precondition" gorm:"type:jsonb;not null"`
	PreconditionHash        string          `json:"precondition_hash" gorm:"not null"`
	BeforeDocumentHash      *string         `json:"before_document_hash,omitempty"`
	DesiredAttachment       string          `json:"desired_attachment" gorm:"not null"`
	DesiredBoundaryARN      *string         `json:"desired_boundary_arn,omitempty" gorm:"column:desired_boundary_arn"`
	DesiredDocumentHash     *string         `json:"desired_document_hash,omitempty"`
	ReplacedBoundaryARN     *string         `json:"replaced_boundary_arn,omitempty" gorm:"column:replaced_boundary_arn"`
	ArtifactDisposition     string          `json:"artifact_disposition" gorm:"not null;default:'keep'"`
	EvidenceBundleID        uuid.UUID       `json:"evidence_bundle_id" gorm:"type:uuid;not null"`
	EvidenceRev             int64           `json:"evidence_rev" gorm:"not null"`
	ResourcePolicyScanRunID *uuid.UUID      `json:"resource_policy_scan_run_id,omitempty" gorm:"type:uuid"`
	FirstAttachment         bool            `json:"first_attachment" gorm:"not null;default:false"`
	Unanalysed              json.RawMessage `json:"unanalysed" gorm:"type:jsonb;not null;default:'[]'"`
	Impact                  json.RawMessage `json:"impact" gorm:"type:jsonb;not null"`
	ImpactHash              string          `json:"impact_hash" gorm:"not null"`
	Operations              json.RawMessage `json:"operations" gorm:"type:jsonb;not null"`
	Diff                    json.RawMessage `json:"diff" gorm:"type:jsonb;not null"`
	PlanHash                string          `json:"plan_hash" gorm:"not null"`
	MaterialHash            string          `json:"material_hash" gorm:"not null"`
	SupersededAt            *time.Time      `json:"superseded_at,omitempty"`
	CreatedAt               time.Time       `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovPlan) TableName() string { return "iga_gov_plan" }

// IGAGovOwnerReview is the consultation of every known owner for a version.
type IGAGovOwnerReview struct {
	ID              uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID       uuid.UUID      `json:"version_id" gorm:"type:uuid;not null"`
	ImpactHashes    pq.StringArray `json:"impact_hashes" gorm:"type:text[];not null"`
	Status          string         `json:"status" gorm:"not null;default:'open'"`
	DeadlineAt      time.Time      `json:"deadline_at" gorm:"not null"`
	ExceptionBy     *uuid.UUID     `json:"exception_by,omitempty" gorm:"type:uuid"`
	ExceptionReason string         `json:"exception_reason" gorm:"not null;default:''"`
	CreatedAt       time.Time      `json:"created_at" gorm:"not null;default:now()"`
	ClosedAt        *time.Time     `json:"closed_at,omitempty"`
}

func (IGAGovOwnerReview) TableName() string { return "iga_gov_owner_review" }

// IGAGovOwnerResponse is one owner's answer, with the age and route
// confirmations §2.6 and §3.4 require.
type IGAGovOwnerResponse struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ReviewID           uuid.UUID       `json:"review_id" gorm:"type:uuid;not null"`
	UserID             uuid.UUID       `json:"user_id" gorm:"type:uuid;not null"`
	OwnerOf            json.RawMessage `json:"owner_of" gorm:"type:jsonb;not null"`
	Delivery           string          `json:"delivery" gorm:"not null;default:'pending'"`
	DeliveryChannels   pq.StringArray  `json:"delivery_channels" gorm:"type:text[];not null;default:'{}'"`
	Response           *string         `json:"response,omitempty"`
	RetainItems        json.RawMessage `json:"retain_items" gorm:"type:jsonb;not null;default:'[]'"`
	AgeConfirmations   json.RawMessage `json:"age_confirmations" gorm:"type:jsonb;not null;default:'[]'"`
	RouteConfirmations json.RawMessage `json:"route_confirmations" gorm:"type:jsonb;not null;default:'[]'"`
	Comment            string          `json:"comment" gorm:"not null;default:''"`
	RespondedAt        *time.Time      `json:"responded_at,omitempty"`
	RespondedVia       *string         `json:"responded_via,omitempty"`
}

func (IGAGovOwnerResponse) TableName() string { return "iga_gov_owner_response" }

// IGAGovApproval is a decision bound to intent, impact, plan and material
// hashes. Accepted items are IGAGovAcceptance rows, never a list here.
type IGAGovApproval struct {
	ID             uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID      uuid.UUID      `json:"version_id" gorm:"type:uuid;not null"`
	Decision       string         `json:"decision" gorm:"not null"`
	DecidedBy      uuid.UUID      `json:"decided_by" gorm:"type:uuid;not null"`
	Channel        string         `json:"channel" gorm:"not null"`
	IntentHash     string         `json:"intent_hash" gorm:"not null"`
	ImpactHashes   pq.StringArray `json:"impact_hashes" gorm:"type:text[];not null"`
	PlanHashes     pq.StringArray `json:"plan_hashes" gorm:"type:text[];not null"`
	MaterialHashes pq.StringArray `json:"material_hashes" gorm:"type:text[];not null"`
	EvidenceRev    int64          `json:"evidence_rev" gorm:"not null"`
	Reason         string         `json:"reason" gorm:"not null;default:''"`
	ExpiresAt      time.Time      `json:"expires_at" gorm:"not null"`
	RevokedAt      *time.Time     `json:"revoked_at,omitempty"`
	RevokedReason  string         `json:"revoked_reason" gorm:"not null;default:''"`
	DecidedAt      time.Time      `json:"decided_at" gorm:"not null;default:now()"`
}

func (IGAGovApproval) TableName() string { return "iga_gov_approval" }

// IGAGovRevalidation is one later evidence check of an approved plan.
// Insert-once (trigger authsec_row_immutable); it never rewrites the plan.
type IGAGovRevalidation struct {
	ID                      uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID             uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PlanID                  uuid.UUID       `json:"plan_id" gorm:"type:uuid;not null"`
	ApprovedMaterialHash    string          `json:"approved_material_hash" gorm:"not null"`
	EvidenceBundleID        uuid.UUID       `json:"evidence_bundle_id" gorm:"type:uuid;not null"`
	EvidenceRev             int64           `json:"evidence_rev" gorm:"not null"`
	ResourcePolicyScanRunID *uuid.UUID      `json:"resource_policy_scan_run_id,omitempty" gorm:"type:uuid"`
	BasisReadAt             time.Time       `json:"basis_read_at" gorm:"not null"`
	MaterialHash            *string         `json:"material_hash,omitempty"`
	Result                  string          `json:"result" gorm:"not null"`
	Changes                 json.RawMessage `json:"changes" gorm:"type:jsonb;not null;default:'[]'"`
	BlockedReason           string          `json:"blocked_reason" gorm:"not null;default:''"`
	CreatedAt               time.Time       `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovRevalidation) TableName() string { return "iga_gov_revalidation" }
