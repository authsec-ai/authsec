package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Phase 3 rollout and execution (SPEC-iga-phase3-policy.md §2.8, §8, §11;
// migration 051): rollouts, acceptances, deployments, the write-ahead attempt
// record, verification, per-deployment service history, current service
// posture, the artifact ledger, workload migrations, health reports and
// validations. The database is the authority for every vocabulary below.

// Rollout stages.
const (
	GovRolloutObserve          = "observe"
	GovRolloutAwaitingApproval = "awaiting_approval"
	GovRolloutCanary           = "canary"
	GovRolloutExpand           = "expand"
	GovRolloutComplete         = "complete"
	GovRolloutPartial          = "partial"
	GovRolloutPaused           = "paused"
	GovRolloutUndone           = "undone"
)

// Acceptance kinds (§2.8): one row per accepted uncertainty.
const (
	GovAcceptEvidenceGap      = "evidence_gap"
	GovAcceptUnanalysedForm   = "unanalysed_form"
	GovAcceptGateNotAvailable = "gate_not_available"
)

// Deployment states (§8.4). The in-flight set (uq_iga_gov_deployment_inflight)
// is queued, applying, outcome_unknown, outcome_unresolved, awaiting_merge and
// awaiting_apply: at most one per control.
const (
	GovDeployQueued            = "queued"
	GovDeployBlocked           = "blocked"
	GovDeployApplying          = "applying"
	GovDeployOutcomeUnknown    = "outcome_unknown"
	GovDeployOutcomeUnresolved = "outcome_unresolved"
	GovDeployRecovered         = "recovered"
	GovDeployAwaitingMerge     = "awaiting_merge"
	GovDeployAwaitingApply     = "awaiting_apply"
	GovDeployAppliedUnverified = "applied_unverified"
	GovDeployVerified          = "verified"
	GovDeployFailed            = "failed"
	GovDeployDrifted           = "drifted"
	GovDeploySuperseded        = "superseded"
	GovDeployUndone            = "undone"
)

// Attempt lifecycle (§8.1): prepared -> dispatched | abandoned;
// dispatched -> completed | unknown. Inserted only as prepared (trigger
// iga_gov_attempt_transition).
const (
	GovAttemptPrepared   = "prepared"
	GovAttemptDispatched = "dispatched"
	GovAttemptCompleted  = "completed"
	GovAttemptUnknown    = "unknown"
	GovAttemptAbandoned  = "abandoned"
)

// Service posture (§8.7): exclusion and route facts, and the derived outcome.
const (
	GovExclusionPending    = "pending"
	GovExclusionApplied    = "applied"
	GovExclusionNotApplied = "not_applied"

	GovRouteNoneObserved  = "none_observed"
	GovRouteBypassKnown   = "bypass_known"
	GovRouteEffectUnknown = "effect_unknown"
	GovRouteNotAnalysed   = "not_analysed"

	GovOutcomePending               = "pending"
	GovOutcomeRemoved               = "removed"
	GovOutcomeExcludedRoutesRemain  = "excluded_routes_remain"
	GovOutcomeExcludedRoutesUnknown = "excluded_routes_unknown"
	GovOutcomeNotRemoved            = "not_removed"
)

// IGAGovRollout is observe -> canary -> expand for one version.
type IGAGovRollout struct {
	ID                           uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID                  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID                    uuid.UUID       `json:"version_id" gorm:"type:uuid;not null"`
	Stage                        string          `json:"stage" gorm:"not null"`
	ObserveUntil                 *time.Time      `json:"observe_until,omitempty"`
	ObserveEvidenceRequiredAfter *time.Time      `json:"observe_evidence_required_after,omitempty"`
	CanaryStartedAt              *time.Time      `json:"canary_started_at,omitempty"`
	CanaryMinUntil               *time.Time      `json:"canary_min_until,omitempty"`
	GateResults                  json.RawMessage `json:"gate_results" gorm:"type:jsonb;not null;default:'{}'"`
	PausedReason                 string          `json:"paused_reason" gorm:"not null;default:''"`
	UpdatedAt                    time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovRollout) TableName() string { return "iga_gov_rollout" }

// IGAGovAcceptance is one explicitly accepted uncertainty. Insert-once.
// gate_not_available binds a rollout, stage and evidence window; the other
// kinds bind an approval, a plan and a bundle (iga_gov_acc_subject_chk).
type IGAGovAcceptance struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	Kind             string     `json:"kind" gorm:"not null"`
	ItemKey          string     `json:"item_key" gorm:"not null"`
	ItemHash         string     `json:"item_hash" gorm:"not null"`
	VersionID        uuid.UUID  `json:"version_id" gorm:"type:uuid;not null"`
	ApprovalID       *uuid.UUID `json:"approval_id,omitempty" gorm:"type:uuid"`
	PlanID           *uuid.UUID `json:"plan_id,omitempty" gorm:"type:uuid"`
	EvidenceBundleID *uuid.UUID `json:"evidence_bundle_id,omitempty" gorm:"type:uuid"`
	RolloutID        *uuid.UUID `json:"rollout_id,omitempty" gorm:"type:uuid"`
	Stage            *string    `json:"stage,omitempty"`
	WindowStart      *time.Time `json:"window_start,omitempty"`
	WindowEnd        *time.Time `json:"window_end,omitempty"`
	Reason           string     `json:"reason" gorm:"not null"`
	AcceptedBy       uuid.UUID  `json:"accepted_by" gorm:"type:uuid;not null"`
	AcceptedAt       time.Time  `json:"accepted_at" gorm:"not null;default:now()"`
}

func (IGAGovAcceptance) TableName() string { return "iga_gov_acceptance" }

// IGAGovDeployment is one plan applied to the control it was compiled for.
// (plan, version, control, kind, delivery) is one composite FK; the
// recovered_by / recovers pair is written in one transaction (deferred FKs).
type IGAGovDeployment struct {
	ID                      uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID             uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	VersionID               uuid.UUID       `json:"version_id" gorm:"type:uuid;not null"`
	PlanID                  uuid.UUID       `json:"plan_id" gorm:"type:uuid;not null"`
	ControlID               uuid.UUID       `json:"control_id" gorm:"type:uuid;not null"`
	ApprovalID              *uuid.UUID      `json:"approval_id,omitempty" gorm:"type:uuid"`
	EmergencyBy             *uuid.UUID      `json:"emergency_by,omitempty" gorm:"type:uuid"`
	EmergencyReason         string          `json:"emergency_reason" gorm:"not null;default:''"`
	Kind                    string          `json:"kind" gorm:"not null"`
	Delivery                string          `json:"delivery" gorm:"not null"`
	State                   string          `json:"state" gorm:"not null;default:'queued'"`
	StateReason             string          `json:"state_reason" gorm:"not null;default:''"`
	CompletedOps            json.RawMessage `json:"completed_ops" gorm:"type:jsonb;not null;default:'[]'"`
	Attempts                int             `json:"attempts" gorm:"not null;default:0"`
	AppliedAt               *time.Time      `json:"applied_at,omitempty"`
	VerifiedAt              *time.Time      `json:"verified_at,omitempty"`
	VerifyDeadlineAt        *time.Time      `json:"verify_deadline_at,omitempty"`
	ApplyDeadlineAt         *time.Time      `json:"apply_deadline_at,omitempty"`
	OutcomeUnknownOp        string          `json:"outcome_unknown_op" gorm:"not null;default:''"`
	SettleAfter             *time.Time      `json:"settle_after,omitempty"`
	RecoveredByDeploymentID *uuid.UUID      `json:"recovered_by_deployment_id,omitempty" gorm:"type:uuid"`
	RecoversDeploymentID    *uuid.UUID      `json:"recovers_deployment_id,omitempty" gorm:"type:uuid"`
	RevalidationID          *uuid.UUID      `json:"revalidation_id,omitempty" gorm:"type:uuid"`
	RevalidationResult      *string         `json:"revalidation_result,omitempty"`
	CreatedAt               time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt               time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovDeployment) TableName() string { return "iga_gov_deployment" }

// IGAGovAttempt is the write-ahead record of one AWS mutation (§8.1). The
// prepared request (deployment, op, attempt, lease version, operation,
// request and document hashes) is immutable once inserted.
type IGAGovAttempt struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	DeploymentID uuid.UUID  `json:"deployment_id" gorm:"type:uuid;not null"`
	OpSeq        int        `json:"op_seq" gorm:"not null"`
	AttemptNo    int        `json:"attempt_no" gorm:"not null"`
	LeaseVersion int64      `json:"lease_version" gorm:"not null"`
	Operation    string     `json:"operation" gorm:"not null"`
	RequestHash  string     `json:"request_hash" gorm:"not null"`
	DocumentHash *string    `json:"document_hash,omitempty"`
	Status       string     `json:"status" gorm:"not null"`
	PreparedAt   time.Time  `json:"prepared_at" gorm:"not null;default:now()"`
	SignedAt     *time.Time `json:"signed_at,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	RequestID    string     `json:"request_id" gorm:"not null;default:''"`
	Outcome      *string    `json:"outcome,omitempty"`
	ErrorCode    string     `json:"error_code" gorm:"not null;default:''"`
	ErrorMessage string     `json:"error_message" gorm:"not null;default:''"`
	ResolvedAs   *string    `json:"resolved_as,omitempty"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
}

func (IGAGovAttempt) TableName() string { return "iga_gov_attempt" }

// IGAGovVerification is one dimension's result for one deployment.
type IGAGovVerification struct {
	ID           uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	DeploymentID uuid.UUID       `json:"deployment_id" gorm:"type:uuid;not null"`
	Dimension    string          `json:"dimension" gorm:"not null"`
	Outcome      string          `json:"outcome" gorm:"not null"`
	Attribution  string          `json:"attribution" gorm:"not null;default:'not_applicable'"`
	Evidence     json.RawMessage `json:"evidence" gorm:"type:jsonb;not null;default:'{}'"`
	CheckedAt    time.Time       `json:"checked_at" gorm:"not null;default:now()"`
}

func (IGAGovVerification) TableName() string { return "iga_gov_verification" }

// IGAGovServiceOutcome is HISTORY: what one deployment established per
// service, with its change relative to the boundary it replaced.
type IGAGovServiceOutcome struct {
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	DeploymentID uuid.UUID       `json:"deployment_id" gorm:"type:uuid;primaryKey"`
	Service      string          `json:"service" gorm:"primaryKey"`
	Change       string          `json:"change" gorm:"not null"`
	Exclusion    string          `json:"exclusion" gorm:"not null;default:'pending'"`
	RouteState   string          `json:"route_state" gorm:"not null"`
	Routes       json.RawMessage `json:"routes" gorm:"type:jsonb;not null;default:'[]'"`
	Restriction  string          `json:"restriction" gorm:"not null;default:'not_observed'"`
	Outcome      string          `json:"outcome" gorm:"not null;default:'pending'"`
	UpdatedAt    time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovServiceOutcome) TableName() string { return "iga_gov_service_outcome" }

// IGAGovServicePosture is CURRENT posture per (account, role incarnation,
// service). Route facts are ordered by EvidenceRev; enforcement facts by the
// control's EnforcementSeq (trigger iga_gov_service_posture_order). Outcome
// is a GENERATED column: read-only here ("->"), never written.
type IGAGovServicePosture struct {
	WorkspaceID           uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	AccountID             string          `json:"account_id" gorm:"primaryKey"`
	RoleID                string          `json:"role_id" gorm:"primaryKey"`
	Service               string          `json:"service" gorm:"primaryKey"`
	ControlID             uuid.UUID       `json:"control_id" gorm:"type:uuid;not null"`
	CurrentDeploymentID   *uuid.UUID      `json:"current_deployment_id,omitempty" gorm:"type:uuid"`
	BoundaryDocumentHash  *string         `json:"boundary_document_hash,omitempty"`
	Exclusion             string          `json:"exclusion" gorm:"not null"`
	Restriction           string          `json:"restriction" gorm:"not null;default:'not_observed'"`
	EnforcementSeq        int64           `json:"enforcement_seq" gorm:"not null"`
	EnforcementObservedAt time.Time       `json:"enforcement_observed_at" gorm:"not null"`
	RouteState            string          `json:"route_state" gorm:"not null"`
	Routes                json.RawMessage `json:"routes" gorm:"type:jsonb;not null;default:'[]'"`
	EvidenceRev           int64           `json:"evidence_rev" gorm:"not null"`
	EvidenceScanRunID     *uuid.UUID      `json:"evidence_scan_run_id,omitempty" gorm:"type:uuid"`
	Outcome               string          `json:"outcome" gorm:"->"`
	AssessedAt            time.Time       `json:"assessed_at" gorm:"not null;default:now()"`
}

func (IGAGovServicePosture) TableName() string { return "iga_gov_service_posture" }

// IGAGovArtifact is the ledger of each native object AuthSec controls.
type IGAGovArtifact struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	ControlID        uuid.UUID  `json:"control_id" gorm:"type:uuid;not null"`
	Kind             string     `json:"kind" gorm:"not null"`
	NativeARN        string     `json:"native_arn" gorm:"column:native_arn;not null"`
	OwnedBy          string     `json:"owned_by" gorm:"not null"`
	State            string     `json:"state" gorm:"not null"`
	DocumentHash     *string    `json:"document_hash,omitempty"`
	AWSVersionID     string     `json:"aws_version_id" gorm:"column:aws_version_id;not null;default:''"`
	LastReadbackAt   *time.Time `json:"last_readback_at,omitempty"`
	LastReadbackHash string     `json:"last_readback_hash" gorm:"not null;default:''"`
	LastDeploymentID uuid.UUID  `json:"last_deployment_id" gorm:"type:uuid;not null"`
	UpdatedAt        time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovArtifact) TableName() string { return "iga_gov_artifact" }

// IGAGovWorkloadMigration is one subject moved off a shared role (§11). Graph
// workloads are linked here by key, never merged. moved requires complete
// evidence, nothing left on the old role and the new workload seen.
type IGAGovWorkloadMigration struct {
	ID               uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID      uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PlanID           uuid.UUID       `json:"plan_id" gorm:"type:uuid;not null"`
	ControlID        uuid.UUID       `json:"control_id" gorm:"type:uuid;not null"`
	SubjectKind      string          `json:"subject_kind" gorm:"not null"`
	SubjectARN       string          `json:"subject_arn" gorm:"column:subject_arn;not null"`
	FromRoleARN      string          `json:"from_role_arn" gorm:"column:from_role_arn;not null"`
	ToRoleARN        string          `json:"to_role_arn" gorm:"column:to_role_arn;not null"`
	FromWorkloadKeys pq.StringArray  `json:"from_workload_keys" gorm:"type:text[];not null"`
	ToWorkloadKeys   pq.StringArray  `json:"to_workload_keys" gorm:"type:text[];not null;default:'{}'"`
	State            string          `json:"state" gorm:"not null;default:'pending'"`
	Evidence         json.RawMessage `json:"evidence" gorm:"type:jsonb;not null;default:'{}'"`
	EvidenceComplete bool            `json:"evidence_complete" gorm:"not null;default:false"`
	RemainingOldRefs *int            `json:"remaining_old_refs,omitempty"`
	CheckedAt        *time.Time      `json:"checked_at,omitempty"`
}

func (IGAGovWorkloadMigration) TableName() string { return "iga_gov_workload_migration" }

// IGAGovHealthReport is an owner's problem / working report on a deployment.
type IGAGovHealthReport struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	DeploymentID uuid.UUID `json:"deployment_id" gorm:"type:uuid;not null"`
	ReportedBy   uuid.UUID `json:"reported_by" gorm:"type:uuid;not null"`
	Kind         string    `json:"kind" gorm:"not null"`
	Service      string    `json:"service" gorm:"not null;default:''"`
	Detail       string    `json:"detail" gorm:"not null;default:''"`
	Channel      string    `json:"channel" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovHealthReport) TableName() string { return "iga_gov_health_report" }

// IGAGovValidation is a declared test call from a dedicated session: an
// event belongs to it only if it comes from this role incarnation, this
// session name, a declared action and the window.
type IGAGovValidation struct {
	ID                  uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID         uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	DeploymentID        uuid.UUID  `json:"deployment_id" gorm:"type:uuid;not null"`
	CreatedBy           uuid.UUID  `json:"created_by" gorm:"type:uuid;not null"`
	RoleID              string     `json:"role_id" gorm:"not null"`
	Correlation         string     `json:"correlation" gorm:"not null"`
	SessionName         string     `json:"session_name" gorm:"not null"`
	DedicatedWorkloadID *uuid.UUID `json:"dedicated_workload_id,omitempty" gorm:"type:uuid"`
	WindowStart         time.Time  `json:"window_start" gorm:"not null"`
	WindowEnd           time.Time  `json:"window_end" gorm:"not null"`
	Note                string     `json:"note" gorm:"not null;default:''"`
	Result              string     `json:"result" gorm:"not null;default:'pending'"`
	CreatedAt           time.Time  `json:"created_at" gorm:"not null;default:now()"`
}

func (IGAGovValidation) TableName() string { return "iga_gov_validation" }

// IGAGovValidationItem is one declared action and what CloudTrail showed.
type IGAGovValidationItem struct {
	WorkspaceID    uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ValidationID   uuid.UUID       `json:"validation_id" gorm:"type:uuid;primaryKey"`
	Action         string          `json:"action" gorm:"primaryKey"`
	Expected       string          `json:"expected" gorm:"not null"`
	Result         string          `json:"result" gorm:"not null;default:'pending'"`
	MatchedEvents  int             `json:"matched_events" gorm:"not null;default:0"`
	OppositeEvents int             `json:"opposite_events" gorm:"not null;default:0"`
	Evidence       json.RawMessage `json:"evidence" gorm:"type:jsonb;not null;default:'{}'"`
}

func (IGAGovValidationItem) TableName() string { return "iga_gov_validation_item" }
