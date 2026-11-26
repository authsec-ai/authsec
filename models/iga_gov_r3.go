package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Phase 3 R3 (SPEC-iga-phase3-policy.md §12.4; 062_r3_runtime_controls):
// agent runtime controls. Row shapes only; the migration's CHECKs and
// triggers are the authority.

// IGAGovRuntimeVersion is one immutable runtime_controls version.
type IGAGovRuntimeVersion struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID           uuid.UUID       `json:"policy_id" gorm:"type:uuid;not null"`
	VersionNo          int             `json:"version_no" gorm:"not null"`
	Intent             json.RawMessage `json:"intent" gorm:"type:jsonb;not null"`
	IntentHash         string          `json:"intent_hash" gorm:"not null"`
	Status             string          `json:"status" gorm:"not null"`
	CreatedBy          uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt          time.Time       `json:"created_at"`
	DecidedBy          *uuid.UUID      `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt          *time.Time      `json:"decided_at,omitempty"`
	DecisionReason     string          `json:"decision_reason"`
	ApprovedIntentHash *string         `json:"approved_intent_hash,omitempty"`
	StatusChangedAt    time.Time       `json:"status_changed_at"`
}

func (IGAGovRuntimeVersion) TableName() string { return "iga_gov_runtime_version" }

// IGAGovRuntimeSettings is a workspace's runtime posture.
type IGAGovRuntimeSettings struct {
	WorkspaceID          uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ArgumentRetention    string          `json:"argument_retention"`
	RedactKeys           json.RawMessage `json:"redact_keys" gorm:"type:jsonb"`
	RetentionDays        int             `json:"retention_days"`
	DecisionTTLSeconds   int             `json:"decision_ttl_seconds"`
	HoldTimeoutMinutes   int             `json:"hold_timeout_minutes"`
	ApprovalValidMinutes int             `json:"approval_valid_minutes"`
	UpdatedBy            *uuid.UUID      `json:"updated_by,omitempty" gorm:"type:uuid"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

func (IGAGovRuntimeSettings) TableName() string { return "iga_gov_runtime_settings" }

// IGAGovRuntimeDecision is one AuthSec runtime decision.
type IGAGovRuntimeDecision struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID          *uuid.UUID      `json:"policy_id,omitempty" gorm:"type:uuid"`
	VersionID         *uuid.UUID      `json:"version_id,omitempty" gorm:"type:uuid"`
	IntentHash        *string         `json:"intent_hash,omitempty"`
	AgentRef          string          `json:"agent_ref"`
	AgentClientID     string          `json:"agent_client_id"`
	HumanUserID       *uuid.UUID      `json:"human_user_id,omitempty" gorm:"type:uuid"`
	CredentialKind    string          `json:"credential_kind"`
	Tool              string          `json:"tool"`
	Action            string          `json:"action"`
	Target            string          `json:"target"`
	ArgsDigest        string          `json:"args_digest"`
	ContextDigest     string          `json:"context_digest"`
	Context           json.RawMessage `json:"context" gorm:"type:jsonb"`
	ArgsRedacted      json.RawMessage `json:"args_redacted,omitempty" gorm:"type:jsonb"`
	SessionKey        string          `json:"session_key"`
	IdempotencyKey    string          `json:"idempotency_key"`
	Decision          string          `json:"decision"`
	ReasonCode        string          `json:"reason_code"`
	Reasons           json.RawMessage `json:"reasons" gorm:"type:jsonb"`
	ApprovalRef       *uuid.UUID      `json:"approval_ref,omitempty" gorm:"type:uuid"`
	BindingHash       string          `json:"binding_hash"`
	TokenHash         *string         `json:"-"`
	ExpiresAt         time.Time       `json:"expires_at"`
	ConsumedAt        *time.Time      `json:"consumed_at,omitempty"`
	ConsumedBy        *string         `json:"consumed_by,omitempty"`
	ToolOutcome       *string         `json:"tool_outcome,omitempty"`
	AWSOutcome        json.RawMessage `json:"aws_outcome,omitempty" gorm:"type:jsonb"`
	ActualCost        *int64          `json:"actual_cost,omitempty"`
	OutcomeSource     *string         `json:"outcome_source,omitempty"`
	OutcomeReportedAt *time.Time      `json:"outcome_reported_at,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
}

func (IGAGovRuntimeDecision) TableName() string { return "iga_gov_runtime_decision" }

// Runtime hold states (062).
const (
	RuntimeHoldPending   = "pending"
	RuntimeHoldApproved  = "approved"
	RuntimeHoldRejected  = "rejected"
	RuntimeHoldExpired   = "expired"
	RuntimeHoldCancelled = "cancelled"
	RuntimeHoldResumed   = "resumed"
)

// IGAGovRuntimeHold is one durable human-in-the-loop hold.
type IGAGovRuntimeHold struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	DecisionID         uuid.UUID  `json:"decision_id" gorm:"type:uuid;not null"`
	PolicyID           uuid.UUID  `json:"policy_id" gorm:"type:uuid;not null"`
	VersionID          uuid.UUID  `json:"version_id" gorm:"type:uuid;not null"`
	AgentRef           string     `json:"agent_ref"`
	HumanUserID        uuid.UUID  `json:"human_user_id" gorm:"type:uuid;not null"`
	Tool               string     `json:"tool"`
	Action             string     `json:"action"`
	Target             string     `json:"target"`
	ArgsDigest         string     `json:"args_digest"`
	IdempotencyKey     string     `json:"idempotency_key"`
	Reason             string     `json:"reason"`
	State              string     `json:"state"`
	ExpiresAt          time.Time  `json:"expires_at"`
	DecidedBy          *uuid.UUID `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	DecisionReason     string     `json:"decision_reason"`
	ApprovalValidUntil *time.Time `json:"approval_valid_until,omitempty"`
	ResumedDecisionID  *uuid.UUID `json:"resumed_decision_id,omitempty" gorm:"type:uuid"`
	ResumedAt          *time.Time `json:"resumed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

func (IGAGovRuntimeHold) TableName() string { return "iga_gov_runtime_hold" }

// IGAGovRuntimeBudget is one per-session budget ledger.
type IGAGovRuntimeBudget struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID     uuid.UUID `json:"policy_id" gorm:"type:uuid;not null"`
	VersionID    uuid.UUID `json:"version_id" gorm:"type:uuid;not null"`
	AgentRef     string    `json:"agent_ref"`
	SessionKey   string    `json:"session_key"`
	BudgetKey    string    `json:"budget_key"`
	Unit         string    `json:"unit"`
	LimitAmount  int64     `json:"limit_amount"`
	Reserved     int64     `json:"reserved"`
	Spent        int64     `json:"spent"`
	WindowEndsAt time.Time `json:"window_ends_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (IGAGovRuntimeBudget) TableName() string { return "iga_gov_runtime_budget" }

// IGAGovRuntimeBudgetEntry is one reservation against a ledger.
type IGAGovRuntimeBudgetEntry struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	BudgetID       uuid.UUID  `json:"budget_id" gorm:"type:uuid;not null"`
	DecisionID     uuid.UUID  `json:"decision_id" gorm:"type:uuid;not null"`
	ReservedAmount int64      `json:"reserved_amount"`
	SettledAmount  *int64     `json:"settled_amount,omitempty"`
	Overrun        int64      `json:"overrun"`
	State          string     `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	SettledAt      *time.Time `json:"settled_at,omitempty"`
}

func (IGAGovRuntimeBudgetEntry) TableName() string { return "iga_gov_runtime_budget_entry" }

// IGAGovRuntimeRoutingProof is a recorded gateway-only routing proof.
type IGAGovRuntimeRoutingProof struct {
	ID           uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	GatewayARN   string          `json:"gateway_arn"`
	AccountID    string          `json:"account_id"`
	Method       string          `json:"method"`
	Statement    string          `json:"statement"`
	Evidence     json.RawMessage `json:"evidence" gorm:"type:jsonb"`
	EvidenceHash string          `json:"evidence_hash"`
	RecordedBy   uuid.UUID       `json:"recorded_by" gorm:"type:uuid;not null"`
	RecordedAt   time.Time       `json:"recorded_at"`
	ValidUntil   time.Time       `json:"valid_until"`
	RevokedAt    *time.Time      `json:"revoked_at,omitempty"`
	RevokedBy    *uuid.UUID      `json:"revoked_by,omitempty" gorm:"type:uuid"`
	RevokeReason string          `json:"revoke_reason"`
}

func (IGAGovRuntimeRoutingProof) TableName() string { return "iga_gov_runtime_routing_proof" }

// IGAGovRuntimeAgentCorePush is one push of compiled Cedar to an engine.
type IGAGovRuntimeAgentCorePush struct {
	ID             uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID       uuid.UUID       `json:"policy_id" gorm:"type:uuid;not null"`
	VersionID      uuid.UUID       `json:"version_id" gorm:"type:uuid;not null"`
	GatewayARN     string          `json:"gateway_arn"`
	PolicyEngineID string          `json:"policy_engine_id"`
	Cedar          json.RawMessage `json:"cedar" gorm:"type:jsonb"`
	CedarHash      string          `json:"cedar_hash"`
	State          string          `json:"state"`
	Remote         json.RawMessage `json:"remote" gorm:"type:jsonb"`
	GatewayMode    string          `json:"gateway_mode"`
	Error          string          `json:"error"`
	PushedBy       uuid.UUID       `json:"pushed_by" gorm:"type:uuid;not null"`
	CreatedAt      time.Time       `json:"created_at"`
	ReadbackAt     *time.Time      `json:"readback_at,omitempty"`
}

func (IGAGovRuntimeAgentCorePush) TableName() string { return "iga_gov_runtime_agentcore_push" }

// IGAGovRuntimeBrokerRole is an opted-in broker role.
type IGAGovRuntimeBrokerRole struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID       uuid.UUID  `json:"connector_id" gorm:"type:uuid;not null"`
	AccountID         string     `json:"account_id"`
	RoleARN           string     `json:"role_arn"`
	MaxSessionSeconds int        `json:"max_session_seconds"`
	State             string     `json:"state"`
	CreatedBy         uuid.UUID  `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt         time.Time  `json:"created_at"`
	DisabledBy        *uuid.UUID `json:"disabled_by,omitempty" gorm:"type:uuid"`
	DisabledAt        *time.Time `json:"disabled_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (IGAGovRuntimeBrokerRole) TableName() string { return "iga_gov_runtime_broker_role" }

// IGAGovRuntimeBrokerSession is one brokered session (no credentials).
type IGAGovRuntimeBrokerSession struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	BrokerRoleID      uuid.UUID       `json:"broker_role_id" gorm:"type:uuid;not null"`
	DecisionID        uuid.UUID       `json:"decision_id" gorm:"type:uuid;not null"`
	AgentRef          string          `json:"agent_ref"`
	HumanUserID       uuid.UUID       `json:"human_user_id" gorm:"type:uuid;not null"`
	RoleARN           string          `json:"role_arn"`
	SessionName       string          `json:"session_name"`
	SourceIdentity    string          `json:"source_identity"`
	SessionPolicyHash string          `json:"session_policy_hash"`
	SessionTags       json.RawMessage `json:"session_tags" gorm:"type:jsonb"`
	DurationSeconds   int             `json:"duration_seconds"`
	State             string          `json:"state"`
	AssumedRoleARN    string          `json:"assumed_role_arn"`
	ExpiresAt         *time.Time      `json:"expires_at,omitempty"`
	Error             string          `json:"error"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func (IGAGovRuntimeBrokerSession) TableName() string { return "iga_gov_runtime_broker_session" }
