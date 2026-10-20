package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Phase 3 R2 (SPEC-iga-phase3-policy.md §12.3; 061_r2_time_bound_access):
// temporary grants and session revocations. Both are AuthSec-owned managed
// policies under /authsec/ attached to one role, with their own request,
// approval, deployment, verification and removal lifecycle.

// R2 states shared by both tables (061 CHECKs).
const (
	R2StateRequested      = "requested"
	R2StateRejected       = "rejected"
	R2StateCancelled      = "cancelled"
	R2StateApproved       = "approved"
	R2StateDeploying      = "deploying"
	R2StateActive         = "active"
	R2StateFailed         = "failed"
	R2StateOutcomeUnknown = "outcome_unknown"
	// Temporary grants end expired (at expiry) or revoked (early).
	R2StateExpiring = "expiring"
	R2StateExpired  = "expired"
	R2StateRevoked  = "revoked"
	// Session revocations end removed.
	R2StateRemoving = "removing"
	R2StateRemoved  = "removed"
)

// IGAGovTempGrant is one temporary grant (iga_gov_temp_grant).
type IGAGovTempGrant struct {
	ID                  uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID         uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID         uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityAccountID   uuid.UUID       `json:"identity_account_id" gorm:"type:uuid;not null"`
	AccountID           string          `json:"account_id" gorm:"not null"`
	RoleID              string          `json:"role_id" gorm:"not null"`
	RoleARN             string          `json:"role_arn" gorm:"column:role_arn;not null"`
	Actions             json.RawMessage `json:"actions" gorm:"type:jsonb;not null"`
	Resources           json.RawMessage `json:"resources" gorm:"type:jsonb;not null"`
	Escalations         json.RawMessage `json:"escalations" gorm:"type:jsonb;not null;default:'[]'"`
	EscalationAck       string          `json:"escalation_ack" gorm:"not null;default:''"`
	Reason              string          `json:"reason" gorm:"not null"`
	ExpiresAt           time.Time       `json:"expires_at" gorm:"not null"`
	PolicyName          string          `json:"policy_name" gorm:"not null"`
	PolicyARN           string          `json:"policy_arn" gorm:"column:policy_arn;not null"`
	DocumentHash        string          `json:"document_hash" gorm:"not null"`
	RequestHash         string          `json:"request_hash" gorm:"not null"`
	RequestKey          string          `json:"request_key" gorm:"not null"`
	State               string          `json:"state" gorm:"not null;default:'requested'"`
	StateReason         string          `json:"state_reason" gorm:"not null;default:''"`
	RequestedBy         uuid.UUID       `json:"requested_by" gorm:"type:uuid;not null"`
	DecidedBy           *uuid.UUID      `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt           *time.Time      `json:"decided_at,omitempty"`
	DecisionReason      string          `json:"decision_reason" gorm:"not null;default:''"`
	ApprovedRequestHash *string         `json:"approved_request_hash,omitempty"`
	EndedBy             *uuid.UUID      `json:"ended_by,omitempty" gorm:"type:uuid"`
	EndReason           string          `json:"end_reason" gorm:"not null;default:''"`
	DeployedAt          *time.Time      `json:"deployed_at,omitempty"`
	VerifiedAt          *time.Time      `json:"verified_at,omitempty"`
	EndedAt             *time.Time      `json:"ended_at,omitempty"`
	LastReadbackAt      *time.Time      `json:"last_readback_at,omitempty"`
	Drift               string          `json:"drift" gorm:"not null;default:''"`
	PendingOp           string          `json:"pending_op" gorm:"not null;default:''"`
	PendingOpAt         *time.Time      `json:"pending_op_at,omitempty"`
	SettleAfter         *time.Time      `json:"settle_after,omitempty"`
	Ops                 json.RawMessage `json:"ops" gorm:"type:jsonb;not null;default:'[]'"`
	CreatedAt           time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt           time.Time       `json:"updated_at" gorm:"not null;default:now()"`
	// Access policies (137): effect allow | deny, the policy and version a
	// deployment row belongs to, and the window start. Nil / allow for R2
	// temporary grants.
	Effect    string     `json:"effect" gorm:"not null;default:'allow'"`
	PolicyID  *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`
	VersionID *uuid.UUID `json:"version_id,omitempty" gorm:"type:uuid"`
	StartsAt  *time.Time `json:"starts_at,omitempty"`
}

func (IGAGovTempGrant) TableName() string { return "iga_gov_temp_grant" }

// IGAGovAccessPolicyVersion is one immutable access-policy version (137).
type IGAGovAccessPolicyVersion struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID        uuid.UUID       `json:"policy_id" gorm:"type:uuid;not null"`
	VersionNo       int             `json:"version_no" gorm:"not null"`
	Intent          json.RawMessage `json:"intent" gorm:"type:jsonb;not null"`
	IntentHash      string          `json:"intent_hash" gorm:"not null"`
	Status          string          `json:"status" gorm:"not null;default:'applied'"`
	CreatedBy       uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	CreatedAt       time.Time       `json:"created_at" gorm:"not null;default:now()"`
	StatusChangedAt time.Time       `json:"status_changed_at" gorm:"not null;default:now()"`
}

func (IGAGovAccessPolicyVersion) TableName() string { return "iga_gov_access_policy_version" }

// Access-policy version statuses (137).
const (
	AccessVersionApplied    = "applied"
	AccessVersionSuperseded = "superseded"
)

// IGAGovSessionRevocation is one session revocation
// (iga_gov_session_revocation).
type IGAGovSessionRevocation struct {
	ID                  uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID         uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID         uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityAccountID   uuid.UUID       `json:"identity_account_id" gorm:"type:uuid;not null"`
	AccountID           string          `json:"account_id" gorm:"not null"`
	RoleID              string          `json:"role_id" gorm:"not null"`
	RoleARN             string          `json:"role_arn" gorm:"column:role_arn;not null"`
	Reason              string          `json:"reason" gorm:"not null"`
	Emergency           bool            `json:"emergency" gorm:"not null;default:false"`
	KeepHours           int             `json:"keep_hours" gorm:"not null;default:13"`
	IssuedBefore        *time.Time      `json:"issued_before,omitempty"`
	RemoveAfter         *time.Time      `json:"remove_after,omitempty"`
	PolicyName          string          `json:"policy_name" gorm:"not null"`
	PolicyARN           string          `json:"policy_arn" gorm:"column:policy_arn;not null"`
	DocumentHash        *string         `json:"document_hash,omitempty"`
	RequestHash         string          `json:"request_hash" gorm:"not null"`
	State               string          `json:"state" gorm:"not null;default:'requested'"`
	StateReason         string          `json:"state_reason" gorm:"not null;default:''"`
	RequestedBy         uuid.UUID       `json:"requested_by" gorm:"type:uuid;not null"`
	DecidedBy           *uuid.UUID      `json:"decided_by,omitempty" gorm:"type:uuid"`
	DecidedAt           *time.Time      `json:"decided_at,omitempty"`
	DecisionReason      string          `json:"decision_reason" gorm:"not null;default:''"`
	ApprovedRequestHash *string         `json:"approved_request_hash,omitempty"`
	EndedBy             *uuid.UUID      `json:"ended_by,omitempty" gorm:"type:uuid"`
	EndReason           string          `json:"end_reason" gorm:"not null;default:''"`
	DeployedAt          *time.Time      `json:"deployed_at,omitempty"`
	VerifiedAt          *time.Time      `json:"verified_at,omitempty"`
	EndedAt             *time.Time      `json:"ended_at,omitempty"`
	LastReadbackAt      *time.Time      `json:"last_readback_at,omitempty"`
	Drift               string          `json:"drift" gorm:"not null;default:''"`
	PendingOp           string          `json:"pending_op" gorm:"not null;default:''"`
	PendingOpAt         *time.Time      `json:"pending_op_at,omitempty"`
	SettleAfter         *time.Time      `json:"settle_after,omitempty"`
	Ops                 json.RawMessage `json:"ops" gorm:"type:jsonb;not null;default:'[]'"`
	CreatedAt           time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt           time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovSessionRevocation) TableName() string { return "iga_gov_session_revocation" }

// IGAGovAzureAccess is one principal's deployment of an access-policy
// version on an Azure resource (144): an allow is a role assignment AuthSec
// creates; a block is the principal's own assignments on the resource,
// removed and recorded in Revoked so they can be restored.
type IGAGovAzureAccess struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyID          uuid.UUID       `json:"policy_id" gorm:"type:uuid;not null"`
	VersionID         uuid.UUID       `json:"version_id" gorm:"type:uuid;not null"`
	ConnectorID       uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	IdentityAccountID uuid.UUID       `json:"identity_account_id" gorm:"type:uuid;not null"`
	TenantID          string          `json:"tenant_id" gorm:"not null"`
	SubscriptionID    string          `json:"subscription_id" gorm:"not null"`
	PrincipalID       string          `json:"principal_id" gorm:"not null"`
	PrincipalType     string          `json:"principal_type" gorm:"not null;default:'ServicePrincipal'"`
	PrincipalName     string          `json:"principal_name" gorm:"not null;default:''"`
	Scope             string          `json:"scope" gorm:"not null"`
	Effect            string          `json:"effect" gorm:"not null"`
	Access            json.RawMessage `json:"access" gorm:"type:jsonb;not null;default:'[]'"`
	RoleDefinitionID  string          `json:"role_definition_id" gorm:"not null;default:''"`
	AssignmentName    string          `json:"assignment_name" gorm:"not null;default:''"`
	Revoked           json.RawMessage `json:"revoked" gorm:"type:jsonb;not null;default:'[]'"`
	State             string          `json:"state" gorm:"not null;default:'approved'"`
	StateReason       string          `json:"state_reason" gorm:"not null;default:''"`
	EndReason         string          `json:"end_reason" gorm:"not null;default:''"`
	Drift             string          `json:"drift" gorm:"not null;default:''"`
	StartsAt          *time.Time      `json:"starts_at,omitempty"`
	ExpiresAt         time.Time       `json:"expires_at" gorm:"not null"`
	DeployedAt        *time.Time      `json:"deployed_at,omitempty"`
	VerifiedAt        *time.Time      `json:"verified_at,omitempty"`
	LastReadbackAt    *time.Time      `json:"last_readback_at,omitempty"`
	EndedAt           *time.Time      `json:"ended_at,omitempty"`
	CreatedBy         uuid.UUID       `json:"created_by" gorm:"type:uuid;not null"`
	Ops               json.RawMessage `json:"ops" gorm:"type:jsonb;not null;default:'[]'"`
	CreatedAt         time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt         time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (IGAGovAzureAccess) TableName() string { return "iga_gov_azure_access" }
