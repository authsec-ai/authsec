package models

import (
	"time"

	"github.com/google/uuid"
)

// ITDR finding lifecycle.
const (
	ITDRFindingStatusOpen          = "open"
	ITDRFindingStatusAcknowledged  = "acknowledged"
	ITDRFindingStatusResolved      = "resolved"
	ITDRFindingStatusFalsePositive = "false_positive"

	ITDRFindingOutcomeAttempted  = "attempted"
	ITDRFindingOutcomePrevented  = "prevented"
	ITDRFindingOutcomeSuccessful = "successful"
	ITDRFindingOutcomeUnknown    = "unknown"

	ITDRSeverityLow      = "low"
	ITDRSeverityMedium   = "medium"
	ITDRSeverityHigh     = "high"
	ITDRSeverityCritical = "critical"

	ITDRConfidenceLow    = "low"
	ITDRConfidenceMedium = "medium"
	ITDRConfidenceHigh   = "high"

	ITDRResponsePlanStatusRequested = "requested"
	ITDRResponsePlanStatusApproved  = "approved"
	ITDRResponsePlanStatusExecuting = "executing"
	ITDRResponsePlanStatusVerified  = "verified"
	ITDRResponsePlanStatusFailed    = "failed"
	ITDRResponsePlanStatusRefused   = "refused"

	ITDRLeaseStatusPending  = "pending"
	ITDRLeaseStatusApproved = "approved"
	ITDRLeaseStatusRedeemed = "redeemed"
	ITDRLeaseStatusExpired  = "expired"
	ITDRLeaseStatusDenied   = "denied"

	ITDRAlertStatusPending   = "pending"
	ITDRAlertStatusDelivered = "delivered"
	ITDRAlertStatusFailed    = "failed"
)

// ITDRDetectionRule is one rule in the workspace detection catalog.
type ITDRDetectionRule struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	RuleKey     string    `json:"rule_key" gorm:"not null"`
	Name        string    `json:"name" gorm:"not null"`
	Description string    `json:"description" gorm:"not null;default:''"`
	Severity    string    `json:"severity" gorm:"not null"`
	Confidence  string    `json:"confidence" gorm:"not null"`
	Enabled     bool      `json:"enabled" gorm:"not null;default:true"`
	Config      []byte    `json:"config" gorm:"type:jsonb;not null;default:'{}'"`
	Version     int       `json:"version" gorm:"not null;default:1"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ITDRDetectionRule) TableName() string { return "itdr_detection_rules" }

// ITDRFinding is a grouped detection event within a configurable window.
type ITDRFinding struct {
	ID                   uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID          uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	RuleID               uuid.UUID  `json:"rule_id" gorm:"type:uuid;not null"`
	RuleVersion          int        `json:"rule_version" gorm:"not null;default:1"`
	Severity             string     `json:"severity" gorm:"not null"`
	Confidence           string     `json:"confidence" gorm:"not null"`
	Status               string     `json:"status" gorm:"not null;default:'open'"`
	Outcome              string     `json:"outcome" gorm:"not null;default:'unknown'"`
	WorkloadID           *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	RuntimeInstanceID    *uuid.UUID `json:"runtime_instance_id,omitempty" gorm:"type:uuid"`
	ResourceID           *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	GraphRevision        int64      `json:"graph_revision" gorm:"not null;default:0"`
	FirstSeen            time.Time  `json:"first_seen"`
	LastSeen             time.Time  `json:"last_seen"`
	EventCount           int        `json:"event_count" gorm:"not null;default:1"`
	FindingWindowSeconds int        `json:"finding_window_seconds" gorm:"not null;default:3600"`
	RecommendedResponse  string     `json:"recommended_response" gorm:"not null;default:''"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (ITDRFinding) TableName() string { return "itdr_findings" }

// ITDRFindingIdentity is the finding ↔ identity join.
type ITDRFindingIdentity struct {
	FindingID         uuid.UUID `json:"finding_id" gorm:"type:uuid;primaryKey"`
	WorkspaceID       uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	IdentityAccountID uuid.UUID `json:"identity_account_id" gorm:"type:uuid;primaryKey"`
}

func (ITDRFindingIdentity) TableName() string { return "itdr_finding_identities" }

// ITDRFindingPolicyRevision is the finding ↔ policy revision join.
type ITDRFindingPolicyRevision struct {
	FindingID        uuid.UUID `json:"finding_id" gorm:"type:uuid;primaryKey"`
	WorkspaceID      uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	PolicyRevisionID uuid.UUID `json:"policy_revision_id" gorm:"type:uuid;primaryKey"`
}

func (ITDRFindingPolicyRevision) TableName() string { return "itdr_finding_policy_revisions" }

// ITDRResponsePlan is an immutable-once-approved response plan.
type ITDRResponsePlan struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	FindingID        uuid.UUID  `json:"finding_id" gorm:"type:uuid;not null"`
	Status           string     `json:"status" gorm:"not null;default:'requested'"`
	Targets          []byte     `json:"targets" gorm:"type:jsonb;not null;default:'[]'"`
	Actions          []byte     `json:"actions" gorm:"type:jsonb;not null;default:'[]'"`
	SharedUseImpact  string     `json:"shared_use_impact" gorm:"not null;default:''"`
	Expiry           *time.Time `json:"expiry,omitempty"`
	RollbackBehavior string     `json:"rollback_behavior" gorm:"not null;default:''"`
	ActorID          uuid.UUID  `json:"actor_id" gorm:"type:uuid;not null"`
	ApprovedBy       *uuid.UUID `json:"approved_by,omitempty" gorm:"type:uuid"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	Reason           string     `json:"reason" gorm:"not null;default:''"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

func (ITDRResponsePlan) TableName() string { return "itdr_response_plans" }

// ITDREscalationLease is a bounded privileged access lease.
type ITDREscalationLease struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID      uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	WorkloadID       *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	ClientIdentityID uuid.UUID  `json:"client_identity_id" gorm:"type:uuid;not null"`
	ResourceID       *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	Action           string     `json:"action" gorm:"not null"`
	PolicyRevisionID *uuid.UUID `json:"policy_revision_id,omitempty" gorm:"type:uuid"`
	ApproverID       *uuid.UUID `json:"approver_id,omitempty" gorm:"type:uuid"`
	Audience         string     `json:"audience" gorm:"not null;default:''"`
	Expiry           time.Time  `json:"expiry" gorm:"not null"`
	Nonce            string     `json:"nonce" gorm:"not null;default:''"`
	MaxUses          int        `json:"max_uses" gorm:"not null;default:1"`
	UsesRemaining    int        `json:"uses_remaining" gorm:"not null;default:1"`
	Status           string     `json:"status" gorm:"not null;default:'pending'"`
	CreatedAt        time.Time  `json:"created_at"`
	RedeemedAt       *time.Time `json:"redeemed_at,omitempty"`
}

func (ITDREscalationLease) TableName() string { return "itdr_escalation_leases" }

// ITDRAlertDelivery is an append-only webhook dispatch log entry.
type ITDRAlertDelivery struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID  uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	FindingID    uuid.UUID  `json:"finding_id" gorm:"type:uuid;not null"`
	WebhookURL   string     `json:"webhook_url" gorm:"not null"`
	Status       string     `json:"status" gorm:"not null;default:'pending'"`
	Attempt      int        `json:"attempt" gorm:"not null;default:0"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
	ResponseCode *int       `json:"response_code,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (ITDRAlertDelivery) TableName() string { return "itdr_alert_deliveries" }
