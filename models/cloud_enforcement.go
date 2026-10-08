package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Phase 3 cloud-side tables (SPEC-iga-phase3-policy.md §3.6, §3.9;
// migrations 053 and 056): the per-account enforcement binding (J3), and the
// immutable, per-scan resource-policy collection with its coverage and
// content-addressed documents.

// Enforcement binding states.
const (
	EnforcementBindingPending   = "pending"
	EnforcementBindingVerifying = "verifying"
	EnforcementBindingVerified  = "verified"
	EnforcementBindingPartial   = "partial"
	EnforcementBindingError     = "error"
	EnforcementBindingRevoked   = "revoked"
)

// Resource-policy coverage states, per (scan, form, region).
const (
	ResourcePolicyComplete     = "complete"
	ResourcePolicyPartial      = "partial"
	ResourcePolicyDenied       = "denied"
	ResourcePolicyNotCollected = "not_collected"
)

// CloudEnforcementBinding is the customer-consented enforcement role of one
// connected account. At most one non-revoked binding per connector. AuthRef
// names the Vault path; no secret is stored here.
type CloudEnforcementBinding struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID     uuid.UUID       `json:"connector_id" gorm:"type:uuid;not null"`
	AccountID       string          `json:"account_id" gorm:"not null"`
	RoleARN         string          `json:"role_arn" gorm:"column:role_arn;not null;default:''"`
	SelftestRoleARN string          `json:"selftest_role_arn" gorm:"column:selftest_role_arn;not null;default:''"`
	AuthRef         string          `json:"auth_ref" gorm:"not null;default:''"`
	TemplateVersion string          `json:"template_version" gorm:"not null;default:''"`
	State           string          `json:"state" gorm:"not null;default:'pending'"`
	Capabilities    json.RawMessage `json:"capabilities" gorm:"type:jsonb;not null;default:'{}'"`
	LastError       string          `json:"last_error" gorm:"not null;default:''"`
	LastErrorCode   string          `json:"last_error_code" gorm:"not null;default:''"`
	ConsentedBy     uuid.UUID       `json:"consented_by" gorm:"type:uuid;not null"`
	VerifiedAt      *time.Time      `json:"verified_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt       time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

func (CloudEnforcementBinding) TableName() string { return "cloud_enforcement_binding" }

// CloudPolicyDocument is a content-addressed resource-policy document,
// insert-once (triggers authsec_document_insert_check, authsec_row_immutable).
type CloudPolicyDocument struct {
	WorkspaceID  uuid.UUID       `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	DocumentHash string          `json:"document_hash" gorm:"primaryKey"`
	Canonical    string          `json:"canonical" gorm:"not null"`
	Document     json.RawMessage `json:"document" gorm:"type:jsonb;not null"`
	FirstSeenAt  time.Time       `json:"first_seen_at" gorm:"not null;default:now()"`
}

func (CloudPolicyDocument) TableName() string { return "cloud_policy_document" }

// CloudResourcePolicyCoverage is what one scan collected for one resource
// form in one region. complete means every enumerated resource was read.
// Immutable.
type CloudResourcePolicyCoverage struct {
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ConnectorID  uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	ScanRunID    uuid.UUID `json:"scan_run_id" gorm:"type:uuid;primaryKey"`
	ResourceForm string    `json:"resource_form" gorm:"primaryKey"`
	Region       string    `json:"region" gorm:"primaryKey"`
	State        string    `json:"state" gorm:"not null"`
	Enumerated   int       `json:"enumerated" gorm:"not null;default:0"`
	ReadOK       int       `json:"read_ok" gorm:"column:read_ok;not null;default:0"`
	ReadFailed   int       `json:"read_failed" gorm:"not null;default:0"`
	Reason       string    `json:"reason" gorm:"not null;default:''"`
	CollectedAt  time.Time `json:"collected_at" gorm:"not null;default:now()"`
}

func (CloudResourcePolicyCoverage) TableName() string { return "cloud_resource_policy_coverage" }

// CloudResourcePolicyObservation is one resource read in one scan, including
// "no policy" (PolicyPresent false). It always belongs to a coverage row.
// Immutable: a rescan adds rows, it never rewrites another scan's.
type CloudResourcePolicyObservation struct {
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ScanRunID     uuid.UUID `json:"scan_run_id" gorm:"type:uuid;primaryKey"`
	ResourceForm  string    `json:"resource_form" gorm:"not null"`
	Region        string    `json:"region" gorm:"not null"`
	ResourceARN   string    `json:"resource_arn" gorm:"column:resource_arn;primaryKey"`
	PolicyPresent bool      `json:"policy_present" gorm:"not null"`
	DocumentHash  *string   `json:"document_hash,omitempty"`
	ParseState    string    `json:"parse_state" gorm:"not null;default:'parsed'"`
	ReadAt        time.Time `json:"read_at" gorm:"not null"`
}

func (CloudResourcePolicyObservation) TableName() string { return "cloud_resource_policy_observation" }
