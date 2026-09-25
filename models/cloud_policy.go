package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// The AWS collection model that migration 035 adds (SPEC-iga-phase2-graph.md
// §1.4, §3 035). These are cloud_* tables: authoritative, per connector, and
// written by the scanners under the run fence. The projector reads them and
// never writes them.
//
// EVERY REFERENCE IS WORKSPACE- AND INTEGRATION-QUALIFIED. These rows are facts
// one integration collected about its own account, so a membership, an inline
// policy's holder and an attachment's principal and policy must belong to the
// same workspace AND the same integration as the row. The composite foreign
// keys make the database refuse anything else (B20).

// Policy kinds as the COLLECTOR records them. The graph distinguishes
// aws_managed from customer_managed (iga_policy.policy_kind); collection only
// needs managed vs inline, plus AWSManaged.
const (
	CloudPolicyManaged = "managed"
	CloudPolicyInline  = "inline"
)

// Attachment kinds. A boundary caps and never grants.
const (
	CloudAttachmentAttached = "attached"
	CloudAttachmentInline   = "inline"
	CloudAttachmentBoundary = "boundary"
)

// CloudPolicy is a policy AS READ BY ONE CONNECTOR.
//
// Keyed per connector, unlike cloud_resource: an AWS-managed policy attached in
// two accounts is two rows here and ONE iga_policy, and no scanner ever
// reassigns another's row -- which is the defect that made a bucket two
// accounts shared vanish from one account's snapshot on the graph branch.
type CloudPolicy struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	PolicyKind string `json:"policy_kind" gorm:"not null"`
	// NativeID is the ARN for a managed policy, and
	// 'inline:' || holder ARN || ':' || name for an inline one.
	NativeID string `json:"native_id" gorm:"not null"`
	// HolderIdentityID is set exactly for inline policies
	// (cloud_policy_inline_chk).
	HolderIdentityID *uuid.UUID `json:"holder_identity_id,omitempty" gorm:"type:uuid"`
	Name             string     `json:"name" gorm:"not null"`

	// PolicyID is AWS's PolicyId (ANPA...), managed only. It is the policy's
	// CREATION BOUNDARY: a customer-managed policy deleted and recreated under
	// the same ARN has a new one, and every key below the policy is built from
	// it (§2.4), so the new incarnation shares nothing with the old.
	PolicyID   string `json:"policy_id" gorm:"not null;default:''"`
	AWSManaged bool   `json:"aws_managed" gorm:"not null;default:false"`
	// VersionID is the default version read, managed only.
	VersionID string `json:"version_id" gorm:"not null;default:''"`

	// Document is NULL exactly when it could not be fetched; DocumentError then
	// says why. cloud_policy_readable_chk requires one or the other.
	Document     json.RawMessage `json:"document,omitempty" gorm:"type:jsonb"`
	DocumentHash string          `json:"document_hash" gorm:"not null;default:''"`
	// DocumentError is non-empty when the document is UNREADABLE this run:
	// "fetch: <reason>" or "parse: <reason>". Such a policy's statements,
	// grants and the resources only it names go STALE, never ended (§4.10).
	DocumentError string `json:"document_error" gorm:"not null;default:''"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
}

func (CloudPolicy) TableName() string { return "cloud_policy" }

// Unreadable reports whether this run could not read the document.
func (p CloudPolicy) Unreadable() bool { return p.DocumentError != "" }

// CloudPolicyAttachment is one account's fact about its own policy and its own
// principal: attached, embedded inline, or set as a permissions boundary.
type CloudPolicyAttachment struct {
	ID                  uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID         uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID         uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	PolicyRowID         uuid.UUID `json:"policy_row_id" gorm:"type:uuid;not null"`
	PrincipalIdentityID uuid.UUID `json:"principal_identity_id" gorm:"type:uuid;not null"`
	AttachmentKind      string    `json:"attachment_kind" gorm:"not null"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
}

func (CloudPolicyAttachment) TableName() string { return "cloud_policy_attachment" }

// CloudGroupMembership is user -> group, as one integration read it.
type CloudGroupMembership struct {
	ID              uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID     uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	UserIdentityID  uuid.UUID `json:"user_identity_id" gorm:"type:uuid;not null"`
	GroupIdentityID uuid.UUID `json:"group_identity_id" gorm:"type:uuid;not null"`

	LastSeenGeneration int       `json:"last_seen_generation" gorm:"not null"`
	FirstSeenAt        time.Time `json:"first_seen_at" gorm:"not null;default:now()"`
	LastSeenAt         time.Time `json:"last_seen_at" gorm:"not null;default:now()"`
}

func (CloudGroupMembership) TableName() string { return "cloud_group_membership" }
