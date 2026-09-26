package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// AD inventory tables (migration 039). These hold scopes, cursors and run
// status. Sanitized objects themselves live in iga_source_objects /
// iga_observations. Nothing here is projected into iga_identity_accounts.

// ADInventoryScope is one administrator-approved base DN.
type ADInventoryScope struct {
	ID                 uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID        uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SyncConfigID       uuid.UUID      `json:"sync_config_id" gorm:"type:uuid;not null;index"`
	IntegrationScopeID *uuid.UUID     `json:"integration_scope_id,omitempty" gorm:"type:uuid"`
	BaseDN             string         `json:"base_dn" gorm:"not null"`
	ObjectClasses      datatypes.JSON `json:"object_classes" gorm:"type:jsonb;not null"`
	Enabled            bool           `json:"enabled" gorm:"not null;default:true"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

func (ADInventoryScope) TableName() string { return "ad_inventory_scopes" }

// ADInventoryCursor is the persisted per-scope change-tracking position.
// A DC change (invocation_id) invalidates it and the next read is full.
type ADInventoryCursor struct {
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	ScopeID      uuid.UUID `json:"scope_id" gorm:"type:uuid;primaryKey"`
	InvocationID string    `json:"invocation_id" gorm:"not null;default:''"`
	HighestUSN   int64     `json:"highest_usn" gorm:"not null;default:0"`
	TrackingMode string    `json:"tracking_mode" gorm:"not null;default:'usn'"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (ADInventoryCursor) TableName() string { return "ad_inventory_cursors" }

// ADInventoryRun is the status of one scoped inventory read.
type ADInventoryRun struct {
	ID            uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID   uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SyncConfigID  uuid.UUID      `json:"sync_config_id" gorm:"type:uuid;not null;index"`
	IntegrationID *uuid.UUID     `json:"integration_id,omitempty" gorm:"type:uuid"`
	ScanRunID     *uuid.UUID     `json:"scan_run_id,omitempty" gorm:"type:uuid"`
	Status        string         `json:"status" gorm:"not null"`
	Mode          string         `json:"mode" gorm:"not null"`
	StartedAt     *time.Time     `json:"started_at,omitempty"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	RequestedBy   string         `json:"requested_by" gorm:"not null;default:''"`
	Coverage      datatypes.JSON `json:"coverage" gorm:"type:jsonb;not null"`
	ErrorText     string         `json:"error,omitempty" gorm:"column:error_text;not null;default:''"`
	ObjectsSeen   int            `json:"objects_seen" gorm:"not null;default:0"`
	CreatedAt     time.Time      `json:"created_at"`
}

func (ADInventoryRun) TableName() string { return "ad_inventory_runs" }

// ADDirectoryInstance is the forest identity used in the source key.
type ADDirectoryInstance struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	SyncConfigID uuid.UUID `json:"sync_config_id" gorm:"type:uuid;not null;index"`
	ForestID     string    `json:"forest_id" gorm:"not null"`
	DomainSID    string    `json:"domain_sid" gorm:"column:domain_sid;not null;default:''"`
	DomainDN     string    `json:"domain_dn" gorm:"not null;default:''"`
	DNSHostName  string    `json:"dns_host_name" gorm:"not null;default:''"`
	InvocationID string    `json:"invocation_id" gorm:"not null;default:''"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (ADDirectoryInstance) TableName() string { return "ad_directory_instances" }

// ADDirectoryPosture is D03 evidence for one account in one inventory run.
// Privileged and AdminCountOrphan are nil when the read cannot support a
// negative. Nothing in this row is a secret.
type ADDirectoryPosture struct {
	ID                      uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID             uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null;index"`
	RunID                   uuid.UUID      `json:"run_id" gorm:"type:uuid;not null;index"`
	ObjectGUID              string         `json:"object_guid" gorm:"not null"`
	ObjectSID               string         `json:"object_sid" gorm:"column:object_sid;not null;default:''"`
	AccountKind             string         `json:"account_kind" gorm:"not null"`
	DistinguishedName       string         `json:"distinguished_name" gorm:"not null;default:''"`
	SAMAccountName          string         `json:"sam_account_name" gorm:"not null;default:''"`
	Coverage                string         `json:"coverage" gorm:"not null"`
	PartialReasons          datatypes.JSON `json:"partial_reasons" gorm:"type:jsonb;not null"`
	UnconstrainedDelegation bool           `json:"unconstrained_delegation" gorm:"not null;default:false"`
	ConstrainedDelegation   bool           `json:"constrained_delegation" gorm:"not null;default:false"`
	ProtocolTransition      bool           `json:"protocol_transition" gorm:"not null;default:false"`
	DelegationTargets       datatypes.JSON `json:"delegation_targets" gorm:"type:jsonb;not null"`
	RBCDPrincipals          datatypes.JSON `json:"rbcd_principals" gorm:"type:jsonb;not null"`
	RBCDAsserted            bool           `json:"rbcd_asserted" gorm:"not null;default:false"`
	Privileged              *bool          `json:"privileged"`
	PrivilegedDirect        bool           `json:"privileged_direct" gorm:"not null;default:false"`
	PrivilegedNested        bool           `json:"privileged_nested" gorm:"not null;default:false"`
	PrivilegedPath          datatypes.JSON `json:"privileged_path" gorm:"type:jsonb;not null"`
	AdminCount              bool           `json:"admin_count" gorm:"not null;default:false"`
	AdminCountOrphan        *bool          `json:"admin_count_orphan"`
	SensitiveNotDelegated   bool           `json:"sensitive_not_delegated" gorm:"not null;default:false"`
	GMSA                    bool           `json:"gmsa" gorm:"not null;default:false"`
	SMSA                    bool           `json:"smsa" gorm:"not null;default:false"`
	DepthExceeded           bool           `json:"depth_exceeded" gorm:"not null;default:false"`
	AccountDisabled         bool           `json:"account_disabled" gorm:"not null;default:false"`
	CreatedAt               time.Time      `json:"created_at"`
}

func (ADDirectoryPosture) TableName() string { return "ad_directory_posture" }
