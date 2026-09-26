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
	DirSyncValid bool      `json:"dirsync_valid" gorm:"column:dirsync_valid;not null;default:false"`
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
