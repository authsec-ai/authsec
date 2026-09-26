package models

import (
	"time"

	"github.com/google/uuid"
)

// SyncConfiguration represents a stored directory sync configuration
type SyncConfiguration struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index:idx_sync_configs_workspace_id"`
	ClientID    uuid.UUID `json:"client_id" gorm:"type:uuid;not null;index:idx_sync_configs_client_id"`
	ProjectID   uuid.UUID `json:"project_id" gorm:"type:uuid;not null"`

	// Sync type: 'active_directory' or 'entra_id'
	SyncType string `json:"sync_type" gorm:"type:varchar(50);not null;check:sync_type IN ('active_directory', 'entra_id');index:idx_sync_configs_sync_type"`

	// Configuration name and description
	ConfigName  string `json:"config_name" gorm:"type:varchar(255);not null"`
	Description string `json:"description" gorm:"type:text"`

	// Status
	IsActive bool `json:"is_active" gorm:"default:true;index:idx_sync_configs_active"`

	// AD-specific fields (encrypted in DB)
	ADServer     string `json:"ad_server,omitempty" gorm:"type:varchar(500)"`
	ADUsername   string `json:"ad_username,omitempty" gorm:"type:varchar(500)"`
	ADPassword   string `json:"ad_password,omitempty" gorm:"type:text"` // Encrypted
	ADBaseDN     string `json:"ad_base_dn,omitempty" gorm:"type:varchar(500)"`
	ADFilter     string `json:"ad_filter,omitempty" gorm:"type:text"`
	ADUseSSL     bool   `json:"ad_use_ssl,omitempty" gorm:"default:true"`
	ADSkipVerify bool   `json:"ad_skip_verify,omitempty" gorm:"default:false"`
	// Inventory-adapter settings. Additive: the human-user import ignores them
	// except CA bundle, StartTLS and the shared TLS policy.
	ADCABundle       string `json:"ad_ca_bundle,omitempty" gorm:"column:ad_ca_bundle;type:text"`
	ADPageSize       int    `json:"ad_page_size,omitempty" gorm:"column:ad_page_size;default:500"`
	ADChangeTracking bool   `json:"ad_change_tracking,omitempty" gorm:"column:ad_change_tracking;default:false"`
	ADStartTLS       bool   `json:"ad_start_tls,omitempty" gorm:"column:ad_start_tls;default:false"`
	ADTrackingMode   string `json:"ad_tracking_mode,omitempty" gorm:"column:ad_tracking_mode;type:text"`

	// Entra ID-specific fields (encrypted in DB)
	EntraWorkspaceID  string `json:"entra_tenant_id,omitempty" gorm:"type:varchar(500)"`
	EntraClientID     string `json:"entra_client_id,omitempty" gorm:"type:varchar(500)"`
	EntraClientSecret string `json:"entra_client_secret,omitempty" gorm:"type:text"` // Encrypted
	EntraScopes       string `json:"entra_scopes,omitempty" gorm:"type:text"`        // JSON array as text
	EntraSkipVerify   bool   `json:"entra_skip_verify,omitempty" gorm:"default:false"`

	// Sync metadata
	LastSyncAt         *time.Time `json:"last_sync_at,omitempty"`
	LastSyncStatus     string     `json:"last_sync_status,omitempty" gorm:"type:varchar(50)"` // 'success', 'failed', 'in_progress'
	LastSyncError      string     `json:"last_sync_error,omitempty" gorm:"type:text"`
	LastSyncUsersCount int        `json:"last_sync_users_count,omitempty" gorm:"default:0"`

	// Audit fields
	CreatedAt time.Time  `json:"created_at" gorm:"default:now()"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"default:now()"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" gorm:"type:uuid"` // Admin user who created this
}

// TableName specifies the table name for SyncConfiguration
func (SyncConfiguration) TableName() string {
	return "sync_configurations"
}

// ADConnection builds the directory connection from a stored row. password is
// the already-decrypted bind secret. The returned config never logs it.
func (s SyncConfiguration) ADConnection(password string) ADSyncConfig {
	mode := s.ADTrackingMode
	if mode == "" {
		mode = "usn"
	}
	return ADSyncConfig{
		Server:         s.ADServer,
		Username:       s.ADUsername,
		Password:       password,
		BaseDN:         s.ADBaseDN,
		Filter:         s.ADFilter,
		UseSSL:         s.ADUseSSL,
		SkipVerify:     s.ADSkipVerify,
		StartTLS:       s.ADStartTLS,
		CABundle:       s.ADCABundle,
		PageSize:       s.ADPageSize,
		ChangeTracking: s.ADChangeTracking,
		TrackingMode:   mode,
	}
}

// CreateSyncConfigRequest represents the request to create a new sync configuration
type CreateSyncConfigRequest struct {
	WorkspaceID string `json:"workspace_id" binding:"required"`
	ClientID    string `json:"client_id"`
	ProjectID   string `json:"project_id"`
	SyncType    string `json:"sync_type" binding:"required"` // 'active_directory' or 'entra_id'
	ConfigName  string `json:"config_name" binding:"required"`
	Description string `json:"description"`

	// AD config (required if sync_type is 'active_directory')
	ADConfig *ADSyncConfig `json:"ad_config,omitempty"`

	// Entra ID config (required if sync_type is 'entra_id')
	EntraConfig *EntraIDSyncConfig `json:"entra_config,omitempty"`
}

// EntraIDSyncConfig represents Entra ID sync configuration
type EntraIDSyncConfig struct {
	WorkspaceID  string   `json:"workspace_id" binding:"required"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret" binding:"required"`
	Scopes       []string `json:"scopes,omitempty"`
	SkipVerify   bool     `json:"skip_verify,omitempty"`
}

// ListSyncConfigsRequest represents the request to list sync configurations
type ListSyncConfigsRequest struct {
	WorkspaceID string  `json:"workspace_id" binding:"required"`
	ClientID    string  `json:"client_id"`
	SyncType    *string `json:"sync_type,omitempty"` // Optional filter: 'active_directory' or 'entra_id'
}

// UpdateSyncConfigRequest represents the request to update a sync configuration
type UpdateSyncConfigRequest struct {
	ID          string  `json:"id" binding:"required"`
	WorkspaceID string  `json:"workspace_id" binding:"required"`
	ClientID    string  `json:"client_id"`
	ConfigName  *string `json:"config_name,omitempty"`
	Description *string `json:"description,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`

	// AD config (partial update)
	ADConfig *ADSyncConfig `json:"ad_config,omitempty"`

	// Entra ID config (partial update)
	EntraConfig *EntraIDSyncConfig `json:"entra_config,omitempty"`
}

// DeleteSyncConfigRequest represents the request to delete a sync configuration
type DeleteSyncConfigRequest struct {
	ID          string `json:"id" binding:"required"`
	WorkspaceID string `json:"workspace_id" binding:"required"`
	ClientID    string `json:"client_id"`
}

// SyncConfigResponse represents the response for sync configuration operations
type SyncConfigResponse struct {
	Success bool                `json:"success"`
	Message string              `json:"message,omitempty"`
	Data    *SyncConfiguration  `json:"data,omitempty"`
	Configs []SyncConfiguration `json:"configs,omitempty"`
}

// SyncWithStoredConfigRequest represents the request to sync using stored credentials
type SyncWithStoredConfigRequest struct {
	ConfigID    string `json:"config_id" binding:"required"`
	WorkspaceID string `json:"workspace_id" binding:"required"`
	ClientID    string `json:"client_id"`
	DryRun      bool   `json:"dry_run,omitempty"`
}
