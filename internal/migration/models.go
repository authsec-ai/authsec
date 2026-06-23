package migration

import (
	"time"

	"github.com/google/uuid"
)

// MigrationLog tracks each migration execution in the master database.
type MigrationLog struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Version     int       `gorm:"not null;index"                                  json:"version"`
	Name        string    `gorm:"type:varchar(255);not null"                      json:"name"`
	ExecutedAt  time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"              json:"executed_at"`
	Success     bool      `gorm:"not null;default:false"                          json:"success"`
	ErrorMsg    string    `gorm:"type:text"                                       json:"error_msg,omitempty"`
	DBType      string    `gorm:"type:varchar(50);not null"                       json:"db_type"`
	WorkspaceID    *string   `gorm:"type:varchar(255);index"                         json:"workspace_id,omitempty"`
	ExecutionMS int64     `gorm:"not null;default:0"                              json:"execution_ms"`
}

func (MigrationLog) TableName() string { return "migration_logs" }

// MigrationStatusResponse is returned by GetMigrationStatus.
type MigrationStatusResponse struct {
	DBType          string    `json:"db_type"`
	WorkspaceID        *string   `json:"workspace_id,omitempty"`
	LastMigration   int       `json:"last_migration"`
	TotalMigrations int       `json:"total_migrations"`
	Status          string    `json:"status"`
	LastExecuted    time.Time `json:"last_executed"`
}

// CreateWorkspaceDBRequest is the payload for the create-tenant-db endpoint.
type CreateWorkspaceDBRequest struct {
	WorkspaceID     string `json:"workspace_id"     binding:"required"`
	DatabaseName string `json:"database_name,omitempty"`
	WorkspaceDomain string `json:"workspace_domain,omitempty"`
}

// CreateWorkspaceDBResponse is the response for the create-tenant-db endpoint.
type CreateWorkspaceDBResponse struct {
	WorkspaceID        string    `json:"workspace_id"`
	DatabaseName    string    `json:"database_name"`
	MigrationStatus string    `json:"migration_status"`
	CreatedAt       time.Time `json:"created_at"`
	Existed         bool      `json:"existed"`
}

// TemplateStatusResponse is returned by the template-status endpoint.
type TemplateStatusResponse struct {
	TemplateName string `json:"template_name"`
	Ready        bool   `json:"ready"`
}
