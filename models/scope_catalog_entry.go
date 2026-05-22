package models

import (
	"time"

	"github.com/google/uuid"
)

// ScopeCatalogEntry is a reusable scope vocabulary item. Catalog entries do
// not grant runtime access directly; app-owned oauth_scopes remain the
// enforcement surface.
type ScopeCatalogEntry struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index;uniqueIndex:idx_scope_catalog_workspace_key"`
	Key         string    `json:"key" gorm:"type:text;not null;uniqueIndex:idx_scope_catalog_workspace_key"`
	DisplayName string    `json:"display_name" gorm:"type:text;not null"`
	Description string    `json:"description" gorm:"type:text"`
	RiskLevel   string    `json:"risk_level" gorm:"type:text;not null;default:'low'"`
	Source      string    `json:"source" gorm:"type:text;not null;default:'manual'"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ScopeCatalogEntry) TableName() string {
	return "scope_catalog_entries"
}
