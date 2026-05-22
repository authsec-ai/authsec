package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

// Permission mirrors the canonical permissions table created in migration 054.
// The full legacy resource_methods / scope_permissions / api_scopes tree has
// been retired; this struct exists only so the GORM many-to-many declarations
// on Role and Scope compile. Authorization decisions go through
// services.RBACService.Check, not this struct.
type Permission struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_permissions_tenant_resource_action"`
	TenantID    *uuid.UUID `json:"tenant_id" gorm:"type:uuid;uniqueIndex:idx_permissions_tenant_resource_action"`
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid;index"`
	Resource    string     `json:"resource" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Action      string     `json:"action" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Description string     `json:"description" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (Permission) TableName() string {
	return "permissions"
}
