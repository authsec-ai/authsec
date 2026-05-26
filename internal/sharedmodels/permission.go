package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

// Permission is the canonical v4 permission row: tenant_id + resource + action.
// Authorization decisions go through services.RBACService.Check.
type Permission struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_permissions_tenant_resource_action"`
	WorkspaceID *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid;uniqueIndex:idx_permissions_tenant_resource_action;index"`
	Resource    string     `json:"resource" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Action      string     `json:"action" gorm:"type:text;not null;uniqueIndex:idx_permissions_tenant_resource_action"`
	Description string     `json:"description" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (Permission) TableName() string {
	return "permissions"
}
