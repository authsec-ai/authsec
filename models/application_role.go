package models

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationRole is a per-Application RBAC role. A role bundles scope
// grants (via ApplicationRoleScopeGrant) and gets bound to users via
// ApplicationRoleBinding (Phase 8 part 2). Lives in the tenant DB.
//
// is_system marks roles that the backend created automatically (e.g. a
// future "viewer" default role). Admins can rename/recolor system roles
// but cannot delete them — enforced in the service layer.
type ApplicationRole struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID      string    `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ApplicationID uuid.UUID `json:"application_id" gorm:"type:uuid;not null;index"`
	Name          string    `json:"name" gorm:"type:text;not null"`
	Description   string    `json:"description,omitempty" gorm:"type:text"`
	IsSystem      bool      `json:"is_system" gorm:"not null;default:false"`
	CreatedAt     time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt     time.Time `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationRole) TableName() string { return "application_roles" }

// ApplicationRoleScopeGrant joins a role to a scope. The composite unique
// constraint (role_id, scope_id) is the natural key — a role grants each
// scope at most once.
type ApplicationRoleScopeGrant struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID  string    `json:"tenant_id" gorm:"type:varchar(255);not null"`
	RoleID    uuid.UUID `json:"role_id" gorm:"type:uuid;not null;index"`
	ScopeID   uuid.UUID `json:"scope_id" gorm:"type:uuid;not null;index"`
	CreatedAt time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationRoleScopeGrant) TableName() string { return "application_role_scope_grants" }
