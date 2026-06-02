package models

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationRoleBinding is the user ↔ role join for per-Application RBAC.
// Each row: "user U has role R on application A." Lives in tenant DB so
// the FK to users.id is real.
type ApplicationRoleBinding struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID      string     `json:"tenant_id" gorm:"type:varchar(255);not null"`
	ApplicationID uuid.UUID  `json:"application_id" gorm:"type:uuid;not null;index"`
	RoleID        uuid.UUID  `json:"role_id" gorm:"type:uuid;not null;index"`
	UserID        uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;index"`
	GrantedAt     time.Time  `json:"granted_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	GrantedBy     *uuid.UUID `json:"granted_by,omitempty" gorm:"type:uuid"`
}

func (ApplicationRoleBinding) TableName() string { return "application_role_bindings" }
