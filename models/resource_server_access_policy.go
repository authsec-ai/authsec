package models

import (
	"time"

	"github.com/google/uuid"
)

// ResourceServerAccessPolicy stores backend-owned onboarding policy for first-time MCP users.
type ResourceServerAccessPolicy struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID          uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;index"`
	ResourceServerID  uuid.UUID  `json:"resource_server_id" gorm:"type:uuid;not null;uniqueIndex"`
	Enabled           bool       `json:"enabled" gorm:"not null;default:false"`
	DefaultRoleID     *uuid.UUID `json:"default_role_id,omitempty" gorm:"type:uuid"`
	AssignmentTrigger string     `json:"assignment_trigger" gorm:"type:text;not null;default:'first_successful_login'"`
	AssignmentSource  string     `json:"assignment_source" gorm:"type:text;not null;default:'default_policy'"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`

	DefaultRole *RBACRole `json:"default_role,omitempty" gorm:"foreignKey:DefaultRoleID;references:ID"`
}

func (ResourceServerAccessPolicy) TableName() string {
	return "resource_server_access_policies"
}
