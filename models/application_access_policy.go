package models

import (
	"time"

	"github.com/google/uuid"
)

// ApplicationAccessPolicy is the lean per-Application default-role policy on
// the prod-mcp-v2 backport. The dev branch stores richer policy data with
// role-option enumeration validated against the RBAC scope-grant graph;
// this version only persists the bare fields the admin UI needs to round-
// trip. Lives in the tenant DB.
//
// PHASE3-NOTE: default_role_id is intentionally NOT validated against
// available roles for the Application here. The dev branch does this via
// listRoleOptions + the scope-grant matrix. On the backport callers can set
// any UUID as default_role_id and we'll persist it; the role
// resolution at runtime is whatever the consuming code chooses to do.
type ApplicationAccessPolicy struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID          string     `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ApplicationID     uuid.UUID  `json:"application_id" gorm:"type:uuid;not null;uniqueIndex"`
	Enabled           bool       `json:"enabled" gorm:"not null;default:false"`
	DefaultRoleID     *uuid.UUID `json:"default_role_id,omitempty" gorm:"type:uuid"`
	AssignmentTrigger string     `json:"assignment_trigger" gorm:"type:text;not null;default:'first_successful_login'"`
	AssignmentSource  string     `json:"assignment_source" gorm:"type:text;not null;default:'default_policy'"`
	CreatedAt         time.Time  `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt         time.Time  `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationAccessPolicy) TableName() string { return "application_access_policies" }
