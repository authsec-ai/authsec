package models

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ScopeUsageInternal = "internal"
	ScopeUsageOAuth    = "oauth"
	ScopeUsageBoth     = "both"
)

// APIScope is the canonical named-scope model shared by internal and OAuth flows.
// The table name remains "scopes"; usage distinguishes internal bundles from
// OAuth-exposed contracts.
type APIScope struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID    *uuid.UUID `json:"tenant_id" gorm:"type:uuid;uniqueIndex:idx_scopes_tenant_name;uniqueIndex:idx_scopes_tenant_id"`
	Name        string     `json:"name" gorm:"type:text;not null;uniqueIndex:idx_scopes_tenant_name"`
	Description string     `json:"description" gorm:"type:text"`
	Usage       string     `json:"usage" gorm:"type:text;not null;default:'oauth'"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`

	Permissions []RBACPermission `json:"permissions,omitempty" gorm:"many2many:scope_permissions;joinForeignKey:ScopeID;joinReferences:PermissionID"`
}

func (APIScope) TableName() string {
	return "scopes"
}

// APIScopePermission is the canonical scope->permission join.
type APIScopePermission struct {
	ScopeID      uuid.UUID `json:"scope_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
}

func (APIScopePermission) TableName() string {
	return "scope_permissions"
}

// RoleScope maps optional named scopes onto roles.
type RoleScope struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	RoleID    uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`
	ScopeID   uuid.UUID `json:"scope_id" gorm:"type:uuid;not null"`
	CreatedAt time.Time `json:"created_at"`
}

func (RoleScope) TableName() string {
	return "role_scopes"
}

type CreateAPIScopeRequest struct {
	Name                string   `json:"name" binding:"required"`
	Description         string   `json:"description"`
	Usage               string   `json:"usage,omitempty"`
	PermissionIDs       []string `json:"permission_ids,omitempty"`
	MappedPermissionIDs []string `json:"mapped_permission_ids,omitempty"`
}

type UpdateAPIScopeRequest struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Usage               string   `json:"usage,omitempty"`
	PermissionIDs       []string `json:"permission_ids,omitempty"`
	MappedPermissionIDs []string `json:"mapped_permission_ids,omitempty"`
}

func (r CreateAPIScopeRequest) EffectivePermissionIDs() []string {
	if len(r.PermissionIDs) > 0 {
		return r.PermissionIDs
	}
	return r.MappedPermissionIDs
}

func (r UpdateAPIScopeRequest) EffectivePermissionIDs() []string {
	if len(r.PermissionIDs) > 0 {
		return r.PermissionIDs
	}
	return r.MappedPermissionIDs
}

// NormalizeScopeUsage coerces user input into the supported usage values.
func NormalizeScopeUsage(value string, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ScopeUsageInternal:
		return ScopeUsageInternal
	case ScopeUsageOAuth:
		return ScopeUsageOAuth
	case ScopeUsageBoth:
		return ScopeUsageBoth
	default:
		return fallback
	}
}

type APIScopeResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Usage             string   `json:"usage"`
	PermissionsLinked int      `json:"permissions_linked"`
	PermissionIDs     []string `json:"permission_ids,omitempty"`
	PermissionStrings []string `json:"permission_strings,omitempty"`
	Resources         []string `json:"resources,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
}

type APIScopeListItem struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Usage             string `json:"usage"`
	PermissionsLinked int    `json:"permissions_linked"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}
