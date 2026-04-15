package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthScope represents a scope in the OAuth scope registry.
// Scopes are discovered from MCP server PRM (scopes_supported) or created manually by admins.
// Each scope has metadata (display_name, risk_level, icon) for the consent UI,
// and maps to internal RBAC permissions via oauth_scope_permissions.
type OAuthScope struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID         uuid.UUID  `json:"tenant_id" gorm:"type:uuid;not null;uniqueIndex:idx_oauth_scopes_unique"`
	ResourceServerID *uuid.UUID `json:"resource_server_id" gorm:"type:uuid;uniqueIndex:idx_oauth_scopes_unique"`
	ScopeString      string     `json:"scope_string" gorm:"type:text;not null;uniqueIndex:idx_oauth_scopes_unique"`
	DisplayName      string     `json:"display_name" gorm:"type:text;not null"`
	Description      string     `json:"description" gorm:"type:text"`
	Icon             string     `json:"icon" gorm:"type:text"`
	RiskLevel        string     `json:"risk_level" gorm:"type:text;not null;default:'low'"`
	ParentScopeID    *uuid.UUID `json:"parent_scope_id" gorm:"type:uuid"`
	IsAutoDiscovered bool       `json:"is_auto_discovered" gorm:"not null;default:false"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`

	// Relations
	Permissions  []RBACPermission `json:"permissions,omitempty" gorm:"many2many:oauth_scope_permissions;joinForeignKey:ScopeID;joinReferences:PermissionID"`
	ParentScope  *OAuthScope      `json:"parent_scope,omitempty" gorm:"foreignKey:ParentScopeID"`
	ChildScopes  []OAuthScope     `json:"child_scopes,omitempty" gorm:"foreignKey:ParentScopeID"`
}

func (OAuthScope) TableName() string {
	return "oauth_scopes"
}

// OAuthScopePermission is the join table between scopes and permissions.
type OAuthScopePermission struct {
	ScopeID      uuid.UUID `json:"scope_id" gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;primaryKey"`
}

func (OAuthScopePermission) TableName() string {
	return "oauth_scope_permissions"
}

// --- Request/Response DTOs ---

type CreateOAuthScopeRequest struct {
	ScopeString      string   `json:"scope_string" binding:"required"`
	DisplayName      string   `json:"display_name" binding:"required"`
	Description      string   `json:"description"`
	Icon             string   `json:"icon"`
	RiskLevel        string   `json:"risk_level"` // low, medium, high, critical
	ParentScopeID    string   `json:"parent_scope_id"`
	PermissionIDs    []string `json:"permission_ids"`
	ResourceServerID string   `json:"resource_server_id"`
}

type UpdateOAuthScopeRequest struct {
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	Icon          string   `json:"icon"`
	RiskLevel     string   `json:"risk_level"`
	ParentScopeID string   `json:"parent_scope_id"`
	PermissionIDs []string `json:"permission_ids"`
}

type OAuthScopeResponse struct {
	ID               string   `json:"id"`
	ScopeString      string   `json:"scope_string"`
	DisplayName      string   `json:"display_name"`
	Description      string   `json:"description"`
	Icon             string   `json:"icon"`
	RiskLevel        string   `json:"risk_level"`
	ParentScopeID    string   `json:"parent_scope_id,omitempty"`
	IsAutoDiscovered bool     `json:"is_auto_discovered"`
	ResourceServerID string   `json:"resource_server_id,omitempty"`
	PermissionIDs    []string `json:"permission_ids,omitempty"`
	ChildScopes      []string `json:"child_scopes,omitempty"`
	CreatedAt        string   `json:"created_at,omitempty"`
}
