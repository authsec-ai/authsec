package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

type Role struct {
	ID          uuid.UUID    `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid();uniqueIndex:idx_roles_workspace_id"`
	WorkspaceID    uuid.UUID    `json:"workspace_id" gorm:"type:uuid;not null;uniqueIndex:idx_roles_tenant_name;uniqueIndex:idx_roles_workspace_id"`
	Name        string       `json:"name" gorm:"type:text;not null;uniqueIndex:idx_roles_tenant_name"`
	Description string       `json:"description" gorm:"type:text"`
	IsSystem    bool         `json:"is_system" gorm:"default:false"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Permissions []Permission `json:"permissions,omitempty" gorm:"many2many:role_permissions;joinForeignKey:RoleID;joinReferences:PermissionID"`
}

type Group struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID    *uuid.UUID `json:"workspace_id,omitempty" gorm:"type:uuid"`
	Name        string     `json:"name" gorm:"uniqueIndex;not null"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

type TokenRequest struct {
	WorkspaceID  string  `json:"workspace_id" binding:"required"`
	ProjectID string  `json:"project_id"`
	ClientID  string  `json:"client_id"`
	SecretID  *string `json:"secret_id,omitempty"`
	EmailID   string  `json:"email_id" binding:"required"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type VerifyRequest struct {
	Token string `json:"token" binding:"required"`
}

type TokenClaims struct {
	WorkspaceID  string   `json:"workspace_id"`
	ProjectID string   `json:"project_id"`
	ClientID  string   `json:"client_id"`
	EmailID   string   `json:"email_id"`
	Scopes    []string `json:"scopes"`
	Roles     []string `json:"roles"`
	Groups    []string `json:"groups"`
	Resources []string `json:"resources"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	Issuer    string   `json:"iss"`
}

type OIDCTokenRequest struct {
	OidcToken string `json:"oidc_token" binding:"required"`
}

type OIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}
