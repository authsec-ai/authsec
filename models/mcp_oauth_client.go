package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// MCPOAuthClient represents an OAuth 2.1 client in the MCP plane.
// These are MCP clients (Codex, Claude, Cursor, Inspector) — NOT MCP servers.
// Clients register via DCR, CIMD, or are pre-registered by an admin.
// This table is global (no workspace_id) — clients can access any RS via the join table.
type MCPOAuthClient struct {
	ID                      uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ClientID                string         `json:"client_id" gorm:"type:varchar(512);uniqueIndex;not null"`
	HydraClientID           string         `json:"-" gorm:"type:varchar(255);uniqueIndex;not null"`
	ClientName              string         `json:"client_name" gorm:"type:varchar(255)"`
	RedirectURIs            pq.StringArray `json:"redirect_uris" gorm:"type:text[];not null;default:'{}'"`
	GrantTypes              pq.StringArray `json:"grant_types" gorm:"type:text[];not null;default:'{authorization_code}'"`
	ResponseTypes           pq.StringArray `json:"response_types" gorm:"type:text[];not null;default:'{code}'"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method" gorm:"type:varchar(50);default:'none'"`
	Scope                   string         `json:"scope,omitempty" gorm:"type:text"`
	RegistrationType        string         `json:"registration_type" gorm:"type:varchar(20);not null;default:'dcr'"`
	CIMDUrl                 string         `json:"-" gorm:"type:text;column:cimd_url"`
	CIMDCachedAt            *time.Time     `json:"-" gorm:"column:cimd_cached_at"`
	PendingRedirectURIs     pq.StringArray `json:"-" gorm:"type:text[];default:'{}'"`
	RedirectReviewPending   bool           `json:"-" gorm:"default:false"`
	PostLogoutRedirectURIs  pq.StringArray `json:"post_logout_redirect_uris,omitempty" gorm:"type:text[];default:'{}'"`
	SupportsRefreshToken    bool           `json:"supports_refresh_token" gorm:"default:false"`
	IsConfidential          bool           `json:"is_confidential" gorm:"default:false"`
	// SyncStatus tracks Hydra synchronisation: active | sync_error | pending_delete.
	// The reconciler service walks non-'active' rows and re-attempts the Hydra
	// side so we never strand a half-created/half-deleted client.
	SyncStatus      string         `json:"sync_status" gorm:"type:text;not null;default:'active'"`
	SyncLastError   *string        `json:"-" gorm:"type:text"`
	SyncLastErrorAt *time.Time     `json:"-" gorm:"type:timestamptz"`
	// Client classification + software identity.
	ClientKind        string         `json:"client_kind" gorm:"type:varchar(32);not null;default:'human_app'"`
	SoftwareID        *string        `json:"software_id,omitempty" gorm:"type:varchar(255)"`
	SoftwareVersion   *string        `json:"software_version,omitempty" gorm:"type:varchar(64)"`
	LastTokenIssuedAt              *time.Time     `json:"last_token_issued_at,omitempty" gorm:"column:last_token_issued_at"`
	Tags                           pq.StringArray `json:"tags" gorm:"type:text[];not null;default:'{}'"`
	RegistrationAccessTokenHash    *string        `json:"-" gorm:"type:varchar(64);column:registration_access_token_hash"`
	CreatedAt time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
}

// MCPOAuthClient sync status constants.
const (
	MCPClientSyncActive        = "active"
	MCPClientSyncError         = "sync_error"
	MCPClientSyncPendingDelete = "pending_delete"
)

func (MCPOAuthClient) TableName() string {
	return "mcp_oauth_clients"
}
