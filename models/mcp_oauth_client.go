package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// MCPOAuthClient is the global OAuth client registry for the standards-compliant
// MCP OAuth flow (DCR / CIMD / PreReg). Mirrors Hydra; sync_status tracks
// convergence. Lives in master DB.
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
	SyncStatus              string         `json:"sync_status" gorm:"type:text;not null;default:'active'"`
	SyncLastError           *string        `json:"-" gorm:"type:text"`
	SyncLastErrorAt         *time.Time     `json:"-" gorm:"type:timestamptz"`
	CreatedAt               time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt               time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt               gorm.DeletedAt `json:"-" gorm:"index"`
}

func (MCPOAuthClient) TableName() string { return "mcp_oauth_clients" }
