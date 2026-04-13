package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// MCPOAuthClient represents an OAuth 2.1 client in the MCP plane.
// These are MCP clients (Codex, Claude, Cursor, Inspector) — NOT MCP servers.
// Clients register via DCR, CIMD, or are pre-registered by an admin.
// This table is global (no tenant_id) — clients can access any RS via the join table.
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
	CreatedAt               time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt               time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt               gorm.DeletedAt `json:"-" gorm:"index"`
}

func (MCPOAuthClient) TableName() string {
	return "mcp_oauth_clients"
}
