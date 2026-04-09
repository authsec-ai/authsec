package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MCPGrantBinding stores per-grant RS binding keyed by hash(refresh_token).
// When the authorization_code exchange succeeds, the Token handler hashes the
// refresh_token from Hydra's response and stores the mapping to the resource server.
// On refresh_token grants, the handler hashes the incoming refresh_token and
// looks up the exact RS binding to verify the client is still approved for that RS.
type MCPGrantBinding struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	RefreshTokenHash string    `json:"refresh_token_hash" gorm:"type:varchar(64);not null;uniqueIndex"`
	HydraClientID    string    `json:"hydra_client_id" gorm:"type:varchar(255);not null;index"`
	ResourceServerID uuid.UUID `json:"resource_server_id" gorm:"type:uuid;not null"`
	ResourceURI      string    `json:"resource_uri" gorm:"type:text;not null"`
	TenantID         string    `json:"tenant_id" gorm:"type:varchar(255);not null"`
	CreatedAt        time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt        time.Time `json:"expires_at" gorm:"not null;index"`
}

func (MCPGrantBinding) TableName() string {
	return "mcp_grant_bindings"
}

func (m *MCPGrantBinding) BeforeCreate(tx *gorm.DB) error {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	return nil
}
