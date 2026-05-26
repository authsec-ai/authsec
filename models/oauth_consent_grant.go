package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// OAuthConsentGrant records a user's consent decision for a specific (client x RS) pair.
// When a matching non-expired, non-revoked grant exists, the consent screen is skipped
// (unless prompt=consent forces re-display).
type OAuthConsentGrant struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID         uuid.UUID      `json:"workspace_id" gorm:"type:uuid;not null"`
	UserID           uuid.UUID      `json:"user_id" gorm:"type:uuid;not null"`
	ClientID         uuid.UUID      `json:"client_id" gorm:"type:uuid;not null"`
	ResourceServerID uuid.UUID      `json:"resource_server_id" gorm:"type:uuid;not null"`
	GrantedScopes    pq.StringArray `json:"granted_scopes" gorm:"type:text[];not null"`
	ExpiresAt        time.Time      `json:"expires_at" gorm:"not null"`
	RevokedAt        *time.Time     `json:"revoked_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

func (OAuthConsentGrant) TableName() string {
	return "oauth_consent_grants"
}

// OAuthConsentGrantResponse is the API representation of a consent grant.
type OAuthConsentGrantResponse struct {
	ID               string   `json:"id"`
	WorkspaceID         string   `json:"workspace_id"`
	UserID           string   `json:"user_id"`
	ClientID         string   `json:"client_id"`
	ClientName       string   `json:"client_name,omitempty"`
	ResourceServerID string   `json:"resource_server_id"`
	ResourceName     string   `json:"resource_name,omitempty"`
	GrantedScopes    []string `json:"granted_scopes"`
	ExpiresAt        string   `json:"expires_at"`
	RevokedAt        string   `json:"revoked_at,omitempty"`
	CreatedAt        string   `json:"created_at"`
}
