package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// OAuthConsentGrant records which user granted which scopes to which
// Application. Used to skip consent on subsequent authorizations and to power
// self-service consent management. Lives in the tenant DB.
type OAuthConsentGrant struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID         string         `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	UserID           uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	ClientID         string         `json:"client_id" gorm:"type:varchar(512);not null"`
	ResourceServerID *uuid.UUID     `json:"resource_server_id,omitempty" gorm:"type:uuid"`
	GrantedScopes    pq.StringArray `json:"granted_scopes" gorm:"type:text[];not null;default:'{}'"`
	Revoked          bool           `json:"revoked" gorm:"not null;default:false;index"`
	RevokedAt        *time.Time     `json:"revoked_at,omitempty"`
	CreatedAt        time.Time      `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt        time.Time      `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (OAuthConsentGrant) TableName() string { return "oauth_consent_grants" }
