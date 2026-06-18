package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthClientSecret holds a bcrypt-hashed shared secret for client_secret_basic auth.
// A client may have multiple active secrets (rotation), identified by id.
// revoked_at NULL = active; non-NULL = revoked but kept for audit.
//
// Backing table: public.oauth_client_secrets.
type OAuthClientSecret struct {
	ID         uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID   uuid.UUID  `json:"client_id" gorm:"type:uuid;not null;index:idx_oauth_client_secrets_active"`
	SecretHash string     `json:"-" gorm:"type:text;not null"`
	CreatedAt  time.Time  `json:"created_at" gorm:"not null;default:now()"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" gorm:"type:timestamptz"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" gorm:"type:timestamptz"`
}

func (OAuthClientSecret) TableName() string { return "oauth_client_secrets" }

// OAuthClientJWKS holds the registered JWKS or jwks_uri for a confidential
// client using private_key_jwt auth. One row per client (UNIQUE on client_id).
//
// Backing table: public.oauth_client_jwks.
type OAuthClientJWKS struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ClientID      uuid.UUID  `json:"client_id" gorm:"type:uuid;not null;uniqueIndex:oauth_client_jwks_client_uq"`
	JWKSUri       *string    `json:"jwks_uri,omitempty" gorm:"type:text;column:jwks_uri"`
	JWKS          *string    `json:"jwks,omitempty" gorm:"type:jsonb;column:jwks"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty" gorm:"type:timestamptz;column:last_fetched_at"`
	CreatedAt     time.Time  `json:"created_at" gorm:"not null;default:now()"`
	UpdatedAt     time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

func (OAuthClientJWKS) TableName() string { return "oauth_client_jwks" }

// ClientAssertionReplay is the jti replay cache for private_key_jwt assertions.
// Primary key (client_id, jti) ensures a given assertion is accepted at most once.
//
// Backing table: public.client_assertion_replay_cache.
type ClientAssertionReplay struct {
	ClientID  string    `json:"client_id" gorm:"type:text;primaryKey"`
	JTI       string    `json:"jti" gorm:"type:text;primaryKey"`
	ExpiresAt time.Time `json:"expires_at" gorm:"type:timestamptz;not null;index:idx_client_assertion_replay_exp"`
}

func (ClientAssertionReplay) TableName() string { return "client_assertion_replay_cache" }
