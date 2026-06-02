package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthRequestContext is the PKCE / state / resource binding captured at
// /oauth/v2/authorize and consumed at /oauth/v2/token. consumed=true after
// token exchange to prevent replay. Lives in the tenant DB.
type AuthRequestContext struct {
	ID                  uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ContextID           string     `json:"context_id" gorm:"type:text;uniqueIndex;not null"`
	TenantID            string     `json:"tenant_id" gorm:"type:varchar(255);not null"`
	ClientID            string     `json:"client_id" gorm:"type:varchar(512);not null;index"`
	ResourceURI         *string    `json:"resource_uri,omitempty" gorm:"type:text"`
	ResourceServerID    *uuid.UUID `json:"resource_server_id,omitempty" gorm:"type:uuid"`
	RedirectURI         string     `json:"redirect_uri" gorm:"type:text;not null"`
	Scope               *string    `json:"scope,omitempty" gorm:"type:text"`
	State               *string    `json:"state,omitempty" gorm:"type:text"`
	CodeChallenge       *string    `json:"code_challenge,omitempty" gorm:"type:text"`
	CodeChallengeMethod *string    `json:"code_challenge_method,omitempty" gorm:"type:varchar(20)"`
	Nonce               *string    `json:"nonce,omitempty" gorm:"type:text"`
	Consumed            bool       `json:"consumed" gorm:"not null;default:false"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	ExpiresAt           time.Time  `json:"expires_at" gorm:"not null;index"`
	CreatedAt           time.Time  `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (AuthRequestContext) TableName() string { return "auth_request_context" }
