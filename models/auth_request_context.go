package models

import (
	"time"

	"github.com/google/uuid"
)

// AuthRequestContext is the per-authorize-request state row that bridges
// /oauth/v2/authorize, the Hydra login + consent dance, and /oauth/v2/token.
//
// Lifecycle:
//
//  1. /authorize INSERTs the row with the client + resource + PKCE +
//     scope captured from the request. context_id is the server-generated
//     binding key, embedded as authsec_ctx in the redirect URL to Hydra.
//  2. /login/page-data sets login_challenge after Hydra emits one.
//  3. Login completion (custom or federated) sets user_id + auth_time.
//  4. /consent sets consent_challenge and, on accept, consent_completed=true.
//  5. /token reads the row by context_id (extracted from session claims),
//     validates consent_completed=true + !consumed, then sets consumed=true.
//
// consent_completed is the fail-closed gate: if it's false at token-exchange
// time, the token is revoked and the dance fails. Lives in the tenant DB.
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
	// Hydra-side challenge tokens — set during the dance, used to look the
	// row up by challenge when Hydra POSTs back to us.
	LoginChallenge   *string `json:"-" gorm:"type:text"`
	ConsentChallenge *string `json:"-" gorm:"type:text"`
	// User identity captured during login completion. user_id is the
	// AuthSec users.id; auth_time is the moment login completed.
	UserID   *uuid.UUID `json:"user_id,omitempty" gorm:"type:uuid"`
	AuthTime *time.Time `json:"auth_time,omitempty"`
	// Consent gate. Token exchange fails closed when false.
	ConsentCompleted bool       `json:"consent_completed" gorm:"not null;default:false"`
	Consumed         bool       `json:"consumed" gorm:"not null;default:false"`
	ConsumedAt       *time.Time `json:"consumed_at,omitempty"`
	ExpiresAt        time.Time  `json:"expires_at" gorm:"not null;index"`
	CreatedAt        time.Time  `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (AuthRequestContext) TableName() string { return "auth_request_context" }
