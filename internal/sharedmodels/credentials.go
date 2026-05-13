package sharedmodels

import (
	"time"

	"github.com/google/uuid"
)

// WebAuthnCredential represents a simplified WebAuthn credential for backward compatibility
// Note: This is kept for legacy code support. New code should use the Credential model.
type WebAuthnCredential struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;index"`
	CredentialID string    `json:"credential_id" gorm:"uniqueIndex;not null"`
	PublicKey    string    `json:"public_key" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

// TableName returns the table name for the WebAuthnCredential model
func (WebAuthnCredential) TableName() string {
	return "webauthn_credentials"
}
