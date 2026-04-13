package models

import "time"

// PKCEVerifier stores PKCE code verifiers in the database for the browser bridge.
// Keyed by state or login_challenge. TTL ~8 minutes, single-use.
type PKCEVerifier struct {
	Key       string    `json:"key" gorm:"type:varchar(512);primary_key"`
	Verifier  string    `json:"-" gorm:"type:text;not null"`
	ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
}

func (PKCEVerifier) TableName() string {
	return "pkce_verifiers"
}
