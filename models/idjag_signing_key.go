package models

import (
	"time"

	"github.com/google/uuid"
)

// IDJAGSigningKey is the RSA keypair AuthSec uses to sign ID-JAGs (Cross-App
// Access identity assertions). Lazily generated on first use and persisted so
// restarts don't invalidate outstanding ID-JAGs.
//
// Rotation policy: when due, mint a new row with Active=true, flip the
// previous row to Active=false, set the old row's NotAfter to ~24h in the
// future so verifiers caching the old JWKS can still validate in-flight
// ID-JAGs until they naturally expire.
type IDJAGSigningKey struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	KID           string     `gorm:"column:kid;type:text;uniqueIndex;not null"`
	Algorithm     string     `gorm:"type:text;not null;default:'RS256'"`
	PrivateKeyPEM []byte     `gorm:"column:private_key_pem;type:bytea;not null"`
	PublicKeyPEM  []byte     `gorm:"column:public_key_pem;type:bytea;not null"`
	Active        bool       `gorm:"not null;default:true"`
	NotBefore     time.Time  `gorm:"column:not_before;not null;default:CURRENT_TIMESTAMP"`
	NotAfter      *time.Time `gorm:"column:not_after"`
	CreatedAt     time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (IDJAGSigningKey) TableName() string { return "idjag_signing_keys" }
