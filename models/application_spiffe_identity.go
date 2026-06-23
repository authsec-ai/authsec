package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ApplicationSpiffeIdentity struct {
	ID            uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID   uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ApplicationID uuid.UUID       `json:"application_id" gorm:"type:uuid;not null;index"`
	SpiffeID      string          `json:"spiffe_id" gorm:"type:text;not null;uniqueIndex"`
	TrustDomain   string          `json:"trust_domain" gorm:"type:text;not null"`
	Selectors     json.RawMessage `json:"selectors" gorm:"type:jsonb;default:'{}'"`
	Status            string          `json:"status" gorm:"type:text;not null;default:'attestation_pending'"`
	LastAttestedAt    *time.Time      `json:"last_attested_at,omitempty" gorm:"column:last_attested_at"`
	LastTokenIssuedAt *time.Time      `json:"last_token_issued_at,omitempty" gorm:"column:last_token_issued_at"`
	LastError         *string         `json:"last_error,omitempty" gorm:"column:last_error;type:text"`
	LastErrorAt       *time.Time      `json:"last_error_at,omitempty" gorm:"column:last_error_at"`
	CreatedAt         time.Time       `json:"created_at" gorm:"autoCreateTime"`
	RevokedAt         *time.Time      `json:"revoked_at,omitempty"`
}

func (ApplicationSpiffeIdentity) TableName() string {
	return "application_spiffe_identities"
}

func (i *ApplicationSpiffeIdentity) BeforeCreate(tx *gorm.DB) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	return nil
}
