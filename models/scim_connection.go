package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SCIMConnection struct {
	ID                 uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID        uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	IdentityProviderID *uuid.UUID `json:"identity_provider_id,omitempty" gorm:"type:uuid;index"`
	TokenHash          string     `json:"-" gorm:"type:text;not null"`
	Status             string     `json:"status" gorm:"type:text;not null;default:'active'"`
	CreatedAt          time.Time  `json:"created_at" gorm:"autoCreateTime"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

func (SCIMConnection) TableName() string {
	return "scim_connections"
}

func (c *SCIMConnection) BeforeCreate(tx *gorm.DB) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	return nil
}
