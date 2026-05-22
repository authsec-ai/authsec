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
	// DefaultClientID and DefaultProjectID let a connection anchor the existing
	// SCIM handlers (which still expect client_id/project_id) during the
	// workspace transition. Both nullable — once handlers are workspace-only
	// these columns can be dropped.
	DefaultClientID  *uuid.UUID `json:"default_client_id,omitempty" gorm:"type:uuid"`
	DefaultProjectID *uuid.UUID `json:"default_project_id,omitempty" gorm:"type:uuid"`
	Status           string     `json:"status" gorm:"type:text;not null;default:'active'"`
	CreatedAt        time.Time  `json:"created_at" gorm:"autoCreateTime"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
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
