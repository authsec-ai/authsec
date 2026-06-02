package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Identity provider type constants. Google is a flavor of OIDC distinguished
// by oidc_providers.provider_name — it is NOT a distinct provider_type.
const (
	IdentityProviderOIDC  = "oidc"
	IdentityProviderSAML  = "saml"
	IdentityProviderAD    = "ad"
	IdentityProviderEntra = "entra"
	IdentityProviderSCIM  = "scim"
)

type IdentityProvider struct {
	ID              uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID     uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ProviderType    string    `json:"provider_type" gorm:"type:text;not null;index"`
	DisplayName     string    `json:"display_name" gorm:"type:text;not null"`
	ConfigRef       string    `json:"config_ref" gorm:"type:text;not null"`
	Status          string    `json:"status" gorm:"type:text;not null;default:'configured'"`
	RedirectURI     string    `json:"redirect_uri,omitempty" gorm:"-"`
	CreatedByUserID uuid.UUID `json:"created_by_user_id" gorm:"type:uuid;not null"`
	CreatedAt       time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt       time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (IdentityProvider) TableName() string {
	return "identity_providers"
}

func (p *IdentityProvider) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

type ApplicationIdentityProviderPolicy struct {
	ID                 uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID        uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ApplicationID      uuid.UUID `json:"application_id" gorm:"type:uuid;not null;uniqueIndex:idx_app_idp_policy"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" gorm:"type:uuid;not null;uniqueIndex:idx_app_idp_policy"`
	Enabled            bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedAt          time.Time `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt          time.Time `json:"updated_at" gorm:"autoUpdateTime"`
}

func (ApplicationIdentityProviderPolicy) TableName() string {
	return "application_identity_provider_policies"
}

func (p *ApplicationIdentityProviderPolicy) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
