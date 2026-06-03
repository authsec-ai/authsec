package models

import (
	"time"

	"github.com/google/uuid"
)

// Identity provider types.
const (
	IdentityProviderOIDC  = "oidc"
	IdentityProviderSAML  = "saml"
	IdentityProviderAD    = "ad"
	IdentityProviderEntra = "entra"
	IdentityProviderSCIM  = "scim"
)

// IdentityProvider is the tenant's IDP registry row. ConfigRef stringifies the
// UUID of the underlying protocol-specific config row (oidc_providers.id,
// saml_providers.id, sync_configurations.id). Lives in the tenant DB.
type IdentityProvider struct {
	ID              uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID        string    `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ProviderType    string    `json:"provider_type" gorm:"type:text;not null"`
	DisplayName     string    `json:"display_name" gorm:"type:text;not null"`
	ConfigRef       string    `json:"config_ref" gorm:"type:text;not null"`
	Status          string    `json:"status" gorm:"type:text;not null;default:'configured'"`
	CreatedByUserID uuid.UUID `json:"created_by_user_id" gorm:"type:uuid;not null"`
	CreatedAt       time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt       time.Time `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (IdentityProvider) TableName() string { return "identity_providers" }

// ApplicationIdentityProviderPolicy whitelists which IDPs an Application
// (resource_servers row) accepts. Default-allow when no rows exist for an
// application; whitelist mode when any rows exist.
type ApplicationIdentityProviderPolicy struct {
	ID                 uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID           string    `json:"tenant_id" gorm:"type:varchar(255);not null;index"`
	ApplicationID      uuid.UUID `json:"application_id" gorm:"type:uuid;not null"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" gorm:"type:uuid;not null"`
	Enabled            bool      `json:"enabled" gorm:"not null;default:true"`
	CreatedAt          time.Time `json:"created_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt          time.Time `json:"updated_at" gorm:"not null;default:CURRENT_TIMESTAMP"`
}

func (ApplicationIdentityProviderPolicy) TableName() string {
	return "application_identity_provider_policies"
}
