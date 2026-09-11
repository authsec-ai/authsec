package models

import (
	"time"

	"github.com/google/uuid"
)

// AzureAppConfig is a workspace's own Entra App Registration.
//
// The client secret is NOT a field here and never will be. AuthRef holds the
// Vault path it lives at, so the value never crosses Postgres, never lands in a
// backup, and cannot be returned by an endpoint that forgot to strip it.
//
// Resolution order in the onboarding flow: this row for the workspace first,
// else the deployment-wide AZURE_* environment variables. A deployment that
// configures neither behaves exactly as it did before this table existed.
type AzureAppConfig struct {
	ID          uuid.UUID `json:"id"           gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;uniqueIndex"`

	// Public by design: the client id appears in every authorize URL.
	ClientID string `json:"client_id" gorm:"column:client_id;not null"`

	// The directory the registration was created in. An application object
	// exists only there; every other tenant holds a service principal instead.
	HomeTenant string `json:"home_tenant" gorm:"column:home_tenant;not null"`

	// Must match a redirect URI registered on the application exactly.
	RedirectURI string `json:"redirect_uri" gorm:"column:redirect_uri;not null"`

	// Vault path, not a secret. json:"-" so it cannot leak through a handler
	// that serialises the struct wholesale -- the same guard
	// ConnectorProviderApp.VaultPath uses.
	AuthRef string `json:"-" gorm:"column:auth_ref;not null"`

	CreatedBy string     `json:"created_by,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty" gorm:"column:checked_at;type:timestamptz"`

	CreatedAt time.Time `json:"created_at" gorm:"type:timestamptz;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"type:timestamptz;autoUpdateTime"`
}

func (AzureAppConfig) TableName() string { return "azure_app_config" }
