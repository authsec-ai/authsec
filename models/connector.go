package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ConnectorProvider is an entry in the fixed integration catalog (HubSpot,
// Mixpanel, Segment, …). Seeded in migrations; not created by tenants.
type ConnectorProvider struct {
	Key           string          `json:"key" gorm:"primaryKey"`
	DisplayName   string          `json:"display_name" gorm:"not null"`
	ComponentType string          `json:"component_type" gorm:"not null;default:''"` // "server" | "browser" | ""
	ConfigSchema  json.RawMessage `json:"config_schema" gorm:"type:jsonb;not null;default:'{}'"`
	SecretKeys    pq.StringArray  `json:"secret_keys" gorm:"type:text[];not null;default:'{}'" swaggertype:"array,string"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (ConnectorProvider) TableName() string { return "connector_providers" }

// Connector is a workspace-scoped configured instance of a catalog provider.
// Non-secret settings live in Config; the event subscriptions/field-mappings
// live verbatim in Subscriptions; secrets live in Vault at VaultPath.
type Connector struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ProviderKey     string          `json:"provider_key" gorm:"not null;index"`
	Name            string          `json:"name" gorm:"not null"`
	Enabled         bool            `json:"enabled" gorm:"not null;default:true"`
	Config          json.RawMessage `json:"config" gorm:"type:jsonb;not null;default:'{}'"`
	Subscriptions   json.RawMessage `json:"subscriptions" gorm:"type:jsonb;not null;default:'[]'"`
	VaultPath       string          `json:"vault_path,omitempty"`
	AgentAccessible bool            `json:"agent_accessible" gorm:"not null;default:false"`
	CreatedBy       string          `json:"created_by" gorm:"not null"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func (Connector) TableName() string { return "connectors" }
