package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ConnectorProvider is an entry in the curated integration catalog (Slack,
// GitHub, Google, HubSpot, Notion, Jira). Seeded in migrations; all connect via
// OAuth 2.0. Not created by workspaces.
type ConnectorProvider struct {
	Key           string          `json:"key" gorm:"primaryKey"`
	DisplayName   string          `json:"display_name" gorm:"not null"`
	ComponentType string          `json:"component_type" gorm:"not null;default:''"`
	ConfigSchema  json.RawMessage `json:"config_schema" gorm:"type:jsonb;not null;default:'{}'"`
	SecretKeys    pq.StringArray  `json:"secret_keys" gorm:"type:text[];not null;default:'{}'" swaggertype:"array,string"`

	// Credential + OAuth metadata (connect-once flow).
	// NOTE: explicit column names are required — GORM's snake_case strategy maps
	// `OAuthAuthorizeURL` to `o_auth_authorize_url`, which does NOT match the
	// migration's `oauth_authorize_url`, so these read back empty without the tag.
	SupportedAuthMethods pq.StringArray `json:"supported_auth_methods" gorm:"column:supported_auth_methods;type:text[];not null;default:'{oauth2}'" swaggertype:"array,string"`
	OAuthAuthorizeURL    string         `json:"oauth_authorize_url" gorm:"column:oauth_authorize_url;not null;default:''"`
	OAuthTokenURL        string         `json:"oauth_token_url" gorm:"column:oauth_token_url;not null;default:''"`
	OAuthScopesSupported pq.StringArray `json:"oauth_scopes_supported" gorm:"column:oauth_scopes_supported;type:text[];not null;default:'{}'" swaggertype:"array,string"`
	OAuthDefaultScopes   pq.StringArray `json:"oauth_default_scopes" gorm:"column:oauth_default_scopes;type:text[];not null;default:'{}'" swaggertype:"array,string"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	VaultPath       string          `json:"-"` // secret location; NEVER serialized to any caller
	AgentAccessible bool            `json:"agent_accessible" gorm:"not null;default:false"`
	CreatedBy       string          `json:"created_by" gorm:"not null"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func (Connector) TableName() string { return "connectors" }

// Connection scope, status and auth-type enum values.
const (
	ConnectionScopeWorkspace = "workspace"
	ConnectionScopeUser      = "user"

	ConnectionStatusActive  = "active"
	ConnectionStatusExpired = "expired"
	ConnectionStatusError   = "error"
	ConnectionStatusRevoked = "revoked"

	ConnectionAuthAPIKey = "api_key"
	ConnectionAuthOAuth2 = "oauth2"
)

// ConnectorConnection is a credential binding for a connector plus its
// lifecycle state. A connector has one workspace-scope connection and N
// user-scope connections. Secret material lives in Vault at VaultPath; this row
// is metadata only. (P1.)
type ConnectorConnection struct {
	ID                  uuid.UUID      `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ConnectorID         uuid.UUID      `json:"connector_id" gorm:"type:uuid;not null;index"`
	Scope               string         `json:"scope" gorm:"not null"`                   // workspace | user
	SubjectUserID       *string        `json:"subject_user_id,omitempty"`               // nil for workspace scope
	Status              string         `json:"status" gorm:"not null;default:'active'"` // active|expired|error|revoked
	AuthType            string         `json:"auth_type" gorm:"not null"`               // api_key | oauth2
	VaultPath           string         `json:"-" gorm:"not null"`                       // secret location; NEVER serialized
	ScopesGranted       pq.StringArray `json:"scopes_granted" gorm:"type:text[];not null;default:'{}'" swaggertype:"array,string"`
	AccessExpiresAt     *time.Time     `json:"access_expires_at,omitempty"`
	RefreshTokenPresent bool           `json:"refresh_token_present" gorm:"not null;default:false"`
	LastRefreshAt       *time.Time     `json:"last_refresh_at,omitempty"`
	LastRefreshError    string         `json:"last_refresh_error,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

func (ConnectorConnection) TableName() string { return "connector_connections" }

// ConnectorAssignment grants an OAuth client (agent) permission to use a
// connector — and optionally a specific action — on the broker data plane.
// ActionKey nil means all actions on the connector. (P0.)
type ConnectorAssignment struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	ClientID    string    `json:"client_id" gorm:"not null;index"`
	ActionKey   *string   `json:"action_key,omitempty"` // nil => all actions
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (ConnectorAssignment) TableName() string { return "connector_assignments" }

// ConnectorAction is a typed, invocable unit defined at the provider level
// (e.g. slack.postMessage). AdapterKey selects the provider adapter that
// implements it; HTTPMethod is adapter-fixed (never caller-supplied). The agent
// fills InputSchema; RequiredScopes are the provider OAuth scopes the action
// needs. (P2 — the only thing an agent can invoke.)
type ConnectorAction struct {
	ID             uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	ProviderKey    string          `json:"provider_key" gorm:"not null;index"`
	ActionKey      string          `json:"action_key" gorm:"not null"`
	DisplayName    string          `json:"display_name" gorm:"not null;default:''"`
	AdapterKey     string          `json:"adapter_key" gorm:"not null"`
	HTTPMethod     string          `json:"http_method" gorm:"not null"`
	InputSchema    json.RawMessage `json:"input_schema" gorm:"type:jsonb;not null;default:'{}'"`
	OutputSchema   json.RawMessage `json:"output_schema" gorm:"type:jsonb;not null;default:'{}'"`
	RequiredScopes pq.StringArray  `json:"required_scopes" gorm:"type:text[];not null;default:'{}'" swaggertype:"array,string"`
	CreatedAt      time.Time       `json:"created_at"`
}

func (ConnectorAction) TableName() string { return "connector_actions" }

// ConnectorOAuthState is short-lived CSRF/PKCE state for the connect-once OAuth
// flow: created at oauth/start, consumed once at oauth/callback. (P3.)
type ConnectorOAuthState struct {
	State         string    `json:"state" gorm:"primaryKey"`
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID   uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`
	ProviderKey   string    `json:"provider_key" gorm:"not null"`
	BindingType   string    `json:"binding_type" gorm:"not null;default:'workspace'"`
	SubjectUserID *string   `json:"subject_user_id,omitempty"`
	CodeVerifier  string    `json:"-" gorm:"not null"`
	RedirectAfter string    `json:"redirect_after,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	ExpiresAt     time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt     time.Time `json:"created_at"`
}

func (ConnectorOAuthState) TableName() string { return "connector_oauth_states" }
