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
	// AllowedSubjectGroups (F5): group ids that may be the on-behalf-of subject of
	// a delegated action. Empty = no subject-group restriction.
	AllowedSubjectGroups pq.StringArray `json:"allowed_subject_groups" gorm:"type:uuid[];not null;default:'{}'" swaggertype:"array,string"`
	CreatedBy            string         `json:"created_by" gorm:"not null"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

func (Connector) TableName() string { return "connectors" }

// Connection binding-type, status and auth-method enum values.
const (
	ConnectionBindingWorkspace = "workspace"
	ConnectionBindingUser      = "user"

	ConnectionStatusActive       = "active"
	ConnectionStatusExpired      = "expired"
	ConnectionStatusError        = "error"
	ConnectionStatusRevoked      = "revoked"
	ConnectionStatusDisconnected = "disconnected"

	ConnectionAuthAPIKey = "api_key"
	ConnectionAuthOAuth2 = "oauth2"
)

// ConnectorConnection is a credential binding for a connector plus its
// lifecycle state. A connector has one workspace-scope connection and N
// user-scope connections. Secret material lives in Vault at VaultPath; this row
// is metadata only. (P1, hardened: workspace_id + composite FK, UUID subject,
// version for refresh CAS, external-account metadata.)
type ConnectorConnection struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID   uuid.UUID  `json:"connector_id" gorm:"type:uuid;not null;index"`
	BindingType   string     `json:"binding_type" gorm:"not null"`               // workspace | user
	SubjectUserID *uuid.UUID `json:"subject_user_id,omitempty" gorm:"type:uuid"` // nil for workspace binding
	Status        string     `json:"status" gorm:"not null;default:'active'"`
	AuthMethod    string     `json:"auth_method" gorm:"not null"` // api_key | oauth2
	VaultPath     string     `json:"-" gorm:"not null"`           // secret location; NEVER serialized

	ScopesGranted pq.StringArray `json:"scopes_granted" gorm:"type:text[];not null;default:'{}'" swaggertype:"array,string"`

	// Non-secret external-account metadata (F2 — reconnect awareness).
	ExternalAccountID   string `json:"external_account_id,omitempty"`
	ExternalAccountName string `json:"external_account_name,omitempty"`
	ExternalOrgID       string `json:"external_org_id,omitempty"`
	ExternalOrgName     string `json:"external_org_name,omitempty"`
	ConnectedBy         string `json:"connected_by,omitempty"`

	AccessExpiresAt     *time.Time `json:"access_expires_at,omitempty"`
	RefreshExpiresAt    *time.Time `json:"refresh_expires_at,omitempty"`
	RefreshTokenPresent bool       `json:"refresh_token_present" gorm:"not null;default:false"`
	LastRefreshAt       *time.Time `json:"last_refresh_at,omitempty"`
	LastRefreshError    string     `json:"last_refresh_error,omitempty"`
	LastUsedAt          *time.Time `json:"last_used_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	Version             int        `json:"version" gorm:"not null;default:1"` // optimistic concurrency (refresh CAS)

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	// InputConstraints (F3): an optional per-assignment predicate over action
	// inputs — a JSON object mapping input field → rule, e.g.
	//   {"owner":{"equals":"acme-eng"},"repo":{"glob":"release-*"}}
	// Enforced in the broker chain AFTER input-schema validation and BEFORE the
	// provider call. Empty/absent = no input restriction. Bounds WHERE an action
	// runs, complementing the assignment (which bounds WHICH action).
	InputConstraints json.RawMessage `json:"input_constraints,omitempty" gorm:"type:jsonb"`
	CreatedBy        string          `json:"created_by,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
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

// ConnectorActionAudit is the durable per-action accountability record: who
// (SubjectID/type), on whose behalf / which agent (ActorClientID/SpiffeID),
// which token (TokenFamily/JTI), what (Connector+Action), and the outcome. One
// row per broker action attempt, allow or deny. Never holds secrets.
type ConnectorActionAudit struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ConnectorID *uuid.UUID `json:"connector_id,omitempty" gorm:"type:uuid"`
	ActionKey   string     `json:"action_key" gorm:"not null"`
	// F8 — four orthogonal outcome fields.
	AuthzOutcome   string     `json:"authz_outcome" gorm:"not null"` // allow | deny
	BrokerStatus   int        `json:"broker_status,omitempty"`
	ProviderStatus *int       `json:"provider_status,omitempty"` // nil if broker denied before the provider call
	ActionOutcome  string     `json:"action_outcome,omitempty"`  // success | provider_error | policy_deny
	DenyReason     string     `json:"deny_reason,omitempty"`
	SubjectType    string     `json:"subject_type,omitempty"`
	SubjectID      *uuid.UUID `json:"subject_id,omitempty" gorm:"type:uuid"`
	ActorClientID  string     `json:"actor_client_id,omitempty"`
	ActorSpiffeID  string     `json:"actor_spiffe_id,omitempty"`
	OwnerEmail     string     `json:"owner_email,omitempty"`
	OwnerTeam      string     `json:"owner_team,omitempty"`
	TokenFamily    string     `json:"token_family,omitempty"`
	TokenJTI       string     `json:"token_jti,omitempty"`
	LatencyMs      int64      `json:"latency_ms,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Action outcome enum values (F8).
const (
	ActionOutcomeSuccess       = "success"
	ActionOutcomeProviderError = "provider_error"
	ActionOutcomePolicyDeny    = "policy_deny"
)

func (ConnectorActionAudit) TableName() string { return "connector_action_audit" }

// ConnectorProviderApp is a workspace's own OAuth application credentials for a
// provider (AuthSec's registered app at the provider). ClientID + RedirectURI
// are non-secret; the client secret lives in Vault at VaultPath. Resolved before
// the global env-var fallback in the connect flow. (Bring-your-own OAuth app.)
type ConnectorProviderApp struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ProviderKey string    `json:"provider_key" gorm:"not null"`
	// AppKind: 'oauth2' (code-exchange, ClientID+RedirectURI, secret in Vault) or
	// 'github_app' (JWT-signed installation tokens, GitHubAppID + private-key PEM
	// in Vault, no redirect).
	AppKind     string    `json:"app_kind" gorm:"not null;default:'oauth2'"`
	ClientID    string    `json:"client_id" gorm:"not null;default:''"`
	RedirectURI string    `json:"redirect_uri" gorm:"not null;default:''"`
	GitHubAppID string    `json:"github_app_id" gorm:"not null;default:''"`
	VaultPath   string    `json:"-" gorm:"not null"` // secret location; NEVER serialized
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ConnectorProviderApp) TableName() string { return "connector_provider_apps" }

// Provider-app kinds + the github_app connection auth method.
const (
	ProviderAppKindOAuth2    = "oauth2"
	ProviderAppKindGitHubApp = "github_app"

	ConnectionAuthGitHubApp = "github_app"
)
