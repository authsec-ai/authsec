package hydramodels

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
)

// Re-export shared model types used by hydra handlers
type User = sharedmodels.User
type Client = sharedmodels.Client
type Tenant = sharedmodels.Tenant
type Project = sharedmodels.Project
type Role = sharedmodels.Role
type Group = sharedmodels.Group

// Hydra-specific models
type HydraLoginRequest struct {
	Challenge string `json:"challenge"`
	Skip      bool   `json:"skip"` // True if Hydra has an existing authenticated session for this subject
	Client    struct {
		ClientID string `json:"client_id"`
	} `json:"client"`
	Subject    string `json:"subject"`
	RequestURL string `json:"request_url"` // Hydra login request URL, used to recover request_uri for PAR-based bridge binding
}

type HydraAcceptLoginRequest struct {
	Subject     string                 `json:"subject"`
	Remember    bool                   `json:"remember"`
	RememberFor int                    `json:"remember_for"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

type HydraAcceptLoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

type HydraConsentRequest struct {
	Challenge string `json:"challenge"`
	Client    struct {
		ClientID string `json:"client_id"`
	} `json:"client"`
	RequestedScope               []string               `json:"requested_scope"`
	RequestedAccessTokenAudience []string               `json:"requested_access_token_audience"`
	Subject                      string                 `json:"subject"`
	LoginChallenge               string                 `json:"login_challenge"`
	LoginSessionID               string                 `json:"login_session_id"`
	Context                      map[string]interface{} `json:"context,omitempty"`
}

type HydraAcceptConsentRequest struct {
	GrantScope               []string               `json:"grant_scope"`
	GrantAccessTokenAudience []string               `json:"grant_access_token_audience"`
	Remember                 bool                   `json:"remember"`
	RememberFor              int                    `json:"remember_for"`
	Session                  map[string]interface{} `json:"session,omitempty"`
}

type HydraAcceptConsentResponse struct {
	RedirectTo string `json:"redirect_to"`
}

type HydraClient struct {
	ClientID     string                 `json:"client_id"`
	ClientName   string                 `json:"client_name"`
	RedirectURIs []string               `json:"redirect_uris"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type OIDCProvider struct {
	ProviderName string                 `json:"provider_name"`
	DisplayName  string                 `json:"display_name"`
	IsActive     bool                   `json:"is_active"`
	SortOrder    int                    `json:"sort_order"`
	CallbackURL  string                 `json:"callback_url"`
	Config       map[string]interface{} `json:"config"`
}

type LoginPageDataResponse struct {
	// WorkspaceID is the canonical scope, resolved server-side from the Hydra
	// login_challenge via auth_request_contexts. The UI carries this forward
	// into login/status + register calls — it does NOT use client_id for that.
	WorkspaceID       string         `json:"workspace_id"`
	ClientID          string         `json:"client_id"`
	Success           bool           `json:"success"`
	LoginChallenge    string         `json:"login_challenge"`
	TenantName        string         `json:"tenant_name"`
	ClientName        string         `json:"client_name"`
	ClientType        string         `json:"client_type,omitempty"`
	RedirectURIs      []string       `json:"redirect_uris,omitempty"`
	Providers         []OIDCProvider `json:"providers"`
	BaseURL           string         `json:"base_url"`
	LocalLoginEnabled bool           `json:"local_login_enabled"`
	Error             string         `json:"error,omitempty"`
}

type AuthInitiateResponse struct {
	Success  bool   `json:"success"`
	AuthURL  string `json:"auth_url"`
	State    string `json:"state"`
	Provider string `json:"provider"`
	Error    string `json:"error,omitempty"`
}

type CallbackValidationResponse struct {
	Success    bool   `json:"success"`
	RedirectTo string `json:"redirect_to"`
	UserInfo   *User  `json:"user_info,omitempty"`
	Error      string `json:"error,omitempty"`
}

type TokenExchangeRequest struct {
	LoginChallenge string `json:"login_challenge"`
	Code           string `json:"code" binding:"required"`
	State          string `json:"state" binding:"required"`
	RedirectURI    string `json:"redirect_uri" binding:"required"`
	CodeVerifier   string `json:"code_verifier,omitempty"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in"`
}

type OIDCTokenRequest struct {
	OidcToken string `json:"oidc_token" binding:"required"`
}

// SAML models

// SAMLProvider is the underlying config row referenced by an identity_providers
// row with provider_type='saml'. Scoped by workspace (workspace_id == workspace_id
// during the rollout). Per-Application restriction is opt-in via
// application_identity_provider_policies — not via a column here.
type SAMLProvider struct {
	ID               uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	WorkspaceID         uuid.UUID      `gorm:"type:uuid;not null;index:idx_saml_provider_unique" json:"workspace_id"`
	ProviderName     string         `gorm:"type:varchar(255);not null;index:idx_saml_provider_unique;uniqueIndex:idx_saml_provider_unique" json:"provider_name"`
	DisplayName      string         `gorm:"type:varchar(255);not null" json:"display_name"`
	EntityID         string         `gorm:"type:varchar(500);not null" json:"entity_id"`
	SSOURL           string         `gorm:"type:varchar(500);not null" json:"sso_url"`
	SLOURL           string         `gorm:"type:varchar(500)" json:"slo_url"`
	Certificate      string         `gorm:"type:text;not null" json:"certificate"`
	MetadataURL      string         `gorm:"type:varchar(500)" json:"metadata_url"`
	NameIDFormat     string         `gorm:"type:varchar(255);default:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'" json:"name_id_format"`
	AttributeMapping datatypes.JSON `gorm:"type:jsonb" json:"attribute_mapping"`
	IsActive              bool           `gorm:"default:true" json:"is_active"`
	SortOrder             int            `gorm:"default:0" json:"sort_order"`
	SPEntityID            string         `gorm:"type:text" json:"sp_entity_id"`
	SPACSURL              string         `gorm:"type:text;column:sp_acs_url" json:"sp_acs_url"`
	WantAssertionsSigned  bool           `gorm:"default:true" json:"want_assertions_signed"`
	CreatedAt             time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt             time.Time      `gorm:"default:CURRENT_TIMESTAMP" json:"updated_at"`
}

func (SAMLProvider) TableName() string { return "saml_providers" }

func (s *SAMLProvider) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.ProviderName = strings.ToLower(strings.TrimSpace(s.ProviderName))
	return nil
}

func (s *SAMLProvider) BeforeUpdate(tx *gorm.DB) error {
	s.ProviderName = strings.ToLower(strings.TrimSpace(s.ProviderName))
	return nil
}

type SAMLSPCertificate struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	WorkspaceID    uuid.UUID `gorm:"type:uuid;not null;unique;index" json:"workspace_id"`
	Certificate string    `gorm:"type:text;not null" json:"certificate"`
	PrivateKey  string    `gorm:"type:text;not null" json:"private_key"`
	CreatedAt   time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (SAMLSPCertificate) TableName() string { return "saml_sp_certificates" }

func (s *SAMLSPCertificate) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

type SAMLRequest struct {
	ID             string    `gorm:"type:text;primary_key" json:"id"`
	LoginChallenge string    `gorm:"type:text;not null;index" json:"login_challenge"`
	WorkspaceID    uuid.UUID `gorm:"type:uuid;not null" json:"workspace_id"`
	ProviderName   string    `gorm:"type:text;not null" json:"provider_name"`
	RelayState     string    `gorm:"type:text" json:"relay_state"`
	CreatedAt      time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (SAMLRequest) TableName() string { return "saml_requests" }

type SAMLInitiateResponse struct {
	Success     bool   `json:"success"`
	SSOURL      string `json:"sso_url"`
	SAMLRequest string `json:"saml_request"`
	RelayState  string `json:"relay_state"`
	Provider    string `json:"provider"`
	Error       string `json:"error,omitempty"`
}

type SAMLCallbackRequest struct {
	SAMLResponse string `form:"SAMLResponse" json:"saml_response" binding:"required"`
	RelayState   string `form:"RelayState" json:"relay_state"`
}

type SAMLMetadataResponse struct {
	Success  bool   `json:"success"`
	Metadata string `json:"metadata"`
	Error    string `json:"error,omitempty"`
}

type SAMLProviderConfig struct {
	ProviderName     string                 `json:"provider_name" binding:"required"`
	DisplayName      string                 `json:"display_name" binding:"required"`
	EntityID         string                 `json:"entity_id" binding:"required"`
	SSOURL           string                 `json:"sso_url" binding:"required"`
	SLOURL           string                 `json:"slo_url"`
	Certificate      string                 `json:"certificate" binding:"required"`
	MetadataURL      string                 `json:"metadata_url"`
	NameIDFormat     string                 `json:"name_id_format"`
	AttributeMapping map[string]interface{} `json:"attribute_mapping"`
	IsActive         bool                   `json:"is_active"`
	SortOrder        int                    `json:"sort_order"`
}

type Provider struct {
	ProviderName string                 `json:"provider_name"`
	DisplayName  string                 `json:"display_name"`
	Type         string                 `json:"type"`
	IsActive     bool                   `json:"is_active"`
	SortOrder    int                    `json:"sort_order"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

type SAMLAssertion struct {
	NameID       string                 `json:"name_id"`
	Email        string                 `json:"email"`
	FirstName    string                 `json:"first_name"`
	LastName     string                 `json:"last_name"`
	Attributes   map[string]interface{} `json:"attributes"`
	SessionIndex string                 `json:"session_index"`
}

type SAMLCallbackState struct {
	ID             string    `gorm:"type:text;primary_key" json:"id"`
	RedirectTo     string    `gorm:"type:text;not null" json:"redirect_to"`
	UserEmail      string    `gorm:"type:varchar(255)" json:"user_email"`
	UserName       string    `gorm:"type:varchar(255)" json:"user_name"`
	ProviderName   string    `gorm:"type:varchar(255)" json:"provider_name"`
	WorkspaceID       uuid.UUID `gorm:"type:uuid" json:"workspace_id"`
	LoginChallenge string    `gorm:"type:text" json:"login_challenge"`
	CreatedAt      time.Time `gorm:"default:CURRENT_TIMESTAMP" json:"created_at"`
	ExpiresAt      time.Time `gorm:"not null" json:"expires_at"`
}

func (SAMLCallbackState) TableName() string { return "saml_callback_states" }
