package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// OIDCService handles OIDC provider interactions
type OIDCService struct {
	providerRepo  *database.OIDCProviderRepository
	stateRepo     *database.OIDCStateRepository
	identityRepo  *database.OIDCUserIdentityRepository
	httpClient    *http.Client
	requestHost   string // Store current request host for dynamic callbacks
	requestOrigin string // Store origin domain for post-auth redirect
}

// NewOIDCService creates a new OIDC service
func NewOIDCService(db *database.DBConnection) *OIDCService {
	return &OIDCService{
		providerRepo: database.NewOIDCProviderRepository(db),
		stateRepo:    database.NewOIDCStateRepository(db),
		identityRepo: database.NewOIDCUserIdentityRepository(db),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetActiveProviders returns global/platform OIDC providers for the generic
// admin login screen. Workspace-owned providers are loaded with
// GetActiveProvidersForWorkspace after the workspace/domain is known.
func (s *OIDCService) GetActiveProviders() ([]models.OIDCProviderPublic, error) {
	providers, err := s.providerRepo.GetActiveProviders()
	if err != nil {
		return nil, err
	}

	return publicOIDCProviders(providers), nil
}

// GetActiveProvidersForWorkspace returns only providers configured for the
// resolved workspace through the canonical identity_providers table.
func (s *OIDCService) GetActiveProvidersForWorkspace(workspaceID uuid.UUID) ([]models.OIDCProviderPublic, error) {
	var providers []models.OIDCProvider
	err := config.DB.
		Table("identity_providers ip").
		Select("op.*").
		Joins("JOIN oidc_providers op ON op.id = ip.oidc_provider_id").
		Where("ip.workspace_id = ?", workspaceID).
		Where("ip.provider_type = ?", models.IdentityProviderOIDC).
		Where("ip.status <> ?", "disabled").
		Where("op.is_active = ?", true).
		Order("op.display_name ASC").
		Find(&providers).Error
	if err != nil {
		return nil, fmt.Errorf("list workspace OIDC providers: %w", err)
	}

	return publicOIDCProviders(providers), nil
}

func publicOIDCProviders(providers []models.OIDCProvider) []models.OIDCProviderPublic {
	publicProviders := make([]models.OIDCProviderPublic, 0, len(providers))
	for _, p := range providers {
		publicProviders = append(publicProviders, models.OIDCProviderPublic{
			ProviderName: p.ProviderName,
			DisplayName:  p.DisplayName,
			IconURL:      p.IconURL,
		})
	}

	return publicProviders
}

// InitiateOIDCFlow starts the OIDC authentication flow.
//
// Workspace gate (v4): when workspaceID is set, the workspace must have an
// identity_providers row with provider_type='oidc', status != 'disabled',
// referencing an oidc_providers row with the requested provider_name. When
// input.ApplicationID is set AND the Application has any
// application_identity_provider_policies rows, the IDP must be in the enabled
// set (default-allow when no policies exist).
func (s *OIDCService) InitiateOIDCFlow(input *models.OIDCInitiateInput, action string, workspaceIDPtr *uuid.UUID) (*models.OIDCInitiateResponse, error) {
	var provider *models.OIDCProvider
	var signedState string
	var err error

	if workspaceIDPtr != nil {
		provider, err = s.resolveEnabledProvider(*workspaceIDPtr, input.Provider, input.ApplicationID)
		if err != nil {
			return nil, err
		}

		// Mint a v4 signed state binding the workspace (and Application when known).
		// Persisted alongside the random state token so the callback can verify the
		// workspace context out-of-band.
		signedState, _, err = MintSignedState(*workspaceIDPtr, input.ApplicationID)
		if err != nil {
			return nil, fmt.Errorf("failed to mint signed OIDC state: %w", err)
		}
	} else {
		provider, err = s.providerRepo.GetProviderByName(input.Provider)
		if err != nil {
			return nil, fmt.Errorf("global provider %q not configured", input.Provider)
		}
		if !provider.IsActive {
			return nil, fmt.Errorf("global provider %q is inactive", input.Provider)
		}
	}

	// Generate state token (for CSRF protection and tenant context)
	stateToken, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := generateSecureToken(64)
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store state in database (expires in 30 minutes)
	state := &models.OIDCState{
		StateToken:     stateToken,
		WorkspaceID:    workspaceIDPtr,
		ApplicationID:  input.ApplicationID,
		SignedState:    signedState,
		TenantDomain:   input.TenantDomain,
		OriginDomain:   s.requestOrigin, // Store origin domain for post-auth redirect
		ProviderName:   input.Provider,
		Action:         action, // "login" | "register" | "discover" | "hydra_login"
		CodeVerifier:   codeVerifier,
		RedirectAfter:  input.RedirectAfter,
		LoginChallenge: input.LoginChallenge, // populated only for action=="hydra_login"
		ExpiresAt:      time.Now().Add(30 * time.Minute),
	}
	log.Printf("DEBUG InitiateOIDCFlow: Creating state with origin_domain='%s' (request_host column)", s.requestOrigin)

	if err := s.stateRepo.CreateState(state); err != nil {
		log.Printf("ERROR: Failed to store OIDC state: %v", err)
		return nil, fmt.Errorf("failed to store OIDC state: %w", err)
	}
	log.Printf("DEBUG InitiateOIDCFlow: Successfully created state with token='%s', tenant_domain='%s', origin_domain='%s', action='%s'", stateToken, input.TenantDomain, s.requestOrigin, action)

	// Build authorization URL
	callbackURL := s.resolveCallbackURL(provider)
	log.Printf("DEBUG InitiateOIDCFlow: Using callbackURL='%s' for provider '%s'", callbackURL, provider.ProviderName)
	authURL, err := s.buildAuthorizationURL(provider, stateToken, codeChallenge, callbackURL)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}
	log.Printf("DEBUG InitiateOIDCFlow: Built authURL with callbackURL='%s'", callbackURL)

	return &models.OIDCInitiateResponse{
		RedirectURL: authURL,
		State:       stateToken,
	}, nil
}

// HandleCallback processes the OIDC callback and returns user info
func (s *OIDCService) HandleCallback(input *models.OIDCCallbackInput) (*models.OIDCState, *models.OIDCUserInfo, error) {
	// Check for error from provider
	if input.Error != "" {
		return nil, nil, fmt.Errorf("OIDC provider error: %s", input.Error)
	}

	// Validate and retrieve state
	log.Printf("DEBUG HandleCallback: Looking up state with token='%s'", input.State)
	state, err := s.stateRepo.GetStateByToken(input.State)
	if err != nil {
		log.Printf("ERROR HandleCallback: Failed to get state for token='%s': %v", input.State, err)
		return nil, nil, fmt.Errorf("invalid or expired state: %w", err)
	}
	log.Printf("DEBUG HandleCallback: Found state: tenant_domain='%s', action='%s', provider='%s'", state.TenantDomain, state.Action, state.ProviderName)

	// If the row carries a v4 signed-state payload, verify it before
	// trusting the workspace/application columns. Mismatches mean either
	// tampered state or a stale row that pre-dates the workspace_id
	// rollout — log loudly and fail closed.
	if state.SignedState != "" {
		claims, verr := VerifySignedState(state.SignedState)
		if verr != nil {
			log.Printf("ERROR HandleCallback: signed state failed verification: %v", verr)
			return nil, nil, fmt.Errorf("oidc state signature invalid: %w", verr)
		}
		if state.WorkspaceID != nil && claims.WorkspaceID != *state.WorkspaceID {
			log.Printf("ERROR HandleCallback: signed workspace_id %s != row workspace_id %s",
				claims.WorkspaceID, state.WorkspaceID)
			return nil, nil, fmt.Errorf("oidc state workspace mismatch")
		}
		if state.ApplicationID != nil && (claims.ApplicationID == nil || *claims.ApplicationID != *state.ApplicationID) {
			log.Printf("ERROR HandleCallback: signed application_id mismatch")
			return nil, nil, fmt.Errorf("oidc state application mismatch")
		}
	}

	// Re-run the same gate used at initiation. This fails closed if an operator
	// disables the workspace IDP or removes its Application policy while the
	// upstream login is in flight.
	var provider *models.OIDCProvider
	if state.WorkspaceID != nil {
		provider, err = s.resolveEnabledProvider(*state.WorkspaceID, state.ProviderName, state.ApplicationID)
	} else {
		provider, err = s.providerRepo.GetProviderByName(state.ProviderName)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("provider not found: %s", state.ProviderName)
	}

	// Get client secret from Vault
	clientSecret, err := s.getClientSecret(provider.ClientSecretVaultPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	// Exchange authorization code for tokens
	tokens, err := s.exchangeCodeForTokens(provider, input.Code, state.CodeVerifier, clientSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.getUserInfo(provider, tokens.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// If userinfo didn't return sub/email (e.g. v1 userinfo endpoint or missing
	// openid scope), fall back to the id_token JWT claims. The id_token is
	// issued directly by Google over HTTPS so we trust its payload without
	// re-verifying the signature here.
	if (userInfo.Sub == "" || userInfo.Email == "") && tokens.IDToken != "" {
		if claims, parseErr := parseIDTokenClaims(tokens.IDToken); parseErr == nil {
			if userInfo.Sub == "" {
				userInfo.Sub = claims.Sub
			}
			if userInfo.Email == "" {
				userInfo.Email = claims.Email
			}
			if userInfo.Email == "" {
				userInfo.Email = claims.PreferredUsername
			}
			if userInfo.Email == "" {
				userInfo.Email = claims.UPN
			}
			if userInfo.Email == "" {
				userInfo.Email = claims.UniqueName
			}
			if !userInfo.EmailVerified {
				userInfo.EmailVerified = claims.EmailVerified
			}
			if userInfo.Name == "" {
				userInfo.Name = claims.Name
			}
			log.Printf("DEBUG HandleCallback: filled missing userinfo fields from id_token sub=%q email=%q", userInfo.Sub, userInfo.Email)
		} else {
			log.Printf("DEBUG HandleCallback: id_token parse failed: %v", parseErr)
		}
	}

	// Delete used state
	if err := s.stateRepo.DeleteState(input.State); err != nil {
		log.Printf("Warning: failed to delete OIDC state: %v", err)
	}

	return state, userInfo, nil
}

func (s *OIDCService) resolveEnabledProvider(workspaceID uuid.UUID, providerName string, applicationID *uuid.UUID) (*models.OIDCProvider, error) {
	var resolved struct {
		IdentityProviderID uuid.UUID
		Status             string
		ProviderModel      models.OIDCProvider `gorm:"embedded"`
	}
	err := config.DB.
		Table("identity_providers ip").
		Select(`ip.id AS identity_provider_id,
		        ip.status AS status,
		        op.*`).
		Joins("JOIN oidc_providers op ON op.id = ip.oidc_provider_id").
		Where("ip.workspace_id = ?", workspaceID).
		Where("ip.provider_type = ?", models.IdentityProviderOIDC).
		Where("op.provider_name = ?", providerName).
		First(&resolved).Error
	if err != nil {
		return nil, fmt.Errorf("provider %q not enabled for workspace", providerName)
	}
	if resolved.Status == "disabled" {
		return nil, fmt.Errorf("provider %q is disabled for workspace", providerName)
	}
	if !resolved.ProviderModel.IsActive {
		return nil, fmt.Errorf("provider %q is inactive", providerName)
	}

	if applicationID != nil {
		var policyCount int64
		if err := config.DB.Table("application_identity_provider_policies").
			Where("workspace_id = ? AND application_id = ?", workspaceID, *applicationID).
			Count(&policyCount).Error; err != nil {
			return nil, fmt.Errorf("check application IDP policies: %w", err)
		}
		if policyCount > 0 {
			var enabledCount int64
			if err := config.DB.Table("application_identity_provider_policies").
				Where("workspace_id = ? AND application_id = ? AND identity_provider_id = ? AND enabled = ?",
					workspaceID, *applicationID, resolved.IdentityProviderID, true).
				Count(&enabledCount).Error; err != nil {
				return nil, fmt.Errorf("check application IDP enabled: %w", err)
			}
			if enabledCount == 0 {
				return nil, fmt.Errorf("provider %q not enabled for application", providerName)
			}
		}
	}

	provider := &resolved.ProviderModel
	provider.ID = resolved.ProviderModel.ID
	return provider, nil
}

// GetIdentityByProviderUser looks up if a provider user exists in any tenant
func (s *OIDCService) GetIdentityByProviderUser(providerName, providerUserID string) (*models.OIDCUserIdentity, error) {
	return s.identityRepo.GetIdentityByProviderUser(providerName, providerUserID)
}

// GetIdentityByTenantAndProviderUser looks up if a provider user exists in a specific tenant
func (s *OIDCService) GetIdentityByTenantAndProviderUser(workspaceID uuid.UUID, providerName, providerUserID string) (*models.OIDCUserIdentity, error) {
	return s.identityRepo.GetIdentityByTenantAndProviderUser(workspaceID, providerName, providerUserID)
}

// CreateIdentity creates a new OIDC user identity link
func (s *OIDCService) CreateIdentity(identity *models.OIDCUserIdentity) error {
	return s.identityRepo.CreateIdentity(identity)
}

// UpdateLastLogin updates the last login timestamp for an identity
func (s *OIDCService) UpdateLastLogin(identityID uuid.UUID) error {
	return s.identityRepo.UpdateLastLogin(identityID)
}

// GetIdentitiesByUser retrieves all OIDC identities for a user
func (s *OIDCService) GetIdentitiesByUser(workspaceID, userID uuid.UUID) ([]models.OIDCUserIdentity, error) {
	return s.identityRepo.GetIdentitiesByUserID(workspaceID, userID)
}

// UnlinkIdentity removes an OIDC identity from a user
func (s *OIDCService) UnlinkIdentity(workspaceID, userID uuid.UUID, providerName string) error {
	return s.identityRepo.DeleteIdentity(workspaceID, userID, providerName)
}

// GetTenantsByEmail finds all tenants where a user with this email has OIDC identity
func (s *OIDCService) GetTenantsByEmail(email string) ([]uuid.UUID, error) {
	return s.identityRepo.GetTenantsByProviderEmail(email)
}

// GetStateByToken retrieves OIDC state by token
func (s *OIDCService) GetStateByToken(token string) (*models.OIDCState, error) {
	return s.stateRepo.GetStateByToken(token)
}

// CleanupExpiredStates removes expired OIDC states (should be called periodically)
func (s *OIDCService) CleanupExpiredStates() error {
	return s.stateRepo.DeleteExpiredStates()
}

// ========================================
// Admin methods for managing providers
// ========================================

// GetAllProviders returns all OIDC providers (for admin)
func (s *OIDCService) GetAllProviders() ([]models.OIDCProvider, error) {
	return s.providerRepo.GetAllProviders()
}

// GetProviderByName returns a specific OIDC provider
func (s *OIDCService) GetProviderByName(name string) (*models.OIDCProvider, error) {
	return s.providerRepo.GetProviderByName(name)
}

// UpdateProvider updates an OIDC provider configuration
func (s *OIDCService) UpdateProvider(providerName string, input *models.OIDCProviderUpdateInput) error {
	return s.providerRepo.UpdateProvider(providerName, input)
}

// ========================================
// Helper methods
// ========================================

// getCallbackURL returns the platform-default OIDC callback URL derived from
// BASE_URL. Used when a provider row has no per-workspace redirect_uri stored.
func (s *OIDCService) getCallbackURL() string {
	baseURL := config.AppConfig.BaseURL
	if baseURL == "" {
		baseURL = "https://app.authsec.dev"
	}
	callbackURL := fmt.Sprintf("%s/authsec/uflow/oidc/callback", baseURL)
	log.Printf("DEBUG getCallbackURL: Using BASE_URL='%s', callbackURL='%s'", baseURL, callbackURL)
	return callbackURL
}

// resolveCallbackURL returns the redirect_uri to send to the upstream OIDC
// provider for this row. Workspace-registered apps (their own Google/GitHub
// OAuth app) store the URI on oidc_providers.redirect_uri so it matches what
// the operator registered in the provider console; rows without one fall back
// to the BASE_URL default.
func (s *OIDCService) resolveCallbackURL(provider *models.OIDCProvider) string {
	if provider != nil && provider.RedirectURI != "" {
		return provider.RedirectURI
	}
	return s.getCallbackURL()
}

// SetRequestHost sets the current request host for dynamic callback URLs
func (s *OIDCService) SetRequestHost(host string) {
	s.requestHost = host
}

// SetRequestOrigin sets the origin domain for post-auth redirect
func (s *OIDCService) SetRequestOrigin(origin string) {
	s.requestOrigin = origin
}

// GetRequestOrigin returns the stored request origin
func (s *OIDCService) GetRequestOrigin() string {
	return s.requestOrigin
}

// buildAuthorizationURL constructs the OAuth2 authorization URL
func (s *OIDCService) buildAuthorizationURL(provider *models.OIDCProvider, state, codeChallenge, callbackURL string) (string, error) {
	log.Printf("DEBUG buildAuthorizationURL: Building auth URL for provider '%s' with redirect_uri='%s'", provider.ProviderName, callbackURL)

	params := url.Values{}
	params.Set("client_id", provider.ClientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("response_type", "code")
	params.Set("scope", provider.Scopes)
	params.Set("state", state)

	// Add PKCE parameters
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	// Provider-specific parameters
	switch provider.ProviderName {
	case "google":
		params.Set("access_type", "offline")
		params.Set("prompt", "select_account")
	case "github":
		// GitHub doesn't support PKCE, but we include state for CSRF
		params.Del("code_challenge")
		params.Del("code_challenge_method")
	case "microsoft":
		params.Set("response_mode", "query")
	}

	return fmt.Sprintf("%s?%s", provider.AuthorizationURL, params.Encode()), nil
}

// exchangeCodeForTokens exchanges the authorization code for access tokens
func (s *OIDCService) exchangeCodeForTokens(provider *models.OIDCProvider, code, codeVerifier, clientSecret string) (*models.OIDCTokenResponse, error) {
	callbackURL := s.resolveCallbackURL(provider)

	// URL decode the code before setting it, to prevent double encoding issues
	decodedCode, err := url.QueryUnescape(code)
	if err != nil {
		log.Printf("Warning: failed to URL unescape code: %v", err)
		decodedCode = code // Use original code if unescaping fails
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", provider.ClientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", decodedCode)
	data.Set("redirect_uri", callbackURL)

	// Add PKCE verifier (except for GitHub)
	if provider.ProviderName != "github" && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequest("POST", provider.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Token exchange failed with status %d: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokens models.OIDCTokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokens, nil
}

// getUserInfo retrieves user info from the OIDC provider
func (s *OIDCService) getUserInfo(provider *models.OIDCProvider, accessToken string) (*models.OIDCUserInfo, error) {
	req, err := http.NewRequest("GET", provider.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("UserInfo request failed: %s", string(body))
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	log.Printf("DEBUG getUserInfo: provider=%q url=%q raw_body=%s", provider.ProviderName, provider.UserinfoURL, string(body))

	// Parse response based on provider
	var userInfo models.OIDCUserInfo
	switch provider.ProviderName {
	case "github":
		userInfo, err = parseGitHubUserInfo(body, accessToken, s.httpClient)
	case "microsoft":
		userInfo, err = parseMicrosoftUserInfo(body)
	default:
		err = json.Unmarshal(body, &userInfo)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	log.Printf("DEBUG getUserInfo: parsed sub=%q email=%q email_verified=%v", userInfo.Sub, userInfo.Email, userInfo.EmailVerified)
	return &userInfo, nil
}

// getClientSecret retrieves the client secret from Vault
func (s *OIDCService) getClientSecret(vaultPath string) (string, error) {
	// For now, try to get from environment as fallback
	// In production, this should read from HashiCorp Vault

	// Try Vault first
	secret, err := GetSecretFromVault(vaultPath)
	if err == nil && secret != "" {
		return secret, nil
	}

	// Fallback to environment variables
	switch {
	case strings.Contains(strings.ToLower(vaultPath), "google"):
		sec := config.AppConfig.GoogleClientSecret
		log.Printf("DEBUG getClientSecret: vault_path=%q matched 'google', secret_empty=%v", vaultPath, sec == "")
		return sec, nil
	case strings.Contains(strings.ToLower(vaultPath), "github"):
		sec := config.AppConfig.GitHubClientSecret
		log.Printf("DEBUG getClientSecret: vault_path=%q matched 'github', secret_empty=%v", vaultPath, sec == "")
		return sec, nil
	case strings.Contains(strings.ToLower(vaultPath), "microsoft"):
		sec := config.AppConfig.MicrosoftClientSecret
		log.Printf("DEBUG getClientSecret: vault_path=%q matched 'microsoft', secret_empty=%v", vaultPath, sec == "")
		return sec, nil
	}

	log.Printf("DEBUG getClientSecret: vault_path=%q did not match any known provider pattern", vaultPath)
	return "", fmt.Errorf("client secret not found for path: %s", vaultPath)
}

// ========================================
// Utility functions
// ========================================

// generateSecureToken generates a cryptographically secure random token
// idTokenClaims holds the fields we care about from a JWT id_token payload.
type idTokenClaims struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	UPN               string `json:"upn"`
	UniqueName        string `json:"unique_name"`
}

// parseIDTokenClaims decodes the payload of a JWT id_token without verifying
// the signature. Safe to call when the token was received directly from the
// provider's token endpoint over HTTPS (the transport already proves
// authenticity).
func parseIDTokenClaims(idToken string) (*idTokenClaims, error) {
	parts := strings.SplitN(idToken, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token is not a valid JWT (expected 3 parts, got %d)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token payload base64 decode: %w", err)
	}
	var claims idTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("id_token payload JSON: %w", err)
	}
	return &claims, nil
}

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateCodeChallenge generates a PKCE code challenge from the verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// parseGitHubUserInfo parses GitHub's userinfo response
// GitHub's response format is different from standard OIDC
func parseGitHubUserInfo(body []byte, accessToken string, client *http.Client) (models.OIDCUserInfo, error) {
	var ghUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.Unmarshal(body, &ghUser); err != nil {
		return models.OIDCUserInfo{}, err
	}

	userInfo := models.OIDCUserInfo{
		Sub:     fmt.Sprintf("%d", ghUser.ID),
		Name:    ghUser.Name,
		Picture: ghUser.AvatarURL,
	}

	// GitHub might not return email in main response, need to fetch from /user/emails
	if ghUser.Email != "" {
		userInfo.Email = ghUser.Email
		userInfo.EmailVerified = true
	} else {
		// Fetch primary email from GitHub
		email, err := fetchGitHubPrimaryEmail(accessToken, client)
		if err == nil && email != "" {
			userInfo.Email = email
			userInfo.EmailVerified = true
		}
	}

	return userInfo, nil
}

// parseMicrosoftUserInfo accepts both the standard Entra OIDC userinfo shape
// and the older Graph /me shape that some existing rows may still store.
func parseMicrosoftUserInfo(body []byte) (models.OIDCUserInfo, error) {
	var msUser struct {
		Sub               string `json:"sub"`
		ID                string `json:"id"`
		Email             string `json:"email"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"given_name"`
		Surname           string `json:"surname"`
	}

	if err := json.Unmarshal(body, &msUser); err != nil {
		return models.OIDCUserInfo{}, err
	}

	userInfo := models.OIDCUserInfo{
		Sub:        coalesceProfileString(msUser.Sub, msUser.ID),
		Email:      coalesceProfileString(msUser.Email, msUser.Mail, msUser.PreferredUsername, msUser.UserPrincipalName),
		Name:       coalesceProfileString(msUser.Name, msUser.DisplayName),
		GivenName:  msUser.GivenName,
		FamilyName: msUser.Surname,
	}
	return userInfo, nil
}

func coalesceProfileString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// fetchGitHubPrimaryEmail fetches the primary email from GitHub API
func fetchGitHubPrimaryEmail(accessToken string, client *http.Client) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch GitHub emails")
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no primary verified email found")
}

// GetSecretFromVault reads the `client_secret` value at the given Vault KV2
// path. The path is the value stored on oidc_providers.client_secret_vault_path
// which for v4 workspace-owned IDPs is built by config.WorkspaceIDPSecretPath.
//
// Returns an empty string + non-nil error when Vault is unconfigured or the
// path has no value — the caller falls back to env vars in dev.
func GetSecretFromVault(path string) (string, error) {
	if config.VaultClient == nil {
		return "", fmt.Errorf("vault client not initialized")
	}
	if path == "" {
		return "", fmt.Errorf("vault path is empty")
	}
	secret, err := config.VaultClient.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("read vault path %s: %w", path, err)
	}
	if secret == nil {
		return "", fmt.Errorf("secret not found at %s", path)
	}
	data, err := config.GetSecretData(secret)
	if err != nil {
		return "", fmt.Errorf("decode vault data: %w", err)
	}
	if v, ok := data["client_secret"].(string); ok {
		return v, nil
	}
	return "", fmt.Errorf("client_secret not present in vault entry %s", path)
}
