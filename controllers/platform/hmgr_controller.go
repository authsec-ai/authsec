package platform

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	hydramodels "github.com/authsec-ai/authsec/internal/hydra/models"
	hydrautils "github.com/authsec-ai/authsec/internal/hydra/utils"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// storePKCEVerifier saves a code verifier to the database, keyed by state or login_challenge.
// Database-backed: survives restarts, works in multi-instance deployments.
func storePKCEVerifier(key, codeVerifier string) {
	v := models.PKCEVerifier{
		Key:       key,
		Verifier:  codeVerifier,
		ExpiresAt: time.Now().Add(8 * time.Minute),
	}
	// Upsert: overwrite if key already exists (e.g., page retry)
	config.DB.Where("key = ?", key).Assign(v).FirstOrCreate(&v)
}

// consumePKCEVerifier retrieves and deletes the stored code verifier from the database.
// Returns an empty string if not found or expired.
func consumePKCEVerifier(key string) string {
	var v models.PKCEVerifier
	if err := config.DB.Where("key = ? AND expires_at > ?", key, time.Now()).First(&v).Error; err != nil {
		return ""
	}
	config.DB.Delete(&v)
	return v.Verifier
}

// HmgrController handles hydra manager authentication requests
type HmgrController struct {
	service        *hydramodels.OAuthLoginService
	authzCtx       *services.AuthorizationContextService
	rsService      *services.ResourceServerService
	scopeResolver  *services.ScopeResolver
	consentService *services.ConsentService
	scopeRegistry  *services.ScopeRegistryService
}

// NewHmgrController creates a new HmgrController
func NewHmgrController(cfg config.Config) *HmgrController {
	return &HmgrController{
		service:        hydramodels.NewOAuthLoginService(cfg),
		authzCtx:       services.NewAuthorizationContextService(config.DB),
		rsService:      services.NewResourceServerService(config.DB),
		scopeResolver:  services.NewScopeResolver(config.DB),
		consentService: services.NewConsentService(config.DB),
		scopeRegistry:  services.NewScopeRegistryService(config.DB),
	}
}

// isNewMCPClient checks if a Hydra client ID belongs to the new MCP OAuth plane.
func (ctrl *HmgrController) isNewMCPClient(hydraClientID string) bool {
	_, err := ctrl.authzCtx.GetMCPOAuthClientByHydraID(hydraClientID)
	return err == nil
}

// StorePKCEVerifierHandler pre-registers a PKCE code_verifier from an external client
// so it can be retrieved at token-exchange time.
// POST /hmgr/pkce/store  { "state": "...", "code_verifier": "..." }
func (ctrl *HmgrController) StorePKCEVerifierHandler(c *gin.Context) {
	var req struct {
		State        string `json:"state" binding:"required"`
		CodeVerifier string `json:"code_verifier" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if len(req.CodeVerifier) < 43 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "code_verifier must be at least 43 characters"})
		return
	}
	storePKCEVerifier(req.State, req.CodeVerifier)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// CompleteLocalLoginHandler bridges a locally authenticated end-user JWT into the
// active Hydra login challenge so browser-based custom login can continue the
// OAuth authorization flow for local development.
func (ctrl *HmgrController) CompleteLocalLoginHandler(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "invalid request body",
		})
		return
	}

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "authorization header required",
		})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "invalid authorization header, expected Bearer token",
		})
		return
	}

	userClaims, err := validateUserJWT(parts[1])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "invalid or expired user token",
			"details": err.Error(),
		})
		return
	}

	userID := claimString(userClaims, "user_id", claimString(userClaims, "sub", ""))
	email := claimString(userClaims, "email_id", claimString(userClaims, "email", ""))
	tenantID := claimString(userClaims, "tenant_id", "")
	projectID := claimString(userClaims, "project_id", "")

	if userID == "" || email == "" || tenantID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"error":   "user token missing required claims",
		})
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "failed to load hydra login request",
		})
		return
	}

	hydraClientID := loginRequest.Client.ClientID
	expectedClientID := strings.TrimSuffix(hydraClientID, "-main-client")
	expectedTenantID := tenantID
	var mcpAuthCtx *models.AuthRequestContext

	if ctrl.isNewMCPClient(hydraClientID) {
		arcCtx, arcErr := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(req.LoginChallenge)
		if arcErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "failed to resolve MCP auth context",
			})
			return
		}
		if !strings.EqualFold(arcCtx.TenantID, tenantID) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "user token tenant does not match login challenge tenant",
			})
			return
		}
		mcpAuthCtx = arcCtx
		expectedTenantID = arcCtx.TenantID
	} else {
		clientDetails, _, hydraErr := ctrl.service.GetHydraClient(hydraClientID)
		if hydraErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "failed to load hydra client",
			})
			return
		}

		if legacyTenantID, _ := clientDetails.Metadata["c_id"].(string); legacyTenantID != "" {
			expectedTenantID = legacyTenantID
		}
		if expectedTenantID == "" {
			if legacyTenantID, _ := clientDetails.Metadata["tenant_id"].(string); legacyTenantID != "" {
				expectedTenantID = legacyTenantID
			}
		}
		if expectedTenantID != "" && !strings.EqualFold(expectedTenantID, tenantID) {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   "user token tenant does not match login challenge tenant",
			})
			return
		}
	}

	tenantDB, err := middlewares.GetConnectionDynamically(config.DB, nil, &expectedTenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to connect to tenant database",
		})
		return
	}

	var user models.User
	if err := tenantDB.Where("id = ?", userID).First(&user).Error; err != nil {
		if err := tenantDB.Where("LOWER(email) = LOWER(?)", email).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   "authenticated user not found in tenant database",
			})
			return
		}
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	loginContext := map[string]interface{}{
		"email":       user.Email,
		"name":        user.Name,
		"username":    username,
		"provider":    user.Provider,
		"provider_id": user.ProviderID,
		"tenant_id":   user.TenantID,
		"project_id":  user.ProjectID,
		"client_id":   expectedClientID,
		"avatar_url":  user.AvatarURL,
	}
	if projectID != "" {
		loginContext["project_id"] = projectID
	}
	if mcpAuthCtx != nil {
		loginContext["context_id"] = mcpAuthCtx.ContextID
		loginContext["resource_server_id"] = mcpAuthCtx.ResourceServerID
		loginContext["resource_uri"] = mcpAuthCtx.ResourceURI
	}

	acceptResponse, err := ctrl.service.AcceptHydraLoginRequestWithContext(req.LoginChallenge, user.ID.String(), loginContext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to accept hydra login request",
			"details": err.Error(),
		})
		return
	}

	// Record auth_time on the auth context for OIDC max_age enforcement.
	if mcpAuthCtx != nil {
		now := time.Now()
		if setErr := ctrl.authzCtx.SetAuthTime(mcpAuthCtx.State, now); setErr != nil {
			log.Printf("[MCP_AUTH] AcceptLogin: SetAuthTime failed state=%s: %v", mcpAuthCtx.State, setErr)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"login_challenge": req.LoginChallenge,
		"redirect_to":     acceptResponse.RedirectTo,
		"client_id":       expectedClientID,
		"tenant_id":       expectedTenantID,
		"email":           user.Email,
	})
}

// GetLoginPageDataHandler handles the login page data request
func (ctrl *HmgrController) GetLoginPageDataHandler(c *gin.Context) {
	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Missing login_challenge parameter",
		})
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(loginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Failed to get login request",
		})
		return
	}

	if loginRequest.Client.ClientID == "" {
		c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Invalid login request: missing client ID",
		})
		return
	}

	hydraClientID := loginRequest.Client.ClientID

	// ── Dual-mode: new MCP path vs legacy path ──
	if ctrl.isNewMCPClient(hydraClientID) {
		// Temporary no-PAR path: bind via authsec_ctx from Hydra's request_url.
		// Legacy request_uri binding remains as a fallback for any in-flight flows minted
		// before the bypass was deployed.
		contextID := ""
		requestURI := ""
		if loginRequest.RequestURL != "" {
			if parsedURL, parseErr := url.Parse(loginRequest.RequestURL); parseErr == nil {
				contextID = parsedURL.Query().Get("authsec_ctx")
				requestURI = parsedURL.Query().Get("request_uri")
			}
		}

		var arcCtx *models.AuthRequestContext
		if contextID != "" {
			// Primary path during the temporary bypass: authsec_ctx binds directly to ContextID.
			var bindErr error
			arcCtx, bindErr = ctrl.authzCtx.BindByContextID(contextID, loginChallenge)
			if bindErr != nil || arcCtx == nil {
				log.Printf("[MCP_AUTH] GetLoginPageData: BindByContextID failed ctx=%s: %v", contextID, bindErr)
				c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
					Success: false,
					Error:   "Authorization context not found",
				})
				return
			}
			log.Printf("[MCP_AUTH] GetLoginPageData: using authsec_ctx=%s (temporary no-PAR flow)", contextID)
		} else if requestURI != "" {
			// Legacy fallback for already-issued PAR flows.
			var bindErr error
			arcCtx, bindErr = ctrl.authzCtx.BindByHydraRequestURI(requestURI, loginChallenge)
			if bindErr != nil || arcCtx == nil {
				log.Printf("[MCP_AUTH] GetLoginPageData: BindByHydraRequestURI failed uri=%s: %v", requestURI, bindErr)
				c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
					Success: false,
					Error:   "Authorization context not found",
				})
				return
			}
		} else {
			log.Printf("[MCP_AUTH] GetLoginPageData: no authsec_ctx or request_uri for client=%s challenge=%s",
				hydraClientID, loginChallenge)
			c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
				Success: false,
				Error:   "Authorization context not found",
			})
			return
		}

		tenantIDForOIDC := arcCtx.TenantID

		// OIDC prompt/max_age enforcement (OpenID Connect Core 1.0 §3.1.2.1)
		if arcCtx.Prompt != nil {
			switch *arcCtx.Prompt {
			case "none":
				// prompt=none: if Hydra says no existing session (Skip=false), reject login.
				// Per OIDC Core §3.1.2.6, Hydra will redirect back with error=login_required
				// when we reject the login. We reject via Hydra's reject-login API so the
				// error flows through the standard OAuth redirect back to the client.
				if !loginRequest.Skip {
					log.Printf("[MCP_AUTH] GetLoginPageData: prompt=none but no session, rejecting login challenge=%s", loginChallenge)
					rejectErr := ctrl.service.RejectHydraLoginRequest(loginChallenge, "login_required", "prompt=none requires an existing session")
					if rejectErr != nil {
						log.Printf("[MCP_AUTH] GetLoginPageData: RejectHydraLoginRequest failed: %v", rejectErr)
					}
					c.JSON(http.StatusOK, hydramodels.LoginPageDataResponse{
						Success: false,
						Error:   "login_required",
					})
					return
				}
			case "login":
				// prompt=login: force re-authentication even if session exists
				// We do this by NOT auto-accepting the skip suggestion
				loginRequest.Skip = false
			}
		}
		if arcCtx.MaxAge != nil && loginRequest.Skip {
			// max_age enforcement: if Hydra suggests Skip (session exists) but the session
			// auth_time + max_age < now, force re-authentication.
			// Check arcCtx.AuthTime if available from a previous session.
			if arcCtx.AuthTime != nil {
				elapsed := int(time.Since(*arcCtx.AuthTime).Seconds())
				if elapsed > *arcCtx.MaxAge {
					log.Printf("[MCP_AUTH] GetLoginPageData: max_age=%d exceeded (elapsed=%d), forcing re-auth challenge=%s",
						*arcCtx.MaxAge, elapsed, loginChallenge)
					loginRequest.Skip = false
				}
			}
			// Also log for dev verification that Hydra is honoring max_age via PAR natively.
			log.Printf("[MCP_AUTH] GetLoginPageData: max_age=%d skip=%v challenge=%s",
				*arcCtx.MaxAge, loginRequest.Skip, loginChallenge)
		}

		// Resolve resource server name for the login page contract.
		rsName := ""
		if rs, rsErr := ctrl.rsService.GetByID(arcCtx.ResourceServerID); rsErr == nil {
			rsName = rs.Name
		}

		allProviders, err := ctrl.service.GetAllProvidersForTenant(tenantIDForOIDC, tenantIDForOIDC, hydraClientID)
		if err != nil {
			// No external OIDC/SAML providers — the login page can still render with
			// built-in email/password flows as long as page-data succeeds.
			log.Printf("[MCP_AUTH] GetLoginPageData: no external providers for tenant=%s challenge=%s: %v", tenantIDForOIDC, loginChallenge, err)
			allProviders = nil
		}

		oidcProviders := make([]hydramodels.OIDCProvider, 0, len(allProviders))
		for _, p := range allProviders {
			providerConfig := map[string]interface{}{"type": p.Type}
			for key, value := range p.Config {
				providerConfig[key] = value
			}
			oidcProviders = append(oidcProviders, hydramodels.OIDCProvider{
				ProviderName: p.ProviderName,
				DisplayName:  p.DisplayName,
				IsActive:     p.IsActive,
				SortOrder:    p.SortOrder,
				Config:       providerConfig,
			})
		}

		c.JSON(http.StatusOK, hydramodels.LoginPageDataResponse{
			ClientID:       tenantIDForOIDC,
			Success:        true,
			LoginChallenge: loginChallenge,
			TenantName:     tenantIDForOIDC,
			ClientName:     rsName,
			Providers:      oidcProviders,
			BaseURL:        config.AppConfig.BaseURL,
		})
		return
	}

	// LEGACY PATH: Resolve tenant from Hydra client metadata
	clientDetails, _, err := ctrl.service.GetHydraClient(hydraClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Client not found",
		})
		return
	}

	tenantIDForOIDC, _ := clientDetails.Metadata["tenant_id"].(string)
	realTenantID, _ := clientDetails.Metadata["c_id"].(string)
	tenantName, _ := clientDetails.Metadata["tenant_name"].(string)

	if tenantIDForOIDC == "" {
		c.JSON(http.StatusBadRequest, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Invalid client configuration",
		})
		return
	}

	clientID := hydraClientID
	allProviders, err := ctrl.service.GetAllProvidersForTenant(tenantIDForOIDC, realTenantID, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.LoginPageDataResponse{
			Success: false,
			Error:   "Failed to get authentication providers",
		})
		return
	}

	oidcProviders := make([]hydramodels.OIDCProvider, 0, len(allProviders))
	for _, p := range allProviders {
		providerConfig := map[string]interface{}{"type": p.Type}
		for key, value := range p.Config {
			providerConfig[key] = value
		}
		oidcProviders = append(oidcProviders, hydramodels.OIDCProvider{
			ProviderName: p.ProviderName,
			DisplayName:  p.DisplayName,
			IsActive:     p.IsActive,
			SortOrder:    p.SortOrder,
			Config:       providerConfig,
		})
	}

	c.JSON(http.StatusOK, hydramodels.LoginPageDataResponse{
		ClientID:       strings.TrimSuffix(hydraClientID, "-main-client"),
		Success:        true,
		LoginChallenge: loginChallenge,
		TenantName:     tenantName,
		ClientName:     clientDetails.ClientName,
		Providers:      oidcProviders,
		BaseURL:        config.AppConfig.BaseURL,
	})
}

// InitiateAuthHandler initiates authentication with a provider
func (ctrl *HmgrController) InitiateAuthHandler(c *gin.Context) {
	providerName := c.Param("provider")

	var req struct {
		LoginChallenge string `json:"login_challenge"`
		OriginDomain   string `json:"origin_domain,omitempty"`
		CodeVerifier   string `json:"code_verifier,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Invalid JSON body",
		})
		return
	}

	if req.LoginChallenge == "" {
		c.JSON(http.StatusBadRequest, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Missing login_challenge",
		})
		return
	}

	// Store the PKCE code_verifier by login_challenge so ExchangeTokenHandler can
	// retrieve it later.
	if req.CodeVerifier != "" {
		storePKCEVerifier(req.LoginChallenge, req.CodeVerifier)
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Failed to get login request",
		})
		return
	}

	hydraClientID := loginRequest.Client.ClientID

	clientDetails, _, err := ctrl.service.GetHydraClient(hydraClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Client not found",
		})
		return
	}

	// ── Dual-mode: resolve tenant from bridge table or Hydra metadata ──
	var tenantID string
	if ctrl.isNewMCPClient(hydraClientID) {
		arcCtx, err := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(req.LoginChallenge)
		if err != nil {
			c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
				Success: false,
				Error:   "Failed to resolve MCP auth context",
			})
			return
		}
		tenantID = arcCtx.TenantID
	} else {
		tenantID, _ = clientDetails.Metadata["tenant_id"].(string)
	}

	providers, err := ctrl.service.GetOIDCProvidersForTenant(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Failed to get OIDC providers",
		})
		return
	}

	var selectedProvider *hydramodels.OIDCProvider
	for _, provider := range providers {
		if strings.EqualFold(provider.ProviderName, providerName) {
			selectedProvider = &provider
			break
		}
	}

	if selectedProvider == nil {
		c.JSON(http.StatusNotFound, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Provider not found",
		})
		return
	}

	if !selectedProvider.IsActive {
		c.JSON(http.StatusBadRequest, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Provider is not active",
		})
		return
	}

	providerConfig := selectedProvider.Config
	clientID, _ := providerConfig["client_id"].(string)
	authURL, _ := providerConfig["auth_url"].(string)
	scopes, _ := providerConfig["scopes"].([]interface{})

	scopeStrings := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeStrings[i] = scope.(string)
	}

	nonce := hydrautils.GenerateCodeVerifier()
	originDomain := req.OriginDomain

	if originDomain == "" {
		originDomain = c.GetHeader("X-Forwarded-Host")
	}
	if originDomain == "" {
		if origin := c.GetHeader("Origin"); origin != "" {
			if u, err := url.Parse(origin); err == nil {
				originDomain = u.Host
			}
		}
	}
	if originDomain == "" {
		if referer := c.GetHeader("Referer"); referer != "" {
			if u, err := url.Parse(referer); err == nil {
				originDomain = u.Host
			}
		}
	}
	if originDomain == "" {
		originDomain = c.Request.Host
	}

	if originDomain != "" && tenantID != "" {
		verifiedDomains, err := hydramodels.GetVerifiedDomainsForTenant(config.DB, tenantID)
		if err == nil && len(verifiedDomains) > 0 {
			isVerified := false
			for _, d := range verifiedDomains {
				if strings.HasSuffix(originDomain, d) || strings.EqualFold(d, originDomain) {
					isVerified = true
					break
				}
			}
			if !isVerified {
				isDev := strings.Contains(originDomain, "localhost") || strings.Contains(originDomain, "127.0.0.1")
				if !isDev {
					c.JSON(http.StatusForbidden, hydramodels.AuthInitiateResponse{
						Success: false,
						Error:   "Origin domain not verified for this tenant",
					})
					return
				}
			}
		}
	}

	stateData := map[string]string{
		"login_challenge": req.LoginChallenge,
		"nonce":           nonce,
		"provider":        providerName,
		"origin_domain":   originDomain,
	}
	stateBytes, err := json.Marshal(stateData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Failed to generate state",
		})
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// For MCP clients, the registered RedirectURIs hold Codex's callback (e.g. http://localhost:11337/callback),
	// NOT AuthSec's own callback handler. Use AuthSec's callback URL for IdP redirect.
	var callbackURL string
	if ctrl.isNewMCPClient(hydraClientID) {
		callbackURL = config.AppConfig.BaseURL + "/authsec/hmgr/auth/callback"
	} else {
		if len(clientDetails.RedirectURIs) == 0 {
			c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
				Success: false,
				Error:   "No registered redirect URI found for client",
			})
			return
		}
		callbackURL = clientDetails.RedirectURIs[0]
	}

	oauthURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s",
		authURL,
		clientID,
		url.QueryEscape(callbackURL),
		url.QueryEscape(strings.Join(scopeStrings, " ")),
		url.QueryEscape(state),
	)

	c.JSON(http.StatusOK, hydramodels.AuthInitiateResponse{
		Success:  true,
		AuthURL:  oauthURL,
		State:    state,
		Provider: providerName,
	})
}

// HandleCallbackHandler processes the OAuth callback
func (ctrl *HmgrController) HandleCallbackHandler(c *gin.Context) {
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
		Error string `json:"error,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{
			Success: false,
			Error:   "Invalid request body: " + err.Error(),
		})
		return
	}

	if req.Error != "" {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("OAuth provider error: %s", req.Error),
		})
		return
	}

	if req.Code == "" || req.State == "" {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{
			Success: false,
			Error:   "Missing required parameters: code or state",
		})
		return
	}

	redirectTo, userInfo, err := ctrl.ProcessOAuthCallback(req.Code, req.State)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{
			Success: false,
			Error:   "Authentication processing failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, hydramodels.CallbackValidationResponse{
		Success:    true,
		RedirectTo: redirectTo,
		UserInfo:   userInfo,
	})
}

// ProcessOAuthCallback processes the OAuth callback logic
func (ctrl *HmgrController) ProcessOAuthCallback(code, receivedState string) (string, *hydramodels.User, error) {
	var stateData map[string]string

	stateBytes, err := base64.URLEncoding.DecodeString(receivedState)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode state: %w", err)
	}

	if err := json.Unmarshal(stateBytes, &stateData); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	loginChallenge := stateData["login_challenge"]
	providerName := stateData["provider"]
	originDomain := stateData["origin_domain"]

	if loginChallenge == "" {
		return "", nil, fmt.Errorf("missing login_challenge in state")
	}
	if providerName == "" {
		return "", nil, fmt.Errorf("missing provider in state")
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(loginChallenge)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get login request: %w", err)
	}

	hydraClientID := loginRequest.Client.ClientID
	clientDetails, _, err := ctrl.service.GetHydraClient(hydraClientID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get client details: %w", err)
	}

	// ── Dual-mode: resolve tenant from bridge table or Hydra metadata ──
	var tenantID string
	isMCP := ctrl.isNewMCPClient(hydraClientID)

	if isMCP {
		arcCtx, err := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(loginChallenge)
		if err != nil {
			return "", nil, fmt.Errorf("failed to resolve MCP auth context: %w", err)
		}
		tenantID = arcCtx.TenantID
	} else {
		tenantID, _ = clientDetails.Metadata["tenant_id"].(string)
		if tenantID == "" {
			return "", nil, fmt.Errorf("missing tenant_id in client metadata")
		}
	}

	providers, err := ctrl.service.GetOIDCProvidersForTenant(tenantID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get OIDC providers: %w", err)
	}

	var selectedProvider *hydramodels.OIDCProvider
	for _, provider := range providers {
		if strings.EqualFold(provider.ProviderName, providerName) {
			selectedProvider = &provider
			break
		}
	}

	if selectedProvider == nil {
		return "", nil, fmt.Errorf("provider %s not found", providerName)
	}

	// For MCP clients, use AuthSec's own callback URL (not the MCP client's redirect URI)
	var redirectURI string
	if isMCP {
		redirectURI = config.AppConfig.BaseURL + "/authsec/hmgr/auth/callback"
	} else {
		if len(clientDetails.RedirectURIs) == 0 {
			return "", nil, fmt.Errorf("no registered redirect URI found for client")
		}
		redirectURI = clientDetails.RedirectURIs[0]
	}

	ctx := context.Background()
	tokenResponse, err := ctrl.service.ExchangeCodeForTokens(ctx, selectedProvider, code, redirectURI)
	if err != nil {
		return "", nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	accessToken, ok := tokenResponse["access_token"].(string)
	if !ok || accessToken == "" {
		return "", nil, fmt.Errorf("no access token in response")
	}

	userInfo, err := ctrl.service.GetUserInfo(ctx, selectedProvider, accessToken)
	if err != nil {
		// For Microsoft, fall back to decoding the id_token instead of calling Graph API.
		if strings.EqualFold(providerName, "microsoft") || strings.EqualFold(providerName, "azure") {
			if idToken, ok := tokenResponse["id_token"].(string); ok && idToken != "" {
				log.Printf("Microsoft Graph userinfo failed (%v), falling back to id_token", err)
				userInfo, err = extractClaimsFromIDToken(idToken)
				if err != nil {
					return "", nil, fmt.Errorf("failed to extract claims from Microsoft id_token: %w", err)
				}
			} else {
				return "", nil, fmt.Errorf("failed to get user info: %w", err)
			}
		} else {
			return "", nil, fmt.Errorf("failed to get user info: %w", err)
		}
	}

	user, userID, err := ctrl.ExtractUserFromProviderResponse(providerName, userInfo)
	if err != nil {
		return "", nil, fmt.Errorf("failed to extract user info: %w", err)
	}

	if isMCP {
		// MCP path: use tenant from bridge table
		parsedTenantID, err := uuid.Parse(tenantID)
		if err != nil {
			return "", nil, fmt.Errorf("invalid MCP tenant ID: %w", err)
		}
		user.TenantID = parsedTenantID
		user.ClientID = parsedTenantID // MCP clients don't have a legacy client_id
	} else {
		// Legacy path: use Hydra client metadata
		parsedTenantID, err := uuid.Parse(clientDetails.Metadata["c_id"].(string))
		if err != nil {
			return "", nil, fmt.Errorf("invalid tenant ID format (c_id): %w", err)
		}

		clientIDStr, ok := clientDetails.Metadata["tenant_id"].(string)
		if !ok || clientIDStr == "" {
			return "", nil, fmt.Errorf("missing tenant_id in client metadata")
		}

		parsedClientID, err := uuid.Parse(clientIDStr)
		if err != nil {
			return "", nil, fmt.Errorf("invalid client ID format (tenant_id): %w", err)
		}

		user.ClientID = parsedClientID
		user.TenantID = parsedTenantID
	}

	user, err = ctrl.service.CreateOrUpdateUser(accessToken, user)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	loginContext := map[string]interface{}{
		"email":       user.Email,
		"name":        user.Name,
		"username":    user.Username,
		"provider":    user.Provider,
		"provider_id": user.ProviderID,
		"tenant_id":   user.TenantID,
		"project_id":  user.ProjectID,
		"avatar_url":  user.AvatarURL,
	}
	// Propagate email_verified from IdP userinfo (Google, Microsoft, etc. include this claim).
	// Defaults to true for social logins since the IdP has verified the email.
	if ev, ok := userInfo["email_verified"]; ok {
		loginContext["email_verified"] = ev
	} else {
		loginContext["email_verified"] = true // Social provider implies verified email
	}
	if isMCP {
		loginContext["tenant_id"] = tenantID
	}

	acceptResponse, err := ctrl.service.AcceptHydraLoginRequestWithContext(loginChallenge, userID, loginContext)
	if err != nil {
		return "", nil, fmt.Errorf("failed to accept login request: %w", err)
	}

	// Record auth_time on the MCP auth context for OIDC max_age enforcement.
	if isMCP {
		if arcCtx, arcErr := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(loginChallenge); arcErr == nil {
			now := time.Now()
			if setErr := ctrl.authzCtx.SetAuthTime(arcCtx.State, now); setErr != nil {
				log.Printf("[MCP_AUTH] ProcessOAuthCallback: SetAuthTime failed state=%s: %v", arcCtx.State, setErr)
			}
		}
	}

	finalRedirectURL := acceptResponse.RedirectTo
	safeOriginDomain := hmgrGetSafeOriginDomainForRedirect(acceptResponse.RedirectTo, originDomain)
	if safeOriginDomain != "" {
		finalRedirectURL = hmgrReplaceRedirectDomain(acceptResponse.RedirectTo, safeOriginDomain)
	}

	return finalRedirectURL, user, nil
}

// ExtractUserFromProviderResponse extracts user information from provider response
func (ctrl *HmgrController) ExtractUserFromProviderResponse(providerName string, userInfo map[string]interface{}) (*hydramodels.User, string, error) {
	var userID, email, name, username, avatarURL, providerUserID string

	switch strings.ToLower(providerName) {
	case "github":
		if id, ok := userInfo["id"].(float64); ok {
			providerUserID = fmt.Sprintf("%.0f", id)
			userID = fmt.Sprintf("github-%.0f", id)
		} else if id, ok := userInfo["id"].(int); ok {
			providerUserID = fmt.Sprintf("%d", id)
			userID = fmt.Sprintf("github-%d", id)
		} else if idStr, ok := userInfo["id"].(string); ok {
			providerUserID = idStr
			userID = fmt.Sprintf("github-%s", idStr)
		}
		if emailVal, exists := userInfo["email"]; exists && emailVal != nil {
			email, _ = emailVal.(string)
		}
		name, _ = userInfo["name"].(string)
		username, _ = userInfo["login"].(string)
		avatarURL, _ = userInfo["avatar_url"].(string)
		if email == "" && username != "" {
			email = fmt.Sprintf("%s@users.noreply.github.com", username)
		}

	case "google":
		if sub, ok := userInfo["sub"].(string); ok && sub != "" {
			providerUserID = sub
			userID = fmt.Sprintf("google-%s", sub)
		}
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
		if givenName, ok1 := userInfo["given_name"].(string); ok1 {
			if familyName, ok2 := userInfo["family_name"].(string); ok2 {
				name = fmt.Sprintf("%s %s", givenName, familyName)
			}
		}
		if email != "" {
			username = strings.Split(email, "@")[0]
		}
		avatarURL, _ = userInfo["picture"].(string)

	case "linkedin":
		if id, ok := userInfo["id"].(string); ok && id != "" {
			providerUserID = id
			userID = fmt.Sprintf("linkedin-%s", id)
		}
		email, _ = userInfo["emailAddress"].(string)
		if firstName, ok := userInfo["localizedFirstName"].(string); ok {
			if lastName, ok := userInfo["localizedLastName"].(string); ok {
				name = fmt.Sprintf("%s %s", firstName, lastName)
			} else {
				name = firstName
			}
		}
		if email != "" {
			username = strings.Split(email, "@")[0]
		}

	case "microsoft", "azure":
		if id, ok := userInfo["id"].(string); ok && id != "" {
			providerUserID = id
			userID = fmt.Sprintf("microsoft-%s", id)
		} else if oid, ok := userInfo["oid"].(string); ok && oid != "" {
			providerUserID = oid
			userID = fmt.Sprintf("microsoft-%s", oid)
		} else if sub, ok := userInfo["sub"].(string); ok && sub != "" {
			providerUserID = sub
			userID = fmt.Sprintf("microsoft-%s", sub)
		}
		email, _ = userInfo["email"].(string)
		if email == "" {
			email, _ = userInfo["mail"].(string)
		}
		if email == "" {
			email, _ = userInfo["userPrincipalName"].(string)
		}
		if email == "" {
			email, _ = userInfo["preferred_username"].(string)
		}
		name, _ = userInfo["displayName"].(string)
		if name == "" {
			name, _ = userInfo["name"].(string)
		}
		username, _ = userInfo["mailNickname"].(string)
		if username == "" && email != "" {
			username = strings.Split(email, "@")[0]
		}

	default:
		if sub, ok := userInfo["sub"].(string); ok && sub != "" {
			providerUserID = sub
			userID = fmt.Sprintf("%s-%s", providerName, sub)
		} else if id, ok := userInfo["id"].(string); ok && id != "" {
			providerUserID = id
			userID = fmt.Sprintf("%s-%s", providerName, id)
		} else if id, ok := userInfo["id"].(float64); ok {
			providerUserID = fmt.Sprintf("%.0f", id)
			userID = fmt.Sprintf("%s-%.0f", providerName, id)
		}
		email, _ = userInfo["email"].(string)
		name, _ = userInfo["name"].(string)
		username, _ = userInfo["username"].(string)
		if username == "" {
			username, _ = userInfo["preferred_username"].(string)
		}
		avatarURL, _ = userInfo["avatar_url"].(string)
		if avatarURL == "" {
			avatarURL, _ = userInfo["picture"].(string)
		}
	}

	if userID == "" || providerUserID == "" {
		if email != "" {
			hash := sha256.Sum256([]byte(email))
			providerUserID = fmt.Sprintf("email-%x", hash[:8])
			userID = fmt.Sprintf("%s-%s", providerName, providerUserID)
		} else if username != "" {
			hash := sha256.Sum256([]byte(username))
			providerUserID = fmt.Sprintf("username-%x", hash[:8])
			userID = fmt.Sprintf("%s-%s", providerName, providerUserID)
		} else {
			return nil, "", fmt.Errorf("unable to extract user identifier from provider response")
		}
	}

	if username == "" && email != "" {
		username = strings.Split(email, "@")[0]
	}
	if name == "" {
		if username != "" {
			name = username
		} else if email != "" {
			name = email
		}
	}
	if email == "" {
		return nil, "", fmt.Errorf("no email found in provider response from %s", providerName)
	}

	userInfoJSON, err := json.Marshal(userInfo)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal user info: %w", err)
	}

	now := time.Now()
	user := &hydramodels.User{
		Email:        email,
		Username:     &username,
		Name:         name,
		Provider:     providerName,
		ProviderID:   providerUserID,
		ProviderData: datatypes.JSON(userInfoJSON),
		AvatarURL:    &avatarURL,
		LastLogin:    &now,
		Active:       true,
	}
	return user, userID, nil
}

// ExchangeTokenHandler handles token exchange requests
func (ctrl *HmgrController) ExchangeTokenHandler(c *gin.Context) {
	var req hydramodels.TokenExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request body: " + err.Error()})
		return
	}

	if !strings.HasPrefix(req.Code, "ory_ac_") {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid authorization code format"})
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to retrieve login information"})
		return
	}

	clientID := loginRequest.Client.ClientID
	clientDetails, _, err := ctrl.service.GetHydraClient(loginRequest.Client.ClientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to retrieve client information"})
		return
	}

	orgID := clientDetails.Metadata["c_id"].(string)

	tenantDB, err := middlewares.GetConnectionDynamically(config.DB, nil, &orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to connect to tenant database"})
		return
	}

	var client hydramodels.Client
	tenantIDStr := clientDetails.Metadata["tenant_id"].(string)
	if err := tenantDB.Where("tenant_id = ? AND active = ? AND client_id = ?", orgID, true, tenantIDStr).First(&client).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to retrieve client information"})
		return
	}

	clientSecret, err := config.SecretInVault(orgID, client.ProjectID.String(), client.ClientID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to retrieve client secret"})
		return
	}

	// Retrieve the stored PKCE code_verifier.
	// Priority order:
	//   1. Stored by state (GenerateLoginURLHandler path — backend-owned PKCE)
	//   2. Stored by login_challenge (server-side flows)
	//   3. Client-supplied in the request body (backward compat while React still owns PKCE)
	codeVerifier := consumePKCEVerifier(req.State)
	if codeVerifier == "" {
		codeVerifier = consumePKCEVerifier(req.LoginChallenge)
	}
	if codeVerifier == "" {
		codeVerifier = req.CodeVerifier
	}

	ctx := context.Background()
	tokens, err := ctrl.ExchangeCodeForHydraTokens(ctx, clientID, clientSecret, req.Code, req.RedirectURI, codeVerifier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to exchange code for tokens: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// ExchangeCodeForHydraTokens exchanges an authorization code for tokens with Hydra
func (ctrl *HmgrController) ExchangeCodeForHydraTokens(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier string) (*hydramodels.TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/oauth2/token", config.AppConfig.HydraPublicURL)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	accessToken, _ := tokenResponse["access_token"].(string)
	return &hydramodels.TokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(tokenResponse["expires_in"].(float64)),
	}, nil
}

// LoginRedirectHandler handles login redirects
func (ctrl *HmgrController) LoginRedirectHandler(c *gin.Context) {
	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.String(http.StatusBadRequest, "Missing login_challenge parameter")
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(loginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{Success: false, Error: "Failed to get login request"})
		return
	}

	// For MCP clients, redirect to AuthSec's own login page (not the MCP client's redirect URI)
	if ctrl.isNewMCPClient(loginRequest.Client.ClientID) {
		c.Redirect(http.StatusFound, config.AppConfig.BuildUILoginURL(loginChallenge))
		return
	}

	clientDetails, _, err := ctrl.service.GetHydraClient(loginRequest.Client.ClientID)
	if err != nil || len(clientDetails.RedirectURIs) == 0 {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{Success: false, Error: "No registered redirect URI found for client"})
		return
	}

	var callbackURL string
	for _, uri := range clientDetails.RedirectURIs {
		if strings.HasSuffix(uri, "/oidc/auth/callback") {
			callbackURL = uri
			break
		}
	}
	if callbackURL == "" {
		callbackURL = clientDetails.RedirectURIs[0]
	}

	baseURL := strings.TrimSuffix(callbackURL, "/oidc/auth/callback")

	if tenantIDObj, ok := clientDetails.Metadata["tenant_id"].(string); ok && tenantIDObj != "" {
		verifiedDomains, err := hydramodels.GetVerifiedDomainsForTenant(config.DB, tenantIDObj)
		if err == nil && len(verifiedDomains) > 0 {
			if u, err := url.Parse(baseURL); err == nil {
				host := u.Hostname()
				isVerified := false
				for _, d := range verifiedDomains {
					if strings.EqualFold(d, host) {
						isVerified = true
						break
					}
				}
				if !isVerified {
					isDev := strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1")
					if !isDev {
						c.JSON(http.StatusForbidden, hydramodels.AuthInitiateResponse{Success: false, Error: "Security violation: Redirect host not verified for this tenant"})
						return
					}
				}
			}
		}
	}

	loginURL, err := config.BuildUILoginURLFromRedirectURI(callbackURL, loginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{Success: false, Error: "Failed to build login redirect URL"})
		return
	}

	c.Redirect(http.StatusFound, loginURL)
}

// ConsentHandler handles consent requests
func (ctrl *HmgrController) ConsentHandler(c *gin.Context) {
	consentChallenge := c.Query("consent_challenge")
	if consentChallenge == "" && c.Request.Method == http.MethodPost {
		consentChallenge = c.PostForm("consent_challenge")
	}
	if consentChallenge == "" {
		c.String(http.StatusBadRequest, "Missing consent_challenge parameter")
		return
	}

	consentRequest, err := ctrl.service.GetHydraConsentRequest(consentChallenge)
	if err != nil {
		log.Printf("[MCP_AUTH] ConsentHandler: GetHydraConsentRequest failed challenge=%s: %v", consentChallenge, err)
		c.String(http.StatusInternalServerError, "Failed to get consent request")
		return
	}

	hydraClientID := consentRequest.Client.ClientID

	// ── Dual-mode: new MCP path uses ScopeResolver + RS audience ──
	if ctrl.isNewMCPClient(hydraClientID) {
		// Prefer the login-bound context, but fall back to the server-generated context_id
		// carried through Hydra login context because Hydra's consent login_challenge is not
		// guaranteed to match the original login challenge value.
		arcCtx, err := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(consentRequest.LoginChallenge)
		if err != nil {
			contextID := ""
			if consentRequest.Context != nil {
				if raw, ok := consentRequest.Context["context_id"].(string); ok {
					contextID = raw
				}
			}
			if contextID != "" {
				arcCtx, err = ctrl.authzCtx.GetActiveAuthRequestContextByContextID(contextID)
			}
		}
		if err != nil {
			log.Printf("[MCP_AUTH] ConsentHandler: auth context lookup failed login_challenge=%s consent_challenge=%s: %v",
				consentRequest.LoginChallenge, consentChallenge, err)
			c.String(http.StatusInternalServerError, "Failed to resolve MCP auth context for consent")
			return
		}

		// Look up the resource server for audience binding.
		rs, err := ctrl.rsService.GetByID(arcCtx.ResourceServerID)
		if err != nil {
			log.Printf("[MCP_AUTH] ConsentHandler: resource server lookup failed rs_id=%s context_id=%s: %v",
				arcCtx.ResourceServerID, arcCtx.ContextID, err)
			c.String(http.StatusInternalServerError, "Failed to resolve resource server")
			return
		}

		// Get the MCP OAuth client for scope resolver
		mcpClient, _ := ctrl.authzCtx.GetMCPOAuthClientByHydraID(hydraClientID)

		// If no scopes were requested (e.g. Claude Code omits the scope parameter),
		// default to all RS-supported scopes. This is standard OAuth AS behaviour:
		// an absent scope parameter means "request all available scopes for this resource."
		// The 3-way intersection with user-effective-scopes still enforces RBAC — the
		// user only receives scopes they are actually permitted to hold.
		requestedScopes := consentRequest.RequestedScope
		if len(requestedScopes) == 0 {
			requestedScopes = []string(rs.ScopesSupported)
		}

		// 3-way intersection: requested ∩ RS-supported ∩ user-effective-scopes (RBAC).
		// ResolveWithReport is fail-closed: any error = no scopes granted.
		report, scopeErr := ctrl.scopeResolver.ResolveWithReport(
			c.Request.Context(),
			arcCtx.TenantID, consentRequest.Subject, arcCtx.ResourceServerID,
			requestedScopes,
			rs,
			mcpClient,
		)
		if scopeErr != nil {
			log.Printf("[MCP_AUTH] ConsentHandler: ResolveWithReport failed context_id=%s: %v", arcCtx.ContextID, scopeErr)
			c.String(http.StatusInternalServerError, "Failed to resolve user permissions")
			return
		}
		// report is guaranteed non-nil past this point
		grantedScopes := report.Grantable
		if len(grantedScopes) == 0 {
			// Fail-closed: no grantable scopes → reject consent
			log.Printf("[MCP_AUTH] ConsentHandler: no grantable scopes for user=%s rs=%s context_id=%s",
				consentRequest.Subject, rs.ResourceURI, arcCtx.ContextID)
			_, rejectErr := ctrl.service.RejectHydraConsentRequest(consentChallenge, "insufficient_scope", "user has no authorized scopes for this resource server")
			if rejectErr != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: RejectHydraConsentRequest failed: %v", rejectErr)
			}
			c.String(http.StatusForbidden, "You do not have permission to access this resource server. Contact your administrator to request access.")
			return
		}

		// Check for remembered consent: if an active grant covers all requested scopes
		// and prompt != "consent", we can auto-accept without showing the consent screen.
		forceConsent := arcCtx.Prompt != nil && *arcCtx.Prompt == "consent"
		var existingGrant *models.OAuthConsentGrant
		if !forceConsent && mcpClient != nil {
			tenantUUID, _ := uuid.Parse(arcCtx.TenantID)
			subjectUUID, _ := uuid.Parse(consentRequest.Subject)
			if tenantUUID != uuid.Nil && subjectUUID != uuid.Nil {
				// Pass report.UserEffective (full RBAC set), NOT report.Grantable.
				// Using the request-scoped grantable set would falsely revoke grants covering
				// scopes the user still holds but didn't request in this particular flow.
				var stale bool
				var consentLookupErr error
				existingGrant, stale, consentLookupErr = ctrl.consentService.CheckExistingConsent(
					tenantUUID, subjectUUID, mcpClient.ID, rs.ID,
					consentRequest.RequestedScope,
					report.UserEffective,
					rs.ScopesSupported,
				)
				if consentLookupErr != nil {
					log.Printf("[MCP_AUTH] ConsentHandler: consent lookup failed user=%s rs=%s context_id=%s: %v",
						consentRequest.Subject, rs.ResourceURI, arcCtx.ContextID, consentLookupErr)
					c.String(http.StatusInternalServerError, "Failed to check existing consent")
					return
				}
				if stale {
					log.Printf("[MCP_AUTH] ConsentHandler: remembered consent revoked (stale) user=%s rs=%s",
						consentRequest.Subject, rs.ResourceURI)
				}
			}
		}

		if c.Request.Method == http.MethodGet {
			if existingGrant != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: remembered consent found grant_id=%s context_id=%s",
					existingGrant.ID, arcCtx.ContextID)
				if ctrl.finalizeMCPConsent(c, consentChallenge, consentRequest, arcCtx, rs, mcpClient, grantedScopes, true) {
					return
				}
				return
			}
			// Load scope metadata for enriched consent page rendering
			tenantUUIDForMeta, _ := uuid.Parse(arcCtx.TenantID)
			allScopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantUUIDForMeta, rs.ID)
			scopeMeta := make(map[string]*models.OAuthScope, len(allScopes))
			for i := range allScopes {
				scopeMeta[allScopes[i].ScopeString] = &allScopes[i]
			}
			ctrl.renderMCPConsentPage(c, consentChallenge, consentRequest, report, scopeMeta)
			return
		}

		if c.Request.PostForm == nil {
			c.Request.ParseForm()
		}
		if c.PostForm("action") == "deny" {
			rejectResponse, rejectErr := ctrl.service.RejectHydraConsentRequest(consentChallenge, "access_denied", "user denied consent")
			if rejectErr != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: RejectHydraConsentRequest failed consent_challenge=%s: %v", consentChallenge, rejectErr)
				c.String(http.StatusInternalServerError, "Failed to deny consent")
				return
			}
			c.Redirect(http.StatusFound, rejectResponse.RedirectTo)
			return
		}

		selectedSet := make(map[string]struct{})
		for _, scope := range c.PostFormArray("grant_scope") {
			selectedSet[scope] = struct{}{}
		}

		var selectedScopes []string
		for _, scope := range grantedScopes {
			if _, ok := selectedSet[scope]; ok {
				selectedScopes = append(selectedScopes, scope)
			}
		}

		if len(selectedScopes) == 0 {
			rejectResponse, rejectErr := ctrl.service.RejectHydraConsentRequest(consentChallenge, "access_denied", "no scopes approved")
			if rejectErr != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: RejectHydraConsentRequest(no scopes) failed consent_challenge=%s: %v", consentChallenge, rejectErr)
				c.String(http.StatusInternalServerError, "Failed to deny consent")
				return
			}
			c.Redirect(http.StatusFound, rejectResponse.RedirectTo)
			return
		}

		remember := c.PostForm("remember") != ""
		if ctrl.finalizeMCPConsent(c, consentChallenge, consentRequest, arcCtx, rs, mcpClient, selectedScopes, remember) {
			return
		}
		return
	}

	// LEGACY PATH: grant all requested scopes/audiences
	acceptResponse, err := ctrl.service.AcceptHydraConsentRequest(consentChallenge, consentRequest)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to complete consent")
		return
	}

	c.Redirect(http.StatusFound, acceptResponse.RedirectTo)
}

func (ctrl *HmgrController) finalizeMCPConsent(
	c *gin.Context,
	consentChallenge string,
	consentRequest *hydramodels.HydraConsentRequest,
	arcCtx *models.AuthRequestContext,
	rs *models.ResourceServer,
	mcpClient *models.MCPOAuthClient,
	grantedScopes []string,
	remember bool,
) bool {
	var rsPermissions []string
	for _, s := range grantedScopes {
		if !services.IsOIDCCoreScope(s) {
			rsPermissions = append(rsPermissions, s)
		}
	}

	sessionClaims := map[string]interface{}{
		"tenant_id":          arcCtx.TenantID,
		"resource_server_id": arcCtx.ResourceServerID,
		"context_id":         arcCtx.ContextID,
		"auth_time":          time.Now().Unix(),
		"permissions":        rsPermissions,
		"rs_id":              arcCtx.ResourceServerID,
	}
	if consentRequest.Context != nil {
		for _, key := range []string{"email", "email_verified", "name", "username", "avatar_url", "provider", "provider_id"} {
			if v, ok := consentRequest.Context[key]; ok {
				sessionClaims[key] = v
			}
		}
	}

	acceptResponse, err := ctrl.service.AcceptHydraConsentRequestMCP(
		consentChallenge,
		consentRequest,
		grantedScopes,
		[]string{rs.ResourceURI},
		sessionClaims,
	)
	if err != nil {
		log.Printf("[MCP_AUTH] ConsentHandler: AcceptHydraConsentRequestMCP failed consent_challenge=%s context_id=%s: %v",
			consentChallenge, arcCtx.ContextID, err)
		c.String(http.StatusInternalServerError, "Failed to complete MCP consent")
		return false
	}

	if markErr := ctrl.authzCtx.MarkConsentCompleted(arcCtx.State); markErr != nil {
		log.Printf("[MCP_AUTH] ConsentHandler: MarkConsentCompleted failed state=%s context_id=%s: %v",
			arcCtx.State, arcCtx.ContextID, markErr)
		c.String(http.StatusInternalServerError, "Failed to finalize consent — please retry the authorization flow")
		return false
	}

	if remember && mcpClient != nil {
		tenantUUID, _ := uuid.Parse(arcCtx.TenantID)
		subjectUUID, _ := uuid.Parse(consentRequest.Subject)
		if tenantUUID != uuid.Nil && subjectUUID != uuid.Nil {
			_, consentErr := ctrl.consentService.UpsertConsent(
				tenantUUID, subjectUUID, mcpClient.ID, rs.ID,
				grantedScopes, services.DefaultConsentTTL,
			)
			if consentErr != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: failed to store consent grant context_id=%s: %v",
					arcCtx.ContextID, consentErr)
			}
		}
	}

	log.Printf("[MCP_AUTH] ConsentHandler: consent completed context_id=%s client=%s rs=%s remember=%v scopes=%d",
		arcCtx.ContextID, consentRequest.Client.ClientID, rs.ResourceURI, remember, len(grantedScopes))

	c.Redirect(http.StatusFound, acceptResponse.RedirectTo)
	return true
}

func (ctrl *HmgrController) renderMCPConsentPage(
	c *gin.Context,
	consentChallenge string,
	consentRequest *hydramodels.HydraConsentRequest,
	report *services.ScopeResolutionReport,
	scopeMeta map[string]*models.OAuthScope,
) {
	// riskBadgeColor maps risk levels to their badge background colors.
	riskBadgeColor := func(level string) string {
		switch strings.ToLower(level) {
		case "low":
			return "#2e7d32"
		case "medium":
			return "#f57c00"
		case "high":
			return "#e65100"
		case "critical":
			return "#b71c1c"
		default:
			return "#66758a"
		}
	}

	// blockedReasonText returns a human-readable explanation for a block reason.
	blockedReasonText := func(reason services.BlockReason) string {
		switch reason {
		case services.BlockNotInRSSupported:
			return "This scope is not declared by the resource server."
		case services.BlockNoRBACBinding:
			return "You do not have a role binding that grants this scope."
		case services.BlockOIDCNotAllowed:
			return "OIDC scope not applicable to this client type."
		default:
			return "Not currently allowed by your administrator-assigned roles."
		}
	}

	var builder strings.Builder
	builder.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorize Access</title>")
	builder.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	builder.WriteString(`<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f7fb;color:#16202a;margin:0;padding:32px;}
main{max-width:720px;margin:0 auto;background:#fff;border:1px solid #d7deea;border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(16,24,40,.08);}
h1{margin:0 0 8px;font-size:28px;}
p{margin:0 0 16px;line-height:1.5;color:#445468;}
fieldset{border:none;padding:0;margin:20px 0;}
label.scope{display:block;border:1px solid #d7deea;border-radius:12px;padding:14px 16px;margin:0 0 12px;background:#fbfcfe;}
label.scope.blocked{opacity:.65;background:#f4f6fa;border-color:#e0e4ed;}
label.scope .scope-header{display:flex;align-items:center;gap:8px;}
label.scope strong{font-size:15px;}
label.scope .scope-desc{display:block;font-size:13px;margin-top:6px;color:#5b6978;}
label.scope .scope-blocked-reason{display:block;font-size:12px;margin-top:4px;color:#c0392b;font-style:italic;}
.risk-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap;}
input[type=checkbox]{margin-right:8px;}
.actions{display:flex;gap:12px;margin-top:24px;}
button{border:none;border-radius:10px;padding:12px 18px;font-weight:600;cursor:pointer;}
button.allow{background:#0f6fff;color:#fff;}
button.deny{background:#edf1f7;color:#16202a;}
.meta{font-size:13px;color:#66758a;margin-top:18px;}
</style></head><body><main>`)
	builder.WriteString("<h1>Authorize access</h1>")
	builder.WriteString("<p><strong>" + html.EscapeString(consentRequest.Client.ClientID) + "</strong> is requesting access to your resources.</p>")
	builder.WriteString("<form method=\"post\" action=\"/authsec/hmgr/consent\">")
	builder.WriteString("<input type=\"hidden\" name=\"consent_challenge\" value=\"" + html.EscapeString(consentChallenge) + "\">")
	builder.WriteString("<fieldset><legend>Select the permissions to grant</legend>")

	// Use report.Diagnostics as the authoritative scope list — this contains the
	// already-defaulted requestedScopes (which may be rs.ScopesSupported when the
	// client sent no scope parameter), so the consent page always shows something
	// even when consentRequest.RequestedScope is empty.
	for _, diag := range report.Diagnostics {
		scope := diag.Scope
		meta := scopeMeta[scope]

		// Display name: prefer registry metadata, fall back to raw scope string.
		displayName := scope
		if meta != nil && meta.DisplayName != "" {
			displayName = meta.DisplayName
		}

		// Description from registry metadata.
		description := ""
		if meta != nil {
			description = meta.Description
		}

		// Risk badge from registry metadata.
		riskLevel := ""
		if meta != nil {
			riskLevel = meta.RiskLevel
		}

		if diag.Granted {
			builder.WriteString(`<label class="scope">`)
			builder.WriteString(`<div class="scope-header">`)
			builder.WriteString(`<input type="checkbox" name="grant_scope" value="` + html.EscapeString(scope) + `" checked>`)
			builder.WriteString(`<strong>` + html.EscapeString(displayName) + `</strong>`)
			if riskLevel != "" {
				color := riskBadgeColor(riskLevel)
				builder.WriteString(` <span class="risk-badge" style="background:` + color + `">` + html.EscapeString(riskLevel) + `</span>`)
			}
			builder.WriteString(`</div>`)
			if description != "" {
				builder.WriteString(`<span class="scope-desc">` + html.EscapeString(description) + `</span>`)
			}
			builder.WriteString(`</label>`)
		} else {
			builder.WriteString(`<label class="scope blocked">`)
			builder.WriteString(`<div class="scope-header">`)
			builder.WriteString(`<input type="checkbox" disabled>`)
			builder.WriteString(`<strong>` + html.EscapeString(displayName) + `</strong>`)
			if riskLevel != "" {
				color := riskBadgeColor(riskLevel)
				builder.WriteString(` <span class="risk-badge" style="background:` + color + `">` + html.EscapeString(riskLevel) + `</span>`)
			}
			builder.WriteString(`</div>`)
			if description != "" {
				builder.WriteString(`<span class="scope-desc">` + html.EscapeString(description) + `</span>`)
			}
			builder.WriteString(`<span class="scope-blocked-reason">` + html.EscapeString(blockedReasonText(diag.Reason)) + `</span>`)
			builder.WriteString(`</label>`)
		}
	}

	builder.WriteString("</fieldset>")
	builder.WriteString(`<label class="scope"><div class="scope-header"><input type="checkbox" name="remember" value="true" checked><strong>Remember this decision for 30 days</strong></div><span class="scope-desc">Clearing this stores nothing beyond the current OAuth transaction.</span></label>`)
	builder.WriteString(`<div class="actions"><button class="allow" type="submit" name="action" value="allow">Allow selected</button><button class="deny" type="submit" name="action" value="deny">Deny</button></div>`)
	builder.WriteString(`<p class="meta">Only the checked scopes will be granted to this client.</p>`)
	builder.WriteString("</form></main></body></html>")

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(builder.String()))
}

// HealthHandler provides a health check endpoint
func (ctrl *HmgrController) HealthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"status":          "healthy",
		"service":         "oauth-login-service-api",
		"timestamp":       time.Now(),
		"hydra_admin_url": config.AppConfig.HydraAdminURL,
		"base_url":        config.AppConfig.BaseURL,
		"react_app_url":   config.AppConfig.ReactAppURL,
		"ui_origin":       config.AppConfig.UIOrigin,
		"ui_base_path":    config.AppConfig.UIBasePath,
	})
}

// LoginChallengeHandler handles login challenge queries
func (ctrl *HmgrController) LoginChallengeHandler(c *gin.Context) {
	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.String(http.StatusBadRequest, "Missing login_challenge parameter")
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(loginChallenge)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get login request")
		return
	}

	c.JSON(http.StatusOK, loginRequest.Client)
}

// GenerateLoginURLHandler generates a login URL for testing
func (ctrl *HmgrController) GenerateLoginURLHandler(c *gin.Context) {
	var req struct {
		TenantID    string `json:"tenant_id"`
		OrgID       string `json:"org_id"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.String(http.StatusBadRequest, "Invalid JSON")
		return
	}

	clients, err := ctrl.service.GetAllHydraClients()
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get clients")
		return
	}

	var tenantClientID string
	for _, client := range clients {
		if tenantID, ok := client.Metadata["tenant_id"].(string); ok && tenantID == req.TenantID {
			if orgID, ok := client.Metadata["org_id"].(string); ok && orgID == req.OrgID {
				if clientType, ok := client.Metadata["type"].(string); ok && clientType == "tenant_main_client" {
					tenantClientID = client.ClientID
					break
				}
			}
		}
	}

	if tenantClientID == "" {
		c.String(http.StatusNotFound, "Tenant client not found")
		return
	}

	codeVerifier := hydrautils.GenerateCodeVerifier()
	codeChallenge := hydrautils.GenerateCodeChallenge(codeVerifier)

	// Store code_verifier server-side, keyed by state.
	// The state value will be echoed back in the exchange-token request, allowing
	// retrieval at token exchange time without ever exposing the verifier to the client.
	if req.State != "" {
		storePKCEVerifier(req.State, codeVerifier)
	}

	hydraAuthURL := strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/") + "/oauth2/auth"
	if config.AppConfig.OAuthAuthURL != "" {
		hydraAuthURL = config.AppConfig.OAuthAuthURL
	}
	oauthURL := fmt.Sprintf("%s?client_id=%s&response_type=code&scope=openid+profile+email&redirect_uri=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		hydraAuthURL,
		tenantClientID,
		url.QueryEscape(req.RedirectURI),
		req.State,
		codeChallenge,
	)

	c.JSON(http.StatusOK, map[string]interface{}{
		"success":          true,
		"tenant_client_id": tenantClientID,
		"oauth_url":        oauthURL,
		"login_endpoint":   fmt.Sprintf("%s/login", config.AppConfig.BaseURL),
		"react_login_url":  config.AppConfig.BuildUIRouteURL("/oidc/login", nil),
	})
}

// --- SAML Handlers ---

// InitiateSAMLAuthHandler initiates SAML authentication with a provider
func (ctrl *HmgrController) InitiateSAMLAuthHandler(c *gin.Context) {
	providerName := c.Param("provider")

	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.SAMLInitiateResponse{Success: false, Error: "Invalid request: " + err.Error()})
		return
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.SAMLInitiateResponse{Success: false, Error: "Failed to get login request"})
		return
	}

	clientDetails, _, err := ctrl.service.GetHydraClient(loginRequest.Client.ClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, hydramodels.SAMLInitiateResponse{Success: false, Error: "Client not found"})
		return
	}

	realTenantID, _ := clientDetails.Metadata["c_id"].(string)
	if realTenantID == "" {
		c.JSON(http.StatusBadRequest, hydramodels.SAMLInitiateResponse{Success: false, Error: "Invalid client configuration - missing c_id"})
		return
	}

	clientID := loginRequest.Client.ClientID
	samlProvider, err := ctrl.service.GetSAMLProvider(realTenantID, providerName, clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, hydramodels.SAMLInitiateResponse{Success: false, Error: "SAML provider not found: " + err.Error()})
		return
	}

	if !samlProvider.IsActive {
		c.JSON(http.StatusBadRequest, hydramodels.SAMLInitiateResponse{Success: false, Error: "Provider is not active"})
		return
	}

	samlRequest, relayState, err := ctrl.service.CreateSAMLRequest(samlProvider, req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.SAMLInitiateResponse{Success: false, Error: "Failed to create SAML request"})
		return
	}

	ssoURL := fmt.Sprintf("%s?SAMLRequest=%s&RelayState=%s",
		samlProvider.SSOURL,
		url.QueryEscape(samlRequest),
		url.QueryEscape(relayState),
	)

	c.JSON(http.StatusOK, hydramodels.SAMLInitiateResponse{
		Success:     true,
		SSOURL:      ssoURL,
		SAMLRequest: samlRequest,
		RelayState:  relayState,
		Provider:    providerName,
	})
}

// HandleSAMLACSHandler handles SAML Assertion Consumer Service (ACS) callback
func (ctrl *HmgrController) HandleSAMLACSHandler(c *gin.Context) {
	var req hydramodels.SAMLCallbackRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	if req.SAMLResponse == "" || req.RelayState == "" {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Missing required SAML parameters"})
		return
	}

	assertion, loginChallenge, providerName, tenantID, _, err := ctrl.service.ValidateSAMLResponse(req.SAMLResponse, req.RelayState)
	if err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	redirectTo, user, err := ctrl.ProcessSAMLAssertion(assertion, loginChallenge, providerName, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Authentication processing failed: " + err.Error()})
		return
	}

	parsedURL, err := url.Parse(redirectTo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Failed to generate redirect URL"})
		return
	}

	redirectURI := parsedURL.Query().Get("redirect_uri")
	if redirectURI == "" {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid OAuth redirect URL"})
		return
	}

	query := url.Values{}
	query.Set("login_challenge", loginChallenge)
	query.Set("success", "true")
	query.Set("user_id", user.ID.String())
	query.Set("user_email", user.Email)
	query.Set("user_name", user.Name)
	query.Set("provider", user.Provider)
	query.Set("client_id", user.ClientID.String())
	query.Set("tenant_id", user.TenantID.String())
	query.Set("project_id", user.ProjectID.String())
	query.Set("provider_id", user.ProviderID)
	query.Set("active", fmt.Sprintf("%t", user.Active))

	redirectURL, err := config.BuildUIRouteURLFromRedirectURI(redirectURI, "/oidc/login", query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Failed to build frontend redirect URL"})
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authentication Successful</title></head><body><p>Authentication successful. Redirecting...</p><script>window.location.href = "%s";</script><noscript><a href="%s">Click here to continue</a></noscript></body></html>`, redirectURL, redirectURL))
}

// HandleSAMLACSClientHandler handles client-specific ACS callback
func (ctrl *HmgrController) HandleSAMLACSClientHandler(c *gin.Context) {
	tenantIDParam := c.Param("tenant_id")
	clientIDParam := c.Param("client_id")

	var req hydramodels.SAMLCallbackRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	if req.SAMLResponse == "" {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Missing SAMLResponse"})
		return
	}

	assertion, loginChallenge, providerName, tenantID, clientID, err := ctrl.service.ValidateSAMLResponse(req.SAMLResponse, req.RelayState)
	if err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	if tenantIDParam != tenantID {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Tenant ID mismatch"})
		return
	}
	if clientIDParam != clientID {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Client ID mismatch"})
		return
	}

	redirectTo, user, err := ctrl.ProcessSAMLAssertion(assertion, loginChallenge, providerName, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Authentication processing failed: " + err.Error()})
		return
	}

	parsedURL, err := url.Parse(redirectTo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Failed to generate redirect URL"})
		return
	}

	redirectURI := parsedURL.Query().Get("redirect_uri")
	if redirectURI == "" {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid OAuth redirect URL"})
		return
	}

	query := url.Values{}
	query.Set("login_challenge", loginChallenge)
	query.Set("success", "true")
	query.Set("user_id", user.ID.String())
	query.Set("user_email", user.Email)
	query.Set("user_name", user.Name)
	query.Set("provider", user.Provider)
	query.Set("client_id", user.ClientID.String())
	query.Set("tenant_id", user.TenantID.String())
	query.Set("project_id", user.ProjectID.String())
	query.Set("provider_id", user.ProviderID)
	query.Set("active", fmt.Sprintf("%t", user.Active))

	redirectURL, err := config.BuildUIRouteURLFromRedirectURI(redirectURI, "/oidc/login", query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.CallbackValidationResponse{Success: false, Error: "Failed to build frontend redirect URL"})
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authentication Successful</title></head><body><p>Authentication successful. Redirecting...</p><script>window.location.href = "%s";</script><noscript><a href="%s">Click here to continue</a></noscript></body></html>`, redirectURL, redirectURL))
}

// ProcessSAMLAssertion processes a SAML assertion and creates/updates user
func (ctrl *HmgrController) ProcessSAMLAssertion(assertion *hydramodels.SAMLAssertion, loginChallenge, providerName, tenantID string) (string, *hydramodels.User, error) {
	if err := hydrautils.ValidateEmail(assertion.Email); err != nil {
		return "", nil, fmt.Errorf("invalid SAML email: %w", err)
	}

	firstName, err := hydrautils.ValidateSAMLAttribute(assertion.FirstName, "FirstName", 100)
	if err != nil {
		return "", nil, fmt.Errorf("invalid first name: %w", err)
	}

	lastName, err := hydrautils.ValidateSAMLAttribute(assertion.LastName, "LastName", 100)
	if err != nil {
		return "", nil, fmt.Errorf("invalid last name: %w", err)
	}

	nameID, err := hydrautils.SanitizeString(assertion.NameID, 255)
	if err != nil {
		return "", nil, fmt.Errorf("invalid NameID: %w", err)
	}
	if nameID == "" {
		return "", nil, fmt.Errorf("NameID cannot be empty")
	}

	loginRequest, err := ctrl.service.GetHydraLoginRequest(loginChallenge)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get login request: %w", err)
	}

	clientDetails, _, err := ctrl.service.GetHydraClient(loginRequest.Client.ClientID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get client details: %w", err)
	}

	clientIDFromMetadata, _ := clientDetails.Metadata["tenant_id"].(string)
	realTenantID, _ := clientDetails.Metadata["c_id"].(string)

	if realTenantID != tenantID {
		return "", nil, fmt.Errorf("tenant ID mismatch: expected %s, got %s", realTenantID, tenantID)
	}

	name := fmt.Sprintf("%s %s", firstName, lastName)
	if name == " " || name == "" {
		name = assertion.Email
	}
	name, err = hydrautils.ValidateName(name)
	if err != nil {
		return "", nil, fmt.Errorf("invalid user name: %w", err)
	}

	username := assertion.Email
	if strings.Contains(username, "@") {
		username = strings.Split(username, "@")[0]
	}

	parsedTenantID, err := hydrautils.ValidateUUID(realTenantID, "tenant_id")
	if err != nil {
		return "", nil, err
	}

	parsedClientID, err := hydrautils.ValidateUUID(clientIDFromMetadata, "client_id")
	if err != nil {
		return "", nil, err
	}

	user := &hydramodels.User{
		Email:      assertion.Email,
		Username:   &username,
		Name:       name,
		Provider:   "saml-" + providerName,
		ProviderID: nameID,
		ClientID:   parsedClientID,
		TenantID:   parsedTenantID,
		Active:     true,
	}

	user, err = ctrl.service.CreateOrUpdateUser("", user)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	userID := fmt.Sprintf("saml-%s-%s", providerName, nameID)
	acceptResponse, err := ctrl.service.AcceptHydraLoginRequestWithContext(loginChallenge, userID, map[string]interface{}{
		"email":       user.Email,
		"name":        user.Name,
		"username":    user.Username,
		"provider":    user.Provider,
		"provider_id": user.ProviderID,
		"tenant_id":   user.TenantID,
		"client_id":   user.ClientID,
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to accept login request: %w", err)
	}

	return acceptResponse.RedirectTo, user, nil
}

// GetSAMLMetadataHandler returns SP metadata for a tenant and client
func (ctrl *HmgrController) GetSAMLMetadataHandler(c *gin.Context) {
	tenantIDStr := c.Param("tenant_id")
	clientIDStr := c.Param("client_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid tenant_id format"})
		return
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid client_id format"})
		return
	}

	metadata, err := ctrl.service.GenerateSAMLMetadata(tenantID, clientID)
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Failed to generate metadata"})
		return
	}

	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, metadata)
}

// CreateSAMLProviderHandler creates a new SAML provider
func (ctrl *HmgrController) CreateSAMLProviderHandler(c *gin.Context) {
	var req hydramodels.SAMLProviderConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request: " + err.Error()})
		return
	}

	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Missing tenant_id"})
		return
	}

	clientIDStr := c.GetString("client_id")
	if clientIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Missing client_id"})
		return
	}

	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid client_id format"})
		return
	}

	attributeMapping, _ := json.Marshal(req.AttributeMapping)
	provider := &hydramodels.SAMLProvider{
		ClientID:         clientID,
		ProviderName:     req.ProviderName,
		DisplayName:      req.DisplayName,
		EntityID:         req.EntityID,
		SSOURL:           req.SSOURL,
		SLOURL:           req.SLOURL,
		Certificate:      req.Certificate,
		MetadataURL:      req.MetadataURL,
		NameIDFormat:     req.NameIDFormat,
		AttributeMapping: attributeMapping,
		IsActive:         req.IsActive,
		SortOrder:        req.SortOrder,
	}

	createdProvider, err := ctrl.service.CreateSAMLProvider(tenantID, provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to create SAML provider: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "provider": createdProvider})
}

// UpdateSAMLProviderHandler updates an existing SAML provider
func (ctrl *HmgrController) UpdateSAMLProviderHandler(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid provider ID"})
		return
	}

	var req hydramodels.SAMLProviderConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request: " + err.Error()})
		return
	}

	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		tenantID = c.GetHeader("X-Tenant-ID")
	}
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Missing tenant_id"})
		return
	}

	clientID := c.Query("client_id")
	attributeMapping, _ := json.Marshal(req.AttributeMapping)
	updates := &hydramodels.SAMLProvider{
		ProviderName:     req.ProviderName,
		DisplayName:      req.DisplayName,
		EntityID:         req.EntityID,
		SSOURL:           req.SSOURL,
		SLOURL:           req.SLOURL,
		Certificate:      req.Certificate,
		MetadataURL:      req.MetadataURL,
		NameIDFormat:     req.NameIDFormat,
		AttributeMapping: attributeMapping,
		IsActive:         req.IsActive,
		SortOrder:        req.SortOrder,
	}

	updatedProvider, err := ctrl.service.UpdateSAMLProvider(tenantID, providerID, clientID, updates)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to update SAML provider: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "provider": updatedProvider})
}

// DeleteSAMLProviderHandler deletes a SAML provider
func (ctrl *HmgrController) DeleteSAMLProviderHandler(c *gin.Context) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid provider ID"})
		return
	}

	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		tenantID = c.GetHeader("X-Tenant-ID")
	}
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Missing tenant_id"})
		return
	}

	clientID := c.Query("client_id")
	if err := ctrl.service.DeleteSAMLProvider(tenantID, providerID, clientID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to delete SAML provider: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "SAML provider deleted successfully"})
}

// GetSAMLProvidersHandler lists all SAML providers for a tenant
func (ctrl *HmgrController) GetSAMLProvidersHandler(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		tenantID = c.GetHeader("X-Tenant-ID")
	}
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Missing tenant_id"})
		return
	}

	clientID := c.Query("client_id")
	providers, err := ctrl.service.GetSAMLProvidersForTenant(tenantID, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to get SAML providers: " + err.Error()})
		return
	}

	response := gin.H{
		"success":   true,
		"providers": providers,
		"count":     len(providers),
		"tenant_id": tenantID,
	}
	if clientID != "" {
		response["filtered_by_client_id"] = clientID
	}

	c.JSON(http.StatusOK, response)
}

// TestSAMLProviderHandler tests SAML provider configuration
func (ctrl *HmgrController) TestSAMLProviderHandler(c *gin.Context) {
	var req struct {
		TenantID     string `json:"tenant_id" binding:"required"`
		ProviderName string `json:"provider_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid request: " + err.Error()})
		return
	}

	provider, err := ctrl.service.GetSAMLProvider(req.TenantID, req.ProviderName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Provider not found: " + err.Error()})
		return
	}

	cfg := ctrl.service.GetConfig()
	metadataURL := fmt.Sprintf("%s/saml/metadata/%s/%s", cfg.BaseURL, provider.TenantID.String(), provider.ClientID.String())
	acsURLShared := fmt.Sprintf("%s/saml/acs", cfg.BaseURL)
	acsURLClient := fmt.Sprintf("%s/saml/acs/%s/%s", cfg.BaseURL, provider.TenantID.String(), provider.ClientID.String())

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"provider": gin.H{
			"name":         provider.ProviderName,
			"display_name": provider.DisplayName,
			"entity_id":    provider.EntityID,
			"sso_url":      provider.SSOURL,
			"is_active":    provider.IsActive,
			"client_id":    provider.ClientID.String(),
		},
		"sp_metadata_url": metadataURL,
		"acs_url_client":  acsURLClient,
		"acs_url_shared":  acsURLShared,
	})
}

// --- Admin stub handlers ---

func (ctrl *HmgrController) GetUsersHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "GetUsers endpoint - to be implemented", "users": []interface{}{}})
}
func (ctrl *HmgrController) CreateUserHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "CreateUser endpoint - to be implemented"})
}
func (ctrl *HmgrController) UpdateUserHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "UpdateUser endpoint - to be implemented", "user_id": c.Param("id")})
}
func (ctrl *HmgrController) DeleteUserHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "DeleteUser endpoint - to be implemented", "user_id": c.Param("id")})
}
func (ctrl *HmgrController) GetTenantsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "GetTenants endpoint - to be implemented", "tenants": []interface{}{}})
}
func (ctrl *HmgrController) CreateTenantHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "CreateTenant endpoint - to be implemented"})
}
func (ctrl *HmgrController) UpdateTenantHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "UpdateTenant endpoint - to be implemented", "tenant_id": c.Param("id")})
}
func (ctrl *HmgrController) DeleteTenantHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "DeleteTenant endpoint - to be implemented", "tenant_id": c.Param("id")})
}
func (ctrl *HmgrController) GetRolesHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "GetRoles endpoint - to be implemented", "roles": []interface{}{}})
}
func (ctrl *HmgrController) CreateRoleHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "CreateRole endpoint - to be implemented"})
}
func (ctrl *HmgrController) UpdateRoleHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "UpdateRole endpoint - to be implemented", "role_id": c.Param("id")})
}
func (ctrl *HmgrController) DeleteRoleHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "DeleteRole endpoint - to be implemented", "role_id": c.Param("id")})
}
func (ctrl *HmgrController) GetPermissionsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "GetPermissions endpoint - to be implemented", "permissions": []interface{}{}})
}
func (ctrl *HmgrController) CreatePermissionHandler(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{"message": "CreatePermission endpoint - to be implemented"})
}
func (ctrl *HmgrController) AssignUserRoleHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "AssignUserRole endpoint - to be implemented", "user_id": c.Param("id")})
}
func (ctrl *HmgrController) RemoveUserRoleHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "RemoveUserRole endpoint - to be implemented", "user_id": c.Param("id"), "role_id": c.Param("role_id")})
}
func (ctrl *HmgrController) GetProfileHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "GetProfile endpoint - to be implemented", "profile": map[string]interface{}{}})
}
func (ctrl *HmgrController) UpdateProfileHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "UpdateProfile endpoint - to be implemented"})
}

// extractClaimsFromIDToken decodes a JWT id_token without signature verification
// and returns its claims as a map. Used as a fallback when the userinfo endpoint
// is unavailable (e.g. Microsoft Graph 403 due to missing User.Read permission).
func extractClaimsFromIDToken(idToken string) (map[string]interface{}, error) {
	parts := strings.SplitN(idToken, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode id_token payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal id_token claims: %w", err)
	}
	return claims, nil
}

// --- Helper functions ---

func hmgrReplaceRedirectDomain(redirectURL, newDomain string) string {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return redirectURL
	}
	normalizedDomain := hmgrNormalizeHost(newDomain)
	if normalizedDomain == "" {
		return redirectURL
	}
	u.Host = normalizedDomain
	if !strings.Contains(normalizedDomain, "localhost") && !strings.Contains(normalizedDomain, "127.0.0.1") {
		u.Scheme = "https"
	}
	return u.String()
}

func hmgrGetSafeOriginDomainForRedirect(redirectURL, originDomain string) string {
	normalizedOrigin := hmgrNormalizeHost(originDomain)
	if normalizedOrigin == "" {
		return ""
	}

	u, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	redirectURIParam := u.Query().Get("redirect_uri")
	if redirectURIParam != "" {
		parsedRedirectURI, err := url.Parse(redirectURIParam)
		if err != nil {
			return ""
		}
		redirectURIHost := hmgrNormalizeHost(parsedRedirectURI.Host)
		if redirectURIHost == "" || !strings.EqualFold(redirectURIHost, normalizedOrigin) {
			return ""
		}
	}
	return normalizedOrigin
}

func hmgrNormalizeHost(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		if parsed, err := url.Parse(v); err == nil {
			v = parsed.Host
		}
	}
	if strings.Contains(v, "/") {
		if parsed, err := url.Parse("https://" + v); err == nil {
			v = parsed.Host
		}
	}
	return strings.TrimSpace(v)
}
