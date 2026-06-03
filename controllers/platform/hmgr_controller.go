package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/clients"
	"github.com/authsec-ai/authsec/config"
	hydramodels "github.com/authsec-ai/authsec/internal/hydra/models"
	hydrautils "github.com/authsec-ai/authsec/internal/hydra/utils"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// StorePKCEVerifier saves a code verifier to the database, keyed by state or
// login_challenge. Database-backed (table mcp_pkce_verifiers): survives restarts
// and works in multi-instance deployments. TTL: 30 minutes.
//
// Exported so other controllers in this package (e.g. oidc_controller) can
// call it directly during the OAuth authorize step.
func StorePKCEVerifier(key, codeVerifier string) {
	log.Printf("[hmgr] PKCE store: key=%q verifier_len=%d", key, len(codeVerifier))
	v := models.PKCEVerifier{
		Key:       key,
		Verifier:  codeVerifier,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	// Upsert: overwrite if key already exists (e.g. page retry).
	config.DB.Where("key = ?", key).Assign(v).FirstOrCreate(&v)
}

// consumePKCEVerifier retrieves and deletes the stored code verifier from the database.
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
	service           *hydramodels.OAuthLoginService
	authzCtx          *services.AuthorizationContextService
	rsService         *services.ResourceServerService
	onboardingService *services.ResourceServerOnboardingService
	scopeResolver     *services.ScopeResolver
	consentService    *services.ConsentService
	scopeRegistry     *services.ScopeRegistryService
	// oidcSvc is the v4 OIDC service. InitiateAuthHandler delegates the
	// upstream-IdP redirect logic here so we use the workspace gate, signed
	// state, Vault-backed secrets, and PKCE on the upstream IdP — all the
	// security guarantees that the deleted v3 hmgr code never had.
	oidcSvc       *services.OIDCService
	billingClient *clients.BillingClient // nil-safe; no-op when BILLING_SERVICE_URL unset
}

// NewHmgrController creates a new HmgrController
func NewHmgrController(cfg config.Config) *HmgrController {
	return &HmgrController{
		service:           hydramodels.NewOAuthLoginService(cfg),
		authzCtx:          services.NewAuthorizationContextService(config.DB),
		rsService:         services.NewResourceServerService(config.DB),
		onboardingService: services.NewResourceServerOnboardingService(config.DB),
		scopeResolver:     services.NewScopeResolver(config.DB),
		consentService:    services.NewConsentService(config.DB),
		scopeRegistry:     services.NewScopeRegistryService(config.DB),
		oidcSvc:           services.NewOIDCService(config.GetDatabase()),
		billingClient:     clients.NewBillingClient(cfg.BillingServiceURL, cfg.JWTSdkSecret),
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
	StorePKCEVerifier(req.State, req.CodeVerifier)
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
	workspaceID := claimString(userClaims, "workspace_id", "")
	projectID := claimString(userClaims, "project_id", "")

	if userID == "" || email == "" || workspaceID == "" {
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
	expectedClientID := hydraClientID
	expectedTenantID := workspaceID
	var mcpAuthCtx *models.AuthRequestContext

	arcCtx, arcErr := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(req.LoginChallenge)
	if arcErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "failed to resolve MCP auth context",
		})
		return
	}
	if !strings.EqualFold(arcCtx.WorkspaceID, workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "user token tenant does not match login challenge tenant",
		})
		return
	}
	mcpAuthCtx = arcCtx
	expectedTenantID = arcCtx.WorkspaceID

	tenantDB := config.DB

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
		"email":        user.Email,
		"name":         user.Name,
		"username":     username,
		"provider":     user.Provider,
		"provider_id":  user.ProviderID,
		"workspace_id": user.WorkspaceID,
		"project_id":   user.ProjectID,
		"client_id":    expectedClientID,
		"avatar_url":   user.AvatarURL,
		"auth_method":  "password",
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
		"workspace_id":    expectedTenantID,
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

		tenantIDForOIDC := arcCtx.WorkspaceID

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
		allProviders, err = ctrl.service.FilterProvidersForApplication(tenantIDForOIDC, arcCtx.ResourceServerID, allProviders)
		if err != nil {
			log.Printf("[MCP_AUTH] GetLoginPageData: filter application providers workspace=%s application=%s challenge=%s: %v",
				tenantIDForOIDC, arcCtx.ResourceServerID, loginChallenge, err)
			c.JSON(http.StatusInternalServerError, hydramodels.LoginPageDataResponse{
				Success: false,
				Error:   "Failed to load application identity providers",
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
			// WorkspaceID is the real workspace resolved from the login_challenge
			// via the auth_request_context. ClientID is the OAuth client (display
			// only) — no longer overloaded to carry the workspace.
			WorkspaceID:       tenantIDForOIDC,
			ClientID:          hydraClientID,
			Success:           true,
			LoginChallenge:    loginChallenge,
			TenantName:        rsName,
			ClientName:        rsName,
			ClientType:        "mcp_dynamic_client",
			Providers:         oidcProviders,
			BaseURL:           config.AppConfig.BaseURL,
			LocalLoginEnabled: true,
		})
		return
	}

	c.JSON(http.StatusNotFound, hydramodels.LoginPageDataResponse{
		Success: false,
		Error:   "Client not found",
	})
}

// InitiateAuthHandler is the thin v4 entry shim for end-user OIDC logins
// driven by a Hydra login_challenge.
//
// It resolves the workspace (and optional Application) from the
// AuthRequestContext bound to the login_challenge, then delegates to
// services.OIDCService.InitiateOIDCFlow with Action="hydra_login" so the
// callback at /authsec/uflow/oidc/callback can call Hydra accept-login at
// the end of the flow. The v4 service enforces the workspace gate, the
// optional Application policy, HMAC-signed state, PKCE on the upstream
// IdP, and Vault-backed client_secret.
//
// All legacy code (Hydra-client-metadata provider lookup, base64 plaintext
// state, DB-stored client_secret) has been deleted.
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

	// Preserve the PKCE verifier the SPA stashed against the Hydra
	// login_challenge — the token-exchange path still needs it.
	if req.CodeVerifier != "" {
		StorePKCEVerifier(req.LoginChallenge, req.CodeVerifier)
	}

	// Resolve workspace + optional Application from the auth context. The
	// GetLoginPageDataHandler already bound the context to this challenge.
	arcCtx, err := ctrl.authzCtx.GetAuthRequestContextByLoginChallenge(req.LoginChallenge)
	if err != nil || arcCtx == nil {
		c.JSON(http.StatusNotFound, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Auth context not found for login_challenge",
		})
		return
	}
	workspaceID, parseErr := uuid.Parse(arcCtx.WorkspaceID)
	if parseErr != nil {
		c.JSON(http.StatusInternalServerError, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   "Invalid workspace ID on auth context",
		})
		return
	}
	var appID *uuid.UUID
	if arcCtx.ResourceServerID != "" {
		if id, perr := uuid.Parse(arcCtx.ResourceServerID); perr == nil && id != uuid.Nil {
			appID = &id
		}
	}

	// Stash the request origin on the v4 service so it lands on OIDCState
	// for the eventual post-auth redirect.
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
		originDomain = c.Request.Host
	}
	ctrl.oidcSvc.SetRequestOrigin(originDomain)

	// Delegate to the v4 service. Action="hydra_login" tells the callback at
	// /authsec/uflow/oidc/callback to accept the Hydra challenge and 302
	// the browser to whatever URL Hydra returns (typically back to the
	// OAuth client app's redirect_uri with an authorization code).
	resp, err := ctrl.oidcSvc.InitiateOIDCFlow(&models.OIDCInitiateInput{
		Provider:       providerName,
		TenantDomain:   originDomain,
		ApplicationID:  appID,
		LoginChallenge: req.LoginChallenge,
	}, "hydra_login", &workspaceID)
	if err != nil {
		// Workspace gate or Application policy rejected. Surface as 403 so
		// the UI's catch block shows the right error to the user.
		c.JSON(http.StatusForbidden, hydramodels.AuthInitiateResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, hydramodels.AuthInitiateResponse{
		Success:  true,
		AuthURL:  resp.RedirectURL,
		State:    resp.State,
		Provider: providerName,
	})
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

	// Phase B/E: the legacy `clients` table lookup (for project_id) was removed.
	// The OAuth client secret lives in Vault at kv/data/secret/{workspace}/{workspace};
	// orgID (Hydra client metadata c_id) is the workspace UUID.
	clientSecret, err := config.SecretInVault(orgID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Failed to retrieve client secret"})
		return
	}

	// Retrieve the stored PKCE code_verifier.
	// Priority order:
	//   1. Stored by state from the exchange request
	//   2. Stored by login_challenge (server-side flows)
	//   3. Stored by the original state from the Hydra request_url (cross-origin fallback)
	//   4. Client-supplied in the request body
	codeVerifier := consumePKCEVerifier(req.State)
	if codeVerifier == "" {
		codeVerifier = consumePKCEVerifier(req.LoginChallenge)
	}
	if codeVerifier == "" {
		if reqURL := loginRequest.RequestURL; reqURL != "" {
			if parsed, parseErr := url.Parse(reqURL); parseErr == nil {
				if origState := parsed.Query().Get("state"); origState != "" && origState != req.State {
					codeVerifier = consumePKCEVerifier(origState)
				}
			}
		}
	}
	if codeVerifier == "" {
		codeVerifier = req.CodeVerifier
	}
	log.Printf("[hmgr] PKCE final: verifier len=%d (state=%q)", len(codeVerifier), req.State)

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

	if tenantIDObj, ok := clientDetails.Metadata["workspace_id"].(string); ok && tenantIDObj != "" {
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

		// State gate (correctness fix #4): refuse consent for any RS that isn't
		// 'ready'. Without this guard, needs_setup / scan_failed / pending_scan
		// RSes still reach scope resolution and emit a cryptic
		// "insufficient_scope" rejection, hiding the actual cause from the user.
		// Empty state is treated as ready for back-compat with rows predating
		// the state column.
		if rs.State != "" && rs.State != models.RSStateReady {
			log.Printf("[MCP_AUTH] ConsentHandler: rs not ready state=%s rs_id=%s context_id=%s",
				rs.State, rs.ID, arcCtx.ContextID)
			_, rejectErr := ctrl.service.RejectHydraConsentRequest(consentChallenge,
				"service_not_yet_activated",
				fmt.Sprintf("Resource server %s has not completed setup (state: %s).", rs.Name, rs.State))
			if rejectErr != nil {
				log.Printf("[MCP_AUTH] ConsentHandler: RejectHydraConsentRequest(state) failed: %v", rejectErr)
			}
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusForbidden, `<!doctype html>
<html><head><title>Service not activated</title></head>
<body style="font-family:system-ui;max-width:560px;margin:80px auto;padding:0 16px;line-height:1.5">
  <h1 style="margin:0 0 8px;font-size:20px">Service not yet activated</h1>
  <p><strong>%s</strong> has not completed setup.</p>
  <p style="color:#666">Current state: <code>%s</code>. Please contact your administrator to complete activation.</p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="color:#999;font-size:13px">AuthSec did not issue a token for this request.</p>
</body></html>`, rs.Name, rs.State)
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

		if applied, bindErr := ctrl.onboardingService.EnsureDefaultAccessBinding(
			c.Request.Context(),
			consentRequest.Subject,
			arcCtx.WorkspaceID,
			rs,
		); bindErr != nil {
			// Default access binding is best-effort. EnsureDefaultAccessBinding
			// already logs and downgrades soft failures (missing role, user
			// lookup, etc.) to nil error. Any error reaching here is unexpected
			// — log and continue rather than 500 the consent flow. The downstream
			// scope resolver will either find the user's existing bindings and
			// grant them, or correctly reject with insufficient_scope.
			log.Printf("[MCP_AUTH] ConsentHandler: EnsureDefaultAccessBinding errored context_id=%s rs=%s: %v — proceeding without auto-bind",
				arcCtx.ContextID, rs.ResourceURI, bindErr)
		} else if applied {
			log.Printf("[MCP_AUTH] ConsentHandler: default access binding created user=%s rs=%s context_id=%s",
				consentRequest.Subject, rs.ResourceURI, arcCtx.ContextID)
		}

		// 3-way intersection: requested ∩ RS-supported ∩ user-effective-scopes (RBAC).
		// ResolveWithReport is fail-closed: any error = no scopes granted.
		report, scopeErr := ctrl.scopeResolver.ResolveWithReport(
			c.Request.Context(),
			arcCtx.WorkspaceID, consentRequest.Subject, arcCtx.ResourceServerID,
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
			tenantUUID, _ := uuid.Parse(arcCtx.WorkspaceID)
			subjectUUID, _ := uuid.Parse(consentRequest.Subject)
			if tenantUUID != uuid.Nil && subjectUUID != uuid.Nil {
				// Pass report.UserEffective (full RBAC set), NOT report.Grantable.
				// Using the request-scoped grantable set would falsely revoke grants covering
				// scopes the user still holds but didn't request in this particular flow.
				var stale bool
				var consentLookupErr error
				// Correctness fix #6: pass the *defaulted* requestedScopes (not
				// consentRequest.RequestedScope), otherwise an empty original
				// request matches narrow stored grants while finalize will grant
				// the full defaulted set — silent overgrant. With requestedScopes,
				// the lookup must find a stored grant covering the same effective
				// scope set that finalize will issue.
				existingGrant, stale, consentLookupErr = ctrl.consentService.CheckExistingConsent(
					tenantUUID, subjectUUID, mcpClient.ID, rs.ID,
					requestedScopes,
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
			tenantUUIDForMeta, _ := uuid.Parse(arcCtx.WorkspaceID)
			allScopes, _ := ctrl.scopeRegistry.ListByResourceServer(tenantUUIDForMeta, rs.ID)
			scopeMeta := make(map[string]*models.OAuthScope, len(allScopes))
			for i := range allScopes {
				scopeMeta[allScopes[i].ScopeString] = &allScopes[i]
			}
			// Override the default consent CSP to include the OAuth client's registered
			// redirect_uri origins. Browsers enforce form-action across the entire
			// redirect chain, and the final hop after consent goes to the client
			// redirect_uri (e.g. https://aditya.mcpauthz.com/applications/.../test).
			// Without this, the consent form submit is blocked.
			c.Header("Content-Security-Policy", middlewares.BuildConsentCSP(redirectURIOriginsFromClient(mcpClient)))
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
		"workspace_id":       arcCtx.WorkspaceID,
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

	tenantUUID, _ := uuid.Parse(arcCtx.WorkspaceID)
	subjectUUID, _ := uuid.Parse(consentRequest.Subject)
	if tenantUUID != uuid.Nil && subjectUUID != uuid.Nil {
		now := time.Now().UTC()
		state := models.TenantEndUserState{
			WorkspaceID:    tenantUUID,
			UserID:         subjectUUID,
			Status:         models.EndUserStatusActive,
			FirstConsentAt: now,
			LastSeenAt:     &now,
		}
		if err := config.DB.
			Where("workspace_id = ? AND user_id = ?", tenantUUID, subjectUUID).
			Assign(map[string]interface{}{
				"status":       models.EndUserStatusActive,
				"last_seen_at": now,
				"updated_at":   now,
			}).
			FirstOrCreate(&state).Error; err != nil {
			log.Printf("[MCP_AUTH] ConsentHandler: failed to upsert end-user state tenant=%s user=%s context_id=%s: %v",
				arcCtx.WorkspaceID, consentRequest.Subject, arcCtx.ContextID, err)
		}
	}

	if remember && mcpClient != nil {
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

// redirectURIOriginsFromClient returns the deduplicated scheme+host origins of
// every redirect_uri registered for an MCP OAuth client. These are passed to
// BuildConsentCSP so the consent form's redirect chain (which terminates at the
// client's redirect_uri) is not blocked by the browser's form-action enforcement.
func redirectURIOriginsFromClient(client *models.MCPOAuthClient) []string {
	if client == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(client.RedirectURIs))
	origins := make([]string, 0, len(client.RedirectURIs))
	for _, raw := range client.RedirectURIs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if _, dup := seen[origin]; dup {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins
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

// --- SAML Handlers ---

// InitiateSAMLAuthHandler initiates SAML authentication with a provider.
//
// Workspace gate (v4): the SAML provider must be backed by an
// identity_providers row with status != 'disabled'. When the request carries
// an Application context AND the Application has any policy rows, the
// matching IDP must be in the enabled set (default-allow when empty).
func (ctrl *HmgrController) InitiateSAMLAuthHandler(c *gin.Context) {
	providerName := strings.ToLower(strings.TrimSpace(c.Param("provider")))

	var req struct {
		LoginChallenge string  `json:"login_challenge" binding:"required"`
		ApplicationID  *string `json:"application_id,omitempty"`
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
	workspaceUUID, err := uuid.Parse(realTenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.SAMLInitiateResponse{Success: false, Error: "Invalid workspace id"})
		return
	}

	// Workspace IDP gate: resolve through identity_providers + saml_providers.
	var resolved struct {
		IdentityProviderID uuid.UUID
		Status             string
		SAMLID             uuid.UUID `gorm:"column:saml_id"`
	}
	err = config.DB.
		Table("identity_providers ip").
		Select("ip.id AS identity_provider_id, ip.status, sp.id AS saml_id").
		Joins("JOIN saml_providers sp ON sp.id = ip.saml_provider_id").
		Where("ip.workspace_id = ?", workspaceUUID).
		Where("ip.provider_type = ?", models.IdentityProviderSAML).
		Where("sp.provider_name = ?", providerName).
		First(&resolved).Error
	if err != nil {
		c.JSON(http.StatusForbidden, hydramodels.SAMLInitiateResponse{Success: false, Error: "SAML provider not enabled for workspace"})
		return
	}
	if resolved.Status == "disabled" {
		c.JSON(http.StatusForbidden, hydramodels.SAMLInitiateResponse{Success: false, Error: "SAML provider is disabled for workspace"})
		return
	}

	// Optional Application gate.
	if req.ApplicationID != nil && *req.ApplicationID != "" {
		appUUID, err := uuid.Parse(*req.ApplicationID)
		if err != nil {
			c.JSON(http.StatusBadRequest, hydramodels.SAMLInitiateResponse{Success: false, Error: "Invalid application_id"})
			return
		}
		var policyCount int64
		if err := config.DB.Table("application_identity_provider_policies").
			Where("workspace_id = ? AND application_id = ?", workspaceUUID, appUUID).
			Count(&policyCount).Error; err == nil && policyCount > 0 {
			var enabledCount int64
			config.DB.Table("application_identity_provider_policies").
				Where("workspace_id = ? AND application_id = ? AND identity_provider_id = ? AND enabled = ?",
					workspaceUUID, appUUID, resolved.IdentityProviderID, true).
				Count(&enabledCount)
			if enabledCount == 0 {
				c.JSON(http.StatusForbidden, hydramodels.SAMLInitiateResponse{Success: false, Error: "SAML provider not enabled for application"})
				return
			}
		}
	}

	// Resolve full SAML provider row for issuer / SSO URL / cert.
	samlProvider, err := ctrl.service.GetSAMLProvider(realTenantID, providerName)
	if err != nil {
		c.JSON(http.StatusNotFound, hydramodels.SAMLInitiateResponse{Success: false, Error: "SAML provider row missing"})
		return
	}
	if !samlProvider.IsActive {
		c.JSON(http.StatusForbidden, hydramodels.SAMLInitiateResponse{Success: false, Error: "Provider is not active"})
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

	assertion, loginChallenge, providerName, workspaceID, err := ctrl.service.ValidateSAMLResponse(req.SAMLResponse, req.RelayState)
	if err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	redirectTo, user, err := ctrl.ProcessSAMLAssertion(assertion, loginChallenge, providerName, workspaceID)
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
	query.Set("workspace_id", user.WorkspaceID.String())
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

// HandleSAMLACSClientHandler handles workspace-scoped ACS callback. The legacy
// per-client URL form (/saml/acs/:tenant_id/:client_id) is retained as a path
// shape, but only the workspace_id segment is validated against the relay
// state — per-Application restriction is enforced at initiate, not here.
func (ctrl *HmgrController) HandleSAMLACSClientHandler(c *gin.Context) {
	workspaceIDParam := c.Param("workspace_id")

	var req hydramodels.SAMLCallbackRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	if req.SAMLResponse == "" {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Missing SAMLResponse"})
		return
	}

	assertion, loginChallenge, providerName, workspaceID, err := ctrl.service.ValidateSAMLResponse(req.SAMLResponse, req.RelayState)
	if err != nil {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Invalid SAML response: " + err.Error()})
		return
	}

	if workspaceIDParam != workspaceID {
		c.JSON(http.StatusBadRequest, hydramodels.CallbackValidationResponse{Success: false, Error: "Workspace ID mismatch"})
		return
	}

	redirectTo, user, err := ctrl.ProcessSAMLAssertion(assertion, loginChallenge, providerName, workspaceID)
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
	query.Set("workspace_id", user.WorkspaceID.String())
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
func (ctrl *HmgrController) ProcessSAMLAssertion(assertion *hydramodels.SAMLAssertion, loginChallenge, providerName, workspaceID string) (string, *hydramodels.User, error) {
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

	clientIDFromMetadata, _ := clientDetails.Metadata["workspace_id"].(string)
	realTenantID, _ := clientDetails.Metadata["c_id"].(string)

	if realTenantID != workspaceID {
		return "", nil, fmt.Errorf("tenant ID mismatch: expected %s, got %s", realTenantID, workspaceID)
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

	parsedTenantID, err := hydrautils.ValidateUUID(realTenantID, "workspace_id")
	if err != nil {
		return "", nil, err
	}

	parsedClientID, err := hydrautils.ValidateUUID(clientIDFromMetadata, "client_id")
	if err != nil {
		return "", nil, err
	}

	user := &hydramodels.User{
		Email:       assertion.Email,
		Username:    &username,
		Name:        name,
		Provider:    "saml-" + providerName,
		ProviderID:  nameID,
		ClientID:    parsedClientID,
		WorkspaceID: parsedTenantID,
		Active:      true,
	}

	user, err = ctrl.service.CreateOrUpdateUser("", user)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	userID := fmt.Sprintf("saml-%s-%s", providerName, nameID)
	acceptResponse, err := ctrl.service.AcceptHydraLoginRequestWithContext(loginChallenge, userID, map[string]interface{}{
		"email":        user.Email,
		"name":         user.Name,
		"username":     user.Username,
		"provider":     user.Provider,
		"provider_id":  user.ProviderID,
		"workspace_id": user.WorkspaceID,
		"client_id":    user.ClientID,
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to accept login request: %w", err)
	}

	return acceptResponse.RedirectTo, user, nil
}

// GetSAMLMetadataHandler returns workspace-scoped SP metadata.
// v4: per-Application restriction is enforced via
// application_identity_provider_policies, not by URL path scoping.
func (ctrl *HmgrController) GetSAMLMetadataHandler(c *gin.Context) {
	workspaceID, err := uuid.Parse(c.Param("workspace_id"))
	if err != nil {
		c.XML(http.StatusBadRequest, gin.H{"error": "Invalid workspace id"})
		return
	}

	metadata, err := ctrl.service.GenerateSAMLMetadata(workspaceID)
	if err != nil {
		c.XML(http.StatusInternalServerError, gin.H{"error": "Failed to generate metadata"})
		return
	}

	c.Header("Content-Type", "application/xml")
	c.String(http.StatusOK, metadata)
}

// Legacy SAML CRUD handlers (Create/Update/Delete/List/Test) have been removed.
// SAML provider management now flows through:
//   POST   /authsec/identity-providers          (provider_type='saml')
//   PUT    /authsec/identity-providers/:id/status
//   DELETE /authsec/identity-providers/:id
// The login + ACS handlers below stay — they're the protocol-execution path.

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
	c.JSON(http.StatusOK, gin.H{"message": "UpdateTenant endpoint - to be implemented", "workspace_id": c.Param("id")})
}
func (ctrl *HmgrController) DeleteTenantHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "DeleteTenant endpoint - to be implemented", "workspace_id": c.Param("id")})
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
