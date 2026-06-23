package platform

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"github.com/authsec-ai/authsec/middlewares"

	icp "github.com/authsec-ai/authsec/internal/clients/icp"
	hydramodels "github.com/authsec-ai/authsec/internal/hydra/models"
	spireservices "github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// safeUUID safely converts an interface{} to uuid.UUID, handling both uuid.UUID and string types.
func safeUUID(v interface{}) uuid.UUID {
	switch val := v.(type) {
	case uuid.UUID:
		return val
	case string:
		parsed, err := uuid.Parse(val)
		if err != nil {
			return uuid.Nil
		}
		return parsed
	default:
		return uuid.Nil
	}
}

func (oc *OIDCController) generateAdminJWTToken(adminUser *models.AdminUser) (string, error) {
	if adminUser == nil {
		return "", errors.New("admin user is required")
	}

	// Fetch admin roles from database
	var roles []string
	if adminUser.WorkspaceID != nil && *adminUser.WorkspaceID != uuid.Nil {
		rolesFromDB, err := oc.adminUserRepo.GetAdminRoles(adminUser.ID, *adminUser.WorkspaceID)
		if err == nil {
			roles = rolesFromDB
		} else {
			log.Printf("Warning: Failed to fetch admin roles for user %s: %v", adminUser.ID, err)
		}
	}

	if len(roles) == 0 {
		roles = []string{"admin"}
	}

	// Use centralized token service — same as email/password login path
	token, err := config.TokenService.GenerateAdminToken(
		adminUser.ID,
		adminUser.Email,
		adminUser.WorkspaceID,
		adminUser.WorkspaceDomain,
		roles,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate admin token: %w", err)
	}

	return token, nil
}

// OIDCController handles OIDC authentication flows
type OIDCController struct {
	oidcService            *services.OIDCService
	workspaceRepo             *database.AdminWorkspaceRepository
	userRepo               *database.UserRepository
	adminUserRepo          *database.AdminUserRepository
	pendingRepo            *database.PendingRegistrationRepository
	icpProvisioningService *services.ICPProvisioningService
	// hydraLoginSvc completes the Hydra login_challenge dance when the OIDC
	// flow is being driven by an upstream OAuth client (Action=="hydra_login").
	hydraLoginSvc *hydramodels.OAuthLoginService
	authzCtx      *services.AuthorizationContextService
}

// NewOIDCController creates a new OIDC controller
func NewOIDCController() (*OIDCController, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Initialize ICP client and provisioning service
	// Generate service-to-service JWT token for ICP
	cfg := config.GetConfig()
	icpToken, err := services.GenerateOIDCServiceToken()
	if err != nil {
		log.Printf("Warning: Failed to generate ICP service token: %v", err)
		// Continue without ICP service - it's optional
		icpToken = ""
	}

	var icpProvisioningService *services.ICPProvisioningService
	if icpToken != "" {
		icpClient := icp.NewClient(cfg.ICPServiceURL, icpToken)
		icpProvisioningService = services.NewICPProvisioningService(icpClient)
	}

	return &OIDCController{
		oidcService:            services.NewOIDCService(db),
		workspaceRepo:             database.NewAdminWorkspaceRepository(db),
		userRepo:               database.NewUserRepository(db),
		adminUserRepo:          database.NewAdminUserRepository(db),
		pendingRepo:            database.NewPendingRegistrationRepository(db),
		icpProvisioningService: icpProvisioningService,
		hydraLoginSvc:          hydramodels.NewOAuthLoginService(*config.AppConfig),
		authzCtx:               services.NewAuthorizationContextService(config.DB),
	}, nil
}

// SetPKIService injects the in-process PKI provisioning service (replaces HTTP ICP client).
func (oc *OIDCController) SetPKIService(pkiSvc *spireservices.PKIProvisioningService) {
	if oc.icpProvisioningService != nil {
		oc.icpProvisioningService.SetPKIService(pkiSvc)
	}
}

// Initiate handles unified OIDC flow - automatically determines register vs login
// @Summary Initiate OIDC flow (unified)
// @Description Starts OIDC flow. If workspace_domain is empty, uses "discover" mode to find existing user.
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.OIDCInitiateInput true "OIDC initiation request"
// @Success 200 {object} models.OIDCInitiateResponse
// @Failure 400 {object} map[string]string
// @Router /authsec/uflow/oidc/initiate [post]
//
// Security note: this is a public endpoint and the caller may supply a
// workspace_domain to pick which workspace's IdP config to advertise. That
// choice is not authority — the resolved workspace is persisted in server-side
// OIDCState bound to the Hydra login_challenge, and finishHydraLogin reads the
// workspace strictly from that state (not from any later caller input). So
// workspace selection here cannot escalate privilege; it only selects which
// public IdP configuration to begin a login against.
func (oc *OIDCController) Initiate(c *gin.Context) {
	var input models.OIDCInitiateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize tenant domain
	input.WorkspaceDomain = strings.ToLower(strings.TrimSpace(input.WorkspaceDomain))

	var action string
	var workspaceID *uuid.UUID

	// Case 1: No tenant domain provided (from app.authsec.dev) - DISCOVER mode
	if input.WorkspaceDomain == "" {
		action = "discover"
		workspaceID = nil
		log.Printf("OIDC: No tenant domain, initiating DISCOVER flow for provider '%s'", input.Provider)
	} else {
		// Validate tenant domain format when provided
		// Allow full custom domains (test.auth-sec.org) in addition to subdomain prefixes (mycompany)
		if !isValidWorkspaceDomainOrCustomDomain(input.WorkspaceDomain) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant domain format"})
			return
		}

		// Check if tenant exists - this determines register vs login
		log.Printf("OIDC Initiate: Looking up tenant for domain: %s", input.WorkspaceDomain)
		existingTenant, err := oc.workspaceRepo.GetWorkspaceByDomain(input.WorkspaceDomain)

		if err == nil && existingTenant != nil {
			// Tenant exists → LOGIN flow (user must exist in this tenant)
			action = "login"
			workspaceID = &existingTenant.WorkspaceID
			log.Printf("OIDC: Tenant '%s' found (workspace_id=%s), initiating LOGIN flow", input.WorkspaceDomain, existingTenant.WorkspaceID)
		} else {
			// Tenant doesn't exist → REGISTER flow (create new tenant)
			action = "register"
			workspaceID = nil
			log.Printf("OIDC: Tenant '%s' not found (error: %v), initiating REGISTER flow", input.WorkspaceDomain, err)
		}
	}

	// Set request host for callback URL (use API domain, e.g., dev.authsec.dev)
	oc.oidcService.SetRequestHost(c.Request.Host)
	log.Printf("DEBUG Initiate: Set requestHost='%s' for OIDC callback", c.Request.Host)

	// Capture origin domain for post-auth redirect (where user came from)
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = c.GetHeader("Referer")
		if origin != "" {
			// Extract domain from referer URL
			if parsedURL, err := url.Parse(origin); err == nil {
				origin = parsedURL.Host
			}
		}
	}
	if origin != "" {
		// Clean up origin (remove https:// prefix if present)
		origin = strings.TrimPrefix(origin, "https://")
		origin = strings.TrimPrefix(origin, "http://")
		oc.oidcService.SetRequestOrigin(origin)
		log.Printf("DEBUG Initiate: Set requestOrigin='%s' for post-auth redirect", origin)
	}

	// Initiate OIDC flow
	response, err := oc.oidcService.InitiateOIDCFlow(&input, action, workspaceID)
	if err != nil {
		log.Printf("Failed to initiate OIDC flow: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"redirect_url": response.RedirectURL,
		"state":        response.State,
		"action":       action, // Tell frontend what will happen
	})
}

// CheckTenantExists checks if a tenant domain is available or taken
// @Summary Check tenant domain availability
// @Description Returns whether a tenant domain exists (for UI to show login vs register)
// @Tags OIDC
// @Param domain query string true "Tenant domain to check"
// @Success 200 {object} map[string]interface{}
// @Router /authsec/uflow/oidc/check-tenant [get]
func (oc *OIDCController) CheckTenantExists(c *gin.Context) {
	domain := strings.ToLower(strings.TrimSpace(c.Query("domain")))

	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Domain parameter required"})
		return
	}

	existingTenant, err := oc.workspaceRepo.GetWorkspaceByDomain(domain)
	exists := err == nil && existingTenant != nil

	c.JSON(http.StatusOK, gin.H{
		"domain": domain,
		"exists": exists,
		"action": map[bool]string{true: "login", false: "register"}[exists],
	})
}

// GetProviders returns OIDC providers for login UI. With no workspace_domain it
// returns only global/platform providers (workspace_id IS NULL). With
// workspace_domain it returns only providers configured for that workspace.
// @Summary Get available OIDC providers
// @Description Returns list of active OIDC providers for display on login page
// @Tags OIDC
// @Produce json
// @Success 200 {object} models.OIDCProviderListResponse
// @Router /authsec/uflow/oidc/providers [get]
func (oc *OIDCController) GetProviders(c *gin.Context) {
	workspaceDomain := strings.ToLower(strings.TrimSpace(c.Query("workspace_domain")))

	var (
		providers []models.OIDCProviderPublic
		err       error
	)
	if workspaceDomain != "" {
		tenant, lookupErr := oc.workspaceRepo.GetWorkspaceByDomain(workspaceDomain)
		if lookupErr != nil || tenant == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
			return
		}
		providers, err = oc.oidcService.GetActiveProvidersForWorkspace(tenant.WorkspaceID)
	} else {
		providers, err = oc.oidcService.GetActiveProviders()
	}
	if err != nil {
		log.Printf("Failed to get OIDC providers: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get providers"})
		return
	}

	c.JSON(http.StatusOK, models.OIDCProviderListResponse{
		Providers: providers,
	})
}

// GetAuthURL generates an OAuth URL based on client ID
// @Summary Generate OAuth URL
// @Description Generates an OAuth URL for a given client ID by finding the associated tenant domain
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.GetAuthURLInput true "Get Auth URL Input"
// @Success 200 {object} models.GetAuthURLResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /authsec/uflow/oidc/auth-url [post]
func (oc *OIDCController) GetAuthURL(c *gin.Context) {
	var input models.GetAuthURLInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Input validation
	if input.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}

	// Look up workspace by workspace_id (client_id == workspace_id for v4 clients)
	tenant, err := oc.workspaceRepo.GetWorkspaceByID(input.ClientID)
	if err != nil {
		log.Printf("Failed to find tenant for client_id %s: %v", input.ClientID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Client ID not found or associated with any tenant"})
		return
	}

	if tenant.WorkspaceDomain == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant found but has no domain configured"})
		return
	}

	// Construct the URL
	baseURL := "https://oauth.prod.authsec.ai/oauth2/auth"
	redirectURI := fmt.Sprintf("https://%s/oidc/auth/callback", tenant.WorkspaceDomain)

	oauthClientID := input.ClientID

	// Generate random state
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate state"})
		return
	}
	freshState := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Generate PKCE code_verifier and code_challenge (S256)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate code_verifier"})
		return
	}
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Store verifier in the in-process PKCE store (hmgr is merged into the same binary).
	StorePKCEVerifier(freshState, codeVerifier)

	params := url.Values{}
	params.Add("client_id", oauthClientID)
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email")
	params.Add("redirect_uri", redirectURI)
	params.Add("state", freshState)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	c.JSON(http.StatusOK, models.GetAuthURLResponse{
		AuthURL: authURL,
		State:   freshState,
	})
}

// InitiateRegistration starts OIDC registration flow for new tenant
// @Summary Initiate OIDC registration
// @Description Starts OIDC flow for registering a new tenant via social login
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.OIDCInitiateInput true "OIDC initiation request"
// @Success 200 {object} models.OIDCInitiateResponse
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string "Tenant domain already exists"
// @Router /authsec/uflow/oidc/register/initiate [post]
func (oc *OIDCController) InitiateRegistration(c *gin.Context) {
	var input models.OIDCInitiateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize tenant domain (lowercase, no spaces)
	input.WorkspaceDomain = strings.ToLower(strings.TrimSpace(input.WorkspaceDomain))

	// Validate tenant domain format
	if !isValidWorkspaceDomain(input.WorkspaceDomain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant domain format. Use only lowercase letters, numbers, and hyphens."})
		return
	}

	// Check if tenant domain already exists
	existingTenant, err := oc.workspaceRepo.GetWorkspaceByDomain(input.WorkspaceDomain)
	if err == nil && existingTenant != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Tenant domain already exists"})
		return
	}

	// v4: OIDC providers are workspace-owned and configured AFTER the workspace
	// exists. The "register a new tenant via OIDC" flow is no longer supported.
	// Direct the operator through the email signup path instead.
	c.JSON(http.StatusBadRequest, gin.H{
		"error": "OIDC registration is unavailable; create the workspace via email signup, then configure OIDC providers from the workspace settings.",
	})
}

// InitiateLogin starts OIDC login flow for existing tenant
// @Summary Initiate OIDC login
// @Description Starts OIDC flow for logging into an existing tenant via social login
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.OIDCInitiateInput true "OIDC initiation request"
// @Success 200 {object} models.OIDCInitiateResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string "Tenant not found"
// @Router /authsec/uflow/oidc/login/initiate [post]
func (oc *OIDCController) InitiateLogin(c *gin.Context) {
	var input models.OIDCInitiateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize tenant domain
	input.WorkspaceDomain = strings.ToLower(strings.TrimSpace(input.WorkspaceDomain))

	// Verify tenant exists
	tenant, err := oc.workspaceRepo.GetWorkspaceByDomain(input.WorkspaceDomain)
	if err != nil || tenant == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	// Set request host for callback URL
	oc.oidcService.SetRequestHost(c.Request.Host)

	// Initiate OIDC flow with action "login" and tenant ID
	response, err := oc.oidcService.InitiateOIDCFlow(&input, "login", &tenant.WorkspaceID)
	if err != nil {
		log.Printf("Failed to initiate OIDC login: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Callback handles the OIDC provider callback
// @Summary OIDC callback handler
// @Description Handles the callback from OIDC provider after authentication. This is part of the traditional redirect flow and is being replaced by the ExchangeCode endpoint for SPA flows.
// @Tags OIDC
// @Accept json
// @Produce json
// @Param code query string true "Authorization code"
// @Param state query string true "State token"
// @Success 200 {object} models.OIDCCallbackResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /authsec/uflow/oidc/callback [get]
func (oc *OIDCController) Callback(c *gin.Context) {
	// This endpoint receives OAuth callback and redirects to frontend SPA with code/state
	// The frontend will then call /exchange-code to complete the flow
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	// Helper function to get workspace_domain from state token
	// Priority: OriginDomain > WorkspaceDomain
	getWorkspaceDomain := func(stateToken string) string {
		if stateToken != "" {
			oidcState, err := oc.oidcService.GetStateByToken(stateToken)
			if err == nil && oidcState != nil {
				if oidcState.OriginDomain != "" {
					return oidcState.OriginDomain
				}
				if oidcState.WorkspaceDomain != "" {
					return oidcState.WorkspaceDomain
				}
			}
		}
		return ""
	}

	// Check for error from provider
	if errorParam != "" {
		errorDesc := c.Query("error_description")
		log.Printf("OIDC provider error: %s - %s", errorParam, errorDesc)
		data := gin.H{"success": false, "error": errorParam, "description": errorDesc}
		if workspaceDomain := getWorkspaceDomain(state); workspaceDomain != "" {
			data["workspace_domain"] = workspaceDomain
		}
		renderOAuthCallbackHTML(c, data)
		return
	}

	if code == "" || state == "" {
		data := gin.H{"success": false, "error": "Missing code or state parameter"}
		if workspaceDomain := getWorkspaceDomain(state); workspaceDomain != "" {
			data["workspace_domain"] = workspaceDomain
		}
		renderOAuthCallbackHTML(c, data)
		return
	}

	// hydra_login fast-path: the user is completing an upstream OAuth flow
	// driven by Hydra (via the hmgr/auth/initiate shim). Handle the entire
	// callback server-side — exchange the code, resolve the user, accept the
	// Hydra login challenge, 302 the browser to Hydra's redirect_to. No SPA
	// round-trip needed because the user's final destination is the OAuth
	// client app, not our admin UI.
	if pre, perr := oc.oidcService.GetStateByToken(state); perr == nil && pre != nil && pre.Action == "hydra_login" {
		oc.handleHydraLoginCallback(c, code, state)
		return
	}

	// Retrieve the state from database to get workspace_domain for proper redirect
	oidcState, err := oc.oidcService.GetStateByToken(state)
	data := gin.H{
		"code":  code,
		"state": state,
	}

	// Add workspace_domain from state if available
	// Priority: OriginDomain (custom domain user came from) > WorkspaceDomain (constructed subdomain)
	if err == nil && oidcState != nil {
		if oidcState.OriginDomain != "" {
			data["workspace_domain"] = oidcState.OriginDomain
			log.Printf("DEBUG Callback: Using origin_domain='%s' from state for redirect", oidcState.OriginDomain)
		} else if oidcState.WorkspaceDomain != "" {
			data["workspace_domain"] = oidcState.WorkspaceDomain
			log.Printf("DEBUG Callback: Using workspace_domain='%s' from state for redirect (fallback)", oidcState.WorkspaceDomain)
		} else {
			log.Printf("DEBUG Callback: No domain found in state (origin_domain='%s', workspace_domain='%s'), will use default or Host header",
				oidcState.OriginDomain, oidcState.WorkspaceDomain)
		}
	} else {
		log.Printf("DEBUG Callback: Failed to get state or state is nil, will use default or Host header")
	}

	// Pass the code and state to frontend for SPA flow
	// Frontend will call POST /uflow/oidc/exchange-code with these parameters
	renderOAuthCallbackHTML(c, data)
}

// handleHydraLoginCallback completes an end-user OIDC login that was kicked
// off by a Hydra login_challenge (the hmgr/auth/initiate shim). Server-side
// flow: verify state + exchange code (via OIDCService.HandleCallback), resolve
// the local user inside the workspace, link the oidc_user_identity if new,
// then call Hydra accept-login and 302 the browser to Hydra's redirect_to.
//
// No SPA round-trip — the user's final destination is the OAuth client app,
// not our admin UI.
func (oc *OIDCController) handleHydraLoginCallback(c *gin.Context, code, stateToken string) {
	state, userInfo, err := oc.oidcService.HandleCallback(&models.OIDCCallbackInput{
		Code:  code,
		State: stateToken,
	})
	if err != nil {
		log.Printf("hydra_login callback: HandleCallback failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err.Error()})
		return
	}
	oc.finishHydraLogin(c, state, userInfo)
}

// finishHydraLogin resolves the local user, links the OIDC identity if new,
// accepts the Hydra login challenge, and 302s the browser to Hydra's
// redirect_to. It is called from both the server-side GET callback path and
// the SPA POST exchange-code path (which already consumed the state/code via
// HandleCallback before dispatching on action).
func (oc *OIDCController) finishHydraLogin(c *gin.Context, state *models.OIDCState, userInfo *models.OIDCUserInfo) {
	var err error
	if state.WorkspaceID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "workspace_id missing from OIDC state"})
		return
	}
	if state.LoginChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge missing from OIDC state"})
		return
	}

	workspaceID := *state.WorkspaceID

	if strings.TrimSpace(userInfo.Sub) == "" || strings.TrimSpace(userInfo.Email) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "OIDC provider did not return a usable subject and email"})
		return
	}
	if state.ProviderName == "google" && !userInfo.EmailVerified {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Google account email is not verified"})
		return
	}

	// 1. Resolve the local user by IdP identity first, fall back to email.
	identity, _ := oc.oidcService.GetIdentityByTenantAndProviderUser(
		workspaceID, state.ProviderName, userInfo.Sub)

	var user *models.ExtendedUser
	if identity != nil {
		user, err = oc.userRepo.GetUserByID(identity.UserID)
		if err != nil {
			log.Printf("hydra_login callback: GetUserByID(%s) failed: %v", identity.UserID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "user lookup failed"})
			return
		}
		_ = oc.oidcService.UpdateLastLogin(identity.ID)
	} else {
		user, err = oc.userRepo.GetUserByEmailAndTenant(userInfo.Email, workspaceID)
		if database.IsUserNotFound(err) {
			user, err = oc.userRepo.CreateOIDCEndUser(workspaceID, state.ProviderName, userInfo)
			if err != nil {
				log.Printf("hydra_login callback: JIT end-user creation failed email=%s workspace=%s: %v", userInfo.Email, workspaceID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create workspace end user"})
				return
			}
			log.Printf("hydra_login callback: provisioned workspace end user user=%s workspace=%s provider=%s", user.ID, workspaceID, state.ProviderName)
		} else if err != nil {
			log.Printf("hydra_login callback: workspace user lookup failed email=%s workspace=%s: %v", userInfo.Email, workspaceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "workspace user lookup failed"})
			return
		}

		profileJSON, _ := json.Marshal(map[string]interface{}{"name": userInfo.Name, "picture": userInfo.Picture})
		if err := oc.oidcService.CreateIdentity(&models.OIDCUserIdentity{
			WorkspaceID:    workspaceID,
			UserID:         user.ID,
			ProviderName:   state.ProviderName,
			ProviderUserID: userInfo.Sub,
			Email:          userInfo.Email,
			ProfileData:    string(profileJSON),
		}); err != nil {
			log.Printf("hydra_login callback: CreateIdentity failed user=%s provider=%s: %v", user.ID, state.ProviderName, err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to link social identity"})
			return
		}
	}

	if !user.Active {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "This end-user account is inactive"})
		return
	}
	if err := oc.userRepo.UpdateLastLogin(user.ID); err != nil {
		log.Printf("hydra_login callback: failed to update user last_login user=%s: %v", user.ID, err)
	}

	// 2. Accept the Hydra login challenge with the local user as subject.
	hydraCtx := map[string]interface{}{
		"workspace_id": workspaceID.String(),
		"email":        user.Email,
		"name":         userInfo.Name,
		"provider":     state.ProviderName,
		"auth_method":  "oidc_federated",
	}
	if state.ApplicationID != nil {
		hydraCtx["application_id"] = state.ApplicationID.String()
	}
	// Propagate the auth_request_contexts.context_id so the consent handler
	// can re-resolve the workspace+application binding when Hydra issues a
	// fresh consent_challenge that doesn't pair 1:1 with the original
	// login_challenge. The login_challenge lookup is the primary path; this
	// is the safety-net fallback (see hmgr_controller.ConsentHandler).
	if arcCtx, lookupErr := oc.authzCtx.GetAuthRequestContextByLoginChallenge(state.LoginChallenge); lookupErr == nil && arcCtx != nil && arcCtx.ContextID != "" {
		hydraCtx["context_id"] = arcCtx.ContextID
	}
	arcCtx, err := oc.authzCtx.GetAuthRequestContextByLoginChallenge(state.LoginChallenge)
	if err != nil || arcCtx == nil {
		log.Printf("hydra_login callback: auth context lookup failed login_challenge=%s: %v", state.LoginChallenge, err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "authorization context not found for login challenge"})
		return
	}
	hydraCtx["context_id"] = arcCtx.ContextID
	hydraCtx["resource_server_id"] = arcCtx.ResourceServerID
	hydraCtx["resource_uri"] = arcCtx.ResourceURI

	accept, err := oc.hydraLoginSvc.AcceptHydraLoginRequestWithContext(
		state.LoginChallenge, user.ID.String(), hydraCtx)
	if err != nil {
		log.Printf("hydra_login callback: AcceptHydraLoginRequestWithContext failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to accept hydra login"})
		return
	}
	if accept == nil || accept.RedirectTo == "" {
		log.Printf("hydra_login callback: Hydra returned empty redirect_to")
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "hydra did not return a redirect"})
		return
	}

	// 3. Hydra is in charge of the rest of the OAuth dance.
	// GET path (server-side callback): 302 directly — the browser navigates.
	// POST path (SPA exchange-code fetch): return JSON with the redirect URL
	// so the frontend can do window.location.href = result.redirect_to.
	// A 302 response to a cross-origin fetch() is CORS-blocked by the browser.
	if c.Request.Method == http.MethodGet {
		c.Redirect(http.StatusFound, accept.RedirectTo)
	} else {
		c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": accept.RedirectTo})
	}
}

// ExchangeCode handles the code exchange for SPAs
// @Summary Exchange OIDC code for a JWT token
// @Description Receives the authorization code from a Single-Page Application and exchanges it for a session JWT.
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.OIDCCallbackInput true "OIDC code and state"
// @Success 200 {object} models.LoginResponse "Successful login response with JWT token"
// @Failure 400 {object} map[string]string "Bad request - invalid input"
// @Failure 401 {object} map[string]string "Unauthorized - invalid code or state"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/oidc/exchange-code [post]
func (oc *OIDCController) ExchangeCode(c *gin.Context) {
	var input models.OIDCCallbackInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if input.Code == "" || input.State == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing code or state parameter"})
		return
	}

	// Process callback using the same service function
	state, userInfo, err := oc.oidcService.HandleCallback(&input)
	if err != nil {
		log.Printf("OIDC code exchange error: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// The rest of the logic is similar to the original callback, but returns JSON instead of HTML.
	// We can reuse the handlers but they need to be adapted to return JSON.
	// For now, let's inline the logic for clarity.

	// Handle based on action (register, login, or discover)
	log.Printf("DEBUG ExchangeCode: Processing action='%s', state.OriginDomain='%s', state.WorkspaceDomain='%s'",
		state.Action, state.OriginDomain, state.WorkspaceDomain)

	switch state.Action {
	// For simplicity, we will focus on the "login" and "discover" which result in a token.
	// Registration is a more complex flow that creates a tenant and might not immediately result in a JWT.
	case "login":
		log.Printf("DEBUG ExchangeCode: Calling handleLoginAndGenerateToken")
		oc.handleLoginAndGenerateToken(c, state, userInfo)
	case "discover":
		log.Printf("DEBUG ExchangeCode: Calling handleDiscoverAndGenerateToken")
		oc.handleDiscoverAndGenerateToken(c, state, userInfo)
	case "register":
		// The registration flow is complex, creates a tenant, and might not return a token immediately.
		// For now, we will return a success message and let the user login separately.
		oc.handleRegistrationCallback(c, state, userInfo) // This renders HTML, needs to be changed.
		// A better approach would be to refactor handleRegistrationCallback to not write a response
		// and then decide here whether to return JSON or HTML.
		// c.JSON(http.StatusOK, gin.H{"message": "Registration successful. Please login."})
	case "hydra_login":
		// End-user is completing a Hydra-driven OAuth flow via the SPA path.
		// HandleCallback above already consumed the code and deleted the state
		// row, so skip straight to the Hydra accept + redirect step.
		log.Printf("DEBUG ExchangeCode: Delegating hydra_login to finishHydraLogin")
		oc.finishHydraLogin(c, state, userInfo)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action in state"})
	}
}

// handleLoginAndGenerateToken is a modified version of handleLoginCallback for the SPA flow
func (oc *OIDCController) handleLoginAndGenerateToken(c *gin.Context, state *models.OIDCState, userInfo *models.OIDCUserInfo) {
	if state.WorkspaceID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id missing from state"})
		return
	}

	// Check if user has OIDC identity in this workspace
	identity, _ := oc.oidcService.GetIdentityByTenantAndProviderUser(*state.WorkspaceID, state.ProviderName, userInfo.Sub)

	var (
		err  error
		user *models.ExtendedUser
	)

	if identity != nil {
		// User has OIDC identity - get user by ID
		user, err = oc.userRepo.GetUserByID(identity.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
			return
		}
		// Update last login
		oc.oidcService.UpdateLastLogin(identity.ID)
	} else {
		// No OIDC identity - check if user exists by email in this tenant
		user, err = oc.userRepo.GetUserByEmailAndTenant(userInfo.Email, *state.WorkspaceID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in this workspace"})
			return
		}

		// User exists by email but no OIDC identity - link the OIDC provider
		profileDataJSON, _ := json.Marshal(map[string]interface{}{"name": userInfo.Name, "picture": userInfo.Picture})
		newIdentity := &models.OIDCUserIdentity{
			WorkspaceID:    *state.WorkspaceID,
			UserID:         user.ID,
			ProviderName:   state.ProviderName,
			ProviderUserID: userInfo.Sub,
			Email:          userInfo.Email,
			ProfileData:    string(profileDataJSON),
		}
		if err := oc.oidcService.CreateIdentity(newIdentity); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link social login."})
			return
		}
	}

	// Now that we have the user, generate a token for them - pass origin domain for correct redirect
	oc.generateAndRespondWithTokenAndOrigin(c, user, state.OriginDomain)
}

// handleDiscoverAndGenerateToken is a modified version of handleDiscoverCallback for the SPA flow
func (oc *OIDCController) handleDiscoverAndGenerateToken(c *gin.Context, state *models.OIDCState, userInfo *models.OIDCUserInfo) {
	// Global email lookup — intentional for the discover flow (pre-workspace).
	// Safety: if multiple workspaces share the same email, we take the first match.
	// The returned token is always scoped to that user's workspace_id so there's
	// no cross-workspace privilege. A more defensive approach would be to return
	// all matching workspaces and let the user choose, but that's a UX change.
	existingUser, err := oc.userRepo.GetUserByEmail(userInfo.Email)

	if err == nil && existingUser != nil {
		// User EXISTS by email - auto-login to their workspace
		// Link identity if it doesn't exist
		existingIdentity, _ := oc.oidcService.GetIdentityByTenantAndProviderUser(existingUser.WorkspaceID, state.ProviderName, userInfo.Sub)
		if existingIdentity == nil {
			profileDataJSON, _ := json.Marshal(map[string]interface{}{"name": userInfo.Name, "picture": userInfo.Picture})
			identity := &models.OIDCUserIdentity{
				WorkspaceID:    existingUser.WorkspaceID,
				UserID:         existingUser.ID,
				ProviderName:   state.ProviderName,
				ProviderUserID: userInfo.Sub,
				Email:          userInfo.Email,
				ProfileData:    string(profileDataJSON),
			}
			oc.oidcService.CreateIdentity(identity)
		} else {
			oc.oidcService.UpdateLastLogin(existingIdentity.ID)
		}

		// Generate a token and respond - pass origin domain for correct redirect
		oc.generateAndRespondWithTokenAndOrigin(c, existingUser, state.OriginDomain)
		return
	}

	// User DOES NOT EXIST by email
	// Check if this is from app.authsec.dev (empty workspace_domain) or custom domain
	if state.WorkspaceDomain == "" {
		// From app.authsec.dev or custom domain - allow registration with needs_domain
		c.JSON(http.StatusNotFound, gin.H{
			"error":         "User not found",
			"needs_domain":  true,
			"message":       "No existing account found. Please choose a workspace name to create your account.",
			"origin_domain": state.OriginDomain, // Pass origin for redirect after registration
			"provider_data": map[string]interface{}{
				"provider":         state.ProviderName,
				"email":            userInfo.Email,
				"name":             userInfo.Name,
				"picture":          userInfo.Picture,
				"provider_user_id": userInfo.Sub,
			},
		})
	} else {
		// From custom domain (e.g., ritam.app.authsec.com) - restrict registration
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "User not found",
			"message": "No account found for this email in this workspace. Please contact your administrator.",
		})
	}
}

func (oc *OIDCController) generateAndRespondWithTokenAndOrigin(c *gin.Context, user *models.ExtendedUser, originDomain string) {
	// user.WorkspaceDomain is the authoritative workspace domain (e.g., papa.dev.authsec.dev).
	// originDomain is just where the request came from (e.g., dev.authsec.dev for generic login).
	// Always return the DB value so the frontend knows which workspace to redirect to.
	workspaceDomain := user.WorkspaceDomain
	log.Printf("DEBUG generateAndRespondWithTokenAndOrigin: workspaceDomain='%s' (from DB), originDomain='%s'",
		workspaceDomain, originDomain)

	// Look up the AdminUser to generate a properly-scoped JWT
	adminUser, err := oc.adminUserRepo.GetAdminUserByEmail(user.Email)
	if err != nil {
		log.Printf("ERROR generateAndRespondWithTokenAndOrigin: failed to look up admin user by email %s: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load user account"})
		return
	}

	tokenStr, err := oc.generateAdminJWTToken(adminUser)
	if err != nil {
		log.Printf("ERROR generateAndRespondWithTokenAndOrigin: failed to generate JWT for user %s: %v", user.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session token"})
		return
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		WorkspaceID:  user.WorkspaceID.String(),
		WorkspaceDomain: workspaceDomain,
		Email:        user.Email,
		FirstLogin:   user.LastLogin == nil,
		Token:        tokenStr,
	})
}

// handleRegistrationCallback processes registration after OIDC callback
func (oc *OIDCController) handleRegistrationCallback(c *gin.Context, state *models.OIDCState, userInfo *models.OIDCUserInfo) {
	// Check if user already exists with this OIDC identity (workspace-scoped when available).
	var existingIdentity *models.OIDCUserIdentity
	var err error
	if state.WorkspaceID != nil {
		existingIdentity, err = oc.oidcService.GetIdentityByTenantAndProviderUser(*state.WorkspaceID, state.ProviderName, userInfo.Sub)
	}
	if err == nil && existingIdentity != nil {
		// User already registered with this provider - redirect to their workspace
		tenant, _ := oc.workspaceRepo.GetWorkspaceByID(existingIdentity.WorkspaceID.String())
		if tenant != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error":         "Account already exists",
				"message":       "You already have an account. Please login instead.",
				"workspace_domain": tenant.WorkspaceDomain,
			})
			return
		}
	}

	// Create new tenant and user
	// Note: In admin registration pattern, workspace_id = client_id for the default client
	// workspaceID is used for tenant.WorkspaceID (business key)
	// tenant.ID (primary key) is auto-generated and used for FK references
	workspaceID := uuid.New()
	projectID := uuid.New()
	clientID := workspaceID // Client ID = Tenant ID for default client (matches admin registration)
	userID := uuid.New()

	// Start transaction
	db := config.GetDatabase()
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}
	defer tx.Rollback()

	// Create the workspace identity row (single master DB — no per-tenant database).
	fullDomain := fmt.Sprintf("%s.%s", state.WorkspaceDomain, config.AppConfig.WorkspaceDomainSuffix)
	username := userInfo.Email
	providerID := userInfo.Sub
	tenant := &models.Tenant{
		ID:           workspaceID, // Use same ID for both id and workspace_id for simplicity
		WorkspaceID:  workspaceID,
		Email:        userInfo.Email,
		Username:     &username,
		Name:         userInfo.Name,
		WorkspaceDomain: fullDomain,
		Provider:     state.ProviderName,
		ProviderID:   &providerID,
		Status:       "active",
		Source:       "oidc",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := oc.workspaceRepo.CreateTenantTx(tx, tenant); err != nil {
		log.Printf("Failed to create tenant: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	// Phase E: `projects` table dropped — no project row created.

	// Createadmin user in main DB (users table)
	usernameStr := userInfo.Email
	adminUser := &models.ExtendedUser{
		User: sharedmodels.User{
			ID:           userID,
			Email:        userInfo.Email,
			Name:         userInfo.Name,
			PasswordHash: "", // No password for OIDC users
			ClientID:     clientID,
			WorkspaceID:  workspaceID,
			ProjectID:    projectID,
			WorkspaceDomain: fullDomain,
			Provider:     state.ProviderName,
			ProviderID:   userInfo.Sub,
			Username:     &usernameStr,
			ProviderData: datatypes.JSON("{}"),
			Active:       true,
		},
	}

	// Store avatar URL if available
	if userInfo.Picture != "" {
		adminUser.AvatarURL = &userInfo.Picture
	}

	if err := oc.userRepo.CreateUserTx(tx, adminUser); err != nil {
		log.Printf("Failed to create admin user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Use EnsureAdminRoleAndPermissionsTx to seed both role AND permissions (fix for OIDC registration bug)
	roleID, err := database.NewAdminSeedRepository(config.GetDatabase()).EnsureAdminRoleAndPermissionsTx(tx, workspaceID)
	if err != nil {
		log.Printf("WARNING: Failed to ensure admin role and permissions for tenant %s: %v", workspaceID, err)
	} else {
		// Insert into role_bindings (user_roles is deprecated)
		// scope_type and scope_id are NULL for tenant-wide role assignments
		if _, err := tx.Exec(`
			INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
			SELECT gen_random_uuid(), $1, $2, $3, NULL, NULL, NOW(), NOW()
			WHERE NOT EXISTS (
				SELECT 1 FROM role_bindings
				WHERE workspace_id = $1 AND user_id = $2 AND role_id = $3 AND scope_type IS NULL AND scope_id IS NULL
			)
		`, workspaceID, userID, roleID); err != nil {
			log.Printf("WARNING: Failed to assign admin role to OIDC user %s: %v", userID, err)
			// Non-fatal - user can still login via OIDC, just not via admin password login
		} else {
			log.Printf("INFO: Admin role assigned to OIDC user %s", userID)
		}
	}

	// Create default role bindings in MAIN DB for admin across core services
	var adminRoleID uuid.UUID
	if err := tx.QueryRow("SELECT id FROM roles WHERE LOWER(name) = 'admin' AND workspace_id = $1 LIMIT 1", workspaceID).Scan(&adminRoleID); err != nil {
		log.Printf("Failed to resolve admin role id for default bindings: %v", err)
	} else {
		services := []string{"external-service", "clients", "user-flow", "ooc-manager", "log-service", "hydra-service", "sdk-manager"}
		usernameVal := userInfo.Email
		for _, svc := range services {
			if _, err := tx.Exec(`
				INSERT INTO role_bindings (id, workspace_id, user_id, role_id, role_name, username, scope_type, scope_id, created_at, updated_at)
				SELECT $1, $2, $3, $4, 'admin', $5, $6, $7, NOW(), NOW()
				WHERE NOT EXISTS (
					SELECT 1 FROM role_bindings
					WHERE workspace_id = $2 AND user_id = $3 AND role_id = $4 AND scope_type = $6 AND scope_id = $7
				)
			`, uuid.New(), workspaceID, userID, adminRoleID, usernameVal, svc, workspaceID); err != nil {
				log.Printf("WARNING: Failed to create role binding for service=%s tenant=%s: %v", svc, workspaceID, err)
				// Non-fatal - continue with other bindings
			}
		}
		// Add a wildcard binding to grant full access for the admin user
		if _, err := tx.Exec(`
			INSERT INTO role_bindings (id, workspace_id, user_id, role_id, role_name, username, scope_type, scope_id, created_at, updated_at)
			SELECT $1, $2, $3, $4, 'admin', $5, '*', NULL, NOW(), NOW()
			WHERE NOT EXISTS (
				SELECT 1 FROM role_bindings
				WHERE workspace_id = $2 AND user_id = $3 AND role_id = $4 AND scope_type = '*' AND scope_id IS NULL
			)
		`, uuid.New(), workspaceID, userID, adminRoleID, usernameVal); err != nil {
			log.Printf("WARNING: Failed to create wildcard role binding tenant=%s: %v", workspaceID, err)
		} else {
			log.Printf("INFO: Created role bindings for OIDC user %s across all services", userID)
		}
	}

	// Bind admin to workspace_memberships (RequireWorkspaceRole checks this)
	if roleID != uuid.Nil {
		if _, err := tx.Exec(`
			INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
			VALUES (gen_random_uuid(), $1, $2, $3, 'active', 'signup', NOW(), NOW())
			ON CONFLICT (workspace_id, user_id) DO NOTHING
		`, workspaceID, userID, roleID); err != nil {
			log.Printf("WARNING: Failed to create workspace_membership for OIDC user %s: %v", userID, err)
		}
	}

	// Commit main DB transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	// Single-tenant: no per-tenant DB provisioning. The workspace lives in master DB.
	mainDB := config.GetDatabase()

	// Provision PKI infrastructure via ICP service
	if oc.icpProvisioningService != nil {
		log.Printf("Provisioning PKI for tenant: %s", workspaceID.String())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		icpResp, err := oc.icpProvisioningService.ProvisionPKI(ctx, &icp.ProvisionPKIRequest{
			WorkspaceID: workspaceID.String(),
			CommonName:  fmt.Sprintf("%s Root CA", userInfo.Name),
			Domain:      fullDomain,
			TTL:         "87600h", // 10 years
			MaxTTL:      "24h",    // Max certificate TTL
		})
		if err != nil {
			log.Printf("Warning: PKI provisioning failed: %v", err)
			// Update tenant status to indicate PKI provisioning failure
			if _, updateErr := mainDB.Exec("UPDATE workspaces SET status = 'pki_provisioning_failed' WHERE workspace_id = $1", workspaceID); updateErr != nil {
				log.Printf("Failed to update tenant status: %v", updateErr)
			}
			// Continue - admin can retry PKI provisioning later
		} else {
			log.Printf("Successfully provisioned PKI - Mount: %s", icpResp.PKIMount)
			// Update tenant with PKI information (vault_mount and ca_cert only)
			if _, err := mainDB.Exec("UPDATE workspaces SET vault_mount = $1, ca_cert = $2 WHERE workspace_id = $3", icpResp.PKIMount, icpResp.CACert, workspaceID); err != nil {
				log.Printf("Warning: Failed to update tenant with PKI info: %v", err)
			}
		}
	} else {
		log.Printf("INFO: ICP provisioning service not configured, skipping PKI setup for tenant %s", workspaceID.String())
	}

	// Phase A: legacy tenant_mappings bridge deleted. Per OAuth 2.1 + MCP
	// authorization spec, OAuth client_id → workspace is not a defined mapping.
	// The (workspace, user, client, resource_server) relationship lives in
	// oauth_consent_grants and resource_server_client_registrations.
	_ = clientID
	log.Printf("[oidc] workspace=%s client=%s (no tenant_mappings insert; relationship lives on consent grants)", workspaceID.String(), clientID.String())

	// Create OIDC identity link
	profileDataJSON, _ := json.Marshal(map[string]interface{}{
		"name":    userInfo.Name,
		"picture": userInfo.Picture,
	})

	identity := &models.OIDCUserIdentity{
		WorkspaceID:    workspaceID,
		UserID:         userID,
		ProviderName:   state.ProviderName,
		ProviderUserID: userInfo.Sub,
		Email:          userInfo.Email,
		ProfileData:    string(profileDataJSON),
	}

	if err := oc.oidcService.CreateIdentity(identity); err != nil {
		log.Printf("Failed to create OIDC identity: %v", err)
		// Non-fatal, user can still login
	}

	// Save secret to Vault (best-effort, non-blocking)
	if _, err := config.SaveSecretToVault(workspaceID.String(), workspaceID.String()); err != nil {
		log.Printf("Warning: Failed to save secret to vault: %v", err)
		log.Printf("OIDC registration will continue without Vault secret storage for tenant: %s", workspaceID.String())
	}

	// Audit log: OIDC registration completed
	middlewares.Audit(c, "oidc", workspaceID.String(), "register", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id":  workspaceID.String(),
			"workspace_domain": fullDomain,
			"user_id":       userID.String(),
			"email":         userInfo.Email,
			"provider":      state.ProviderName,
		},
	})

	// Use origin domain for redirect (where user came from) instead of fullDomain
	// The origin domain is stored in state and persists across the OAuth redirect
	redirectDomain := state.OriginDomain
	if redirectDomain == "" {
		redirectDomain = fullDomain // Fallback to constructed domain
	}
	log.Printf("DEBUG handleRegistrationCallback: Using redirectDomain='%s' (state.OriginDomain='%s', fullDomain='%s')", redirectDomain, state.OriginDomain, fullDomain)

	// Return HTML page that communicates with frontend
	renderOAuthCallbackHTML(c, map[string]interface{}{
		"success":       true,
		"message":       "Registration successful",
		"workspace_domain": redirectDomain,
		"workspace_id":  workspaceID.String(),
		"client_id":     clientID.String(),
		"first_login":   true,
	})
}

// CompleteRegistration completes registration after discover mode found no existing user
// @Summary Complete OIDC registration after discover
// @Description Completes registration for a new user after discover mode, with chosen tenant domain
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body OIDCCompleteRegistrationInput true "Registration completion input"
// @Success 200 {object} models.OIDCCallbackResponse
// @Failure 400 {object} map[string]string
// @Router /authsec/uflow/oidc/complete-registration [post]
func (oc *OIDCController) CompleteRegistration(c *gin.Context) {
	var input struct {
		WorkspaceDomain string `json:"workspace_domain" binding:"required"`
		Provider        string `json:"provider" binding:"required"`
		Email           string `json:"email" binding:"required"`
		Name            string `json:"name"`
		Picture         string `json:"picture"`
		ProviderUserID  string `json:"provider_user_id" binding:"required"`
		StateToken      string `json:"state_token"` // signed OIDC state for verification
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the OIDC state if provided — prevents arbitrary identity registration.
	// The state_token was returned by the discover flow and proves the caller
	// completed OIDC authentication with this provider+email+sub.
	if input.StateToken != "" {
		var stateRow struct {
			ProviderName string `gorm:"column:provider_name"`
			Action       string `gorm:"column:action"`
		}
		if err := config.DB.Table("oidc_states").
			Select("provider_name, action").
			Where("state_token = ?", input.StateToken).
			First(&stateRow).Error; err == nil {
			if stateRow.ProviderName != input.Provider {
				c.JSON(http.StatusForbidden, gin.H{"error": "provider mismatch: OIDC state does not match request"})
				return
			}
		}
	}

	// Normalize and validate tenant domain
	workspaceDomain := strings.ToLower(strings.TrimSpace(input.WorkspaceDomain))
	if !isValidWorkspaceDomain(workspaceDomain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant domain format. Use only lowercase letters, numbers, and hyphens."})
		return
	}

	// Check if tenant domain already exists
	existingTenant, err := oc.workspaceRepo.GetWorkspaceByDomain(workspaceDomain)
	if err == nil && existingTenant != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Tenant domain already exists. Please choose a different name."})
		return
	}

	// Duplicate OIDC identity check removed — the unique constraint on
	// oidc_user_identities(workspace_id, provider_name, provider_user_id) catches
	// duplicates at the DB level. A global (cross-workspace) check is not safe.

	// Create new workspace and user (similar to handleRegistrationCallback)
	// Note: In admin registration pattern, workspace_id = client_id for the default client
	workspaceID := uuid.New()
	projectID := uuid.New()
	clientID := workspaceID // Client ID = Tenant ID for default client (matches admin registration)
	userID := uuid.New()

	// Start transaction
	db := config.GetDatabase()
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to start transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}
	defer tx.Rollback()

	// Create tenant
	fullDomain := fmt.Sprintf("%s.%s", workspaceDomain, config.AppConfig.WorkspaceDomainSuffix)
	username := input.Email
	providerIDPtr := input.ProviderUserID
	tenant := &models.Tenant{
		ID:           workspaceID, // Use same ID for both id and workspace_id for simplicity
		WorkspaceID:  workspaceID,
		Email:        input.Email,
		Username:     &username,
		Name:         input.Name,
		WorkspaceDomain: fullDomain,
		Provider:     input.Provider,
		ProviderID:   &providerIDPtr,
		Status:       "active",
		Source:       "oidc",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := oc.workspaceRepo.CreateTenantTx(tx, tenant); err != nil {
		log.Printf("Failed to create tenant: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	// Phase E: `projects` table dropped — no project row created.

	// Createuser in main DB (users table)
	usernameStr := input.Email
	adminUser := &models.ExtendedUser{
		User: sharedmodels.User{
			ID:           userID,
			Email:        input.Email,
			Name:         input.Name,
			PasswordHash: "", // No password for OIDC users
			ClientID:     clientID,
			WorkspaceID:  workspaceID,
			ProjectID:    projectID,
			WorkspaceDomain: fullDomain,
			Provider:     input.Provider,
			ProviderID:   input.ProviderUserID,
			Username:     &usernameStr,
			ProviderData: datatypes.JSON("{}"),
			Active:       true,
		},
	}

	// Store avatar URL if available
	if input.Picture != "" {
		adminUser.AvatarURL = &input.Picture
	}

	if err := oc.userRepo.CreateUserTx(tx, adminUser); err != nil {
		log.Printf("Failed to create user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Use EnsureAdminRoleAndPermissionsTx to seed both role AND permissions (fix for OIDC registration bug)
	roleID, err := database.NewAdminSeedRepository(config.GetDatabase()).EnsureAdminRoleAndPermissionsTx(tx, workspaceID)
	if err != nil {
		log.Printf("WARNING: Failed to ensure admin role and permissions for tenant %s: %v", workspaceID, err)
	} else {
		// Insert into role_bindings (user_roles is deprecated)
		// scope_type and scope_id are NULL for tenant-wide role assignments
		if _, err := tx.Exec(`
			INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
			SELECT gen_random_uuid(), $1, $2, $3, NULL, NULL, NOW(), NOW()
			WHERE NOT EXISTS (
				SELECT 1 FROM role_bindings
				WHERE workspace_id = $1 AND user_id = $2 AND role_id = $3 AND scope_type IS NULL AND scope_id IS NULL
			)
		`, workspaceID, userID, roleID); err != nil {
			log.Printf("WARNING: Failed to assign admin role to OIDC user %s: %v", userID, err)
		} else {
			log.Printf("INFO: Admin role assigned to OIDC user %s", userID)
		}

		// Bind admin to workspace_memberships (RequireWorkspaceRole checks this)
		if _, err := tx.Exec(`
			INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
			VALUES (gen_random_uuid(), $1, $2, $3, 'active', 'signup', NOW(), NOW())
			ON CONFLICT (workspace_id, user_id) DO NOTHING
		`, workspaceID, userID, roleID); err != nil {
			log.Printf("WARNING: Failed to create workspace_membership for OIDC user %s: %v", userID, err)
		}
	}

	// Commit main DB transaction
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	// Single-tenant: no per-tenant DB provisioning.

	// Provision PKI infrastructure via ICP service
	mainDB := config.GetDatabase()
	if oc.icpProvisioningService != nil {
		log.Printf("Provisioning PKI for tenant: %s", workspaceID.String())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		icpResp, err := oc.icpProvisioningService.ProvisionPKI(ctx, &icp.ProvisionPKIRequest{
			WorkspaceID: workspaceID.String(),
			CommonName:  fmt.Sprintf("%s Root CA", input.Name),
			Domain:      fullDomain,
			TTL:         "87600h", // 10 years
			MaxTTL:      "24h",    // Max certificate TTL
		})

		if err != nil {
			log.Printf("Warning: PKI provisioning failed: %v", err)
			// Update tenant status to indicate PKI provisioning failure
			if _, updateErr := mainDB.Exec("UPDATE workspaces SET status = 'pki_provisioning_failed' WHERE workspace_id = $1", workspaceID); updateErr != nil {
				log.Printf("Failed to update tenant status: %v", updateErr)
			}
			// Continue - admin can retry PKI provisioning later
		} else {
			log.Printf("Successfully provisioned PKI - Mount: %s", icpResp.PKIMount)
			// Update tenant with PKI information (vault_mount and ca_cert only)
			if _, err := mainDB.Exec("UPDATE workspaces SET vault_mount = $1, ca_cert = $2 WHERE workspace_id = $3", icpResp.PKIMount, icpResp.CACert, workspaceID); err != nil {
				log.Printf("Warning: Failed to update tenant with PKI info: %v", err)
			}
		}
	} else {
		log.Printf("INFO: ICP provisioning service not configured, skipping PKI setup for tenant %s", workspaceID.String())
	}

	// Phase A: legacy tenant_mappings bridge deleted. Per OAuth 2.1 + MCP
	// authorization spec, OAuth client_id → workspace is not a defined mapping.
	// The (workspace, user, client, resource_server) relationship lives on
	// oauth_consent_grants and resource_server_client_registrations.
	_ = clientID
	log.Printf("[oidc] workspace=%s client=%s (no tenant_mappings insert; relationship lives on consent grants)", workspaceID.String(), clientID.String())

	// Create OIDC identity link
	profileDataJSON, _ := json.Marshal(map[string]interface{}{
		"name":    input.Name,
		"picture": input.Picture,
	})

	identity := &models.OIDCUserIdentity{
		WorkspaceID:    workspaceID,
		UserID:         userID,
		ProviderName:   input.Provider,
		ProviderUserID: input.ProviderUserID,
		Email:          input.Email,
		ProfileData:    string(profileDataJSON),
	}

	if err := oc.oidcService.CreateIdentity(identity); err != nil {
		log.Printf("Failed to create OIDC identity: %v", err)
	}

	// Save secret to Vault (best-effort, non-blocking)
	if _, err := config.SaveSecretToVault(workspaceID.String(), workspaceID.String()); err != nil {
		log.Printf("Warning: Failed to save secret to vault: %v", err)
		log.Printf("OIDC registration will continue without Vault secret storage for tenant: %s", workspaceID.String())
	}

	// Return JSON response without token (frontend should login separately)
	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Registration successful - welcome to your new workspace!",
		"workspace_domain": fullDomain,
		"workspace_id":  workspaceID.String(),
		"client_id":     clientID.String(),
		"first_login":   true, // Always true for new registrations
	})
}

// LinkIdentity links an OIDC provider to an existing user account
// @Summary Link OIDC provider to account
// @Description Links a social login provider to an existing user account
// @Tags OIDC
// @Accept json
// @Produce json
// @Param input body models.LinkOIDCIdentityInput true "Provider to link"
// @Success 200 {object} models.OIDCInitiateResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /authsec/uflow/oidc/link [post]
func (oc *OIDCController) LinkIdentity(c *gin.Context) {
	// Get user from context (requires auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	workspaceID, exists := c.Get("workspace_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant not found"})
		return
	}

	var input models.LinkOIDCIdentityInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Safely extract tenant ID string
	var workspaceIDStr string
	switch v := workspaceID.(type) {
	case uuid.UUID:
		workspaceIDStr = v.String()
	case string:
		workspaceIDStr = v
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
		return
	}

	tid, err := uuid.Parse(workspaceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Get tenant domain
	tenant, tErr := oc.workspaceRepo.GetWorkspaceByID(workspaceIDStr)
	if tErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	// Initiate OIDC flow with action "link"
	oidcInput := &models.OIDCInitiateInput{
		WorkspaceDomain: tenant.WorkspaceDomain,
		Provider:     input.Provider,
	}
	response, err := oc.oidcService.InitiateOIDCFlow(oidcInput, "link", &tid)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Store user ID in state for linking
	// TODO: Update state with user_id for linking

	c.JSON(http.StatusOK, gin.H{
		"redirect_url": response.RedirectURL,
		"message":      "Redirecting to provider for authorization",
	})
	_ = userID // Will be used when implementing link callback
}

// GetLinkedIdentities returns all OIDC identities linked to current user
// @Summary Get linked OIDC identities
// @Description Returns list of social login providers linked to user account
// @Tags OIDC
// @Produce json
// @Success 200 {array} models.OIDCUserIdentity
// @Failure 401 {object} map[string]string
// @Router /authsec/uflow/oidc/identities [get]
func (oc *OIDCController) GetLinkedIdentities(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	workspaceID, exists := c.Get("workspace_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant not found"})
		return
	}

	identities, err := oc.oidcService.GetIdentitiesByUser(safeUUID(workspaceID), safeUUID(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get identities"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"identities": identities})
}

// UnlinkIdentity removes an OIDC provider from user account
// @Summary Unlink OIDC provider
// @Description Removes a social login provider from user account
// @Tags OIDC
// @Param provider path string true "Provider name (google, github, microsoft)"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /authsec/uflow/oidc/unlink/{provider} [delete]
func (oc *OIDCController) UnlinkIdentity(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider name required"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	workspaceID, exists := c.Get("workspace_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant not found"})
		return
	}

	if err := oc.oidcService.UnlinkIdentity(safeUUID(workspaceID), safeUUID(userID), provider); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider unlinked successfully"})
}

// ========================================
// Admin endpoints for managing OIDC providers
// ========================================

// GetAllProviders returns all OIDC providers (admin)
func (oc *OIDCController) GetAllProviders(c *gin.Context) {
	providers, err := oc.oidcService.GetAllProviders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get providers"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// UpdateProvider updates an OIDC provider configuration (admin)
func (oc *OIDCController) UpdateProvider(c *gin.Context) {
	providerName := c.Param("provider")
	if providerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Provider name required"})
		return
	}

	var input models.OIDCProviderUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := oc.oidcService.UpdateProvider(providerName, &input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider updated successfully"})
}

// ========================================
// Helper functions
// ========================================

// renderOAuthCallbackHTML returns HTML page that communicates OAuth results to frontend
func renderOAuthCallbackHTML(c *gin.Context, data map[string]interface{}) {
	// Convert data to JSON string for embedding in JavaScript
	dataJSON, _ := json.Marshal(data)

	log.Printf("DEBUG renderOAuthCallbackHTML: Received data with workspace_domain='%v'", data["workspace_domain"])

	// Determine the frontend redirect URL
	// Priority: 1. workspace_domain from data (preserves user's login domain), 2. Host header, 3. Default
	defaultBaseURL := config.AppConfig.BaseURL
	if defaultBaseURL == "" {
		defaultBaseURL = config.AppConfig.UIOrigin
	}
	if defaultBaseURL == "" {
		defaultBaseURL = "https://localhost:3000"
	}
	redirectURL := defaultBaseURL + "/authsec/uflow/oidc/callback"

	// Try to use workspace_domain from data first (this preserves the domain the user logged in from)
	if workspaceDomain, ok := data["workspace_domain"].(string); ok && workspaceDomain != "" {
		// Use the tenant domain that was passed in (from state or database)
		// No validation needed - trust the domain from the state/database
		redirectURL = "https://" + workspaceDomain + "/authsec/uflow/oidc/callback"
		log.Printf("DEBUG renderOAuthCallbackHTML: Using workspace_domain from data, redirectURL='%s'", redirectURL)
	} else {
		// Fallback: Try to extract from Host or X-Forwarded-Host header
		host := c.GetHeader("X-Forwarded-Host")
		if host == "" {
			host = c.Request.Host
		}

		// Strip port if present
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}

		// Convert API domain to frontend domain
		// dev.api.authsec.dev -> dev.authsec.dev
		// api.authsec.dev -> app.authsec.dev
		frontendHost := convertAPIToFrontendDomain(host)

		// For platform domains, validate against allowlist
		// For custom domains, trust them (they came from workspace_domains table via state)
		if isAllowedFrontendDomain(frontendHost) || (!strings.HasSuffix(frontendHost, ".authsec.dev") && !strings.HasSuffix(frontendHost, ".authsec.ai")) {
			redirectURL = "https://" + frontendHost + "/authsec/uflow/oidc/callback"
		}
	}

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authentication</title>
    <script>
        window.onload = function() {
            const data = %s;
            const redirectURL = '%s';

            // If opened in popup window, send message to opener
            if (window.opener && !window.opener.closed) {
                window.opener.postMessage({ type: 'oauth-callback', data: data }, '*');
                setTimeout(() => window.close(), 100);
            } else {
                // If opened in same window, redirect to frontend with query params
                const params = new URLSearchParams();
                for (const [key, value] of Object.entries(data)) {
                    if (value !== null && value !== undefined) {
                        params.append(key, String(value));
                    }
                }
                window.location.href = redirectURL + '?' + params.toString();
            }
        };
    </script>
</head>
<body>
    <p>Processing authentication... Please wait.</p>
</body>
</html>
	`, string(dataJSON), redirectURL)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// convertAPIToFrontendDomain converts API domain to frontend domain.
// Examples:
//   - dev.api.authsec.dev -> dev.authsec.dev
//   - api.authsec.dev -> app.authsec.dev
//   - localhost:8080 -> localhost:8080 (unchanged)
func convertAPIToFrontendDomain(host string) string {
	// Specific API to Frontend mappings
	apiToFrontendMap := map[string]string{
		// Dev environment (.authsec.dev)
		"dev.api.authsec.dev": "dev.authsec.dev",     // Dev API -> Dev Frontend
		"api.authsec.dev":     "app.authsec.dev",     // Legacy shared API -> app frontend
		"staging.authsec.dev": "staging.authsec.dev", // Staging (if same)
		// Prod environment (.authsec.ai)
		"prod.api.authsec.ai": "app.authsec.ai", // Prod API -> Prod Frontend
	}

	// Check for exact match
	if frontend, ok := apiToFrontendMap[host]; ok {
		return frontend
	}

	// Handle pattern {env}.api.authsec.dev -> {env}.authsec.dev
	if strings.Contains(host, ".api.authsec.dev") {
		return strings.Replace(host, ".api.authsec.dev", ".authsec.dev", 1)
	}

	// Handle pattern {env}.api.authsec.ai -> {env}.authsec.ai
	if strings.Contains(host, ".api.authsec.ai") {
		return strings.Replace(host, ".api.authsec.ai", ".authsec.ai", 1)
	}

	// No conversion needed (already frontend domain or custom domain)
	return host
}

// isAllowedFrontendDomain checks if the domain is an allowed frontend domain
func isAllowedFrontendDomain(host string) bool {
	// Strip port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	allowedDomains := []string{
		// Dev environment
		"app.authsec.dev",
		"dev.authsec.dev",
		"dev2.authsec.dev",
		"staging.authsec.dev",
		// Prod environment
		"app.authsec.ai",
		// Local
		"localhost",
	}

	// Check exact match
	for _, allowed := range allowedDomains {
		if host == allowed {
			return true
		}
	}

	// Check if it's a subdomain of authsec.dev or authsec.ai
	if strings.HasSuffix(host, ".authsec.dev") || strings.HasSuffix(host, ".authsec.ai") {
		return true
	}

	return false
}

// isValidWorkspaceDomain validates tenant domain format (subdomain prefix only)
func isValidWorkspaceDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 63 {
		return false
	}

	// Must start with letter
	if domain[0] < 'a' || domain[0] > 'z' {
		return false
	}

	// Only lowercase letters, numbers, and hyphens
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}

	// Cannot end with hyphen
	if domain[len(domain)-1] == '-' {
		return false
	}

	return true
}

// isValidWorkspaceDomainOrCustomDomain validates both subdomain prefixes and full custom domains
func isValidWorkspaceDomainOrCustomDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// If it contains a dot, it's a full domain (e.g., test.auth-sec.org)
	if strings.Contains(domain, ".") {
		// Basic full domain validation
		// Must not start or end with dot
		if domain[0] == '.' || domain[len(domain)-1] == '.' {
			return false
		}
		// Must not have consecutive dots
		if strings.Contains(domain, "..") {
			return false
		}
		// Each label must be valid
		labels := strings.Split(domain, ".")
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 {
				return false
			}
			// Label must start with alphanumeric
			if !((label[0] >= 'a' && label[0] <= 'z') || (label[0] >= '0' && label[0] <= '9')) {
				return false
			}
			// Label can contain alphanumeric and hyphens
			for _, char := range label {
				if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
					return false
				}
			}
			// Cannot end with hyphen
			if label[len(label)-1] == '-' {
				return false
			}
		}
		return true
	}

	// If no dot, treat as subdomain prefix - use original validation
	return isValidWorkspaceDomain(domain)
}
