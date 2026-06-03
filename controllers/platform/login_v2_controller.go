package platform

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// LoginV2Controller serves the auth-side endpoints that bridge Hydra's
// login + consent challenges to AuthSec. This is the API surface; the UI
// is whoever's pointed at us (could be the dev UI, could be a future
// prod UI, doesn't matter to this layer).
//
// Session 1 of the port wires only /login/page-data. Sessions 2-5 add
// /login/complete-local, OIDC initiate/callback, SAML initiate/ACS, and
// the consent handler.
//
// Mounted under /authsec/oauth/v2 in routes.go. Public — no JWT — because
// the login challenge IS the authentication context. Hydra signs it so
// we can't forge.
type LoginV2Controller struct {
	hydraLogin *services.HydraLoginService
	idpSvc     *services.IdentityProviderV2Service
	rsSvc      *services.ResourceServerService
}

func NewLoginV2Controller() *LoginV2Controller {
	return &LoginV2Controller{
		hydraLogin: services.NewHydraLoginService(),
		idpSvc:     services.NewIdentityProviderV2Service(),
		rsSvc:      services.NewResourceServerService(),
	}
}

// LoginPageDataResponse is the JSON the (separate) UI consumes to render
// the login page. The UI shows:
//   - email + password form (if the Application accepts custom-login)
//   - one button per identity_providers row (OIDC/SAML federated)
//
// Submit targets are the URLs in the `submit` block. The UI POSTs the
// user's input + the login_challenge to those endpoints. Each endpoint
// completes its half of the dance and returns a redirect_to URL the UI
// must navigate to.
type LoginPageDataResponse struct {
	Success         bool                   `json:"success"`
	LoginChallenge  string                 `json:"login_challenge"`
	ContextID       string                 `json:"context_id,omitempty"`
	TenantID        string                 `json:"tenant_id,omitempty"`
	ApplicationID   *uuid.UUID             `json:"application_id,omitempty"`
	ApplicationName string                 `json:"application_name,omitempty"`
	ResourceURI     string                 `json:"resource_uri,omitempty"`
	RequestedScope  []string               `json:"requested_scope,omitempty"`
	Skip            bool                   `json:"skip"`              // Hydra says "we have a session already, skip auth"
	Subject         string                 `json:"subject,omitempty"` // pre-existing subject if Skip=true
	IdentityProviders []LoginIDPOption     `json:"identity_providers"`
	OIDCContext     map[string]interface{} `json:"oidc_context,omitempty"` // prompt, max_age — UI may show re-auth gate
	Submit          LoginSubmitURLs        `json:"submit"`
}

// LoginIDPOption is one row the UI renders as a "Continue with X" button.
type LoginIDPOption struct {
	IdentityProviderID uuid.UUID `json:"identity_provider_id"`
	ProviderType       string    `json:"provider_type"`
	DisplayName        string    `json:"display_name"`
	// ProviderName is the underlying oidc_providers/saml_providers slug —
	// used by /login/oidc/initiate's :provider param and /login/saml/initiate's.
	ProviderName string `json:"provider_name,omitempty"`
}

// LoginSubmitURLs tells the UI where to POST for each login method.
type LoginSubmitURLs struct {
	Custom    string `json:"custom"`    // POST email+password here  (Session 2)
	OIDC      string `json:"oidc"`      // POST {provider_name, login_challenge} here  (Session 4)
	SAML      string `json:"saml"`      // POST {provider_name, login_challenge} here  (Session 5)
	Reject    string `json:"reject"`    // POST {login_challenge, reason} to abort the dance
}

// GetLoginPageData handles GET /authsec/oauth/v2/login/page-data?login_challenge=...
//
// Flow:
//  1. Read login_challenge from query string.
//  2. Call Hydra GET /admin/oauth2/auth/requests/login to fetch the
//     challenge metadata (which client, what scope, what request_url).
//  3. Parse authsec_ctx from request_url — that's our ContextID.
//  4. Look up the auth_request_context row by ContextID; bind the
//     login_challenge to it for the future /consent step to find.
//  5. Look up the Application (resource_servers) by ResourceURI.
//  6. List identity_providers for the tenant; filter by the
//     application_identity_provider_policies whitelist if any rows exist.
//  7. Return the JSON.
//
// Errors are 4xx + JSON {success:false, error:"..."}; nothing about this
// surface should ever serve HTML.
func (ctrl *LoginV2Controller) GetLoginPageData(c *gin.Context) {
	loginChallenge := c.Query("login_challenge")
	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, LoginPageDataResponse{
			Success: false,
		})
		return
	}

	loginReq, err := ctrl.hydraLogin.GetLoginRequest(loginChallenge)
	if err != nil {
		// Hydra failed; don't leak internal error to the UI.
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "login_challenge invalid or expired",
		})
		return
	}

	// Hydra "skip=true" means there's an existing user session for this
	// client — we should accept-login immediately with the existing subject
	// rather than show the page. The UI doesn't render anything; the
	// caller should POST to /login/skip-accept (Session 2) with this
	// challenge to complete the dance. For now we just surface it.
	if loginReq.Skip {
		c.JSON(http.StatusOK, LoginPageDataResponse{
			Success:        true,
			LoginChallenge: loginChallenge,
			Skip:           true,
			Subject:        loginReq.Subject,
			RequestedScope: loginReq.RequestedScope,
			Submit:         ctrl.buildSubmitURLs(),
		})
		return
	}

	// Pull authsec_ctx out of the request_url Hydra echoes back.
	contextID := extractAuthsecCtx(loginReq.RequestURL)
	if contextID == "" {
		// This is unexpected: every /oauth/v2/authorize call should set
		// authsec_ctx. If we got a login_challenge without one, the
		// dance was initiated through a different path we don't support.
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "authsec_ctx not present on this login_challenge — was the OAuth dance initiated via /authsec/oauth/v2/authorize?",
		})
		return
	}

	// Resolve the Application from the requested resource. The audience on
	// the Hydra client is the canonical pointer to resource_uri, set at
	// DCR/prereg time. We use the first audience entry — should always be
	// the Application's resource_uri.
	var resourceURI string
	if len(loginReq.Client.Audience) > 0 {
		resourceURI = loginReq.Client.Audience[0]
	}
	if resourceURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "no resource bound to this client; cannot resolve Application",
		})
		return
	}

	rs, tenantID, err := ctrl.rsSvc.GetByResourceURI(resourceURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Application not found for resource " + resourceURI,
		})
		return
	}

	// Bind the login_challenge into the auth_request_context row so the
	// /consent step can find it. Atomic update keyed by context_id.
	if err := ctrl.bindLoginChallenge(tenantID, contextID, loginChallenge); err != nil {
		// Failure here means the context row doesn't exist or was already
		// consumed — fail closed.
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "auth context lookup failed: " + err.Error(),
		})
		return
	}

	// List the tenant's identity providers, filtered by the Application's
	// IDP policy (whitelist mode when any policy rows exist, default-allow
	// otherwise).
	idps, err := ctrl.listIDPsForApplication(tenantID, rs.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "failed to list identity providers: " + err.Error(),
		})
		return
	}

	resp := LoginPageDataResponse{
		Success:           true,
		LoginChallenge:    loginChallenge,
		ContextID:         contextID,
		TenantID:          tenantID,
		ApplicationID:     &rs.ID,
		ApplicationName:   rs.Name,
		ResourceURI:       rs.ResourceURI,
		RequestedScope:    loginReq.RequestedScope,
		IdentityProviders: idps,
		Submit:            ctrl.buildSubmitURLs(),
	}
	// OIDCContext surfaces prompt + max_age if Hydra forwarded them. UI may
	// use these to render "you were asked to re-authenticate" hints.
	if len(loginReq.OIDCContext.Prompt) > 0 || loginReq.OIDCContext.MaxAge != nil {
		resp.OIDCContext = map[string]interface{}{
			"prompt":  loginReq.OIDCContext.Prompt,
			"max_age": loginReq.OIDCContext.MaxAge,
		}
	}
	c.JSON(http.StatusOK, resp)
}

// bindLoginChallenge updates the auth_request_context row identified by
// context_id, setting its login_challenge column. Idempotent: if the row
// already has the same challenge bound, this is a no-op.
func (ctrl *LoginV2Controller) bindLoginChallenge(tenantID, contextID, loginChallenge string) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return err
	}
	var existing models.AuthRequestContext
	if err := tenantDB.Where("context_id = ? AND tenant_id = ?", contextID, tenantID).
		First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("context not found")
		}
		return err
	}
	if existing.Consumed {
		return errors.New("context already consumed")
	}
	return tenantDB.Model(&existing).
		Update("login_challenge", loginChallenge).Error
}

// listIDPsForApplication returns the IDP options the UI should display.
// Default-allow when the Application has no application_identity_provider_policies
// rows; whitelist mode when it does (only enabled rows pass through).
func (ctrl *LoginV2Controller) listIDPsForApplication(tenantID string, applicationID uuid.UUID) ([]LoginIDPOption, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, err
	}
	// Are there any policy rows for this Application? If yes, only return
	// enabled IDPs that have a policy row. If no, return all configured
	// IDPs for the tenant.
	var policyCount int64
	if err := tenantDB.Model(&models.ApplicationIdentityProviderPolicy{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&policyCount).Error; err != nil {
		return nil, err
	}

	var idps []models.IdentityProvider
	q := tenantDB.Where("tenant_id = ? AND status = ?", tenantID, "configured")
	if policyCount > 0 {
		q = q.Where(`id IN (
            SELECT identity_provider_id
              FROM application_identity_provider_policies
             WHERE application_id = ? AND enabled = true
        )`, applicationID)
	}
	if err := q.Order("display_name ASC").Find(&idps).Error; err != nil {
		return nil, err
	}

	out := make([]LoginIDPOption, 0, len(idps))
	for _, idp := range idps {
		opt := LoginIDPOption{
			IdentityProviderID: idp.ID,
			ProviderType:       idp.ProviderType,
			DisplayName:        idp.DisplayName,
		}
		// For OIDC/SAML, the provider_name is on the underlying config row.
		// We don't hydrate it here — the /login/oidc/initiate and
		// /login/saml/initiate handlers (Sessions 4-5) resolve it via
		// config_ref. For now leave ProviderName empty; the UI uses the
		// IdentityProviderID as the click target.
		out = append(out, opt)
	}
	return out, nil
}

// buildSubmitURLs returns the URLs the UI uses to POST login decisions.
// Sessions 2-5 land the handlers; for now we surface the URLs so consumers
// know what to wire up.
func (ctrl *LoginV2Controller) buildSubmitURLs() LoginSubmitURLs {
	base := strings.TrimSuffix(config.AppConfig.OAuthBaseURL, "/")
	if base == "" {
		// Match the well-known sentinel: ops grep for this in logs.
		base = "https://authsec-oauth-base-url-not-configured.invalid"
	}
	return LoginSubmitURLs{
		Custom: base + "/authsec/oauth/v2/login/complete-local",
		OIDC:   base + "/authsec/oauth/v2/login/oidc/initiate",
		SAML:   base + "/authsec/oauth/v2/login/saml/initiate",
		Reject: base + "/authsec/oauth/v2/login/reject",
	}
}

// extractAuthsecCtx parses authsec_ctx from Hydra's request_url. The URL
// looks like:
//
//	https://oauth.example.com/oauth2/auth?client_id=...&authsec_ctx=<uuid>&...
//
// We just pull the query param. Returns "" if not present or unparseable.
func extractAuthsecCtx(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("authsec_ctx")
}

// ─────────────────────────────────────────────────────────────────────────
// Session 2 — Custom-login completion (email + password)
// ─────────────────────────────────────────────────────────────────────────

// CompleteCustomLoginRequest is the body the (separate) UI POSTs after
// the user enters email + password on the login page.
type CompleteCustomLoginRequest struct {
	LoginChallenge string `json:"login_challenge" binding:"required"`
	Email          string `json:"email" binding:"required,email"`
	Password       string `json:"password" binding:"required"`
	// Remember, when true, asks Hydra to skip auth on next visit for this
	// client + subject pair. UI usually surfaces this as a "Keep me signed
	// in" checkbox. Default false to be safe.
	Remember bool `json:"remember,omitempty"`
}

// CompleteCustomLoginResponse tells the UI where to send the browser next.
// Hydra's redirect_to is the canonical answer — it'll be the consent
// endpoint URL (or, if Hydra remembers consent, directly back to the
// client's redirect_uri with a code).
type CompleteCustomLoginResponse struct {
	Success    bool   `json:"success"`
	RedirectTo string `json:"redirect_to,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CompleteCustomLogin handles POST /authsec/oauth/v2/login/complete-local.
//
// Flow:
//
//  1. Read body: login_challenge, email, password.
//  2. Look up auth_request_context by login_challenge to get tenant_id +
//     application_id (set by /login/page-data earlier in the dance).
//  3. Look up the user in the tenant DB by email + provider IN
//     ('custom', 'ad_sync', 'entra_id', 'scim'). Federated-only users
//     (provider='oidc') go through /login/oidc/initiate instead.
//  4. Verify password via bcrypt.
//  5. Call Hydra accept-login with subject=user.id (UUID string) — the
//     RBAC introspect filter (commit 2d9f8ae) requires sub to be a
//     parseable UUID matching users.id.
//  6. Update auth_request_context: user_id, auth_time.
//  7. Return Hydra's redirect_to so the UI navigates the browser.
//
// All errors are 4xx JSON; no HTML, no PII in error_description.
func (ctrl *LoginV2Controller) CompleteCustomLogin(c *gin.Context) {
	var req CompleteCustomLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CompleteCustomLoginResponse{
			Success: false,
			Error:   "invalid request body",
		})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// 1. Find the auth context by login_challenge. The /login/page-data
	// handler bound it; if it's missing here, the UI is calling out of
	// order or the challenge expired.
	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, CompleteCustomLoginResponse{
			Success: false,
			Error:   "login_challenge not found or expired",
		})
		return
	}

	// 2. Look up the user in the tenant DB. Same provider filter as the
	// legacy /uflow/auth/enduser/login handler so the contract matches.
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{
			Success: false,
			Error:   "tenant database unavailable",
		})
		return
	}
	var user models.ExtendedUser
	err = tenantDB.Where(
		"email = ? AND provider IN ?",
		req.Email,
		[]string{"custom", "ad_sync", "entra_id", "scim"},
	).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Don't leak which is wrong (no-such-user vs bad-password).
			c.JSON(http.StatusUnauthorized, CompleteCustomLoginResponse{
				Success: false,
				Error:   "invalid credentials",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{
			Success: false,
			Error:   "user lookup failed",
		})
		return
	}
	if !user.Active {
		c.JSON(http.StatusUnauthorized, CompleteCustomLoginResponse{
			Success: false,
			Error:   "user is not active",
		})
		return
	}

	// 3. Verify password.
	if !user.CheckPassword(req.Password) {
		c.JSON(http.StatusUnauthorized, CompleteCustomLoginResponse{
			Success: false,
			Error:   "invalid credentials",
		})
		return
	}

	// 4. Call Hydra accept-login.
	rememberFor := 0
	if req.Remember {
		// 8 hours default — same as dev. Hydra caches the consent session
		// for this duration; subsequent /authorize calls for the same
		// (client, subject) within the window skip the login prompt.
		rememberFor = 8 * 3600
	}
	acceptResp, err := ctrl.hydraLogin.AcceptLoginRequest(req.LoginChallenge, services.HydraAcceptLoginRequest{
		Subject:     user.ID.String(),
		Remember:    req.Remember,
		RememberFor: rememberFor,
		ACR:         "pwd", // bare password — acr=pwd per RFC 8176
		Context: map[string]interface{}{
			"email":       user.Email,
			"name":        user.Name,
			"provider":    user.Provider,
			"auth_method": "custom_login",
			"tenant_id":   tenantID,
			"context_id":  arcRow.ContextID,
		},
	})
	if err != nil {
		// Hydra accept failed — log server-side, return generic to UI.
		c.JSON(http.StatusBadGateway, CompleteCustomLoginResponse{
			Success: false,
			Error:   "authorization server unavailable",
		})
		return
	}

	// 5. Stamp user_id + auth_time onto auth_request_context. The consent
	// step (Session 3) reads these to populate the access token's session
	// claims.
	now := time.Now().UTC()
	if err := tenantDB.Model(&arcRow).Updates(map[string]interface{}{
		"user_id":   user.ID,
		"auth_time": now,
	}).Error; err != nil {
		// We've already told Hydra we accepted — best-effort log + continue.
		// The token exchange downstream will work because Hydra has the
		// subject; only our session-claim hydration is degraded.
		log.Printf("[login-v2] failed to write user_id onto context_id=%s: %v", arcRow.ContextID, err)
	}

	c.JSON(http.StatusOK, CompleteCustomLoginResponse{
		Success:    true,
		RedirectTo: acceptResp.RedirectTo,
	})
}

// findContextByLoginChallenge resolves the auth_request_context row whose
// login_challenge column matches. Returns the row + the tenant_id we
// pulled from it.
//
// Tricky: we don't know which tenant DB to query because login_challenge
// isn't on the master-side index. So we need a way to find the right
// tenant. Two approaches:
//
//   - (a) Cross-DB search: query every tenant DB until found. O(tenants).
//   - (b) Add login_challenge to a master-side index. Adds schema +
//         lockstep writes.
//
// We use the GetLoginRequest call's request_url -> authsec_ctx -> Application
// resource_uri -> resource_server_tenant_index path that /login/page-data
// already uses. So this lookup is "fetch from Hydra, then resolve."
func (ctrl *LoginV2Controller) findContextByLoginChallenge(loginChallenge string) (*models.AuthRequestContext, string, error) {
	hydraReq, err := ctrl.hydraLogin.GetLoginRequest(loginChallenge)
	if err != nil {
		return nil, "", err
	}
	contextID := extractAuthsecCtx(hydraReq.RequestURL)
	if contextID == "" {
		return nil, "", errors.New("authsec_ctx not in login request")
	}
	if len(hydraReq.Client.Audience) == 0 {
		return nil, "", errors.New("no resource bound to client")
	}
	_, tenantID, err := ctrl.rsSvc.GetByResourceURI(hydraReq.Client.Audience[0])
	if err != nil {
		return nil, "", err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, "", err
	}
	var arc models.AuthRequestContext
	if err := tenantDB.Where("context_id = ? AND tenant_id = ?", contextID, tenantID).
		First(&arc).Error; err != nil {
		return nil, "", err
	}
	if arc.Consumed {
		return nil, "", errors.New("context already consumed")
	}
	return &arc, tenantID, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Session 2 — Reject (user clicked Cancel on the login page)
// ─────────────────────────────────────────────────────────────────────────

// RejectLoginRequest is the body for /login/reject.
type RejectLoginRequestBody struct {
	LoginChallenge   string `json:"login_challenge" binding:"required"`
	Reason           string `json:"reason,omitempty"`
}

// RejectLogin handles POST /authsec/oauth/v2/login/reject. Used when the
// user clicks "Cancel" or "Back to app" on the login page. Tells Hydra
// to abort the dance; returns a redirect_to that ends up back at the
// client's redirect_uri with ?error=access_denied.
func (ctrl *LoginV2Controller) RejectLogin(c *gin.Context) {
	var req RejectLoginRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "User cancelled login"
	}
	resp, err := ctrl.hydraLogin.RejectLoginRequest(req.LoginChallenge, services.HydraRejectLoginRequest{
		Error:            "access_denied",
		ErrorDescription: reason,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": resp.RedirectTo})
}
