package platform

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

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
