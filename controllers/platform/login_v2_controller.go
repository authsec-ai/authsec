package platform

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	hydramodels "github.com/authsec-ai/authsec/internal/hydra/models"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	sharedmodels "github.com/authsec-ai/sharedmodels"
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
	hydraLogin     *services.HydraLoginService
	idpSvc         *services.IdentityProviderV2Service
	rsSvc          *services.ResourceServerService
	bindingSvc     *services.BindingService
	consentGrantSvc *services.ConsentGrantService
	federatedSvc   *services.FederatedLoginService
}

func NewLoginV2Controller() *LoginV2Controller {
	return &LoginV2Controller{
		hydraLogin:      services.NewHydraLoginService(),
		idpSvc:          services.NewIdentityProviderV2Service(),
		rsSvc:           services.NewResourceServerService(),
		bindingSvc:      services.NewBindingService(),
		consentGrantSvc: services.NewConsentGrantService(),
		federatedSvc:    services.NewFederatedLoginService(),
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
	RedirectTo      string                 `json:"redirect_to,omitempty"` // set on Skip: where the browser should continue (Hydra)
	Error           string                 `json:"error,omitempty"`
	IdentityProviders []LoginIDPOption     `json:"identity_providers"`
	OIDCContext     map[string]interface{} `json:"oidc_context,omitempty"` // prompt, max_age — UI may show re-auth gate
	Submit          LoginSubmitURLs        `json:"submit"`
	// Step drives the SPA: "" / "login" = show login form; "webauthn" = primary
	// auth already done (user_id stamped), run the 2FA ceremony. WebauthnMode is
	// "enroll" (no passkey yet) or "authenticate". Email identifies the user.
	Step         string `json:"step,omitempty"`
	WebauthnMode string `json:"webauthn_mode,omitempty"`
	Email        string `json:"email,omitempty"`
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

	// Note: Hydra "skip=true" (an existing session for this client) is handled
	// below, AFTER we resolve + bind the auth_request_context — we auto-accept
	// the login with the existing subject and continue to consent rather than
	// dead-ending the user on a "sign in again" page.

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

	// Resolve the Application from the requested resource. Preferred path
	// is the audience on the Hydra client, set at DCR/prereg time. Fallback:
	// parse the `resource` (RFC 8707) query param from the request_url Hydra
	// echoes back — this covers DCR clients whose audience wasn't persisted
	// for whatever reason (older DCR flows, Hydra config drops, etc.).
	var resourceURI string
	if len(loginReq.Client.Audience) > 0 {
		resourceURI = loginReq.Client.Audience[0]
	}
	if resourceURI == "" {
		if u, err := url.Parse(loginReq.RequestURL); err == nil {
			resourceURI = u.Query().Get("resource")
		}
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

	// Pending second factor: primary auth already stamped user_id (e.g. the
	// browser was bounced back here after an OIDC/SAML callback, or the page
	// was reloaded mid-2FA) but the WebAuthn ceremony isn't done. Surface the
	// 2FA step instead of the login form so the SPA runs it.
	if tdb, derr := config.GetTenantGORMDB(tenantID); derr == nil {
		var arc models.AuthRequestContext
		if ferr := tdb.Where("login_challenge = ? AND tenant_id = ?", loginChallenge, tenantID).
			First(&arc).Error; ferr == nil && arc.UserID != nil && !arc.SecondFactorCompleted {
			mode := "authenticate"
			var credCount int64
			_ = tdb.Table("credentials").Where("client_id = ?", *arc.UserID).Count(&credCount).Error
			if credCount == 0 {
				mode = "enroll"
			}
			var email string
			_ = tdb.Raw(`SELECT COALESCE(email,'') FROM users WHERE id = ?`, *arc.UserID).Scan(&email).Error
			c.JSON(http.StatusOK, LoginPageDataResponse{
				Success:         true,
				LoginChallenge:  loginChallenge,
				TenantID:        tenantID,
				ApplicationName: rs.Name,
				RequestedScope:  loginReq.RequestedScope,
				Step:            "webauthn",
				WebauthnMode:    mode,
				Email:           email,
				Submit:          ctrl.buildSubmitURLs(),
			})
			return
		}
	}

	// Skip mode: Hydra already has a remembered session for this client. Don't
	// silently accept — surface the existing subject so the UI can offer a
	// quick "Continue as <subject>" (SkipAccept) or "Sign in as a different
	// user" (SwitchUser, which revokes the Hydra login session and re-prompts).
	// The login_challenge is already bound above, so SkipAccept can resolve the
	// context to stamp user_id.
	if loginReq.Skip && strings.TrimSpace(loginReq.Subject) != "" {
		c.JSON(http.StatusOK, LoginPageDataResponse{
			Success:         true,
			LoginChallenge:  loginChallenge,
			ContextID:       contextID,
			TenantID:        tenantID,
			ApplicationID:   &rs.ID,
			ApplicationName: rs.Name,
			ResourceURI:     rs.ResourceURI,
			RequestedScope:  loginReq.RequestedScope,
			Skip:            true,
			Subject:         loginReq.Subject,
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
		// Hydrate provider_name from the underlying config row so the UI
		// can render an icon ("google", "github", "microsoft", ...) without
		// a second lookup. config_ref is the foreign key to oidc_providers
		// (or saml_providers when that lands). Failures are non-fatal — we
		// just leave ProviderName empty and let the UI fall back to
		// DisplayName.
		if configUUID, err := uuid.Parse(idp.ConfigRef); err == nil {
			switch idp.ProviderType {
			case models.IdentityProviderOIDC:
				var row struct {
					ProviderName string `gorm:"column:provider_name"`
				}
				_ = tenantDB.Table("oidc_providers").
					Select("provider_name").
					Where("id = ?", configUUID).
					Scan(&row).Error
				opt.ProviderName = row.ProviderName
			}
			// SAML side: when SAML lands, look up saml_providers.provider_name
			// here. Stub for now.
		}
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
	// NeedsWebauthn signals the UI to run the WebAuthn 2FA step before the
	// login is accepted. Email + TenantID are echoed so the UI can drive the
	// ceremony. When true, RedirectTo is empty.
	NeedsWebauthn bool   `json:"needs_webauthn,omitempty"`
	Email         string `json:"email,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
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

	// 4. Stamp user_id onto auth_request_context but DO NOT accept the Hydra
	// login yet — the WebAuthn 2FA step (enroll first time, challenge after)
	// runs next and accepts the login on success. auth_time is stamped then.
	if err := tenantDB.Model(&arcRow).Updates(map[string]interface{}{
		"user_id": user.ID,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{
			Success: false,
			Error:   "failed to persist login state",
		})
		return
	}

	c.JSON(http.StatusOK, CompleteCustomLoginResponse{
		Success:       true,
		NeedsWebauthn: true,
		Email:         user.Email,
		TenantID:      tenantID,
	})
}

// RegisterEndUserRequest is the body for OAuth-flow email/pass self-registration.
type RegisterEndUserRequest struct {
	LoginChallenge string `json:"login_challenge" binding:"required"`
	Email          string `json:"email" binding:"required,email"`
	Password       string `json:"password" binding:"required,min=8"`
	Name           string `json:"name,omitempty"`
}

// RegisterEndUser handles POST /authsec/oauth/v2/login/register. It creates a
// `custom` end-user scoped to the Application (mirrors the OIDC JIT anchoring),
// stamps user_id on the auth_request_context, and returns needs_webauthn so the
// UI immediately enrolls a passkey before the login is accepted. No email OTP.
func (ctrl *LoginV2Controller) RegisterEndUser(c *gin.Context) {
	var req RegisterEndUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CompleteCustomLoginResponse{Success: false, Error: "email and a password of at least 8 characters are required"})
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, CompleteCustomLoginResponse{Success: false, Error: "login_challenge invalid or expired"})
		return
	}
	if arcRow.ResourceServerID == nil {
		c.JSON(http.StatusBadRequest, CompleteCustomLoginResponse{Success: false, Error: "no application bound to this request"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "tenant db unavailable"})
		return
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "invalid tenant"})
		return
	}

	// Reject if an account with this email already exists in the tenant — they
	// should sign in instead. Matches the login lookup (email + local providers).
	var existing int64
	if err := tenantDB.Table("users").
		Where("LOWER(email) = ? AND tenant_id = ? AND provider IN ?",
			req.Email, tenantUUID, []string{"custom", "ad_sync", "entra_id", "scim"}).
		Count(&existing).Error; err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "registration check failed"})
		return
	}
	if existing > 0 {
		c.JSON(http.StatusConflict, CompleteCustomLoginResponse{Success: false, Error: "an account with this email already exists; please sign in"})
		return
	}

	// Anchor users.client_id + project_id to a real clients row, preferring
	// the Application's legacy_client_id (mirrors resolveOrJITFederatedUser).
	var rs models.ResourceServer
	if err := tenantDB.Where("id = ?", *arcRow.ResourceServerID).First(&rs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "application lookup failed"})
		return
	}
	var clientRow struct {
		ClientID  uuid.UUID `gorm:"column:client_id"`
		ProjectID uuid.UUID `gorm:"column:project_id"`
	}
	cq := tenantDB.Table("clients").Select("client_id, project_id").Where("tenant_id = ? AND active = true", tenantUUID)
	if rs.LegacyClientID != nil {
		cq = cq.Where("client_id = ?", *rs.LegacyClientID)
	}
	if err := cq.Order("created_at ASC").First(&clientRow).Error; err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "could not anchor account"})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Email
	}
	hashUser := sharedmodels.User{PasswordHash: req.Password}
	if err := hashUser.HashPassword(); err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "could not secure password"})
		return
	}

	now := time.Now().UTC()
	newUserID := uuid.New()
	insertSQL := `
		INSERT INTO users (
			id, client_id, tenant_id, project_id, resource_server_id,
			name, email, password_hash, tenant_domain, provider, provider_id,
			active, created_at, updated_at
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?, 'custom', ?,
			true, ?, ?
		)`
	if err := tenantDB.Exec(insertSQL,
		newUserID, clientRow.ClientID, tenantUUID, clientRow.ProjectID, *arcRow.ResourceServerID,
		name, req.Email, hashUser.PasswordHash, config.AppConfig.TenantDomainSuffix, req.Email,
		now, now,
	).Error; err != nil {
		log.Printf("[login-v2-register] create user failed: %v", err)
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "could not create account"})
		return
	}

	// Stamp user_id; the WebAuthn enrollment step accepts the login next.
	if err := tenantDB.Model(&arcRow).Updates(map[string]interface{}{"user_id": newUserID}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, CompleteCustomLoginResponse{Success: false, Error: "failed to persist registration"})
		return
	}

	c.JSON(http.StatusOK, CompleteCustomLoginResponse{
		Success:       true,
		NeedsWebauthn: true,
		Email:         req.Email,
		TenantID:      tenantID,
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
	// Resolve resource_uri. Preferred path is the Hydra client's audience
	// (set at DCR/prereg time). Fallback: parse `resource` (RFC 8707) from
	// the request_url Hydra echoes back. Same fallback as /login/page-data.
	var resourceURI string
	if len(hydraReq.Client.Audience) > 0 {
		resourceURI = hydraReq.Client.Audience[0]
	}
	if resourceURI == "" {
		if u, parseErr := url.Parse(hydraReq.RequestURL); parseErr == nil {
			resourceURI = u.Query().Get("resource")
		}
	}
	if resourceURI == "" {
		return nil, "", errors.New("no resource bound to client")
	}
	_, tenantID, err := ctrl.rsSvc.GetByResourceURI(resourceURI)
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

// SkipAccept handles POST /authsec/oauth/v2/login/skip-accept. Called when the
// user chooses "Continue as <existing account>" on the skip chooser. Accepts
// the Hydra login with the remembered subject and stamps the context so the
// consent step can resolve scopes.
func (ctrl *LoginV2Controller) SkipAccept(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	loginReq, err := ctrl.hydraLogin.GetLoginRequest(req.LoginChallenge)
	if err != nil || strings.TrimSpace(loginReq.Subject) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge invalid or no existing session"})
		return
	}
	arcRow, tenantID, ctxErr := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	acceptResp, aerr := ctrl.hydraLogin.AcceptLoginRequest(req.LoginChallenge, services.HydraAcceptLoginRequest{
		Subject:     loginReq.Subject,
		Remember:    true,
		RememberFor: 8 * 3600,
		ACR:         "skip", // existing session reuse
		Context: map[string]interface{}{
			"auth_method": "session_reuse",
			"tenant_id":   tenantID,
		},
	})
	if aerr != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	// Best-effort stamp of user_id + auth_time so consent can resolve scopes.
	if ctxErr == nil {
		if tenantDB, dbErr := config.GetTenantGORMDB(tenantID); dbErr == nil {
			now := time.Now().UTC()
			_ = tenantDB.Model(&arcRow).Updates(map[string]interface{}{
				"user_id":   loginReq.Subject,
				"auth_time": now,
			}).Error
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": acceptResp.RedirectTo})
}

// SwitchUser handles POST /authsec/oauth/v2/login/switch-user. Called when the
// user chooses "Sign in as a different user" on the skip chooser. Revokes the
// remembered Hydra LOGIN session for the current subject (server-side — the CLI
// dropping its local token does NOT clear this, which is why clearing the CLI
// alone didn't change anything) and returns the original authorize URL so the
// browser can re-run the dance; with the session gone, Hydra no longer skips
// and the login form is shown.
func (ctrl *LoginV2Controller) SwitchUser(c *gin.Context) {
	var req struct {
		LoginChallenge string `json:"login_challenge" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	loginReq, err := ctrl.hydraLogin.GetLoginRequest(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "login_challenge invalid or expired"})
		return
	}
	if subject := strings.TrimSpace(loginReq.Subject); subject != "" {
		if rerr := services.RevokeV2LoginSession(subject); rerr != nil {
			// Non-fatal: log and still send them back to re-authorize. Worst
			// case Hydra still has the session and skips again.
			log.Printf("[login-v2] switch-user: revoke login session for subject=%s failed: %v", subject, rerr)
		}
	}
	if strings.TrimSpace(loginReq.RequestURL) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "no authorize URL to re-initiate login"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": loginReq.RequestURL})
}

// ─────────────────────────────────────────────────────────────────────────
// Session 3 — Consent handler
// ─────────────────────────────────────────────────────────────────────────

// ConsentPageDataResponse is what GET /consent returns. The (separate) UI
// reads this and either:
//   - shows a consent screen with the grantable scopes + a remember
//     checkbox (when auto_approved=false), OR
//   - immediately navigates the browser to redirect_to (when auto_approved=
//     true; happens when the user previously remembered consent for this
//     same client+application+scopeset).
//
// rejected_scopes is informational only — surfaces "you asked for X but
// don't have it" so the consent UI can show a tooltip. The dance proceeds
// with grantable_scopes only; rejected scopes never make it into the token.
type ConsentPageDataResponse struct {
	Success           bool              `json:"success"`
	ConsentChallenge  string            `json:"consent_challenge"`
	AutoApproved      bool              `json:"auto_approved"`
	RedirectTo        string            `json:"redirect_to,omitempty"` // set when AutoApproved=true OR after POST
	ApplicationID     *uuid.UUID        `json:"application_id,omitempty"`
	ApplicationName   string            `json:"application_name,omitempty"`
	ResourceURI       string            `json:"resource_uri,omitempty"`
	ClientID          string            `json:"client_id,omitempty"`
	Subject           string            `json:"subject,omitempty"`
	RequestedScopes   []string          `json:"requested_scopes,omitempty"`
	GrantableScopes   []string          `json:"grantable_scopes,omitempty"`
	RejectedScopes    map[string]string `json:"rejected_scopes,omitempty"` // scope -> reason
	Error             string            `json:"error,omitempty"`
	Submit            ConsentSubmitURLs `json:"submit"`
}

// ConsentSubmitURLs tells the UI where to POST consent decisions.
type ConsentSubmitURLs struct {
	Accept string `json:"accept"`
	Reject string `json:"reject"`
}

// GetConsentPageData handles GET /authsec/oauth/v2/consent?consent_challenge=...
//
// Flow:
//
//  1. Read consent_challenge from query.
//  2. Call Hydra GET /requests/consent to fetch metadata (subject, client,
//     requested scopes, audience).
//  3. Resolve the auth_request_context row by walking authsec_ctx in
//     request_url (same pattern as /login/page-data). Bind
//     consent_challenge to the row.
//  4. Load the Application; compute grantable scopes via
//     BindingService.ResolveGrantableScopes (3-way intersection).
//  5. Look up an existing oauth_consent_grants row for this
//     (user, client, application). If found AND its granted_scopes is
//     a superset of grantable scopes, auto-approve: call
//     finalizeConsent immediately and return RedirectTo. UI just navigates.
//  6. Otherwise return ConsentPageDataResponse with AutoApproved=false
//     and Grantable/Rejected scopes for the UI to render.
func (ctrl *LoginV2Controller) GetConsentPageData(c *gin.Context) {
	consentChallenge := c.Query("consent_challenge")
	if consentChallenge == "" {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "consent_challenge required",
		})
		return
	}

	consentReq, err := ctrl.hydraLogin.GetConsentRequest(consentChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "consent_challenge invalid or expired",
		})
		return
	}

	// Resolve auth_request_context. The consent challenge's request_url
	// is the same /oauth2/auth URL Hydra received — it still has
	// authsec_ctx on it.
	contextID := extractAuthsecCtx(consentReq.RequestURL)
	if contextID == "" {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "authsec_ctx missing — dance not initiated via /authsec/oauth/v2/authorize",
		})
		return
	}
	// Resolve resource_uri. Preferred path is the Hydra client's audience
	// (set at DCR/prereg time). Fallback: parse `resource` (RFC 8707) from
	// the request_url Hydra echoes back. Same fallback as /login/page-data
	// and findContextByLoginChallenge — DCR'd MCP clients don't always
	// get audience persisted in Hydra.
	var resourceURI string
	if len(consentReq.Client.Audience) > 0 {
		resourceURI = consentReq.Client.Audience[0]
	}
	if resourceURI == "" {
		if u, parseErr := url.Parse(consentReq.RequestURL); parseErr == nil {
			resourceURI = u.Query().Get("resource")
		}
	}
	if resourceURI == "" {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "no resource bound to client",
		})
		return
	}
	rs, tenantID, err := ctrl.rsSvc.GetByResourceURI(resourceURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "Application not found for resource",
		})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ConsentPageDataResponse{
			Success: false, Error: "tenant db unavailable",
		})
		return
	}
	var arcRow models.AuthRequestContext
	if err := tenantDB.Where("context_id = ? AND tenant_id = ?", contextID, tenantID).
		First(&arcRow).Error; err != nil {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "auth context not found",
		})
		return
	}
	if arcRow.Consumed {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "auth context already consumed",
		})
		return
	}

	// Bind consent_challenge to the row so POST can find it.
	if err := tenantDB.Model(&arcRow).
		Update("consent_challenge", consentChallenge).Error; err != nil {
		log.Printf("[consent-v2] failed to bind consent_challenge ctx=%s: %v", contextID, err)
	}

	// Parse subject — must be a UUID (set by login complete-local or OIDC).
	subjectUUID, err := uuid.Parse(consentReq.Subject)
	if err != nil {
		c.JSON(http.StatusBadRequest, ConsentPageDataResponse{
			Success: false, Error: "subject is not a valid uuid; non-user tokens cannot use this consent path",
		})
		return
	}

	// 3-way scope intersection.
	log.Printf("[consent-v2] resolving grant: tenant=%s app=%s subject=%s requested=%v client_id=%s",
		tenantID, rs.ID, subjectUUID, consentReq.RequestedScope, consentReq.Client.ClientID)
	grant, err := ctrl.bindingSvc.ResolveGrantableScopes(
		tenantID, rs.ID, subjectUUID, consentReq.RequestedScope,
	)
	if err != nil {
		log.Printf("[consent-v2] ResolveGrantableScopes failed ctx=%s: %v", contextID, err)
		c.JSON(http.StatusInternalServerError, ConsentPageDataResponse{
			Success: false, Error: "scope resolution failed",
		})
		return
	}
	log.Printf("[consent-v2] resolved grant: grantable=%v rejected=%v", grant.Grantable, grant.Rejected)
	if len(grant.Grantable) == 0 {
		// No scope intersection at all — reject the consent. Hydra
		// returns a redirect_to back to the client with access_denied.
		ctrl.rejectConsent(c, consentChallenge, "no grantable scopes", grant)
		return
	}

	// Look for a remembered consent grant for this (user, client, app).
	existing, err := ctrl.consentGrantSvc.LookupActiveGrant(
		tenantID, subjectUUID, consentReq.Client.ClientID, rs.ID,
	)
	if err != nil {
		log.Printf("[consent-v2] LookupActiveGrant failed: %v", err)
		// Don't block on this — proceed without auto-approve.
	}
	// Auto-approve only if the remembered grant covers EVERY grantable scope.
	if existing != nil && coversAll(existing.GrantedScopes, grant.Grantable) {
		redirectTo, ferr := ctrl.finalizeConsent(
			c, consentChallenge, consentReq, &arcRow, rs, tenantID,
			grant.Grantable, subjectUUID, false /* don't double-remember */, tenantDB,
		)
		if ferr != nil {
			c.JSON(http.StatusInternalServerError, ConsentPageDataResponse{
				Success: false, Error: ferr.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, ConsentPageDataResponse{
			Success:          true,
			ConsentChallenge: consentChallenge,
			AutoApproved:     true,
			RedirectTo:       redirectTo,
			ApplicationID:    &rs.ID,
			ApplicationName:  rs.Name,
			ResourceURI:      rs.ResourceURI,
			ClientID:         consentReq.Client.ClientID,
			Subject:          consentReq.Subject,
			RequestedScopes:  consentReq.RequestedScope,
			GrantableScopes:  grant.Grantable,
			RejectedScopes:   grant.Rejected,
			Submit:           ctrl.buildConsentSubmitURLs(),
		})
		return
	}

	// Render path: return data for the UI to show the consent screen.
	c.JSON(http.StatusOK, ConsentPageDataResponse{
		Success:          true,
		ConsentChallenge: consentChallenge,
		AutoApproved:     false,
		ApplicationID:    &rs.ID,
		ApplicationName:  rs.Name,
		ResourceURI:      rs.ResourceURI,
		ClientID:         consentReq.Client.ClientID,
		Subject:          consentReq.Subject,
		RequestedScopes:  consentReq.RequestedScope,
		GrantableScopes:  grant.Grantable,
		RejectedScopes:   grant.Rejected,
		Submit:           ctrl.buildConsentSubmitURLs(),
	})
}

// AcceptConsentRequest is the body for POST /consent/accept.
type AcceptConsentRequestBody struct {
	ConsentChallenge string   `json:"consent_challenge" binding:"required"`
	// GrantScope is the user's chosen subset of grantable scopes. The UI
	// may let the user uncheck some scopes; the backend re-enforces that
	// every entry must be in the freshly-computed grantable set (otherwise
	// a malicious UI could request more than the user has).
	GrantScope []string `json:"grant_scope"`
	Remember   bool     `json:"remember,omitempty"`
}

// AcceptConsent handles POST /authsec/oauth/v2/consent/accept. User clicked
// Approve.
func (ctrl *LoginV2Controller) AcceptConsent(c *gin.Context) {
	var req AcceptConsentRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}

	consentReq, err := ctrl.hydraLogin.GetConsentRequest(req.ConsentChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "consent_challenge invalid or expired"})
		return
	}
	contextID := extractAuthsecCtx(consentReq.RequestURL)
	if contextID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid consent context"})
		return
	}
	// Resource resolution: audience first, fallback to request_url.resource.
	var resourceURI string
	if len(consentReq.Client.Audience) > 0 {
		resourceURI = consentReq.Client.Audience[0]
	}
	if resourceURI == "" {
		if u, parseErr := url.Parse(consentReq.RequestURL); parseErr == nil {
			resourceURI = u.Query().Get("resource")
		}
	}
	if resourceURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid consent context"})
		return
	}
	rs, tenantID, err := ctrl.rsSvc.GetByResourceURI(resourceURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Application not found"})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "tenant db unavailable"})
		return
	}
	var arcRow models.AuthRequestContext
	if err := tenantDB.Where("context_id = ? AND tenant_id = ?", contextID, tenantID).
		First(&arcRow).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "auth context not found"})
		return
	}
	subjectUUID, err := uuid.Parse(consentReq.Subject)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "subject not a valid uuid"})
		return
	}

	// Re-resolve grantable scopes — single source of truth, even if the
	// UI somehow sent a different list.
	grant, err := ctrl.bindingSvc.ResolveGrantableScopes(
		tenantID, rs.ID, subjectUUID, consentReq.RequestedScope,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "scope resolution failed"})
		return
	}
	grantableSet := make(map[string]struct{}, len(grant.Grantable))
	for _, s := range grant.Grantable {
		grantableSet[s] = struct{}{}
	}

	// Filter the user's chosen subset to what's actually grantable.
	// If they didn't pass GrantScope, grant ALL grantable (UI didn't
	// surface a picker).
	var finalGrant []string
	if len(req.GrantScope) == 0 {
		finalGrant = grant.Grantable
	} else {
		for _, s := range req.GrantScope {
			if _, ok := grantableSet[strings.TrimSpace(s)]; ok {
				finalGrant = append(finalGrant, s)
			}
		}
	}
	if len(finalGrant) == 0 {
		// User unchecked everything OR didn't have anything grantable.
		ctrl.rejectConsent(c, req.ConsentChallenge, "user granted no scopes", grant)
		return
	}

	redirectTo, ferr := ctrl.finalizeConsent(
		c, req.ConsentChallenge, consentReq, &arcRow, rs, tenantID,
		finalGrant, subjectUUID, req.Remember, tenantDB,
	)
	if ferr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": ferr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": redirectTo})
}

// RejectConsent handles POST /authsec/oauth/v2/consent/reject. User clicked Deny.
func (ctrl *LoginV2Controller) RejectConsent(c *gin.Context) {
	var req struct {
		ConsentChallenge string `json:"consent_challenge" binding:"required"`
		Reason           string `json:"reason,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	reason := req.Reason
	if reason == "" {
		reason = "user denied consent"
	}
	resp, err := ctrl.hydraLogin.RejectConsentRequest(req.ConsentChallenge, services.HydraRejectConsentRequest{
		Error:            "access_denied",
		ErrorDescription: reason,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "redirect_to": resp.RedirectTo})
}

// ─────────────────────────────────────────────────────────────────────────
// Consent helpers
// ─────────────────────────────────────────────────────────────────────────

// finalizeConsent is the shared accept path called by both auto-approve
// and explicit POST /accept. Calls Hydra accept-consent with the final
// grant set + session claims, marks the auth_request_context as
// consent_completed, and optionally remembers the grant for next time.
//
// Returns Hydra's redirect_to URL.
//
// session.access_token.ext.context_id is the critical wire: /oauth/v2/token
// introspects the freshly-minted access token, pulls context_id from the
// ext claim, looks up the auth_request_context, validates consent_completed,
// and consumes the row. Skipping this breaks the token-exchange gate.
func (ctrl *LoginV2Controller) finalizeConsent(
	c *gin.Context,
	consentChallenge string,
	consentReq *services.HydraConsentRequest,
	arcRow *models.AuthRequestContext,
	rs *models.ResourceServer,
	tenantID string,
	grantedScopes []string,
	subjectUUID uuid.UUID,
	remember bool,
	tenantDB *gorm.DB,
) (string, error) {
	// Build session claims. Both access_token (.ext) and id_token get the
	// minimum identity payload; the access_token gets the load-bearing
	// context_id so /token can find the auth_request_context.
	accessExt := map[string]interface{}{
		"context_id":         arcRow.ContextID,
		"resource_server_id": rs.ID.String(),
		"tenant_id":          tenantID,
		"auth_time":          time.Now().Unix(),
	}
	idTokenClaims := map[string]interface{}{}
	if consentReq.Context != nil {
		for _, key := range []string{"email", "name", "username", "provider", "auth_method"} {
			if v, ok := consentReq.Context[key]; ok {
				idTokenClaims[key] = v
			}
		}
	}

	rememberFor := 0
	if remember {
		// 8 hours — same as login remember default.
		rememberFor = 8 * 3600
	}

	acceptResp, err := ctrl.hydraLogin.AcceptConsentRequest(consentChallenge, services.HydraAcceptConsentRequest{
		GrantScope:               grantedScopes,
		GrantAccessTokenAudience: []string{rs.ResourceURI},
		Remember:                 remember,
		RememberFor:              rememberFor,
		Session: services.HydraConsentSession{
			AccessToken: accessExt,
			IDToken:     idTokenClaims,
		},
	})
	if err != nil {
		return "", fmt.Errorf("hydra accept consent: %w", err)
	}

	// Mark consent_completed on the auth_request_context row. Token exchange
	// will fail closed if this isn't set.
	if err := tenantDB.Model(arcRow).Updates(map[string]interface{}{
		"consent_completed": true,
		"scope":             strings.Join(grantedScopes, " "),
	}).Error; err != nil {
		// We've already told Hydra we accepted — log + continue. The
		// missing flag will cause /token to fail closed on this exchange,
		// which is the right (if frustrating) result.
		log.Printf("[consent-v2] MarkConsentCompleted failed ctx=%s: %v", arcRow.ContextID, err)
	}

	// Remembered consent grant for next time.
	if remember {
		if _, err := ctrl.consentGrantSvc.UpsertGrant(
			tenantID, subjectUUID, consentReq.Client.ClientID, rs.ID, grantedScopes,
		); err != nil {
			// Best-effort log. The current dance succeeds even if we can't
			// persist for future skip-consent.
			log.Printf("[consent-v2] UpsertGrant failed ctx=%s: %v", arcRow.ContextID, err)
		}
	}

	return acceptResp.RedirectTo, nil
}

// rejectConsent is the shared reject path. Used by both the GET handler
// (no grantable scopes) and AcceptConsent (user unchecked everything).
func (ctrl *LoginV2Controller) rejectConsent(c *gin.Context, consentChallenge, reason string, grant *services.GrantableScopesResult) {
	resp, err := ctrl.hydraLogin.RejectConsentRequest(consentChallenge, services.HydraRejectConsentRequest{
		Error:            "access_denied",
		ErrorDescription: reason,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": "authorization server unavailable"})
		return
	}
	c.JSON(http.StatusOK, ConsentPageDataResponse{
		Success:          true,
		AutoApproved:     false,
		RedirectTo:       resp.RedirectTo,
		Error:            reason,
		GrantableScopes:  []string{},
		RejectedScopes:   grant.Rejected,
	})
}

// buildConsentSubmitURLs mirrors the login submit-URLs helper.
func (ctrl *LoginV2Controller) buildConsentSubmitURLs() ConsentSubmitURLs {
	base := strings.TrimSuffix(config.AppConfig.OAuthBaseURL, "/")
	if base == "" {
		base = "https://authsec-oauth-base-url-not-configured.invalid"
	}
	return ConsentSubmitURLs{
		Accept: base + "/authsec/oauth/v2/consent/accept",
		Reject: base + "/authsec/oauth/v2/consent/reject",
	}
}

// coversAll reports whether `granted` contains every element of `required`.
// Used to decide whether a remembered consent grant covers the current
// grantable set — if yes, auto-approve.
func coversAll(granted []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	g := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		g[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := g[r]; !ok {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────
// Session 4 — OIDC federated initiate + callback
// ─────────────────────────────────────────────────────────────────────────

// InitiateOIDCRequest is what the UI POSTs when the user clicks the
// "Continue with <provider>" button on the login page.
type InitiateOIDCRequest struct {
	LoginChallenge     string    `json:"login_challenge" binding:"required"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" binding:"required"`
}

// InitiateOIDCResponse tells the UI which upstream URL to navigate to.
type InitiateOIDCResponseAPI struct {
	Success         bool   `json:"success"`
	UpstreamAuthURL string `json:"upstream_auth_url,omitempty"`
	State           string `json:"state,omitempty"`
	Error           string `json:"error,omitempty"`
}

// InitiateOIDC handles POST /authsec/oauth/v2/login/oidc/initiate.
//
// Flow:
//  1. Resolve auth_request_context by login_challenge → tenant_id, application_id, context_id.
//  2. Build the absolute callback URL (config.AppConfig.OAuthBaseURL + /login/oidc/callback).
//  3. Call FederatedLoginService.InitiateOIDC to mint state + persist
//     oidc_states row + build the upstream provider auth URL.
//  4. Return upstream_auth_url to the UI; the UI navigates the browser.
func (ctrl *LoginV2Controller) InitiateOIDC(c *gin.Context) {
	var req InitiateOIDCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, InitiateOIDCResponseAPI{Success: false, Error: "invalid request body"})
		return
	}
	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, InitiateOIDCResponseAPI{Success: false, Error: "login_challenge not found or expired"})
		return
	}
	if arcRow.ResourceServerID == nil {
		c.JSON(http.StatusBadRequest, InitiateOIDCResponseAPI{Success: false, Error: "auth context has no application"})
		return
	}
	callbackURL := strings.TrimSuffix(config.AppConfig.OAuthBaseURL, "/") + "/authsec/oauth/v2/login/oidc/callback"
	out, err := ctrl.federatedSvc.InitiateOIDC(services.InitiateOIDCInput{
		TenantID:           tenantID,
		ApplicationID:      *arcRow.ResourceServerID,
		IdentityProviderID: req.IdentityProviderID,
		LoginChallenge:     req.LoginChallenge,
		ContextID:          arcRow.ContextID,
		CallbackURL:        callbackURL,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, InitiateOIDCResponseAPI{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, InitiateOIDCResponseAPI{
		Success:         true,
		UpstreamAuthURL: out.UpstreamAuthURL,
		State:           out.State,
	})
}

// CallbackOIDCResponse mirrors CompleteCustomLoginResponse so the UI can
// reuse the same redirect handling. The UI navigates the browser to
// redirect_to (which is Hydra's consent endpoint URL).
type CallbackOIDCResponse struct {
	Success    bool   `json:"success"`
	RedirectTo string `json:"redirect_to,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CallbackOIDC handles GET /authsec/oauth/v2/login/oidc/callback?state=...&code=...
//
// The upstream provider redirects the browser here after the user authenticates.
//
// Flow:
//  1. Read state + code from query string.
//  2. Call FederatedLoginService.HandleOIDCCallback — splits state into
//     (tenant_id, random), exchanges code at upstream, fetches userinfo,
//     resolves the AuthSec user, returns LoginChallenge + UserID.
//  3. Call Hydra accept-login with subject=user.id, auth_method=oidc_federated.
//  4. Stamp user_id + auth_time onto auth_request_context.
//  5. Return Hydra's redirect_to. The UI receives this as JSON and navigates.
//
// Why not 302 directly? Because the (separate) UI is the consumer here — it
// expects JSON. If callers want a browser-redirecting endpoint, they can
// add a thin wrapper that 302s to redirect_to.
func (ctrl *LoginV2Controller) CallbackOIDC(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")
	if upstreamErr := c.Query("error"); upstreamErr != "" {
		c.JSON(http.StatusBadRequest, CallbackOIDCResponse{Success: false, Error: "upstream provider returned error: " + upstreamErr})
		return
	}
	if state == "" || code == "" {
		c.JSON(http.StatusBadRequest, CallbackOIDCResponse{Success: false, Error: "state and code required"})
		return
	}
	callbackURL := strings.TrimSuffix(config.AppConfig.OAuthBaseURL, "/") + "/authsec/oauth/v2/login/oidc/callback"
	result, err := ctrl.federatedSvc.HandleOIDCCallback(services.HandleOIDCCallbackInput{
		State:       state,
		Code:        code,
		CallbackURL: callbackURL,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, CallbackOIDCResponse{Success: false, Error: err.Error()})
		return
	}
	if result.LoginChallenge == "" {
		c.JSON(http.StatusBadRequest, CallbackOIDCResponse{Success: false, Error: "state has no login_challenge"})
		return
	}

	// Stamp user_id on the auth_request_context row but DO NOT accept the Hydra
	// login yet — the WebAuthn 2FA step runs next and accepts on success.
	tenantDB, dbErr := config.GetTenantGORMDB(result.TenantID)
	if dbErr == nil {
		_ = tenantDB.Model(&models.AuthRequestContext{}).
			Where("login_challenge = ? AND tenant_id = ?", result.LoginChallenge, result.TenantID).
			Updates(map[string]interface{}{"user_id": result.UserID}).Error
	}

	// The upstream OIDC provider redirects the *browser* straight to this
	// endpoint, so bounce it to the SPA login page, which detects the pending
	// second factor (user_id stamped, second_factor_completed=false) and runs
	// the WebAuthn ceremony before the login is accepted → consent.
	c.Redirect(http.StatusFound, oauthLoginUIURL(result.LoginChallenge))
}

// oauthLoginUIURL builds the SPA login-page URL the browser is sent to so the
// WebAuthn 2FA step can run (used after the OIDC/SAML callbacks).
//
// The login page is served at the tenant-domain-suffix host (stage.authsec.dev,
// app.authsec.ai, …) — the same host WebAuthn's RP ID/origin uses — which is
// reliable across environments. REACT_APP_URL is NOT (it carries release- or
// path-specific values like ".../oidc/auth"), so we don't use it here.
func oauthLoginUIURL(loginChallenge string) string {
	host := strings.TrimSpace(config.AppConfig.TenantDomainSuffix)
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"), "/")
	if host == "" {
		// Last-resort fallback so we never emit a bare path.
		host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(config.AppConfig.ReactAppURL, "https://"), "http://"), "/")
	}
	return "https://" + host + "/oauth/login?login_challenge=" + url.QueryEscape(loginChallenge)
}

// ─────────────────────────────────────────────────────────────────────────
// Session 5 — SAML federated initiate + ACS (stubs returning 501)
// ─────────────────────────────────────────────────────────────────────────

// InitiateSAMLRequest mirrors InitiateOIDCRequest. Same shape so the UI
// can use one code path for "click federated button".
type InitiateSAMLRequest struct {
	LoginChallenge     string    `json:"login_challenge" binding:"required"`
	IdentityProviderID uuid.UUID `json:"identity_provider_id" binding:"required"`
}

// InitiateSAMLResponseAPI mirrors InitiateOIDCResponseAPI but with SAML's
// SAMLRequest + SSO endpoint instead of upstream_auth_url.
type InitiateSAMLResponseAPI struct {
	Success        bool   `json:"success"`
	UpstreamSSOURL string `json:"upstream_sso_url,omitempty"`
	SAMLRequest    string `json:"saml_request,omitempty"` // base64; UI POSTs to UpstreamSSOURL
	RelayState     string `json:"relay_state,omitempty"`
	Error          string `json:"error,omitempty"`
}

// InitiateSAML handles POST /authsec/oauth/v2/login/saml/initiate.
//
// Resolves the identity_providers row (per-Application whitelist applied),
// pulls the underlying saml_providers config row, then calls the legacy
// OAuthLoginService.CreateSAMLRequest to build the AuthnRequest XML +
// deflate/base64 encode + persist a saml_requests row keyed by
// login_challenge. The UI POSTs (SAMLRequest, RelayState) to UpstreamSSOURL
// to drive the SP-initiated dance.
func (ctrl *LoginV2Controller) InitiateSAML(c *gin.Context) {
	var req InitiateSAMLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, InitiateSAMLResponseAPI{Success: false, Error: "invalid request body"})
		return
	}
	arcRow, tenantID, err := ctrl.findContextByLoginChallenge(req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusBadRequest, InitiateSAMLResponseAPI{Success: false, Error: "login_challenge not found or expired"})
		return
	}
	if arcRow.ResourceServerID == nil {
		c.JSON(http.StatusBadRequest, InitiateSAMLResponseAPI{Success: false, Error: "auth context has no application"})
		return
	}

	// Validate IDP + whitelist via the federated service (which has all
	// the cross-table joins). Returns the config_ref (saml_providers.id).
	tenantDB, _, configUUID, err := ctrl.federatedSvc.ResolveSAMLProviderForApplication(services.InitiateSAMLInput{
		TenantID:           tenantID,
		ApplicationID:      *arcRow.ResourceServerID,
		IdentityProviderID: req.IdentityProviderID,
		LoginChallenge:     req.LoginChallenge,
		ContextID:          arcRow.ContextID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, InitiateSAMLResponseAPI{Success: false, Error: err.Error()})
		return
	}

	// Load the saml_providers row directly here (controller is allowed to
	// import internal/hydra/models; the service isn't, due to a pre-
	// existing import cycle).
	var samlProv hydramodels.SAMLProvider
	if err := tenantDB.Where("id = ?", configUUID).First(&samlProv).Error; err != nil {
		c.JSON(http.StatusBadRequest, InitiateSAMLResponseAPI{Success: false, Error: "saml_providers config row not found: " + err.Error()})
		return
	}

	// Mint the AuthnRequest via legacy code.
	legacy := hydramodels.NewOAuthLoginService(*config.AppConfig)
	samlRequest, relayState, err := legacy.CreateSAMLRequest(&samlProv, req.LoginChallenge)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InitiateSAMLResponseAPI{Success: false, Error: "create saml request: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, InitiateSAMLResponseAPI{
		Success:        true,
		UpstreamSSOURL: samlProv.SSOURL,
		SAMLRequest:    samlRequest,
		RelayState:     relayState,
	})
}

// CallbackSAMLResponse mirrors CallbackOIDCResponse.
type CallbackSAMLResponse struct {
	Success    bool   `json:"success"`
	RedirectTo string `json:"redirect_to,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CallbackSAML handles POST /authsec/oauth/v2/login/saml/acs. The SAML IdP
// posts (SAMLResponse, RelayState) form-encoded; we:
//
//  1. Validate via legacy OAuthLoginService.ValidateSAMLResponse — decodes
//     base64, parses XML, checks Status + entity_id against saml_providers
//     row, extracts NameID + email + attributes from the assertion.
//  2. Look up our v2 auth_request_context row by login_challenge (recovered
//     from RelayState) to get the resource_server_id (legacy SAML doesn't
//     track that — it's a v2-only concept).
//  3. Route through resolveOrJITFederatedUser so the SAML user gets the
//     same per-MCP scoping as OIDC federated users (migration 034).
//  4. Accept-login at Hydra.
func (ctrl *LoginV2Controller) CallbackSAML(c *gin.Context) {
	samlResponse := c.PostForm("SAMLResponse")
	relayState := c.PostForm("RelayState")
	if samlResponse == "" || relayState == "" {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "SAMLResponse and RelayState required"})
		return
	}

	legacy := hydramodels.NewOAuthLoginService(*config.AppConfig)

	// Two-phase validation so the entity_id check honors per-MCP SAML rows:
	//
	//  1. Decode RelayState to pull login_challenge + tenant_id WITHOUT
	//     calling ValidateSAMLResponse (which would do entity_id check
	//     against a possibly-wrong tenant-wide row).
	//  2. Look up auth_request_context by login_challenge to find this
	//     dance's application_id (= resource_server_id).
	//  3. Call ValidateSAMLResponseForApplication so the entity_id check
	//     uses the per-MCP saml_providers row if one exists.
	//
	// The relay state format is base64("<challenge>:<provider>:<tenant>:<client>"),
	// minted by CreateSAMLRequest. We parse it inline here rather than
	// exporting a helper.
	preLoginChallenge, preTenantID, preParseErr := parseSAMLRelayStateLoginAndTenant(relayState)
	if preParseErr != nil {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "parse relay state: " + preParseErr.Error()})
		return
	}
	tenantDB, err := config.GetTenantGORMDB(preTenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, CallbackSAMLResponse{Success: false, Error: "get tenant db: " + err.Error()})
		return
	}
	var arc models.AuthRequestContext
	if err := tenantDB.Where("login_challenge = ? AND tenant_id = ?", preLoginChallenge, preTenantID).
		First(&arc).Error; err != nil {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "v2 auth_request_context not found; SAML must be initiated via /authsec/oauth/v2/authorize: " + err.Error()})
		return
	}
	if arc.ResourceServerID == nil {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "v2 auth_request_context has no resource_server_id; cannot scope SAML user per-MCP"})
		return
	}

	// Now do the per-MCP-aware validation.
	assertion, loginChallenge, providerName, tenantID, _, err := legacy.ValidateSAMLResponseForApplication(samlResponse, relayState, *arc.ResourceServerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "validate saml response: " + err.Error()})
		return
	}
	if loginChallenge == "" {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "RelayState carried no login_challenge"})
		return
	}
	// Sanity-check the relay state didn't shapeshift between the pre-parse
	// and the full validate (it shouldn't — same input both times — but
	// guard explicitly).
	if loginChallenge != preLoginChallenge || tenantID != preTenantID {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "relay state inconsistent"})
		return
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, CallbackSAMLResponse{Success: false, Error: "invalid tenant_id"})
		return
	}

	// Build a display name from given+sn or fall back to email.
	displayName := strings.TrimSpace(assertion.FirstName + " " + assertion.LastName)
	userID, userEmail, userName, err := ctrl.federatedSvc.ResolveOrJITFederatedUserBasic(
		tenantDB, tenantUUID, *arc.ResourceServerID, providerName,
		assertion.NameID, assertion.Email, displayName,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, CallbackSAMLResponse{Success: false, Error: "resolve user: " + err.Error()})
		return
	}

	// Stamp user_id but DO NOT accept the Hydra login yet — the WebAuthn 2FA
	// step runs next (in the SPA) and accepts on success. provider/name are
	// captured here for completeness but the accept's Context is rebuilt at
	// the WebAuthn-finish step from the user row.
	_ = userEmail
	_ = userName
	_ = providerName
	_ = tenantDB.Model(&models.AuthRequestContext{}).
		Where("login_challenge = ? AND tenant_id = ?", loginChallenge, tenantID).
		Updates(map[string]interface{}{"user_id": userID}).Error

	// The SAML ACS is reached by a browser POST, so bounce it to the SPA login
	// page, which detects the pending second factor and runs WebAuthn before
	// the login is accepted → consent.
	c.Redirect(http.StatusFound, oauthLoginUIURL(loginChallenge))
}

// parseSAMLRelayStateLoginAndTenant pulls login_challenge + tenant_id out of
// the SAML RelayState without doing any of the heavier XML / signature
// validation ValidateSAMLResponseForApplication does. Mirror of the format
// produced by hydramodels.CreateSAMLRequest:
//
//	base64("<login_challenge>:<provider_name>:<tenant_id>:<client_id>")
//
// Returns (loginChallenge, tenantID, error). Used in the v2 SAML callback
// to look up the auth_request_context (and thus application_id) BEFORE
// running full validation, so the entity_id check can target the per-MCP
// saml_providers row instead of the tenant-wide default.
func parseSAMLRelayStateLoginAndTenant(relayState string) (string, string, error) {
	raw, err := base64.StdEncoding.DecodeString(relayState)
	if err != nil {
		return "", "", fmt.Errorf("invalid relay state base64: %w", err)
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid relay state format, expected 4 colon-separated parts, got %d", len(parts))
	}
	return parts[0], parts[2], nil
}
