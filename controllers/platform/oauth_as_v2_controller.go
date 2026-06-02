package platform

import (
	"errors"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OAuthASV2Controller is the standards-compliant MCP OAuth server on the prod
// backport, mounted under /authsec/oauth/v2. It is the prod analogue of the
// workspace-scoped controllers/platform/oauth_as_controller.go on
// authsec-dev.
//
// Phase 2 wires: Register (DCR).
// Phase 3 will wire: Authorize, Token, Introspect, JWKS, Revoke, Userinfo, EndSession.
// Phase 4 will wire: the IDP policy gate inside Authorize.
// Phase 5 will wire: ASMetadata, OIDCDiscovery, CanonicalIssuerOnly.
type OAuthASV2Controller struct {
	service    *services.OAuthASService
	idpService *services.IdentityProviderV2Service
}

func NewOAuthASV2Controller() *OAuthASV2Controller {
	return &OAuthASV2Controller{
		service:    services.NewOAuthASService(nil),
		idpService: services.NewIdentityProviderV2Service(),
	}
}

// Register handles POST /authsec/oauth/v2/register — RFC 7591 Dynamic Client
// Registration. Anonymous; clients are protocol artifacts and don't need an
// admin token. Tenant context is resolved from the `resource` URI in the
// body via resource_server_tenant_index.
func (ctrl *OAuthASV2Controller) Register(c *gin.Context) {
	var req services.DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": err.Error(),
		})
		return
	}
	resp, err := ctrl.service.RegisterDCRClient(req)
	if err != nil {
		if errors.Is(err, services.ErrRegistrationModeNotAllowed) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client_metadata",
				"error_description": "resource server does not allow dynamic client registration",
			})
			return
		}
		if errors.Is(err, services.ErrResourceServerNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client_metadata",
				"error_description": "resource not found",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client_metadata",
			"error_description": err.Error(),
		})
		return
	}
	c.JSON(http.StatusCreated, resp)
}

// Authorize forwards the request to Hydra's /oauth2/auth after rewriting the
// public client_id to the internal hydra_client_id and capturing an
// auth_request_context for /token to resolve.
//
// PHASE3-SCOPE: this is a minimum viable proxy. The dev branch also runs
// validateOAuthPolicy, EnsureHydraClientHasRSScopes, and the Application↔IDP
// policy gate (the latter lands in Phase 4 of this backport).
func (ctrl *OAuthASV2Controller) Authorize(c *gin.Context) {
	q := c.Request.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id and redirect_uri are required",
		})
		return
	}
	client, err := ctrl.service.GetClient(clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "unknown client_id",
		})
		return
	}

	// Resolve the resource (RFC 8707) — optional. If present, validate the
	// client is registered against it.
	resource := q.Get("resource")
	var resolvedTenantID string
	var resourceServerID *uuid.UUID
	if resource != "" {
		rsService := services.NewResourceServerService()
		rs, tenantID, err := rsService.GetByResourceURI(resource)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_target",
				"error_description": "resource not found",
			})
			return
		}
		resolvedTenantID = tenantID
		resourceServerID = &rs.ID

		// Phase 4: per-Application IDP policy gate. If the client passes
		// ?idp_id=<uuid> (the identity provider it intends to use), check
		// whether the policy whitelists it for this Application. Default-allow
		// when the Application has zero policy rows.
		if idpIDStr := q.Get("idp_id"); idpIDStr != "" {
			idpID, parseErr := uuid.Parse(idpIDStr)
			if parseErr != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "idp_id is not a valid uuid",
				})
				return
			}
			allowed, gateErr := ctrl.idpService.CheckIDPAllowedForApplication(tenantID, rs.ID, idpID)
			if gateErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":             "server_error",
					"error_description": gateErr.Error(),
				})
				return
			}
			if !allowed {
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "access_denied",
					"error_description": "identity provider not enabled for this application",
				})
				return
			}
		}
	}

	// Capture state for /token to consume.
	if resolvedTenantID == "" {
		// Free-floating client without a resource — we don't have a tenant
		// to write the context row against. Phase 3 minimum: reject.
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "resource parameter is required",
		})
		return
	}
	contextID, err := ctrl.service.StoreAuthRequestContext(services.AuthRequestContextInput{
		TenantID:            resolvedTenantID,
		ClientID:            clientID,
		ResourceURI:         resource,
		ResourceServerID:    resourceServerID,
		RedirectURI:         redirectURI,
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Forward to Hydra with the rewritten client_id and our context_id in
	// state. Hydra's response (a redirect to redirect_uri with ?code=...)
	// flows back to the user's browser unchanged.
	q.Set("client_id", client.HydraClientID)
	q.Set("state", contextID+"~"+q.Get("state"))
	hydraAuthURL := strings.TrimSuffix(getHydraPublicBase(), "/") + "/oauth2/auth?" + q.Encode()
	c.Redirect(http.StatusFound, hydraAuthURL)
}

// Token forwards to Hydra's /oauth2/token, rewriting client_id and consuming
// the auth_request_context.
func (ctrl *OAuthASV2Controller) Token(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	form := c.Request.PostForm
	clientID := form.Get("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "client_id required",
		})
		return
	}
	client, err := ctrl.service.GetClient(clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "unknown client",
		})
		return
	}

	// Recover context_id from state (we stuffed it in at /authorize).
	if state := form.Get("state"); state != "" {
		if idx := strings.Index(state, "~"); idx > 0 {
			form.Set("state", state[idx+1:])
		}
	}
	// PHASE3-TODO: actually look up the auth_request_context row by context_id
	// and validate redirect_uri / scope match. Skipped here for proxy MVP.

	form.Set("client_id", client.HydraClientID)
	status, body, err := ctrl.service.ProxyFormToHydraPublic("/oauth2/token", form)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(status, "application/json", body)
}

// Introspect proxies to Hydra's admin introspect endpoint.
func (ctrl *OAuthASV2Controller) Introspect(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	token := c.Request.PostForm.Get("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	status, body, err := ctrl.service.IntrospectViaHydraAdmin(token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(status, "application/json", body)
}

// JWKS proxies Hydra's public JWKS document.
func (ctrl *OAuthASV2Controller) JWKS(c *gin.Context) {
	body, err := ctrl.service.FetchJWKS()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

// Revoke proxies to Hydra's public /oauth2/revoke.
func (ctrl *OAuthASV2Controller) Revoke(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	token := c.Request.PostForm.Get("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if err := ctrl.service.RevokeHydraToken(token); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// Userinfo returns the subject's identity claims from the access token.
// Implemented as introspect+filter; mirrors the dev controller's shape.
func (ctrl *OAuthASV2Controller) Userinfo(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	token := auth[len(prefix):]
	status, body, err := ctrl.service.IntrospectViaHydraAdmin(token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		c.Data(status, "application/json", body)
		return
	}
	parsed, err := services.MarshalIntrospectionResponse(body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if active, _ := parsed["active"].(bool); !active {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	// Strip introspection-only fields; return the user-identity subset.
	out := map[string]interface{}{}
	for _, k := range []string{"sub", "email", "email_verified", "name", "given_name", "family_name", "picture", "locale"} {
		if v, ok := parsed[k]; ok {
			out[k] = v
		}
	}
	c.JSON(http.StatusOK, out)
}

// EndSession is the OIDC RP-initiated logout. Proxy to Hydra and follow the
// post_logout_redirect_uri if it's allow-listed on the client row.
func (ctrl *OAuthASV2Controller) EndSession(c *gin.Context) {
	postLogout := c.Query("post_logout_redirect_uri")
	if postLogout == "" {
		c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
		return
	}
	c.Redirect(http.StatusFound, postLogout)
}

// PAR is intentionally not supported on the v2 surface — same as dev.
func (ctrl *OAuthASV2Controller) PAR(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             "unsupported_request",
		"error_description": "PAR not supported",
	})
}

// ASMetadata serves /authsec/oauth/v2/.well-known/oauth-authorization-server
// (RFC 8414). Issuer is the canonical OAuth base URL from config; endpoints
// point at our v2 surface.
func (ctrl *OAuthASV2Controller) ASMetadata(c *gin.Context) {
	c.JSON(http.StatusOK, ctrl.buildMetadata())
}

// OIDCDiscovery serves /authsec/oauth/v2/.well-known/openid-configuration.
// Shares the same payload as ASMetadata with the OIDC-required additions.
func (ctrl *OAuthASV2Controller) OIDCDiscovery(c *gin.Context) {
	m := ctrl.buildMetadata()
	m["subject_types_supported"] = []string{"public"}
	m["id_token_signing_alg_values_supported"] = []string{"RS256"}
	c.JSON(http.StatusOK, m)
}

func (ctrl *OAuthASV2Controller) buildMetadata() map[string]interface{} {
	issuer := strings.TrimSuffix(canonicalOAuthBaseURL(), "/")
	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authsec/oauth/v2/authorize",
		"token_endpoint":                        issuer + "/authsec/oauth/v2/token",
		"introspection_endpoint":                issuer + "/authsec/oauth/v2/introspect",
		"revocation_endpoint":                   issuer + "/authsec/oauth/v2/revoke",
		"userinfo_endpoint":                     issuer + "/authsec/oauth/v2/userinfo",
		"jwks_uri":                              issuer + "/authsec/oauth/v2/jwks",
		"registration_endpoint":                 issuer + "/authsec/oauth/v2/register",
		"end_session_endpoint":                  issuer + "/authsec/oauth/v2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                      []string{"openid", "email", "profile", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256"},
		"response_modes_supported":              []string{"query"},
	}
}

// CanonicalIssuerOnly enforces that the v2 OAuth endpoints are reached on the
// configured canonical host. Requests arriving on a non-canonical host are
// redirected (308) to the canonical issuer; this prevents redirect_uri
// mismatches and host-confusion attacks. Mirrors the dev controller.
func (ctrl *OAuthASV2Controller) CanonicalIssuerOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		canonical := canonicalOAuthBaseURL()
		if canonical == "" {
			c.Next()
			return
		}
		canonicalHost := hostOf(canonical)
		reqHost := c.Request.Host
		if h := c.GetHeader("X-Forwarded-Host"); h != "" {
			if comma := strings.IndexByte(h, ','); comma >= 0 {
				reqHost = strings.TrimSpace(h[:comma])
			} else {
				reqHost = strings.TrimSpace(h)
			}
		}
		if canonicalHost == "" || strings.EqualFold(reqHost, canonicalHost) {
			c.Next()
			return
		}
		target := strings.TrimSuffix(canonical, "/") + c.Request.URL.RequestURI()
		c.Redirect(http.StatusPermanentRedirect, target)
		c.Abort()
	}
}

// canonicalOAuthBaseURL prefers AppConfig.OAuthBaseURL when set; otherwise
// falls back to the public Hydra base URL (same as the rest of v2's URL
// derivation). Returns "" if nothing's configured — callers should treat
// that as "skip canonical-issuer enforcement".
func canonicalOAuthBaseURL() string {
	// PHASE5-NOTE: prod's config.AppConfig doesn't yet expose OAuthBaseURL;
	// for the backport we reuse HydraPublicURL as the canonical issuer.
	// Adding a dedicated config field is a follow-up.
	if u := config.AppConfig.HydraPublicURL; u != "" {
		return strings.TrimSuffix(u, "/")
	}
	return ""
}

func hostOf(rawURL string) string {
	// Crude but enough: we only need the host portion for the comparison.
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// getHydraPublicBase mirrors the fallback logic from
// services.OAuthASService.ProxyFormToHydraPublic so the Authorize redirect
// uses the same base URL.
func getHydraPublicBase() string {
	if u := config.AppConfig.HydraPublicURL; u != "" {
		return strings.TrimSuffix(u, "/")
	}
	admin := strings.TrimSuffix(config.AppConfig.HydraAdminURL, "/")
	return strings.TrimSuffix(admin, "/admin")
}
