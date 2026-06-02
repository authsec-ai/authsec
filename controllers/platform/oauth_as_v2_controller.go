package platform

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
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
	service       *services.OAuthASService
	idpService    *services.IdentityProviderV2Service
	sdkPolicySvc  *services.SDKPolicyService
	bindingSvc    *services.BindingService
}

func NewOAuthASV2Controller() *OAuthASV2Controller {
	return &OAuthASV2Controller{
		service:      services.NewOAuthASService(nil),
		idpService:   services.NewIdentityProviderV2Service(),
		sdkPolicySvc: services.NewSDKPolicyService(),
		bindingSvc:   services.NewBindingService(),
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
//
// The auth_request_context lookup uses two paths:
//
//  1. Preferred — the RP echoed the state value we stuffed at /authorize
//     (`<context_id>~<rp_state>`). We split it, look up by context_id, and
//     atomically consume the row.
//  2. Fallback — the RP dropped state on the way to /token. We resolve the
//     tenant via the `resource` form param (RFC 8707) and find the most
//     recent unconsumed row for (tenant_id, client_id, redirect_uri).
//
// On either path we then validate:
//   - redirect_uri matches the captured value (RFC 6749 §4.1.3)
//   - scope (if requested) is a subset of what we captured
//
// If validation fails we do NOT forward to Hydra. Fail closed.
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

	// auth_request_context binding is only required for the authorization_code
	// grant — refresh_token replays don't have a fresh /authorize behind them.
	grantType := form.Get("grant_type")
	if grantType == "authorization_code" {
		if errResp := ctrl.consumeAndValidateContext(form, clientID); errResp != nil {
			c.JSON(http.StatusBadRequest, errResp)
			return
		}
	}

	// Recover and strip any context_id we tucked into state before proxying
	// to Hydra. Hydra does not expect our custom prefix.
	if state := form.Get("state"); state != "" {
		if idx := strings.Index(state, "~"); idx > 0 {
			form.Set("state", state[idx+1:])
		}
	}

	form.Set("client_id", client.HydraClientID)
	status, body, err := ctrl.service.ProxyFormToHydraPublic("/oauth2/token", form)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Data(status, "application/json", body)
}

// consumeAndValidateContext finds the auth_request_context row that this
// /token call is the second leg of, atomically marks it consumed, and
// validates the redirect_uri / scope match what we captured at /authorize.
//
// Returns a non-nil error map (suitable for JSON response with status 400)
// on validation failure. Returns nil on success.
func (ctrl *OAuthASV2Controller) consumeAndValidateContext(form url.Values, clientID string) map[string]interface{} {
	redirectURI := form.Get("redirect_uri")
	if redirectURI == "" {
		return map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "redirect_uri required for authorization_code grant",
		}
	}

	// Try path (1): pull context_id from state.
	var contextID string
	if state := form.Get("state"); state != "" {
		if idx := strings.Index(state, "~"); idx > 0 {
			contextID = state[:idx]
		}
	}

	// Resolve the tenant. The `resource` form param (RFC 8707) is the
	// canonical hint; without it we can't look up tenant from master.
	resource := form.Get("resource")
	if resource == "" {
		return map[string]interface{}{
			"error":             "invalid_request",
			"error_description": "resource parameter required on /token (RFC 8707)",
		}
	}
	tenantID, err := ctrl.service.LookupTenantForClientByResource(resource)
	if err != nil {
		return map[string]interface{}{
			"error":             "invalid_target",
			"error_description": "resource not recognized",
		}
	}

	var row interface {
		// minimal interface so we don't pin to a single import path in the
		// switch below — both code paths return *models.AuthRequestContext.
	}
	_ = row

	var ctxRow *models.AuthRequestContext
	if contextID != "" {
		ctxRow, err = ctrl.service.ConsumeAuthRequestContext(tenantID, contextID)
	} else {
		// Path (2): fall back to (tenant_id, client_id, redirect_uri) lookup,
		// then consume by context_id.
		var found *models.AuthRequestContext
		found, err = ctrl.service.FindLatestUnconsumedContext(tenantID, clientID, redirectURI)
		if err != nil {
			return map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "no matching authorize request found",
			}
		}
		ctxRow, err = ctrl.service.ConsumeAuthRequestContext(tenantID, found.ContextID)
	}
	if err != nil {
		return map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "auth context invalid: " + err.Error(),
		}
	}

	// Validate the bindings.
	if ctxRow.ClientID != clientID {
		return map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "client_id mismatch between authorize and token",
		}
	}
	if ctxRow.RedirectURI != redirectURI {
		return map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "redirect_uri mismatch between authorize and token",
		}
	}
	if ctxRow.ResourceURI != nil && *ctxRow.ResourceURI != "" && *ctxRow.ResourceURI != resource {
		return map[string]interface{}{
			"error":             "invalid_target",
			"error_description": "resource mismatch between authorize and token",
		}
	}
	if requested := form.Get("scope"); requested != "" {
		captured := ""
		if ctxRow.Scope != nil {
			captured = *ctxRow.Scope
		}
		if !isScopeSubset(requested, captured) {
			return map[string]interface{}{
				"error":             "invalid_scope",
				"error_description": "requested scope exceeds what was authorized",
			}
		}
	}

	return nil
}

// isScopeSubset returns true when every space-separated token in `requested`
// is present in `captured`. Empty captured means we never recorded a scope
// at /authorize, in which case we allow anything (the RP is requesting
// whatever Hydra approves).
func isScopeSubset(requested, captured string) bool {
	if captured == "" {
		return true
	}
	capSet := make(map[string]struct{})
	for _, tok := range strings.Fields(captured) {
		capSet[tok] = struct{}{}
	}
	for _, tok := range strings.Fields(requested) {
		if _, ok := capSet[tok]; !ok {
			return false
		}
	}
	return true
}

// Introspect proxies to Hydra's admin introspect endpoint AND applies
// per-Application RBAC scope filtering before returning the response.
//
// Authentication (RFC 7662 §2.1): the caller MUST present HTTP Basic auth
// with `<application_id>:<introspection_secret>`. These are the
// resource-server credentials minted via
// POST /authsec/applications/:id/rotate-introspection-secret.
//
// RBAC filter (PHASE3 closeout):
//
// Hydra returns the token's *claimed* scope — what was issued at /token
// time. That can become stale: an admin revokes a user's role, but the
// access token is still alive for up to its remaining lifetime.
//
// We recompute the user's current effective scopes from the role-binding
// stack (Phase 5/8) and intersect with the token's claim. The MCP server
// receives the *current* set, so admin revocations take effect on the
// very next introspection round-trip.
//
// Special cases:
//
//   - sub doesn't parse as a UUID → non-user token (client_credentials,
//     SPIRE workload). Skip the filter; return Hydra's response unchanged.
//   - sub is a UUID but the user doesn't exist in this tenant → narrow to
//     empty scope. Fail closed.
//   - resolver error (DB hiccup, etc.) → narrow to empty scope. Fail
//     closed. Logged for ops.
//   - active=false → return the body unchanged (no point filtering an
//     already-invalid token).
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

	// Authenticate the caller. The Basic username is the Application's
	// UUID, which also gives us the RBAC context for filtering.
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.Header("WWW-Authenticate", `Basic realm="introspect"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "Basic auth required (application_id:introspection_secret)",
		})
		return
	}
	appID, rsSecret, ok := parseBasicAuth(authHeader)
	if !ok {
		c.Header("WWW-Authenticate", `Basic realm="introspect"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	applicationID, err := uuid.Parse(appID)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="introspect"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	rs, tenantID, err := ctrl.sdkPolicySvc.AuthorizeFromBasic(
		"Basic "+basicEncode(appID, rsSecret),
		applicationID,
	)
	if err != nil {
		c.Header("WWW-Authenticate", `Basic realm="introspect"`)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}
	_ = rs // not used yet; reserved for future scope-supported gating

	// Proxy to Hydra.
	status, body, err := ctrl.service.IntrospectViaHydraAdmin(token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		// Pass non-200 through unchanged.
		c.Data(status, "application/json", body)
		return
	}

	parsed, err := services.MarshalIntrospectionResponse(body)
	if err != nil {
		// If we can't parse the body, return it raw rather than crash.
		c.Data(status, "application/json", body)
		return
	}
	active, _ := parsed["active"].(bool)
	if !active {
		// No point filtering an invalid token's scope.
		c.Data(status, "application/json", body)
		return
	}

	// Apply the RBAC filter.
	subject, _ := parsed["sub"].(string)
	scopeClaim, _ := parsed["scope"].(string)
	filtered, filterApplied := ctrl.filterScope(tenantID, applicationID, subject, scopeClaim)
	if filterApplied {
		parsed["scope"] = filtered
		// Add an x-* claim so the MCP server can tell the response was filtered.
		// Hydra-original tokens' scope is what was *issued*; our filtered
		// scope is what the user still has *now*. Surfacing this helps
		// SDK debug logs explain "wait, why did my token's scope shrink?"
		parsed["ext_authsec_scope_filtered"] = true
	}

	out, err := json.Marshal(parsed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "marshal_introspect_response"})
		return
	}
	c.Data(http.StatusOK, "application/json", out)
}

// filterScope is the RBAC narrowing step. Returns (filteredScope, applied).
// applied=false means the caller should leave the scope claim unchanged —
// either the subject wasn't a user token, or the token had no scope claim
// to begin with.
//
// On any error, returns ("", true) — applied=true forces the empty string
// to be written back into the response, which is the fail-closed posture.
func (ctrl *OAuthASV2Controller) filterScope(
	tenantID string,
	applicationID uuid.UUID,
	subject string,
	scopeClaim string,
) (filtered string, applied bool) {
	if scopeClaim == "" {
		return "", false
	}
	effective, isUserSubject, err := ctrl.bindingSvc.EffectiveScopesForSubject(
		tenantID, applicationID, subject,
	)
	if err != nil {
		// Fail closed: log + return empty filtered scope.
		log.Printf("[introspect] effective-scope resolver failed for app=%s sub=%s: %v",
			applicationID, subject, err)
		return "", true
	}
	if !isUserSubject {
		// Non-user token: skip the filter.
		return "", false
	}
	// Intersect claimed scope with effective scope.
	effectiveSet := make(map[string]struct{}, len(effective))
	for _, s := range effective {
		effectiveSet[s] = struct{}{}
	}
	claimed := strings.Fields(scopeClaim)
	kept := make([]string, 0, len(claimed))
	for _, c := range claimed {
		if _, ok := effectiveSet[c]; ok {
			kept = append(kept, c)
		}
	}
	return strings.Join(kept, " "), true
}

// parseBasicAuth pulls (username, password) out of an HTTP Basic header.
// Returns ok=false on any decode failure.
func parseBasicAuth(authHeader string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// basicEncode rebuilds the base64-encoded credential string. Used so we
// can delegate the verify-the-secret step to the existing
// SDKPolicyService.AuthorizeFromBasic without re-implementing bcrypt
// comparison here.
func basicEncode(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
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
