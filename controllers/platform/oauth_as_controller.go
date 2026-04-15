package platform

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// OAuthASController handles global OAuth Authorization Server endpoints.
// All endpoints are global (not per-RS). RS context is carried by the `resource` parameter.
type OAuthASController struct {
	service        *services.OAuthASService
	rsService      *services.ResourceServerService
	scopeResolver  *services.ScopeResolver
	consentService *services.ConsentService
}

func NewOAuthASController() *OAuthASController {
	return &OAuthASController{
		service:        services.NewOAuthASService(config.DB),
		rsService:      services.NewResourceServerService(config.DB),
		scopeResolver:  services.NewScopeResolver(config.DB),
		consentService: services.NewConsentService(config.DB),
	}
}

// ASMetadata serves RFC 8414 Authorization Server Metadata.
// GET /.well-known/oauth-authorization-server
func (ctrl *OAuthASController) ASMetadata(c *gin.Context) {
	baseURL := config.AppConfig.BaseURL
	c.JSON(http.StatusOK, ctrl.service.ASMetadata(baseURL))
}

// OIDCDiscovery serves OpenID Connect Discovery 1.0 metadata.
// GET /.well-known/openid-configuration
// Returns the same superset document as ASMetadata (OIDC Discovery is a superset of RFC 8414).
func (ctrl *OAuthASController) OIDCDiscovery(c *gin.Context) {
	baseURL := config.AppConfig.BaseURL
	c.JSON(http.StatusOK, ctrl.service.ASMetadata(baseURL))
}

// Authorize handles the OAuth authorization request.
// GET /oauth/authorize
//
// Hard rules:
//   - Generates server-side context_id (never trusts client state for binding)
//   - Only supports response_type=code
//   - Only supports response_mode=query
//   - PKCE S256 required
func (ctrl *OAuthASController) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	requestURI := c.Query("request_uri")

	// RFC 9126 §4: If request_uri is present, the client already called /oauth/par.
	// All authorization parameters are stored server-side — just look up the Hydra
	// client_id from the AuthSec client and redirect to Hydra with the PAR reference.
	if requestURI != "" {
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id required with request_uri"})
			return
		}
		var oauthClient *models.MCPOAuthClient
		var err error
		if services.IsHTTPSURL(clientID) {
			oauthClient, err = ctrl.service.GetOAuthClient(clientID)
			if err != nil {
				// CIMD client may exist but use the URL as client_id
				oauthClient, err = ctrl.service.ResolveCIMDClient(clientID)
			}
		} else {
			oauthClient, err = ctrl.service.GetOAuthClient(clientID)
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		arcCtx, ctxErr := ctrl.service.GetActiveAuthRequestContextByHydraRequestURI(requestURI)
		if ctxErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request_uri",
				"error_description": "request_uri is unknown or expired",
			})
			return
		}
		if arcCtx.HydraClientID != oauthClient.HydraClientID {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request_uri",
				"error_description": "request_uri does not belong to the supplied client",
			})
			return
		}
		hydraAuthURL := strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/") + "/oauth2/auth"
		if config.AppConfig.OAuthAuthURL != "" {
			hydraAuthURL = config.AppConfig.OAuthAuthURL
		}
		redirectParams := url.Values{
			"client_id":   {oauthClient.HydraClientID},
			"request_uri": {requestURI},
		}
		c.Redirect(http.StatusFound, hydraAuthURL+"?"+redirectParams.Encode())
		return
	}

	// Full authorize flow — all params on the query string (AuthSec pushes PAR internally)
	resource := c.Query("resource")
	state := c.Query("state")
	redirectURI := c.Query("redirect_uri")
	scopeParam := c.Query("scope")
	responseType := c.Query("response_type")
	responseMode := c.Query("response_mode")

	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// OIDC Core 1.0 §3.1.2.1 parameters
	nonce := c.Query("nonce")
	prompt := c.Query("prompt")
	maxAgeStr := c.Query("max_age")

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id required"})
		return
	}
	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource parameter required (RFC 8707)"})
		return
	}
	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state parameter required"})
		return
	}

	// response_type is REQUIRED (RFC 6749 §4.1.1). Only "code" is supported.
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "response_type=code is required",
		})
		return
	}

	// Reject non-query response_mode. The code-binding design requires query-style redirect.
	if responseMode != "" && responseMode != "query" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_mode",
			"error_description": "only response_mode=query is supported (form_post/fragment not supported)",
		})
		return
	}

	// PKCE is required for public clients (MCP spec mandates S256)
	if codeChallenge == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code_challenge required (PKCE)"})
		return
	}
	if codeChallengeMethod != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code_challenge_method must be S256"})
		return
	}
	if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code_challenge must be 43-128 characters"})
		return
	}

	// 1. Look up resource server by resource URI
	rs, err := ctrl.rsService.GetByResourceURI(resource)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown resource", "resource": resource})
		return
	}

	// 2. Resolve OAuth client (CIMD if HTTPS URL, else DCR/prereg lookup)
	// Client resolution MUST happen before scope validation so OIDC capability can be checked.
	var oauthClient *models.MCPOAuthClient
	if services.IsHTTPSURL(clientID) {
		// CIMD flow
		if !rs.AllowsRegistrationMode("cimd") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "resource server does not allow CIMD registration"})
			return
		}
		oauthClient, err = ctrl.service.ResolveCIMDClient(clientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to resolve CIMD client", "detail": err.Error()})
			return
		}
		if redirectURI != "" && !containsString([]string(oauthClient.RedirectURIs), redirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri not registered in CIMD document"})
			return
		}
		if _, err := ctrl.service.EnsureClientRegistration(rs.ID, oauthClient.ID, "cimd"); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register CIMD client for resource"})
			return
		}
	} else {
		oauthClient, err = ctrl.service.GetOAuthClient(clientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown client_id"})
			return
		}
		// Validate redirect_uri against registered URIs (same check as CIMD branch)
		if redirectURI != "" && !containsString([]string(oauthClient.RedirectURIs), redirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri not registered for this client"})
			return
		}
	}

	// 2b. Validate requested scopes against RS + client OIDC capability.
	// OIDC core scopes (openid, profile, etc.) are rejected for non-OIDC clients.
	if scopeParam != "" {
		requestedScopes := strings.Split(scopeParam, " ")
		if invalid := services.ValidateRequestedScopes(requestedScopes, rs, oauthClient); len(invalid) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "unsupported scope(s): " + strings.Join(invalid, ", "),
			})
			return
		}
	}

	// 3. Check join table — all client types must have an existing approved registration.
	// CIMD creates its join row at line 140 above; DCR/prereg create theirs at /oauth/register time.
	reg, err := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if err != nil || reg.Status != "approved" {
		c.JSON(http.StatusForbidden, gin.H{"error": "client not authorized for this resource"})
		return
	}

	redirectURIToUse := redirectURI
	switch len(oauthClient.RedirectURIs) {
	case 0:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "client has no registered redirect_uri",
		})
		return
	case 1:
		if redirectURIToUse == "" {
			redirectURIToUse = oauthClient.RedirectURIs[0]
		}
	default:
		if redirectURIToUse == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "redirect_uri is required for clients with multiple registered redirect URIs",
			})
			return
		}
	}

	// 4. Generate server-side context_id for deterministic binding.
	// This is NOT the client's state — it's an AuthSec-internal ID.
	contextID := uuid.New().String()

	// 5. Store auth request context first (audit trail, DB-backed from the start)
	ctx := &models.AuthRequestContext{
		State:            uuid.New().String(), // Server-generated PK (not client state)
		ContextID:        contextID,
		HydraClientID:    oauthClient.HydraClientID,
		ResourceServerID: rs.ID.String(),
		TenantID:         rs.TenantID.String(),
		ResourceURI:      rs.ResourceURI,
		RedirectURI:      redirectURIToUse,
		RequestedScopes:  scopeParam,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
	}
	// OIDC Core 1.0 §3.1.2.1 — persist OIDC params for hmgr enforcement + id_token binding
	if nonce != "" {
		ctx.Nonce = &nonce
	}
	if prompt != "" {
		ctx.Prompt = &prompt
	}
	if maxAgeStr != "" {
		if maxAgeInt, err := strconv.Atoi(maxAgeStr); err == nil {
			ctx.MaxAge = &maxAgeInt
		}
	}
	if err := ctrl.service.StoreAuthRequestContext(ctx); err != nil {
		log.Printf("[MCP_AUTH] Authorize: failed to store auth context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store auth context"})
		return
	}

	// 6. Push authorization request to Hydra via PAR (RFC 9126, server-to-server)
	parParams := url.Values{}
	parParams.Set("client_id", oauthClient.HydraClientID)
	parParams.Set("resource", resource)
	parParams.Set("state", state)
	parParams.Set("redirect_uri", redirectURIToUse)
	parParams.Set("response_type", "code")
	parParams.Set("response_mode", "query")
	parParams.Set("code_challenge", codeChallenge)
	parParams.Set("code_challenge_method", codeChallengeMethod)
	if scopeParam != "" {
		parParams.Set("scope", scopeParam)
	}
	// OIDC Core 1.0 — forward nonce/prompt/max_age to Hydra via PAR.
	// Hydra uses nonce when minting id_token; prompt/max_age control login behavior.
	if nonce != "" {
		parParams.Set("nonce", nonce)
	}
	if prompt != "" {
		parParams.Set("prompt", prompt)
	}
	if maxAgeStr != "" {
		parParams.Set("max_age", maxAgeStr)
	}
	requestURI, parExpiresIn, err := services.PushAuthorizationRequest(parParams)
	if err != nil {
		log.Printf("[MCP_AUTH] Authorize: PAR failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error":             "server_error",
			"error_description": "failed to initiate authorization request",
		})
		return
	}

	// 7. Update context with Hydra request_uri and align expiry (compare-and-set)
	alignedExpiry := ctx.ExpiresAt
	if parExpiresIn > 0 {
		parExpiry := time.Now().Add(time.Duration(parExpiresIn) * time.Second)
		if parExpiry.Before(alignedExpiry) {
			alignedExpiry = parExpiry
		}
	}
	if updateErr := ctrl.service.UpdateAuthRequestContextPAR(ctx.State, requestURI, alignedExpiry); updateErr != nil {
		// PAR succeeded but DB update failed — orphaned PAR object will expire in Hydra.
		// Do NOT redirect. Fail closed.
		log.Printf("[MCP_AUTH] Authorize: PAR succeeded but DB update failed state=%s request_uri=%s: %v",
			ctx.State, requestURI, updateErr)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "failed to persist authorization state",
		})
		return
	}

	log.Printf("[MCP_AUTH] Authorize: context_id=%s request_uri=%s client=%s resource=%s",
		contextID, requestURI, clientID, resource)

	// 8. Redirect browser with minimal params — only client_id + request_uri
	hydraAuthURL := strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/") + "/oauth2/auth"
	if config.AppConfig.OAuthAuthURL != "" {
		hydraAuthURL = config.AppConfig.OAuthAuthURL
	}
	redirectParams := url.Values{
		"client_id":   {oauthClient.HydraClientID},
		"request_uri": {requestURI},
	}
	c.Redirect(http.StatusFound, hydraAuthURL+"?"+redirectParams.Encode())
}

// Token handles the OAuth token exchange.
// POST /oauth/token
//
// ALL token requests go through context-bound exchange. No legacy passthrough.
//   - client_id is REQUIRED
//   - authorization_code: captures Hydra response, introspects access token for context_id,
//     looks up auth context, validates RS binding. FAILS CLOSED on missing context.
//   - refresh_token: supported when client has offline_access scope (OIDC/OAuth 2.1).
func (ctrl *OAuthASController) Token(c *gin.Context) {
	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}

	clientID := c.PostForm("client_id")
	grantType := c.PostForm("grant_type")

	// client_id is mandatory — no anonymous/legacy passthrough
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// Look up MCP OAuth client — must be registered
	oauthClient, err := ctrl.service.GetOAuthClient(clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "unknown client_id",
		})
		return
	}

	switch grantType {
	case "authorization_code":
		ctrl.tokenAuthCodeGrant(c, oauthClient)
	case "refresh_token":
		if !oauthClient.SupportsRefreshToken {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "unsupported_grant_type",
				"error_description": "refresh_token is not supported for this client",
			})
			return
		}
		ctrl.tokenRefreshGrant(c, oauthClient)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "only authorization_code and refresh_token are supported",
		})
		return
	}
}

// tokenAuthCodeGrant handles authorization_code exchange for MCP clients.
//
// Flow:
//  1. Rewrite client_id → hydra_client_id
//  2. Proxy to Hydra (capture response)
//  3. If Hydra returns 200, introspect the access token to extract context_id from session claims
//  4. Look up auth context by context_id (requires consent_completed=true, consumed=false)
//  5. If not found → FAIL CLOSED (do NOT forward token to client)
//  6. Validate RS registration
//  7. Consume auth context
//  8. Forward Hydra's response
func (ctrl *OAuthASController) tokenAuthCodeGrant(c *gin.Context, oauthClient *models.MCPOAuthClient) {
	redirectURI := c.PostForm("redirect_uri")
	resourceParam := c.PostForm("resource")

	// 1. Proxy to Hydra
	c.Request.PostForm.Set("client_id", oauthClient.HydraClientID)
	statusCode, body, respHeader, err := ctrl.service.ProxyFormToHydraPublicCapture(
		"/oauth2/token", c.Request.PostForm, c.Request.Header,
	)
	if err != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: Hydra unavailable: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server unavailable"})
		return
	}

	// If Hydra rejected → forward error as-is
	if statusCode != http.StatusOK {
		writeProxiedResponse(c.Writer, statusCode, body, respHeader)
		return
	}

	// 2. Parse Hydra's token response
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: failed to parse Hydra token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// 3. Extract context_id from the access token's session claims.
	// Hydra embeds session claims in the JWT access token under "ext".
	accessToken, _ := tokenResp["access_token"].(string)
	contextID := extractContextIDFromToken(accessToken)

	if contextID == "" {
		// Try introspection as fallback (handles opaque tokens)
		if tokenInfo, introErr := ctrl.service.IntrospectViaHydraAdmin(accessToken); introErr == nil {
			if ext, ok := tokenInfo["ext"].(map[string]interface{}); ok {
				contextID, _ = ext["context_id"].(string)
			}
		}
	}

	// 4. FAIL CLOSED: MCP authorization_code exchange MUST have a bound auth context.
	if contextID == "" {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: no context_id in access token for client=%s", oauthClient.ClientID)
		// Revoke the orphaned token Hydra just issued (best-effort)
		go ctrl.service.RevokeHydraToken(accessToken)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "no authorization context found for this token exchange",
		})
		return
	}

	arcCtx, err := ctrl.service.GetAuthRequestContextByContextID(contextID)
	if err != nil || arcCtx == nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: context_id=%s not found or not ready: %v", contextID, err)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authorization context not found or consent not completed",
		})
		return
	}

	// 5. Validate redirect_uri (RFC 6749 §4.1.3: REQUIRED if sent in authorize request)
	if arcCtx.RedirectURI != "" {
		if redirectURI == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "redirect_uri is required (was included in authorization request)",
			})
			return
		}
		if redirectURI != arcCtx.RedirectURI {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: redirect_uri mismatch for context_id=%s", contextID)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "redirect_uri mismatch",
			})
			return
		}
	}

	// Validate resource (RFC 8707 §2.2: REQUIRED, must match authorization request)
	if resourceParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "resource parameter is required",
		})
		return
	}
	if resourceParam != arcCtx.ResourceURI {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "resource parameter does not match authorization request",
		})
		return
	}

	// 6. Re-check join table status
	rs, rsErr := ctrl.rsService.GetByID(arcCtx.ResourceServerID)
	if rsErr != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: RS not found for context_id=%s rs_id=%s", contextID, arcCtx.ResourceServerID)
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "resource server not found"})
		return
	}
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if regErr != nil || reg.Status != "approved" {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: client not approved for RS context_id=%s", contextID)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "client registration for resource server is not approved",
		})
		return
	}

	// 6b. Defense-in-depth: re-run RBAC scope resolution at token exchange time.
	// If a role was revoked between consent and token exchange → fail-closed.
	if arcCtx.RequestedScopes != "" {
		tokenSubject := ""
		if tokenInfo, introErr := ctrl.service.IntrospectViaHydraAdmin(accessToken); introErr == nil {
			tokenSubject, _ = tokenInfo["sub"].(string)
		}
		if tokenSubject != "" {
			requestedScopes := strings.Split(arcCtx.RequestedScopes, " ")
			currentScopes, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
				c.Request.Context(),
				arcCtx.TenantID, tokenSubject, arcCtx.ResourceServerID,
				requestedScopes, rs, oauthClient,
			)
			if rbacErr != nil || len(currentScopes) == 0 {
				log.Printf("[MCP_AUTH] tokenAuthCodeGrant: RBAC re-check failed or empty scopes context_id=%s sub=%s err=%v",
					contextID, tokenSubject, rbacErr)
				go ctrl.service.RevokeHydraToken(accessToken)
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "insufficient_scope",
					"error_description": "user permissions have been revoked since authorization",
				})
				return
			}
		}
	}

	// 7. Atomically consume the auth context BEFORE returning the token.
	// If this fails (already consumed = concurrent request), reject.
	if err := ctrl.service.ConsumeAuthRequestContext(arcCtx.State); err != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: consume failed context_id=%s: %v", contextID, err)
		// Revoke the Hydra token since we can't safely return it
		go ctrl.service.RevokeHydraToken(accessToken)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authorization context already consumed",
		})
		return
	}

	// 8. Conditionally strip refresh tokens.
	// Clients without offline_access/SupportsRefreshToken get refresh_token stripped.
	// OIDC clients that opted into offline_access keep it.
	if !oauthClient.SupportsRefreshToken {
		if _, ok := tokenResp["refresh_token"]; ok {
			delete(tokenResp, "refresh_token")
			body, _ = json.Marshal(tokenResp)
		}
	}

	log.Printf("[MCP_AUTH] tokenAuthCodeGrant: success context_id=%s client=%s rs=%s", contextID, oauthClient.ClientID, arcCtx.ResourceURI)

	// 9. Forward response
	writeProxiedResponse(c.Writer, statusCode, body, respHeader)
}

// tokenRefreshGrant handles refresh_token exchange for OIDC clients.
// Proxies to Hydra after client_id rewrite. No context consumption — the original
// consent persists for the lifetime of the refresh chain.
//
// RFC 8707 §2.2: resource parameter SHOULD be validated on refresh. Clients may
// narrow the audience on refresh but cannot widen it beyond the original consent.
func (ctrl *OAuthASController) tokenRefreshGrant(c *gin.Context, oauthClient *models.MCPOAuthClient) {
	resourceParam := c.PostForm("resource")

	if resourceParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "resource parameter required",
		})
		return
	}

	// Validate resource if provided — must correspond to an RS the client is registered for.
	// This prevents audience widening on refresh.
	rs, err := ctrl.rsService.GetByResourceURI(resourceParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "unknown resource",
		})
		return
	}
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if regErr != nil || reg.Status != "approved" {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "client not authorized for this resource",
		})
		return
	}

	// Rewrite client_id to Hydra client_id
	c.Request.PostForm.Set("client_id", oauthClient.HydraClientID)
	statusCode, body, respHeader, err := ctrl.service.ProxyFormToHydraPublicCapture(
		"/oauth2/token", c.Request.PostForm, c.Request.Header,
	)
	if err != nil {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: Hydra unavailable: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server unavailable"})
		return
	}

	// RBAC re-check on refresh: if Hydra issued a new token, verify the user still has permissions.
	// This closes the gap where an admin revokes a role but the user keeps refreshing.
	if statusCode == http.StatusOK && resourceParam != "" {
		var tokenResp map[string]interface{}
		if jsonErr := json.Unmarshal(body, &tokenResp); jsonErr == nil {
			accessToken, _ := tokenResp["access_token"].(string)
			if accessToken != "" {
				if tokenInfo, introErr := ctrl.service.IntrospectViaHydraAdmin(accessToken); introErr == nil {
					sub, _ := tokenInfo["sub"].(string)
					tokenScopeStr, _ := tokenInfo["scope"].(string)
					if sub != "" && tokenScopeStr != "" {
						rs, rsErr := ctrl.rsService.GetByResourceURI(resourceParam)
						if rsErr == nil {
							tokenScopes := strings.Split(tokenScopeStr, " ")
							currentScopes, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
								c.Request.Context(),
								rs.TenantID.String(), sub, rs.ID.String(),
								tokenScopes, rs, oauthClient,
							)
							if rbacErr != nil || len(currentScopes) == 0 {
								log.Printf("[MCP_AUTH] tokenRefreshGrant: RBAC revoked for sub=%s rs=%s", sub, resourceParam)
								go ctrl.service.RevokeHydraToken(accessToken)
								c.JSON(http.StatusForbidden, gin.H{
									"error":             "insufficient_scope",
									"error_description": "user permissions have been revoked",
								})
								return
							}
						}
					}
				}
			}
		}
	}

	log.Printf("[MCP_AUTH] tokenRefreshGrant: client=%s resource=%s status=%d", oauthClient.ClientID, resourceParam, statusCode)
	writeProxiedResponse(c.Writer, statusCode, body, respHeader)
}

// Register handles Dynamic Client Registration (RFC 7591).
// POST /oauth/register
func (ctrl *OAuthASController) Register(c *gin.Context) {
	var req services.DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uris required"})
		return
	}

	for _, uri := range req.RedirectURIs {
		if !isValidRedirectURI(uri) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect_uri: must be HTTPS or localhost", "uri": uri})
			return
		}
	}

	for _, uri := range req.PostLogoutRedirectURIs {
		if !isValidRedirectURI(uri) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid post_logout_redirect_uri: must be HTTPS or localhost", "uri": uri})
			return
		}
	}

	// resource is REQUIRED — DCR clients must bind to a specific RS at registration
	if req.Resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "resource parameter is required for dynamic client registration",
		})
		return
	}

	rs, err := ctrl.rsService.GetByResourceURI(req.Resource)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown resource", "resource": req.Resource})
		return
	}
	if !rs.AllowsRegistrationMode("dcr") {
		c.JSON(http.StatusForbidden, gin.H{"error": "resource server does not allow DCR"})
		return
	}

	client, err := ctrl.service.RegisterDCRClient(req, rs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration failed", "detail": err.Error()})
		return
	}

	resp := services.DCRResponse{
		ClientID:                client.ClientID,
		ClientName:              client.ClientName,
		RedirectURIs:            []string(client.RedirectURIs),
		GrantTypes:              []string(client.GrantTypes),
		ResponseTypes:           []string(client.ResponseTypes),
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		Resource:                req.Resource,
		Scope:                   req.Scope,
		PostLogoutRedirectURIs:  []string(client.PostLogoutRedirectURIs),
	}

	c.JSON(http.StatusCreated, resp)
}

// Introspect handles OAuth token introspection (RFC 7662).
// POST /oauth/introspect
//
// RS authenticates via HTTP Basic Auth (rs_id:introspection_secret).
// On audience match: returns full introspection response (intentional — RS needs all claims for authz decisions).
// On mismatch or inactive: returns ONLY {"active": false}.
func (ctrl *OAuthASController) Introspect(c *gin.Context) {
	rsID, secret, ok := c.Request.BasicAuth()
	if !ok {
		c.Header("WWW-Authenticate", `Basic realm="introspection"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "resource server credentials required"})
		return
	}

	rs, err := ctrl.service.ValidateIntrospectionCredentials(rsID, secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token parameter required"})
		return
	}

	tokenInfo, err := ctrl.service.IntrospectViaHydraAdmin(token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	active, _ := tokenInfo["active"].(bool)
	if !active {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// RFC 7519 §4.1.3: "aud" can be a single string or an array of strings.
	audMatch := false
	switch aud := tokenInfo["aud"].(type) {
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == rs.ResourceURI {
				audMatch = true
				break
			}
		}
	case string:
		audMatch = (aud == rs.ResourceURI)
	}
	if !audMatch {
		log.Printf("[MCP_AUTH] Introspect: audience mismatch rs=%s token_aud=%v", rs.ResourceURI, tokenInfo["aud"])
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// LIVE RBAC enforcement: re-resolve current permissions from RBAC at introspection time.
	// This enables instant revocation — admin revokes a role → next MCP request → active: false.
	sub, _ := tokenInfo["sub"].(string)
	tokenScopeStr, _ := tokenInfo["scope"].(string)
	if sub != "" && tokenScopeStr != "" {
		tokenScopes := strings.Split(tokenScopeStr, " ")
		currentScopes, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
			c.Request.Context(),
			rs.TenantID.String(), sub, rs.ID.String(),
			tokenScopes,
			rs,
			nil, // no client needed for introspection — OIDC core scopes pass through on their own
		)
		if rbacErr != nil {
			log.Printf("[MCP_AUTH] Introspect: RBAC resolution failed sub=%s rs=%s: %v", sub, rs.ResourceURI, rbacErr)
			// Fail-closed: RBAC error → treat as inactive
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		if len(currentScopes) == 0 {
			// Role was fully revoked → token is effectively inactive
			log.Printf("[MCP_AUTH] Introspect: RBAC revoked all scopes sub=%s rs=%s", sub, rs.ResourceURI)
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		// Override scope in response with CURRENT RBAC-resolved permissions
		tokenInfo["scope"] = strings.Join(currentScopes, " ")
		// Update ext.permissions if present
		if ext, ok := tokenInfo["ext"].(map[string]interface{}); ok {
			ext["permissions"] = currentScopes
		}
	}

	c.JSON(http.StatusOK, tokenInfo)
}

// JWKS serves the cached Hydra JWKS.
// GET /oauth/jwks
func (ctrl *OAuthASController) JWKS(c *gin.Context) {
	jwks, err := ctrl.service.FetchJWKS()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch JWKS"})
		return
	}

	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "public, max-age=300")
	c.Writer.Write(jwks)
}

// Userinfo serves the OIDC UserInfo endpoint (OpenID Connect Core 1.0 §5.3).
// GET/POST /oauth/userinfo
//
// Accepts a Bearer access token, introspects it via Hydra admin, and returns
// claims filtered by granted scopes. Claims are sourced from Hydra session
// (populated during consent) enriched with federated identity data when available.
func (ctrl *OAuthASController) Userinfo(c *gin.Context) {
	// 1. Extract Bearer token
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.Header("WWW-Authenticate", `Bearer`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// 2. Introspect via Hydra admin
	tokenInfo, err := ctrl.service.IntrospectViaHydraAdmin(token)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	active, _ := tokenInfo["active"].(bool)
	if !active {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// 3. Check openid scope is granted
	scopeStr, _ := tokenInfo["scope"].(string)
	scopes := strings.Fields(scopeStr)
	hasOpenID := false
	scopeSet := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		scopeSet[s] = true
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		c.Header("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "error_description": "openid scope required"})
		return
	}

	// 4. Build claims from Hydra session (consent handler populates these)
	claims := map[string]interface{}{
		"sub": tokenInfo["sub"],
	}

	// Extract session claims from ext (Hydra stores consent session claims here)
	ext, _ := tokenInfo["ext"].(map[string]interface{})

	// profile scope: name, preferred_username, picture, updated_at
	if scopeSet["profile"] {
		if name := extractClaim(ext, tokenInfo, "name"); name != "" {
			claims["name"] = name
		}
		if username := extractClaim(ext, tokenInfo, "username"); username != "" {
			claims["preferred_username"] = username
		}
		if avatar := extractClaim(ext, tokenInfo, "avatar_url"); avatar != "" {
			claims["picture"] = avatar
		}
	}

	// email scope: email, email_verified (OIDC Core 5.1)
	if scopeSet["email"] {
		if email := extractClaim(ext, tokenInfo, "email"); email != "" {
			claims["email"] = email
			// email_verified MUST reflect the actual state — not hardcoded.
			// Check session claims first (consent handler sets this from provider data),
			// then fall back to false for local/unverified accounts.
			if ev := extractClaimBool(ext, tokenInfo, "email_verified"); ev != nil {
				claims["email_verified"] = *ev
			} else {
				claims["email_verified"] = false
			}
		}
	}

	// auth_time: OIDC Core §2 — MUST be present when max_age was used,
	// SHOULD be included when openid scope is granted.
	if authTime := extractClaim(ext, tokenInfo, "auth_time"); authTime != "" {
		claims["auth_time"] = authTime
	} else if authTimeNum := extractClaimFloat(ext, tokenInfo, "auth_time"); authTimeNum != nil {
		claims["auth_time"] = int64(*authTimeNum)
	}

	// Enrich with local user + OIDC identity data (graceful degradation — session claims are baseline)
	sub, _ := tokenInfo["sub"].(string)
	ctrl.service.EnrichUserinfoClaims(claims, sub, scopeSet)

	c.JSON(http.StatusOK, claims)
}

// EndSession handles RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0).
// GET /oauth/logout
//
// Accepts id_token_hint for session identification, validates post_logout_redirect_uri,
// revokes the Hydra login session, and redirects.
//
// Security: id_token_hint is verified via Hydra introspection (not just parsed).
// post_logout_redirect_uri REQUIRES client_id for validation against registered URIs.
func (ctrl *OAuthASController) EndSession(c *gin.Context) {
	idTokenHint := c.Query("id_token_hint")
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	state := c.Query("state")
	clientID := c.Query("client_id")

	var subject string

	// 1. Verify id_token_hint by validating the JWT signature against our JWKS.
	// This is the correct approach for id_tokens — Hydra's introspection endpoint is for
	// access tokens and may not recognize id_tokens.
	if idTokenHint != "" {
		sub, err := ctrl.service.VerifyIDTokenHint(idTokenHint, config.AppConfig.BaseURL, clientID)
		if err != nil {
			log.Printf("[MCP_AUTH] EndSession: id_token_hint verification failed: %v", err)
			// id_token_hint is optional per spec — proceed without subject
		} else {
			subject = sub
		}
	}

	// 2. post_logout_redirect_uri REQUIRES client_id — prevents open redirect.
	// Per OIDC RP-Initiated Logout §2: the AS MUST verify the URI against the client's
	// registered post_logout_redirect_uris.
	if postLogoutRedirectURI != "" {
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "client_id is required when post_logout_redirect_uri is provided",
			})
			return
		}
		oauthClient, err := ctrl.service.GetOAuthClient(clientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
			return
		}
		if !containsString([]string(oauthClient.PostLogoutRedirectURIs), postLogoutRedirectURI) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "post_logout_redirect_uri not registered"})
			return
		}
	}

	// 3. Revoke Hydra login session
	if subject != "" {
		if err := ctrl.service.RevokeHydraLoginSession(subject); err != nil {
			log.Printf("[MCP_AUTH] EndSession: failed to revoke Hydra session for sub=%s: %v", subject, err)
			// Continue — best effort
		}
	}

	// 4. Redirect (only to validated URI) or respond
	if postLogoutRedirectURI != "" {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			sep := "?"
			if strings.Contains(redirectURL, "?") {
				sep = "&"
			}
			redirectURL += sep + "state=" + url.QueryEscape(state)
		}
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

// PAR handles the public Pushed Authorization Request endpoint (RFC 9126).
// POST /oauth/par
//
// Clients can push authorization parameters before redirecting to /oauth/authorize.
// Returns a request_uri that can be used in the subsequent authorize redirect.
func (ctrl *OAuthASController) PAR(c *gin.Context) {
	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}

	clientID := c.PostForm("client_id")
	resource := c.PostForm("resource")
	state := c.PostForm("state")
	redirectURI := c.PostForm("redirect_uri")
	scopeParam := c.PostForm("scope")
	responseType := c.PostForm("response_type")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")
	nonce := c.PostForm("nonce")
	prompt := c.PostForm("prompt")
	maxAgeStr := c.PostForm("max_age")

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "client_id required"})
		return
	}
	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "resource parameter required"})
		return
	}
	if state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "state required"})
		return
	}
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_response_type", "error_description": "response_type=code required"})
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "PKCE S256 required"})
		return
	}

	// Resolve client
	oauthClient, rs, err := ctrl.resolveClientAndRS(clientID, resource)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Validate scopes against RS + client OIDC capability
	if scopeParam != "" {
		requestedScopes := strings.Split(scopeParam, " ")
		if invalid := services.ValidateRequestedScopes(requestedScopes, rs, oauthClient); len(invalid) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "unsupported scope(s): " + strings.Join(invalid, ", "),
			})
			return
		}
	}

	// Validate redirect_uri
	if redirectURI != "" && !containsString([]string(oauthClient.RedirectURIs), redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri not registered"})
		return
	}
	if redirectURI == "" {
		if len(oauthClient.RedirectURIs) == 1 {
			redirectURI = oauthClient.RedirectURIs[0]
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri required"})
			return
		}
	}

	// Build auth context
	contextID := uuid.New().String()
	ctx := &models.AuthRequestContext{
		State:            uuid.New().String(),
		ContextID:        contextID,
		HydraClientID:    oauthClient.HydraClientID,
		ResourceServerID: rs.ID.String(),
		TenantID:         rs.TenantID.String(),
		ResourceURI:      rs.ResourceURI,
		RedirectURI:      redirectURI,
		RequestedScopes:  scopeParam,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
	}
	if nonce != "" {
		ctx.Nonce = &nonce
	}
	if prompt != "" {
		ctx.Prompt = &prompt
	}
	if maxAgeStr != "" {
		if maxAgeInt, convErr := strconv.Atoi(maxAgeStr); convErr == nil {
			ctx.MaxAge = &maxAgeInt
		}
	}
	if err := ctrl.service.StoreAuthRequestContext(ctx); err != nil {
		log.Printf("[MCP_AUTH] PAR: failed to store auth context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Push to Hydra
	parParams := url.Values{}
	parParams.Set("client_id", oauthClient.HydraClientID)
	parParams.Set("resource", resource)
	parParams.Set("state", state)
	parParams.Set("redirect_uri", redirectURI)
	parParams.Set("response_type", "code")
	parParams.Set("response_mode", "query")
	parParams.Set("code_challenge", codeChallenge)
	parParams.Set("code_challenge_method", codeChallengeMethod)
	if scopeParam != "" {
		parParams.Set("scope", scopeParam)
	}
	if nonce != "" {
		parParams.Set("nonce", nonce)
	}
	if prompt != "" {
		parParams.Set("prompt", prompt)
	}
	if maxAgeStr != "" {
		parParams.Set("max_age", maxAgeStr)
	}

	requestURI, parExpiresIn, parErr := services.PushAuthorizationRequest(parParams)
	if parErr != nil {
		log.Printf("[MCP_AUTH] PAR: Hydra PAR failed: %v", parErr)
		c.JSON(http.StatusBadGateway, gin.H{"error": "server_error", "error_description": "failed to push authorization request"})
		return
	}

	// Update context with PAR request_uri
	alignedExpiry := ctx.ExpiresAt
	if parExpiresIn > 0 {
		parExpiry := time.Now().Add(time.Duration(parExpiresIn) * time.Second)
		if parExpiry.Before(alignedExpiry) {
			alignedExpiry = parExpiry
		}
	}
	if updateErr := ctrl.service.UpdateAuthRequestContextPAR(ctx.State, requestURI, alignedExpiry); updateErr != nil {
		log.Printf("[MCP_AUTH] PAR: DB update failed state=%s: %v", ctx.State, updateErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	log.Printf("[MCP_AUTH] PAR: context_id=%s request_uri=%s client=%s", contextID, requestURI, clientID)

	c.JSON(http.StatusCreated, gin.H{
		"request_uri": requestURI,
		"expires_in":  parExpiresIn,
	})
}

// resolveClientAndRS resolves the OAuth client (CIMD or DCR) and resource server.
func (ctrl *OAuthASController) resolveClientAndRS(clientID, resource string) (*models.MCPOAuthClient, *models.ResourceServer, error) {
	rs, err := ctrl.rsService.GetByResourceURI(resource)
	if err != nil {
		return nil, nil, fmt.Errorf("unknown resource: %s", resource)
	}

	var oauthClient *models.MCPOAuthClient

	if services.IsHTTPSURL(clientID) {
		// CIMD flow
		resolved, cimdErr := ctrl.service.ResolveCIMDClient(clientID)
		if cimdErr != nil {
			return nil, nil, fmt.Errorf("CIMD resolution failed: %w", cimdErr)
		}
		oauthClient = resolved
		if _, regErr := ctrl.service.EnsureClientRegistration(rs.ID, oauthClient.ID, "cimd"); regErr != nil {
			return nil, nil, fmt.Errorf("client registration failed: %w", regErr)
		}
	} else {
		found, lookupErr := ctrl.service.GetOAuthClient(clientID)
		if lookupErr != nil {
			return nil, nil, fmt.Errorf("unknown client_id: %s", clientID)
		}
		oauthClient = found
	}

	// Check approved registration
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if regErr != nil || reg.Status != "approved" {
		return nil, nil, fmt.Errorf("client not authorized for this resource")
	}

	return oauthClient, rs, nil
}

// extractClaim extracts a string claim from Hydra ext session claims or top-level introspection.
func extractClaim(ext map[string]interface{}, tokenInfo map[string]interface{}, key string) string {
	if ext != nil {
		if v, ok := ext[key].(string); ok && v != "" {
			return v
		}
	}
	if v, ok := tokenInfo[key].(string); ok {
		return v
	}
	return ""
}

// extractClaimBool extracts a boolean claim from Hydra ext session or top-level.
// Returns nil if not found (distinguishes "missing" from "false").
func extractClaimBool(ext map[string]interface{}, tokenInfo map[string]interface{}, key string) *bool {
	if ext != nil {
		if v, ok := ext[key].(bool); ok {
			return &v
		}
	}
	if v, ok := tokenInfo[key].(bool); ok {
		return &v
	}
	return nil
}

// extractClaimFloat extracts a numeric claim (JSON numbers decode as float64).
func extractClaimFloat(ext map[string]interface{}, tokenInfo map[string]interface{}, key string) *float64 {
	if ext != nil {
		if v, ok := ext[key].(float64); ok {
			return &v
		}
	}
	if v, ok := tokenInfo[key].(float64); ok {
		return &v
	}
	return nil
}

// Revoke handles OAuth token revocation (RFC 7009).
// POST /oauth/revoke
func (ctrl *OAuthASController) Revoke(c *gin.Context) {
	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}

	clientID := c.PostForm("client_id")
	if clientID != "" {
		oauthClient, err := ctrl.service.GetOAuthClient(clientID)
		if err == nil {
			c.Request.PostForm.Set("client_id", oauthClient.HydraClientID)
		}
	}

	ctrl.service.ProxyFormToHydraPublic("/oauth2/revoke", c.Request.PostForm, c.Request.Header, c.Writer)
}

// --- Helpers ---

func isValidRedirectURI(uri string) bool {
	if strings.HasPrefix(uri, "https://") {
		return true
	}
	if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
		return true
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func writeProxiedResponse(w http.ResponseWriter, statusCode int, body []byte, respHeader http.Header) {
	for k, vv := range respHeader {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(statusCode)
	w.Write(body)
}

// extractContextIDFromToken decodes a JWT access token's payload to extract the context_id
// from session claims (under "ext.context_id"). Returns "" if not a JWT or context_id not found.
// Does NOT verify the signature — this is for internal session claim extraction only.
func extractContextIDFromToken(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return "" // Not a JWT (opaque token)
	}

	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}

	// Hydra stores session claims under "ext" in the JWT
	ext, ok := claims["ext"].(map[string]interface{})
	if !ok {
		return ""
	}

	contextID, _ := ext["context_id"].(string)
	return contextID
}

// ListConsentGrants lists consent grants for the admin (filterable by user, client, RS).
// GET /platform/consent-grants?tenant_id=...&user_id=...&client_id=...&rs_id=...
func (ctrl *OAuthASController) ListConsentGrants(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	var userID, clientID, rsID *uuid.UUID
	if v := c.Query("user_id"); v != "" {
		if u, err := uuid.Parse(v); err == nil {
			userID = &u
		}
	}
	if v := c.Query("client_id"); v != "" {
		if u, err := uuid.Parse(v); err == nil {
			clientID = &u
		}
	}
	if v := c.Query("rs_id"); v != "" {
		if u, err := uuid.Parse(v); err == nil {
			rsID = &u
		}
	}

	grants, err := ctrl.consentService.ListByTenant(tenantID, userID, clientID, rsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list consent grants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"consent_grants": grants})
}

// RevokeConsentGrant revokes a consent grant (admin).
// DELETE /platform/consent-grants/:id
func (ctrl *OAuthASController) RevokeConsentGrant(c *gin.Context) {
	grantIDStr := c.Param("id")
	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid grant ID"})
		return
	}

	if err := ctrl.consentService.RevokeConsent(grantID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "consent grant not found or already revoked"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ListUserConsentGrants lists consent grants for the authenticated user.
// GET /oauth/consent-grants (user self-service)
func (ctrl *OAuthASController) ListUserConsentGrants(c *gin.Context) {
	tenantID, userID, err := ctrl.requireAuthenticatedUserContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	grants, err := ctrl.consentService.ListByUser(tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list consent grants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"consent_grants": grants})
}

// RevokeUserConsentGrant revokes a consent grant for the authenticated user.
// DELETE /oauth/consent-grants/:id
func (ctrl *OAuthASController) RevokeUserConsentGrant(c *gin.Context) {
	grantIDStr := c.Param("id")
	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid grant ID"})
		return
	}

	_, userID, err := ctrl.requireAuthenticatedUserContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if err := ctrl.consentService.RevokeConsentByUser(grantID, userID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "consent grant not found or already revoked"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

func (ctrl *OAuthASController) requireAuthenticatedUserContext(c *gin.Context) (uuid.UUID, uuid.UUID, error) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("tenant_id required in JWT")
	}

	userIDStr, err := middlewares.ResolveUserID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("user_id required in JWT")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid user_id in JWT")
	}

	return tenantID, userID, nil
}
