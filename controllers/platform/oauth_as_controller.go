package platform

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// CanonicalIssuerOnly redirects discovery and OAuth requests to the configured
// OAuth issuer host when they arrive on a different public host (for example the
// SPA host). This keeps a single canonical issuer while still avoiding SPA HTML
// on accidentally probed well-known or /oauth paths.
func (ctrl *OAuthASController) CanonicalIssuerOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		canonicalBase := config.AppConfig.OAuthBaseURL()
		parsed, err := url.Parse(canonicalBase)
		if err != nil || parsed.Host == "" {
			c.Next()
			return
		}

		requestHost := c.Request.Host
		if forwardedHost := c.GetHeader("X-Forwarded-Host"); forwardedHost != "" {
			requestHost = strings.TrimSpace(strings.Split(forwardedHost, ",")[0])
		}

		if strings.EqualFold(requestHost, parsed.Host) {
			c.Next()
			return
		}

		target := strings.TrimSuffix(canonicalBase, "/") + c.Request.URL.RequestURI()
		c.Redirect(http.StatusPermanentRedirect, target)
		c.Abort()
	}
}

// ASMetadata serves RFC 8414 Authorization Server Metadata.
// GET /.well-known/oauth-authorization-server
func (ctrl *OAuthASController) ASMetadata(c *gin.Context) {
	baseURL := config.AppConfig.OAuthBaseURL()
	c.JSON(http.StatusOK, ctrl.service.ASMetadata(baseURL))
}

// OIDCDiscovery serves OpenID Connect Discovery 1.0 metadata.
// GET /.well-known/openid-configuration
// Returns the same superset document as ASMetadata (OIDC Discovery is a superset of RFC 8414).
func (ctrl *OAuthASController) OIDCDiscovery(c *gin.Context) {
	baseURL := config.AppConfig.OAuthBaseURL()
	c.JSON(http.StatusOK, ctrl.service.ASMetadata(baseURL))
}

// Authorize handles the OAuth authorization request.
// GET /oauth/authorize
//
// Temporary no-PAR bridge:
//   - PAR is disabled at the public AuthSec surface for now.
//   - AuthSec stores the auth context and redirects directly to Hydra /oauth2/auth.
//   - authsec_ctx=contextID is the temporary correlation key consumed by hmgr.
//
// Hard rules:
//   - Generates server-side context_id (never trusts client state for binding)
//   - Only supports response_type=code
//   - Only supports response_mode=query
//   - PKCE S256 required
func (ctrl *OAuthASController) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	requestURI := c.Query("request_uri")

	// Temporary compatibility mode: public PAR is disabled while AuthSec is still backed
	// by stock Hydra, which does not expose /oauth2/par. Reject request_uri explicitly
	// instead of pretending to support RFC 9126.
	if requestURI != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request_uri",
			"error_description": "PAR is temporarily disabled; retry the authorization request without request_uri",
		})
		return
	}

	// Temporary no-PAR authorize flow — AuthSec stores context and redirects to Hydra directly.
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
		inferredResource, inferErr := ctrl.inferAuthorizeResource(clientID)
		if inferErr != nil {
			c.JSON(inferErr.Status, gin.H{"error": inferErr.Code, "error_description": inferErr.Description})
			return
		}
		resource = inferredResource
		log.Printf("[MCP_AUTH] Authorize: inferred resource=%s for client=%s (compatibility mode)", resource, clientID)
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

	// Resolve client + RS and enforce all policy gates in one shared pass — identical to PAR.
	// validateOAuthPolicy is the single authoritative check for both entrypoints.
	policy, pErr := ctrl.validateOAuthPolicy(clientID, resource, redirectURI, strings.Fields(scopeParam))
	if pErr != nil {
		c.JSON(pErr.Status, gin.H{"error": pErr.Code, "error_description": pErr.Description})
		return
	}
	oauthClient := policy.Client
	rs := policy.RS
	redirectURIToUse := policy.RedirectURI

	// JIT scope binding for DCR clients. RFC 7591 lets clients register with
	// an empty `scope`; spec-compliant MCP clients (Claude Code, etc.) do
	// exactly that, expecting resource-bound scopes to be granted at
	// /authorize. Without this step, Hydra would reject with
	//   "OAuth 2.0 Client is not allowed to request scope '<rs-scope>'"
	// because the Hydra client was registered with an empty scope set.
	// See EnsureHydraClientHasRSScopes for the full rationale + safety
	// argument (this only widens what the client may REQUEST; consent + RBAC
	// still gate what's actually granted).
	if err := ctrl.service.EnsureHydraClientHasRSScopes(oauthClient, rs); err != nil {
		log.Printf("[MCP_AUTH] Authorize: scope-binding update failed client=%s rs=%s: %v",
			oauthClient.ClientID, rs.ResourceURI, err)
		// Don't fail the request — Hydra will still reject any requested
		// scope not in the registered set, which is the correct fallback.
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
		WorkspaceID:         rs.WorkspaceID.String(),
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

	// 6. Redirect directly to Hydra /oauth2/auth. Keep the client-supplied OAuth state
	// flowing through Hydra and use authsec_ctx only as an internal correlation key.
	hydraAuthURL := strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/") + "/oauth2/auth"
	if config.AppConfig.OAuthAuthURL != "" {
		hydraAuthURL = config.AppConfig.OAuthAuthURL
	}
	redirectParams := url.Values{}
	redirectParams.Set("client_id", oauthClient.HydraClientID)
	redirectParams.Set("resource", resource)
	redirectParams.Set("state", state)
	redirectParams.Set("redirect_uri", redirectURIToUse)
	redirectParams.Set("response_type", "code")
	redirectParams.Set("response_mode", "query")
	redirectParams.Set("code_challenge", codeChallenge)
	redirectParams.Set("code_challenge_method", codeChallengeMethod)
	if scopeParam != "" {
		redirectParams.Set("scope", scopeParam)
	}
	if nonce != "" {
		redirectParams.Set("nonce", nonce)
	}
	if prompt != "" {
		redirectParams.Set("prompt", prompt)
	}
	if maxAgeStr != "" {
		redirectParams.Set("max_age", maxAgeStr)
	}
	redirectParams.Set("authsec_ctx", contextID)

	log.Printf("[MCP_AUTH] Authorize: context_id=%s authsec_ctx=%s client=%s resource=%s",
		contextID, contextID, clientID, resource)

	// 7. Redirect browser with the full authorize request plus authsec_ctx bridge.
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

	// 2. Parse Hydra's token response immediately — capture both tokens before any check
	// so that every subsequent rejection path can revoke the full set synchronously.
	var tokenResp map[string]interface{}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: failed to parse Hydra token response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	accessToken, _ := tokenResp["access_token"].(string)
	refreshToken, _ := tokenResp["refresh_token"].(string) // may be empty for non-OIDC clients

	// revokeIssuedTokens revokes both tokens synchronously before a hard-denial response.
	// Policy: 403 is always returned even if Hydra revocation fails (Hydra downtime must
	// not become a bypass). Revocation errors are logged for operator awareness.
	revokeIssuedTokens := func(label string) {
		if err := ctrl.service.RevokeFullTokenSet(accessToken, refreshToken); err != nil {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: revocation failed (%s): %v — returning 403 regardless", label, err)
		}
	}

	// 3. Extract context_id from the access token's session claims.
	// Hydra embeds session claims in the JWT access token under "ext".
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
		revokeIssuedTokens("missing context_id")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "no authorization context found for this token exchange",
		})
		return
	}

	arcCtx, err := ctrl.service.GetAuthRequestContextByContextID(contextID)
	if err != nil || arcCtx == nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: context_id=%s not found or not ready: %v", contextID, err)
		revokeIssuedTokens("context not found")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authorization context not found or consent not completed",
		})
		return
	}

	// 5. Validate redirect_uri (RFC 6749 §4.1.3: REQUIRED if sent in authorize request)
	if arcCtx.RedirectURI != "" {
		if redirectURI == "" {
			revokeIssuedTokens("redirect_uri required but absent")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "redirect_uri is required (was included in authorization request)",
			})
			return
		}
		if redirectURI != arcCtx.RedirectURI {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: redirect_uri mismatch for context_id=%s", contextID)
			revokeIssuedTokens("redirect_uri mismatch")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "redirect_uri mismatch",
			})
			return
		}
	}

	// Validate resource. In compatibility mode, clients that omit the redundant token-time
	// resource parameter inherit the single resource that was already authorized and stored
	// in the auth request context.
	if resourceParam == "" {
		resourceParam = arcCtx.ResourceURI
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: defaulted missing resource to stored auth context resource=%s context_id=%s",
			resourceParam, contextID)
	}
	if resourceParam != arcCtx.ResourceURI {
		revokeIssuedTokens("resource param mismatch at exchange")
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
		revokeIssuedTokens("RS not found at exchange")
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied", "error_description": "resource server not found"})
		return
	}
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if regErr != nil || reg.Status != "approved" {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: client not approved for RS context_id=%s", contextID)
		revokeIssuedTokens("registration not approved at exchange")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "client registration for resource server is not approved",
		})
		return
	}

	// 6b. Defense-in-depth: strict-subset RBAC scope enforcement at token exchange time.
	//
	// FAIL-CLOSED: if Hydra admin introspection fails, or the token carries no subject/scope,
	// we cannot confirm the user's current permissions — hard denial + full revocation.
	// Hydra downtime must not become a bypass. Operators must monitor introspection failures.
	//
	// tokenScopes MUST come from Hydra's admin introspection of the issued access token —
	// NOT from arcCtx.RequestedScopes. The user may have consented to a subset of the
	// original request; using the request scopes would over-reject valid partial consents.
	{
		tokenInfo, introErr := ctrl.service.IntrospectViaHydraAdmin(accessToken)
		if introErr != nil {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: Hydra admin introspection failed context_id=%s: %v — failing closed",
				contextID, introErr)
			revokeIssuedTokens("Hydra introspection failure at exchange")
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "access_denied",
				"error_description": "authorization server unavailable for permission verification",
			})
			return
		}
		tokenSubject, _ := tokenInfo["sub"].(string)
		issuedScopeStr, _ := tokenInfo["scope"].(string)
		if tokenSubject == "" || issuedScopeStr == "" {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: introspection returned no sub/scope context_id=%s — failing closed",
				contextID)
			revokeIssuedTokens("empty sub or scope in introspection response")
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "access_denied",
				"error_description": "token carries no subject or scope",
			})
			return
		}
		issuedScopes := strings.Fields(issuedScopeStr)
		currentScopes, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
			c.Request.Context(),
			arcCtx.WorkspaceID, tokenSubject, arcCtx.ResourceServerID,
			issuedScopes, rs, oauthClient,
		)
		if rbacErr != nil || len(currentScopes) == 0 {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: RBAC full revocation context_id=%s sub=%s err=%v",
				contextID, tokenSubject, rbacErr)
			revokeIssuedTokens("RBAC revocation (full loss)")
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "user permissions have been revoked since authorization",
			})
			return
		}
		// Strict-subset check: if any RS-specific scope in the issued token is no longer
		// RBAC-grantable, deny. Partial scope loss is a hard denial (no narrowing).
		issuedRS := services.RSSpecificScopes(issuedScopes)
		currentRS := services.RSSpecificScopes(currentScopes)
		if lost := services.ScopesLost(issuedRS, currentRS); len(lost) > 0 {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: partial scope loss context_id=%s sub=%s lost=%v",
				contextID, tokenSubject, lost)
			revokeIssuedTokens("partial scope loss at exchange")
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "insufficient_scope",
				"error_description": "user permissions have been partially revoked since authorization",
			})
			return
		}
	}

	// 7. Atomically consume the auth context BEFORE returning the token.
	// If this fails (already consumed = concurrent request), reject.
	if err := ctrl.service.ConsumeAuthRequestContext(arcCtx.State); err != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: consume failed context_id=%s: %v", contextID, err)
		revokeIssuedTokens("context already consumed")
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
		inferredResource, err := ctrl.service.InferSingleResourceURIForClient(oauthClient)
		if err != nil {
			if errors.Is(err, services.ErrResourceInferenceAmbiguous) {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "resource parameter required because client maps to multiple resource servers",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "resource parameter required because client is not bound to a single resource server",
			})
			return
		}
		resourceParam = inferredResource
		log.Printf("[MCP_AUTH] tokenRefreshGrant: inferred missing resource=%s for client=%s (compatibility mode)",
			resourceParam, oauthClient.ClientID)
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

	// Hydra rejected the refresh token (e.g. expired, already used, unknown client).
	// Proxy the error back as-is — no RBAC enforcement needed for non-200 responses.
	if statusCode != http.StatusOK {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: Hydra rejected refresh client=%s resource=%s status=%d",
			oauthClient.ClientID, resourceParam, statusCode)
		writeProxiedResponse(c.Writer, statusCode, body, respHeader)
		return
	}

	// statusCode == 200: Hydra issued a new token set.
	//
	// FAIL-CLOSED RBAC enforcement — ALL of the following steps are UNCONDITIONAL:
	// every parse failure, introspection failure, or permission mismatch revokes the
	// newly-issued token set synchronously and returns 403.
	//
	// Hydra downtime is NOT a bypass: if admin introspection is unreachable we cannot
	// verify current user permissions, so we must deny. Operators must monitor
	// revocation failure logs; Hydra token TTL is the backstop for revocation failures.
	//
	// The old refresh token was already consumed by Hydra before this point.
	// Both new tokens (access + refresh) are revoked on any denial.

	var refreshResp map[string]interface{}
	if jsonErr := json.Unmarshal(body, &refreshResp); jsonErr != nil {
		// Body is not parseable — cannot verify permissions. No tokens to revoke yet.
		log.Printf("[MCP_AUTH] tokenRefreshGrant: cannot parse Hydra 200 response: %v — failing closed", jsonErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	newAccessToken, _ := refreshResp["access_token"].(string)
	newRefreshToken, _ := refreshResp["refresh_token"].(string)

	// revokeRefreshed revokes both newly-issued tokens synchronously.
	// 403 is always returned even when revocation itself fails — Hydra downtime must
	// not become a bypass. The trade-off (live Hydra tokens vs. denied refresh) is
	// accepted; operators must monitor revocation failure logs.
	revokeRefreshed := func(label string) {
		if err := ctrl.service.RevokeFullTokenSet(newAccessToken, newRefreshToken); err != nil {
			log.Printf("[MCP_AUTH] tokenRefreshGrant: revocation failed (%s): %v — returning 403 regardless", label, err)
		}
	}

	if newAccessToken == "" {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: Hydra 200 response missing access_token — failing closed")
		revokeRefreshed("missing access_token in refresh response")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authorization server returned invalid token response",
		})
		return
	}

	// Admin introspection is required to obtain the canonical issued scope and subject.
	// Failure here (network, 5xx, circuit-open) → fail closed.
	tokenInfo, introErr := ctrl.service.IntrospectViaHydraAdmin(newAccessToken)
	if introErr != nil {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: admin introspect failed: %v — failing closed", introErr)
		revokeRefreshed("admin introspect failure at refresh")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authorization server unavailable for permission verification",
		})
		return
	}

	sub, _ := tokenInfo["sub"].(string)
	issuedScopeStr, _ := tokenInfo["scope"].(string)
	if sub == "" || issuedScopeStr == "" {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: introspect returned empty sub/scope — failing closed")
		revokeRefreshed("empty sub or scope in refresh introspection response")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "token carries no subject or scope",
		})
		return
	}

	issuedScopes := strings.Fields(issuedScopeStr)
	currentScopes, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
		c.Request.Context(),
		rs.WorkspaceID.String(), sub, rs.ID.String(),
		issuedScopes, rs, oauthClient,
	)
	if rbacErr != nil || len(currentScopes) == 0 {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: RBAC fully revoked sub=%s rs=%s err=%v", sub, resourceParam, rbacErr)
		revokeRefreshed("full RBAC loss on refresh")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "insufficient_scope",
			"error_description": "user permissions have been revoked",
		})
		return
	}

	// Strict-subset: any RS-specific scope the refreshed token carries that RBAC no longer
	// grants is a hard denial. Scope narrowing is not permitted at refresh time.
	issuedRS := services.RSSpecificScopes(issuedScopes)
	currentRS := services.RSSpecificScopes(currentScopes)
	if lost := services.ScopesLost(issuedRS, currentRS); len(lost) > 0 {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: partial scope loss sub=%s rs=%s lost=%v", sub, resourceParam, lost)
		revokeRefreshed("partial scope loss on refresh")
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "insufficient_scope",
			"error_description": "user permissions have been partially revoked",
		})
		return
	}

	// All checks passed — return the refreshed token set.
	log.Printf("[MCP_AUTH] tokenRefreshGrant: success client=%s resource=%s", oauthClient.ClientID, resourceParam)
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

	// resource is OPTIONAL at DCR time (RFC 7591 does not mandate it).
	// Many real-world clients (e.g. Claude Code) omit it and pass the resource
	// parameter at the /authorize call instead, per RFC 8707. When present we
	// still honour it to bind the client to an RS up-front; when absent we
	// register an unbound client and defer binding to /authorize, which already
	// enforces the resource parameter.
	var rs *models.ResourceServer
	if req.Resource != "" {
		var err error
		rs, err = ctrl.rsService.GetByResourceURI(req.Resource)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown resource", "resource": req.Resource})
			return
		}
		if !rs.AllowsRegistrationMode("dcr") {
			c.JSON(http.StatusForbidden, gin.H{"error": "resource server does not allow DCR"})
			return
		}
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
		log.Printf("[MCP_AUTH] Introspect: Hydra admin introspection error rs=%s: %v", rs.ResourceURI, err)
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	active, _ := tokenInfo["active"].(bool)
	if !active {
		log.Printf("[MCP_AUTH] Introspect: Hydra reports token inactive rs=%s sub=%q aud=%v",
			rs.ResourceURI, tokenInfo["sub"], tokenInfo["aud"])
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

	// LIVE RBAC enforcement with OIDC-only token fix.
	//
	// Design principles:
	//  1. sub and scope are REQUIRED for any active, audience-matched token. If either is
	//     absent, we cannot enforce permissions — treat as inactive (fail closed).
	//  2. OIDC core scopes (openid, profile, email, ...) are passed through without RBAC
	//     resolution. Previously, passing nil client to ResolveGrantableScopes caused
	//     clientIsOIDC(nil)==false → OIDC scopes treated as RS-specific → empty resolution
	//     → active:false for valid OIDC-only tokens. Fixed by partitioning before resolution.
	//  3. RS-specific scopes are subject to live RBAC resolution and strict-subset enforcement.
	sub, _ := tokenInfo["sub"].(string)
	tokenScopeStr, _ := tokenInfo["scope"].(string)

	// Fail closed: sub and scope are mandatory for enforcement. An active token missing
	// either field is structurally invalid from AuthSec's perspective — return active:false
	// rather than passing the raw Hydra payload through without a permission check.
	if sub == "" || tokenScopeStr == "" {
		log.Printf("[MCP_AUTH] Introspect: active token missing sub or scope sub=%q scope=%q — failing closed",
			sub, tokenScopeStr)
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// Enforcement block runs unconditionally for all active, audience-matched tokens.
	tokenScopes := strings.Fields(tokenScopeStr)
	oidcScopes, rsScopes := services.PartitionScopes(tokenScopes)

	var finalScopes []string

	if len(rsScopes) > 0 {
		// Run RBAC resolution only for the RS-specific portion of the token's scopes.
		// Passing nil client is correct here: rsScopes contains no OIDC core scopes,
		// so clientIsOIDC(nil)==false causes no incorrect exclusions.
		currentRS, rbacErr := ctrl.scopeResolver.ResolveGrantableScopes(
			c.Request.Context(),
			rs.WorkspaceID.String(), sub, rs.ID.String(),
			rsScopes,
			rs,
			nil,
		)
		if rbacErr != nil {
			log.Printf("[MCP_AUTH] Introspect: RBAC resolution failed sub=%s rs=%s: %v", sub, rs.ResourceURI, rbacErr)
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		if len(currentRS) == 0 {
			log.Printf("[MCP_AUTH] Introspect: RBAC revoked all RS scopes sub=%s rs=%s", sub, rs.ResourceURI)
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		// Strict-subset: any RS scope the token carried that RBAC no longer grants → inactive.
		if lost := services.ScopesLost(rsScopes, currentRS); len(lost) > 0 {
			log.Printf("[MCP_AUTH] Introspect: partial RS scope loss sub=%s rs=%s lost=%v", sub, rs.ResourceURI, lost)
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		finalScopes = append(oidcScopes, currentRS...)
	} else {
		// OIDC-only token (e.g. openid profile): no RS-specific scopes → no RBAC check.
		// The token remains active as long as Hydra considers it active and the audience matches.
		finalScopes = oidcScopes
	}

	if len(finalScopes) == 0 {
		log.Printf("[MCP_AUTH] Introspect: no scopes remain after enforcement sub=%s rs=%s", sub, rs.ResourceURI)
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// Override scope in response with current live permissions
	tokenInfo["scope"] = strings.Join(finalScopes, " ")
	if ext, ok := tokenInfo["ext"].(map[string]interface{}); ok {
		ext["permissions"] = finalScopes
	}

	log.Printf("[MCP_AUTH] Introspect: active=true sub=%s rs=%s scopes=%v aud=%v",
		sub, rs.ResourceURI, finalScopes, tokenInfo["aud"])
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
		sub, err := ctrl.service.VerifyIDTokenHint(idTokenHint, config.AppConfig.OAuthBaseURL(), clientID)
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

// PAR is temporarily disabled while AuthSec is still backed by stock Hydra, which
// does not expose /oauth2/par in self-hosted mode. A later AuthSec-owned PAR
// implementation will re-enable this endpoint without depending on Hydra PAR.
func (ctrl *OAuthASController) PAR(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":             "unsupported_request",
		"error_description": "PAR is temporarily disabled; use /oauth/authorize directly",
	})
}

// OAuthPolicyResult holds the validated policy state from validateOAuthPolicy.
type OAuthPolicyResult struct {
	Client      *models.MCPOAuthClient
	RS          *models.ResourceServer
	RedirectURI string // resolved (auto-selected for single-URI clients)
}

// policyError is a structured policy rejection that carries an HTTP status code,
// an OAuth error code, and a human-readable description.
type policyError struct {
	Status      int
	Code        string
	Description string
}

func (e *policyError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (ctrl *OAuthASController) inferAuthorizeResource(clientID string) (string, *policyError) {
	if services.IsHTTPSURL(clientID) {
		return "", &policyError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "resource parameter required for HTTPS client_id",
		}
	}

	oauthClient, err := ctrl.service.GetOAuthClient(clientID)
	if err != nil {
		return "", &policyError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_client",
			Description: "unknown client_id",
		}
	}

	resourceURI, inferErr := ctrl.service.InferSingleResourceURIForClient(oauthClient)
	if inferErr == nil {
		return resourceURI, nil
	}
	if errors.Is(inferErr, services.ErrResourceInferenceAmbiguous) {
		return "", &policyError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "resource parameter required because client maps to multiple resource servers",
		}
	}
	if errors.Is(inferErr, services.ErrResourceInferenceUnavailable) {
		return "", &policyError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "resource parameter required because client is not bound to a single resource server",
		}
	}
	return "", &policyError{
		Status:      http.StatusInternalServerError,
		Code:        "server_error",
		Description: "failed to infer resource server",
	}
}

// validateOAuthPolicy is the single authoritative policy gate for all new OAuth
// authorization requests — PAR and full-query Authorize (Branch B).
//
// Checks enforced in order (fail-closed):
//  1. RS exists and is Active
//  2. Client resolution: CIMD (HTTPS client_id) or DCR/prereg
//  3. Exact registration-mode check: rs.AllowsRegistrationMode(client.RegistrationType)
//     — prevents an RS that only allows "prereg" from admitting a "dcr" client even if
//     both modes were once enabled.
//  4. Client registration approval (join-table Status == "approved")
//  5. Redirect URI validation (auto-selects single URI, requires explicit URI for multiples)
//  6. Scope validation via services.ValidateRequestedScopes
func (ctrl *OAuthASController) validateOAuthPolicy(
	clientID, resource, redirectURI string,
	requestedScopes []string,
) (*OAuthPolicyResult, *policyError) {
	// 1. RS resolution and active check
	rs, err := ctrl.rsService.GetByResourceURI(resource)
	if err != nil {
		return nil, &policyError{http.StatusBadRequest, "invalid_request", "unknown resource: " + resource}
	}
	if !rs.Active {
		return nil, &policyError{http.StatusForbidden, "access_denied", "resource server is inactive"}
	}

	// 2. Client resolution + exact registration-mode enforcement.
	//
	// For CIMD (HTTPS clientID): we know the intended type is "cimd" before any network
	// call. Fail fast if cimd is not in the RS's RegistrationModes — avoids an unnecessary
	// outbound fetch and gives a meaningful 403 rather than a network error.
	//
	// For DCR/prereg (non-HTTPS): resolve the client first to learn its actual
	// RegistrationType, then enforce the mode check. This catches the case where an RS
	// allows only ["prereg"] but an existing "dcr" client attempts to use it.
	var oauthClient *models.MCPOAuthClient
	if services.IsHTTPSURL(clientID) {
		// Fast-path mode check before the outbound CIMD fetch
		if !rs.AllowsRegistrationMode("cimd") {
			return nil, &policyError{
				http.StatusForbidden, "access_denied",
				"resource server does not allow cimd registration",
			}
		}
		resolved, cimdErr := ctrl.service.ResolveCIMDClient(clientID)
		if cimdErr != nil {
			return nil, &policyError{http.StatusBadRequest, "invalid_client", "failed to resolve CIMD client: " + cimdErr.Error()}
		}
		oauthClient = resolved
		// Lazily create the join row for CIMD clients (idempotent)
		if _, regErr := ctrl.service.EnsureClientRegistration(rs.ID, oauthClient.ID, rs.WorkspaceID, "cimd"); regErr != nil {
			return nil, &policyError{http.StatusInternalServerError, "server_error", "failed to register CIMD client for resource"}
		}
	} else {
		// DCR / prereg path: clientID is a UUID string
		found, lookupErr := ctrl.service.GetOAuthClient(clientID)
		if lookupErr != nil {
			return nil, &policyError{http.StatusBadRequest, "invalid_client", "unknown client_id"}
		}
		oauthClient = found
	}

	// 3. Exact registration-mode enforcement for DCR/prereg clients.
	// (CIMD was already checked with a fast-path in step 2 before the fetch.)
	if !rs.AllowsRegistrationMode(oauthClient.RegistrationType) {
		return nil, &policyError{
			http.StatusForbidden, "access_denied",
			fmt.Sprintf("resource server does not allow %s registration", oauthClient.RegistrationType),
		}
	}

	// 4. Client registration approval (join table).
	//
	// DCR clients registered without a `resource` parameter (RFC 7591 strict;
	// e.g. Claude Code) have no registration row yet. Since the RS has already
	// passed the AllowsRegistrationMode("dcr") check above, lazily create the
	// join row here — identical semantics to the CIMD lazy-registration path
	// in step 2. For prereg clients, continue to require an existing approval.
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if regErr != nil {
		if oauthClient.RegistrationType == "dcr" {
			if _, ensureErr := ctrl.service.EnsureClientRegistration(rs.ID, oauthClient.ID, rs.WorkspaceID, "dcr"); ensureErr != nil {
				return nil, &policyError{http.StatusInternalServerError, "server_error", "failed to register DCR client for resource"}
			}
		} else {
			return nil, &policyError{http.StatusForbidden, "access_denied", "client not authorized for this resource"}
		}
	} else if reg.Status != "approved" {
		return nil, &policyError{http.StatusForbidden, "access_denied", "client not authorized for this resource"}
	}

	// 5. Redirect URI resolution and validation
	resolvedRedirectURI := redirectURI
	switch len(oauthClient.RedirectURIs) {
	case 0:
		return nil, &policyError{http.StatusBadRequest, "invalid_client", "client has no registered redirect_uri"}
	case 1:
		if resolvedRedirectURI == "" {
			resolvedRedirectURI = oauthClient.RedirectURIs[0]
		} else if resolvedRedirectURI != oauthClient.RedirectURIs[0] {
			return nil, &policyError{http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client"}
		}
	default:
		if resolvedRedirectURI == "" {
			return nil, &policyError{http.StatusBadRequest, "invalid_request",
				"redirect_uri is required for clients with multiple registered redirect URIs"}
		}
		if !containsString([]string(oauthClient.RedirectURIs), resolvedRedirectURI) {
			return nil, &policyError{http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client"}
		}
	}

	// 6. Scope validation
	if len(requestedScopes) > 0 {
		if invalid := services.ValidateRequestedScopes(requestedScopes, rs, oauthClient); len(invalid) > 0 {
			return nil, &policyError{
				http.StatusBadRequest, "invalid_scope",
				"unsupported scope(s): " + strings.Join(invalid, ", "),
			}
		}
	}

	return &OAuthPolicyResult{Client: oauthClient, RS: rs, RedirectURI: resolvedRedirectURI}, nil
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

// proxyResponseSkipHeaders are headers that must NOT be copied from the upstream
// (Hydra) response to the client. The AuthSec CORS middleware owns CORS headers
// — copying Hydra's `Access-Control-Allow-Origin: *` on top of the middleware's
// per-origin value produces two header values, which browsers reject with
// "header contains multiple values". The hop-by-hop headers are scrubbed for
// correctness when proxying.
var proxyResponseSkipHeaders = map[string]struct{}{
	"Access-Control-Allow-Origin":      {},
	"Access-Control-Allow-Methods":     {},
	"Access-Control-Allow-Headers":     {},
	"Access-Control-Allow-Credentials": {},
	"Access-Control-Expose-Headers":    {},
	"Access-Control-Max-Age":           {},
	// Hop-by-hop / framing — let the response writer set these correctly.
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Content-Length":      {},
}

func writeProxiedResponse(w http.ResponseWriter, statusCode int, body []byte, respHeader http.Header) {
	for k, vv := range respHeader {
		if _, skip := proxyResponseSkipHeaders[http.CanonicalHeaderKey(k)]; skip {
			continue
		}
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
	workspaceID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
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

	grants, err := ctrl.consentService.ListByTenant(workspaceID, userID, clientID, rsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list consent grants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"consent_grants": grants})
}

// RevokeConsentGrant revokes a consent grant (admin).
// DELETE /authsec/consent-grants/:id
func (ctrl *OAuthASController) RevokeConsentGrant(c *gin.Context) {
	workspaceID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	grantIDStr := c.Param("id")
	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid grant ID"})
		return
	}

	// RevokeConsentByTenant enforces tenant ownership — cross-tenant revocations are rejected.
	if err := ctrl.consentService.RevokeConsentByTenant(grantID, workspaceID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "consent grant not found or already revoked"})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "consent_grant_revoked", "oauth_consent_grant",
		grantIDStr, http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ListUserConsentGrants lists consent grants for the authenticated user.
// GET /oauth/consent-grants (user self-service)
func (ctrl *OAuthASController) ListUserConsentGrants(c *gin.Context) {
	workspaceID, userID, err := ctrl.requireAuthenticatedUserContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	grants, err := ctrl.consentService.ListByUser(workspaceID, userID)
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
	workspaceID, err := extractTenantID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("workspace_id required in JWT")
	}

	userIDStr, err := middlewares.ResolveUserID(c)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("user_id required in JWT")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid user_id in JWT")
	}

	return workspaceID, userID, nil
}
