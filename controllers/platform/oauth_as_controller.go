package platform

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/policy"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// OAuthASController handles global OAuth Authorization Server endpoints.
// All endpoints are global (not per-RS). RS context is carried by the `resource` parameter.
type OAuthASController struct {
	service        *services.OAuthASService
	rsService      *services.ResourceServerService
	scopeResolver  *services.ScopeResolver
	consentService *services.ConsentService
	nativeIssuer   *tokens.NativeIssuer
	xaaService     *services.XAAService
	cibaService    *services.TenantCIBAAuthService // nil when XAA_CIBA=off
	pdp            policy.PDP                      // nil when POLICY_ENGINE_MODE=off
}

func NewOAuthASController() *OAuthASController {
	issuerURL := ""
	if config.AppConfig != nil {
		issuerURL = config.AppConfig.OAuthBaseURL()
	}
	ctrl := &OAuthASController{
		service:        services.NewOAuthASService(config.DB),
		rsService:      services.NewResourceServerService(config.DB),
		scopeResolver:  services.NewScopeResolver(config.DB),
		consentService: services.NewConsentService(config.DB),
		nativeIssuer:   tokens.NewNativeIssuer(config.DB, tokens.NativeKeys(), issuerURL),
		xaaService:     services.NewXAAService(config.DB),
	}
	if config.AppConfig != nil && config.DB != nil {
		mode := config.AppConfig.PolicyEngineMode
		if mode == "shadow" || mode == "enforce" {
			ctrl.pdp = policy.NewSimplePDP(config.DB)
		}
	}
	// Wire the workspace-plane CIBA service only when native RS-bearer CIBA is
	// enabled — it backs the standards POST /oauth/bc-authorize + ciba grant.
	if config.AppConfig != nil && config.AppConfig.XAACiba {
		pushService, perr := services.NewPushNotificationService()
		if perr != nil {
			pushService = nil // service degrades gracefully without push
		}
		ctrl.cibaService = services.NewTenantCIBAAuthService(pushService)
	}
	return ctrl
}

// evalPDP consults the PDP and, in shadow mode, writes an audit record.
// Returns true (block) only in enforce mode when the PDP says EffectDeny.
// gatePermit must always be true at call-site (thin gates have already passed).
func (ctrl *OAuthASController) evalPDP(ctx context.Context, req policy.PolicyRequest, grantedScopes string) (block bool) {
	if ctrl.pdp == nil {
		return false
	}
	mode := "shadow"
	if config.AppConfig != nil {
		mode = config.AppConfig.PolicyEngineMode
	}

	decision, _ := ctrl.pdp.Decide(ctx, req)

	// thin gates passed → gateEffect is always permit at this point
	pdpAgrees := decision.Effect != policy.EffectDeny
	sid := req.SubjectID
	policy.RecordAudit(ctx, config.DB, policy.IssuanceAuditRow{
		WorkspaceID:      req.WorkspaceID,
		TokenFamily:      req.TokenFamily,
		ClientID:         req.ClientID,
		SubjectType:      req.SubjectType,
		SubjectID:        &sid,
		ResourceServerID: req.ResourceServerID,
		PDPEffect:        string(decision.Effect),
		GateEffect:       "permit",
		PDPAgrees:        pdpAgrees,
		ScopesRequested:  req.RequestedScopes,
		ScopesGranted:    grantedScopes,
		PDPReason:        decision.Reason,
	})

	if mode == "enforce" && decision.Effect == policy.EffectDeny {
		return true
	}
	return false
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
		WorkspaceID:      rs.WorkspaceID.String(),
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

	grantType := c.PostForm("grant_type")

	// Resolve client_id: body first, then Basic auth header. client_credentials
	// callers use Basic auth and may omit client_id from the body.
	clientID := c.PostForm("client_id")
	if clientID == "" {
		clientID = services.ExtractClientIDFromBasicAuth(c.Request)
	}
	// For private_key_jwt the client_id is embedded in the assertion; we defer
	// extraction to authenticateClient in the M2M handler.
	assertionType := c.PostForm("client_assertion_type")
	if clientID == "" && assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// For client_credentials with private_key_jwt the client lookup happens
	// inside the handler (client_id must be extracted from the assertion).
	// For all other grants we look up the client now.
	var oauthClient *models.MCPOAuthClient
	if clientID != "" {
		var err error
		oauthClient, err = ctrl.service.GetOAuthClient(clientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "unknown client_id",
			})
			return
		}
	}

	// authorization_code and refresh_token consume the pre-resolved oauthClient
	// directly; only the confidential machine grants defer client resolution to
	// their own AuthenticateClient call. When client_id was omitted (legal only
	// for private_key_jwt), oauthClient is nil — reject those grants here rather
	// than dereferencing nil downstream (panic / DoS).
	if oauthClient == nil {
		switch grantType {
		case "client_credentials",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:openid:params:grant-type:ciba":
			// these authenticate the client themselves
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "client_id is required for this grant type",
			})
			return
		}
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
	case "client_credentials":
		ctrl.tokenClientCredentialsGrant(c, oauthClient)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		ctrl.tokenJWTBearerGrant(c, oauthClient)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		ctrl.tokenExchangeGrant(c, oauthClient)
	case "urn:openid:params:grant-type:ciba":
		ctrl.tokenCIBAGrant(c, oauthClient)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "only authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:jwt-bearer, urn:ietf:params:oauth:grant-type:token-exchange, and urn:openid:params:grant-type:ciba are supported",
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

	// Stamp last_token_issued_at on the client row (best-effort; don't block on failure).
	now := time.Now()
	if dbErr := config.DB.Model(&models.MCPOAuthClient{}).
		Where("id = ?", oauthClient.ID).
		Update("last_token_issued_at", now).Error; dbErr != nil {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: failed to stamp last_token_issued_at for client=%s: %v", oauthClient.ClientID, dbErr)
	}

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

// tokenClientCredentialsGrant handles client_credentials token exchange for
// confidential service-account clients via the NativeSealer (M2M path).
// Requires XAA_M2M feature flag; the Hydra proxy is gone — native issuance only.
func (ctrl *OAuthASController) tokenClientCredentialsGrant(c *gin.Context, _ *models.MCPOAuthClient) {
	if config.AppConfig == nil || !config.AppConfig.XAAm2m {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "client_credentials is not enabled on this authorization server",
		})
		return
	}

	ctx := c.Request.Context()
	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"

	// ── 1. Authenticate the client (private_key_jwt or client_secret_basic).
	client, err := services.AuthenticateClient(ctx, config.DB, c.Request, tokenEndpoint)
	if err != nil {
		log.Printf("[M2M] tokenClientCredentialsGrant: auth failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}

	// ── 2. Resolve the linked service account (must exist and be active).
	sa, err := ctrl.service.GetServiceAccountByClientID(ctx, client.ID)
	if err != nil {
		log.Printf("[M2M] tokenClientCredentialsGrant: SA lookup failed client=%s: %v", client.ClientID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if sa == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "no service account linked to this client",
		})
		return
	}
	if sa.Status != "active" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "service account is not active",
		})
		return
	}

	// ── 3. Resolve the resource server.
	resourceParam := c.PostForm("resource")
	if resourceParam == "" {
		inferred, iErr := ctrl.service.InferSingleResourceURIForClient(client)
		if iErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_target",
				"error_description": "resource parameter required",
			})
			return
		}
		resourceParam = inferred
	}
	rs, err := ctrl.rsService.GetByResourceURI(resourceParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_target",
			"error_description": "unknown resource",
		})
		return
	}
	// ── 4. Registration gate — client must be approved for this RS.
	reg, regErr := ctrl.service.GetClientRegistration(rs.ID, client.ID)
	if regErr != nil || reg.Status != "approved" {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "client not authorized for this resource server",
		})
		return
	}

	// ── 5. Resolve scopes via RBAC (SA principal).
	requestedScopes := strings.Fields(c.PostForm("scope"))
	principal := tokens.Principal{
		SubjectType: tokens.SubjectTypeServiceAccount,
		SubjectID:   sa.ID,
		WorkspaceID: sa.WorkspaceID,
	}
	grantedScopes, err := ctrl.scopeResolver.ResolvePrincipalEffectiveScopes(
		ctx, principal, rs.ID.String(), requestedScopes, rs, client,
	)
	if err != nil {
		log.Printf("[M2M] tokenClientCredentialsGrant: scope resolution failed sa=%s: %v", sa.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if len(grantedScopes) == 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "no scopes granted to this service account for the requested resource",
		})
		return
	}

	// ── 6. PDP gate (shadow/enforce).
	if ctrl.evalPDP(ctx, policy.PolicyRequest{
		WorkspaceID:      sa.WorkspaceID,
		ClientID:         client.ClientID,
		SubjectType:      "service_account",
		SubjectID:        sa.ID,
		ResourceServerID: rs.ID,
		TokenFamily:      "m2m",
		RequestedScopes:  strings.Join(requestedScopes, " "),
	}, strings.Join(grantedScopes, " ")) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "policy denied this request",
		})
		return
	}

	// ── 7. Mint a native M2M token.
	claims := tokens.NativeClaims{
		Family:           models.TokenFamilyM2M,
		WorkspaceID:      sa.WorkspaceID,
		SubjectType:      tokens.SubjectTypeServiceAccount,
		SubjectID:        sa.ID,
		ClientID:         client.ClientID,
		ResourceServerID: rs.ID,
		Audience:         rs.ResourceURI,
		Scope:            strings.Join(grantedScopes, " "),
		TTL:              time.Hour,
	}
	tokenStr, jti, err := ctrl.nativeIssuer.Issue(ctx, claims)
	if err != nil {
		log.Printf("[M2M] tokenClientCredentialsGrant: issue failed sa=%s: %v", sa.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	log.Printf("[M2M] tokenClientCredentialsGrant: issued jti=%s sa=%s client=%s rs=%s scopes=%q",
		jti, sa.ID, client.ClientID, rs.ID, claims.Scope)

	// Best-effort: advance attested → token_issued in application_spiffe_identities
	// for SPIFFE-backed service accounts.
	if sa.SpiffeID != nil {
		config.DB.WithContext(ctx).Exec(
			`UPDATE application_spiffe_identities
			    SET status = 'token_issued', last_token_issued_at = NOW()
			  WHERE spiffe_id = ? AND status IN ('attested', 'token_issued')`,
			*sa.SpiffeID,
		)
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": tokenStr,
		"token_type":   "Bearer",
		"expires_in":   int(time.Hour.Seconds()),
		"scope":        claims.Scope,
	})
}

// tokenJWTBearerGrant handles the XAA redemption grant
// (urn:ietf:params:oauth:grant-type:jwt-bearer): validates an ID-JAG assertion,
// maps the external subject to a local user, and mints a native XAA token.
//
// Requires XAA_REDEMPTION flag. Does NOT call BindClientToRS — uses read-only
// CheckClientApprovedForRS; side-effects (access_requests pending row) are
// recorded when approval is missing.
func (ctrl *OAuthASController) tokenJWTBearerGrant(c *gin.Context, _ *models.MCPOAuthClient) {
	if config.AppConfig == nil || !config.AppConfig.XAARedemption {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "jwt-bearer is not enabled on this authorization server",
		})
		return
	}

	ctx := c.Request.Context()
	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"
	selfIssuer := config.AppConfig.OAuthBaseURL()

	// ── 1. Authenticate the requesting agent client.
	agentClient, err := services.AuthenticateClient(ctx, config.DB, c.Request, tokenEndpoint)
	if err != nil {
		log.Printf("[XAA] tokenJWTBearerGrant: client auth failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}

	// ── 2. Check for DPoP — reject if present but XAA_DPOP is off (§plan).
	if c.GetHeader("DPoP") != "" && (config.AppConfig == nil || !config.AppConfig.XAADPOP) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "DPoP is not enabled on this server",
		})
		return
	}

	// ── 3. Validate the ID-JAG assertion.
	assertion := c.PostForm("assertion")
	if assertion == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "assertion parameter required",
		})
		return
	}
	idjagClaims, trustedIssuer, err := ctrl.xaaService.ValidateIDJAG(ctx, assertion, agentClient.ClientID, selfIssuer)
	if err != nil {
		log.Printf("[XAA] tokenJWTBearerGrant: ID-JAG validation failed client=%s: %v", agentClient.ClientID, err)
		errCode := "invalid_grant"
		if err == services.ErrUntrustedIssuer {
			errCode = "invalid_grant"
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errCode,
			"error_description": err.Error(),
		})
		return
	}

	// ── 4. Resolve target resource server.
	resourceParam := c.PostForm("resource")
	if resourceParam == "" {
		inferred, iErr := ctrl.service.InferSingleResourceURIForClient(agentClient)
		if iErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_target",
				"error_description": "resource parameter required",
			})
			return
		}
		resourceParam = inferred
	}
	rs, err := ctrl.rsService.GetByResourceURI(resourceParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_target",
			"error_description": "unknown resource",
		})
		return
	}
	if idjagClaims.Resource != "" && idjagClaims.Resource != resourceParam {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "ID-JAG resource does not match requested resource",
		})
		return
	}

	// ── 5. Conformant XAA boundary (ID-JAG draft §4.1 / §7.3): the trust boundary
	// is the resource server (audience), NOT the workspace. An agent in the SAME
	// workspace as the MCP server is still a distinct application and may use XAA —
	// this is the canonical single-org Okta case (one IdP, many apps). §7.3 ("the
	// IdP must not mint a token from an ID-JAG to reach its own resources") is
	// already enforced above: the target must resolve to a registered
	// resource_servers row, and AuthSec's own admin API is not one. The only thing
	// left to forbid is literal self-delegation: a resource server's own client
	// redeeming an ID-JAG to reach itself (no delegation actually occurs).
	// issuance_workspace remains on the ID-JAG as audit/provenance only.
	if rs.LegacyClientID != nil && *rs.LegacyClientID == agentClient.ID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "self_delegation: a client cannot use an ID-JAG to reach its own resource server",
		})
		return
	}

	// ── 6. mapSubject FIRST: resolve / JIT-provision the local user before any
	// access_request is written, so every pending row carries the real subject.
	// (Journey B: "login worked" precedes the approval/RBAC gates; writing a
	// uuid.Nil placeholder here would collapse distinct users into one pending
	// row under the (ws,rs,subject_type,subject_id,client) partial-unique index,
	// destroying provenance and letting one user's approval satisfy another's.)
	localUserID, err := ctrl.xaaService.MapSubject(ctx, idjagClaims.Subject, trustedIssuer, rs.WorkspaceID)
	if err != nil {
		log.Printf("[XAA] tokenJWTBearerGrant: mapSubject failed sub=%s ws=%s: %v", idjagClaims.Subject, rs.WorkspaceID, err)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": err.Error(),
		})
		return
	}

	// ── 7. Read-only brokering gate: client must be approved for this RS.
	approved, err := ctrl.service.CheckClientApprovedForRS(ctx, agentClient.ID, rs.ID)
	if err != nil {
		log.Printf("[XAA] tokenJWTBearerGrant: approval check error client=%s: %v", agentClient.ClientID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	// RFC 9396 authorization_details (raw RAR JSON), preserved on the access
	// request so the admin approves with the full structured payload, not just
	// a scope string (finding #2). Empty when the request carries no RAR.
	authzDetails := c.PostForm("authorization_details")
	if !approved {
		// Upsert a pending access_request keyed to the REAL subject so the admin
		// queue shows who is waiting and approvals don't bleed across users.
		scopes := strings.Join(strings.Fields(c.PostForm("scope")), " ")
		reqID, _ := ctrl.service.UpsertAccessRequest(
			ctx, rs.WorkspaceID, rs.ID,
			"user", localUserID,
			agentClient.ClientID, scopes,
			authzDetails, nil,
		)
		log.Printf("[XAA] tokenJWTBearerGrant: client not approved, access_request=%s user=%s", reqID, localUserID)
		ctrl.service.NotifyAdminsOfPendingAccessRequest(
			rs.WorkspaceID, rs.ID, reqID,
			agentClient.ClientID, scopes,
			time.Now().UTC().Add(7*24*time.Hour), false,
		)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "access_pending",
			"request_id":        reqID.String(),
			"status_url":        selfIssuer + "/oauth/access-requests/" + reqID.String(),
		})
		return
	}

	// ── 8. Resolve scopes via RBAC (user principal acting via agent).
	requestedScopes := strings.Fields(c.PostForm("scope"))
	if len(requestedScopes) == 0 && idjagClaims.Scope != "" {
		requestedScopes = strings.Fields(idjagClaims.Scope)
	}
	if !scopesWithin(strings.Join(requestedScopes, " "), idjagClaims.Scope) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_scope",
			"error_description": "requested scope exceeds ID-JAG scope",
		})
		return
	}
	principal := tokens.Principal{
		SubjectType: tokens.SubjectTypeUser,
		SubjectID:   localUserID,
		WorkspaceID: rs.WorkspaceID,
	}
	grantedScopes, err := ctrl.scopeResolver.ResolvePrincipalEffectiveScopes(
		ctx, principal, rs.ID.String(), requestedScopes, rs, agentClient,
	)
	if err != nil {
		log.Printf("[XAA] tokenJWTBearerGrant: scope resolution failed user=%s: %v", localUserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if len(grantedScopes) == 0 {
		// RBAC resolved to zero scopes — upsert access_request with known subject.
		scopeStr := strings.Join(requestedScopes, " ")
		reqID, _ := ctrl.service.UpsertAccessRequest(
			ctx, rs.WorkspaceID, rs.ID,
			"user", localUserID,
			agentClient.ClientID, scopeStr,
			authzDetails, nil,
		)
		ctrl.service.NotifyAdminsOfPendingAccessRequest(
			rs.WorkspaceID, rs.ID, reqID,
			agentClient.ClientID, scopeStr,
			time.Now().UTC().Add(7*24*time.Hour), false,
		)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "access_pending",
			"request_id":        reqID.String(),
			"status_url":        selfIssuer + "/oauth/access-requests/" + reqID.String(),
		})
		return
	}

	// ── 9. PDP gate (shadow/enforce).
	if ctrl.evalPDP(ctx, policy.PolicyRequest{
		WorkspaceID:      rs.WorkspaceID,
		ClientID:         agentClient.ClientID,
		SubjectType:      "user",
		SubjectID:        localUserID,
		ResourceServerID: rs.ID,
		TokenFamily:      "xaa",
		RequestedScopes:  strings.Join(requestedScopes, " "),
	}, strings.Join(grantedScopes, " ")) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "policy denied this request",
		})
		return
	}

	// ── 10. Mint a native XAA token; replay guard is atomic in the issuance tx.
	actClientID := agentClient.ClientID
	nativeClaims := tokens.NativeClaims{
		Family:           models.TokenFamilyXAA,
		WorkspaceID:      rs.WorkspaceID,
		SubjectType:      tokens.SubjectTypeUser,
		SubjectID:        localUserID,
		ClientID:         agentClient.ClientID,
		ActorClientID:    &actClientID,
		ResourceServerID: rs.ID,
		Audience:         rs.ResourceURI,
		Scope:            strings.Join(grantedScopes, " "),
		SourceGrantJTI:   &idjagClaims.JTI,
		SourceGrantIss:   &idjagClaims.Issuer,
		TTL:              time.Hour,
	}
	replayHook := services.IDJAGReplayInsert(config.DB, idjagClaims.Issuer, idjagClaims.JTI, idjagClaims.ExpiresAt)
	tokenStr, jti, err := ctrl.nativeIssuer.Issue(ctx, nativeClaims, replayHook)
	if err != nil {
		if err == services.ErrIDJAGReplayed {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": services.ErrIDJAGReplayed.Error(),
			})
			return
		}
		log.Printf("[XAA] tokenJWTBearerGrant: issue failed user=%s: %v", localUserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	log.Printf("[XAA] tokenJWTBearerGrant: issued jti=%s user=%s client=%s rs=%s scopes=%q",
		jti, localUserID, agentClient.ClientID, rs.ID, nativeClaims.Scope)

	c.JSON(http.StatusOK, gin.H{
		"access_token": tokenStr,
		"token_type":   "Bearer",
		"expires_in":   int(time.Hour.Seconds()),
		"scope":        nativeClaims.Scope,
	})
}

type oauthJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// verifySelfIssuedIDToken validates an OIDC id_token issued by this AuthSec AS
// and intended for the authenticated OAuth client. This is the standards path
// for token-exchange subject_token_type=id_token; ID tokens are JWT assertions,
// not Hydra-introspectable access tokens.
func (ctrl *OAuthASController) verifySelfIssuedIDToken(raw string, expectedClientID string) (jwt.MapClaims, error) {
	if config.AppConfig == nil {
		return nil, fmt.Errorf("server configuration unavailable")
	}
	selfIssuer := config.AppConfig.OAuthBaseURL()
	jwks, err := ctrl.service.FetchJWKS()
	if err != nil {
		return nil, fmt.Errorf("id_token JWKS unavailable")
	}
	keys, err := parseRSAJWKS(jwks)
	if err != nil {
		return nil, fmt.Errorf("id_token JWKS invalid: %w", err)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected id_token alg %s", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("id_token missing kid")
		}
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("id_token kid %q not found in issuer JWKS", kid)
		}
		return key, nil
	})
	if err != nil || !parsed.Valid {
		if err == nil {
			err = fmt.Errorf("id_token invalid")
		}
		return nil, fmt.Errorf("id_token signature/claims invalid: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != selfIssuer {
		return nil, fmt.Errorf("id_token issuer mismatch")
	}
	if !claimHasAudience(claims["aud"], expectedClientID) {
		return nil, fmt.Errorf("id_token audience does not include authenticated client")
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, fmt.Errorf("id_token missing sub")
	}
	if ws, _ := claims["workspace_id"].(string); ws == "" {
		return nil, fmt.Errorf("id_token missing workspace_id")
	}
	return claims, nil
}

func parseRSAJWKS(raw json.RawMessage) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []oauthJWK `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, jwk := range doc.Keys {
		if jwk.Kid == "" || jwk.Kty != "RSA" || jwk.N == "" || jwk.E == "" {
			continue
		}
		nBytes, nErr := base64.RawURLEncoding.DecodeString(jwk.N)
		eBytes, eErr := base64.RawURLEncoding.DecodeString(jwk.E)
		if nErr != nil || eErr != nil || len(eBytes) == 0 {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e == 0 {
			continue
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no RSA signing keys")
	}
	return keys, nil
}

func claimHasAudience(aud interface{}, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, item := range v {
			if s, _ := item.(string); s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func scopesWithin(requested, allowed string) bool {
	requestedFields := strings.Fields(requested)
	if len(requestedFields) == 0 || strings.TrimSpace(allowed) == "" {
		return true
	}
	allowedSet := make(map[string]struct{}, len(strings.Fields(allowed)))
	for _, s := range strings.Fields(allowed) {
		allowedSet[s] = struct{}{}
	}
	for _, s := range requestedFields {
		if _, ok := allowedSet[s]; !ok {
			return false
		}
	}
	return true
}

// tokenExchangeGrant handles RFC 8693 token exchange for ID-JAG issuance
// (draft-ietf-oauth-identity-assertion-authz-grant-04).
//
// Flow:
//  1. XAAIssuance flag guard.
//  2. requested_token_type must be urn:ietf:params:oauth:token-type:id-jag.
//  3. subject_token verified → extract (sub=user, workspace_id, issuing client_id).
//  4. Client binding: issuing client_id must match the authenticated client.
//  5. Issuance brokering gate (a2a_brokering_policies side='issuance').
//  6. Mint ID-JAG via NativeIssuer.IssueIDJAG — NOT stored in native_tokens.
//  7. RFC 8693 response: issued_token_type, access_token, token_type:"N_A", expires_in.
func (ctrl *OAuthASController) tokenExchangeGrant(c *gin.Context, oauthClient *models.MCPOAuthClient) {
	ctx := c.Request.Context()

	// ── 1. Flag guard.
	if config.AppConfig == nil || !config.AppConfig.XAAIssuance {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "token-exchange (ID-JAG issuance) is not enabled",
		})
		return
	}

	// ── 2. requested_token_type check.
	requestedType := c.PostForm("requested_token_type")
	if requestedType != tokens.IDJAGTokenType {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "requested_token_type must be " + tokens.IDJAGTokenType,
		})
		return
	}

	// ── 3. Verify subject_token — extracts (sub, workspace_id, client_id).
	subjectToken := c.PostForm("subject_token")
	if subjectToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "subject_token parameter required",
		})
		return
	}

	type subjectCtx struct {
		UserID      uuid.UUID
		WorkspaceID uuid.UUID
		ClientID    string
	}

	var subject subjectCtx
	subjectTokenType := c.PostForm("subject_token_type")
	if subjectTokenType == "urn:ietf:params:oauth:token-type:id_token" {
		// OIDC ID tokens are identity assertions, not introspectable access
		// tokens. Validate the JWT against this issuer's JWKS and extract the
		// MCP consent session claims needed to mint the native ID-JAG.
		claims, verr := ctrl.verifySelfIssuedIDToken(subjectToken, oauthClient.ClientID)
		if verr != nil {
			log.Printf("[ISSUANCE] tokenExchangeGrant: id_token validation failed client=%s: %v", oauthClient.ClientID, verr)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": verr.Error(),
			})
			return
		}
		subStr, _ := claims["sub"].(string)
		wsStr, _ := claims["workspace_id"].(string)
		clientIDStr, _ := claims["client_id"].(string)
		if clientIDStr == "" {
			// Hydra's id_token uses aud as the OAuth client binding. The verifier
			// already checked aud contains oauthClient.ClientID.
			clientIDStr = oauthClient.ClientID
		}
		subjectUserID, uerr := uuid.Parse(subStr)
		workspaceID, werr := uuid.Parse(wsStr)
		if uerr != nil || werr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "id_token missing sub or workspace_id",
			})
			return
		}
		subject = subjectCtx{
			UserID:      subjectUserID,
			WorkspaceID: workspaceID,
			ClientID:    clientIDStr,
		}
	} else if cls := tokens.Classify(subjectToken, tokens.NativeKeys().NativeKeyIDs()); cls.Family == tokens.FamilyNative {
		// Native token path: verify signature, look up native_tokens row.
		pub, ok := tokens.NativeKeys().PublicKeyForKID(cls.Kid)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token has unknown native kid",
			})
			return
		}
		nativeClaims := jwt.MapClaims{}
		parsed, perr := jwt.ParseWithClaims(subjectToken, nativeClaims, func(t *jwt.Token) (interface{}, error) {
			if _, isRSA := t.Method.(*jwt.SigningMethodRSA); !isRSA {
				return nil, fmt.Errorf("unexpected alg %s", t.Method.Alg())
			}
			return pub, nil
		})
		if perr != nil || !parsed.Valid {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token signature/claims invalid",
			})
			return
		}
		jti, _ := nativeClaims["jti"].(string)
		row, lerr := tokens.LookupNativeToken(ctx, config.DB, jti)
		if lerr != nil || row == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token not found or already revoked",
			})
			return
		}
		// Check revocation.
		issuerURL := config.AppConfig.OAuthBaseURL()
		if rev, _ := tokens.IsRevoked(ctx, config.DB, issuerURL, "access_token", jti); rev {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token has been revoked",
			})
			return
		}
		if row.SubjectType != "user" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token must carry a user subject for ID-JAG issuance",
			})
			return
		}
		subject = subjectCtx{
			UserID:      row.SubjectID,
			WorkspaceID: row.WorkspaceID,
			ClientID:    row.ClientID,
		}
	} else {
		// Hydra token path: use admin introspect.
		tokenInfo, ierr := ctrl.service.IntrospectViaHydraAdmin(subjectToken)
		if ierr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token introspection failed",
			})
			return
		}
		active, _ := tokenInfo["active"].(bool)
		if !active {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token is not active",
			})
			return
		}
		subStr, _ := tokenInfo["sub"].(string)
		clientIDStr, _ := tokenInfo["client_id"].(string)
		// Hydra nests custom session claims under "ext"; workspace_id is a
		// consent-time session claim, not a top-level introspection field.
		wsStr := ""
		if ext, ok := tokenInfo["ext"].(map[string]interface{}); ok {
			wsStr, _ = ext["workspace_id"].(string)
		}
		subjectUserID, uerr := uuid.Parse(subStr)
		workspaceID, werr := uuid.Parse(wsStr)
		if uerr != nil || werr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_grant",
				"error_description": "subject_token missing sub or workspace_id",
			})
			return
		}
		subject = subjectCtx{
			UserID:      subjectUserID,
			WorkspaceID: workspaceID,
			ClientID:    clientIDStr,
		}
	}

	// ── 4. Client binding: the authenticated client must match the subject_token's client.
	if subject.ClientID != oauthClient.ClientID {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "authenticated client does not match subject_token client",
		})
		return
	}

	// ── 5. Issuance brokering gate (a2a_brokering_policies side='issuance').
	// Explicit-deny-wins: any deny row for (workspace, client) blocks issuance.
	// No matching row = permit (ownership of a valid subject_token is sufficient consent).
	type brokeringRow struct{ Effect string }
	var brokeringRows []brokeringRow
	config.DB.WithContext(ctx).Raw(`
		SELECT effect FROM a2a_brokering_policies
		WHERE workspace_id = ? AND side = 'issuance'
		  AND (client_id IS NULL OR client_id = ?)`,
		subject.WorkspaceID, oauthClient.ClientID,
	).Scan(&brokeringRows)
	for _, br := range brokeringRows {
		if br.Effect == "deny" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "access_denied",
				"error_description": "ID-JAG issuance is not permitted for this client in this workspace",
			})
			return
		}
	}

	// ── 6. Determine target issuer (audience for the ID-JAG).
	// Default to this AS's own issuer (cross-workspace same-AS scenario).
	targetIssuer := c.PostForm("audience")
	selfIssuer := config.AppConfig.OAuthBaseURL()
	if targetIssuer == "" {
		targetIssuer = selfIssuer
	}
	resource := c.PostForm("resource")
	scope := strings.Join(strings.Fields(c.PostForm("scope")), " ")

	// ── 7. Mint ID-JAG — NOT stored in native_tokens.
	// The issuance_workspace is the CLIENT's home workspace — the workspace
	// that registered/owns the agent client. This is NOT the user's workspace
	// or the RS workspace. The §19 same-domain check compares
	// issuance_workspace vs the target RS workspace; if the client and RS
	// live in the same workspace, XAA is unnecessary (use direct M2M).
	issuanceWorkspace := subject.WorkspaceID
	if oauthClient.HomeWorkspaceID != nil {
		issuanceWorkspace = *oauthClient.HomeWorkspaceID
	}
	idjagClaims := tokens.IDJAGClaims{
		WorkspaceID:  issuanceWorkspace,
		SubjectID:    subject.UserID,
		ClientID:     oauthClient.ClientID,
		TargetIssuer: targetIssuer,
		Resource:     resource,
		Scope:        scope,
	}
	tokenStr, jti, err := ctrl.nativeIssuer.IssueIDJAG(ctx, idjagClaims)
	if err != nil {
		log.Printf("[ISSUANCE] tokenExchangeGrant: IssueIDJAG failed user=%s: %v", subject.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	log.Printf("[ISSUANCE] tokenExchangeGrant: issued id-jag jti=%s user=%s client=%s ws=%s",
		jti, subject.UserID, oauthClient.ClientID, subject.WorkspaceID)

	resp := gin.H{
		"issued_token_type": tokens.IDJAGTokenType,
		"access_token":      tokenStr,
		"token_type":        "N_A",
		"expires_in":        int(tokens.IDJAGTLL.Seconds()),
	}
	if scope != "" {
		resp["scope"] = scope
	}
	c.JSON(http.StatusOK, resp)
}

// BackchannelAuthorize is the OIDC CIBA backchannel authorization endpoint
// (POST /oauth/bc-authorize). Unlike the legacy workspace-plane /ciba/initiate
// (which takes client_id in the body), this standards endpoint resolves the
// client from client authentication, so SDK callers never hand-craft a
// client_id. It maps onto the workspace-plane InitiateTenantCIBAAuth and
// returns the standard CIBA response (auth_req_id, expires_in, interval).
//
// Gated on XAA_CIBA. Delivery mode is poll-only (matches AS metadata).
func (ctrl *OAuthASController) BackchannelAuthorize(c *gin.Context) {
	if config.AppConfig == nil || !config.AppConfig.XAACiba || ctrl.cibaService == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "CIBA is not enabled on this authorization server",
		})
		return
	}

	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}
	ctx := c.Request.Context()
	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"

	// Resolve + authenticate the client from credentials (not a body field).
	client, err := services.AuthenticateClient(ctx, config.DB, c.Request, tokenEndpoint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}

	// login_hint carries the user identifier (email) per OIDC CIBA.
	loginHint := strings.TrimSpace(c.PostForm("login_hint"))
	if loginHint == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "login_hint is required",
		})
		return
	}

	resp, err := ctrl.cibaService.InitiateTenantCIBAAuth(&models.TenantCIBAInitiateRequest{
		ClientID:       client.ClientID,
		Email:          loginHint,
		BindingMessage: c.PostForm("binding_message"),
		Scopes:         strings.Fields(c.PostForm("scope")),
		Resource:       c.PostForm("resource"),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if resp.Error != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             resp.Error,
			"error_description": resp.ErrorDescription,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"auth_req_id": resp.AuthReqID,
		"expires_in":  resp.ExpiresIn,
		"interval":    resp.Interval,
	})
}

// tokenCIBAGrant handles the CIBA token poll on /oauth/token
// (grant_type=urn:openid:params:grant-type:ciba). The client authenticates and
// polls with auth_req_id; the handler maps onto the workspace-plane poll and
// returns either a native RS-bearer token (tf=ciba when XAA_CIBA on) or the
// standard CIBA pending/terminal error (authorization_pending, access_denied,
// expired_token).
func (ctrl *OAuthASController) tokenCIBAGrant(c *gin.Context, oauthClient *models.MCPOAuthClient) {
	if config.AppConfig == nil || !config.AppConfig.XAACiba || ctrl.cibaService == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "CIBA is not enabled on this authorization server",
		})
		return
	}
	ctx := c.Request.Context()
	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"

	// Authenticate the polling client confidentially.
	client, err := services.AuthenticateClient(ctx, config.DB, c.Request, tokenEndpoint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}

	authReqID := strings.TrimSpace(c.PostForm("auth_req_id"))
	if authReqID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "auth_req_id is required",
		})
		return
	}

	resp, err := ctrl.cibaService.PollTenantCIBAToken(&models.TenantCIBATokenRequest{
		AuthReqID: authReqID,
		ClientID:  client.ClientID,
		Resource:  c.PostForm("resource"),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if resp.Error != "" {
		// authorization_pending / slow_down are 400 per RFC; map terminal ones too.
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             resp.Error,
			"error_description": resp.ErrorDescription,
		})
		return
	}

	out := gin.H{
		"access_token": resp.AccessToken,
		"token_type":   resp.TokenType,
		"expires_in":   resp.ExpiresIn,
	}
	if resp.Scope != "" {
		out["scope"] = resp.Scope
	}
	c.JSON(http.StatusOK, out)
}

// RequesterBootstrapTarget is one RS entry in the bootstrap bundle (Appendix §4).
type RequesterBootstrapTarget struct {
	ResourceServerID   string                 `json:"resource_server_id"`
	Resource           string                 `json:"resource"`
	WorkspaceID        string                 `json:"workspace_id"`
	Relationship       string                 `json:"relationship"`        // "same_workspace" | "cross_workspace"
	RecommendedFlow    string                 `json:"recommended_flow"`    // "direct" | "id_jag"
	RegistrationStatus string                 `json:"registration_status"` // "approved" | "pending_approval" | "revoked" | "none"
	AccessStatus       string                 `json:"access_status"`       // "granted" | "pending" | "denied" | "none"
	ScopesSupported    []string               `json:"scopes_supported"`
	PRM                map[string]interface{} `json:"prm"`
}

// RequesterBootstrapPending is one open access request in the bundle.
type RequesterBootstrapPending struct {
	RequestID        string `json:"request_id"`
	ResourceServerID string `json:"resource_server_id"`
	Status           string `json:"status"`
	ExpiresAt        string `json:"expires_at,omitempty"`
}

// RequesterBootstrap returns the launch bundle for a client-authenticated
// requester SDK (Appendix §4). The client authenticates itself (same as
// /oauth/token client_credentials) and receives:
//   - one target per RS it is registered for, PLUS first-contact targets for any
//     `resource` it names that it isn't yet registered for (so an unbound client
//     learns where to request access);
//   - recommended_flow: a CLIENT-LEVEL recommendation derived from the client's
//     resolved workspace context (service-account workspace ∪ approved-registration
//     workspaces) vs the RS workspace — NOT the mutable home_workspace_id. Caveat:
//     bootstrap is client-authenticated and does not know which human user will
//     later arrive on the ID-JAG/browser path, so for XAA this is a hint, not a
//     per-user determination. The §19 same-domain check at redemption is the
//     authoritative backstop if the recommendation and the acting user disagree;
//   - per-target access_status, a top-level pending[] of open access requests,
//     and a content-hashed metadata_version for drift detection.
//
// GET and POST. POST is preferred for private_key_jwt (assertion in body). On GET
// a client_assertion in the query string is REJECTED (query-string JWTs leak),
// so GET is for header-credential auth (client_secret_basic) only.
func (ctrl *OAuthASController) RequesterBootstrap(c *gin.Context) {
	ctx := c.Request.Context()

	if config.AppConfig == nil || !config.AppConfig.XAAIssuance {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	if c.Request.Method == http.MethodGet && c.Request.URL.Query().Get("client_assertion") != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_assertion must not be sent in the query string; use POST (assertion in body) or client_secret_basic",
		})
		return
	}

	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"
	client, err := services.AuthenticateClient(ctx, config.DB, c.Request, tokenEndpoint)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": err.Error(),
		})
		return
	}

	issuerURL := config.AppConfig.OAuthBaseURL()

	// ── Registrations for this client.
	var regs []models.ResourceServerClientRegistration
	if err := config.DB.WithContext(ctx).
		Where("oauth_client_id = ?", client.ID).
		Find(&regs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// ── Resolved requester workspace context (NOT home_workspace_id authority):
	// the service-account workspace(s) this client backs, plus the workspaces it
	// already holds an approved registration in. A target is "same_workspace" iff
	// its workspace is in this set.
	requesterWorkspaces := map[uuid.UUID]bool{}
	var saWs []uuid.UUID
	config.DB.WithContext(ctx).
		Raw(`SELECT workspace_id FROM service_accounts WHERE oauth_client_id = ?`, client.ID).
		Scan(&saWs)
	for _, w := range saWs {
		requesterWorkspaces[w] = true
	}
	regByRS := make(map[uuid.UUID]models.ResourceServerClientRegistration, len(regs))
	for _, reg := range regs {
		regByRS[reg.ResourceServerID] = reg
		if reg.Status == models.ClientRegStatusApproved {
			requesterWorkspaces[reg.WorkspaceID] = true
		}
	}

	// ── access_requests for this client → per-RS aggregate + pending[] list.
	var ars []models.AccessRequest
	config.DB.WithContext(ctx).
		Where("requested_by_client = ?", client.ClientID).
		Find(&ars)
	// Only the in-flight signals matter here; access_requests.approved is NOT
	// tracked because it is never grant authority (see accessStatus below).
	type arAgg struct{ pending, denied bool }
	arByRS := map[uuid.UUID]*arAgg{}
	pending := make([]RequesterBootstrapPending, 0)
	for _, ar := range ars {
		agg := arByRS[ar.ResourceServerID]
		if agg == nil {
			agg = &arAgg{}
			arByRS[ar.ResourceServerID] = agg
		}
		switch ar.Status {
		case "pending":
			agg.pending = true
			p := RequesterBootstrapPending{
				RequestID:        ar.ID.String(),
				ResourceServerID: ar.ResourceServerID.String(),
				Status:           ar.Status,
			}
			if ar.ExpiresAt != nil {
				p.ExpiresAt = ar.ExpiresAt.UTC().Format(time.RFC3339)
			}
			pending = append(pending, p)
		case "denied":
			agg.denied = true
		}
	}

	// accessStatus folds the coordination record into the §4 enum. "granted"
	// comes from LIVE authority only — an approved client↔RS registration — and
	// NEVER from access_requests.approved, which is a coordination record, not a
	// grant (a stale approved request must not survive a revoked registration or
	// removed RBAC). access_requests only contributes the in-flight signals:
	// a live pending wins (a re-request must not be hidden by a past denial),
	// then a live registration grant, then a recorded denial, else none.
	// NB: "granted" reflects the CONNECTION-level grant; per-subject scopes are
	// resolved at token time (decision #1), so the SDK still confirms scopes then.
	accessStatus := func(rsID uuid.UUID, regApproved bool) string {
		agg := arByRS[rsID]
		switch {
		case agg != nil && agg.pending:
			return "pending"
		case regApproved:
			return "granted"
		case agg != nil && agg.denied:
			return "denied"
		default:
			return "none"
		}
	}

	buildTarget := func(rs *models.ResourceServer, regStatus string) RequesterBootstrapTarget {
		regApproved := regStatus == models.ClientRegStatusApproved
		relationship := "cross_workspace"
		flow := "id_jag"
		if requesterWorkspaces[rs.WorkspaceID] {
			relationship = "same_workspace"
			if regApproved {
				flow = "direct"
			}
		}
		// Capability disclosure rule: only reveal scopes_supported once the client
		// is actually registered for the RS. First-contact ("none") targets get an
		// empty list so a client can't enumerate any RS's scope surface just by
		// naming its resource_uri — it learns the scopes after approval.
		scopesSupported := []string{}
		if regStatus != "none" {
			scopesSupported = []string(rs.ScopesSupported)
		}
		return RequesterBootstrapTarget{
			ResourceServerID:   rs.ID.String(),
			Resource:           rs.ResourceURI,
			WorkspaceID:        rs.WorkspaceID.String(),
			Relationship:       relationship,
			RecommendedFlow:    flow,
			RegistrationStatus: regStatus,
			AccessStatus:       accessStatus(rs.ID, regApproved),
			ScopesSupported:    scopesSupported,
			// PRM is owned and served by the resource server (RFC 9728); AuthSec
			// only names the source. The SDK fetches the RS's own PRM document.
			PRM: map[string]interface{}{"source": "resource_server"},
		}
	}

	targets := make([]RequesterBootstrapTarget, 0, len(regs)+2)
	covered := map[uuid.UUID]bool{}
	for _, reg := range regs {
		rs, rsErr := ctrl.rsService.GetByID(reg.ResourceServerID.String())
		if rsErr != nil || rs == nil || !rs.Active {
			continue
		}
		covered[rs.ID] = true
		targets = append(targets, buildTarget(rs, reg.Status))
	}

	// ── First-contact: surface any `resource` the caller names that it isn't
	// registered for yet, as a target with registration_status="none" so the SDK
	// can route through ID-JAG + approval instead of getting an empty bundle.
	requested := append(c.QueryArray("resource"), c.PostFormArray("resource")...)
	seenResource := map[string]bool{}
	for _, resURI := range requested {
		if resURI == "" || seenResource[resURI] {
			continue
		}
		seenResource[resURI] = true
		rs, rsErr := ctrl.rsService.GetByResourceURI(resURI)
		if rsErr != nil || rs == nil || !rs.Active || covered[rs.ID] {
			continue
		}
		covered[rs.ID] = true
		targets = append(targets, buildTarget(rs, "none"))
	}

	// ── Content-hashed metadata_version (drift detection): changes whenever the
	// client metadata or any target's registration/access status changes.
	sortedKeys := make([]string, 0, len(targets))
	for _, t := range targets {
		sortedKeys = append(sortedKeys, t.ResourceServerID+":"+t.RegistrationStatus+":"+t.AccessStatus)
	}
	sort.Strings(sortedKeys)
	h := fnv.New64a()
	fmt.Fprintf(h, "%d", client.UpdatedAt.Unix())
	for _, k := range sortedKeys {
		fmt.Fprintf(h, "|%s", k)
	}
	metadataVersion := fmt.Sprintf("%x", h.Sum64())

	c.JSON(http.StatusOK, gin.H{
		"client": gin.H{
			"client_id":   client.ClientID,
			"client_kind": client.ClientKind,
			// home_workspace_id is a hint only — recommended_flow is derived from
			// the resolved workspace context above, not this field.
			"home_workspace_id": client.HomeWorkspaceID,
		},
		"issuer":           issuerURL,
		"as_metadata_url":  issuerURL + "/.well-known/oauth-authorization-server",
		"metadata_version": metadataVersion,
		"targets":          targets,
		"pending":          pending,
	})
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

	client, rawRAT, err := ctrl.service.RegisterDCRClient(req, rs)
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
	resp.ClientKind = client.ClientKind
	if client.SoftwareID != nil {
		resp.SoftwareID = *client.SoftwareID
	}
	if client.SoftwareVersion != nil {
		resp.SoftwareVersion = *client.SoftwareVersion
	}
	// RFC 7592 — include registration management token and URI when available
	if rawRAT != "" {
		resp.RegistrationAccessToken = rawRAT
		resp.RegistrationClientURI = fmt.Sprintf("%s/oauth/register/%s", config.AppConfig.OAuthBaseURL(), client.ClientID)
	}

	c.JSON(http.StatusCreated, resp)
}

// RFC7592Get handles GET /oauth/register/:client_id (RFC 7592 client read).
// The caller must present the registration_access_token issued at registration time
// as a Bearer token in the Authorization header.
func (ctrl *OAuthASController) RFC7592Get(c *gin.Context) {
	clientID := c.Param("client_id")
	rawRAT := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	client, err := ctrl.service.GetClientByRegistrationToken(clientID, rawRAT)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_id":                  client.ClientID,
		"client_name":                client.ClientName,
		"redirect_uris":              []string(client.RedirectURIs),
		"grant_types":                []string(client.GrantTypes),
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"software_id":                client.SoftwareID,
		"software_version":           client.SoftwareVersion,
		"client_kind":                client.ClientKind,
	})
}

// RFC7592Delete handles DELETE /oauth/register/:client_id (RFC 7592 client self-revoke).
// The caller must present the registration_access_token as a Bearer token.
func (ctrl *OAuthASController) RFC7592Delete(c *gin.Context) {
	clientID := c.Param("client_id")
	rawRAT := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	client, err := ctrl.service.GetClientByRegistrationToken(clientID, rawRAT)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	if err := ctrl.service.RevokeClientSelf(client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revocation failed"})
		return
	}
	c.Status(http.StatusNoContent)
}

// RFC7592Put handles PUT /oauth/register/:client_id (RFC 7592 §2 client update).
// Mutable fields: client_name, redirect_uris (queued for admin review), software_version.
// Immutable: grant_types, token_endpoint_auth_method — escalation prevention.
func (ctrl *OAuthASController) RFC7592Put(c *gin.Context) {
	clientID := c.Param("client_id")
	rawRAT := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	client, err := ctrl.service.GetClientByRegistrationToken(clientID, rawRAT)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	var req services.RFC7592UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	redirectPending, err := ctrl.service.UpdateClientMetadata(client, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}

	resp := gin.H{
		"client_id":                  client.ClientID,
		"client_name":                client.ClientName,
		"redirect_uris":              []string(client.RedirectURIs),
		"grant_types":                []string(client.GrantTypes),
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"software_id":                client.SoftwareID,
		"software_version":           client.SoftwareVersion,
		"client_kind":                client.ClientKind,
	}
	if redirectPending {
		resp["redirect_review_pending"] = true
		resp["redirect_review_message"] = "redirect_uris change requires admin approval; current URIs remain active until approved"
	}
	c.JSON(http.StatusOK, resp)
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

	// Forgery-safe classification (§1): a token bearing a native kid commits to
	// the native validation path and NEVER falls back to Hydra. Everything else
	// (opaque/JWT-with-other-kid/unparseable) takes the existing Hydra path.
	if config.AppConfig != nil && config.AppConfig.XAANativeSealer {
		if cls := tokens.Classify(token, tokens.NativeKeys().NativeKeyIDs()); cls.Family == tokens.FamilyNative {
			ctrl.introspectNative(c, token, cls.Kid, rs)
			return
		}
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

	// Registration-status gate. Per models/resource_server_client_registration.go:
	// "All access paths (/oauth/authorize, /oauth/register, consent, introspection)
	// must check this table." Without this, a revoked client's existing access
	// tokens keep working against the MCP server until natural Hydra TTL.
	//
	// Resolve the AuthSec client by Hydra client_id (what the token carries) and
	// look up the join row for (rs, client). Missing row or non-approved status
	// → fail closed.
	hydraClientID, _ := tokenInfo["client_id"].(string)
	if hydraClientID != "" {
		mcpClient, lookupErr := ctrl.service.GetMCPOAuthClientByHydraID(hydraClientID)
		if lookupErr != nil {
			log.Printf("[MCP_AUTH] Introspect: no AuthSec client for hydra_client_id=%s rs=%s — failing closed",
				hydraClientID, rs.ResourceURI)
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		reg, regErr := ctrl.service.GetClientRegistration(rs.ID, mcpClient.ID)
		if regErr != nil || reg.Status != "approved" {
			log.Printf("[MCP_AUTH] Introspect: client registration not approved client=%s rs=%s status=%v — failing closed",
				mcpClient.ClientID, rs.ResourceURI, regStatusOr(reg, regErr))
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
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

// introspectNative is the native (NativeSealer) introspection path. A native-kid
// token is validated here or rejected — it is NEVER retried on Hydra (§1, §3).
// The JWT proves signature + jti; the native_tokens row is the authoritative
// source for workspace/subject/rs/family/scope. We additionally enforce the same
// registration gate as the Hydra path and re-resolve live RBAC, normalizing to
// the identical RS-facing shape (only ext.* varies by family).
func (ctrl *OAuthASController) introspectNative(c *gin.Context, token, kid string, rs *models.ResourceServer) {
	ctx := c.Request.Context()

	// Single shared verifier — same implementation the connector broker uses, so
	// the native invariants (signature → native_tokens → revocation → audience →
	// registration → live RBAC) can never drift between callers.
	authCtx, err := services.VerifyProtectedResourceToken(ctx, config.DB, ctrl.service, ctrl.scopeResolver, token, kid, rs)
	if err != nil {
		log.Printf("[MCP_AUTH] introspectNative: inactive rs=%s: %v", rs.ResourceURI, err)
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	ext := gin.H{
		"workspace_id":       authCtx.Principal.WorkspaceID.String(),
		"resource_server_id": authCtx.ResourceServerID,
		"token_family":       authCtx.TokenFamily,
	}
	if authCtx.Actor != nil {
		ext["act"] = gin.H{"client_id": authCtx.Actor.ClientID, "spiffe_id": authCtx.Actor.SpiffeID}
	}

	// G9: resolve role_ids for the subject+RS binding.
	var roleIDs []string
	roleIDCol := "user_id"
	if authCtx.Principal.SubjectType == "service_account" {
		roleIDCol = "service_account_id"
	}
	config.DB.WithContext(ctx).
		Raw("SELECT role_id::text FROM role_bindings WHERE scope_type = 'resource_server' AND scope_id = ? AND "+roleIDCol+" = ? AND (expires_at IS NULL OR expires_at > NOW())", rs.ID, authCtx.Principal.SubjectID).
		Scan(&roleIDs)
	if roleIDs == nil {
		roleIDs = []string{}
	}

	resp := gin.H{
		"active":       true,
		"sub":          authCtx.Principal.SubjectID.String(),
		"subject_type": authCtx.Principal.SubjectType,
		"token_family": authCtx.TokenFamily,
		"workspace_id": authCtx.Principal.WorkspaceID.String(),
		"client_id":    authCtx.ClientID,
		"aud":          []string{rs.ResourceURI},
		"scope":        strings.Join(authCtx.Scopes, " "),
		"role_ids":     roleIDs,
		"ext":          ext,
		"exp":          authCtx.ExpiresAt.Unix(),
	}
	// G9: typed identity fields for SDK / policy consumers.
	if authCtx.Principal.SubjectType == "service_account" {
		resp["service_account_id"] = authCtx.Principal.SubjectID.String()
		resp["acting_user_id"] = nil
	} else {
		resp["acting_user_id"] = authCtx.Principal.SubjectID.String()
		resp["service_account_id"] = nil
	}
	log.Printf("[MCP_AUTH] introspectNative: active=true family=%s sub=%s rs=%s scopes=%v",
		authCtx.TokenFamily, authCtx.Principal.SubjectID, rs.ResourceURI, authCtx.Scopes)
	c.JSON(http.StatusOK, resp)
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

	// Native tokens are not userinfo subjects in Phase 0: M2M has no user, and
	// XAA/CIBA userinfo (gated on `openid`) lands with those families. A native
	// kid here is rejected — never introspected against Hydra (§1, specifics (d)).
	if config.AppConfig != nil && config.AppConfig.XAANativeSealer {
		if cls := tokens.Classify(token, tokens.NativeKeys().NativeKeyIDs()); cls.Family == tokens.FamilyNative {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
	}

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
		// List available resource URIs to help the client developer.
		var uris []string
		var servers []models.ResourceServer
		if dbErr := config.DB.Where("active = true").Select("resource_uri").Find(&servers).Error; dbErr == nil {
			for _, s := range servers {
				uris = append(uris, s.ResourceURI)
			}
		}
		desc := "resource parameter required because client maps to multiple resource servers"
		if len(uris) > 0 {
			desc += ". Available: " + strings.Join(uris, ", ")
		}
		return "", &policyError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: desc,
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
		// Lazily bind the CIMD client (adopt-on-first-bind; cross-workspace
		// binds park as pending_approval and are denied until approved).
		if bindErr := ctrl.service.BindClientToRS(oauthClient, rs, "cimd"); bindErr != nil {
			if errors.Is(bindErr, services.ErrCrossWorkspacePending) {
				return nil, &policyError{http.StatusForbidden, "access_denied", "client requires admin approval in this workspace"}
			}
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
			// Adopt-on-first-bind: the client's first lazy bind stamps its home
			// workspace and auto-approves. A bind against a DIFFERENT
			// workspace's RS is parked as pending_approval and denied until
			// that workspace's admin approves it in the Clients page.
			if bindErr := ctrl.service.BindClientToRS(oauthClient, rs, "dcr"); bindErr != nil {
				if errors.Is(bindErr, services.ErrCrossWorkspacePending) {
					return nil, &policyError{http.StatusForbidden, "access_denied", "client requires admin approval in this workspace"}
				}
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

	// Native-family dispatch (§1): a native-kid token is revoked in
	// revoked_tokens (source of truth) and never proxied to Hydra.
	if token := c.PostForm("token"); token != "" && config.AppConfig != nil && config.AppConfig.XAANativeSealer {
		if cls := tokens.Classify(token, tokens.NativeKeys().NativeKeyIDs()); cls.Family == tokens.FamilyNative {
			ctrl.revokeNative(c, token, cls.Kid)
			return
		}
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

// revokeNative records a native access-token revocation in revoked_tokens.
// Per RFC 7009 the endpoint returns 200 regardless of whether the token was
// valid or known — we only persist a revocation for a verifiably-signed token.
func (ctrl *OAuthASController) revokeNative(c *gin.Context, token, kid string) {
	if pub, ok := tokens.NativeKeys().PublicKeyForKID(kid); ok {
		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			if _, isRSA := t.Method.(*jwt.SigningMethodRSA); !isRSA {
				return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
			}
			return pub, nil
		})
		// Allow revoking an already-expired token too (jwt marks it invalid):
		// extract jti/iss/exp from claims regardless of the validity error, as
		// long as the signature itself verified.
		if parsed != nil {
			jti, _ := claims["jti"].(string)
			iss, _ := claims["iss"].(string)
			exp := time.Now().Add(24 * time.Hour)
			if e, ok := claims["exp"].(float64); ok {
				exp = time.Unix(int64(e), 0)
			}
			if jti != "" && iss != "" && (err == nil || parsed.Valid || isExpiryOnlyError(err)) {
				if rerr := tokens.RevokeAccessToken(c.Request.Context(), config.DB, iss, jti, "oauth_revoke", exp); rerr != nil {
					log.Printf("[MCP_AUTH] revokeNative: revoke failed jti=%s: %v", jti, rerr)
				}
			}
		}
	}
	c.Status(http.StatusOK)
}

// isExpiryOnlyError reports whether a jwt parse error is solely token expiry
// (signature was valid) — we still allow revoking such a token.
func isExpiryOnlyError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
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

// regStatusOr returns a readable status for log lines: the registration's
// status string when one was found, otherwise the lookup error's message.
func regStatusOr(reg *models.ResourceServerClientRegistration, err error) string {
	if reg != nil {
		return reg.Status
	}
	if err != nil {
		return "lookup_error:" + err.Error()
	}
	return "unknown"
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
// GET /platform/consent-grants?workspace_id=...&user_id=...&client_id=...&rs_id=...
func (ctrl *OAuthASController) ListConsentGrants(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
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
	workspaceID, err := extractWorkspaceID(c)
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

// AccessRequestStatus returns the current status of an access_request by ID.
// This is the requester-facing status-poll endpoint (Journey B, §5). No auth
// is required — the request ID is a capability token; it doesn't reveal anything
// about other requests. Returns status, expires_at, and reason if denied.
func (ctrl *OAuthASController) AccessRequestStatus(c *gin.Context) {
	reqID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	var req models.AccessRequest
	if err := config.DB.WithContext(c.Request.Context()).
		Where("id = ?", reqID).First(&req).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "access request not found"})
		return
	}

	resp := gin.H{
		"id":         req.ID.String(),
		"status":     req.Status,
		"created_at": req.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": req.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if req.ExpiresAt != nil {
		resp["expires_at"] = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if req.Reason != nil {
		resp["reason"] = *req.Reason
	}
	c.JSON(http.StatusOK, resp)
}

func (ctrl *OAuthASController) requireAuthenticatedUserContext(c *gin.Context) (uuid.UUID, uuid.UUID, error) {
	workspaceID, err := extractWorkspaceID(c)
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
