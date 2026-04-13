package platform

import (
	"encoding/base64"
	"encoding/json"
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
)

// OAuthASController handles global OAuth Authorization Server endpoints.
// All endpoints are global (not per-RS). RS context is carried by the `resource` parameter.
type OAuthASController struct {
	service   *services.OAuthASService
	rsService *services.ResourceServerService
}

func NewOAuthASController() *OAuthASController {
	return &OAuthASController{
		service:   services.NewOAuthASService(config.DB),
		rsService: services.NewResourceServerService(config.DB),
	}
}

// ASMetadata serves RFC 8414 Authorization Server Metadata.
// GET /.well-known/oauth-authorization-server
func (ctrl *OAuthASController) ASMetadata(c *gin.Context) {
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
	resource := c.Query("resource")
	state := c.Query("state")
	redirectURI := c.Query("redirect_uri")
	scopeParam := c.Query("scope")
	responseType := c.Query("response_type")
	responseMode := c.Query("response_mode")

	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

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

	// 1b. Validate requested scopes against RS-supported scopes (if RS declares them)
	if scopeParam != "" {
		requestedScopes := strings.Split(scopeParam, " ")
		if invalid := services.ValidateRequestedScopes(requestedScopes, rs); len(invalid) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_scope",
				"error_description": "unsupported scope(s): " + strings.Join(invalid, ", "),
			})
			return
		}
	}

	// 2. Resolve OAuth client (CIMD if HTTPS URL, else DCR/prereg lookup)
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
//   - refresh_token: explicitly unsupported in MCP OAuth v1.
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "refresh_token is not supported",
		})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "only authorization_code is supported",
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

	// 8. Strip refresh tokens from the upstream response.
	// MCP OAuth v1 is intentionally authorization_code-only.
	if _, ok := tokenResp["refresh_token"]; ok {
		delete(tokenResp, "refresh_token")
		body, _ = json.Marshal(tokenResp)
	}

	log.Printf("[MCP_AUTH] tokenAuthCodeGrant: success context_id=%s client=%s rs=%s", contextID, oauthClient.ClientID, arcCtx.ResourceURI)

	// 9. Forward response
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
