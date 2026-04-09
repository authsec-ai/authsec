package platform

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	service       *services.OAuthASService
	rsService     *services.ResourceServerService
	scopeResolver *services.ScopeResolver
}

func NewOAuthASController() *OAuthASController {
	return &OAuthASController{
		service:       services.NewOAuthASService(config.DB),
		rsService:     services.NewResourceServerService(config.DB),
		scopeResolver: services.NewScopeResolver(),
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
//   - Only supports response_type=code (rejects form_post etc.)
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

	// Only response_type=code supported. Reject anything else explicitly.
	if responseType != "" && responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "only response_type=code is supported",
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
	}

	// 3. Check join table
	reg, err := ctrl.service.GetClientRegistration(rs.ID, oauthClient.ID)
	if err != nil || reg.Status != "approved" {
		c.JSON(http.StatusForbidden, gin.H{"error": "client not authorized for this resource"})
		return
	}

	// 4. Validate requested scopes
	var requestedScopes []string
	if scopeParam != "" {
		requestedScopes = strings.Split(scopeParam, " ")
	}
	if len(requestedScopes) > 0 && !rs.SupportsScopes(requestedScopes) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "requested scopes not supported by resource server"})
		return
	}

	// 5. Generate server-side context_id for deterministic binding.
	// This is NOT the client's state — it's an AuthSec-internal ID.
	contextID := uuid.New().String()

	// 6. Store auth request context
	ctx := &models.AuthRequestContext{
		State:            uuid.New().String(), // Server-generated PK (not client state)
		ContextID:        contextID,
		HydraClientID:    oauthClient.HydraClientID,
		ResourceServerID: rs.ID.String(),
		TenantID:         rs.TenantID.String(),
		ResourceURI:      rs.ResourceURI,
		RedirectURI:      redirectURI,
		RequestedScopes:  scopeParam,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
	}
	if err := ctrl.service.StoreAuthRequestContext(ctx); err != nil {
		log.Printf("[MCP_AUTH] Authorize: failed to store auth context: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store auth context"})
		return
	}

	log.Printf("[MCP_AUTH] Authorize: context_id=%s client=%s resource=%s", contextID, clientID, resource)

	// 7. Forward to Hydra with the internal hydra_client_id.
	// The context_id is included in the query params so Hydra preserves it in request_url.
	params := c.Request.URL.Query()
	params.Set("client_id", oauthClient.HydraClientID)
	params.Set("authsec_ctx", contextID) // Carried in Hydra's stored request_url
	hydraURL := config.AppConfig.HydraPublicURL + "/oauth2/auth?" + params.Encode()
	c.Redirect(http.StatusFound, hydraURL)
}

// Token handles the OAuth token exchange.
// POST /oauth/token
//
// Hard rules for MCP clients:
//   - authorization_code: captures Hydra response, introspects access token for context_id,
//     looks up auth context, validates RS binding. FAILS CLOSED on missing context.
//   - refresh_token: looks up MCPGrantBinding by hash(refresh_token). FAILS CLOSED on missing binding.
//   - If StoreGrantBinding fails after Hydra issues a refresh token, strip the refresh_token
//     from the response (access-only semantics) to prevent broken future state.
func (ctrl *OAuthASController) Token(c *gin.Context) {
	if c.Request.PostForm == nil {
		c.Request.ParseForm()
	}

	clientID := c.PostForm("client_id")
	grantType := c.PostForm("grant_type")

	// No client_id → legacy passthrough
	if clientID == "" {
		ctrl.service.ProxyFormToHydraPublic("/oauth2/token", c.Request.PostForm, c.Request.Header, c.Writer)
		return
	}

	// Look up MCP OAuth client
	oauthClient, err := ctrl.service.GetOAuthClient(clientID)
	if err != nil {
		// Not an MCP client → legacy passthrough
		ctrl.service.ProxyFormToHydraPublic("/oauth2/token", c.Request.PostForm, c.Request.Header, c.Writer)
		return
	}

	switch grantType {
	case "authorization_code":
		ctrl.tokenAuthCodeGrant(c, oauthClient)
	case "refresh_token":
		ctrl.tokenRefreshGrant(c, oauthClient)
	default:
		c.Request.PostForm.Set("client_id", oauthClient.HydraClientID)
		ctrl.service.ProxyFormToHydraPublic("/oauth2/token", c.Request.PostForm, c.Request.Header, c.Writer)
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
//  7. Store MCPGrantBinding for refresh token. If store fails → strip refresh_token from response.
//  8. Consume auth context
//  9. Forward (possibly modified) response
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
		// TODO: Revoke the token we just got from Hydra (best-effort cleanup)
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

	// 5. Validate redirect_uri and resource
	if redirectURI != "" && arcCtx.RedirectURI != "" && redirectURI != arcCtx.RedirectURI {
		log.Printf("[MCP_AUTH] tokenAuthCodeGrant: redirect_uri mismatch for context_id=%s", contextID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "redirect_uri mismatch",
		})
		return
	}
	if resourceParam != "" && arcCtx.ResourceURI != "" && resourceParam != arcCtx.ResourceURI {
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

	// 7. Store MCPGrantBinding for refresh token tracking.
	// If store fails → strip refresh_token from response (access-only semantics).
	if rt, ok := tokenResp["refresh_token"].(string); ok && rt != "" {
		rsID, _ := uuid.Parse(arcCtx.ResourceServerID)
		binding := &models.MCPGrantBinding{
			RefreshTokenHash: sha256Hex(rt),
			HydraClientID:    oauthClient.HydraClientID,
			ResourceServerID: rsID,
			ResourceURI:      arcCtx.ResourceURI,
			TenantID:         arcCtx.TenantID,
			ExpiresAt:        time.Now().Add(30 * 24 * time.Hour), // TODO: match Hydra's refresh TTL from config
		}
		if storeErr := ctrl.service.StoreGrantBinding(binding); storeErr != nil {
			log.Printf("[MCP_AUTH] tokenAuthCodeGrant: CRITICAL failed to store grant binding for context_id=%s: %v — stripping refresh_token", contextID, storeErr)
			// Strip refresh_token to prevent broken future state
			delete(tokenResp, "refresh_token")
			body, _ = json.Marshal(tokenResp)
		}
	}

	// 8. Consume the auth context
	_ = ctrl.service.ConsumeAuthRequestContext(arcCtx.State)

	log.Printf("[MCP_AUTH] tokenAuthCodeGrant: success context_id=%s client=%s rs=%s", contextID, oauthClient.ClientID, arcCtx.ResourceURI)

	// 9. Forward response
	writeProxiedResponse(c.Writer, statusCode, body, respHeader)
}

// tokenRefreshGrant handles refresh_token exchange for MCP clients.
//
// Hard rules:
//   - FAIL CLOSED: MCP clients MUST have a grant binding. No binding = no refresh.
//   - Validates RS registration is still approved for the specific RS the token was minted for.
//   - If Hydra rotates the refresh token, updates the binding hash.
//   - On concurrent rotation (old hash not found), Hydra rejects the second call;
//     we don't need special handling — Hydra enforces single-use refresh tokens.
func (ctrl *OAuthASController) tokenRefreshGrant(c *gin.Context, oauthClient *models.MCPOAuthClient) {
	refreshToken := c.PostForm("refresh_token")
	oldHash := sha256Hex(refreshToken)

	// FAIL CLOSED: MCP clients must have a grant binding.
	binding, err := ctrl.service.GetGrantBindingByRefreshHash(oldHash)
	if err != nil || binding == nil {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: no grant binding for client=%s hash=%s — FAIL CLOSED: %v",
			oauthClient.ClientID, oldHash[:12], err)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "no grant binding found for this refresh token",
		})
		return
	}

	// Check RS registration is still approved for this specific RS
	reg, regErr := ctrl.service.GetClientRegistration(binding.ResourceServerID, oauthClient.ID)
	if regErr != nil || reg.Status != "approved" {
		log.Printf("[MCP_AUTH] tokenRefreshGrant: client=%s revoked for RS=%s", oauthClient.ClientID, binding.ResourceURI)
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "access_denied",
			"error_description": "client registration for resource server has been revoked",
		})
		return
	}

	// Proxy to Hydra
	c.Request.PostForm.Set("client_id", oauthClient.HydraClientID)
	statusCode, body, respHeader, err := ctrl.service.ProxyFormToHydraPublicCapture(
		"/oauth2/token", c.Request.PostForm, c.Request.Header,
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server unavailable"})
		return
	}

	// If Hydra rotated the refresh token, update the binding hash.
	// Concurrency note: if two parallel refresh calls hit Hydra, Hydra rejects the second
	// with invalid_grant (single-use enforcement). We only update on 200.
	if statusCode == http.StatusOK {
		var tokenResp map[string]interface{}
		if json.Unmarshal(body, &tokenResp) == nil {
			if newRT, ok := tokenResp["refresh_token"].(string); ok && newRT != "" {
				newHash := sha256Hex(newRT)
				if newHash != oldHash {
					if updateErr := ctrl.service.UpdateGrantBindingRefreshHash(oldHash, newHash); updateErr != nil {
						log.Printf("[MCP_AUTH] tokenRefreshGrant: failed to update binding hash: %v", updateErr)
					} else {
						log.Printf("[MCP_AUTH] tokenRefreshGrant: rotated binding hash for client=%s", oauthClient.ClientID)
					}
				}
			}
		}
	}

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

	audMatch := false
	if aud, ok := tokenInfo["aud"].([]interface{}); ok {
		for _, a := range aud {
			if s, ok := a.(string); ok && s == rs.ResourceURI {
				audMatch = true
				break
			}
		}
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

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
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

// Unused import guard
var _ = fmt.Sprintf
