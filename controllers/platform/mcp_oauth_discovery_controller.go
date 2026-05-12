package platform

import (
	"net/http"
	"os"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
)

// MCPOAuthDiscoveryController serves the user-facing OAuth/OIDC discovery
// document MCP clients require (https://modelcontextprotocol.io/specification/draft/basic/authorization).
//
// This is INTENTIONALLY separate from spiffe_delegate_controller.go:OIDCDiscovery,
// which serves SPIRE's federation document (response_types=id_token only, no
// authorization_endpoint, no token_endpoint). Mixing the two breaks SPIRE.
//
// Endpoints registered by this controller:
//
//	GET /authsec/oauth/.well-known/openid-configuration
//	GET /authsec/oauth/.well-known/oauth-authorization-server   (RFC 8414, what MCP checks first)
//
// The two paths return the same document. RFC 8414 says clients try
// /.well-known/oauth-authorization-server first; OIDC clients try
// /.well-known/openid-configuration. Serving both is the path of fewest
// integration headaches.
type MCPOAuthDiscoveryController struct {
	// issuer is the public base URL clients will see (e.g. https://prod.api.authsec.ai/authsec/oauth).
	// MUST equal the URL the discovery doc is served from, per RFC 8414 §3.3.
	issuer string
	// publicBase is the host root (e.g. https://prod.api.authsec.ai), without
	// the /authsec/oauth suffix. Used for endpoints that live elsewhere on
	// the same host (jwks, the existing authorize/token routes).
	publicBase string
}

// NewMCPOAuthDiscoveryController builds the controller using AppConfig.BaseURL.
//
// The issuer is BASE_URL + "/authsec/oauth". For example, if BASE_URL is
// "https://prod.api.authsec.ai", the issuer becomes
// "https://prod.api.authsec.ai/authsec/oauth", and the discovery doc is
// served at "https://prod.api.authsec.ai/authsec/oauth/.well-known/...".
// That satisfies RFC 8414's issuer-equality requirement.
//
// To override (e.g. when AuthSec sits behind a CDN), set the env var
// OAUTH_PUBLIC_BASE_URL — that wins over BASE_URL for this purpose.
func NewMCPOAuthDiscoveryController(cfg *config.Config) *MCPOAuthDiscoveryController {
	base := strings.TrimRight(getOAuthPublicBase(cfg), "/")
	return &MCPOAuthDiscoveryController{
		issuer:     base + "/authsec/oauth",
		publicBase: base,
	}
}

// Discovery serves the OAuth 2.1 / OIDC discovery document.
//
//	@Summary     MCP-compliant OAuth / OIDC discovery document
//	@Description Returns RFC 8414 + OIDC Discovery metadata for AuthSec's user-facing
//	             OAuth provider. This is what MCP clients (and the compliance checker
//	             at mcp-auth.dev) read to learn how to talk to AuthSec.
//	@Tags        OAuth Discovery
//	@Produce     json
//	@Success     200 {object} map[string]interface{}
//	@Router      /authsec/oauth/.well-known/openid-configuration [get]
//	@Router      /authsec/oauth/.well-known/oauth-authorization-server [get]
func (ctrl *MCPOAuthDiscoveryController) Discovery(c *gin.Context) {
	iss := ctrl.issuer

	// All endpoints listed here MUST be reachable for real. Lying in the
	// discovery doc is worse than not advertising a feature — strict MCP
	// clients will retry against advertised endpoints and surface a worse
	// error than "not supported" if those endpoints 404.
	doc := gin.H{
		"issuer": iss,

		// Endpoints currently wired in routes.go that match each role.
		// authorize: see routes.go playgroundOAuth /sdkmgr/playground/oauth/authorize
		// token:     see routes.go authmgr      /authmgr/token/generate
		// jwks:      same key material as the SPIRE-federation JWKS, served on the SPIRE path.
		// These point at the existing AuthSec OAuth routes (already wired in
		// routes.go). Keeping them at their current paths avoids creating
		// stub routes that would 404.
		"authorization_endpoint": ctrl.publicBase + "/authsec/sdkmgr/playground/oauth/authorize",
		"token_endpoint":         ctrl.publicBase + "/authsec/authmgr/token/generate",
		"jwks_uri":               ctrl.publicBase + "/authsec/.well-known/jwks.json",

		// MCP authorization spec requirements.
		// PKCE: clients MUST use S256 (no plain).
		"code_challenge_methods_supported": []string{"S256"},

		// authorization_code only — implicit and ROPC are forbidden by the
		// MCP spec. refresh_token is allowed and recommended for long-lived
		// agent sessions.
		"grant_types_supported": []string{"authorization_code", "refresh_token"},

		// The MCP spec requires "code" (no "id_token", no "token").
		"response_types_supported": []string{"code"},

		// Public clients (CLI/desktop agents) use PKCE with no secret;
		// confidential clients post their secret. No basic auth — keeping
		// surface narrow.
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},

		// Scopes AuthSec currently advertises. Tenants can ask for more via
		// the user/admin auth flow; this is the minimum set MCP needs.
		"scopes_supported": []string{"openid", "profile", "email", "offline_access"},

		// Identity-token shape (unchanged from SPIRE side).
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},

		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat",
			"user_id", "tenant_id", "email", "spiffe_id",
		},

		// RFC 8707 resource indicators — MCP's newer spec requires the
		// client to bind a token to a specific MCP server URL. AuthSec's
		// token endpoint must validate the `resource` parameter for full
		// compliance; advertising it here is a promise we keep on the
		// server side. See deployment note alongside this controller.
		"resource_indicators_supported": true,

		// NOTE: registration_endpoint (RFC 7591 Dynamic Client Registration)
		// is intentionally NOT advertised yet. AuthSec's existing
		// /authsec/user/clients/register sits behind AuthMiddleware, which
		// violates the spec — DCR must be public so an MCP client can
		// self-register at first contact. Advertising a 401-gated endpoint
		// is worse than omitting it.
		//
		// When the auth team ships a public, rate-limited
		// /authsec/oauth/register handler that complies with RFC 7591, add
		// it here as:
		//   "registration_endpoint": iss + "/register",
	}

	c.JSON(http.StatusOK, doc)
}

// getOAuthPublicBase resolves the public base URL for OAuth endpoints.
// Precedence: OAUTH_PUBLIC_BASE_URL env > cfg.BaseURL > the fallback.
//
// cfg may be nil (the function is used from inside the handler where we
// want to recompute on every request in case env is reloaded; in practice
// it always falls through to the env or to the cached cfg below).
func getOAuthPublicBase(cfg *config.Config) string {
	if v := os.Getenv("OAUTH_PUBLIC_BASE_URL"); v != "" {
		return v
	}
	if cfg != nil && cfg.BaseURL != "" {
		return cfg.BaseURL
	}
	// Fallback to the config singleton if it's been loaded.
	if config.AppConfig != nil && config.AppConfig.BaseURL != "" {
		return config.AppConfig.BaseURL
	}
	return "https://app.authsec.dev"
}
