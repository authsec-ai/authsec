package tokens

import "github.com/gin-gonic/gin"

// TokenResponse is the normalized result of a token grant. Native handlers
// populate it directly; the Hydra handler returns Hydra's response bytes
// verbatim and does not use this type.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	// Deliberately NO refresh_token: native (M2M/XAA/CIBA) tokens are
	// short-lived and non-refreshable.
}

// GrantHandler is the per-grant orchestration seam used by the /oauth/token
// dispatcher. Each grant owns its own flow (authenticate client, validate
// inputs/assertions, gate via policy/registration, resolve principal+scopes,
// mint, audit).
//
// Design note (reviewer-driven): the Hydra authorization_code/refresh_token
// path is NOT minting-only — it proxies to Hydra, extracts context_id,
// validates resource-server registration, and revokes the full token set on
// failure. It is therefore implemented as a GrantHandler that keeps that
// orchestration in place; it is explicitly NOT wrapped behind the narrow
// NativeIssuer "mint" seam. Native handlers (M2M/XAA/CIBA), by contrast, call
// NativeIssuer to mint after they finish their own orchestration.
type GrantHandler interface {
	// Handle runs the full grant flow and writes the HTTP response on c.
	Handle(c *gin.Context)
}
