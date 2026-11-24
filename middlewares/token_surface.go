package middlewares

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Token surfaces (AS-033). AuthMiddleware admits a session token only when its
// class (internal/sessiontoken) is accepted on the surface of the request path:
//
//   - console (the default for every path not listed below): admin tokens.
//   - end-user self-service (endUserSurfacePrefixes): end-user and admin
//     tokens. Console users are users too, and the console calls these routes
//     (their own TOTP/CIBA devices, consent grants, profile) with its token.
//   - SDK (sdkSurfacePrefixes): SDK, end-user and admin tokens. The SDK calls
//     the authorization checks with the signed-in user's token.
//
// Legacy (typ-less) tokens are admitted on every surface until the legacy
// deadline (see internal/sessiontoken), exactly as before this change.
//
// So an end-user or SDK token is refused on the console, and an SDK token is
// refused on end-user self-service. A new route that end users must reach
// with their own token has to be listed here.
var endUserSurfacePrefixes = []string{
	"/authsec/auth/logout",
	"/oauth/consent-grants",
	"/authsec/uflow/user/",
	"/authsec/uflow/auth/",
	"/authsec/webauthn/",
}

var sdkSurfacePrefixes = []string{
	"/authsec/authz/",
	"/authsec/auth/token/",
	"/authsec/uflow/sdk/",
	"/authsec/uflow/agent/actions",
}

func hasAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// surfaceClasses returns the token classes accepted on a request path.
func surfaceClasses(path string) []sessiontoken.Class {
	switch {
	case hasAnyPrefix(path, sdkSurfacePrefixes):
		return []sessiontoken.Class{sessiontoken.SDK, sessiontoken.EndUser, sessiontoken.Admin, sessiontoken.Legacy}
	case hasAnyPrefix(path, endUserSurfacePrefixes):
		return []sessiontoken.Class{sessiontoken.EndUser, sessiontoken.Admin, sessiontoken.Legacy}
	default:
		return []sessiontoken.Class{sessiontoken.Admin, sessiontoken.Legacy}
	}
}

// userSessionClasses are the classes that name an interactive user: used
// where a handler validates a user session outside AuthMiddleware.
var userSessionClasses = []sessiontoken.Class{sessiontoken.Admin, sessiontoken.EndUser, sessiontoken.Legacy}

// IsInteractiveUserSession reports whether the session token AuthMiddleware
// verified for this request is an admin or end-user session (a person signed
// in), not an SDK token, which is what an agent holds. A legacy (typ-less)
// token is refused: it may have been signed with the SDK secret, so its class
// cannot be known. Use it where only the human may act, such as deciding an
// agent's action.
func IsInteractiveUserSession(c *gin.Context) bool {
	raw, ok := c.Get("claims")
	if !ok {
		return false
	}
	claims, ok := raw.(jwt.MapClaims)
	if !ok {
		return false
	}
	switch sessiontoken.ClassOf(claims) {
	case sessiontoken.Admin, sessiontoken.EndUser:
		return true
	}
	return false
}
