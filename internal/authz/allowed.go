package authz

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Allows reports whether the request's token satisfies (resource, action) by
// exactly the test Require applies -- the resource-list check when enforced,
// then perms, scope or a database role binding -- without aborting the
// request or writing a response.
//
// It exists for handlers that must STATE a permission rather than enforce it:
// a detail response's meta.capabilities says whether the caller may perform an
// action served by another route (SPEC-iga-phase2-graph.md §5.2; the console
// never infers permissions from role names, §2.14.6). The route that performs
// the action keeps its Require middleware, which remains the enforcement; this
// only decides what to offer, so it fails closed: no claims, or claims of an
// unexpected type, is false.
func Allows(c *gin.Context, resource, action string) bool {
	claimsAny, ok := c.Get("claims")
	if !ok {
		return false
	}
	claims, ok := claimsAny.(jwt.MapClaims)
	if !ok {
		return false
	}
	if enforceResourceList && !hasResource(claims, resource) {
		return false
	}
	return hasPerm(claims, resource, action) ||
		hasScope(claims, resource+":"+action) ||
		hasDBPermission(claims, resource, action)
}
