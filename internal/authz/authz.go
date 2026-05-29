package authz

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Need struct{ Resource, Action string }

// ENV toggle: also require resources claim to list the resource (defense in depth)
var enforceResourceList = strings.EqualFold(os.Getenv("AUTH_ENFORCE_RESOURCE_LIST"), "true")

// Require enforces a single (resource, action) pair.
func Require(resource, action string) gin.HandlerFunc {
	return RequireAll(Need{Resource: resource, Action: action})
}

// RequireAll enforces that ALL needs are satisfied.
func RequireAll(needs ...Need) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("[AUTHZ RequireAll] Starting authorization check for %d needs", len(needs))
		for i, need := range needs {
			log.Printf("[AUTHZ RequireAll] Need %d: Resource='%s', Action='%s'", i+1, need.Resource, need.Action)
		}

		claimsAny, ok := c.Get("claims")
		if !ok {
			log.Printf("[AUTHZ RequireAll] ERROR: No claims found in context")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claims := claimsAny.(jwt.MapClaims)
		log.Printf("[AUTHZ RequireAll] Claims retrieved from context")

		// Optional: belt-and-suspenders check that the resource is listed in "resources"
		if enforceResourceList {
			log.Printf("[AUTHZ RequireAll] Resource list enforcement enabled")
			for _, n := range needs {
				hasRes := hasResource(claims, n.Resource)
				log.Printf("[AUTHZ RequireAll] Checking resource '%s': %t", n.Resource, hasRes)
				if !hasRes {
					log.Printf("[AUTHZ RequireAll] FAIL: Resource '%s' not found in token resources", n.Resource)
					denyInsufficientScope(c)
					return
				}
			}
			log.Printf("[AUTHZ RequireAll] All resources validated")
		} else {
			log.Printf("[AUTHZ RequireAll] Resource list enforcement disabled")
		}

		// Admin claim bypass removed. The canonical owner/admin/member roles
		// seeded per workspace (migration 115) now carry explicit permissions;
		// access is decided through the same hasPerm / hasScope path as every
		// other principal. Tokens with `roles: ["admin"]` no longer skip checks.

		// All needs must pass (perms or scope fallback)
		log.Printf("[AUTHZ RequireAll] Checking permissions for all needs")
		for _, n := range needs {
			hasPermCheck := hasPerm(claims, n.Resource, n.Action)
			hasScopeCheck := hasScope(claims, n.Resource+":"+n.Action)
			hasDBPermCheck := hasDBPermission(claims, n.Resource, n.Action)
			result := hasPermCheck || hasScopeCheck || hasDBPermCheck
			log.Printf("[AUTHZ RequireAll] Need Resource='%s', Action='%s': hasPerm=%t, hasScope=%t, hasDBPerm=%t, result=%t",
				n.Resource, n.Action, hasPermCheck, hasScopeCheck, hasDBPermCheck, result)
			if !result {
				log.Printf("[AUTHZ RequireAll] FAIL: Need not satisfied - Resource='%s', Action='%s'", n.Resource, n.Action)
				denyInsufficientScope(c)
				return
			}
		}
		log.Printf("[AUTHZ RequireAll] SUCCESS: All needs satisfied")
		c.Next()
	}
}

// RequireAny enforces that AT LEAST ONE of the needs is satisfied.
func RequireAny(needs ...Need) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("[AUTHZ RequireAny] Starting authorization check for %d needs (at least one required)", len(needs))
		for i, need := range needs {
			log.Printf("[AUTHZ RequireAny] Need %d: Resource='%s', Action='%s'", i+1, need.Resource, need.Action)
		}

		claimsAny, ok := c.Get("claims")
		if !ok {
			log.Printf("[AUTHZ RequireAny] ERROR: No claims found in context")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claims := claimsAny.(jwt.MapClaims)
		log.Printf("[AUTHZ RequireAny] Claims retrieved from context")

		// If resource list is enforced, ensure at least one needed resource appears
		if enforceResourceList {
			log.Printf("[AUTHZ RequireAny] Resource list enforcement enabled")
			found := false
			for _, n := range needs {
				hasRes := hasResource(claims, n.Resource)
				log.Printf("[AUTHZ RequireAny] Checking resource '%s': %t", n.Resource, hasRes)
				if hasRes {
					found = true
					log.Printf("[AUTHZ RequireAny] Resource '%s' found", n.Resource)
					break
				}
			}
			if !found {
				log.Printf("[AUTHZ RequireAny] FAIL: No required resources found in token")
				denyInsufficientScope(c)
				return
			}
			log.Printf("[AUTHZ RequireAny] At least one resource validated")
		} else {
			log.Printf("[AUTHZ RequireAny] Resource list enforcement disabled")
		}

		// (Admin claim bypass removed — see RequireAll above for rationale.)

		log.Printf("[AUTHZ RequireAny] Checking permissions for at least one need")
		for _, n := range needs {
			hasPermCheck := hasPerm(claims, n.Resource, n.Action)
			hasScopeCheck := hasScope(claims, n.Resource+":"+n.Action)
			hasDBPermCheck := hasDBPermission(claims, n.Resource, n.Action)
			result := hasPermCheck || hasScopeCheck || hasDBPermCheck
			log.Printf("[AUTHZ RequireAny] Need Resource='%s', Action='%s': hasPerm=%t, hasScope=%t, hasDBPerm=%t, result=%t",
				n.Resource, n.Action, hasPermCheck, hasScopeCheck, hasDBPermCheck, result)
			if result {
				log.Printf("[AUTHZ RequireAny] SUCCESS: Need satisfied - Resource='%s', Action='%s'", n.Resource, n.Action)
				c.Next()
				return
			}
		}
		log.Printf("[AUTHZ RequireAny] FAIL: No needs satisfied")
		denyInsufficientScope(c)
	}
}

// ---------- helpers ----------

func denyInsufficientScope(c *gin.Context) {
	log.Printf("[AUTHZ] Access denied: insufficient scope/permissions for path %s", c.Request.URL.Path)

	c.Header("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":             "insufficient_scope",
		"error_description": "token is valid but lacks required permissions",
	})
}

func hasDBPermission(claims jwt.MapClaims, resource, action string) bool {
	if config.DB == nil {
		log.Printf("[AUTHZ hasDBPermission] DB not initialized")
		return false
	}

	workspaceIDStr := firstClaimString(claims, "workspace_id")
	userIDStr := firstClaimString(claims, "user_id", "sub")
	if workspaceIDStr == "" || userIDStr == "" {
		log.Printf("[AUTHZ hasDBPermission] Missing workspace/user claim: workspace=%q user=%q", workspaceIDStr, userIDStr)
		return false
	}

	workspaceID, err := uuid.Parse(workspaceIDStr)
	if err != nil {
		log.Printf("[AUTHZ hasDBPermission] Invalid workspace id %q: %v", workspaceIDStr, err)
		return false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		log.Printf("[AUTHZ hasDBPermission] Invalid user id %q: %v", userIDStr, err)
		return false
	}

	var count int64
	if err := config.DB.Table("role_bindings rb").
		Joins("JOIN roles r ON r.id = rb.role_id").
		Joins("JOIN role_permissions rp ON rp.role_id = r.id").
		Joins("JOIN permissions p ON p.id = rp.permission_id").
		Where("rb.user_id = ? AND rb.workspace_id = ?", userID, workspaceID).
		Where("p.workspace_id = ? OR p.workspace_id IS NULL", workspaceID).
		Where("(p.resource = ? OR p.resource = '*') AND (p.action = ? OR p.action = '*')", resource, action).
		Where("rb.expires_at IS NULL OR rb.expires_at > NOW()").
		Count(&count).Error; err != nil {
		log.Printf("[AUTHZ hasDBPermission] DB permission check failed: %v", err)
		return false
	}

	return count > 0
}

func firstClaimString(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if value, ok := claims[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

// hasRole was previously used by the now-removed admin claim bypass in
// RequireAll / RequireAny. Authorization now flows through hasPerm + hasScope
// against the canonical permissions table. The function is kept as
// `_ = hasRole` would obscure intent; deleted in favour of explicit removal.

func hasPerm(claims jwt.MapClaims, r, a string) bool {
	log.Printf("[AUTHZ hasPerm] Checking permission for Resource='%s', Action='%s'", r, a)

	// perms is expected to be []{ r:string, a:[]string }
	switch arr := claims["perms"].(type) {
	case []Perm:
		// Handle []Perm type returned by FromScopes() when enriching from DB
		log.Printf("[AUTHZ hasPerm] Processing perms as []Perm with %d entries", len(arr))
		for i, p := range arr {
			log.Printf("[AUTHZ hasPerm] Checking perm entry %d: resource='%s', actions=%v", i+1, p.R, p.A)
			if p.R == r || p.R == "*" || r == "*" {
				log.Printf("[AUTHZ hasPerm] Found matching resource '%s'", p.R)
				for j, act := range p.A {
					if act == a || act == "*" || a == "*" {
						log.Printf("[AUTHZ hasPerm] SUCCESS: Found matching action '%s' at index %d", act, j)
						return true
					}
					log.Printf("[AUTHZ hasPerm] Action %d: '%s' (no match)", j+1, act)
				}
			} else {
				log.Printf("[AUTHZ hasPerm] Resource '%s' does not match needed '%s'", p.R, r)
			}
		}
	case []any:
		log.Printf("[AUTHZ hasPerm] Processing perms as []any with %d entries", len(arr))
		for i, p := range arr {
			log.Printf("[AUTHZ hasPerm] Checking perm entry %d", i+1)
			if m, ok := p.(map[string]any); ok {
				if mr, _ := m["r"].(string); mr == r {
					log.Printf("[AUTHZ hasPerm] Found matching resource '%s'", mr)
					switch acts := m["a"].(type) {
					case []any:
						log.Printf("[AUTHZ hasPerm] Actions as []any with %d entries", len(acts))
						for j, v := range acts {
							s, _ := v.(string)
							if s == a {
								log.Printf("[AUTHZ hasPerm] SUCCESS: Found matching action '%s' at index %d", s, j)
								return true
							}
							log.Printf("[AUTHZ hasPerm] Action %d: '%s' (no match)", j+1, s)
						}
					case []string:
						log.Printf("[AUTHZ hasPerm] Actions as []string with %d entries", len(acts))
						for j, act := range acts {
							if act == a {
								log.Printf("[AUTHZ hasPerm] SUCCESS: Found matching action '%s' at index %d", act, j)
								return true
							}
							log.Printf("[AUTHZ hasPerm] Action %d: '%s' (no match)", j+1, act)
						}
					default:
						log.Printf("[AUTHZ hasPerm] Actions type not recognized: %T", acts)
					}
				} else {
					log.Printf("[AUTHZ hasPerm] Resource '%s' does not match needed '%s'", mr, r)
				}
			} else {
				log.Printf("[AUTHZ hasPerm] Perm entry %d is not a map[string]any", i+1)
			}
		}
	case []map[string]any:
		log.Printf("[AUTHZ hasPerm] Processing perms as []map[string]any with %d entries", len(arr))
		for i, m := range arr {
			log.Printf("[AUTHZ hasPerm] Checking perm entry %d", i+1)
			if mr, _ := m["r"].(string); mr == r {
				log.Printf("[AUTHZ hasPerm] Found matching resource '%s'", mr)
				if acts, ok := m["a"].([]any); ok {
					log.Printf("[AUTHZ hasPerm] Actions as []any with %d entries", len(acts))
					for j, v := range acts {
						s, _ := v.(string)
						if s == a {
							log.Printf("[AUTHZ hasPerm] SUCCESS: Found matching action '%s' at index %d", s, j)
							return true
						}
						log.Printf("[AUTHZ hasPerm] Action %d: '%s' (no match)", j+1, s)
					}
				} else {
					log.Printf("[AUTHZ hasPerm] Actions not found or not []any")
				}
			} else {
				log.Printf("[AUTHZ hasPerm] Resource '%s' does not match needed '%s'", mr, r)
			}
		}
	default:
		log.Printf("[AUTHZ hasPerm] Perms type not recognized: %T", arr)
	}
	log.Printf("[AUTHZ hasPerm] FAIL: No matching permission found")
	return false
}

func hasScope(claims jwt.MapClaims, needed string) bool {
	log.Printf("[AUTHZ hasScope] Checking scope for needed='%s'", needed)

	// Prefer canonical "scope" (space-delimited string)
	if s, ok := claims["scope"].(string); ok && s != "" {
		log.Printf("[AUTHZ hasScope] Found 'scope' claim: '%s'", s)
		fields := strings.Fields(s)
		log.Printf("[AUTHZ hasScope] Split into %d fields: %v", len(fields), fields)
		if wildcardMatch(fields, needed) {
			log.Printf("[AUTHZ hasScope] SUCCESS: Wildcard match found in 'scope' claim")
			return true
		}
		log.Printf("[AUTHZ hasScope] No match in 'scope' claim")
	} else {
		log.Printf("[AUTHZ hasScope] 'scope' claim not found or empty")
	}

	// Fallback to "scopes" ([]string)
	switch arr := claims["scopes"].(type) {
	case []any:
		log.Printf("[AUTHZ hasScope] Processing 'scopes' as []any with %d entries", len(arr))
		have := make([]string, 0, len(arr))
		for i, v := range arr {
			if sv, _ := v.(string); sv != "" {
				have = append(have, sv)
				log.Printf("[AUTHZ hasScope] Scope %d: '%s'", i+1, sv)
			} else {
				log.Printf("[AUTHZ hasScope] Scope %d: invalid or empty", i+1)
			}
		}
		result := wildcardMatch(have, needed)
		log.Printf("[AUTHZ hasScope] Wildcard match result: %t", result)
		return result
	case []string:
		log.Printf("[AUTHZ hasScope] Processing 'scopes' as []string with %d entries: %v", len(arr), arr)
		result := wildcardMatch(arr, needed)
		log.Printf("[AUTHZ hasScope] Wildcard match result: %t", result)
		return result
	default:
		log.Printf("[AUTHZ hasScope] 'scopes' claim type not recognized: %T", arr)
	}
	log.Printf("[AUTHZ hasScope] FAIL: No matching scope found")
	return false
}

func hasResource(claims jwt.MapClaims, resource string) bool {
	log.Printf("[AUTHZ hasResource] Checking for resource='%s'", resource)

	switch arr := claims["resources"].(type) {
	case []any:
		log.Printf("[AUTHZ hasResource] Processing 'resources' as []any with %d entries", len(arr))
		for i, v := range arr {
			if res, _ := v.(string); res == resource {
				log.Printf("[AUTHZ hasResource] SUCCESS: Found matching resource '%s' at index %d", res, i)
				return true
			}
			log.Printf("[AUTHZ hasResource] Resource %d: '%v' (no match)", i+1, v)
		}
	case []string:
		log.Printf("[AUTHZ hasResource] Processing 'resources' as []string with %d entries: %v", len(arr), arr)
		for i, s := range arr {
			if s == resource {
				log.Printf("[AUTHZ hasResource] SUCCESS: Found matching resource '%s' at index %d", s, i)
				return true
			}
			log.Printf("[AUTHZ hasResource] Resource %d: '%s' (no match)", i+1, s)
		}
	default:
		log.Printf("[AUTHZ hasResource] 'resources' claim type not recognized: %T", arr)
	}
	log.Printf("[AUTHZ hasResource] FAIL: Resource '%s' not found", resource)
	return false
}

// wildcardMatch supports "resource:action" with *, e.g. "invoice:*", "*:read", "*:*".
func wildcardMatch(have []string, needed string) bool {
	log.Printf("[AUTHZ wildcardMatch] Checking wildcard match: have=%v, needed='%s'", have, needed)

	np := strings.SplitN(needed, ":", 2)
	if len(np) != 2 {
		log.Printf("[AUTHZ wildcardMatch] FAIL: Invalid needed format (no colon)")
		return false
	}
	nr, na := np[0], np[1]
	log.Printf("[AUTHZ wildcardMatch] Parsed needed: resource='%s', action='%s'", nr, na)

	for i, h := range have {
		log.Printf("[AUTHZ wildcardMatch] Checking have[%d]: '%s'", i, h)
		hp := strings.SplitN(h, ":", 2)
		if len(hp) != 2 {
			log.Printf("[AUTHZ wildcardMatch] Skipping invalid have format (no colon)")
			continue
		}
		hr, ha := hp[0], hp[1]
		log.Printf("[AUTHZ wildcardMatch] Parsed have: resource='%s', action='%s'", hr, ha)

		resourceMatch := (hr == nr || hr == "*" || nr == "*")
		actionMatch := (ha == na || ha == "*" || na == "*")
		log.Printf("[AUTHZ wildcardMatch] Match check: resourceMatch=%t, actionMatch=%t", resourceMatch, actionMatch)

		if resourceMatch && actionMatch {
			log.Printf("[AUTHZ wildcardMatch] SUCCESS: Wildcard match found")
			return true
		}
	}
	log.Printf("[AUTHZ wildcardMatch] FAIL: No wildcard match found")
	return false
}
