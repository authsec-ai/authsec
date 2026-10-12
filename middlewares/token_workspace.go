package middlewares

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// workspaceInputKeys are the names under which requests name a workspace
// (path parameter, query parameter, or top-level JSON field).
var workspaceInputKeys = []string{"workspace_id", "tenant_id", "workspaceId", "tenantId"}

// crossWorkspaceRoutes may name a workspace other than the token's because the
// handler itself checks the caller's membership of the named workspace.
var crossWorkspaceRoutes = map[string]bool{
	"/authsec/workspaces/:workspace_id/switch": true,
}

// enforceTokenWorkspace rejects a request that names a workspace other than
// the one in its verified token. The workspace is resolved once, from the
// token; a workspace_id in the path, query or body can only repeat it.
//
// Many handlers read workspace_id from the request instead of the token,
// which let an admin of one workspace read and write another (AS-006). The
// mismatch answers 404, so a caller cannot confirm another workspace exists.
func enforceTokenWorkspace(c *gin.Context, tokenWorkspace string) bool {
	if crossWorkspaceRoutes[c.FullPath()] {
		return true
	}

	var named []string
	for _, k := range workspaceInputKeys {
		if v := c.Param(k); v != "" {
			named = append(named, v)
		}
		for _, v := range c.QueryArray(k) {
			if v != "" {
				named = append(named, v)
			}
		}
	}
	if strings.Contains(c.ContentType(), "json") {
		if body, err := peekBody(c); err == nil && len(body) > 0 {
			var m map[string]interface{}
			if json.Unmarshal(body, &m) == nil {
				for _, k := range workspaceInputKeys {
					if v, ok := m[k].(string); ok && v != "" {
						named = append(named, v)
					}
				}
			}
		}
	}

	for _, v := range named {
		if !strings.EqualFold(strings.TrimSpace(v), tokenWorkspace) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return false
		}
	}
	return true
}
