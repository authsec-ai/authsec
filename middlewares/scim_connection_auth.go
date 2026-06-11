package middlewares

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
)

// SCIMConnectionAuth authenticates a request hitting
//
//	/scim/v2/c/:scim_connection_id/...
//
// using the opaque connection ID in the path plus the Bearer token in the
// Authorization header. The token is hashed (SHA-256) and compared in constant
// time against scim_connections.token_hash for the matching row.
//
// On success the handler downstream sees the same context the legacy SCIM
// routes set up — workspace_id, client_id, project_id — so existing handler
// logic keeps working. The new fields workspace_id and scim_connection_id
// are also set so handlers that get rewritten can drop the legacy keys.
//
// On any failure the request is short-circuited with 401 and a SCIM-style
// error body.
func SCIMConnectionAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		connectionID := strings.TrimSpace(c.Param("scim_connection_id"))
		if connectionID == "" {
			scimUnauthorized(c, "scim_connection_id required in path")
			return
		}

		token, err := extractBearerToken(c)
		if err != nil || token == "" {
			scimUnauthorized(c, "bearer token required")
			return
		}

		var conn models.SCIMConnection
		if err := config.DB.Where("id = ?", connectionID).First(&conn).Error; err != nil {
			scimUnauthorized(c, "scim connection not found")
			return
		}

		if conn.Status != "active" {
			scimUnauthorized(c, "scim connection is not active")
			return
		}

		// Constant-time compare against the current token hash.
		incoming := sha256.Sum256([]byte(token))
		incomingHex := hex.EncodeToString(incoming[:])
		matchesCurrent := subtle.ConstantTimeCompare([]byte(incomingHex), []byte(conn.TokenHash)) == 1
		// Also accept the previous token during its grace window (rotation overlap).
		matchesPrevious := false
		if !matchesCurrent && conn.PreviousTokenHash != nil && conn.PreviousTokenExpiresAt != nil &&
			conn.PreviousTokenExpiresAt.After(time.Now()) {
			matchesPrevious = subtle.ConstantTimeCompare([]byte(incomingHex), []byte(*conn.PreviousTokenHash)) == 1
		}
		if !matchesCurrent && !matchesPrevious {
			scimUnauthorized(c, "invalid scim bearer token")
			return
		}

		// Populate the same context keys the legacy SCIM middleware sets so
		// existing handlers don't care which path invoked them.
		workspaceID := conn.WorkspaceID.String()
		c.Set("workspace_id", workspaceID)
		c.Set("scim_connection_id", conn.ID.String())

		if conn.DefaultClientID != nil {
			c.Set("scim_default_client_id", conn.DefaultClientID.String())
		}
		if conn.DefaultProjectID != nil {
			c.Set("scim_default_project_id", conn.DefaultProjectID.String())
		}

		c.Next()
	}
}

func scimUnauthorized(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":   "401",
		"detail":   message,
		"scimType": "invalidCredentials",
	})
}
