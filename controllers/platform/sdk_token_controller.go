package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// SDKTokenController handles SDK/agent token retrieval endpoints.
// AI agents use these endpoints to pull their delegated JWT-SVID tokens.
type SDKTokenController struct{}

func NewSDKTokenController() *SDKTokenController {
	return &SDKTokenController{}
}

// GetDelegationToken returns the active delegation token for an AI agent.
// Workspace is resolved from the caller's JWT workspace_id claim.
// client_id identifies the agent (resource_servers.id).
//
// GET /uflow/sdk/delegation-token?client_id=<uuid>
func (sc *SDKTokenController) GetDelegationToken(c *gin.Context) {
	// Workspace from the caller's JWT (same pattern as RevokeDelegationToken).
	workspaceID, err := resolveDelegationTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = c.GetHeader("X-Client-ID")
	}
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required (query param or X-Client-ID header)"})
		return
	}
	if _, err := uuid.Parse(clientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id format"})
		return
	}

	tenantDB := config.DB

	var dt models.DelegationToken
	result := tenantDB.
		Where("client_id::text = ? AND workspace_id = ? AND status = 'active'", clientID, workspaceID).
		First(&dt)
	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "No active delegation token found",
			"details": "An admin must delegate a token first via POST /uflow/admin/agents/:id/delegate-token",
		})
		return
	}

	// Check expiry
	if dt.IsExpired() {
		// Mark as expired
		tenantDB.Model(&dt).Update("status", "expired")
		c.JSON(http.StatusGone, gin.H{
			"error":      "Delegation token has expired",
			"expired_at": dt.ExpiresAt,
			"details":    "Admin must re-delegate via POST /uflow/admin/agents/:id/delegate-token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":        dt.Token,
		"spiffe_id":    dt.SpiffeID,
		"permissions":  dt.GetPermissions(),
		"audience":     dt.GetAudience(),
		"expires_at":   dt.ExpiresAt,
		"ttl_seconds":  dt.TTLSeconds,
		"client_id":    dt.ClientID,
		"workspace_id": dt.WorkspaceID,
		"status":       dt.Status,
		"issued_at":    dt.CreatedAt,
		"updated_at":   dt.UpdatedAt,
	})
}

// RevokeDelegationToken revokes the active delegation token for an AI agent.
// POST /uflow/admin/agents/:id/revoke-token
func (sc *SDKTokenController) RevokeDelegationToken(c *gin.Context) {
	workspaceID, err := resolveDelegationTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	clientID := c.Param("id")
	if _, err := uuid.Parse(clientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	tenantDB := config.DB

	result := tenantDB.Model(&models.DelegationToken{}).
		Where("client_id::text = ? AND workspace_id = ? AND status = 'active'", clientID, workspaceID).
		Updates(map[string]interface{}{
			"status":     "revoked",
			"updated_at": time.Now(),
		})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No active delegation token found for this agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "revoked",
		"client_id": clientID,
		"message":   "Delegation token revoked successfully",
	})
}

