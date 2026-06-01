package admin

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	sharedCtrl "github.com/authsec-ai/authsec/controllers/shared"
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

// RevokeDelegationToken revokes the active delegation token for an AI agent.
// POST /uflow/admin/agents/:id/revoke-token
func (sc *SDKTokenController) RevokeDelegationToken(c *gin.Context) {
	workspaceID, err := sharedCtrl.ResolveWorkspaceIDFromTokenPtr(c)
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

