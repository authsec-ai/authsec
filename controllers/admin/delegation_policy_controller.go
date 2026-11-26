package admin

import (
	"net/http"

	sharedCtrl "github.com/authsec-ai/authsec/controllers/shared"
	"github.com/gin-gonic/gin"
)

// DelegationPolicyController serves the admin self-introspection the
// delegation UI uses. Delegation-policy CRUD lives in
// controllers/platform (/authsec/uflow/delegation-policies).
type DelegationPolicyController struct{}

func NewDelegationPolicyController() *DelegationPolicyController {
	return &DelegationPolicyController{}
}

// GetMyRolesAndPermissions returns the authenticated admin's roles and permissions.
// This is used by the delegation UI to show what permissions can be delegated.
// @Summary     Get my roles and permissions
// @Tags        Delegation
// @Produce     json
// @Security    BearerAuth
// @Success     200 {object} map[string]interface{}
// @Failure     401 {object} map[string]string
// @Router      /uflow/admin/me/roles-permissions [get]
func (dc *DelegationPolicyController) GetMyRolesAndPermissions(c *gin.Context) {
	workspaceID, err := sharedCtrl.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	userID := sharedCtrl.ContextStringValue(c, "user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	tid := workspaceID.String()

	// Get all tenant roles
	roles, err := getTenantRoleNames(tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get roles: " + err.Error()})
		return
	}

	// Get all tenant permissions
	permissions, err := getTenantPermissionStrings(tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get permissions: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":      userID,
		"workspace_id": tid,
		"roles":        roles,
		"permissions":  permissions,
	})
}
