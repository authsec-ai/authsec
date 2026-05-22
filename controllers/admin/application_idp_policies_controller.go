package admin

import (
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ApplicationIDPPoliciesController manages the optional Application→IDP
// whitelist. When an Application has no policy rows, every workspace IDP is
// allowed (default-allow). Operators opt INTO restriction by adding rows.
//
// Routes (mounted under /authsec/applications/:id):
//
//	GET     /identity-providers           list policies for the Application
//	POST    /identity-providers           add a policy {identity_provider_id, enabled}
//	DELETE  /identity-providers/:idp_id   remove the policy
type ApplicationIDPPoliciesController struct {
	service *services.IdentityProviderService
}

func NewApplicationIDPPoliciesController() *ApplicationIDPPoliciesController {
	return &ApplicationIDPPoliciesController{
		service: services.NewIdentityProviderService(config.DB),
	}
}

type addAppIDPRequest struct {
	IdentityProviderID string `json:"identity_provider_id" binding:"required"`
	Enabled            *bool  `json:"enabled,omitempty"`
}

// List handles GET /authsec/applications/:id/identity-providers.
func (ctrl *ApplicationIDPPoliciesController) List(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	rows, err := ctrl.service.ListApplicationPolicies(workspaceID, applicationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// Add handles POST /authsec/applications/:id/identity-providers.
// Defaults enabled=true when the field is omitted.
func (ctrl *ApplicationIDPPoliciesController) Add(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	var req addAppIDPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	idpID, err := uuid.Parse(req.IdentityProviderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_provider_id"})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	row, err := ctrl.service.PinIDPToApplication(workspaceID, applicationID, idpID, enabled)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, row)
}

// Remove handles DELETE /authsec/applications/:id/identity-providers/:idp_id.
func (ctrl *ApplicationIDPPoliciesController) Remove(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	applicationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid application id"})
		return
	}
	idpID, err := uuid.Parse(c.Param("idp_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	if err := ctrl.service.UnpinIDPFromApplication(workspaceID, applicationID, idpID); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "removed"})
}
