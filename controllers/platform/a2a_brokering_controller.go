package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// A2ABrokeringController exposes workspace-scoped CRUD for cross-app (XAA)
// brokering permit/deny rules (a2a_brokering_policies). The token-endpoint
// enforcement gate already reads this table (explicit-deny-wins); this surfaces
// it for governance (plan Journey 7).
//
// Routes (workspace admin JWT):
//
//	GET    /authsec/brokering-policies      list this workspace's rules
//	POST   /authsec/brokering-policies      create a permit/deny rule
//	DELETE /authsec/brokering-policies/:id   delete a rule
type A2ABrokeringController struct{}

func NewA2ABrokeringController() *A2ABrokeringController { return &A2ABrokeringController{} }

type listBrokeringResponse struct {
	Items []models.A2ABrokeringPolicy `json:"items"`
}

type createBrokeringBody struct {
	Side             string  `json:"side"`   // "issuance" | "redemption"
	Effect           string  `json:"effect"` // "permit" | "deny"
	ClientID         *string `json:"client_id,omitempty"`
	ResourceServerID *string `json:"resource_server_id,omitempty"`
}

// List handles GET /authsec/brokering-policies.
func (ctrl *A2ABrokeringController) List(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	var items []models.A2ABrokeringPolicy
	if err := config.DB.WithContext(c.Request.Context()).
		Where("workspace_id = ?", wsID).
		Order("created_at DESC").
		Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't list brokering policies"})
		return
	}
	if items == nil {
		items = []models.A2ABrokeringPolicy{}
	}
	c.JSON(http.StatusOK, listBrokeringResponse{Items: items})
}

// Create handles POST /authsec/brokering-policies.
func (ctrl *A2ABrokeringController) Create(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	var body createBrokeringBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Side != "issuance" && body.Side != "redemption" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "side must be 'issuance' or 'redemption'"})
		return
	}
	if body.Effect != "permit" && body.Effect != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "effect must be 'permit' or 'deny'"})
		return
	}

	now := time.Now().UTC()
	p := models.A2ABrokeringPolicy{
		ID:          uuid.New(),
		WorkspaceID: wsID,
		Side:        body.Side,
		Effect:      body.Effect,
		ClientID:    body.ClientID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if body.ResourceServerID != nil && *body.ResourceServerID != "" {
		rsid, perr := uuid.Parse(*body.ResourceServerID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "invalid resource_server_id"})
			return
		}
		p.ResourceServerID = &rsid
	}

	if err := config.DB.WithContext(c.Request.Context()).Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't create brokering policy"})
		return
	}
	c.JSON(http.StatusCreated, p)
}

// Delete handles DELETE /authsec/brokering-policies/:id.
func (ctrl *A2ABrokeringController) Delete(c *gin.Context) {
	wsID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	id, perr := uuid.Parse(c.Param("id"))
	if perr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	res := config.DB.WithContext(c.Request.Context()).
		Where("id = ? AND workspace_id = ?", id, wsID).
		Delete(&models.A2ABrokeringPolicy{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id.String()})
}
