package platform

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// EnforcementBindingController handles enforcement binding CRUD for agents.
type EnforcementBindingController struct {
	svc *services.EnforcementBindingService
}

// NewEnforcementBindingController creates a new enforcement binding controller.
func NewEnforcementBindingController(svc *services.EnforcementBindingService) *EnforcementBindingController {
	return &EnforcementBindingController{svc: svc}
}

// GetBinding returns the current enforcement binding for an agent.
// GET /authsec/discovery/agents/:id/enforcement-binding
func (ctl *EnforcementBindingController) GetBinding(c *gin.Context) {
	wsID, ok := ctl.workspace(c)
	if !ok {
		return
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	binding, err := ctl.svc.Get(c.Request.Context(), wsID, agentID)
	if err != nil {
		bindingError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": binding})
}

// PutDraft creates or updates a draft enforcement binding for an agent.
// PUT /authsec/discovery/agents/:id/enforcement-binding/draft
func (ctl *EnforcementBindingController) PutDraft(c *gin.Context) {
	wsID, ok := ctl.workspace(c)
	if !ok {
		return
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	ifMatch := c.GetHeader("If-Match")
	idempotencyKey := c.GetHeader("Idempotency-Key")
	if idempotencyKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Idempotency-Key header is required"})
		return
	}

	var req services.PutBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	binding, err := ctl.svc.PutDraft(c.Request.Context(), wsID, agentID, ifMatch, req)
	if err != nil {
		bindingError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": binding})
}

// GetResolution returns the resolved effective binding for an agent.
// GET /authsec/discovery/agents/:id/enforcement-binding/resolution
func (ctl *EnforcementBindingController) GetResolution(c *gin.Context) {
	wsID, ok := ctl.workspace(c)
	if !ok {
		return
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	resolution, err := ctl.svc.Resolve(c.Request.Context(), wsID, agentID)
	if err != nil {
		bindingError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": resolution})
}

func (ctl *EnforcementBindingController) workspace(c *gin.Context) (uuid.UUID, bool) {
	wsStr := c.GetString("workspace_id")
	if wsStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
		return uuid.Nil, false
	}
	wsID, err := uuid.Parse(wsStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id"})
		return uuid.Nil, false
	}
	return wsID, true
}

func bindingError(c *gin.Context, err error) {
	var se *services.StatusError
	if errors.As(err, &se) {
		c.JSON(se.Status, gin.H{"error": se.Message, "code": se.Code})
		return
	}
	if errors.Is(err, services.ErrBindingNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "enforcement binding not found"})
		return
	}
	if errors.Is(err, services.ErrBindingConflict) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
}
