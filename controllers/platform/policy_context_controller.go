package platform

import (
	"net/http"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PolicyContextController is the /api/iga/v2/runtime-policies/contexts API.
type PolicyContextController struct {
	svc *services.PolicyContextService
}

// NewPolicyContextController builds the controller.
func NewPolicyContextController(svc *services.PolicyContextService) *PolicyContextController {
	return &PolicyContextController{svc: svc}
}

// Prepare handles POST /api/iga/v2/runtime-policies/contexts — create a
// prepared policy context.
func (ctl *PolicyContextController) Prepare(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}

	var req models.PolicyContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writePolicy(c, 0, nil, &services.StatusError{
			Status: http.StatusBadRequest, Code: "invalid_document", Message: "The request body is not valid JSON.",
		})
		return
	}

	resp, err := ctl.svc.Prepare(c.Request.Context(), actor, actor.WorkspaceID, req)
	if err != nil {
		writePolicy(c, 0, nil, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": resp})
}

// Get handles GET /api/iga/v2/runtime-policies/contexts/:id — retrieve a
// prepared policy context.
func (ctl *PolicyContextController) Get(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}

	contextID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{
			Status: http.StatusNotFound, Code: "not_found", Message: "Not found.",
		})
		return
	}

	resp, svcErr := ctl.svc.Get(c.Request.Context(), actor.WorkspaceID, contextID, actor.UserID)
	if svcErr != nil {
		writePolicy(c, 0, nil, svcErr)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": resp})
}
