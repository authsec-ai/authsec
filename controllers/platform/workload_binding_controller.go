package platform

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// WorkloadBindingController handles per-workload policy binding endpoints.
type WorkloadBindingController struct {
	svc *services.WorkloadBindingService
}

func NewWorkloadBindingController(svc *services.WorkloadBindingService) *WorkloadBindingController {
	return &WorkloadBindingController{svc: svc}
}

// Get returns active/pending bindings for a workload.
func (ctl *WorkloadBindingController) Get(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	wid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "not_found", "message": "Not found."}})
		return
	}
	bindings, err := ctl.svc.GetForWorkload(c.Request.Context(), actor.WorkspaceID, wid)
	if err != nil {
		se, ok := err.(*services.StatusError)
		if !ok {
			se = &services.StatusError{Status: http.StatusInternalServerError, Code: "internal", Message: "Internal error."}
		}
		c.JSON(se.Status, gin.H{"error": gin.H{"code": se.Code, "message": se.Message}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": bindings})
}

// Put creates or updates a workload binding.
func (ctl *WorkloadBindingController) Put(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	wid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "not_found", "message": "Not found."}})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_body", "message": "Could not read body."}})
		return
	}
	var req services.PutWorkloadBindingRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_body", "message": "Invalid JSON."}})
		return
	}
	binding, err := ctl.svc.PutBinding(c.Request.Context(), actor.WorkspaceID, wid, req)
	if err != nil {
		se, ok := err.(*services.StatusError)
		if !ok {
			se = &services.StatusError{Status: http.StatusInternalServerError, Code: "internal", Message: "Internal error."}
		}
		c.JSON(se.Status, gin.H{"error": gin.H{"code": se.Code, "message": se.Message}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": binding})
}
