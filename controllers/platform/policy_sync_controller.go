package platform

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// PolicySyncController handles collector policy sync requests.
type PolicySyncController struct {
	svc *services.PolicySyncService
}

func NewPolicySyncController(svc *services.PolicySyncService) *PolicySyncController {
	return &PolicySyncController{svc: svc}
}

// Sync handles POST /api/iga/v2/collectors/self/runtime-policy-sync.
func (ctl *PolicySyncController) Sync(c *gin.Context) {
	p := middlewares.CollectorFrom(c)
	if p == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "unauthenticated", "message": "No collector."}})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_body", "message": "Could not read body."}})
		return
	}
	var req services.PolicySyncRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_body", "message": "Invalid JSON."}})
			return
		}
	}
	resp, err := ctl.svc.Sync(c.Request.Context(), p, req)
	if err != nil {
		se, ok := err.(*services.StatusError)
		if !ok {
			se = &services.StatusError{Status: http.StatusInternalServerError, Code: "internal", Message: "Internal error."}
		}
		c.JSON(se.Status, gin.H{"error": gin.H{"code": se.Code, "message": se.Message}})
		return
	}
	c.JSON(http.StatusOK, resp)
}
