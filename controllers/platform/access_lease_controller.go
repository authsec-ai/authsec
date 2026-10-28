package platform

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// AccessLeaseController serves the access-lease surface under /api/iga/v2.
//
// A lease is the materialised grant produced by an approved access request. It is
// time-bounded and use-bounded: redemption increments use_count, and once max_uses
// is reached the lease is consumed. An administrator can revoke a lease at any time.
type AccessLeaseController struct {
	svc *services.AccessLeaseService
}

// NewAccessLeaseController constructs the controller.
func NewAccessLeaseController(svc *services.AccessLeaseService) *AccessLeaseController {
	return &AccessLeaseController{svc: svc}
}

// workspace resolves the caller's workspace from the token. Never from the body.
func (ctl *AccessLeaseController) workspace(c *gin.Context) (string, bool) {
	raw := c.GetString("workspace_id")
	if raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	return raw, true
}

// accessLeaseError maps a service error to the right HTTP status.
func accessLeaseError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrAccessLeaseNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, services.ErrAccessLeaseState):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAccessLeaseExhausted):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAccessRedeemDuplicate):
		// A duplicate redeem is not an error from the caller's perspective; it is
		// idempotent. Return 200 so a retry after a lost response does not fail.
		c.JSON(http.StatusOK, gin.H{"status": "already_redeemed"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
	}
}

// GetLease handles GET /api/iga/v2/access-leases/:id.
func (ctl *AccessLeaseController) GetLease(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	out, err := ctl.svc.GetLease(c.Request.Context(), ws, id)
	if err != nil {
		accessLeaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// RedeemLease handles POST /api/iga/v2/access-leases/:id/redeem.
func (ctl *AccessLeaseController) RedeemLease(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	var body struct {
		OperationID string `json:"operation_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := ctl.svc.RedeemLease(c.Request.Context(), ws, id, body.OperationID); err != nil {
		accessLeaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "redeemed"})
}

// RevokeLease handles POST /api/iga/v2/access-leases/:id/revoke.
func (ctl *AccessLeaseController) RevokeLease(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	if err := ctl.svc.RevokeLease(c.Request.Context(), ws, id); err != nil {
		accessLeaseError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
