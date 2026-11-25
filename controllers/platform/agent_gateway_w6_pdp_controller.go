package platform

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// W6 PDP routes (gateway credential "Authorization: Bearer agw_…" only; it
// alone decides workspace and gateway):
//
//	GET  /authsec/pdp/v1/provider-keys        the provider keys AuthSec holds for this gateway
//	                                          (Cache-Control: no-store; never logged)
//	POST /authsec/pdp/v1/holds                hold a call outside its argument bounds
//	GET  /authsec/pdp/v1/holds/:id            a hold's state (this gateway's holds only)
//	POST /authsec/pdp/v1/holds/:id/consume    let an approved hold's call through once

// MountAgentGatewayW6PDPRoutes mounts the routes next to the PDP's.
func MountAgentGatewayW6PDPRoutes(g gin.IRoutes, ctl *AgentGatewayPDPController) {
	g.GET("/pdp/v1/provider-keys", ctl.ProviderKeys)
	g.POST("/pdp/v1/holds", ctl.CreateHold)
	g.GET("/pdp/v1/holds/:id", ctl.HoldStatus)
	g.POST("/pdp/v1/holds/:id/consume", ctl.ConsumeHold)
}

// ProviderKeys handles GET /pdp/v1/provider-keys.
func (ctl *AgentGatewayPDPController) ProviderKeys(c *gin.Context) {
	p, _, ok := ctl.principal(c, false)
	if !ok {
		return
	}
	out, err := ctl.svc().ProviderSecretsFor(c.Request.Context(), *p)
	if err != nil {
		log.Printf("[agent-gateway-pdp] stage=provider_keys workspace=%s gateway=%s outcome=error", p.WorkspaceID, p.GatewayID)
		pdpError(c, http.StatusServiceUnavailable, "the provider keys could not be read; retry")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, out)
}

func pdpGovError(c *gin.Context, p *services.AgentGatewayPrincipal, stage string, err error) {
	var ge *services.GovError
	if errors.As(err, &ge) {
		c.AbortWithStatusJSON(ge.Status, gin.H{"error": gin.H{"code": ge.Code, "message": ge.Message}})
		return
	}
	log.Printf("[agent-gateway-pdp] stage=%s workspace=%s gateway=%s outcome=error err=%v", stage, p.WorkspaceID, p.GatewayID, err)
	pdpError(c, http.StatusInternalServerError, "the hold could not be processed; deny")
}

func pdpHoldID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pdpError(c, http.StatusNotFound, "not found")
		return uuid.Nil, false
	}
	return id, true
}

// CreateHold handles POST /pdp/v1/holds.
func (ctl *AgentGatewayPDPController) CreateHold(c *gin.Context) {
	p, body, ok := ctl.principal(c, true)
	if !ok {
		return
	}
	var in services.AgentGatewayHoldRequest
	if err := decodePDPBody(body, &in); err != nil {
		pdpError(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	t, err := ctl.svc().CreateHold(c.Request.Context(), *p, in)
	if err != nil {
		pdpGovError(c, p, "hold", err)
		return
	}
	c.JSON(http.StatusCreated, t)
}

// HoldStatus handles GET /pdp/v1/holds/:id.
func (ctl *AgentGatewayPDPController) HoldStatus(c *gin.Context) {
	p, _, ok := ctl.principal(c, false)
	if !ok {
		return
	}
	id, ok := pdpHoldID(c)
	if !ok {
		return
	}
	t, err := ctl.svc().HoldStatus(c.Request.Context(), *p, id)
	if err != nil {
		pdpGovError(c, p, "hold_status", err)
		return
	}
	c.JSON(http.StatusOK, t)
}

// ConsumeHold handles POST /pdp/v1/holds/:id/consume.
func (ctl *AgentGatewayPDPController) ConsumeHold(c *gin.Context) {
	p, body, ok := ctl.principal(c, true)
	if !ok {
		return
	}
	id, ok := pdpHoldID(c)
	if !ok {
		return
	}
	var in services.AgentGatewayHoldConsume
	if err := decodePDPBody(body, &in); err != nil {
		pdpError(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	t, err := ctl.svc().ConsumeHold(c.Request.Context(), *p, id, in)
	if err != nil {
		pdpGovError(c, p, "hold_consume", err)
		return
	}
	c.JSON(http.StatusOK, t)
}
