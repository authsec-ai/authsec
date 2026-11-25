package platform

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Pending changes (tier 3, two people; pending_change, migration 163), under
// /api/iga/v1:
//
//	GET  /pending-changes?state=&kind=&limit=   governance:read
//	GET  /pending-changes/:id                   governance:read
//	POST /pending-changes/:id/approve           governance:approve (re-read from the database; never the requester)
//	POST /pending-changes/:id/reject  {reason}  governance:read + (governance:approve held now, or the requester)
//
// The workspace is the token's; another workspace's change is 404. Writes
// need a verified workspace member session and are audited.

// PendingChangeController serves the routes above.
type PendingChangeController struct {
	db func() *gorm.DB
}

// NewPendingChangeControllerFor builds the controller over the graph
// controller's database.
func NewPendingChangeControllerFor(g *IGAGraphReadController) *PendingChangeController {
	return &PendingChangeController{db: g.db}
}

// NewPendingChangeController is the production controller (config.DB).
func NewPendingChangeController() *PendingChangeController {
	return &PendingChangeController{db: func() *gorm.DB { return config.DB }}
}

// MountPendingChangeRoutes mounts the routes on g (the /api/iga/v1 group).
func MountPendingChangeRoutes(g *gin.RouterGroup, ctl *PendingChangeController) {
	read := middlewares.Require("governance", "read")
	g.GET("/pending-changes", read, ctl.List)
	g.GET("/pending-changes/:id", read, ctl.Get)
	g.POST("/pending-changes/:id/approve", middlewares.Require("governance", "approve"), ctl.Approve)
	g.POST("/pending-changes/:id/reject", read, ctl.Reject)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a transaction under row-level security for the token's workspace.
func (ctl *PendingChangeController) svc() *services.PendingChangeService {
	return services.NewPendingChangeService(ctl.db())
}

func (ctl *PendingChangeController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Deciding a change requires a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Deciding a change requires a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// List handles GET /pending-changes.
func (ctl *PendingChangeController) List(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.PendingChangeFilter{State: c.Query("state"), Kind: c.Query("kind")}
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > services.MaxGovPage {
			govErrorOut(c, services.GovBadParam("limit", "limit must be between 1 and 200."))
			return
		}
		f.Limit = n
	}
	rows, err := ctl.svc().List(c.Request.Context(), ws, f)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// Get handles GET /pending-changes/:id.
func (ctl *PendingChangeController) Get(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return
	}
	v, err := ctl.svc().Get(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

func (ctl *PendingChangeController) target(c *gin.Context) (uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	return ws, actor, id, true
}

// Approve handles POST /pending-changes/:id/approve.
func (ctl *PendingChangeController) Approve(c *gin.Context) {
	ws, actor, id, ok := ctl.target(c)
	if !ok {
		return
	}
	before, after, err := ctl.svc().Approve(c.Request.Context(), ws, id, actor)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "pending_change.approve", "pending_change", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

// Reject handles POST /pending-changes/:id/reject.
func (ctl *PendingChangeController) Reject(c *gin.Context) {
	ws, actor, id, ok := ctl.target(c)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if c.Request.ContentLength != 0 {
		if err := strictJSON(c, &body); err != nil {
			govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"reason\": \"...\"}."))
			return
		}
	}
	before, after, err := ctl.svc().Reject(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "pending_change.reject", "pending_change", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}
