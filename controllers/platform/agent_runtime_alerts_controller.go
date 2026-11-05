package platform

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/authz"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime alerts (SPEC-agent-runtime-visibility.md §5.7, §10 Q3),
// under /api/iga/v1/agent-runtime:
//
//	GET    /alerts                       governance:read or discovery:read
//	       ?state=&severity=&detection=&identity_id=&cursor=&limit=
//	GET    /alerts/:id                   governance:read or discovery:read
//	POST   /alerts/:id/acknowledge       governance:enforce   {reason}
//	POST   /alerts/:id/resolve           governance:enforce   {reason}
//	GET    /alert-settings               governance:read or discovery:read
//	PUT    /alert-settings               governance:enforce
//	GET    /siem-endpoints               governance:read or discovery:read
//	POST   /siem-endpoints               governance:enforce   {url, secret?}
//	DELETE /siem-endpoints/:id           governance:enforce
//	POST   /siem-endpoints/:id/test      governance:enforce
//
// The workspace is the token's (AuthMiddleware); another workspace's alert
// or endpoint is 404, exactly like an unknown one. Writes need a verified
// workspace member session (the actor rule, humanActor) and write an
// audit_events row. Errors use the {"error": {code, message, detail}}
// envelope of the governance routes.

// AgentRuntimeAlertsController serves the routes above.
type AgentRuntimeAlertsController struct {
	db func() *gorm.DB
}

// NewAgentRuntimeAlertsController is the production controller (config.DB).
func NewAgentRuntimeAlertsController() *AgentRuntimeAlertsController {
	return &AgentRuntimeAlertsController{db: func() *gorm.DB { return config.DB }}
}

// NewAgentRuntimeAlertsControllerWith builds a controller over db (tests).
func NewAgentRuntimeAlertsControllerWith(db *gorm.DB) *AgentRuntimeAlertsController {
	return &AgentRuntimeAlertsController{db: func() *gorm.DB { return db }}
}

// MountAgentRuntimeAlertRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group) with their permissions.
func MountAgentRuntimeAlertRoutes(g *gin.RouterGroup, ctl *AgentRuntimeAlertsController) {
	read := middlewares.RequireAny(authz.Need{Resource: "governance", Action: "read"}, authz.Need{Resource: "discovery", Action: "read"})
	write := middlewares.Require("governance", "enforce")
	RegisterAgentRuntimeAlertRoutes(g.Group("/agent-runtime"), ctl, read, write)
}

// RegisterAgentRuntimeAlertRoutes is the route table (one table, so tests
// mount the same one).
func RegisterAgentRuntimeAlertRoutes(g gin.IRoutes, ctl *AgentRuntimeAlertsController, read, write gin.HandlerFunc) {
	g.GET("/alerts", read, ctl.ListAlerts)
	g.GET("/alerts/:id", read, ctl.GetAlert)
	g.POST("/alerts/:id/acknowledge", write, ctl.AcknowledgeAlert)
	g.POST("/alerts/:id/resolve", write, ctl.ResolveAlert)
	g.GET("/alert-settings", read, ctl.GetSettings)
	g.PUT("/alert-settings", write, ctl.PutSettings)
	g.GET("/siem-endpoints", read, ctl.ListSIEMEndpoints)
	g.POST("/siem-endpoints", write, ctl.CreateSIEMEndpoint)
	g.DELETE("/siem-endpoints/:id", write, ctl.DeleteSIEMEndpoint)
	g.POST("/siem-endpoints/:id/test", write, ctl.TestSIEMEndpoint)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *AgentRuntimeAlertsController) svc() *services.AgentAlertService {
	return services.NewAgentAlertService(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AgentRuntimeAlertsController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Alert changes require a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Alert changes require a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// agentAlertPathID parses :id; a malformed id is 404 (it names nothing).
func agentAlertPathID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return uuid.Nil, false
	}
	return id, true
}

// ListAlerts handles GET /alerts.
func (ctl *AgentRuntimeAlertsController) ListAlerts(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AgentAlertFilter{State: c.Query("state"), Severity: c.Query("severity"), Detection: c.Query("detection")}
	if v := c.Query("identity_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			govErrorOut(c, services.GovBadParam("identity_id", "identity_id must be a UUID."))
			return
		}
		f.IdentityID = &id
	}
	limit := 0
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			govErrorOut(c, services.GovBadParam("limit", "limit must be between 1 and 200."))
			return
		}
		limit = n
	}
	rows, next, err := ctl.svc().List(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}

// GetAlert handles GET /alerts/:id.
func (ctl *AgentRuntimeAlertsController) GetAlert(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
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

type agentAlertReasonBody struct {
	Reason string `json:"reason"`
}

func (ctl *AgentRuntimeAlertsController) transition(c *gin.Context, resolve bool) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body agentAlertReasonBody
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"reason\": \"...\"}."))
			return
		}
	}
	svc := ctl.svc()
	var (
		a   *services.AgentAlert
		err error
	)
	action := "agent_alert.acknowledge"
	if resolve {
		action = "agent_alert.resolve"
		a, err = svc.Resolve(c.Request.Context(), ws, id, actor, body.Reason)
	} else {
		a, err = svc.Acknowledge(c.Request.Context(), ws, id, actor, body.Reason)
	}
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), action, "agent_alert", id.String(), http.StatusOK, nil,
		map[string]any{"state": a.State, "reason": a.Reason})
	c.JSON(http.StatusOK, gin.H{"data": a})
}

// AcknowledgeAlert handles POST /alerts/:id/acknowledge.
func (ctl *AgentRuntimeAlertsController) AcknowledgeAlert(c *gin.Context) { ctl.transition(c, false) }

// ResolveAlert handles POST /alerts/:id/resolve.
func (ctl *AgentRuntimeAlertsController) ResolveAlert(c *gin.Context) { ctl.transition(c, true) }

// GetSettings handles GET /alert-settings.
func (ctl *AgentRuntimeAlertsController) GetSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	s, err := ctl.svc().Settings(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": s})
}

// PutSettings handles PUT /alert-settings (omitted fields keep their value).
func (ctl *AgentRuntimeAlertsController) PutSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var u services.AgentAlertSettingsUpdate
	if err := c.ShouldBindJSON(&u); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be a JSON settings object."))
		return
	}
	s, err := ctl.svc().UpdateSettings(c.Request.Context(), ws, actor, u)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.settings_update", "agent_alert_setting", ws.String(), http.StatusOK, nil, s)
	c.JSON(http.StatusOK, gin.H{"data": s})
}

// ListSIEMEndpoints handles GET /siem-endpoints.
func (ctl *AgentRuntimeAlertsController) ListSIEMEndpoints(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	eps, err := ctl.svc().ListSIEMEndpoints(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": eps})
}

type createSIEMEndpointBody struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// CreateSIEMEndpoint handles POST /siem-endpoints. The signing secret is in
// this response only.
func (ctl *AgentRuntimeAlertsController) CreateSIEMEndpoint(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body createSIEMEndpointBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"url\": \"https://...\", \"secret\": \"...\"}."))
		return
	}
	ep, secret, err := ctl.svc().CreateSIEMEndpoint(c.Request.Context(), ws, actor, body.URL, body.Secret)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.siem_endpoint_create", "agent_alert_siem_endpoint", ep.ID.String(),
		http.StatusCreated, nil, map[string]any{"url": ep.URL})
	c.JSON(http.StatusCreated, gin.H{"data": gin.H{"endpoint": ep, "secret": secret,
		"signature": "X-AuthSec-Signature: sha256=<hex HMAC-SHA256(secret, X-AuthSec-Timestamp + \".\" + body)>"}})
}

// DeleteSIEMEndpoint handles DELETE /siem-endpoints/:id.
func (ctl *AgentRuntimeAlertsController) DeleteSIEMEndpoint(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	if _, ok := ctl.actor(c, ws); !ok {
		return
	}
	if err := ctl.svc().DeleteSIEMEndpoint(c.Request.Context(), ws, id); err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.siem_endpoint_delete", "agent_alert_siem_endpoint", id.String(), http.StatusNoContent, nil, nil)
	c.Status(http.StatusNoContent)
}

// TestSIEMEndpoint handles POST /siem-endpoints/:id/test.
func (ctl *AgentRuntimeAlertsController) TestSIEMEndpoint(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	if _, ok := ctl.actor(c, ws); !ok {
		return
	}
	res, err := ctl.svc().TestSIEMEndpoint(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.siem_endpoint_test", "agent_alert_siem_endpoint", id.String(), http.StatusOK, nil, res)
	c.JSON(http.StatusOK, gin.H{"data": res})
}
