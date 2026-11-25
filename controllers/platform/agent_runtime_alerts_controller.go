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

// Agent runtime alerts (SPEC-agent-runtime-visibility.md §5.7, §10 Q3), with
// versioned detection rules (SecOps F6), the alert lifecycle (F8) and alert
// suppressions (P6), under /api/iga/v1/agent-runtime:
//
//	GET    /alerts                       governance:read or discovery:read
//	       ?state=&severity=&detection=&identity_id=&suppressed=&cursor=&limit=
//	GET    /alerts/:id                   governance:read or discovery:read
//	POST   /alerts/:id/acknowledge       governance:enforce   {reason?}
//	POST   /alerts/:id/resolve           governance:enforce   {outcome, reason?}
//	POST   /alerts/:id/reopen            governance:enforce   {reason}
//	GET    /alert-settings               governance:read or discovery:read
//	PUT    /alert-settings               governance:enforce   proposes a rule version:
//	                                     200 applied, 202 waiting for a second person
//	GET    /alert-settings/versions      governance:read or discovery:read  ?state=&limit=
//	POST   /alert-settings/versions/:id/approve  governance:approve  {reason?}
//	POST   /alert-settings/versions/:id/reject   governance:approve, or the proposer {reason}
//	GET    /suppressions                 governance:read or discovery:read  ?state=&identity_id=&limit=
//	GET    /suppressions/:id             governance:read or discovery:read
//	POST   /suppressions                 governance:enforce   {identity_id, detection, instance_digest?, reason, days?}
//	POST   /suppressions/:id/approve     governance:approve   {reason?}
//	POST   /suppressions/:id/reject      governance:approve, or the requester {reason}
//	POST   /suppressions/:id/renew       governance:enforce   {reason, days?}
//	POST   /suppressions/:id/end         governance:enforce   {reason}
//	GET    /siem-endpoints               governance:read or discovery:read
//	POST   /siem-endpoints               governance:enforce   {url, secret?}
//	DELETE /siem-endpoints/:id           governance:enforce
//	POST   /siem-endpoints/:id/test      governance:enforce
//
// The workspace is the token's (AuthMiddleware); another workspace's alert,
// rule version, suppression or endpoint is 404, exactly like an unknown one.
// Writes need a verified workspace member session (the actor rule,
// humanActor) and write an audit_events row. Approvals are re-checked
// against the database (governance:approve now, and never the requester).
// Errors use the {"error": {code, message, detail}} envelope of the
// governance routes.

// AgentRuntimeAlertsController serves the routes above.
type AgentRuntimeAlertsController struct {
	db func() *gorm.DB
}

// NewAgentRuntimeAlertsControllerFor builds the controller over the graph
// controller's database (see NewAgentRuntimeControllerFor).
func NewAgentRuntimeAlertsControllerFor(g *IGAGraphReadController) *AgentRuntimeAlertsController {
	return &AgentRuntimeAlertsController{db: g.db}
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
	approve := middlewares.Require("governance", "approve")
	decide := middlewares.RequireAny(authz.Need{Resource: "governance", Action: "approve"}, authz.Need{Resource: "governance", Action: "enforce"})
	RegisterAgentRuntimeAlertRoutes(g.Group("/agent-runtime"), ctl, read, write, approve, decide)
}

// RegisterAgentRuntimeAlertRoutes is the route table (one table, so tests
// mount the same one). approve guards approvals (governance:approve); decide
// guards rejections (governance:approve, or governance:enforce for a
// requester withdrawing their own: the service decides which).
func RegisterAgentRuntimeAlertRoutes(g gin.IRoutes, ctl *AgentRuntimeAlertsController, read, write, approve, decide gin.HandlerFunc) {
	g.GET("/alerts", read, ctl.requireSchema, ctl.ListAlerts)
	g.GET("/alerts/:id", read, ctl.requireSchema, ctl.GetAlert)
	g.POST("/alerts/:id/acknowledge", write, ctl.requireSchema, ctl.AcknowledgeAlert)
	g.POST("/alerts/:id/resolve", write, ctl.requireSchema, ctl.ResolveAlert)
	g.POST("/alerts/:id/reopen", write, ctl.requireSchema, ctl.ReopenAlert)
	g.GET("/alert-settings", read, ctl.requireSchema, ctl.GetSettings)
	g.PUT("/alert-settings", write, ctl.requireSchema, ctl.PutSettings)
	g.GET("/alert-settings/versions", read, ctl.requireSchema, ctl.ListRuleVersions)
	g.POST("/alert-settings/versions/:id/approve", approve, ctl.requireSchema, ctl.ApproveRuleVersion)
	g.POST("/alert-settings/versions/:id/reject", decide, ctl.requireSchema, ctl.RejectRuleVersion)
	g.GET("/suppressions", read, ctl.requireSchema, ctl.ListSuppressions)
	g.GET("/suppressions/:id", read, ctl.requireSchema, ctl.GetSuppression)
	g.POST("/suppressions", write, ctl.requireSchema, ctl.CreateSuppression)
	g.POST("/suppressions/:id/approve", approve, ctl.requireSchema, ctl.ApproveSuppression)
	g.POST("/suppressions/:id/reject", decide, ctl.requireSchema, ctl.RejectSuppression)
	g.POST("/suppressions/:id/renew", write, ctl.requireSchema, ctl.RenewSuppression)
	g.POST("/suppressions/:id/end", write, ctl.requireSchema, ctl.EndSuppression)
	g.GET("/siem-endpoints", read, ctl.requireSchema, ctl.ListSIEMEndpoints)
	g.POST("/siem-endpoints", write, ctl.requireSchema, ctl.CreateSIEMEndpoint)
	g.DELETE("/siem-endpoints/:id", write, ctl.requireSchema, ctl.DeleteSIEMEndpoint)
	g.POST("/siem-endpoints/:id/test", write, ctl.requireSchema, ctl.TestSIEMEndpoint)
}

// requireSchema answers 503 with the reason until migrations 150 and
// 164-166 verify.
func (ctl *AgentRuntimeAlertsController) requireSchema(c *gin.Context) {
	// TENANT-EXEMPT: the 150 schema check reads the Postgres catalog only.
	if err := services.RequireAgentAlerts(ctl.db()); err != nil {
		govErrorOut(c, err)
	}
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

// queryLimit parses ?limit= (1..200; 0 when absent).
func queryLimit(c *gin.Context) (int, bool) {
	v := c.Query("limit")
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 200 {
		govErrorOut(c, services.GovBadParam("limit", "limit must be between 1 and 200."))
		return 0, false
	}
	return n, true
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
	switch c.Query("suppressed") {
	case "":
	case "true", "false":
		v := c.Query("suppressed") == "true"
		f.Suppressed = &v
	default:
		govErrorOut(c, services.GovBadParam("suppressed", "suppressed must be true or false."))
		return
	}
	limit, ok := queryLimit(c)
	if !ok {
		return
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
	Reason  string `json:"reason"`
	Outcome string `json:"outcome"`
}

// decision is the workspace, path id, verified actor and optional {reason,
// outcome} body of a write on one row; false: an answer was written.
func (ctl *AgentRuntimeAlertsController) decision(c *gin.Context) (ws, id, actor uuid.UUID, body agentAlertReasonBody, ok bool) {
	if ws, ok = policyWorkspace(c); !ok {
		return
	}
	if id, ok = agentAlertPathID(c); !ok {
		return
	}
	if actor, ok = ctl.actor(c, ws); !ok {
		return
	}
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"reason": "..."}.`))
			return ws, id, actor, body, false
		}
	}
	return ws, id, actor, body, true
}

func (ctl *AgentRuntimeAlertsController) transition(c *gin.Context, to string) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	svc := ctl.svc()
	var (
		a      *services.AgentAlert
		err    error
		action string
	)
	switch to {
	case services.AgentAlertResolved:
		action = "agent_alert.resolve"
		a, err = svc.Resolve(c.Request.Context(), ws, id, actor, body.Outcome, body.Reason)
	case services.AgentAlertReopened:
		action = "agent_alert.reopen"
		a, err = svc.Reopen(c.Request.Context(), ws, id, actor, body.Reason)
	default:
		action = "agent_alert.acknowledge"
		a, err = svc.Acknowledge(c.Request.Context(), ws, id, actor, body.Reason)
	}
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), action, "agent_alert", id.String(), http.StatusOK, nil,
		map[string]any{"state": a.State, "reason": a.Reason, "outcome": a.Outcome})
	c.JSON(http.StatusOK, gin.H{"data": a})
}

// AcknowledgeAlert handles POST /alerts/:id/acknowledge.
func (ctl *AgentRuntimeAlertsController) AcknowledgeAlert(c *gin.Context) {
	ctl.transition(c, services.AgentAlertAcknowledged)
}

// ResolveAlert handles POST /alerts/:id/resolve ({outcome, reason?}).
func (ctl *AgentRuntimeAlertsController) ResolveAlert(c *gin.Context) {
	ctl.transition(c, services.AgentAlertResolved)
}

// ReopenAlert handles POST /alerts/:id/reopen ({reason}).
func (ctl *AgentRuntimeAlertsController) ReopenAlert(c *gin.Context) {
	ctl.transition(c, services.AgentAlertReopened)
}

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

// PutSettings handles PUT /alert-settings (omitted fields keep their value):
// it proposes a detection rule version. data stays the ACTIVE settings (as
// before F6); change says whether this request applied (200) or waits for a
// second person (202).
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
	before, err := ctl.svc().Settings(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	ch, err := ctl.svc().ProposeSettings(c.Request.Context(), ws, actor, u)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	status := http.StatusOK
	if ch.Pending {
		status = http.StatusAccepted
	}
	target := ws.String()
	if ch.Version != nil {
		target = ch.Version.ID.String()
	}
	auditAdminMutation(c, ws.String(), "agent_alert.settings_propose", "agent_detection_rule_version", target, status,
		map[string]any{"settings": before}, ch)
	c.JSON(status, gin.H{"data": ch.Settings, "change": ch})
}

// ListRuleVersions handles GET /alert-settings/versions.
func (ctl *AgentRuntimeAlertsController) ListRuleVersions(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	limit, ok := queryLimit(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().ListRuleVersions(c.Request.Context(), ws, c.Query("state"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// ApproveRuleVersion handles POST /alert-settings/versions/:id/approve.
func (ctl *AgentRuntimeAlertsController) ApproveRuleVersion(c *gin.Context) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	ch, err := ctl.svc().ApproveRuleVersion(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.rules_approve", "agent_detection_rule_version", id.String(), http.StatusOK, nil, ch)
	c.JSON(http.StatusOK, gin.H{"data": ch.Settings, "change": ch})
}

// RejectRuleVersion handles POST /alert-settings/versions/:id/reject.
func (ctl *AgentRuntimeAlertsController) RejectRuleVersion(c *gin.Context) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	v, err := ctl.svc().RejectRuleVersion(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.rules_reject", "agent_detection_rule_version", id.String(), http.StatusOK, nil, v)
	c.JSON(http.StatusOK, gin.H{"data": v})
}

// ListSuppressions handles GET /suppressions.
func (ctl *AgentRuntimeAlertsController) ListSuppressions(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	limit, ok := queryLimit(c)
	if !ok {
		return
	}
	var identity *uuid.UUID
	if v := c.Query("identity_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			govErrorOut(c, services.GovBadParam("identity_id", "identity_id must be a UUID."))
			return
		}
		identity = &id
	}
	rows, err := ctl.svc().ListSuppressions(c.Request.Context(), ws, c.Query("state"), identity, limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// GetSuppression handles GET /suppressions/:id.
func (ctl *AgentRuntimeAlertsController) GetSuppression(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	v, err := ctl.svc().GetSuppression(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

// suppressionStatus is 202 while a request waits for a second person, 201
// when it is in force at once (break-glass).
func suppressionStatus(r *services.AgentAlertSuppressionResult) int {
	if r.Pending {
		return http.StatusAccepted
	}
	return http.StatusCreated
}

// CreateSuppression handles POST /suppressions (tier 3).
func (ctl *AgentRuntimeAlertsController) CreateSuppression(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var req services.AgentAlertSuppressionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {identity_id, detection, instance_digest?, reason, days?}."))
		return
	}
	r, err := ctl.svc().RequestSuppression(c.Request.Context(), ws, actor, req)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	status := suppressionStatus(r)
	auditAdminMutation(c, ws.String(), "agent_alert.suppression_request", "agent_alert_suppression", r.Suppression.ID.String(), status, nil, r)
	c.JSON(status, gin.H{"data": r})
}

// ApproveSuppression handles POST /suppressions/:id/approve.
func (ctl *AgentRuntimeAlertsController) ApproveSuppression(c *gin.Context) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	r, err := ctl.svc().ApproveSuppression(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.suppression_approve", "agent_alert_suppression", id.String(), http.StatusOK, nil, r)
	c.JSON(http.StatusOK, gin.H{"data": r})
}

// RejectSuppression handles POST /suppressions/:id/reject.
func (ctl *AgentRuntimeAlertsController) RejectSuppression(c *gin.Context) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	r, err := ctl.svc().RejectSuppression(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.suppression_reject", "agent_alert_suppression", id.String(), http.StatusOK, nil, r)
	c.JSON(http.StatusOK, gin.H{"data": r})
}

type renewSuppressionBody struct {
	Reason string `json:"reason"`
	Days   int    `json:"days"`
}

// RenewSuppression handles POST /suppressions/:id/renew (tier 3).
func (ctl *AgentRuntimeAlertsController) RenewSuppression(c *gin.Context) {
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
	var body renewSuppressionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {reason, days?}."))
		return
	}
	r, err := ctl.svc().RenewSuppression(c.Request.Context(), ws, id, actor, body.Reason, body.Days)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	status := suppressionStatus(r)
	auditAdminMutation(c, ws.String(), "agent_alert.suppression_renew", "agent_alert_suppression", r.Suppression.ID.String(), status,
		map[string]any{"renewal_of": id}, r)
	c.JSON(status, gin.H{"data": r})
}

// EndSuppression handles POST /suppressions/:id/end.
func (ctl *AgentRuntimeAlertsController) EndSuppression(c *gin.Context) {
	ws, id, actor, body, ok := ctl.decision(c)
	if !ok {
		return
	}
	r, err := ctl.svc().EndSuppression(c.Request.Context(), ws, id, actor, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_alert.suppression_end", "agent_alert_suppression", id.String(), http.StatusOK, nil, r)
	c.JSON(http.StatusOK, gin.H{"data": r})
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
