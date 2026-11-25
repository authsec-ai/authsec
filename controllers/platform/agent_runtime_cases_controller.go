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

// Agent runtime cases (SPEC-secops-backend-upgrade.md W3 / P2), under
// /api/iga/v1/agent-runtime, with the alert routes' rights:
//
//	GET  /cases                     governance:read or discovery:read
//	     ?state=&severity=&assignee=<uuid>|none&agent=<identity or workload id>&cursor=&limit=
//	GET  /cases/:id                 governance:read or discovery:read
//	POST /cases                     governance:enforce  {alert_ids, title?, exercise_id?}       tier 1
//	POST /cases/:id/assign          governance:enforce  {assignee_user_id|null}                tier 1
//	POST /cases/:id/notes           governance:enforce  {body}                                 tier 1
//	POST /cases/:id/split           governance:enforce  {alert_ids, title?}                    tier 1
//	POST /cases/:id/alerts          governance:enforce  {alert_ids}                            tier 1
//	POST /cases/:id/severity        governance:enforce  {severity} (raise only)                tier 0
//	POST /cases/:id/close           governance:enforce  {outcome, reason?, duplicate_of?}      tier 0
//	POST /cases/:id/reopen          governance:enforce  {reason?}                              tier 1
//	POST /cases/:id/export          governance:enforce                                         tier 0
//
// The workspace is the token's; another workspace's case or alert is 404,
// exactly like an unknown one. Writes need a verified workspace member
// session (humanActor) and write an audit_events row; the service logs
// every change in iga_gov_event. Tier 0 writes still need
// governance:enforce until W5's tier map replaces the per-route right.

// AgentRuntimeCasesController serves the routes above.
type AgentRuntimeCasesController struct {
	db func() *gorm.DB
}

// NewAgentRuntimeCasesControllerFor builds the controller over the graph
// controller's database.
func NewAgentRuntimeCasesControllerFor(g *IGAGraphReadController) *AgentRuntimeCasesController {
	return &AgentRuntimeCasesController{db: g.db}
}

// NewAgentRuntimeCasesController is the production controller (config.DB).
func NewAgentRuntimeCasesController() *AgentRuntimeCasesController {
	return &AgentRuntimeCasesController{db: func() *gorm.DB { return config.DB }}
}

// MountAgentRuntimeCaseRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group).
func MountAgentRuntimeCaseRoutes(g *gin.RouterGroup, ctl *AgentRuntimeCasesController) {
	read := middlewares.RequireAny(authz.Need{Resource: "governance", Action: "read"}, authz.Need{Resource: "discovery", Action: "read"})
	write := middlewares.Require("governance", "enforce")
	RegisterAgentRuntimeCaseRoutes(g.Group("/agent-runtime"), ctl, read, write)
}

// RegisterAgentRuntimeCaseRoutes is the route table.
func RegisterAgentRuntimeCaseRoutes(g gin.IRoutes, ctl *AgentRuntimeCasesController, read, write gin.HandlerFunc) {
	g.GET("/cases", read, ctl.requireSchema, ctl.ListCases)
	g.GET("/cases/:id", read, ctl.requireSchema, ctl.GetCase)
	g.POST("/cases", write, ctl.requireSchema, ctl.CreateCase)
	g.POST("/cases/:id/assign", write, ctl.requireSchema, ctl.AssignCase)
	g.POST("/cases/:id/notes", write, ctl.requireSchema, ctl.AddNote)
	g.POST("/cases/:id/split", write, ctl.requireSchema, ctl.SplitCase)
	g.POST("/cases/:id/alerts", write, ctl.requireSchema, ctl.MoveAlerts)
	g.POST("/cases/:id/severity", write, ctl.requireSchema, ctl.RaiseSeverity)
	g.POST("/cases/:id/close", write, ctl.requireSchema, ctl.CloseCase)
	g.POST("/cases/:id/reopen", write, ctl.requireSchema, ctl.ReopenCase)
	g.POST("/cases/:id/export", write, ctl.requireSchema, ctl.ExportCase)
}

// requireSchema answers 503 with the reason until migrations 150 and 186 verify.
func (ctl *AgentRuntimeCasesController) requireSchema(c *gin.Context) {
	// TENANT-EXEMPT: the 186 schema check reads the Postgres catalog only.
	if err := services.RequireAgentCases(ctl.db()); err != nil {
		govErrorOut(c, err)
	}
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *AgentRuntimeCasesController) svc() *services.AgentCaseService {
	return services.NewAgentCaseService(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AgentRuntimeCasesController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Case changes require a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Case changes require a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// begin resolves the workspace, :id (when withID) and the actor; ok false
// means the response is written.
func (ctl *AgentRuntimeCasesController) begin(c *gin.Context, withID bool) (ws, id, actor uuid.UUID, ok bool) {
	if ws, ok = policyWorkspace(c); !ok {
		return
	}
	if withID {
		if id, ok = agentAlertPathID(c); !ok {
			return
		}
	}
	actor, ok = ctl.actor(c, ws)
	return
}

// bind decodes an optional JSON body into dst.
func agentCaseBind(c *gin.Context, dst any, shape string) bool {
	if c.Request.ContentLength == 0 {
		return true
	}
	if err := c.ShouldBindJSON(dst); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: "+shape+"."))
		return false
	}
	return true
}

// ListCases handles GET /cases.
func (ctl *AgentRuntimeCasesController) ListCases(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AgentCaseFilter{State: c.Query("state"), Severity: c.Query("severity")}
	switch v := c.Query("assignee"); v {
	case "":
	case "none":
		f.Unassigned = true
	default:
		id, err := uuid.Parse(v)
		if err != nil {
			govErrorOut(c, services.GovBadParam("assignee", "assignee must be a user id or none."))
			return
		}
		f.Assignee = &id
	}
	if v := c.Query("agent"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			govErrorOut(c, services.GovBadParam("agent", "agent must be an identity or workload id."))
			return
		}
		f.Agent = &id
	}
	limit := 0
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > services.MaxGovPage {
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

// GetCase handles GET /cases/:id.
func (ctl *AgentRuntimeCasesController) GetCase(c *gin.Context) {
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

func (ctl *AgentRuntimeCasesController) done(c *gin.Context, ws uuid.UUID, action, id string, status int, data, audit any, err error) {
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), action, "agent_case", id, status, nil, audit)
	c.JSON(status, gin.H{"data": data})
}

// CreateCase handles POST /cases.
func (ctl *AgentRuntimeCasesController) CreateCase(c *gin.Context) {
	ws, _, actor, ok := ctl.begin(c, false)
	if !ok {
		return
	}
	var body services.AgentCaseCreate
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"alert_ids\": [...], \"title\": \"...\"}."))
		return
	}
	cs, err := ctl.svc().Create(c.Request.Context(), ws, actor, body)
	id := ""
	if cs != nil {
		id = cs.ID.String()
	}
	ctl.done(c, ws, "agent_case.create", id, http.StatusCreated, cs, map[string]any{"alert_ids": body.AlertIDs}, err)
}

type agentCaseAssignBody struct {
	AssigneeUserID *uuid.UUID `json:"assignee_user_id"`
}

// AssignCase handles POST /cases/:id/assign.
func (ctl *AgentRuntimeCasesController) AssignCase(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseAssignBody
	if !agentCaseBind(c, &body, `{"assignee_user_id": "<uuid>" | null}`) {
		return
	}
	cs, err := ctl.svc().Assign(c.Request.Context(), ws, id, actor, body.AssigneeUserID)
	ctl.done(c, ws, "agent_case.assign", id.String(), http.StatusOK, cs, map[string]any{"assignee_user_id": body.AssigneeUserID}, err)
}

type agentCaseNoteBody struct {
	Body string `json:"body"`
}

// AddNote handles POST /cases/:id/notes.
func (ctl *AgentRuntimeCasesController) AddNote(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseNoteBody
	if !agentCaseBind(c, &body, `{"body": "..."}`) {
		return
	}
	n, err := ctl.svc().AddNote(c.Request.Context(), ws, id, actor, body.Body)
	audit := map[string]any{}
	if n != nil {
		audit["note_id"] = n.ID
	}
	ctl.done(c, ws, "agent_case.note", id.String(), http.StatusCreated, n, audit, err)
}

type agentCaseAlertsBody struct {
	AlertIDs []uuid.UUID `json:"alert_ids"`
	Title    string      `json:"title"`
}

// SplitCase handles POST /cases/:id/split; it answers the new case.
func (ctl *AgentRuntimeCasesController) SplitCase(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseAlertsBody
	if !agentCaseBind(c, &body, `{"alert_ids": [...], "title": "..."}`) {
		return
	}
	cs, err := ctl.svc().Split(c.Request.Context(), ws, id, actor, body.AlertIDs, body.Title)
	audit := map[string]any{"alert_ids": body.AlertIDs}
	if cs != nil {
		audit["new_case_id"] = cs.ID
	}
	ctl.done(c, ws, "agent_case.split", id.String(), http.StatusCreated, cs, audit, err)
}

// MoveAlerts handles POST /cases/:id/alerts.
func (ctl *AgentRuntimeCasesController) MoveAlerts(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseAlertsBody
	if !agentCaseBind(c, &body, `{"alert_ids": [...]}`) {
		return
	}
	cs, err := ctl.svc().MoveAlerts(c.Request.Context(), ws, id, actor, body.AlertIDs)
	ctl.done(c, ws, "agent_case.move_alerts", id.String(), http.StatusOK, cs, map[string]any{"alert_ids": body.AlertIDs}, err)
}

type agentCaseSeverityBody struct {
	Severity string `json:"severity"`
}

// RaiseSeverity handles POST /cases/:id/severity.
func (ctl *AgentRuntimeCasesController) RaiseSeverity(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseSeverityBody
	if !agentCaseBind(c, &body, `{"severity": "high"}`) {
		return
	}
	cs, err := ctl.svc().RaiseSeverity(c.Request.Context(), ws, id, actor, body.Severity)
	ctl.done(c, ws, "agent_case.raise_severity", id.String(), http.StatusOK, cs, map[string]any{"severity": body.Severity}, err)
}

// CloseCase handles POST /cases/:id/close.
func (ctl *AgentRuntimeCasesController) CloseCase(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body services.AgentCaseClose
	if !agentCaseBind(c, &body, `{"outcome": "true_positive", "reason": "..."}`) {
		return
	}
	cs, err := ctl.svc().Close(c.Request.Context(), ws, id, actor, body)
	ctl.done(c, ws, "agent_case.close", id.String(), http.StatusOK, cs,
		map[string]any{"outcome": body.Outcome, "reason": body.Reason, "duplicate_of": body.DuplicateOf}, err)
}

type agentCaseReasonBody struct {
	Reason string `json:"reason"`
}

// ReopenCase handles POST /cases/:id/reopen.
func (ctl *AgentRuntimeCasesController) ReopenCase(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	var body agentCaseReasonBody
	if !agentCaseBind(c, &body, `{"reason": "..."}`) {
		return
	}
	cs, err := ctl.svc().Reopen(c.Request.Context(), ws, id, actor, body.Reason)
	ctl.done(c, ws, "agent_case.reopen", id.String(), http.StatusOK, cs, map[string]any{"reason": body.Reason}, err)
}

// ExportCase handles POST /cases/:id/export.
func (ctl *AgentRuntimeCasesController) ExportCase(c *gin.Context) {
	ws, id, actor, ok := ctl.begin(c, true)
	if !ok {
		return
	}
	ex, err := ctl.svc().Export(c.Request.Context(), ws, id, actor)
	audit := map[string]any{}
	if ex != nil {
		audit["sha256"] = ex.SHA256
	}
	ctl.done(c, ws, "agent_case.export", id.String(), http.StatusOK, ex, audit, err)
}
