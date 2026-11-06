package platform

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime gateway admin (SPEC-agent-runtime-gateway.md §8), under
// /api/iga/v1/agent-runtime:
//
//	GET    /gateways                      governance:read
//	POST   /gateways                      governance:enforce  {name} -> credential, shown once
//	GET    /gateways/:id                  governance:read
//	PATCH  /gateways/:id                  governance:enforce  {name, version}
//	POST   /gateways/:id/rotate           governance:enforce  -> new credential, shown once
//	DELETE /gateways/:id                  governance:enforce  revoke
//	GET    /gateway-settings              governance:read
//	PUT    /gateway-settings              governance:enforce  {mode, cache_ttl_seconds, decision_retention_days, version}
//	GET    /tool-policies                 governance:read
//	POST   /tool-policies                 governance:enforce
//	POST   /tool-policies/evaluate        governance:read     dry run (records nothing)
//	GET    /tool-policies/:id             governance:read
//	PUT    /tool-policies/:id             governance:enforce  (version required)
//	DELETE /tool-policies/:id             governance:enforce
//	GET    /gateway-decisions             governance:read
//	       ?gateway_id=&decision=&kind=&subject_id=&source=&record_type=&since=&until=&cursor=&limit=
//
// The workspace is the token's (AuthMiddleware); another workspace's
// gateway or policy is 404, exactly like an unknown one. Writes need a
// verified workspace member session (humanActor) and write an audit_events
// row (never a credential: only its prefix). Errors use the {"error": {code,
// message, detail}} envelope of the governance routes.

// AgentGatewayController serves the routes above.
type AgentGatewayController struct {
	db func() *gorm.DB
}

// NewAgentGatewayControllerFor builds the controller over the graph
// controller's database (as NewAgentRuntimeAlertsControllerFor).
func NewAgentGatewayControllerFor(g *IGAGraphReadController) *AgentGatewayController {
	return &AgentGatewayController{db: g.db}
}

// NewAgentGatewayController is the production controller (config.DB).
func NewAgentGatewayController() *AgentGatewayController {
	return &AgentGatewayController{db: func() *gorm.DB { return config.DB }}
}

// MountAgentGatewayRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group) with their permissions.
func MountAgentGatewayRoutes(g *gin.RouterGroup, ctl *AgentGatewayController) {
	RegisterAgentGatewayRoutes(g.Group("/agent-runtime"), ctl,
		middlewares.Require("governance", "read"), middlewares.Require("governance", "enforce"))
}

// RegisterAgentGatewayRoutes is the route table.
func RegisterAgentGatewayRoutes(g gin.IRoutes, ctl *AgentGatewayController, read, write gin.HandlerFunc) {
	g.GET("/gateways", read, ctl.ListGateways)
	g.POST("/gateways", write, ctl.CreateGateway)
	g.GET("/gateways/:id", read, ctl.GetGateway)
	g.PATCH("/gateways/:id", write, ctl.RenameGateway)
	g.POST("/gateways/:id/rotate", write, ctl.RotateGateway)
	g.DELETE("/gateways/:id", write, ctl.RevokeGateway)
	g.GET("/gateway-settings", read, ctl.GetSettings)
	g.PUT("/gateway-settings", write, ctl.PutSettings)
	g.GET("/tool-policies", read, ctl.ListPolicies)
	g.POST("/tool-policies", write, ctl.CreatePolicy)
	g.POST("/tool-policies/evaluate", read, ctl.EvaluatePolicies)
	g.GET("/tool-policies/:id", read, ctl.GetPolicy)
	g.PUT("/tool-policies/:id", write, ctl.UpdatePolicy)
	g.DELETE("/tool-policies/:id", write, ctl.DeletePolicy)
	g.GET("/gateway-decisions", read, ctl.ListDecisions)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a transaction under row-level security for the token's workspace.
func (ctl *AgentGatewayController) svc() *services.AgentGatewayService {
	return services.AgentGatewayServiceFor(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AgentGatewayController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Gateway changes require a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Gateway changes require a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

func agentGatewayPathID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return uuid.Nil, false
	}
	return id, true
}

// writeTarget is the workspace, the verified actor and (withID) the path id.
func (ctl *AgentGatewayController) writeTarget(c *gin.Context, withID bool) (uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	var id uuid.UUID
	if withID {
		if id, ok = agentGatewayPathID(c); !ok {
			return uuid.Nil, uuid.Nil, uuid.Nil, false
		}
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return uuid.Nil, uuid.Nil, uuid.Nil, false
	}
	return ws, actor, id, true
}

/* --------------------------------- gateways ------------------------------- */

// ListGateways handles GET /gateways.
func (ctl *AgentGatewayController) ListGateways(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	gws, err := ctl.svc().ListGateways(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gws})
}

// GetGateway handles GET /gateways/:id.
func (ctl *AgentGatewayController) GetGateway(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return
	}
	g, err := ctl.svc().GetGateway(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": g})
}

type agentGatewayNameBody struct {
	Name    string `json:"name"`
	Version *int   `json:"version"`
}

func credentialResponse(c *gin.Context, status int, g services.AgentGatewayView, cred string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"data": gin.H{
		"gateway":    g,
		"credential": cred,
		"pdp": gin.H{
			"evaluation_path":  "/authsec/pdp/access/v1/evaluation",
			"evaluations_path": "/authsec/pdp/access/v1/evaluations",
			"decisions_path":   "/authsec/pdp/v1/decisions",
			"hints_path":       "/authsec/pdp/v1/policy-hints",
			"header":           "Authorization: Bearer <credential>",
		},
	}, "meta": gin.H{"note": "the credential is shown only in this response; set it as AUTHSEC_GATEWAY_CREDENTIAL on the gateway"}})
}

// CreateGateway handles POST /gateways.
func (ctl *AgentGatewayController) CreateGateway(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	var body agentGatewayNameBody
	if err := strictJSON(c, &body); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"name\": \"...\"}."))
		return
	}
	g, cred, err := ctl.svc().CreateGateway(c.Request.Context(), ws, actor, body.Name)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.create", "agent_gateway", g.ID.String(), http.StatusCreated, nil, g)
	credentialResponse(c, http.StatusCreated, g, cred)
}

// RenameGateway handles PATCH /gateways/:id.
func (ctl *AgentGatewayController) RenameGateway(c *gin.Context) {
	ws, _, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	var body agentGatewayNameBody
	if err := strictJSON(c, &body); err != nil || body.Version == nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"name\": \"...\", \"version\": N}."))
		return
	}
	before, after, err := ctl.svc().RenameGateway(c.Request.Context(), ws, id, body.Name, *body.Version)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.rename", "agent_gateway", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

// RotateGateway handles POST /gateways/:id/rotate.
func (ctl *AgentGatewayController) RotateGateway(c *gin.Context) {
	ws, _, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	g, cred, err := ctl.svc().RotateGateway(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.rotate", "agent_gateway", id.String(), http.StatusOK, nil,
		map[string]any{"credential_prefix": g.CredentialPrefix})
	credentialResponse(c, http.StatusOK, g, cred)
}

// RevokeGateway handles DELETE /gateways/:id.
func (ctl *AgentGatewayController) RevokeGateway(c *gin.Context) {
	ws, _, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	before, after, err := ctl.svc().RevokeGateway(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.revoke", "agent_gateway", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

/* --------------------------------- settings ------------------------------- */

// GetSettings handles GET /gateway-settings.
func (ctl *AgentGatewayController) GetSettings(c *gin.Context) {
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

// PutSettings handles PUT /gateway-settings (omitted fields keep their value).
func (ctl *AgentGatewayController) PutSettings(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	var u services.AgentGatewaySettingsUpdate
	if err := strictJSON(c, &u); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be a JSON settings object."))
		return
	}
	before, after, err := ctl.svc().UpdateSettings(c.Request.Context(), ws, actor, u)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.settings_update", "agent_gateway_setting", ws.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

/* --------------------------------- policies ------------------------------- */

// ListPolicies handles GET /tool-policies.
func (ctl *AgentGatewayController) ListPolicies(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	ps, err := ctl.svc().ListPolicies(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": ps})
}

// GetPolicy handles GET /tool-policies/:id.
func (ctl *AgentGatewayController) GetPolicy(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return
	}
	p, err := ctl.svc().GetPolicy(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": p})
}

func bindPolicyInput(c *gin.Context) (services.AgentToolPolicyInput, bool) {
	var in services.AgentToolPolicyInput
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be a JSON tool policy: "+err.Error()))
		return in, false
	}
	return in, true
}

// CreatePolicy handles POST /tool-policies.
func (ctl *AgentGatewayController) CreatePolicy(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	in, ok := bindPolicyInput(c)
	if !ok {
		return
	}
	p, err := ctl.svc().CreatePolicy(c.Request.Context(), ws, actor, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_tool_policy.create", "agent_tool_policy", p.ID, http.StatusCreated, nil, p)
	c.JSON(http.StatusCreated, gin.H{"data": p})
}

// UpdatePolicy handles PUT /tool-policies/:id.
func (ctl *AgentGatewayController) UpdatePolicy(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	in, ok := bindPolicyInput(c)
	if !ok {
		return
	}
	before, after, err := ctl.svc().UpdatePolicy(c.Request.Context(), ws, id, actor, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_tool_policy.update", "agent_tool_policy", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

// DeletePolicy handles DELETE /tool-policies/:id.
func (ctl *AgentGatewayController) DeletePolicy(c *gin.Context) {
	ws, _, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	before, err := ctl.svc().DeletePolicy(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_tool_policy.delete", "agent_tool_policy", id.String(), http.StatusNoContent, before, nil)
	c.Status(http.StatusNoContent)
}

type agentGatewayDryRunBody struct {
	agentgateway.EvaluationRequest
	GatewayID string `json:"gateway_id"`
}

// EvaluatePolicies handles POST /tool-policies/evaluate: an AuthZEN
// evaluation request (plus an optional gateway_id to simulate) in, the
// decision and every policy's part in it out. Nothing is recorded.
func (ctl *AgentGatewayController) EvaluatePolicies(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	raw, err := c.GetRawData()
	if err != nil {
		govErrorOut(c, services.GovBadParam("body", "could not read the request body"))
		return
	}
	var body agentGatewayDryRunBody
	if err := json.Unmarshal(raw, &body); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be an AuthZEN evaluation request."))
		return
	}
	out, err := ctl.svc().DryRun(c.Request.Context(), ws, body.GatewayID, body.EvaluationRequest)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

/* --------------------------------- decisions ------------------------------ */

func optTime(c *gin.Context, name string) (*time.Time, bool) {
	v := c.Query(name)
	if v == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		govErrorOut(c, services.GovBadParam(name, name+" must be an RFC 3339 time."))
		return nil, false
	}
	return &t, true
}

// ListDecisions handles GET /gateway-decisions.
func (ctl *AgentGatewayController) ListDecisions(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AgentGatewayDecisionFilter{Decision: c.Query("decision"), Kind: c.Query("kind"),
		SubjectID: c.Query("subject_id"), Source: c.Query("source"), RecordType: c.Query("record_type")}
	if v := c.Query("gateway_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			govErrorOut(c, services.GovBadParam("gateway_id", "gateway_id must be a UUID."))
			return
		}
		f.GatewayID = &id
	}
	if f.Since, ok = optTime(c, "since"); !ok {
		return
	}
	if f.Until, ok = optTime(c, "until"); !ok {
		return
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
	rows, next, err := ctl.svc().ListDecisions(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}
