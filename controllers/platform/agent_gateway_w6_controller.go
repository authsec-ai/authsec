package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// W6 admin routes under /api/iga/v1/agent-runtime:
//
//	GET    /gateway-provider-keys              governance:read     fingerprints only, never a key
//	POST   /gateway-provider-keys              governance:enforce  {name, provider, key, gateway_id?, provider_key_id?}
//	GET    /gateway-provider-keys/:id          governance:read
//	POST   /gateway-provider-keys/:id/rotate   governance:enforce  {key}
//	DELETE /gateway-provider-keys/:id          governance:enforce  revoke (destroyed in Vault)
//	GET    /gateway-agent-keys                 governance:read
//	POST   /gateway-agent-keys                 governance:enforce  {name, spiffe_id and/or workload_id, ...} -> key, shown once
//	POST   /gateway-agent-keys/:id/rotate      governance:enforce  -> key, shown once
//	DELETE /gateway-agent-keys/:id             governance:enforce  {reason?}
//	GET    /gateway-holds                      governance:read     ?state=
//	GET    /gateway-holds/:id                  governance:read     the held values while open
//	POST   /gateway-holds/:id/decide           governance:approve  {decision: approve|deny, reason}
//	GET    /join-settings                      governance:read
//	PUT    /join-settings                      governance:enforce  {egress_hosts, flow_log_groups, version}
//	GET    /usage-reconciliation               governance:read     ?label=&from=&to=
//
// The workspace is the token's; another workspace's key or hold is 404.
// Audit rows never carry a key (only fingerprints and prefixes) nor a held
// value.

// MountAgentGatewayW6Routes mounts the routes on the /api/iga/v1 group.
func MountAgentGatewayW6Routes(g *gin.RouterGroup, ctl *AgentGatewayController) {
	RegisterAgentGatewayW6Routes(g.Group("/agent-runtime", TierGuard()), ctl, middlewares.Require("governance", "read"),
		middlewares.Require("governance", "enforce"), middlewares.Require("governance", "approve"))
}

// RegisterAgentGatewayW6Routes is the route table.
func RegisterAgentGatewayW6Routes(g gin.IRoutes, ctl *AgentGatewayController, read, write, approve gin.HandlerFunc) {
	g.GET("/gateway-provider-keys", read, ctl.ListProviderKeys)
	g.POST("/gateway-provider-keys", write, ctl.AddProviderKey)
	g.GET("/gateway-provider-keys/:id", read, ctl.GetProviderKey)
	g.POST("/gateway-provider-keys/:id/rotate", write, ctl.RotateProviderKey)
	g.DELETE("/gateway-provider-keys/:id", write, ctl.RevokeProviderKey)
	g.GET("/gateway-agent-keys", read, ctl.ListAgentKeys)
	g.POST("/gateway-agent-keys", write, ctl.IssueAgentKey)
	g.POST("/gateway-agent-keys/:id/rotate", write, ctl.RotateAgentKey)
	g.DELETE("/gateway-agent-keys/:id", write, ctl.RevokeAgentKey)
	g.GET("/gateway-holds", read, ctl.ListHolds)
	g.GET("/gateway-holds/:id", read, ctl.GetHold)
	g.POST("/gateway-holds/:id/decide", approve, ctl.DecideHold)
	g.GET("/join-settings", read, ctl.GetJoinSettings)
	g.PUT("/join-settings", write, ctl.PutJoinSettings)
	g.GET("/usage-reconciliation", read, ctl.ListUsageReconciliation)
}

/* ---------------------------------- provider keys -------------------------- */

func (ctl *AgentGatewayController) ListProviderKeys(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	out, err := ctl.svc().ListProviderKeys(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) GetProviderKey(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return
	}
	out, err := ctl.svc().GetProviderKey(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) AddProviderKey(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	var in services.AgentGatewayProviderKeyInput
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"name\", \"provider\", \"key\", \"gateway_id\"?, \"provider_key_id\"?}."))
		return
	}
	out, err := ctl.svc().AddProviderKey(c.Request.Context(), ws, actor, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.provider_key_add", "agent_gateway_provider_key", out.ID.String(), http.StatusCreated, nil, out)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{"data": out})
}

func (ctl *AgentGatewayController) RotateProviderKey(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	var in struct {
		Key string `json:"key"`
	}
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"key\": \"...\"}."))
		return
	}
	out, err := ctl.svc().RotateProviderKey(c.Request.Context(), ws, actor, id, in.Key)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.provider_key_rotate", "agent_gateway_provider_key", id.String(), http.StatusOK,
		nil, map[string]any{"key_fingerprint": out.KeyFingerprint})
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) RevokeProviderKey(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	out, err := ctl.svc().RevokeProviderKey(c.Request.Context(), ws, actor, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.provider_key_revoke", "agent_gateway_provider_key", id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, gin.H{"data": out})
}

/* ------------------------------------ agent keys --------------------------- */

func agentKeyResponse(c *gin.Context, status int, k *services.AgentGatewayAgentKeyView, key string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"data": gin.H{"agent_key": k, "key": key},
		"meta": gin.H{"note": "the key is shown only in this response; the agent presents it together with its bound workload identity"}})
}

func (ctl *AgentGatewayController) ListAgentKeys(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	out, err := ctl.svc().ListAgentKeys(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) IssueAgentKey(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	var in services.AgentGatewayAgentKeyInput
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be a JSON agent key request."))
		return
	}
	out, key, err := ctl.svc().IssueAgentKey(c.Request.Context(), ws, actor, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.agent_key_issue", "agent_gateway_agent_key", out.ID.String(), http.StatusCreated, nil, out)
	agentKeyResponse(c, http.StatusCreated, out, key)
}

func (ctl *AgentGatewayController) RotateAgentKey(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	out, key, err := ctl.svc().RotateAgentKey(c.Request.Context(), ws, actor, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.agent_key_rotate", "agent_gateway_agent_key", id.String(), http.StatusOK,
		nil, map[string]any{"key_prefix": out.KeyPrefix})
	agentKeyResponse(c, http.StatusOK, out, key)
}

func (ctl *AgentGatewayController) RevokeAgentKey(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if c.Request.ContentLength > 0 {
		if err := strictJSON(c, &in); err != nil {
			govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"reason\": \"...\"}."))
			return
		}
	}
	out, err := ctl.svc().RevokeAgentKey(c.Request.Context(), ws, actor, id, in.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.agent_key_revoke", "agent_gateway_agent_key", id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, gin.H{"data": out})
}

/* --------------------------------------- holds ----------------------------- */

func (ctl *AgentGatewayController) ListHolds(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	out, err := ctl.svc().ListHolds(c.Request.Context(), ws, c.Query("state"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) GetHold(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentGatewayPathID(c)
	if !ok {
		return
	}
	out, err := ctl.svc().GetHold(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) DecideHold(c *gin.Context) {
	ws, actor, id, ok := ctl.writeTarget(c, true)
	if !ok {
		return
	}
	var in struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"decision\": \"approve\"|\"deny\", \"reason\"}."))
		return
	}
	before, after, err := ctl.svc().DecideHold(c.Request.Context(), ws, id, actor, in.Decision, in.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_gateway.hold_"+in.Decision, "agent_gateway_hold", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

/* ------------------------------------ joins -------------------------------- */

func (ctl *AgentGatewayController) GetJoinSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	// TENANT-EXEMPT: not a statement here: the service runs every statement under row-level security for the token's workspace.
	out, err := services.NewAgentRuntimeJoinService(ctl.db()).Settings(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (ctl *AgentGatewayController) PutJoinSettings(c *gin.Context) {
	ws, actor, _, ok := ctl.writeTarget(c, false)
	if !ok {
		return
	}
	var in services.AgentJoinSettingsInput
	if err := strictJSON(c, &in); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"egress_hosts\", \"flow_log_groups\", \"version\"}."))
		return
	}
	// TENANT-EXEMPT: not a statement here: the service runs every statement under row-level security for the token's workspace.
	before, after, err := services.NewAgentRuntimeJoinService(ctl.db()).PutSettings(c.Request.Context(), ws, actor, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_runtime.join_settings_update", "agent_join_setting", ws.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after})
}

func (ctl *AgentGatewayController) ListUsageReconciliation(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	from, ok := optTime(c, "from")
	if !ok {
		return
	}
	to, ok := optTime(c, "to")
	if !ok {
		return
	}
	// TENANT-EXEMPT: not a statement here: the service runs every statement under row-level security for the token's workspace.
	out, err := services.NewUsageReconcileService(ctl.db()).List(c.Request.Context(), ws, c.Query("label"), from, to)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}
