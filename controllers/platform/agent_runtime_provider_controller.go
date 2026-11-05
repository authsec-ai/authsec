package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Model provider usage (SPEC-agent-runtime-provider-usage.md §7), under
// /api/iga/v1/agent-runtime:
//
//	POST   /model-providers               governance:enforce  {provider, admin_key, display_name}
//	GET    /model-providers               discovery:read
//	GET    /model-providers/:id           discovery:read
//	POST   /model-providers/:id/rotate    governance:enforce  {admin_key}
//	DELETE /model-providers/:id           governance:enforce
//	POST   /model-providers/:id/sync      governance:enforce
//	GET    /model-providers/:id/keys      discovery:read
//	GET    /model-providers/:id/usage     discovery:read      ?from=&to=&group_by=key|model|project
//
// The workspace is the token's (AuthMiddleware); another workspace's
// connection is 404, exactly like an unknown one. The admin key is
// write-only: no response carries it, and the audit rows record only the
// fingerprint. Writes need a verified workspace member session.

// AgentRuntimeProviderController serves the routes above.
type AgentRuntimeProviderController struct {
	db func() *gorm.DB
	// service, when set, is the service used (tests: a fake provider client).
	service *services.ModelProviderService
}

// NewAgentRuntimeProviderControllerFor builds the controller over the graph
// controller's database.
func NewAgentRuntimeProviderControllerFor(g *IGAGraphReadController) *AgentRuntimeProviderController {
	return &AgentRuntimeProviderController{db: g.db}
}

// NewAgentRuntimeProviderController is the production controller (config.DB).
func NewAgentRuntimeProviderController() *AgentRuntimeProviderController {
	return &AgentRuntimeProviderController{db: func() *gorm.DB { return config.DB }}
}

// NewAgentRuntimeProviderControllerWith builds a controller over a service
// (tests: a fake provider client factory).
func NewAgentRuntimeProviderControllerWith(db *gorm.DB, svc *services.ModelProviderService) *AgentRuntimeProviderController {
	return &AgentRuntimeProviderController{db: func() *gorm.DB { return db }, service: svc}
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *AgentRuntimeProviderController) svc() *services.ModelProviderService {
	if ctl.service != nil {
		return ctl.service
	}
	// TENANT-EXEMPT: not a statement here: the service runs every statement under row-level security for the token's workspace.
	return services.NewModelProviderService(ctl.db())
}

// MountAgentRuntimeProviderRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group) with their permissions.
func MountAgentRuntimeProviderRoutes(g *gin.RouterGroup, ctl *AgentRuntimeProviderController) {
	RegisterAgentRuntimeProviderRoutes(g.Group("/agent-runtime"), ctl,
		middlewares.Require("discovery", "read"), middlewares.Require("governance", "enforce"))
}

// RegisterAgentRuntimeProviderRoutes is the route table (one table, so tests
// mount the same one).
func RegisterAgentRuntimeProviderRoutes(g gin.IRoutes, ctl *AgentRuntimeProviderController, read, write gin.HandlerFunc) {
	g.POST("/model-providers", write, ctl.Connect)
	g.GET("/model-providers", read, ctl.List)
	g.GET("/model-providers/:id", read, ctl.Get)
	g.POST("/model-providers/:id/rotate", write, ctl.Rotate)
	g.DELETE("/model-providers/:id", write, ctl.Revoke)
	g.POST("/model-providers/:id/sync", write, ctl.Sync)
	g.GET("/model-providers/:id/keys", read, ctl.Keys)
	g.GET("/model-providers/:id/usage", read, ctl.Usage)
}

func (ctl *AgentRuntimeProviderController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Model provider changes require a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Model provider changes require a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// auditView is what an audit row records of a connection: never the key.
func providerAuditView(p *services.ModelProviderConnection) map[string]any {
	return map[string]any{"provider": p.Provider, "display_name": p.DisplayName, "org_id": p.OrgID,
		"key_fingerprint": p.KeyFingerprint, "status": p.Status}
}

type connectModelProviderBody struct {
	Provider    string `json:"provider"`
	AdminKey    string `json:"admin_key"`
	DisplayName string `json:"display_name"`
}

// Connect handles POST /model-providers.
func (ctl *AgentRuntimeProviderController) Connect(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body connectModelProviderBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"provider": "openai|anthropic", "admin_key": "...", "display_name": "..."}.`))
		return
	}
	p, err := ctl.svc().Connect(c.Request.Context(), ws, actor, body.Provider, body.AdminKey, body.DisplayName)
	body.AdminKey = ""
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "model_provider.connect", "model_provider_connection", p.ID.String(), http.StatusCreated, nil, providerAuditView(p))
	c.JSON(http.StatusCreated, gin.H{"data": p})
}

// List handles GET /model-providers.
func (ctl *AgentRuntimeProviderController) List(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().List(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// Get handles GET /model-providers/:id.
func (ctl *AgentRuntimeProviderController) Get(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	p, err := ctl.svc().Get(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": p})
}

type rotateModelProviderBody struct {
	AdminKey string `json:"admin_key"`
}

// Rotate handles POST /model-providers/:id/rotate.
func (ctl *AgentRuntimeProviderController) Rotate(c *gin.Context) {
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
	var body rotateModelProviderBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"admin_key": "..."}.`))
		return
	}
	p, err := ctl.svc().Rotate(c.Request.Context(), ws, id, body.AdminKey)
	body.AdminKey = ""
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "model_provider.rotate", "model_provider_connection", id.String(), http.StatusOK, nil, providerAuditView(p))
	c.JSON(http.StatusOK, gin.H{"data": p})
}

// Revoke handles DELETE /model-providers/:id.
func (ctl *AgentRuntimeProviderController) Revoke(c *gin.Context) {
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
	p, err := ctl.svc().Revoke(c.Request.Context(), ws, actor, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "model_provider.revoke", "model_provider_connection", id.String(), http.StatusOK, nil, providerAuditView(p))
	c.JSON(http.StatusOK, gin.H{"data": p})
}

// Sync handles POST /model-providers/:id/sync.
func (ctl *AgentRuntimeProviderController) Sync(c *gin.Context) {
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
	next, err := ctl.svc().RequestSync(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "model_provider.sync", "model_provider_connection", id.String(), http.StatusAccepted, nil,
		map[string]any{"next_sync_at": next})
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{"queued": true, "next_sync_at": next}})
}

// Keys handles GET /model-providers/:id/keys.
func (ctl *AgentRuntimeProviderController) Keys(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Keys(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

func providerTimeParam(c *gin.Context, name string) (*time.Time, bool) {
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

// Usage handles GET /model-providers/:id/usage.
func (ctl *AgentRuntimeProviderController) Usage(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := agentAlertPathID(c)
	if !ok {
		return
	}
	from, ok := providerTimeParam(c, "from")
	if !ok {
		return
	}
	to, ok := providerTimeParam(c, "to")
	if !ok {
		return
	}
	group := c.DefaultQuery("group_by", "key")
	rows, start, end, err := ctl.svc().Usage(c.Request.Context(), ws, id, from, to, group)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"from": start, "to": end, "group_by": group}})
}
