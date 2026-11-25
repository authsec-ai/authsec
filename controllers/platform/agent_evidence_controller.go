package platform

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/authz"
	"github.com/authsec-ai/authsec/middlewares"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Evidence and coverage (SPEC-secops-backend-upgrade W1), under /api/iga/v1:
//
//	GET  /agent-runtime/evidence?principal=&source=&from=&to=&cursor=&limit=   read
//	GET  /agent-runtime/evidence/retention                                     read
//	PUT  /agent-runtime/evidence/retention   {retention_days: {class: days}}   governance:enforce
//	POST /agent-runtime/backfill             {connector_id, from, to}          governance:enforce (tier 1)
//	GET  /agent-runtime/backfill                                               read
//	GET  /agent-runtime/azure/connectors/:id/ingest                            read
//	POST /agent-runtime/azure/connectors/:id/ingest   (secret shown once)      discovery:admin
//	DELETE /agent-runtime/azure/connectors/:id/ingest                          discovery:admin
//	GET  /coverage/capabilities?scope=&capability=&state=                      read
//	GET  /coverage/sources                                                     read
//	PUT  /coverage/capabilities/:id/declare  {reason}                          governance:enforce (tier 3 request)
//	POST /coverage/declarations/:id/approve  {reason}                          governance:approve (second person)
//	POST /coverage/declarations/:id/reject   {reason}                          governance:approve (second person)
//	POST /coverage/declarations/:id/review                                     governance:approve (break-glass review)
//
// read = governance:read or discovery:read. The workspace is the token's;
// another workspace's row is 404 like an unknown one. Writes need a verified
// workspace member session and write an audit_events row.
//
// And, with no AuthMiddleware (the credential alone decides the workspace):
//
//	POST /authsec/ingest/azure/events   X-AuthSec-Event-Secret: azev_...
//	POST /authsec/ingest/k8s/audit      Authorization: Bearer <actuation credential | ingest token>

// AgentEvidenceController serves the routes above.
type AgentEvidenceController struct {
	db         func() *gorm.DB
	collectors *services.CollectorService
}

// NewAgentEvidenceControllerFor builds the controller over the graph
// controller's database.
func NewAgentEvidenceControllerFor(g *IGAGraphReadController) *AgentEvidenceController {
	return &AgentEvidenceController{db: g.db, collectors: services.NewCollectorService(g.db())}
}

// NewAgentEvidenceControllerWith builds a controller over db (tests).
func NewAgentEvidenceControllerWith(db *gorm.DB) *AgentEvidenceController {
	return &AgentEvidenceController{db: func() *gorm.DB { return db }, collectors: services.NewCollectorService(db)}
}

// NewAgentCollectorIngestController is the production ingest controller
// (config.DB); one instance holds the per-connector rate limits.
func NewAgentCollectorIngestController() *AgentEvidenceController {
	return &AgentEvidenceController{db: func() *gorm.DB { return config.DB }, collectors: services.NewCollectorService(config.DB)}
}

// WithCollectors replaces the collector service (tests).
func (ctl *AgentEvidenceController) WithCollectors(s *services.CollectorService) *AgentEvidenceController {
	ctl.collectors = s
	return ctl
}

// MountAgentEvidenceRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group) with their permissions.
func MountAgentEvidenceRoutes(g *gin.RouterGroup, ctl *AgentEvidenceController) {
	read := middlewares.RequireAny(authz.Need{Resource: "governance", Action: "read"}, authz.Need{Resource: "discovery", Action: "read"})
	RegisterAgentEvidenceRoutes(g, ctl, read, middlewares.Require("governance", "enforce"),
		middlewares.Require("governance", "approve"), middlewares.Require("discovery", "admin"))
}

// RegisterAgentEvidenceRoutes is the route table (tests mount the same one).
func RegisterAgentEvidenceRoutes(g gin.IRouter, ctl *AgentEvidenceController, read, enforce, approve, discoveryAdmin gin.HandlerFunc) {
	ar := g.Group("/agent-runtime")
	ar.GET("/evidence", read, ctl.requireSchema, ctl.ListEvidence)
	ar.GET("/evidence/retention", read, ctl.requireSchema, ctl.GetRetention)
	ar.PUT("/evidence/retention", enforce, ctl.requireSchema, ctl.PutRetention)
	ar.POST("/backfill", enforce, ctl.requireSchema, ctl.RequestBackfill)
	ar.GET("/backfill", read, ctl.requireSchema, ctl.ListBackfills)
	ar.GET("/azure/connectors/:id/ingest", read, ctl.requireSchema, ctl.GetAzureIngest)
	ar.POST("/azure/connectors/:id/ingest", discoveryAdmin, ctl.requireSchema, ctl.CreateAzureIngest)
	ar.DELETE("/azure/connectors/:id/ingest", discoveryAdmin, ctl.requireSchema, ctl.RevokeAzureIngest)
	cov := g.Group("/coverage")
	cov.GET("/capabilities", read, ctl.requireSchema, ctl.ListCapabilities)
	cov.GET("/sources", read, ctl.requireSchema, ctl.ListSources)
	cov.PUT("/capabilities/:id/declare", enforce, ctl.requireSchema, ctl.Declare)
	cov.POST("/declarations/:id/approve", approve, ctl.requireSchema, ctl.Approve)
	cov.POST("/declarations/:id/reject", approve, ctl.requireSchema, ctl.Reject)
	cov.POST("/declarations/:id/review", approve, ctl.requireSchema, ctl.Review)
}

// MountAgentCollectorIngestRoutes mounts the two collectors on the
// unauthenticated /authsec group.
func MountAgentCollectorIngestRoutes(g gin.IRouter, ctl *AgentEvidenceController) {
	g.POST("/ingest/azure/events", ctl.IngestAzureEvents)
	g.POST("/ingest/k8s/audit", ctl.IngestK8sAudit)
}

func (ctl *AgentEvidenceController) requireSchema(c *gin.Context) {
	// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
	if err := services.RequireAgentEvidence(ctl.db()); err != nil {
		govErrorOut(c, err)
	}
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AgentEvidenceController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace.
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "This change requires a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "This change requires a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

func pathUUID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return uuid.Nil, false
	}
	return id, true
}

func optionalTime(c *gin.Context, name string) (*time.Time, bool) {
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

/* --------------------------------- evidence -------------------------------- */

// ListEvidence handles GET /agent-runtime/evidence.
func (ctl *AgentEvidenceController) ListEvidence(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AgentEvidenceFilter{Principal: c.Query("principal"), Source: c.Query("source")}
	if f.From, ok = optionalTime(c, "from"); !ok {
		return
	}
	if f.To, ok = optionalTime(c, "to"); !ok {
		return
	}
	limit := 0
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			govErrorOut(c, services.GovBadParam("limit", "limit must be between 1 and 500."))
			return
		}
		limit = n
	}
	rows, next, err := services.NewAgentEvidenceService(ctl.db()).List(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}

// GetRetention handles GET /agent-runtime/evidence/retention.
func (ctl *AgentEvidenceController) GetRetention(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	r, err := services.NewAgentEvidenceService(ctl.db()).Retention(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": r})
}

// PutRetention handles PUT /agent-runtime/evidence/retention.
func (ctl *AgentEvidenceController) PutRetention(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body struct {
		RetentionDays map[string]int `json:"retention_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.RetentionDays) == 0 {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"retention_days": {"default": 90, ...}}.`))
		return
	}
	r, err := services.NewAgentEvidenceService(ctl.db()).SetRetention(c.Request.Context(), ws, actor, body.RetentionDays)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_evidence.retention_update", "agent_evidence_retention", ws.String(), http.StatusOK, nil, r)
	c.JSON(http.StatusOK, gin.H{"data": r})
}

/* --------------------------------- backfill -------------------------------- */

// RequestBackfill handles POST /agent-runtime/backfill (tier 1): the
// backfill is queued and run by the backfill worker.
func (ctl *AgentEvidenceController) RequestBackfill(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body struct {
		ConnectorID string `json:"connector_id"`
		From        string `json:"from"`
		To          string `json:"to"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"connector_id", "from", "to"}.`))
		return
	}
	conn, err := uuid.Parse(body.ConnectorID)
	if err != nil {
		govErrorOut(c, services.GovBadParam("connector_id", "connector_id must be a UUID."))
		return
	}
	from, err1 := time.Parse(time.RFC3339, body.From)
	to, err2 := time.Parse(time.RFC3339, body.To)
	if err1 != nil || err2 != nil {
		govErrorOut(c, services.GovBadParam("from", "from and to must be RFC 3339 times."))
		return
	}
	b, err := services.NewTrailBackfillService(ctl.db(), nil).Request(c.Request.Context(), ws, conn, actor, from, to)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_evidence.backfill_request", "agent_trail_backfill", b.ID.String(), http.StatusAccepted, nil, b)
	c.JSON(http.StatusAccepted, gin.H{"data": b})
}

// ListBackfills handles GET /agent-runtime/backfill.
func (ctl *AgentEvidenceController) ListBackfills(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := services.NewTrailBackfillService(ctl.db(), nil).List(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

/* ------------------------------- Azure ingest ------------------------------ */

func (ctl *AgentEvidenceController) azureErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound), errors.Is(err, services.ErrAzureIngestNotFound):
		policyNotFound(c)
	case errors.Is(err, services.ErrAzureConnectorRevoked):
		policyErr(c, http.StatusConflict, "connector_revoked", err.Error(), nil)
	default:
		govErrorOut(c, err)
	}
}

// GetAzureIngest handles GET /agent-runtime/azure/connectors/:id/ingest.
func (ctl *AgentEvidenceController) GetAzureIngest(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	v, err := ctl.collectors.GetAzure(c.Request.Context(), ws, id)
	if err != nil {
		ctl.azureErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

// CreateAzureIngest handles POST /agent-runtime/azure/connectors/:id/ingest:
// a new secret (shown once) or a rotation.
func (ctl *AgentEvidenceController) CreateAzureIngest(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	v, secret, err := ctl.collectors.EnableOrRotateAzure(c.Request.Context(), ws, id, actor.String())
	if err != nil {
		ctl.azureErr(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_evidence.azure_ingest_secret", "agent_ingest_secret", id.String(), http.StatusOK, nil,
		map[string]any{"secret_prefix": v.SecretPrefix})
	c.JSON(http.StatusOK, gin.H{"data": v, "secret": secret,
		"note": "The secret is shown once. Configure your Event Hub forwarder to send it as " + services.AgentEventSecretHeader + "."})
}

// RevokeAzureIngest handles DELETE /agent-runtime/azure/connectors/:id/ingest.
func (ctl *AgentEvidenceController) RevokeAzureIngest(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	if _, ok := ctl.actor(c, ws); !ok {
		return
	}
	v, err := ctl.collectors.RevokeAzure(c.Request.Context(), ws, id)
	if err != nil {
		ctl.azureErr(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_evidence.azure_ingest_revoke", "agent_ingest_secret", id.String(), http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"data": v})
}

/* --------------------------------- coverage -------------------------------- */

// ListCapabilities handles GET /coverage/capabilities.
func (ctl *AgentEvidenceController) ListCapabilities(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := services.NewAgentCoverageService(ctl.db()).Capabilities(c.Request.Context(), ws, services.CoverageCapabilitiesFilter{
		Scope: c.Query("scope"), Capability: c.Query("capability"), State: c.Query("state")})
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// ListSources handles GET /coverage/sources.
func (ctl *AgentEvidenceController) ListSources(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := services.NewAgentCoverageService(ctl.db()).Sources(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

type coverageReasonBody struct {
	Reason string `json:"reason"`
}

func bindReason(c *gin.Context) (string, bool) {
	var body coverageReasonBody
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"reason": "..."}.`))
			return "", false
		}
	}
	return body.Reason, true
}

// Declare handles PUT /coverage/capabilities/:id/declare (tier 3).
func (ctl *AgentEvidenceController) Declare(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	reason, ok := bindReason(c)
	if !ok {
		return
	}
	res, err := services.NewAgentCoverageService(ctl.db()).Declare(c.Request.Context(), ws, id, actor, reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	status := http.StatusAccepted // waiting for a second person
	if res.Declaration.State == "applied" {
		status = http.StatusOK // break-glass
	}
	auditAdminMutation(c, ws.String(), "coverage.declare", "agent_capability_state", id.String(), status, nil, res.Declaration)
	c.JSON(status, gin.H{"data": res})
}

func (ctl *AgentEvidenceController) decide(c *gin.Context, approve bool) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	reason, ok := bindReason(c)
	if !ok {
		return
	}
	res, err := services.NewAgentCoverageService(ctl.db()).Decide(c.Request.Context(), ws, id, actor, approve, reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	action := "coverage.declaration_reject"
	if approve {
		action = "coverage.declaration_approve"
	}
	auditAdminMutation(c, ws.String(), action, "agent_capability_declaration", id.String(), http.StatusOK, nil, res.Declaration)
	c.JSON(http.StatusOK, gin.H{"data": res})
}

// Approve handles POST /coverage/declarations/:id/approve.
func (ctl *AgentEvidenceController) Approve(c *gin.Context) { ctl.decide(c, true) }

// Reject handles POST /coverage/declarations/:id/reject.
func (ctl *AgentEvidenceController) Reject(c *gin.Context) { ctl.decide(c, false) }

// Review handles POST /coverage/declarations/:id/review.
func (ctl *AgentEvidenceController) Review(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	d, err := services.NewAgentCoverageService(ctl.db()).Review(c.Request.Context(), ws, id, actor)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "coverage.break_glass_review", "agent_capability_declaration", id.String(), http.StatusOK, nil, d)
	c.JSON(http.StatusOK, gin.H{"data": d})
}

/* -------------------------------- collectors ------------------------------- */

func readCollectorBody(c *gin.Context) ([]byte, bool) {
	if c.Request.ContentLength > services.CollectorMaxRequestBytes {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request larger than 4 MB"})
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, services.CollectorMaxRequestBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request larger than 4 MB"})
			return nil, false
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "could not read the request body"})
		return nil, false
	}
	return body, true
}

func collectorOut(c *gin.Context, kind string, p *services.CollectorPrincipal, res services.CollectorResult, err error) {
	switch {
	case errors.Is(err, agentruntime.ErrCollectorBody):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unsupported body"})
	case errors.Is(err, services.ErrCollectorTooLarge):
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAgentEventUnauthenticated):
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAgentEventDispatch):
		c.Header("Retry-After", "5")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": err.Error(), "result": res})
	case err != nil:
		log.Printf("[collector] kind=%s workspace=%s connector=%s outcome=error err=%v", kind, p.WorkspaceID, p.ConnectorID, err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "the events could not be recorded; retry"})
	case res.Received > 0 && res.Rejected == res.Received:
		status := http.StatusBadRequest
		if res.RejectedTenant > 0 {
			status = http.StatusForbidden
		}
		c.AbortWithStatusJSON(status, gin.H{"error": "every record was refused", "result": res})
	default:
		c.JSON(http.StatusAccepted, gin.H{"success": true, "data": res})
	}
}

// IngestAzureEvents handles POST /authsec/ingest/azure/events.
func (ctl *AgentEvidenceController) IngestAzureEvents(c *gin.Context) {
	ctx := c.Request.Context()
	// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
	if ok, _ := services.AgentEvidenceStatus(ctl.db()); !ok {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "evidence ingest is not available on this server"})
		return
	}
	secret := strings.TrimSpace(c.GetHeader(services.AgentEventSecretHeader))
	if secret == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + services.AgentEventSecretHeader})
		return
	}
	p, err := ctl.collectors.AuthenticateAzure(ctx, secret)
	if err != nil {
		log.Printf("[collector] kind=azure stage=auth outcome=error err=%v", err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "could not verify the secret; retry"})
		return
	}
	if p == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unknown or revoked secret"})
		return
	}
	if !ctl.collectors.Allow(p.ConnectorID) {
		c.Header("Retry-After", "1")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded for this connector"})
		return
	}
	body, ok := readCollectorBody(c)
	if !ok {
		return
	}
	res, err := ctl.collectors.IngestAzure(ctx, *p, body)
	collectorOut(c, "azure", p, res, err)
}

// IngestK8sAudit handles POST /authsec/ingest/k8s/audit.
func (ctl *AgentEvidenceController) IngestK8sAudit(c *gin.Context) {
	ctx := c.Request.Context()
	// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
	if ok, _ := services.AgentEvidenceStatus(ctl.db()); !ok {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "evidence ingest is not available on this server"})
		return
	}
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer credential"})
		return
	}
	p, err := ctl.collectors.AuthenticateK8s(ctx, strings.TrimPrefix(auth, "Bearer "), c.GetHeader(services.K8sAuditSourceHeader))
	switch {
	case errors.Is(err, services.ErrK8sAuditUnauthenticated), errors.Is(err, services.ErrK8sAuditNeedsConnectorCredential):
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	case errors.Is(err, services.ErrK8sAuditSourceUnknown):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	case err != nil:
		log.Printf("[collector] kind=k8s stage=auth outcome=error err=%v", err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "could not verify the credential; retry"})
		return
	}
	if !ctl.collectors.Allow(p.ConnectorID) {
		c.Header("Retry-After", "1")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded for this connector"})
		return
	}
	body, ok := readCollectorBody(c)
	if !ok {
		return
	}
	res, err := ctl.collectors.IngestK8sAudit(ctx, *p, body)
	collectorOut(c, "k8s", p, res, err)
}
