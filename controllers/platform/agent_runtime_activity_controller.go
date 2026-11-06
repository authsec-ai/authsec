package platform

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentactivity"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime activity timeline (SPEC-agent-runtime-activity.md §4.3, §7).
//
// Ingest, no AuthMiddleware -- the per-workspace OTLP token is the credential
// and alone decides the workspace:
//
//	POST /authsec/ingest/otlp/v1/traces   Authorization: Bearer aot_... | X-AuthSec-Ingest-Token
//	  200 ExportTraceServiceResponse | 400 | 401 | 413 | 415 | 429 | 503
//
// Under /api/iga/v1/agent-runtime, workspace from the token (AuthMiddleware),
// governance error envelope; another workspace's rows read as absent:
//
//	GET    /activity                       discovery:read
//	       ?identity_id=&workload_id=&kind=&outcome=&source=&from=&to=&cursor=&limit=
//	GET    /activity/traces/:trace_id      discovery:read
//	GET    /activity/coverage              discovery:read
//	GET    /activity/settings              discovery:read
//	PUT    /activity/settings              discovery:admin  {retention_days}
//	POST   /otlp-tokens                    discovery:admin  {label, expires_in_days?}
//	GET    /otlp-tokens                    discovery:read
//	DELETE /otlp-tokens/:id                discovery:admin

// AgentRuntimeActivityController serves the /api/iga/v1 routes above.
type AgentRuntimeActivityController struct {
	db func() *gorm.DB
}

// NewAgentRuntimeActivityControllerFor builds the controller over the graph
// controller's database (as the alerts controller).
func NewAgentRuntimeActivityControllerFor(g *IGAGraphReadController) *AgentRuntimeActivityController {
	return &AgentRuntimeActivityController{db: g.db}
}

// NewAgentRuntimeActivityControllerWith builds a controller over db (tests).
func NewAgentRuntimeActivityControllerWith(db *gorm.DB) *AgentRuntimeActivityController {
	return &AgentRuntimeActivityController{db: func() *gorm.DB { return db }}
}

// MountAgentRuntimeActivityRoutes mounts the routes on g (the authenticated
// /api/iga/v1 group) with their permissions.
func MountAgentRuntimeActivityRoutes(g *gin.RouterGroup, ctl *AgentRuntimeActivityController) {
	RegisterAgentRuntimeActivityRoutes(g.Group("/agent-runtime"), ctl,
		middlewares.Require("discovery", "read"), middlewares.Require("discovery", "admin"))
}

// RegisterAgentRuntimeActivityRoutes is the route table.
func RegisterAgentRuntimeActivityRoutes(g gin.IRoutes, ctl *AgentRuntimeActivityController, read, admin gin.HandlerFunc) {
	g.GET("/activity", read, ctl.ListActivity)
	g.GET("/activity/traces/:trace_id", read, ctl.GetTrace)
	g.GET("/activity/coverage", read, ctl.GetCoverage)
	g.GET("/activity/settings", read, ctl.GetSettings)
	g.PUT("/activity/settings", admin, ctl.PutSettings)
	g.POST("/otlp-tokens", admin, ctl.CreateOTLPToken)
	g.GET("/otlp-tokens", read, ctl.ListOTLPTokens)
	g.DELETE("/otlp-tokens/:id", admin, ctl.RevokeOTLPToken)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *AgentRuntimeActivityController) svc() *services.AgentActivityService {
	return services.NewAgentActivityService(ctl.db())
}

// TENANT-EXEMPT: not a statement here: token administration runs under the
// token's workspace (tenancy.InWorkspace).
func (ctl *AgentRuntimeActivityController) otlp() *services.AgentOTLPService {
	return services.NewAgentOTLPService(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AgentRuntimeActivityController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
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

func queryUUID(c *gin.Context, name string) (*uuid.UUID, bool) {
	v := c.Query(name)
	if v == "" {
		return nil, true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		govErrorOut(c, services.GovBadParam(name, name+" must be a UUID."))
		return nil, false
	}
	return &id, true
}

func queryTime(c *gin.Context, name string) (*time.Time, bool) {
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

// ListActivity handles GET /activity.
func (ctl *AgentRuntimeActivityController) ListActivity(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AgentActivityFilter{Kind: c.Query("kind"), Outcome: c.Query("outcome"), Source: c.Query("source")}
	if f.IdentityID, ok = queryUUID(c, "identity_id"); !ok {
		return
	}
	if f.WorkloadID, ok = queryUUID(c, "workload_id"); !ok {
		return
	}
	if f.From, ok = queryTime(c, "from"); !ok {
		return
	}
	if f.To, ok = queryTime(c, "to"); !ok {
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
	rows, next, err := ctl.svc().List(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}

// GetTrace handles GET /activity/traces/:trace_id.
func (ctl *AgentRuntimeActivityController) GetTrace(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	tr, err := ctl.svc().Trace(c.Request.Context(), ws, c.Param("trace_id"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tr})
}

// GetCoverage handles GET /activity/coverage.
func (ctl *AgentRuntimeActivityController) GetCoverage(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	cov, err := ctl.svc().Coverage(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": cov})
}

// GetSettings handles GET /activity/settings.
func (ctl *AgentRuntimeActivityController) GetSettings(c *gin.Context) {
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

type putActivitySettingsBody struct {
	RetentionDays *int `json:"retention_days"`
}

// PutSettings handles PUT /activity/settings.
func (ctl *AgentRuntimeActivityController) PutSettings(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body putActivitySettingsBody
	if err := c.ShouldBindJSON(&body); err != nil || body.RetentionDays == nil {
		govErrorOut(c, services.GovBadParam("retention_days", "The body must be JSON: {\"retention_days\": 90}."))
		return
	}
	s, err := ctl.svc().UpdateSettings(c.Request.Context(), ws, actor, *body.RetentionDays)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_activity.settings_update", "agent_activity_setting", ws.String(), http.StatusOK, nil, s)
	c.JSON(http.StatusOK, gin.H{"data": s})
}

type createOTLPTokenBody struct {
	Label         string `json:"label"`
	ExpiresInDays int    `json:"expires_in_days"`
}

// CreateOTLPToken handles POST /otlp-tokens. The token is in this response
// only.
func (ctl *AgentRuntimeActivityController) CreateOTLPToken(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body createOTLPTokenBody
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&body); err != nil {
			govErrorOut(c, services.GovBadParam("body", "The body must be JSON: {\"label\": \"...\", \"expires_in_days\": 90}."))
			return
		}
	}
	tok, secret, err := ctl.otlp().CreateToken(c.Request.Context(), ws, actor.String(), body.Label, body.ExpiresInDays)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	// The audit record carries the prefix, never the token.
	auditAdminMutation(c, ws.String(), "agent_activity.otlp_token_create", "agent_otlp_token", tok.ID.String(), http.StatusCreated, nil, tok)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{"data": gin.H{
		"token_info": tok,
		"token":      secret,
		"endpoint":   otlpEndpointURL(),
		"headers":    gin.H{"Authorization": "Bearer <token>"},
	}, "meta": gin.H{"note": "the token is shown only in this response"}})
}

// otlpEndpointURL is the public receiver URL, from the OAuth base URL.
func otlpEndpointURL() string {
	if config.AppConfig == nil {
		return services.AgentOTLPIngestPath
	}
	base := strings.TrimRight(config.AppConfig.OAuthBaseURL(), "/")
	if base == "" {
		return services.AgentOTLPIngestPath
	}
	return base + services.AgentOTLPIngestPath
}

// ListOTLPTokens handles GET /otlp-tokens.
func (ctl *AgentRuntimeActivityController) ListOTLPTokens(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.otlp().ListTokens(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// RevokeOTLPToken handles DELETE /otlp-tokens/:id.
func (ctl *AgentRuntimeActivityController) RevokeOTLPToken(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return
	}
	if _, ok := ctl.actor(c, ws); !ok {
		return
	}
	tok, err := ctl.otlp().RevokeToken(c.Request.Context(), ws, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "agent_activity.otlp_token_revoke", "agent_otlp_token", id.String(), http.StatusOK, nil, tok)
	c.JSON(http.StatusOK, gin.H{"data": tok})
}

/* ---------------------------------- ingest -------------------------------- */

// AgentOTLPIngestController serves POST /authsec/ingest/otlp/v1/traces. One
// instance serves every request: its service holds the per-token limits.
type AgentOTLPIngestController struct {
	svc *services.AgentOTLPService
}

// NewAgentOTLPIngestController constructs the controller.
func NewAgentOTLPIngestController(db *gorm.DB) *AgentOTLPIngestController {
	return &AgentOTLPIngestController{svc: services.NewAgentOTLPService(db)}
}

// WithService replaces the service (tests).
func (ctl *AgentOTLPIngestController) WithService(svc *services.AgentOTLPService) *AgentOTLPIngestController {
	ctl.svc = svc
	return ctl
}

// presentedOTLPToken reads the token from Authorization: Bearer or
// X-AuthSec-Ingest-Token.
func presentedOTLPToken(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader(services.AgentOTLPTokenHeader)); v != "" {
		return v
	}
	h := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// otlpStatus writes an OTLP error: a google.rpc.Status-shaped JSON body (the
// OTLP/HTTP spec allows either encoding for failures; JSON is readable by
// every exporter's logs).
func otlpStatus(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"code": status, "message": msg})
}

// IngestTraces handles POST /authsec/ingest/otlp/v1/traces. The workspace
// comes from the token only; the body is never logged.
func (ctl *AgentOTLPIngestController) IngestTraces(c *gin.Context) {
	ctx := c.Request.Context()
	presented := presentedOTLPToken(c)
	if presented == "" {
		otlpStatus(c, http.StatusUnauthorized, "missing OTLP token (Authorization: Bearer or "+services.AgentOTLPTokenHeader+")")
		return
	}
	p, err := ctl.svc.Authenticate(ctx, presented)
	if err != nil {
		log.Printf("[agent-otlp-ingest] stage=auth outcome=error err=%v", err)
		otlpStatus(c, http.StatusServiceUnavailable, "could not verify the token; retry")
		return
	}
	if p == nil {
		otlpStatus(c, http.StatusUnauthorized, "unknown, revoked or expired OTLP token")
		return
	}
	if !ctl.svc.Allow(p.TokenID) {
		c.Header("Retry-After", "1")
		otlpStatus(c, http.StatusTooManyRequests, "rate limit exceeded for this token")
		return
	}
	mt, _, _ := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if mt != "application/x-protobuf" && mt != "application/json" {
		otlpStatus(c, http.StatusUnsupportedMediaType, "Content-Type must be application/x-protobuf or application/json")
		return
	}
	if c.Request.ContentLength > services.AgentOTLPMaxBodyBytes {
		otlpStatus(c, http.StatusRequestEntityTooLarge, "request larger than 4 MB")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, services.AgentOTLPMaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			otlpStatus(c, http.StatusRequestEntityTooLarge, "request larger than 4 MB")
			return
		}
		otlpStatus(c, http.StatusBadRequest, "could not read the request body")
		return
	}
	switch strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			otlpStatus(c, http.StatusBadRequest, "invalid gzip body")
			return
		}
		body, err = io.ReadAll(io.LimitReader(zr, services.AgentOTLPMaxBodyBytes+1))
		_ = zr.Close()
		if err != nil {
			otlpStatus(c, http.StatusBadRequest, "invalid gzip body")
			return
		}
		if len(body) > services.AgentOTLPMaxBodyBytes {
			otlpStatus(c, http.StatusRequestEntityTooLarge, "decompressed request larger than 4 MB")
			return
		}
	default:
		otlpStatus(c, http.StatusUnsupportedMediaType, "Content-Encoding must be gzip or none")
		return
	}

	var spans []agentactivity.Span
	if mt == "application/json" {
		spans, err = agentactivity.DecodeOTLPJSON(body)
	} else {
		spans, err = agentactivity.DecodeOTLPProtobuf(body)
	}
	switch {
	case errors.Is(err, agentactivity.ErrTooManySpans), errors.Is(err, agentactivity.ErrOTLPTooLarge):
		otlpStatus(c, http.StatusRequestEntityTooLarge, err.Error())
		return
	case err != nil:
		otlpStatus(c, http.StatusBadRequest, agentactivity.ErrBadOTLP.Error())
		return
	}

	res, err := ctl.svc.Ingest(ctx, *p, spans)
	switch {
	case errors.Is(err, services.ErrAgentOTLPUnauthenticated):
		otlpStatus(c, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		log.Printf("[agent-otlp-ingest] stage=ingest workspace=%s token=%s outcome=error err=%v", p.WorkspaceID, p.TokenID, err)
		c.Header("Retry-After", "5")
		otlpStatus(c, http.StatusServiceUnavailable, "the spans could not be recorded; retry")
		return
	}
	// Rejected spans (no ids, outside retention) are a partial success; spans
	// that are not GenAI / agent / MCP are accepted and dropped by design.
	msg := ""
	if res.Rejected > 0 {
		msg = strconv.Itoa(res.Rejected) + " spans rejected: missing trace/span id, or outside the retention window"
	}
	c.Header("X-AuthSec-Accepted", strconv.Itoa(res.Accepted))
	c.Header("X-AuthSec-Ignored", strconv.Itoa(res.Ignored))
	if mt == "application/json" {
		raw, _ := json.Marshal(agentactivity.ExportResponseJSON(int64(res.Rejected), msg))
		c.Data(http.StatusOK, "application/json", raw)
		return
	}
	c.Data(http.StatusOK, "application/x-protobuf", agentactivity.ExportResponseProto(int64(res.Rejected), msg))
}
