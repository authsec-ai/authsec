package platform

import (
	"net/http"
	"strconv"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// LogsController serves the Logs UI from the existing audit tables. Every
// handler is workspace-scoped from JWT context (workspace_id is set by
// ValidateWorkspaceFromToken) and never trusts a client-supplied workspace.
type LogsController struct {
	svc *services.LogsService
}

// NewLogsController builds a LogsController over the shared DB handle.
func NewLogsController() *LogsController {
	var svc *services.LogsService
	if config.DB != nil {
		svc = services.NewLogsService(config.DB)
	}
	return &LogsController{svc: svc}
}

func (lc *LogsController) workspace(c *gin.Context) (string, bool) {
	ws := c.GetString("workspace_id")
	if ws == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "workspace context required"})
		return "", false
	}
	if lc.svc == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "logs service unavailable"})
		return "", false
	}
	return ws, true
}

func pageParams(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	return page, limit
}

// ── Response shapes (trimmed to what the tables actually hold) ──

type authLogResponse struct {
	ID          uint   `json:"id"`
	Timestamp   string `json:"timestamp"`
	RequestID   string `json:"requestId"`
	WorkspaceID string `json:"workspaceId"`
	ActorRealm  string `json:"actorRealm"`
	UserID      string `json:"userId"`
	Action      string `json:"action"`
	Status      string `json:"status"`
	IPAddress   string `json:"ipAddress"`
	UserAgent   string `json:"userAgent"`
	Error       string `json:"error,omitempty"`
}

type auditLogResponse struct {
	ID          uint   `json:"id"`
	Timestamp   string `json:"timestamp"`
	RequestID   string `json:"requestId"`
	WorkspaceID string `json:"workspaceId"`
	ActorRealm  string `json:"actorRealm"`
	UserID      string `json:"userId"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	ResourceID  string `json:"resourceId"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	StatusCode  int    `json:"statusCode"`
	Status      string `json:"status"`
	IPAddress   string `json:"ipAddress"`
	UserAgent   string `json:"userAgent"`
	Error       string `json:"error,omitempty"`
}

type m2mLogResponse struct {
	ID               string `json:"id"`
	CreatedAt        string `json:"createdAt"`
	WorkspaceID      string `json:"workspaceId"`
	TokenFamily      string `json:"tokenFamily"`
	ClientID         string `json:"clientId"`
	SubjectType      string `json:"subjectType"`
	SubjectID        string `json:"subjectId,omitempty"`
	ResourceServerID string `json:"resourceServerId"`
	PDPEffect        string `json:"pdpEffect"`
	GateEffect       string `json:"gateEffect"`
	PDPAgrees        bool   `json:"pdpAgrees"`
	ScopesRequested  string `json:"scopesRequested"`
	ScopesGranted    string `json:"scopesGranted"`
	PDPReason        string `json:"pdpReason,omitempty"`
}

func eventStatus(e monitoring.AuditEvent) string {
	if e.Error != "" || (e.StatusCode >= 400 && e.StatusCode != 0) {
		return "failure"
	}
	return "success"
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// GetAuthLogs → GET /authsec/logs/auth/paginated
func (lc *LogsController) GetAuthLogs(c *gin.Context) {
	ws, ok := lc.workspace(c)
	if !ok {
		return
	}
	page, limit := pageParams(c)
	rows, total, err := lc.svc.AuthLogs(ws, c.Query("status"), c.Query("action"), page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]authLogResponse, 0, len(rows))
	for _, e := range rows {
		out = append(out, authLogResponse{
			ID: e.ID, Timestamp: ts(e.Timestamp), RequestID: e.RequestID,
			WorkspaceID: e.WorkspaceID, ActorRealm: e.ActorRealm, UserID: e.UserID,
			Action: e.Action, Status: eventStatus(e),
			IPAddress: e.ClientIP, UserAgent: e.UserAgent, Error: e.Error,
		})
	}
	c.JSON(http.StatusOK, gin.H{"logs": out, "page": page, "limit": limit, "total": total})
}

// GetAuditLogs → GET /authsec/logs/audit/paginated
func (lc *LogsController) GetAuditLogs(c *gin.Context) {
	ws, ok := lc.workspace(c)
	if !ok {
		return
	}
	page, limit := pageParams(c)
	rows, total, err := lc.svc.AuditLogs(ws, c.Query("action"), c.Query("resource"), page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]auditLogResponse, 0, len(rows))
	for _, e := range rows {
		out = append(out, auditLogResponse{
			ID: e.ID, Timestamp: ts(e.Timestamp), RequestID: e.RequestID,
			WorkspaceID: e.WorkspaceID, ActorRealm: e.ActorRealm, UserID: e.UserID,
			Action: e.Action, Resource: e.Resource, ResourceID: e.ResourceID,
			Method: e.Method, Path: e.Path, StatusCode: e.StatusCode,
			Status: eventStatus(e), IPAddress: e.ClientIP, UserAgent: e.UserAgent, Error: e.Error,
		})
	}
	c.JSON(http.StatusOK, gin.H{"logs": out, "page": page, "limit": limit, "total": total})
}

// GetM2MLogs → GET /authsec/logs/m2m/paginated
func (lc *LogsController) GetM2MLogs(c *gin.Context) {
	ws, ok := lc.workspace(c)
	if !ok {
		return
	}
	page, limit := pageParams(c)
	rows, total, err := lc.svc.M2MLogs(ws, c.Query("client_id"), page, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]m2mLogResponse, 0, len(rows))
	for _, r := range rows {
		row := m2mLogResponse{
			ID: r.ID.String(), CreatedAt: ts(r.CreatedAt), WorkspaceID: r.WorkspaceID.String(),
			TokenFamily: r.TokenFamily, ClientID: r.ClientID, SubjectType: r.SubjectType,
			ResourceServerID: r.ResourceServerID.String(), PDPEffect: r.PDPEffect,
			GateEffect: r.GateEffect, PDPAgrees: r.PDPAgrees,
			ScopesRequested: r.ScopesRequested, ScopesGranted: r.ScopesGranted,
		}
		if r.SubjectID != nil {
			row.SubjectID = r.SubjectID.String()
		}
		if r.PDPReason != nil {
			row.PDPReason = *r.PDPReason
		}
		out = append(out, row)
	}
	c.JSON(http.StatusOK, gin.H{"logs": out, "page": page, "limit": limit, "total": total})
}

// GetStatus → GET /authsec/logs/status
// Reports the honest state: logs are served from the database, per source.
func (lc *LogsController) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled": true,
		"backend": "database",
		"sources": gin.H{
			"auth":  "audit_events",
			"audit": "audit_events",
			"m2m":   "auth_issuance_audit",
			"spire": "spire_audit_logs",
		},
	})
}

// ConfigureFluentBit → POST /authsec/logs/admin/fluent-bit
// External log forwarding (Fluent Bit etc.) is a deploy-layer concern in this
// build; the in-product Logs views read straight from the database. We accept
// the request so the existing UI contract doesn't break, but do not persist a
// forwarder config server-side.
func (lc *LogsController) ConfigureFluentBit(c *gin.Context) {
	var body map[string]any
	_ = c.ShouldBindJSON(&body)
	c.JSON(http.StatusOK, gin.H{
		"status": "accepted",
		"note":   "log forwarding is configured at the deployment layer; in-product logs are served from the database",
	})
}
