package platform

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
)

/* The AWS agent review service's keys route (services/agent_review_keys.go):

     POST /authsec/internal/aws/workspaces/:workspace_id/connectors/:connector_id/session
     Authorization: Bearer <AGENT_REVIEW_SERVICE_TOKEN>

   The caller is one platform service, not a workspace member: the service
   token is its only credential and is compared in constant time. It serves
   every workspace, so the workspace is the path's; the connector is then read
   under row-level security for that workspace, and a connector of any other
   workspace is a 404 (CLAUDE.md §4 rule 6). Every issue is audited in the
   connector's workspace (rule 12); the keys are never logged or stored.

   Mounted only when AGENT_REVIEW_SERVICE_TOKEN is set; without the secrets
   store every request answers 503. */

// AgentReviewKeyIssuer issues keys for one connector (services.AgentReviewKeys).
type AgentReviewKeyIssuer interface {
	Issue(ctx context.Context, ws, connectorID uuid.UUID) (*services.AgentReviewCredentials, error)
}

// MountAgentReviewRoutes mounts the keys route on r. keys may be nil (no
// secrets store): the route then answers 503.
func MountAgentReviewRoutes(r gin.IRouter, token string, keys AgentReviewKeyIssuer) {
	if token == "" {
		return
	}
	want := []byte("Bearer " + token)
	r.POST("/authsec/internal/aws/workspaces/:workspace_id/connectors/:connector_id/session", func(c *gin.Context) {
		agentReviewSession(c, want, keys)
	})
}

func agentReviewSession(c *gin.Context, want []byte, keys AgentReviewKeyIssuer) {
	c.Header("Cache-Control", "no-store")
	if subtle.ConstantTimeCompare([]byte(c.GetHeader("Authorization")), want) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	ws, err1 := uuid.Parse(c.Param("workspace_id"))
	connectorID, err2 := uuid.Parse(c.Param("connector_id"))
	if err1 != nil || err2 != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector_not_found"})
		return
	}
	if keys == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secrets_store_unavailable"})
		return
	}

	creds, err := keys.Issue(c.Request.Context(), ws, connectorID)
	status, code := agentReviewStatus(err)
	auditAgentReviewSession(c, ws, connectorID, status, creds, err)
	if err != nil {
		if status >= http.StatusInternalServerError {
			log.Printf("agent review keys: ws=%s connector=%s: %v", ws, connectorID, err)
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, creds)
}

// agentReviewStatus maps an issue error to the route's answer. The service
// fails a review on 404 and 409 and retries it later on 5xx.
func agentReviewStatus(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, services.ErrAgentReviewConnectorNotFound):
		return http.StatusNotFound, "connector_not_found"
	case errors.Is(err, services.ErrAgentReviewConnectorRevoked):
		return http.StatusConflict, "connector_revoked"
	case errors.Is(err, services.ErrAgentReviewAssumeFailed):
		return http.StatusBadGateway, "assume_role_failed"
	default:
		return http.StatusServiceUnavailable, "keys_unavailable"
	}
}

// auditAgentReviewSession records one issue, or one refusal, in the
// connector's workspace: who asked (the review service), for which
// connector, and until when the keys hold. Never a key.
func auditAgentReviewSession(c *gin.Context, ws, connectorID uuid.UUID, status int,
	creds *services.AgentReviewCredentials, issueErr error) {
	if config.AuditLogger == nil {
		return
	}
	event := &monitoring.AuditEvent{
		RequestID:   c.GetString("request_id"),
		WorkspaceID: ws.String(),
		ActorRealm:  "service",
		UserID:      "aws-agent-review",
		Action:      "issue_agent_review_session",
		Resource:    "cloud_connector",
		ResourceID:  connectorID.String(),
		Method:      c.Request.Method,
		Path:        c.Request.URL.Path,
		UserAgent:   c.GetHeader("User-Agent"),
		ClientIP:    c.ClientIP(),
		StatusCode:  status,
		Timestamp:   time.Now(),
	}
	if creds != nil {
		v, _ := json.Marshal(map[string]any{"role_arn": creds.RoleARN, "expiration": creds.Expiration,
			"duration_seconds": services.AgentReviewSessionSeconds})
		s := string(v)
		event.NewValues = &s
	}
	if issueErr != nil {
		_, event.Error = agentReviewStatus(issueErr)
	}
	config.AuditLogger.LogEvent(event)
}
