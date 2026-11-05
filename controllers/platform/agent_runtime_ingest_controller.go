package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime event stream and templates (SPEC-agent-runtime-visibility.md
// §5.4 as amended in §10, §5.6).
//
// Ingest, no AuthMiddleware -- the credential is the connector's event secret:
//
//	POST /authsec/ingest/aws/events      X-AuthSec-Event-Secret
//	  202 accepted (counts) | 400 bad body | 401 unknown secret |
//	  403 every event for another account | 413 too large | 429 rate limited |
//	  503 sinks failed (the events stay unseen; EventBridge retries)
//
// Admin, workspace from the token only (AuthMiddleware), errors in the §5.2
// envelope the Phase 2 connector routes use:
//
//	POST   /authsec/discovery/aws/connectors/:id/event-stream           discovery:admin
//	GET    /authsec/discovery/aws/connectors/:id/event-stream           discovery:read
//	DELETE /authsec/discovery/aws/connectors/:id/event-stream           discovery:admin
//	GET    /authsec/discovery/aws/connectors/:id/event-stream/template  discovery:read
//	GET    /authsec/discovery/aws/templates/model-access?mode=&form=    discovery:read
//
// Another workspace's connector is 404, like an absent one.

// AgentRuntimeIngestController serves the routes above. One instance serves
// every request: its service holds the per-connector rate limits.
type AgentRuntimeIngestController struct {
	svc *services.AgentRuntimeIngestService
}

// NewAgentRuntimeIngestController constructs the controller.
func NewAgentRuntimeIngestController(db *gorm.DB) *AgentRuntimeIngestController {
	return &AgentRuntimeIngestController{svc: services.NewAgentRuntimeIngestService(db)}
}

// WithService replaces the service (tests).
func (ctl *AgentRuntimeIngestController) WithService(svc *services.AgentRuntimeIngestService) *AgentRuntimeIngestController {
	ctl.svc = svc
	return ctl
}

/* ---------------------------------- ingest -------------------------------- */

// IngestAWSEvents handles POST /authsec/ingest/aws/events. The workspace and
// connector come from the secret only; the body is never logged.
func (ctl *AgentRuntimeIngestController) IngestAWSEvents(c *gin.Context) {
	ctx := c.Request.Context()
	secret := strings.TrimSpace(c.GetHeader(services.AgentEventSecretHeader))
	if secret == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + services.AgentEventSecretHeader})
		return
	}
	p, err := ctl.svc.Authenticate(ctx, secret)
	if err != nil {
		log.Printf("[agent-event-ingest] stage=auth outcome=error err=%v", err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "could not verify the event secret; retry"})
		return
	}
	if p == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unknown or revoked event secret"})
		return
	}
	if !ctl.svc.Allow(p.ConnectorID) {
		c.Header("Retry-After", "1")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded for this connector"})
		return
	}
	if c.Request.ContentLength > services.AgentEventMaxRequestBytes {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request larger than 1 MB"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, services.AgentEventMaxRequestBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request larger than 1 MB"})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "could not read the request body"})
		return
	}

	res, err := ctl.svc.Ingest(ctx, *p, body)
	switch {
	case errors.Is(err, services.ErrAgentEventBadBody):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	case errors.Is(err, services.ErrAgentEventTooLarge):
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
		return
	case errors.Is(err, services.ErrAgentEventUnauthenticated):
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	case errors.Is(err, services.ErrAgentEventDispatch):
		c.Header("Retry-After", "5")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": err.Error(), "result": res})
		return
	case err != nil:
		log.Printf("[agent-event-ingest] stage=ingest workspace=%s connector=%s outcome=error err=%v",
			p.WorkspaceID, p.ConnectorID, err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "the events could not be recorded; retry"})
		return
	}
	if res.Rejected > 0 {
		log.Printf("[agent-event-ingest] workspace=%s connector=%s received=%d rejected_account=%d rejected_invalid=%d",
			p.WorkspaceID, p.ConnectorID, res.Received, res.RejectedAccount, res.RejectedInvalid)
	}
	if res.Received > 0 && res.Rejected == res.Received {
		// Nothing was for this connector's account (403), or nothing was a
		// CloudTrail event at all (400). Neither is worth a retry.
		status := http.StatusBadRequest
		if res.RejectedAccount > 0 {
			status = http.StatusForbidden
		}
		c.AbortWithStatusJSON(status, gin.H{"error": "every event was refused", "result": res})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"success": true, "data": res})
}

/* --------------------------------- admin ---------------------------------- */

// eventStreamTarget resolves the token's workspace and the route's connector,
// after the stream's schema verified (503 with the reason until then).
func (ctl *AgentRuntimeIngestController) eventStreamTarget(c *gin.Context) (uuid.UUID, uuid.UUID, string, bool) {
	if ok, reason := ctl.svc.Available(); !ok {
		awsP2Error(c, http.StatusServiceUnavailable, services.GovCodeAgentRuntimeUnavailable,
			"Agent runtime visibility is not available on this server.", gin.H{"reason": reason})
		return uuid.Nil, uuid.Nil, "", false
	}
	ws, actor, err := workspaceAndActorFrom(c)
	if err != nil {
		awsP2Error(c, http.StatusUnauthorized, "unauthenticated", err.Error(), nil)
		return uuid.Nil, uuid.Nil, "", false
	}
	id, rerr := igaread.RouteID(igaread.RefConnector, c.Param("id"))
	if rerr != nil {
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
		return uuid.Nil, uuid.Nil, "", false
	}
	return ws, id, actor, true
}

func eventStreamError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
	case errors.Is(err, services.ErrAgentEventStreamNotFound):
		awsP2Error(c, http.StatusNotFound, "not_found", err.Error(), nil)
	case errors.Is(err, services.ErrAWSConnectorRevoked):
		awsP2Error(c, http.StatusConflict, "connector_revoked", err.Error(), nil)
	case errors.Is(err, services.ErrAgentEventSilentAfter):
		awsP2Error(c, http.StatusUnprocessableEntity, "invalid_parameter", err.Error(),
			gin.H{"parameter": "silent_after_minutes"})
	default:
		log.Printf("[agent-event-stream] outcome=error err=%v", err)
		awsP2Error(c, http.StatusInternalServerError, "internal_error",
			"the event stream could not be read or changed", nil)
	}
}

type postEventStreamBody struct {
	// SilentAfterMinutes: how long without events before the stream reads as
	// silent (15 .. 10080). Omitted keeps the current value (360 for a new one).
	SilentAfterMinutes *int `json:"silent_after_minutes"`
}

// CreateEventStream handles POST .../aws/connectors/:id/event-stream: turns
// the stream on, or rotates its secret. The secret is in this response and
// nowhere else, ever.
func (ctl *AgentRuntimeIngestController) CreateEventStream(c *gin.Context) {
	ws, id, actor, ok := ctl.eventStreamTarget(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 16<<10))
	if err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", "could not read the request body",
			gin.H{"parameter": "body"})
		return
	}
	var body postEventStreamBody
	if len(bytes.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
				"invalid request body: "+err.Error(), gin.H{"parameter": "body"})
			return
		}
	}
	var silentAfter *time.Duration
	if body.SilentAfterMinutes != nil {
		d := time.Duration(*body.SilentAfterMinutes) * time.Minute
		silentAfter = &d
	}
	view, secret, rotated, err := ctl.svc.EnableOrRotate(c.Request.Context(), ws, id, actor, silentAfter)
	if err != nil {
		eventStreamError(c, err)
		return
	}
	action := "enable_agent_event_stream"
	if rotated {
		action = "rotate_agent_event_stream"
	}
	// The audit record carries the view: the secret prefix, never the secret.
	auditAdminMutation(c, ws.String(), action, "cloud_connector", id.String(), http.StatusOK, nil, view)

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"stream":  view,
			"secret":  secret,
			"rotated": rotated,
			"cloudformation": gin.H{
				"template_url": "/authsec/discovery/aws/connectors/" + id.String() + "/event-stream/template",
				"parameters":   services.EventStreamStackParameters(view.EndpointURL, secret, id),
				"notes":        services.EventStreamNotes(),
			},
		},
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note":  "the secret is shown only in this response; store it in the stack's EventSecret parameter",
		},
	})
}

// GetEventStream handles GET .../aws/connectors/:id/event-stream: the
// stream's state, counters and whether it is silent (and since when).
func (ctl *AgentRuntimeIngestController) GetEventStream(c *gin.Context) {
	ws, id, _, ok := ctl.eventStreamTarget(c)
	if !ok {
		return
	}
	view, err := ctl.svc.Get(c.Request.Context(), ws, id)
	if err != nil {
		eventStreamError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": view, "meta": gin.H{"as_of": time.Now().UTC()}})
}

// RevokeEventStream handles DELETE .../aws/connectors/:id/event-stream: the
// secret is refused from now on. The row and its counters stay.
func (ctl *AgentRuntimeIngestController) RevokeEventStream(c *gin.Context) {
	ws, id, _, ok := ctl.eventStreamTarget(c)
	if !ok {
		return
	}
	before, after, err := ctl.svc.Revoke(c.Request.Context(), ws, id)
	if err != nil {
		eventStreamError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "revoke_agent_event_stream", "cloud_connector", id.String(),
		http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": after, "meta": gin.H{"as_of": time.Now().UTC()}})
}

// GetEventStreamTemplate handles GET .../event-stream/template: the stack and
// the connector's parameters, with the secret as a placeholder.
// ?format=yaml returns the template file itself.
func (ctl *AgentRuntimeIngestController) GetEventStreamTemplate(c *gin.Context) {
	ws, id, _, ok := ctl.eventStreamTarget(c)
	if !ok {
		return
	}
	// The connector must be this workspace's AWS connector (404 otherwise).
	if _, err := ctl.svc.Get(c.Request.Context(), ws, id); err != nil {
		eventStreamError(c, err)
		return
	}
	doc := services.EventStreamTemplate(id)
	if strings.EqualFold(c.Query("format"), "yaml") {
		c.Header("Content-Disposition", `attachment; filename="`+doc.FileName+`"`)
		c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", []byte(doc.Template))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": doc})
}

// GetModelAccessTemplate handles GET /authsec/discovery/aws/templates/model-access
// ?mode=audit|deny&form=scp|policy|rcp (default audit, scp). Deny mode returns a
// CloudFormation template (?format=yaml: the file); audit mode returns the
// audit document and denies nothing.
func (ctl *AgentRuntimeIngestController) GetModelAccessTemplate(c *gin.Context) {
	if _, _, err := workspaceAndActorFrom(c); err != nil {
		awsP2Error(c, http.StatusUnauthorized, "unauthenticated", err.Error(), nil)
		return
	}
	doc, err := services.ModelAccessTemplate(c.Query("mode"), c.Query("form"))
	if err != nil {
		param := "mode"
		if m := strings.ToLower(c.Query("mode")); m == "" || m == services.ModelAccessModeAudit || m == services.ModelAccessModeDeny {
			param = "form"
		}
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", err.Error(), gin.H{"parameter": param})
		return
	}
	if strings.EqualFold(c.Query("format"), "yaml") && doc.Template != "" {
		c.Header("Content-Disposition", `attachment; filename="`+doc.FileName+`"`)
		c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", []byte(doc.Template))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": doc})
}
