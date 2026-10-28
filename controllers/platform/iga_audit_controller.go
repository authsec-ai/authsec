package platform

import (
	"net/http"
	"strconv"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// IGAAuditController serves the IGA audit surface under /api/iga/v2.
//
// The audit endpoint returns normalised lifecycle events that link discovery,
// identity, policy, enforcement and access decisions into a continuous chain.
// Results are cursor-paginated and can be filtered by agent, SPIFFE identity,
// policy revision, rule/primitive, backend, actor, time range, outcome, and
// correlation ID.
type IGAAuditController struct {
	svc *services.IGAAuditService
}

// NewIGAAuditController constructs the controller.
func NewIGAAuditController(svc *services.IGAAuditService) *IGAAuditController {
	return &IGAAuditController{svc: svc}
}

// workspace resolves the caller's workspace from the token. Never from the
// body or query parameters.
func (ctl *IGAAuditController) workspace(c *gin.Context) (uuid.UUID, bool) {
	raw := c.GetString("workspace_id")
	if raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
	ws, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
	return ws, true
}

// QueryAuditEvents handles GET /api/iga/v2/audit.
//
// Query parameters:
//
//	agent_id        — filter by agent UUID
//	spiffe_id       — filter by SPIFFE identity URI
//	policy_id       — filter by policy UUID
//	policy_revision — filter by integer revision
//	rule_id         — filter by rule ID string
//	primitive_id    — filter by primitive ID string
//	backend         — filter by enforcement backend
//	actor_id        — filter by verified actor UUID
//	event_type      — filter by event type
//	outcome         — filter by outcome
//	correlation_id  — filter by correlation ID
//	time_from       — RFC 3339 lower bound (inclusive)
//	time_to         — RFC 3339 upper bound (inclusive)
//	cursor          — opaque cursor from a previous response
//	limit           — page size (1..200, default 50)
func (ctl *IGAAuditController) QueryAuditEvents(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}

	filter := services.IGAAuditFilter{
		SpiffeID:      c.Query("spiffe_id"),
		RuleID:        c.Query("rule_id"),
		PrimitiveID:   c.Query("primitive_id"),
		Backend:       c.Query("backend"),
		EventType:     c.Query("event_type"),
		Outcome:       c.Query("outcome"),
		CorrelationID: c.Query("correlation_id"),
		Cursor:        c.Query("cursor"),
	}

	if v := c.Query("agent_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.AgentID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
			return
		}
	}
	if v := c.Query("policy_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.PolicyID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy_id"})
			return
		}
	}
	if v := c.Query("actor_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			filter.ActorID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid actor_id"})
			return
		}
	}
	if v := c.Query("policy_revision"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.PolicyRevision = &n
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy_revision"})
			return
		}
	}
	if v := c.Query("time_from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.TimeFrom = &t
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid time_from: use RFC 3339"})
			return
		}
	}
	if v := c.Query("time_to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.TimeTo = &t
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid time_to: use RFC 3339"})
			return
		}
	}
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}

	page, err := ctl.svc.QueryEvents(c.Request.Context(), ws, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}

	c.JSON(http.StatusOK, page)
}
