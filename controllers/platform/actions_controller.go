package platform

import (
	"net/http"
	"strconv"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ActionsController serves the Activity Index & Actions API surface under
// /api/iga/v1 (workload actions) and /api/iga/v2 (collector actions, changes,
// detail). The workspace is always taken from the token, never from a body or
// query parameter.
type ActionsController struct {
	svc *services.ActionsService
}

// NewActionsController constructs the controller.
func NewActionsController(svc *services.ActionsService) *ActionsController {
	return &ActionsController{svc: svc}
}

// ListForWorkload handles GET /api/iga/v1/workloads/:id/actions.
// Extracts the workload ID from the path, cursor/limit from query.
func (ctl *ActionsController) ListForWorkload(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	workloadID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workload id"})
		return
	}

	cursor := c.Query("cursor")
	limit := ctl.parseLimit(c)
	filters := ctl.parseFilters(c)

	page, err := ctl.svc.ListForWorkload(c.Request.Context(), ws, workloadID, cursor, limit, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": page})
}

// ListForCollector handles GET /api/iga/v2/collectors/:id/actions.
// Includes unattributed events (workload_id IS NULL).
func (ctl *ActionsController) ListForCollector(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	collectorID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid collector id"})
		return
	}

	cursor := c.Query("cursor")
	limit := ctl.parseLimit(c)
	filters := ctl.parseFilters(c)

	page, err := ctl.svc.ListForCollector(c.Request.Context(), ws, collectorID, cursor, limit, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": page})
}

// GetAction handles GET /api/iga/v2/actions/:id.
// Returns the full detail of one action.
func (ctl *ActionsController) GetAction(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	actionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action id"})
		return
	}

	detail, err := ctl.svc.Get(c.Request.Context(), ws, actionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": detail})
}

// Changes handles GET /api/iga/v2/actions/changes.
// Returns a forward catch-up page by activity_sequence.
func (ctl *ActionsController) Changes(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}

	cursor := c.Query("cursor")
	limit := ctl.parseLimit(c)

	page, err := ctl.svc.Changes(c.Request.Context(), ws, cursor, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": page})
}

// workspace resolves the caller's workspace from the token. Never from the
// body or query parameters.
func (ctl *ActionsController) workspace(c *gin.Context) (uuid.UUID, bool) {
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

// parseLimit reads the limit query parameter and clamps it.
func (ctl *ActionsController) parseLimit(c *gin.Context) int {
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0 // service applies the default
}

// parseFilters builds an ActionFilter from query parameters.
func (ctl *ActionsController) parseFilters(c *gin.Context) services.ActionFilter {
	f := services.ActionFilter{
		EventFamily: c.Query("event_family"),
		Operation:   c.Query("operation"),
		Outcome:     c.Query("outcome"),
		Source:      c.Query("source"),
	}
	if v := c.Query("time_from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.TimeFrom = &t
		}
	}
	if v := c.Query("time_to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.TimeTo = &t
		}
	}
	if v := c.Query("policy_ref"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.PolicyRef = &id
		}
	}
	return f
}
