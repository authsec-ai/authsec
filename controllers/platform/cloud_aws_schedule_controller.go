package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Automatic AWS rescans: the per-connector schedule.
//
//	GET /authsec/discovery/aws/connectors/:id/schedule   discovery:read
//	PUT /authsec/discovery/aws/connectors/:id/schedule   discovery:admin
//
// Errors use the §5.2 envelope the other Phase 2 connector routes use
// ({"error": {"code", "message"}}). See .claude/specs/SPEC-aws-scheduled-scans.md.

type putScanScheduleBody struct {
	Enabled         *bool `json:"enabled"`
	IntervalMinutes *int  `json:"interval_minutes"`
}

func (ctl *CloudAWSController) scheduleService(c *gin.Context) (*services.AWSScanScheduleService, bool) {
	svc, ok := ctl.p2Service(c)
	if !ok {
		return nil, false
	}
	return services.NewAWSScanScheduleService(ctl.db, svc), true
}

// scheduleError maps a schedule service error to a status that says whose
// problem it is.
func scheduleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repositories.ErrCloudConnectorNotFound):
		awsP2Error(c, http.StatusNotFound, "not_found", "connector not found", nil)
	case errors.Is(err, services.ErrAWSConnectorRevoked):
		awsP2Error(c, http.StatusConflict, "connector_revoked", err.Error(), nil)
	case errors.Is(err, services.ErrScheduleInterval):
		awsP2Error(c, http.StatusUnprocessableEntity, "invalid_parameter", err.Error(),
			gin.H{"parameter": "interval_minutes"})
	default:
		awsP2Error(c, http.StatusInternalServerError, "internal_error",
			"the schedule could not be read or changed", nil)
	}
}

// GetScanSchedule handles GET .../aws/connectors/:id/schedule. A connector that
// was never scheduled reads as off with the default interval.
func (ctl *CloudAWSController) GetScanSchedule(c *gin.Context) {
	ws, id, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	svc, ok := ctl.scheduleService(c)
	if !ok {
		return
	}
	view, err := svc.Get(c.Request.Context(), ws, id)
	if err != nil {
		scheduleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    view,
		"meta":    gin.H{"as_of": time.Now().UTC()},
	})
}

// UpdateScanSchedule handles PUT .../aws/connectors/:id/schedule with
// {"enabled": bool, "interval_minutes": int}. enabled is required;
// interval_minutes (1440 or 10080) keeps its current value, or the default, when
// omitted. Turning a schedule on, resuming a paused one or changing its
// interval sets the next scan one interval from now; it never scans at once.
func (ctl *CloudAWSController) UpdateScanSchedule(c *gin.Context) {
	ws, id, ok := ctl.p2Target(c)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter", "could not read the request body",
			gin.H{"parameter": "body"})
		return
	}
	var body putScanScheduleBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"invalid request body: "+err.Error(), gin.H{"parameter": "body"})
		return
	}
	if dec.More() {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"the request body must be one JSON object", gin.H{"parameter": "body"})
		return
	}
	if body.Enabled == nil {
		awsP2Error(c, http.StatusBadRequest, "invalid_parameter",
			"enabled is required", gin.H{"parameter": "enabled"})
		return
	}

	_, actor, aerr := ctl.workspaceAndActor(c)
	if aerr != nil {
		awsP2Error(c, http.StatusUnauthorized, "unauthenticated", aerr.Error(), nil)
		return
	}
	svc, ok := ctl.scheduleService(c)
	if !ok {
		return
	}
	after, before, err := svc.Put(c.Request.Context(), ws, id, *body.Enabled, body.IntervalMinutes, actor)
	if err != nil {
		scheduleError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "update_scan_schedule", "cloud_connector", id.String(),
		http.StatusOK, before, after)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    after,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			"note": "the next scan is one interval from now; use Scan now to scan immediately. " +
				"Scans run only while the scheduler is active on this deployment (data.scheduler_active).",
		},
	})
}
