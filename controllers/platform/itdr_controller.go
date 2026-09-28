package platform

import (
	"io"
	"net/http"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ITDRController is the /api/iga/v2/itdr admin API (TRD 2, WP-A8).
type ITDRController struct {
	svc *services.ITDRService
}

// NewITDRController builds the controller.
func NewITDRController(svc *services.ITDRService) *ITDRController {
	return &ITDRController{svc: svc}
}

// ── Detection rules ────────────────────────────────────────────────────

func (ctl *ITDRController) ListDetectionRules(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	status, body, err := ctl.svc.ListDetectionRules(c.Request.Context(), actor.WorkspaceID)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) GetDetectionRule(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "rule_id")
	if !ok {
		return
	}
	status, body, err := ctl.svc.GetDetectionRule(c.Request.Context(), actor.WorkspaceID, id)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) CreateDetectionRule(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.CreateDetectionRule(c.Request.Context(), actor, body)
	writePolicy(c, status, resp, svcErr)
}

func (ctl *ITDRController) UpdateDetectionRule(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "rule_id")
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.UpdateDetectionRule(c.Request.Context(), actor, id, body)
	writePolicy(c, status, resp, svcErr)
}

// ── Findings ───────────────────────────────────────────────────────────

func (ctl *ITDRController) ListFindings(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	filterStatus := c.Query("status")
	status, body, err := ctl.svc.ListFindings(c.Request.Context(), actor.WorkspaceID, filterStatus)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) GetFinding(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "finding_id")
	if !ok {
		return
	}
	status, body, err := ctl.svc.GetFinding(c.Request.Context(), actor.WorkspaceID, id)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) CreateFinding(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.CreateFinding(c.Request.Context(), actor, body)
	writePolicy(c, status, resp, svcErr)
}

func (ctl *ITDRController) UpdateFindingStatus(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "finding_id")
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.UpdateFindingStatus(c.Request.Context(), actor, id, body)
	writePolicy(c, status, resp, svcErr)
}

// ── Response plans ─────────────────────────────────────────────────────

func (ctl *ITDRController) ListResponsePlans(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	findingID, ok := itdrID(c, "finding_id")
	if !ok {
		return
	}
	status, body, err := ctl.svc.ListResponsePlans(c.Request.Context(), actor.WorkspaceID, findingID)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) CreateResponsePlan(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.CreateResponsePlan(c.Request.Context(), actor, body)
	writePolicy(c, status, resp, svcErr)
}

func (ctl *ITDRController) ApproveResponsePlan(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "plan_id")
	if !ok {
		return
	}
	status, body, err := ctl.svc.ApproveResponsePlan(c.Request.Context(), actor, id)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) TransitionResponsePlan(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "plan_id")
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.TransitionResponsePlan(c.Request.Context(), actor, id, body)
	writePolicy(c, status, resp, svcErr)
}

// ── Escalation leases ──────────────────────────────────────────────────

func (ctl *ITDRController) ListEscalationLeases(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	filterStatus := c.Query("status")
	status, body, err := ctl.svc.ListEscalationLeases(c.Request.Context(), actor.WorkspaceID, filterStatus)
	writePolicy(c, status, body, err)
}

func (ctl *ITDRController) CreateEscalationLease(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "read_error", Message: "Cannot read body."})
		return
	}
	status, resp, svcErr := ctl.svc.CreateEscalationLease(c.Request.Context(), actor, body)
	writePolicy(c, status, resp, svcErr)
}

func (ctl *ITDRController) RedeemEscalationLease(c *gin.Context) {
	actor, ok := policyActor(c)
	if !ok {
		return
	}
	id, ok := itdrID(c, "lease_id")
	if !ok {
		return
	}
	var input struct {
		Nonce string `json:"nonce"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "nonce is required."})
		return
	}
	status, body, err := ctl.svc.RedeemEscalationLease(c.Request.Context(), actor.WorkspaceID, id, input.Nonce)
	writePolicy(c, status, body, err)
}

// itdrID parses a UUID path param, returning 404 on failure.
func itdrID(c *gin.Context, param string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(param))
	if err != nil {
		writePolicy(c, 0, nil, &services.StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Not found."})
		return uuid.Nil, false
	}
	return id, true
}
