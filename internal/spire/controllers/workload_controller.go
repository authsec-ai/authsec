package controllers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/spire/middleware"
	"github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/internal/spire/utils"
)

// WorkloadController handles workload attestation and entry management.
// The workspace is always the authenticated one: an admin's platform token
// (entry CRUD) or an agent's certificate (attest, revoke, by-parent).
type WorkloadController struct {
	attestationService *services.WorkloadAttestationService
	entryService       *services.WorkloadEntryService
	logger             *logrus.Entry
}

// NewWorkloadController creates a new workload controller
func NewWorkloadController(attestationService *services.WorkloadAttestationService, entryService *services.WorkloadEntryService, logger *logrus.Entry) *WorkloadController {
	return &WorkloadController{attestationService: attestationService, entryService: entryService, logger: logger}
}

// --- Workload attestation (agent certificate) ---

// AttestWorkload handles POST /spiresvc/v1/workload/attest.
func (ctrl *WorkloadController) AttestWorkload(c *gin.Context) {
	var req struct {
		WorkspaceID string            `json:"workspace_id"`
		AgentID     string            `json:"agent_id"`
		Selectors   map[string]string `json:"selectors"`
		CSR         string            `json:"csr"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	agentSpiffeID, ok := middleware.GetSpireSpiffeID(c)
	if !ok {
		sendError(c, ctrl.logger, errors.NewUnauthorizedError("Agent certificate required", nil))
		return
	}
	if req.AgentID != "" && req.AgentID != agentSpiffeID {
		sendError(c, ctrl.logger, errors.NewForbiddenError("agent_id does not match the authenticated agent", nil))
		return
	}
	if len(req.Selectors) == 0 {
		sendError(c, ctrl.logger, errors.NewBadRequestError("selectors are required", nil))
		return
	}
	resp, err := ctrl.attestationService.AttestWorkload(c.Request.Context(), &services.AttestWorkloadRequest{
		AgentID:   agentSpiffeID,
		Selectors: req.Selectors,
		CSR:       req.CSR,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"spiffe_id":    resp.SpiffeID,
		"certificate":  resp.Certificate,
		"trust_bundle": resp.TrustBundle,
		"expires_at":   resp.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		"ttl":          resp.TTL,
	})
}

// RevokeWorkloadSVID handles POST /spiresvc/v1/workload/revoke: an SVID the
// authenticated agent obtained, in its workspace.
func (ctrl *WorkloadController) RevokeWorkloadSVID(c *gin.Context) {
	var req struct {
		WorkspaceID  string `json:"workspace_id"`
		SerialNumber string `json:"serial_number"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if req.SerialNumber == "" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("serial_number is required", nil))
		return
	}
	agentSpiffeID, _ := middleware.GetSpireSpiffeID(c)
	if err := ctrl.attestationService.RevokeWorkloadSVID(c.Request.Context(), agentSpiffeID, req.SerialNumber); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workload SVID revoked successfully", "serial_number": req.SerialNumber})
}

// ListEntriesByParent handles GET /spiresvc/v1/entries/by-parent: the
// entries the authenticated agent serves (its own and unassigned ones).
func (ctrl *WorkloadController) ListEntriesByParent(c *gin.Context) {
	if err := sameWorkspace(c, c.Query("workspace_id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	agentSpiffeID, ok := middleware.GetSpireSpiffeID(c)
	if !ok {
		sendError(c, ctrl.logger, errors.NewUnauthorizedError("Agent certificate required", nil))
		return
	}
	if p := c.Query("parent_id"); p != "" && p != agentSpiffeID {
		sendError(c, ctrl.logger, errors.NewForbiddenError("parent_id must be the authenticated agent", nil))
		return
	}
	entries, err := ctrl.entryService.ListEntriesByParent(c.Request.Context(), agentSpiffeID)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	ctrl.sendEntries(c, entries, len(entries))
}

// --- Entry management (AuthMiddleware) ---

// CreateEntry handles POST /spiresvc/v1/entries
func (ctrl *WorkloadController) CreateEntry(c *gin.Context) {
	var req dto.CreateWorkloadEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	created, err := ctrl.entryService.CreateEntry(c.Request.Context(), &models.WorkloadEntry{
		SpiffeID:   req.SpiffeID,
		ParentID:   req.ParentID,
		Selectors:  req.Selectors,
		TTL:        req.TTL,
		Admin:      req.Admin,
		Downstream: req.Downstream,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusCreated, toEntryResponse(created))
}

// CreateAgentEntry handles POST /spiresvc/v1/entries/agent: an entry for an
// AI agent, SPIFFE ID spiffe://<workspace>/agent/<client_id>/<agent_type>.
func (ctrl *WorkloadController) CreateAgentEntry(c *gin.Context) {
	var req dto.CreateAgentEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	if err := sameWorkspace(c, req.WorkspaceID); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	ws, err := requestWorkspace(c)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if err := utils.ValidateSpiffeComponent(req.ClientID, "client_id"); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError(err.Error(), err))
		return
	}
	if err := utils.ValidateSpiffeComponent(req.AgentType, "agent_type"); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError(err.Error(), err))
		return
	}
	selectors := map[string]string{}
	for k, v := range req.Selectors {
		selectors[k] = v
	}
	selectors["authsec:client_id"] = req.ClientID
	selectors["authsec:agent_type"] = req.AgentType
	selectors["authsec:workspace_id"] = ws

	created, err := ctrl.entryService.CreateEntry(c.Request.Context(), &models.WorkloadEntry{
		SpiffeID:  "spiffe://" + ws + "/agent/" + req.ClientID + "/" + req.AgentType,
		ParentID:  req.ParentID,
		Selectors: selectors,
		TTL:       req.TTL,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusCreated, dto.CreateAgentEntryResponse{
		EntryID:     created.ID,
		SpiffeID:    created.SpiffeID,
		WorkspaceID: created.WorkspaceID,
		ClientID:    req.ClientID,
		ParentID:    created.ParentID,
		Selectors:   created.Selectors,
		TTL:         created.TTL,
		CreatedAt:   created.CreatedAt,
	})
}

// GetEntry handles GET /spiresvc/v1/entries/:id. Another workspace's entry
// is 404.
func (ctrl *WorkloadController) GetEntry(c *gin.Context) {
	entry, err := ctrl.entryService.GetEntry(c.Request.Context(), c.Param("id"))
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, toEntryResponse(entry))
}

// ListEntries handles GET /spiresvc/v1/entries
func (ctrl *WorkloadController) ListEntries(c *gin.Context) {
	if err := sameWorkspace(c, c.Query("workspace_id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	selectorType := c.Query("selector_type")
	if selectorType != "" && selectorType != "unix" && selectorType != "kubernetes" && selectorType != "docker" {
		sendError(c, ctrl.logger, errors.NewBadRequestError("selector_type must be one of: unix, kubernetes, docker", nil))
		return
	}
	limit := 100
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = min(v, 1000)
	}
	offset := 0
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		offset = v
	}
	var admin *bool
	switch c.Query("admin") {
	case "true":
		t := true
		admin = &t
	case "false":
		f := false
		admin = &f
	}
	filter := &models.WorkloadEntryFilter{
		ParentID:     c.Query("parent_id"),
		SpiffeID:     c.Query("spiffe_id"),
		SelectorType: selectorType,
		Admin:        admin,
		Limit:        limit,
		Offset:       offset,
	}
	if s := c.Query("spiffe_id_search"); s != "" {
		filter.SpiffeID, filter.SpiffeIDPartial = s, true
	}
	entries, err := ctrl.entryService.ListEntries(c.Request.Context(), filter)
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	total, err := ctrl.entryService.CountEntries(c.Request.Context(), filter)
	if err != nil {
		total = len(entries)
	}
	ctrl.sendEntries(c, entries, total)
}

// UpdateEntry handles PUT /spiresvc/v1/entries/:id. Another workspace's
// entry is 404.
func (ctrl *WorkloadController) UpdateEntry(c *gin.Context) {
	if err := sameWorkspace(c, c.Query("workspace_id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	var req dto.UpdateWorkloadEntryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sendError(c, ctrl.logger, errors.NewBadRequestError("Invalid request body", err))
		return
	}
	updated, err := ctrl.entryService.UpdateEntry(c.Request.Context(), &models.WorkloadEntry{
		ID:         c.Param("id"),
		SpiffeID:   req.SpiffeID,
		ParentID:   req.ParentID,
		Selectors:  req.Selectors,
		TTL:        req.TTL,
		Admin:      req.Admin,
		Downstream: req.Downstream,
	})
	if err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, toEntryResponse(updated))
}

// DeleteEntry handles DELETE /spiresvc/v1/entries/:id. Another workspace's
// entry is 404.
func (ctrl *WorkloadController) DeleteEntry(c *gin.Context) {
	if err := sameWorkspace(c, c.Query("workspace_id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	if err := ctrl.entryService.DeleteEntry(c.Request.Context(), c.Param("id")); err != nil {
		sendError(c, ctrl.logger, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Workload entry deleted successfully", "id": c.Param("id")})
}

func (ctrl *WorkloadController) sendEntries(c *gin.Context, entries []*models.WorkloadEntry, total int) {
	out := make([]*dto.WorkloadEntryResponse, 0, len(entries))
	for _, e := range entries {
		out = append(out, toEntryResponse(e))
	}
	c.JSON(http.StatusOK, dto.ListWorkloadEntriesResponse{Entries: out, Total: total})
}

func toEntryResponse(e *models.WorkloadEntry) *dto.WorkloadEntryResponse {
	return &dto.WorkloadEntryResponse{
		ID:          e.ID,
		WorkspaceID: e.WorkspaceID,
		SpiffeID:    e.SpiffeID,
		ParentID:    e.ParentID,
		Selectors:   e.Selectors,
		TTL:         e.TTL,
		Admin:       e.Admin,
		Downstream:  e.Downstream,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	}
}
