package platform

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/authsec-ai/authsec/middlewares"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DiscoveryController serves the workspace-scoped agent-discovery inventory:
// connector registration, the Unregistered Agents report, and the claim /
// quarantine decisions that bring a discovered agent under management.
//
// Discovery is safe to run against production because a sighting grants
// nothing — rows land unregistered and only a human moves them forward.
type DiscoveryController struct {
	db *gorm.DB
}

// NewDiscoveryController constructs a DiscoveryController.
func NewDiscoveryController(db *gorm.DB) *DiscoveryController {
	return &DiscoveryController{db: db}
}

/* -------------------------------------------------------------------------- */
/*                              Request types                                 */
/* -------------------------------------------------------------------------- */

// DiscoverySourceCreateRequest is the body for POST /authsec/discovery/sources.
type DiscoverySourceCreateRequest struct {
	Kind        string                 `json:"kind" binding:"required"`
	DisplayName string                 `json:"display_name" binding:"required"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
}

// DiscoverySourceUpdateRequest is the body for PUT /authsec/discovery/sources/:id.
type DiscoverySourceUpdateRequest struct {
	DisplayName *string                `json:"display_name,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	LastStatus  *string                `json:"last_status,omitempty"`
	LastError   *string                `json:"last_error,omitempty"`
}

// SightingRequest is the body for POST /authsec/discovery/sightings — what a
// connector reports. Idempotent on (source, fingerprint) within the workspace.
type SightingRequest struct {
	Source            string                 `json:"source" binding:"required"`
	DiscoverySourceID *uuid.UUID             `json:"discovery_source_id,omitempty"`
	Fingerprint       string                 `json:"fingerprint" binding:"required"`
	DisplayName       string                 `json:"display_name,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	DeploymentOrigin  string                 `json:"deployment_origin,omitempty"`
	Archetype         string                 `json:"archetype,omitempty"`
}

// AgentUpdateRequest is the body for PUT /authsec/discovery/agents/:id.
// Registering an agent is not done here — that is the claim endpoint.
type AgentUpdateRequest struct {
	DisplayName      *string                `json:"display_name,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	DeploymentOrigin *string                `json:"deployment_origin,omitempty"`
	Archetype        *string                `json:"archetype,omitempty"`
	Status           *string                `json:"status,omitempty"`
	OwnerUserID      *uuid.UUID             `json:"owner_user_id,omitempty"`
}

// ClaimAgentRequest is the body for POST /authsec/discovery/agents/:id/claim.
// Both fields are mandatory: an agent needs an identity for its tokens and a
// human who is accountable for it.
type ClaimAgentRequest struct {
	MatchedClientID uuid.UUID `json:"matched_client_id" binding:"required"`
	OwnerUserID     uuid.UUID `json:"owner_user_id" binding:"required"`
	Archetype       string    `json:"archetype,omitempty"`
}

// QuarantineAgentRequest is the body for POST /authsec/discovery/agents/:id/quarantine.
type QuarantineAgentRequest struct {
	Reason string `json:"reason" binding:"required"`
}

/* -------------------------------------------------------------------------- */
/*                            Internal helpers                                */
/* -------------------------------------------------------------------------- */

func (ctl *DiscoveryController) manager() services.DiscoveryManager {
	return services.NewDiscoveryManager(repositories.NewDiscoveryRepository(ctl.db))
}

// workspace returns the caller's workspace and principal from the token. The
// workspace is never taken from the request body — a caller must not be able to
// name someone else's workspace.
func (ctl *DiscoveryController) workspace(c *gin.Context) (uuid.UUID, string, error) {
	workspaceStr := c.GetString("workspace_id")
	if workspaceStr == "" {
		return uuid.Nil, "", fmt.Errorf("workspace_id not found in token")
	}
	wsID, err := uuid.Parse(workspaceStr)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid workspace_id: %w", err)
	}

	principal := c.GetString("client_id")
	if principal == "" {
		if userID, uerr := middlewares.ResolveUserID(c); uerr == nil {
			principal = userID
		}
	}
	if principal == "" {
		principal = workspaceStr
	}
	return wsID, principal, nil
}

// actingUser returns the authenticated user id, used to attribute a claim or a
// quarantine to a person. Nil when the caller is a machine principal.
func (ctl *DiscoveryController) actingUser(c *gin.Context) *uuid.UUID {
	raw, err := middlewares.ResolveUserID(c)
	if err != nil || raw == "" {
		return nil
	}
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed == uuid.Nil {
		return nil
	}
	return &parsed
}

// pathID parses the :id path parameter.
func pathID(c *gin.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid id: %w", err)
	}
	return id, nil
}

// discoveryError maps a service/repository error to the right HTTP status.
func discoveryError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, repositories.ErrQuarantined):
		// The agent exists but is flagged untrusted — a conflict, not a 500.
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, repositories.ErrForwardOnly):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

/* -------------------------------------------------------------------------- */
/*                          Handlers — sources                                */
/* -------------------------------------------------------------------------- */

// CreateDiscoverySource handles POST /authsec/discovery/sources.
func (ctl *DiscoveryController) CreateDiscoverySource(c *gin.Context) {
	wsID, principal, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req DiscoverySourceCreateRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().CreateSource(wsID, principal, services.DiscoverySourceInput{
		Kind:        req.Kind,
		DisplayName: req.DisplayName,
		Config:      req.Config,
		Enabled:     req.Enabled,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "create", "discovery_source", out.ID.String(),
		http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// ListDiscoverySources handles GET /authsec/discovery/sources.
func (ctl *DiscoveryController) ListDiscoverySources(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().ListSources(wsID, c.Query("kind"), c.Query("enabled") == "true")
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sources": out})
}

// GetDiscoverySource handles GET /authsec/discovery/sources/:id.
func (ctl *DiscoveryController) GetDiscoverySource(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().GetSource(wsID, id)
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// UpdateDiscoverySource handles PUT /authsec/discovery/sources/:id.
func (ctl *DiscoveryController) UpdateDiscoverySource(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req DiscoverySourceUpdateRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := ctl.manager()
	before, err := mgr.GetSource(wsID, id)
	if err != nil {
		discoveryError(c, err)
		return
	}

	out, err := mgr.UpdateSource(wsID, id, services.DiscoverySourceUpdateInput{
		DisplayName: req.DisplayName,
		Config:      req.Config,
		Enabled:     req.Enabled,
		LastStatus:  req.LastStatus,
		LastError:   req.LastError,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "update", "discovery_source", id.String(),
		http.StatusOK, before, out)
	c.JSON(http.StatusOK, out)
}

// DeleteDiscoverySource handles DELETE /authsec/discovery/sources/:id. Agents
// already discovered by this source are kept; their pointer is simply nulled.
func (ctl *DiscoveryController) DeleteDiscoverySource(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ctl.manager().DeleteSource(wsID, id); err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "delete", "discovery_source", id.String(),
		http.StatusNoContent, nil, nil)
	c.Status(http.StatusNoContent)
}

/* -------------------------------------------------------------------------- */
/*                        Handlers — sightings & agents                       */
/* -------------------------------------------------------------------------- */

// ReportSighting handles POST /authsec/discovery/sightings — the connector
// ingress and the only path that creates an inventory row.
//
// Returns 201 for a newly seen agent and 200 when an existing row was bumped.
// Neither is an error: a connector must be able to re-report on every scan.
func (ctl *DiscoveryController) ReportSighting(c *gin.Context) {
	wsID, principal, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req SightingRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, created, err := ctl.manager().ReportSighting(wsID, principal, services.SightingInput{
		Source:            req.Source,
		DiscoverySourceID: req.DiscoverySourceID,
		Fingerprint:       req.Fingerprint,
		DisplayName:       req.DisplayName,
		Metadata:          req.Metadata,
		DeploymentOrigin:  req.DeploymentOrigin,
		Archetype:         req.Archetype,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
		// Only a first sighting is a governance event worth auditing; a bump is
		// routine telemetry and would flood the admin-mutation log.
		auditAdminMutation(c, wsID.String(), "discover", "discovered_agent",
			agent.ID.String(), status, nil, agent)
	}
	c.JSON(status, gin.H{"agent": agent, "created": created})
}

// ListDiscoveredAgents handles GET /authsec/discovery/agents.
// Filter with ?status=&deployment_origin=&source=&archetype=&unowned=true.
// status=unregistered is the Unregistered Agents report; manual-origin agents
// sort first because they are the hardest to attribute.
func (ctl *DiscoveryController) ListDiscoveredAgents(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))

	agents, total, err := ctl.manager().ListAgents(wsID, repositories.AgentFilter{
		Status:           c.Query("status"),
		DeploymentOrigin: c.Query("deployment_origin"),
		Source:           c.Query("source"),
		Archetype:        c.Query("archetype"),
		UnownedOnly:      c.Query("unowned") == "true",
		Limit:            limit,
		Offset:           offset,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents, "total": total})
}

// GetDiscoveredAgent handles GET /authsec/discovery/agents/:id. Pass
// ?source=&fingerprint= instead of an id to look one up by fingerprint.
func (ctl *DiscoveryController) GetDiscoveredAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().GetAgent(wsID, id)
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// LookupDiscoveredAgent handles GET /authsec/discovery/agents/lookup?source=&fingerprint=
// — the connector-side "do you already know this agent?" check.
func (ctl *DiscoveryController) LookupDiscoveredAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().GetAgentByFingerprint(wsID, c.Query("source"), c.Query("fingerprint"))
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}

// UpdateDiscoveredAgent handles PUT /authsec/discovery/agents/:id — operator
// corrections (a misclassified origin, a known archetype) and the move to
// 'ignored'. Registering goes through the claim endpoint.
func (ctl *DiscoveryController) UpdateDiscoveredAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req AgentUpdateRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := ctl.manager()
	before, err := mgr.GetAgent(wsID, id)
	if err != nil {
		discoveryError(c, err)
		return
	}

	out, err := mgr.UpdateAgent(wsID, id, services.AgentUpdateInput{
		DisplayName:      req.DisplayName,
		Metadata:         req.Metadata,
		DeploymentOrigin: req.DeploymentOrigin,
		Archetype:        req.Archetype,
		Status:           req.Status,
		OwnerUserID:      req.OwnerUserID,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "update", "discovered_agent", id.String(),
		http.StatusOK, before, out)
	c.JSON(http.StatusOK, out)
}

// DeleteDiscoveredAgent handles DELETE /authsec/discovery/agents/:id. Prefer
// status='ignored' to keep the row as evidence; this drops it outright.
func (ctl *DiscoveryController) DeleteDiscoveredAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ctl.manager().DeleteAgent(wsID, id); err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "delete", "discovered_agent", id.String(),
		http.StatusNoContent, nil, nil)
	c.Status(http.StatusNoContent)
}

/* -------------------------------------------------------------------------- */
/*                     Handlers — claim / quarantine / KPI                    */
/* -------------------------------------------------------------------------- */

// ClaimAgent handles POST /authsec/discovery/agents/:id/claim — the transition
// from "seen" to "governed". Quarantine blocks it and an owner is mandatory.
func (ctl *DiscoveryController) ClaimAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req ClaimAgentRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().ClaimAgent(wsID, id, services.ClaimInput{
		MatchedClientID: req.MatchedClientID,
		OwnerUserID:     req.OwnerUserID,
		Archetype:       req.Archetype,
		// Who claimed it comes from the token, never the body.
		ClaimedBy: ctl.actingUser(c),
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "claim", "discovered_agent", id.String(),
		http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// QuarantineAgent handles POST /authsec/discovery/agents/:id/quarantine — the
// alternative to a claim. Flags the agent untrusted and blocks a later claim.
func (ctl *DiscoveryController) QuarantineAgent(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req QuarantineAgentRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().QuarantineAgent(wsID, id, req.Reason, ctl.actingUser(c))
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "quarantine", "discovered_agent", id.String(),
		http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// GetCoverage handles GET /authsec/discovery/coverage — the headline governance
// KPI: what share of discovered agents is under management, split by origin.
func (ctl *DiscoveryController) GetCoverage(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	out, err := ctl.manager().Coverage(wsID)
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
