package platform

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	// WorkspaceID is supplied by the connector, which is configured with it at
	// deploy time. The sightings route is unauthenticated (see routes.go), so there
	// is no token to derive the workspace from — the caller asserts it.
	//
	// Typed as a string rather than uuid.UUID on purpose: `binding:"required"` on a
	// uuid.UUID treats the all-zero UUID as absent, and the all-zero UUID is the
	// real System workspace. A string plus an explicit parse avoids silently
	// rejecting it and yields a clearer error.
	WorkspaceID       string                 `json:"workspace_id" binding:"required"`
	Source            string                 `json:"source" binding:"required"`
	DiscoverySourceID *uuid.UUID             `json:"discovery_source_id,omitempty"`
	Fingerprint       string                 `json:"fingerprint" binding:"required"`
	DisplayName       string                 `json:"display_name,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	DeploymentOrigin  string                 `json:"deployment_origin,omitempty"`
	Archetype         string                 `json:"archetype,omitempty"`
	// ObservedAt is when the connector saw this, which orders runtime-state
	// transitions. Optional for backward compatibility with connectors that predate
	// lifecycle tracking; absent means "now".
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// AgentRegistrationRequest is the body for POST
// /authsec/discovery/agent-registration — a deployed connector announcing itself
// and then heartbeating.
//
// Unauthenticated, exactly like /sightings, and for the same reason: the agent is
// configured with its workspace at deploy time and asserts it. WorkspaceID is a
// string for the same reason too — `binding:"required"` on a uuid.UUID rejects the
// all-zero UUID, which is the real System workspace.
type AgentRegistrationRequest struct {
	WorkspaceID string `json:"workspace_id" binding:"required"`
	Kind        string `json:"kind" binding:"required"`
	// InstanceID is the stable key this agent re-registers under, so a restart,
	// upgrade, or reschedule updates its row instead of creating another.
	InstanceID   string                 `json:"instance_id" binding:"required"`
	DisplayName  string                 `json:"display_name,omitempty"`
	ClusterName  string                 `json:"cluster_name" binding:"required"`
	ClusterUID   string                 `json:"cluster_uid,omitempty"`
	AgentVersion string                 `json:"agent_version,omitempty"`
	Status       string                 `json:"status,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Runtime      map[string]interface{} `json:"runtime,omitempty"`
	// ReportedSightings lets a heartbeat advance last_sync_at only when the agent
	// has actually produced output. An idle cluster's agent is healthy but has
	// nothing to sync.
	ReportedSightings int64 `json:"reported_sightings,omitempty"`
}

// LifecycleEventRequest is the body for POST /authsec/discovery/lifecycle — a
// connector reporting that an agent's runtime state changed.
type LifecycleEventRequest struct {
	WorkspaceID       string                 `json:"workspace_id" binding:"required"`
	Source            string                 `json:"source" binding:"required"`
	DiscoverySourceID *uuid.UUID             `json:"discovery_source_id,omitempty"`
	Fingerprint       string                 `json:"fingerprint" binding:"required"`
	Event             string                 `json:"event" binding:"required"`
	Reason            string                 `json:"reason,omitempty"`
	Actor             string                 `json:"actor,omitempty"`
	Channel           string                 `json:"channel,omitempty"`
	ClusterName       string                 `json:"cluster,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	ObservedAt        *time.Time             `json:"observed_at,omitempty"`
}

// ResyncManifestRequest is the body for POST /authsec/discovery/resync-manifest —
// the complete set of agents a sweep observed, which is what makes disappearance
// detectable by diff.
type ResyncManifestRequest struct {
	WorkspaceID       string     `json:"workspace_id" binding:"required"`
	Source            string     `json:"source" binding:"required"`
	DiscoverySourceID *uuid.UUID `json:"discovery_source_id,omitempty"`
	ClusterName       string     `json:"cluster" binding:"required"`
	ScanKind          string     `json:"scan_kind,omitempty"`
	// Complete is false when any LIST in the sweep failed. A partial manifest is
	// accepted but retires nothing — see services.ReconcileManifest.
	Complete       bool       `json:"complete"`
	Namespaces     []string   `json:"namespaces"`
	Fingerprints   []string   `json:"fingerprints"`
	SweepStartedAt *time.Time `json:"sweep_started_at,omitempty"`
	ObservedAt     *time.Time `json:"observed_at,omitempty"`
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
	// MatchedClientID is OPTIONAL. Omit it and the platform mints a governed
	// identity from the sighting, named after the workload. Most discovered agents
	// are workloads that never authenticate to AuthSec, so requiring an operator to
	// pick a credential-holder for them was ceremony blocking the only judgement
	// that needs a human: who is accountable.
	//
	// Supply it to bind this sighting to an identity that already exists.
	MatchedClientID uuid.UUID `json:"matched_client_id,omitempty"`
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

// assertedWorkspace resolves the workspace an UNAUTHENTICATED connector claims in
// its request body, and confirms it exists.
//
// Used by the three ingress routes (sightings, agent-registration, lifecycle,
// resync-manifest) where there is no token to derive the workspace from — the
// caller asserts it and the agent is configured with it at deploy time.
//
// The existence check is not redundant with the foreign key. Without it a typo'd
// workspace id surfaces as a raw Postgres FK violation, which is a miserable thing
// to debug from inside a cluster — and a typo is now a likely mistake, because an
// operator types this into a Helm flag by hand. One indexed primary-key lookup is
// worth the clarity.
func (ctl *DiscoveryController) assertedWorkspace(c *gin.Context, raw string) (uuid.UUID, bool) {
	wsID, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("workspace_id %q is not a valid uuid", raw),
		})
		return uuid.Nil, false
	}

	var exists int64
	if err := ctl.db.Table("workspaces").Where("id = ?", wsID).Count(&exists).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify workspace"})
		return uuid.Nil, false
	}
	if exists == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("unknown workspace_id %s", wsID),
		})
		return uuid.Nil, false
	}
	return wsID, true
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
	var req SightingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// This route is unauthenticated, so the workspace comes from the body rather
	// than a token claim. See the ingress comment in routes.go for what that trades.
	wsID, ok := ctl.assertedWorkspace(c, req.WorkspaceID)
	if !ok {
		return
	}

	// No authenticated principal on this path. Record an explicitly-marked
	// attribution rather than something that reads like a verified identity, so a
	// row's provenance is never overstated when someone reads it later.
	principal := "unauthenticated:" + req.Source

	agent, created, err := ctl.manager().ReportSighting(wsID, principal, services.SightingInput{
		Source:            req.Source,
		DiscoverySourceID: req.DiscoverySourceID,
		Fingerprint:       req.Fingerprint,
		DisplayName:       req.DisplayName,
		Metadata:          req.Metadata,
		DeploymentOrigin:  req.DeploymentOrigin,
		Archetype:         req.Archetype,
		ObservedAt:        req.ObservedAt,
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

// RegisterAgent handles POST /authsec/discovery/agent-registration — a deployed
// connector announcing itself, then heartbeating on a timer.
//
// This is what makes a fleet legible. One control plane serves discovery agents in
// many clusters; before this, the only record of which cluster a sighting came
// from was a string buried in its metadata, so "which clusters are reporting?",
// "what version is each running?" and "has one gone quiet?" had no answer. The
// response returns the connector's id, which the agent then stamps on every
// sighting — turning cluster attribution into a foreign key instead of a jsonb dig.
//
// Returns 201 on first registration and 200 for a heartbeat. Neither is an error.
func (ctl *DiscoveryController) RegisterAgent(c *gin.Context) {
	var req AgentRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	wsID, ok := ctl.assertedWorkspace(c, req.WorkspaceID)
	if !ok {
		return
	}

	source, created, err := ctl.manager().RegisterAgent(wsID, services.AgentRegistrationInput{
		Kind:              req.Kind,
		InstanceID:        req.InstanceID,
		DisplayName:       req.DisplayName,
		ClusterName:       req.ClusterName,
		ClusterUID:        req.ClusterUID,
		AgentVersion:      req.AgentVersion,
		Status:            req.Status,
		Error:             req.Error,
		Runtime:           req.Runtime,
		ReportedSightings: req.ReportedSightings,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
		// Only first contact is a governance event worth auditing. A heartbeat every
		// 60 seconds from every cluster would drown the admin-mutation log.
		auditAdminMutation(c, wsID.String(), "register", "discovery_source",
			source.ID.String(), status, nil, source)
	}
	c.JSON(status, gin.H{
		// Named discovery_source_id, not id: this is the value the agent copies onto
		// every sighting and lifecycle event it sends.
		"discovery_source_id": source.ID,
		"source":              source,
		"created":             created,
	})
}

// ReportLifecycleEvent handles POST /authsec/discovery/lifecycle — a connector
// reporting that an agent's observed runtime state changed.
//
// The gap this closes: sightings only ever asserted "this exists". A workload that
// was deleted left a row indistinguishable from a running one, forever. This
// endpoint carries the other half — that it was deleted, when, and (from admission,
// where the API server authenticates the caller) by whom.
//
// It writes runtime_status, never status: what a human decided about an agent and
// what we observed about it are separate axes. An agent that was claimed and then
// deleted must stay registered — the audit trail is the point — while its runtime
// status becomes gone.
func (ctl *DiscoveryController) ReportLifecycleEvent(c *gin.Context) {
	var req LifecycleEventRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	wsID, ok := ctl.assertedWorkspace(c, req.WorkspaceID)
	if !ok {
		return
	}

	agent, event, err := ctl.manager().RecordLifecycleEvent(wsID, services.LifecycleEventInput{
		Source:            req.Source,
		DiscoverySourceID: req.DiscoverySourceID,
		Fingerprint:       req.Fingerprint,
		Event:             req.Event,
		Reason:            req.Reason,
		Actor:             req.Actor,
		Channel:           req.Channel,
		ClusterName:       req.ClusterName,
		Metadata:          req.Metadata,
		ObservedAt:        req.ObservedAt,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	// 202 when the event was kept but matched no inventory row. That happens for
	// real: an agent created and destroyed between two resyncs, or deleted while the
	// reporting queue was backed up. The event is the only evidence it ever existed,
	// so it is recorded rather than rejected — but the connector should be able to
	// tell that case from a fold into a known agent.
	status := http.StatusOK
	if agent == nil {
		status = http.StatusAccepted
	}
	c.JSON(status, gin.H{"agent": agent, "event": event, "matched": agent != nil})
}

// ReportResyncManifest handles POST /authsec/discovery/resync-manifest — the
// complete set of agents one sweep observed.
//
// This is the third lifecycle signal, and the only one that catches an agent
// destroyed while nobody was watching: admission sees deletions live but not the
// ones that happened before install or during an outage. A manifest states a fact
// ("at T, sweeping these namespaces, these were present, and my sweep was
// complete") and the control plane decides what absence means.
//
// A partial manifest (complete=false) is accepted and retires NOTHING. One
// transient RBAC error or API timeout during a sweep would otherwise retire a
// large part of a customer's inventory in a single request.
func (ctl *DiscoveryController) ReportResyncManifest(c *gin.Context) {
	var req ResyncManifestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	wsID, ok := ctl.assertedWorkspace(c, req.WorkspaceID)
	if !ok {
		return
	}

	result, err := ctl.manager().ReconcileManifest(wsID, services.ManifestInput{
		Source:            req.Source,
		DiscoverySourceID: req.DiscoverySourceID,
		ClusterName:       req.ClusterName,
		ScanKind:          req.ScanKind,
		Complete:          req.Complete,
		Namespaces:        req.Namespaces,
		Fingerprints:      req.Fingerprints,
		SweepStartedAt:    req.SweepStartedAt,
		ObservedAt:        req.ObservedAt,
	})
	if err != nil {
		discoveryError(c, err)
		return
	}

	if result.MarkedGone > 0 {
		// Retiring agents from the inventory IS a governance-visible change, unlike a
		// routine sighting, so it is audited even though the caller is a machine.
		auditAdminMutation(c, wsID.String(), "retire", "discovered_agent",
			req.ClusterName, http.StatusOK, nil, result)
	}
	c.JSON(http.StatusOK, result)
}

// ListAgentLifecycle handles GET /authsec/discovery/agents/:id/events — the
// history behind an agent's current runtime status.
//
// The inventory row says an agent is gone; this says when it was deleted, through
// which channel it was observed, and which principal the API server attributed it
// to. That is the difference between knowing an agent vanished and being able to
// answer for it.
func (ctl *DiscoveryController) ListAgentLifecycle(c *gin.Context) {
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

	limit, _ := strconv.Atoi(c.Query("limit"))
	events, err := ctl.manager().ListAgentEvents(wsID, id, limit)
	if err != nil {
		discoveryError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events)})
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

	// ?discovery_source_id= is in practice "agents in this cluster" — the question
	// self-registration exists to make answerable. A malformed value is ignored
	// rather than fatal: a filter is a narrowing, and silently returning everything
	// is less surprising in a console than a 400 on a stale bookmark.
	var sourceID *uuid.UUID
	if raw := c.Query("discovery_source_id"); raw != "" {
		if parsed, perr := uuid.Parse(raw); perr == nil {
			sourceID = &parsed
		}
	}

	agents, total, err := ctl.manager().ListAgents(wsID, repositories.AgentFilter{
		Status:           c.Query("status"),
		DeploymentOrigin: c.Query("deployment_origin"),
		Source:           c.Query("source"),
		Archetype:        c.Query("archetype"),
		UnownedOnly:      c.Query("unowned") == "true",
		RuntimeStatus:    c.Query("runtime_status"),
		// ?live=true is the actionable queue: drop agents we have observed to be
		// destroyed, which need no claim decision.
		LiveOnly:          c.Query("live") == "true",
		DiscoverySourceID: sourceID,
		Limit:             limit,
		Offset:            offset,
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

// UnquarantineAgent handles POST /authsec/discovery/agents/:id/unquarantine — the
// release half of the quarantine loop.
//
// Same permission as quarantine (discovery:quarantine), deliberately: whoever can cut
// an agent off can restore it. Splitting them would mean an operator able to contain
// an incident but not to undo a mistake, which is how a mis-click becomes an outage
// nobody present can fix.
//
// No body. A quarantine needs a reason because it is an accusation that must be
// answerable; a release does not, because it restores the status quo. The actor and
// timestamp are recorded either way.
func (ctl *DiscoveryController) UnquarantineAgent(c *gin.Context) {
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

	out, err := ctl.manager().ReleaseQuarantine(wsID, id, ctl.actingUser(c))
	if err != nil {
		discoveryError(c, err)
		return
	}

	auditAdminMutation(c, wsID.String(), "unquarantine", "discovered_agent", id.String(),
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
