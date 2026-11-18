package platform

// AuthSec Agent Kit (authsec-cli) control plane routes.
//
// Machine routes (no user token; on the discovery ingress group):
//
//	POST /authsec/discovery/agentkit/machine/events    a batch of daemon records
//	GET  /authsec/discovery/agentkit/machine/policies  the policies to enforce
//
// A machine is a vm_sensor discovery source. These routes ALWAYS require a
// credential, whatever IGA_DISCOVERY_INGEST_AUTH says: the machine's
// actuation token (once it has handed one over), or else a live ingest token
// of the workspace. Policies say what a machine lets its agents do, so they
// are never given to an unauthenticated caller, and the logs are evidence,
// so nobody unauthenticated writes them.
//
// Console routes (AuthMiddleware; the workspace is the token's):
//
//	GET  /authsec/discovery/agentkit/events                     discovery:read
//	GET  /authsec/discovery/agentkit/access                     discovery:read
//	GET  /authsec/discovery/agentkit/policies                   discovery:read
//	GET  /authsec/discovery/agentkit/policies/:agent/versions   discovery:read
//	PUT  /authsec/discovery/agentkit/policies/:agent            discovery:admin
//	POST /authsec/discovery/agentkit/policies/:agent/block      discovery:admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MountAgentKitMachineRoutes registers the machine routes on the
// unauthenticated discovery ingress group.
func MountAgentKitMachineRoutes(g gin.IRouter, ctl *DiscoveryController) {
	g.POST("/agentkit/machine/events", ctl.AgentKitReportEvents)
	g.GET("/agentkit/machine/policies", ctl.AgentKitMachinePolicies)
}

// MountAgentKitConsoleRoutes registers the console routes on an
// AUTHENTICATED discovery group.
func MountAgentKitConsoleRoutes(g gin.IRouter, ctl *DiscoveryController, require func(resource, action string) gin.HandlerFunc) {
	g.GET("/agentkit/events", require("discovery", "read"), ctl.AgentKitListEvents)
	g.GET("/agentkit/access", require("discovery", "read"), ctl.AgentKitListAccess)
	g.GET("/agentkit/policies", require("discovery", "read"), ctl.AgentKitListPolicies)
	g.GET("/agentkit/policies/:agent/versions", require("discovery", "read"), ctl.AgentKitPolicyVersions)
	g.PUT("/agentkit/policies/:agent", require("discovery", "admin"), ctl.AgentKitPutPolicy)
	g.POST("/agentkit/policies/:agent/block", require("discovery", "admin"), ctl.AgentKitBlock)
}

func (ctl *DiscoveryController) agentKit() *services.AgentKit { return services.NewAgentKit(ctl.db) }

/* ------------------------------ machine auth ------------------------------ */

// agentKitMachine authenticates a machine call and returns its workspace and
// source. rawWS and rawSource are what the machine asserts; a source is
// required. On false the response has been written.
func (ctl *DiscoveryController) agentKitMachine(c *gin.Context, rawWS, rawSource string) (uuid.UUID, uuid.UUID, bool) {
	presented := bearerToken(c)
	if presented == "" {
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "a machine credential is required"})
		return uuid.Nil, uuid.Nil, false
	}
	notFound := func() (uuid.UUID, uuid.UUID, bool) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return uuid.Nil, uuid.Nil, false
	}

	// 1. The machine's own actuation credential decides workspace and source.
	if src, err := services.NewActuationManager(ctl.db).AuthenticateAgent(presented); err == nil {
		if rawWS != "" && rawWS != src.WorkspaceID.String() {
			return notFound()
		}
		if rawSource != "" && rawSource != src.ID.String() {
			return notFound()
		}
		if src.Kind != models.DiscoverySourceVMSensor {
			return notFound()
		}
		return src.WorkspaceID, src.ID, true
	}
	if strings.HasPrefix(presented, connectorCredentialPrefix) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid connector credential"})
		return uuid.Nil, uuid.Nil, false
	}

	// 2. An ingest token, checked as in enforce mode.
	wsID, err := uuid.Parse(rawWS)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id must be a uuid"})
		return uuid.Nil, uuid.Nil, false
	}
	srcID, err := uuid.Parse(rawSource)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "discovery_source_id must be a uuid"})
		return uuid.Nil, uuid.Nil, false
	}
	d, err := ctl.ingestTokens().Authorize(services.IngestAuthEnforce, presented, wsID,
		func() (*uuid.UUID, error) { return &srcID, nil })
	if err != nil {
		countIngest("error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify the credential"})
		return uuid.Nil, uuid.Nil, false
	}
	switch d.Outcome {
	case services.IngestAccept:
	case services.IngestRejectForeignWorkspace:
		countIngest("rejected_other_workspace")
		monitoring.RecordAuthRequest("discovery_ingest", "rejected_other_workspace", d.Token.WorkspaceID.String())
		c.JSON(http.StatusForbidden, gin.H{"error": "ingest token is not valid for this workspace"})
		return uuid.Nil, uuid.Nil, false
	default:
		key := "rejected_unauthenticated_" + d.Reason
		countIngest(key)
		monitoring.RecordAuthRequest("discovery_ingest", key, "-")
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ingest token required"})
		return uuid.Nil, uuid.Nil, false
	}
	// A machine that handed over its actuation credential speaks only with it.
	locked, err := ctl.credentialedConnector(wsID, &srcID, connectorLookup{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify connector"})
		return uuid.Nil, uuid.Nil, false
	}
	if locked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "this machine has a credential: send it as the bearer token"})
		return uuid.Nil, uuid.Nil, false
	}
	if _, err := ctl.agentKit().MachineSource(c.Request.Context(), wsID, srcID); err != nil {
		if errors.Is(err, services.ErrAgentKitSourceNotFound) {
			return notFound()
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify the machine"})
		return uuid.Nil, uuid.Nil, false
	}
	countIngest("accepted_token")
	monitoring.RecordAuthRequest("discovery_ingest", "accepted_token", wsID.String())
	return wsID, srcID, true
}

/* ----------------------------- machine routes ----------------------------- */

// AgentKitEventsRequest is the body of POST .../agentkit/machine/events.
type AgentKitEventsRequest struct {
	WorkspaceID       string            `json:"workspace_id"`
	DiscoverySourceID string            `json:"discovery_source_id"`
	Events            []json.RawMessage `json:"events"`
}

// agentKitMaxBody bounds a batch: 500 records of at most 16 KiB.
const agentKitMaxBody = services.AgentKitMaxEventsPerBatch*services.AgentKitMaxRecordBytes + 4096

// AgentKitReportEvents stores a batch of a machine's records.
func (ctl *DiscoveryController) AgentKitReportEvents(c *gin.Context) {
	if bearerToken(c) == "" {
		// Refused before the body is read.
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "a machine credential is required"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, agentKitMaxBody)
	var req AgentKitEventsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	ws, src, ok := ctl.agentKitMachine(c, req.WorkspaceID, req.DiscoverySourceID)
	if !ok {
		return
	}
	if len(req.Events) > services.AgentKitMaxEventsPerBatch {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "at most 500 events per batch"})
		return
	}
	res, err := ctl.agentKit().IngestEvents(c.Request.Context(), ws, src, req.Events)
	if errors.Is(err, services.ErrAgentKitSourceNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store events"})
		return
	}
	c.JSON(http.StatusOK, res)
}

// AgentKitMachinePolicies returns the newest version of every policy of the
// machine's workspace. ?workspace_id= and ?discovery_source_id= name the
// machine for an ingest token. The response carries an etag (a digest of
// every id and version) so a machine reloads only on change.
func (ctl *DiscoveryController) AgentKitMachinePolicies(c *gin.Context) {
	ws, _, ok := ctl.agentKitMachine(c, c.Query("workspace_id"), c.Query("discovery_source_id"))
	if !ok {
		return
	}
	pols, err := ctl.agentKit().LatestPolicies(c.Request.Context(), ws)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read policies"})
		return
	}
	type machinePolicy struct {
		AgentID  string `json:"agent_id"`
		Version  int    `json:"version"`
		SHA256   string `json:"sha256"`
		Document string `json:"document"`
	}
	out := make([]machinePolicy, 0, len(pols))
	var tag strings.Builder
	for _, p := range pols {
		out = append(out, machinePolicy{AgentID: p.AgentID, Version: p.Version, SHA256: p.SHA256, Document: p.Document})
		tag.WriteString(p.AgentID + ":" + strconv.Itoa(p.Version) + ":" + p.SHA256 + ";")
	}
	etag := `"` + shortDigest(tag.String()) + `"`
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	if c.GetHeader("If-None-Match") == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": out, "etag": etag})
}

/* ----------------------------- console routes ----------------------------- */

func parseTimeQuery(c *gin.Context, name string) (*time.Time, bool) {
	raw := c.Query(name)
	if raw == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": name + " must be RFC 3339"})
		return nil, false
	}
	return &t, true
}

func parseUUIDQuery(c *gin.Context, name string) (*uuid.UUID, bool) {
	raw := c.Query(name)
	if raw == "" {
		return nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": name + " must be a uuid"})
		return nil, false
	}
	return &id, true
}

// AgentKitListEvents lists the workspace's machine events, newest first.
// Filters: discovery_source_id, type (comma list), agent_id, severity,
// action, tag, enforced=true, since, until (RFC 3339); paging: limit,
// before (the next_cursor of the previous page).
func (ctl *DiscoveryController) AgentKitListEvents(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	f := services.AgentKitEventFilter{
		AgentID:      c.Query("agent_id"),
		Severity:     c.Query("severity"),
		Action:       c.Query("action"),
		Tag:          c.Query("tag"),
		EnforcedOnly: c.Query("enforced") == "true",
	}
	var ok bool
	if f.SourceID, ok = parseUUIDQuery(c, "discovery_source_id"); !ok {
		return
	}
	if f.Before, ok = parseUUIDQuery(c, "before"); !ok {
		return
	}
	if f.Since, ok = parseTimeQuery(c, "since"); !ok {
		return
	}
	if f.Until, ok = parseTimeQuery(c, "until"); !ok {
		return
	}
	if raw := c.Query("type"); raw != "" {
		f.Types = strings.Split(raw, ",")
	}
	if raw := c.Query("limit"); raw != "" {
		if f.Limit, err = strconv.Atoi(raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be a number"})
			return
		}
	}
	rows, next, err := ctl.agentKit().ListEvents(c.Request.Context(), ws, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list events"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": rows, "next_cursor": next})
}

// AgentKitListAccess returns each machine agent's latest access summary.
func (ctl *DiscoveryController) AgentKitListAccess(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	src, ok := parseUUIDQuery(c, "discovery_source_id")
	if !ok {
		return
	}
	rows, err := ctl.agentKit().LatestAccess(c.Request.Context(), ws, src, c.Query("agent_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read access"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access": rows})
}

// AgentKitListPolicies returns the newest version of every policy.
func (ctl *DiscoveryController) AgentKitListPolicies(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	rows, err := ctl.agentKit().LatestPolicies(c.Request.Context(), ws)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read policies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": rows})
}

func agentParam(c *gin.Context) (string, bool) {
	id := c.Param("agent")
	if !services.ValidAgentKitAgentID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent must be * or a recogniser id such as claude-code"})
		return "", false
	}
	return id, true
}

// AgentKitPolicyVersions lists one agent's policy versions, newest first.
func (ctl *DiscoveryController) AgentKitPolicyVersions(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	agent, ok := agentParam(c)
	if !ok {
		return
	}
	rows, err := ctl.agentKit().PolicyVersions(c.Request.Context(), ws, agent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read policy versions"})
		return
	}
	if len(rows) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"versions": rows})
}

// AgentKitPutPolicyRequest is the body of PUT .../agentkit/policies/:agent.
type AgentKitPutPolicyRequest struct {
	Document string `json:"document" binding:"required"`
	Comment  string `json:"comment"`
	// BaseVersion is the version the editor started from (0: none). When
	// set and no longer the latest, the answer is 409.
	BaseVersion *int `json:"base_version"`
}

func agentKitPolicyError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrAgentKitPolicyInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrAgentKitPolicyConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save the policy"})
	}
}

// AgentKitPutPolicy stores a new version of an agent's policy.
func (ctl *DiscoveryController) AgentKitPutPolicy(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	agent, ok := agentParam(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, services.AgentKitMaxPolicyBytes+8192)
	var req AgentKitPutPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "document is required"})
		return
	}
	row, created, err := ctl.agentKit().PutPolicy(c.Request.Context(), ws, agent, req.Document, req.Comment,
		req.BaseVersion, ctl.actingUser(c))
	if err != nil {
		agentKitPolicyError(c, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		auditAdminMutation(c, ws.String(), "update", "agentkit_policy", row.ID.String(), status, nil,
			gin.H{"agent_id": row.AgentID, "version": row.Version, "sha256": row.SHA256, "comment": row.Comment})
	}
	c.JSON(status, gin.H{"policy": row, "created": created})
}

// AgentKitBlock denies one resource (host, cidr, path, command, mcp) to an
// agent as a new policy version: the console's right-click "block".
func (ctl *DiscoveryController) AgentKitBlock(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	agent, ok := agentParam(c)
	if !ok {
		return
	}
	var req services.AgentKitBlock
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type and value are required"})
		return
	}
	res, err := ctl.agentKit().BlockResource(c.Request.Context(), ws, agent, req, ctl.actingUser(c))
	if err != nil {
		agentKitPolicyError(c, err)
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
		auditAdminMutation(c, ws.String(), "block", "agentkit_policy", res.Policy.ID.String(), status, nil,
			gin.H{"agent_id": res.Policy.AgentID, "version": res.Policy.Version, "block": req})
	}
	c.JSON(status, res)
}

// shortDigest is a 128-bit hex digest, for an etag.
func shortDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
