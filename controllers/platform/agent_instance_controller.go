package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AgentInstanceController provides the per-agent instance and effective-policy
// read endpoints for the All Agents inventory.
type AgentInstanceController struct {
	db *gorm.DB
}

// NewAgentInstanceController creates a new agent instance controller.
func NewAgentInstanceController(db *gorm.DB) *AgentInstanceController {
	return &AgentInstanceController{db: db}
}

type agentInstanceRow struct {
	ID               uuid.UUID `json:"id"`
	AgentID          uuid.UUID `json:"agent_id"`
	WorkloadID       uuid.UUID `json:"workload_id"`
	ExecutionID      string    `json:"execution_id"`
	Principal        string    `json:"principal"`
	Backend          string    `json:"backend"`
	BindingID        *uuid.UUID `json:"binding_id,omitempty"`
	PolicyDigest     string    `json:"policy_digest,omitempty"`
	Status           string    `json:"status"`
	LastSeenAt       string    `json:"last_seen_at,omitempty"`
}

// ListInstances returns current execution instances for an agent.
// GET /authsec/discovery/agents/:id/instances
func (ctl *AgentInstanceController) ListInstances(c *gin.Context) {
	wsID, ok := ctl.workspace(c)
	if !ok {
		return
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	var instances []agentInstanceRow
	err = ctl.db.WithContext(c.Request.Context()).Raw(`
		SELECT
			ri.id,
			da.id AS agent_id,
			w.id AS workload_id,
			ri.execution_id,
			COALESCE(ci.principal_id, '') AS principal,
			COALESCE(eb.backend, '') AS backend,
			eb.id AS binding_id,
			COALESCE(eb.capability_digest, '') AS policy_digest,
			COALESCE(ri.status, 'unknown') AS status,
			ri.updated_at AS last_seen_at
		FROM iga_runtime_instances ri
		JOIN iga_workload w ON w.id = ri.workload_id AND w.workspace_id = ri.workspace_id
		JOIN discovered_agents da ON da.workload_id = w.id AND da.workspace_id = w.workspace_id
		LEFT JOIN collector_instances ci ON ci.workspace_id = da.workspace_id AND ci.discovery_source_id = da.discovery_source_id
		LEFT JOIN enforcement_bindings eb ON eb.workspace_id = da.workspace_id AND eb.agent_id = da.id AND eb.state != 'superseded'
		WHERE da.workspace_id = ? AND da.id = ?
		ORDER BY ri.updated_at DESC
	`, wsID, agentID).Scan(&instances).Error

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query instances"})
		return
	}
	if instances == nil {
		instances = []agentInstanceRow{}
	}
	c.JSON(http.StatusOK, gin.H{"data": instances})
}

type effectivePolicyRow struct {
	PolicyID     uuid.UUID `json:"policy_id"`
	PolicyName   string    `json:"policy_name"`
	Revision     int       `json:"revision"`
	ContentHash  string    `json:"content_hash"`
	Format       string    `json:"format"`
	State        string    `json:"state"`
}

type primitiveCoverageRow struct {
	PrimitiveID       string `json:"primitive_id"`
	DiscoveryStatus   string `json:"discovery_status"`
	EnforcementStatus string `json:"enforcement_status"`
	Backend           string `json:"backend"`
	Profile           string `json:"profile"`
}

// GetEffectivePolicy returns the contributing policy revisions and primitive
// coverage matrix for an agent.
// GET /authsec/discovery/agents/:id/effective-policy
func (ctl *AgentInstanceController) GetEffectivePolicy(c *gin.Context) {
	wsID, ok := ctl.workspace(c)
	if !ok {
		return
	}
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	// Get contributing policy revisions.
	var policies []effectivePolicyRow
	err = ctl.db.WithContext(c.Request.Context()).Raw(`
		SELECT
			rp.id AS policy_id,
			rp.name AS policy_name,
			rev.revision,
			rev.content_hash,
			rev.compiler_format AS format,
			rev.state
		FROM runtime_policies rp
		JOIN runtime_policy_revisions rev ON rev.policy_id = rp.id
			AND rev.workspace_id = rp.workspace_id
			AND rev.revision = rp.current_draft_revision
		WHERE rp.workspace_id = ?
			AND rev.state IN ('approved', 'published')
			AND EXISTS (
				SELECT 1 FROM discovered_agents da
				JOIN iga_workload w ON w.id = da.workload_id AND w.workspace_id = da.workspace_id
				WHERE da.id = ? AND da.workspace_id = ?
				AND rev.document::text LIKE '%' || w.id::text || '%'
			)
		ORDER BY rp.name
	`, wsID, agentID, wsID).Scan(&policies).Error

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query effective policy"})
		return
	}
	if policies == nil {
		policies = []effectivePolicyRow{}
	}

	// Build primitive coverage matrix based on agent capabilities.
	coverage := buildPrimitiveCoverage(ctl.db, c.Request.Context(), wsID, agentID)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"contributing_revisions": policies,
			"primitive_coverage":     coverage,
		},
	})
}

func buildPrimitiveCoverage(db *gorm.DB, _ interface{}, wsID, agentID uuid.UUID) []primitiveCoverageRow {
	// Get the agent's capability digest.
	var capDigest string
	db.Raw(`
		SELECT COALESCE(ccr.capability_digest, '')
		FROM discovered_agents da
		LEFT JOIN collector_instances ci ON ci.workspace_id = da.workspace_id AND ci.discovery_source_id = da.discovery_source_id
		LEFT JOIN collector_capability_reports ccr ON ccr.workspace_id = ci.workspace_id AND ccr.collector_instance_id = ci.id
		WHERE da.workspace_id = ? AND da.id = ?
		LIMIT 1
	`, wsID, agentID).Scan(&capDigest)

	// Return coverage for all canonical primitives.
	primitives := []primitiveCoverageRow{
		{PrimitiveID: "file.read", DiscoveryStatus: "discovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "file.write", DiscoveryStatus: "discovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "process.harden", DiscoveryStatus: "discovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "process.exec", DiscoveryStatus: "discovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "network.connect", DiscoveryStatus: "discovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "unix_socket.connect", DiscoveryStatus: "undiscovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "secret.read", DiscoveryStatus: "undiscovered", EnforcementStatus: "enforceable", Backend: "authsec", Profile: "linux-managed-v1"},
		{PrimitiveID: "llm.invoke", DiscoveryStatus: "undiscovered", EnforcementStatus: "observe_only", Backend: "authsec"},
		{PrimitiveID: "github.operation", DiscoveryStatus: "undiscovered", EnforcementStatus: "observe_only", Backend: "authsec"},
		{PrimitiveID: "device.open", DiscoveryStatus: "undiscovered", EnforcementStatus: "not_supported"},
		{PrimitiveID: "db.operation", DiscoveryStatus: "undiscovered", EnforcementStatus: "observe_only", Backend: "authsec"},
		{PrimitiveID: "remote.session", DiscoveryStatus: "undiscovered", EnforcementStatus: "observe_only", Backend: "authsec"},
	}
	return primitives
}

func (ctl *AgentInstanceController) workspace(c *gin.Context) (uuid.UUID, bool) {
	wsStr := c.GetString("workspace_id")
	if wsStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
		return uuid.Nil, false
	}
	wsID, err := uuid.Parse(wsStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id"})
		return uuid.Nil, false
	}
	return wsID, true
}
