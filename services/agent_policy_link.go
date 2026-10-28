package services

import (
	"log"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// A runtime policy names workloads in the current revision document
// (targets.workload_ids). A workload adopted from a sighting keeps
// source_key discovered-agent:<discovered_agents.id>. That pair is the
// link. discovered_agent_workloads and workload_policy_bindings are not
// consulted: those tables can be empty while this join still holds.
const policyAgentLinkSQL = `
SELECT p.id AS policy_id,
       p.name AS policy_name,
       p.lifecycle AS policy_lifecycle,
       a.id AS agent_id,
       a.display_name AS agent_name,
       a.source AS agent_source
FROM runtime_policies p
JOIN runtime_policy_revisions r
  ON r.workspace_id = p.workspace_id
 AND r.policy_id = p.id
 AND r.revision = p.current_draft_revision
JOIN iga_workload w
  ON w.workspace_id = p.workspace_id
 AND w.lifecycle <> 'retired'
 AND r.document->'targets'->'workload_ids' @> jsonb_build_array(w.id::text)
JOIN discovered_agents a
  ON a.workspace_id = w.workspace_id
 AND w.source_key = 'discovered-agent:' || a.id::text
WHERE p.workspace_id = ?`

type policyAgentRow struct {
	PolicyID        uuid.UUID
	PolicyName      string
	PolicyLifecycle string
	AgentID         uuid.UUID
	AgentName       string
	AgentSource     string
}

// policyAgentLink is one discovered agent a policy's current revision targets.
type policyAgentLink struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Source      string    `json:"source"`
}

func loadPolicyAgentRows(db *gorm.DB, ws uuid.UUID, extra string, arg any) []policyAgentRow {
	if db == nil {
		return nil
	}
	var rows []policyAgentRow
	if err := db.Raw(policyAgentLinkSQL+extra, ws, arg).Scan(&rows).Error; err != nil {
		// A missing policy table must not hide the inventory or the policy list.
		log.Printf("[runtime-policy] agent link: %v", err)
		return nil
	}
	return rows
}

func attachPolicyAgents(db *gorm.DB, ws uuid.UUID, heads []policyHead) {
	if len(heads) == 0 {
		return
	}
	ids := make([]uuid.UUID, len(heads))
	for i := range heads {
		ids[i] = heads[i].ID
	}
	rows := loadPolicyAgentRows(db, ws, " AND p.id IN ?", ids)
	by := map[uuid.UUID][]policyAgentLink{}
	seen := map[string]struct{}{}
	for _, row := range rows {
		key := row.PolicyID.String() + "|" + row.AgentID.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		by[row.PolicyID] = append(by[row.PolicyID], policyAgentLink{
			ID:          row.AgentID,
			DisplayName: row.AgentName,
			Source:      row.AgentSource,
		})
	}
	for i := range heads {
		if links := by[heads[i].ID]; len(links) > 0 {
			heads[i].Agents = links
		}
	}
}

func attachAgentPolicies(db *gorm.DB, ws uuid.UUID, agents []models.DiscoveredAgent) {
	if len(agents) == 0 {
		return
	}
	ids := make([]uuid.UUID, len(agents))
	for i := range agents {
		ids[i] = agents[i].ID
	}
	rows := loadPolicyAgentRows(db, ws, " AND a.id IN ?", ids)
	by := map[uuid.UUID][]models.DiscoveredAgentPolicy{}
	seen := map[string]struct{}{}
	for _, row := range rows {
		key := row.AgentID.String() + "|" + row.PolicyID.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		by[row.AgentID] = append(by[row.AgentID], models.DiscoveredAgentPolicy{
			ID:        row.PolicyID,
			Name:      row.PolicyName,
			Lifecycle: row.PolicyLifecycle,
		})
	}
	for i := range agents {
		if links := by[agents[i].ID]; len(links) > 0 {
			agents[i].Policies = links
		}
	}
}

// attachAgentWorkloads fills WorkloadID from the adopted iga_workload.
// The join is source_key = discovered-agent:<discovered_agents.id>. A
// sighting with no adopted workload stays empty, and the identity graph
// tab must not invent a root from that.
func attachAgentWorkloads(db *gorm.DB, ws uuid.UUID, agents []models.DiscoveredAgent) {
	if db == nil || len(agents) == 0 {
		return
	}
	ids := make([]uuid.UUID, len(agents))
	for i := range agents {
		ids[i] = agents[i].ID
	}
	var rows []struct {
		AgentID    uuid.UUID
		WorkloadID uuid.UUID
	}
	if err := db.Raw(`
SELECT a.id AS agent_id, w.id AS workload_id
FROM discovered_agents a
JOIN iga_workload w
  ON w.workspace_id = a.workspace_id
 AND w.lifecycle <> 'retired'
 AND w.source_key = 'discovered-agent:' || a.id::text
WHERE a.workspace_id = ? AND a.id IN ?`, ws, ids).Scan(&rows).Error; err != nil {
		log.Printf("[discovery] workload link: %v", err)
		return
	}
	by := map[uuid.UUID]uuid.UUID{}
	for _, row := range rows {
		if _, ok := by[row.AgentID]; !ok {
			by[row.AgentID] = row.WorkloadID
		}
	}
	for i := range agents {
		if id, ok := by[agents[i].ID]; ok {
			wid := id
			agents[i].WorkloadID = &wid
		}
	}
}
