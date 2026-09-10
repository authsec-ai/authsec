package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/*
Package-level note — the enforcement plan (ENFORCEMENT-ARCHITECTURE.md §4).

The plan is the WHOLE interface between governance and a customer's cluster. The
agent makes no governance decision, evaluates no policy, and never learns why a
fingerprint is on the list beyond the reason string it is handed.

Three properties are load-bearing, and each one is a decision rather than an
implementation detail:

  - WHOLE PLAN, NEVER A DELTA. A missed delta silently un-enforces and nothing
    notices; a whole plan is self-correcting on the next poll. The list is bounded
    by the number of quarantined agents in one cluster, which is small by
    construction — this is not a scaling problem waiting to happen.

  - VERSION CHANGES ON CONTENT, NOT ON TRAFFIC. The agent re-reads and re-indexes
    on a version change and the console reads a version gap as drift, so a version
    that ticked because somebody polled would make both meaningless.

  - PER-CONNECTOR. A plan is scoped to one cluster, so a leaked actuation token
    reads that cluster's decisions and no other's.
*/

// EnforcementPlanManager publishes and serves the plan one cluster enforces.
type EnforcementPlanManager interface {
	// Publish computes the current plan for a connector and stores it if the
	// contents differ from the last published version. Returns the plan in force
	// and whether this call minted a new version.
	Publish(workspaceID, sourceID uuid.UUID) (*models.EnforcementPlan, bool, error)

	// Latest returns the most recently published plan, or nil when none exists.
	Latest(sourceID uuid.UUID) (*models.EnforcementPlan, error)

	// History returns published versions newest-first, for the console.
	History(workspaceID, sourceID uuid.UUID, limit int) ([]models.EnforcementPlan, error)

	// RecordReport folds what an agent says about itself into its connector row.
	// Called on the agent's plan fetch; see models.EnforcementReport for why the
	// report rides on the fetch rather than a call of its own.
	RecordReport(sourceID uuid.UUID, rep models.EnforcementReport) error
}

type enforcementPlanManager struct {
	db       *gorm.DB
	policies AgentPolicyManager
}

// NewEnforcementPlanManager builds the manager.
func NewEnforcementPlanManager(db *gorm.DB) EnforcementPlanManager {
	return &enforcementPlanManager{db: db, policies: NewAgentPolicyManager(db)}
}

/* -------------------------------- publish -------------------------------- */

func (m *enforcementPlanManager) Publish(workspaceID,
	sourceID uuid.UUID) (*models.EnforcementPlan, bool, error) {

	var src models.DiscoverySource
	if err := m.db.First(&src, "id = ? AND workspace_id = ?",
		sourceID, workspaceID).Error; err != nil {
		return nil, false, fmt.Errorf("unknown connector for this workspace: %w", err)
	}

	doc, err := m.build(workspaceID, &src)
	if err != nil {
		return nil, false, err
	}
	hash := doc.Hash()

	latest, err := m.Latest(sourceID)
	if err != nil {
		return nil, false, err
	}
	if latest != nil && latest.ContentHash == hash {
		// Unchanged. Serve what is already published rather than re-stamping
		// generated_at: the agent uses the version to decide whether to re-index,
		// and a plan whose timestamp moves but whose contents do not would make
		// every poll look like a change.
		return latest, false, nil
	}

	next := int64(1)
	if latest != nil {
		next = latest.Version + 1
	}
	doc.Version = next
	doc.GeneratedAt = time.Now().UTC()

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, false, fmt.Errorf("marshal enforcement plan: %w", err)
	}

	row := &models.EnforcementPlan{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		DiscoverySourceID: sourceID,
		Version:           next,
		Plan:              raw,
		ContentHash:       hash,
		GeneratedAt:       doc.GeneratedAt,
	}

	// Two agent replicas polling in the same instant both compute version N+1.
	// The unique index decides; the loser takes the winner's plan rather than
	// retrying, because both computed the same contents from the same state and a
	// retry would only mint an identical version under a higher number.
	err = m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "discovery_source_id"}, {Name: "version"}},
		DoNothing: true,
	}).Create(row).Error
	if err != nil {
		return nil, false, err
	}
	stored, err := m.Latest(sourceID)
	if err != nil {
		return nil, false, err
	}
	if stored == nil {
		return nil, false, errors.New("published a plan but could not read it back")
	}
	return stored, stored.ID == row.ID, nil
}

func (m *enforcementPlanManager) Latest(sourceID uuid.UUID) (*models.EnforcementPlan, error) {
	var row models.EnforcementPlan
	err := m.db.Where("discovery_source_id = ?", sourceID).
		Order("version DESC").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (m *enforcementPlanManager) History(workspaceID, sourceID uuid.UUID,
	limit int) ([]models.EnforcementPlan, error) {

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var rows []models.EnforcementPlan
	err := m.db.Where("workspace_id = ? AND discovery_source_id = ?", workspaceID, sourceID).
		Order("version DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

/* --------------------------------- build --------------------------------- */

// build assembles the document from the DECISIONS of record.
//
// The source of truth is discovered_agents.status, not the policy table. A policy
// asking for quarantine only reaches the cluster once the reconciler has moved the
// agent's status — so there is exactly one answer to "is this agent contained",
// and a dry-run reconcile can never contain anything.
func (m *enforcementPlanManager) build(workspaceID uuid.UUID,
	src *models.DiscoverySource) (*models.EnforcementPlanDoc, error) {

	var agents []models.DiscoveredAgent
	err := m.db.Where(`workspace_id = ? AND discovery_source_id = ?
             AND status = ? AND quarantine_released_at IS NULL`,
		workspaceID, src.ID, models.DiscoveredAgentQuarantined).
		Order("fingerprint ASC").Find(&agents).Error
	if err != nil {
		return nil, err
	}

	// Policy attribution costs a query per quarantining policy, so it is only
	// computed when there is something to attribute. With nothing contained -- the
	// overwhelmingly common case, polled every 30 seconds by every cluster -- the
	// build is one indexed SELECT that returns no rows.
	var byAgent map[uuid.UUID]uuid.UUID
	if len(agents) > 0 {
		byAgent, err = m.quarantiningPolicies(workspaceID)
		if err != nil {
			return nil, err
		}
	}

	doc := &models.EnforcementPlanDoc{
		Cluster: src.ClusterName,
		// Never nil: a nil slice marshals to `null`, and an agent that decodes
		// null into its cache has to special-case it to avoid reading it as "no
		// plan" rather than "an empty plan". An empty plan is a real answer.
		Deny: []models.EnforcementPlanEntry{},
	}

	for i := range agents {
		a := &agents[i]
		ns, kind, name, container := k8sCoordinates(a.Metadata)

		since := a.UpdatedAt
		if a.QuarantinedAt != nil {
			since = *a.QuarantinedAt
		}

		reason := strings.TrimSpace(a.QuarantineReason)
		if reason == "" {
			reason = "quarantined by IGA governance"
		} else {
			reason = "quarantined: " + reason
		}

		e := models.EnforcementPlanEntry{
			Fingerprint:  a.Fingerprint,
			Namespace:    ns,
			WorkloadKind: kind,
			WorkloadName: name,
			Container:    container,
			DecisionID:   a.ID.String(),
			Reason:       reason,
			Since:        since.UTC(),
		}
		if pid, ok := byAgent[a.ID]; ok {
			e.PolicyID = pid.String()
		}
		doc.Deny = append(doc.Deny, e)
	}
	return doc, nil
}

// quarantiningPolicies maps each agent to a policy that asks for its containment.
//
// Only policies whose desired_state is 'quarantined' are expanded, so an agent
// quarantined by hand is not retroactively attributed to a policy that merely
// happens to cap its scope. An agent covered by more than one keeps the first by
// creation order, which is stable across calls — the field is an explanation, not
// the authority, and the authority is the agent's status.
func (m *enforcementPlanManager) quarantiningPolicies(
	workspaceID uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {

	policies, err := m.policies.List(workspaceID, true)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID]uuid.UUID{}
	for i := range policies {
		p := &policies[i]
		if p.DesiredState != models.AgentPolicyStateQuarantined {
			continue
		}
		agents, err := m.policies.Expand(workspaceID, p)
		if err != nil {
			// A broken selector must not blank the plan. Skipping it costs an
			// explanation on some entries; failing the build would stop serving
			// every containment in the cluster, which is the far worse outcome.
			continue
		}
		for j := range agents {
			if _, seen := out[agents[j].ID]; !seen {
				out[agents[j].ID] = p.ID
			}
		}
	}
	return out, nil
}

// k8sCoordinates pulls the workload coordinates out of a sighting's metadata.
//
// Best-effort by design: these are for a human reading the plan, and the agent
// matches on the fingerprint alone. A row whose metadata predates a schema change
// still produces a usable, enforceable entry.
func k8sCoordinates(raw json.RawMessage) (namespace, kind, name, container string) {
	if len(raw) == 0 {
		return
	}
	var md struct {
		Kubernetes struct {
			Namespace     string `json:"namespace"`
			WorkloadKind  string `json:"workload_kind"`
			WorkloadName  string `json:"workload_name"`
			ContainerName string `json:"container_name"`
		} `json:"kubernetes"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		return
	}
	return md.Kubernetes.Namespace, md.Kubernetes.WorkloadKind,
		md.Kubernetes.WorkloadName, md.Kubernetes.ContainerName
}

// clusterOf reads the cluster name a sighting reported.
//
// Lives beside k8sCoordinates because both answer "where is this agent" from the
// same blob, and a warning that names a workload without naming its cluster is
// ambiguous for anyone running more than one.
func clusterOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var md struct {
		Cluster struct {
			Name string `json:"name"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(raw, &md); err != nil {
		return ""
	}
	return md.Cluster.Name
}

/* ------------------------------ agent report ----------------------------- */

func (m *enforcementPlanManager) RecordReport(sourceID uuid.UUID,
	rep models.EnforcementReport) error {

	mode := strings.TrimSpace(rep.Mode)
	if mode == "" {
		// Nothing asserted, nothing to record. Not an error: an agent on an older
		// build fetches the plan without reporting, and refusing it would take
		// enforcement away from exactly the clusters that need upgrading.
		return nil
	}
	if !containsString(models.ValidEnforcementModes(), mode) {
		return fmt.Errorf("unknown enforcement mode %q", mode)
	}

	now := time.Now()
	updates := map[string]interface{}{
		"enforcement_mode": mode,
		"enforced_plan_at": now,
		"updated_at":       now,
	}
	if rep.Version != nil {
		updates["enforced_plan_version"] = *rep.Version
	}
	if rep.Evict != nil {
		updates["enforcement_evict"] = *rep.Evict
	}
	if rep.DenialsTotal != nil {
		// Stored as reported, INCLUDING a decrease. The counter resets when the
		// agent process restarts, and rewriting a smaller value as a larger one
		// would turn a restart into a permanently inflated total nobody can
		// explain.
		updates["enforcement_denials_total"] = *rep.DenialsTotal
	}
	return m.db.Model(&models.DiscoverySource{}).
		Where("id = ?", sourceID).Updates(updates).Error
}
