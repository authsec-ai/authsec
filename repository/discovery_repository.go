package repositories

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

// ErrForwardOnly is returned when a caller tries to move a discovered agent's
// status backwards to unregistered. Status is forward-only by design.
var ErrForwardOnly = errors.New("discovered agent status cannot move back to unregistered")

// ErrQuarantined is returned when a caller tries to claim a quarantined agent.
// Quarantine is what blocks a claim.
var ErrQuarantined = errors.New("agent is quarantined and cannot be claimed")

// DiscoveryRepository provides workspace-scoped CRUD for discovery sources and
// the discovered-agent inventory, plus the claim / quarantine transitions.
type DiscoveryRepository interface {
	CreateSource(s *models.DiscoverySource) error
	GetSource(workspaceID, id uuid.UUID) (*models.DiscoverySource, error)
	ListSources(workspaceID uuid.UUID, kind string, enabledOnly bool) ([]models.DiscoverySource, error)
	TouchSource(workspaceID, id uuid.UUID, status string) error
	UpdateSource(s *models.DiscoverySource) error
	// DeleteSource removes a source, its integration, and its findings.
	// Returns a secrets-store path to purge when this was the workspace's last
	// GitHub organisation, or "" when there is nothing to purge.
	DeleteSource(workspaceID, id uuid.UUID) (string, error)

	// UpsertSelfRegistration records a heartbeat from a deployed agent as ONE
	// atomic statement keyed by (workspace_id, kind, instance_id). Machine-owned
	// fields are refreshed; admin-owned ones are never overwritten.
	UpsertSelfRegistration(s *models.DiscoverySource) (stored *models.DiscoverySource, created bool, err error)

	GetAgent(workspaceID, id uuid.UUID) (*models.DiscoveredAgent, error)
	GetAgentByFingerprint(workspaceID uuid.UUID, source, fingerprint string) (*models.DiscoveredAgent, error)
	ListAgents(workspaceID uuid.UUID, f AgentFilter) ([]models.DiscoveredAgent, int64, error)
	UpdateAgent(workspaceID, id uuid.UUID, fields map[string]interface{}) (*models.DiscoveredAgent, error)
	DeleteAgent(workspaceID, id uuid.UUID) error

	// UpsertSighting records a sighting as ONE atomic statement keyed by
	// (workspace_id, source, fingerprint). A repeated sighting bumps last_seen_at
	// and sighting_count; it never creates a duplicate row and never touches the
	// human decision fields. Reports whether the row was newly created.
	UpsertSighting(a *models.DiscoveredAgent) (stored *models.DiscoveredAgent, created bool, err error)

	// ApplyLifecycleEvent appends an immutable event and folds its assertion into
	// the agent's runtime columns, in one transaction. Returns the matched agent,
	// or nil when the fingerprint is unknown — the event is still recorded.
	ApplyLifecycleEvent(e *models.DiscoveredAgentEvent) (*models.DiscoveredAgent, error)

	// ListAgentEvents returns the lifecycle history for one agent, newest first.
	ListAgentEvents(workspaceID, agentID uuid.UUID, limit int) ([]models.DiscoveredAgentEvent, error)

	// MarkAbsent folds a COMPLETE resync manifest into the inventory: every agent
	// last seen in the manifest's scope but missing from it is marked gone.
	// Returns the fingerprints it marked.
	MarkAbsent(in MarkAbsentInput) ([]string, error)

	// ClaimAgent links a sighting to a governed identity and an accountable
	// owner in one conditional update. Refuses a quarantined or already-claimed
	// agent.
	ClaimAgent(in ClaimAgentInput) (*models.DiscoveredAgent, error)

	// QuarantineAgent flags an agent untrusted, which blocks a later claim.
	QuarantineAgent(workspaceID, id uuid.UUID, reason string, by *uuid.UUID) (*models.DiscoveredAgent, error)
	// ReleaseQuarantine lifts a quarantine, returning the agent to the status it held
	// before it. Guarded on status='quarantined' so a race cannot release twice.
	ReleaseQuarantine(workspaceID, id uuid.UUID, by *uuid.UUID) (*models.DiscoveredAgent, error)

	// Coverage returns registered-over-total segmented by origin and source.
	Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error)

	// DB exposes the handle so the service can queue in-cluster enforcement alongside
	// a governance decision.
	DB() *gorm.DB
}

// AgentFilter narrows an inventory listing. Empty fields are ignored. The
// Unregistered Agents report is Status=unregistered with the default ordering,
// which surfaces manual-origin agents first.
type AgentFilter struct {
	Status           string
	DeploymentOrigin string
	Source           string
	Archetype        string
	UnownedOnly      bool
	// RuntimeStatus filters on OBSERVED state (running/stopped/gone/unknown).
	RuntimeStatus string
	// LiveOnly excludes agents observed to be gone. This is what the actionable
	// Unregistered Agents queue wants: a deleted agent needs no claim decision, and
	// leaving it in the queue means coverage never reaches 100%.
	LiveOnly bool
	// DiscoverySourceID scopes to one connector — in practice, "agents in this
	// cluster", which is the question self-registration exists to make answerable.
	DiscoverySourceID *uuid.UUID
	Limit             int
	Offset            int
}

// MarkAbsentInput describes a completed resync sweep. Absence is only meaningful
// inside the scope actually swept, which is why Namespaces is required rather
// than optional: the agent never looked outside it.
type MarkAbsentInput struct {
	WorkspaceID uuid.UUID
	Source      string
	SourceID    *uuid.UUID
	ClusterName string
	// Present is every fingerprint the sweep observed.
	Present []string
	// Namespaces bounds the sweep. An agent in an unswept namespace must not be
	// marked gone just because this manifest does not mention it.
	Namespaces []string
	// SweepStartedAt is when the sweep BEGAN. Absence is only evidence for agents
	// that already existed then: one created mid-sweep is legitimately missing from
	// the manifest, and comparing against the sweep's end would retire it.
	SweepStartedAt time.Time
	ObservedAt     time.Time
	Reason         string
}

// ClaimAgentInput carries everything a claim needs. OwnerUserID is mandatory —
// the DB also enforces it via discovered_agents_registered_chk.
type ClaimAgentInput struct {
	WorkspaceID     uuid.UUID
	AgentID         uuid.UUID
	MatchedClientID uuid.UUID
	OwnerUserID     uuid.UUID
	Archetype       string
	ClaimedBy       *uuid.UUID
}

type discoveryRepository struct{ db *gorm.DB }

// NewDiscoveryRepository constructs a DiscoveryRepository.
func NewDiscoveryRepository(db *gorm.DB) DiscoveryRepository {
	return &discoveryRepository{db}
}

func (r *discoveryRepository) DB() *gorm.DB { return r.db }

/* ------------------------------- sources -------------------------------- */

func (r *discoveryRepository) CreateSource(s *models.DiscoverySource) error {
	return r.db.Create(s).Error
}

func (r *discoveryRepository) GetSource(workspaceID, id uuid.UUID) (*models.DiscoverySource, error) {
	var s models.DiscoverySource
	if err := r.db.First(&s, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	// The same computed-on-read count ListSources produces, so a detail view and
	// a list view can never disagree about how many agents a source found. Best
	// effort: a failed count must not turn a readable source into an error.
	_ = r.db.Model(&models.DiscoveredAgent{}).
		Where("workspace_id = ? AND discovery_source_id = ?", workspaceID, id).
		Count(&s.AgentCount).Error
	return &s, nil
}

func (r *discoveryRepository) ListSources(workspaceID uuid.UUID, kind string, enabledOnly bool) ([]models.DiscoverySource, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if kind != "" {
		q = q.Where("kind = ?", kind)
	}
	if enabledOnly {
		q = q.Where("enabled = ?", true)
	}
	var sources []models.DiscoverySource
	if err := q.Order("kind, display_name").Find(&sources).Error; err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return sources, nil
	}

	// One grouped query for the whole page rather than a count per row.
	type row struct {
		DiscoverySourceID uuid.UUID
		N                 int64
	}
	var rows []row
	if err := r.db.Model(&models.DiscoveredAgent{}).
		Select("discovery_source_id, count(*) AS n").
		Where("workspace_id = ? AND discovery_source_id IS NOT NULL", workspaceID).
		Group("discovery_source_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	counts := make(map[uuid.UUID]int64, len(rows))
	for _, x := range rows {
		counts[x.DiscoverySourceID] = x.N
	}
	for i := range sources {
		sources[i].AgentCount = counts[sources[i].ID]
	}
	return sources, nil
}

// TouchSource records that a source just reported. Best-effort: a sighting must
// never fail because the liveness stamp could not be written, so the caller
// ignores the error. Without this, last_sync_at is never written by anything and
// the console shows every integration as "Never run" forever.
func (r *discoveryRepository) TouchSource(workspaceID, id uuid.UUID, status string) error {
	return r.db.Model(&models.DiscoverySource{}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Updates(map[string]interface{}{
			"last_sync_at": time.Now(),
			"last_status":  status,
			"last_error":   "",
			"updated_at":   time.Now(),
		}).Error
}

func (r *discoveryRepository) UpdateSource(s *models.DiscoverySource) error {
	return r.db.Save(s).Error
}

// DeleteSource removes a discovery source and the integration binding it owns.
//
// The cascade is the point. A repo_scan source is created together with an
// iga_integrations row that exists only to serve it, and deleting the source
// alone used to strand that row: it kept reporting itself as an active,
// verified GitHub binding for an organisation nobody was scanning any more, and
// nothing in the console could reach it to clear it.
//
// Both statements run in one transaction because a half-applied delete is the
// same stranded row by another route. This is why the reach into
// iga_integrations lives here rather than a layer up, where the two deletes
// could not share a transaction.
//
// The findings go too. discovered_agents.discovery_source_id is ON DELETE SET
// NULL, so leaving the database to it produces rows with no source at all --
// sightings the console still lists and counts toward coverage, with nothing
// left that can rescan, refresh or explain them. There is an argument that a
// finding should outlive its scanner, and this used to implement it; in practice
// it made "delete" mean "hide the integration and keep its rows forever", which
// is not what deleting an integration is for. Deleting is now deleting.
//
// Everything that points at discovered_agents (events, access requests,
// provenance, provisioning instructions, IGA links) is itself ON DELETE SET
// NULL, so this cannot cascade into an audit trail or fail on a dependent row.
func (r *discoveryRepository) DeleteSource(workspaceID, id uuid.UUID) (string, error) {
	purgePath := ""
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var src models.DiscoverySource
		if err := tx.First(&src, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
			return err
		}

		integrationID := ""
		if len(src.Config) > 0 {
			var cfg struct {
				IntegrationID string `json:"integration_id"`
			}
			_ = json.Unmarshal(src.Config, &cfg)
			integrationID = cfg.IntegrationID
		}

		// BEFORE the source: once the source row goes, the FK nulls
		// discovery_source_id and there is no way left to tell which findings
		// belonged to it.
		if derr := tx.Delete(&models.DiscoveredAgent{},
			"workspace_id = ? AND discovery_source_id = ?", workspaceID, id).Error; derr != nil {
			return derr
		}

		res := tx.Delete(&models.DiscoverySource{}, "id = ? AND workspace_id = ?", id, workspaceID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}

		if integrationID != "" {
			if integID, perr := uuid.Parse(integrationID); perr == nil {
				// Not checked for RowsAffected: a source whose integration was
				// already removed is a source we still want deleted, not an
				// error that leaves it in place.
				if derr := tx.Delete(&models.IGAIntegration{},
					"id = ? AND workspace_id = ?", integID, workspaceID).Error; derr != nil {
					return derr
				}
			}
		}

		// Removing the LAST GitHub organisation also forgets the workspace's
		// GitHub App. Otherwise "delete the integration" leaves a registered App
		// and a private key behind with nothing using them -- which is where the
		// App appeared to come from after a delete, since the wizard reads it and
		// skips its own first step.
		if src.Kind == models.DiscoverySourceRepoScan {
			var remaining int64
			if cerr := tx.Model(&models.DiscoverySource{}).
				Where("workspace_id = ? AND kind = ?", workspaceID, models.DiscoverySourceRepoScan).
				Count(&remaining).Error; cerr != nil {
				return cerr
			}

			// The App key store is SHARED with the connector action broker, whose
			// shipped use is an agent calling a provider through it. Deleting the
			// key while a GitHub connector still exists would break that with an
			// error naming nothing the operator did. Discovery only gets to
			// remove the App when it is the last thing using it.
			var brokerConnectors int64
			if cerr := tx.Table("connectors").
				Where("workspace_id = ? AND provider_key = ?", workspaceID, "github").
				Count(&brokerConnectors).Error; cerr != nil {
				return cerr
			}

			if remaining == 0 && brokerConnectors == 0 {
				var app models.ConnectorProviderApp
				if ferr := tx.First(&app, "workspace_id = ? AND provider_key = ?",
					workspaceID, "github").Error; ferr == nil {
					if derr := tx.Delete(&models.ConnectorProviderApp{},
						"workspace_id = ? AND provider_key = ?", workspaceID, "github").Error; derr != nil {
						return derr
					}
					// Purged by the caller: the secrets store is not part of this
					// transaction, so it must happen only after the commit that
					// makes the row's removal real.
					purgePath = app.VaultPath
				}
			}
		}
		return nil
	})
	return purgePath, err
}

/* -------------------------- self-registration --------------------------- */

// UpsertSelfRegistration folds an agent heartbeat into its connector row.
//
// ON CONFLICT against the PARTIAL unique index discovery_sources_instance_key.
// The TargetWhere is not optional decoration: Postgres will only infer a partial
// index when the statement repeats the index predicate, so without
// `WHERE instance_id <> ”` this fails to find any arbiter index at all.
//
// One statement, so N agent replicas heartbeating concurrently cannot each insert
// a row for the same cluster.
func (r *discoveryRepository) UpsertSelfRegistration(s *models.DiscoverySource) (*models.DiscoverySource, bool, error) {
	if s.InstanceID == "" {
		return nil, false, errors.New("instance_id is required for self-registration")
	}
	proposedID := s.ID

	// Machine-owned fields only. display_name, enabled, config, created_by and
	// created_at are deliberately absent: an admin may rename a connector or
	// disable it, and the next heartbeat 60 seconds later must not undo that.
	assignments := map[string]interface{}{
		"cluster_name":      s.ClusterName,
		"agent_version":     s.AgentVersion,
		"last_heartbeat_at": s.LastHeartbeatAt,
		"last_status":       s.LastStatus,
		"last_error":        s.LastError,
		"runtime":           s.Runtime,
		"self_registered":   true,
		"updated_at":        time.Now(),
	}
	// Keep the last non-empty cluster UID. An agent that loses the RBAC to read it
	// (or is upgraded from a version that never sent it) would otherwise erase the
	// only evidence of which physical cluster this row belongs to.
	assignments["cluster_uid"] = gorm.Expr(
		"CASE WHEN excluded.cluster_uid <> '' THEN excluded.cluster_uid ELSE discovery_sources.cluster_uid END")
	// last_sync_at means "last did useful work", which a heartbeat is not — an idle
	// cluster heartbeats without producing sightings. Only advance it when the
	// agent says it actually reported something.
	if s.LastSyncAt != nil {
		assignments["last_sync_at"] = s.LastSyncAt
	}

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: "kind"}, {Name: "instance_id"},
			},
			TargetWhere: clause.Where{
				Exprs: []clause.Expression{gorm.Expr("instance_id <> ''")},
			},
			DoUpdates: clause.Assignments(assignments),
		},
		clause.Returning{},
	).Create(s).Error
	if err != nil {
		// A self-registering agent proposes a display name derived from its cluster.
		// If an admin already created a connector under that exact name, the insert
		// trips the display-name uniqueness constraint instead of the instance one,
		// and ON CONFLICT cannot catch a different arbiter. Say so plainly — the
		// generic Postgres text gives an operator nothing to act on.
		if strings.Contains(err.Error(), "discovery_sources_workspace_kind_name_key") {
			return nil, false, fmt.Errorf(
				"a %s connector named %q already exists in this workspace and is not the "+
					"self-registered one for cluster %q; rename it in the console so the agent "+
					"can register", s.Kind, s.DisplayName, s.ClusterName)
		}
		return nil, false, err
	}

	return s, s.ID == proposedID, nil
}

/* -------------------------------- agents -------------------------------- */

func (r *discoveryRepository) GetAgent(workspaceID, id uuid.UUID) (*models.DiscoveredAgent, error) {
	var a models.DiscoveredAgent
	if err := r.db.First(&a, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *discoveryRepository) GetAgentByFingerprint(workspaceID uuid.UUID, source, fingerprint string) (*models.DiscoveredAgent, error) {
	var a models.DiscoveredAgent
	err := r.db.First(&a, "workspace_id = ? AND source = ? AND fingerprint = ?",
		workspaceID, source, fingerprint).Error
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *discoveryRepository) ListAgents(workspaceID uuid.UUID, f AgentFilter) ([]models.DiscoveredAgent, int64, error) {
	q := r.db.Model(&models.DiscoveredAgent{}).Where("workspace_id = ?", workspaceID)

	if f.Status != "" {
		q = q.Where("status = ?", f.Status)
	}
	if f.DeploymentOrigin != "" {
		q = q.Where("deployment_origin = ?", f.DeploymentOrigin)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.Archetype != "" {
		q = q.Where("archetype = ?", f.Archetype)
	}
	if f.UnownedOnly {
		q = q.Where("owner_user_id IS NULL")
	}
	if f.RuntimeStatus != "" {
		q = q.Where("runtime_status = ?", f.RuntimeStatus)
	}
	if f.LiveOnly {
		// 'unknown' is included on purpose: never observing an agent's lifecycle is
		// not evidence it is gone, and excluding it would quietly hide every row that
		// predates lifecycle tracking.
		q = q.Where("runtime_status <> ?", models.RuntimeStatusGone)
	}
	if f.DiscoverySourceID != nil {
		q = q.Where("discovery_source_id = ?", *f.DiscoverySourceID)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Agents observed gone sort last regardless of origin: a destroyed agent needs
	// no claim decision, so leading the report with one wastes the reviewer's
	// attention on work that no longer exists.
	//
	// Within the live set: manual origin first, then unknown, then automated — the
	// report should lead with the agents nobody can attribute.
	var agents []models.DiscoveredAgent
	err := q.Order("CASE WHEN runtime_status = 'gone' THEN 1 ELSE 0 END").
		Order("CASE deployment_origin WHEN 'manual' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END").
		Order("last_seen_at DESC").
		Limit(f.Limit).Offset(f.Offset).
		Find(&agents).Error
	return agents, total, err
}

func (r *discoveryRepository) UpdateAgent(workspaceID, id uuid.UUID, fields map[string]interface{}) (*models.DiscoveredAgent, error) {
	if len(fields) == 0 {
		return r.GetAgent(workspaceID, id)
	}
	fields["updated_at"] = time.Now()

	res := r.db.Model(&models.DiscoveredAgent{}).
		Where("id = ? AND workspace_id = ?", id, workspaceID).
		Updates(fields)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return r.GetAgent(workspaceID, id)
}

func (r *discoveryRepository) DeleteAgent(workspaceID, id uuid.UUID) error {
	res := r.db.Delete(&models.DiscoveredAgent{}, "id = ? AND workspace_id = ?", id, workspaceID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

/* ---------------------------- sighting upsert --------------------------- */

func (r *discoveryRepository) UpsertSighting(a *models.DiscoveredAgent) (*models.DiscoveredAgent, bool, error) {
	// The id we would insert. Postgres RETURNING gives back the surviving row's
	// id, so a differing id after the statement means an existing row was bumped.
	proposedID := a.ID

	// ON CONFLICT DO UPDATE against discovered_agents_fingerprint_key. This is the
	// whole idempotency guarantee: one statement, no read-then-write race, so two
	// connectors reporting the same agent concurrently can never both insert.
	assignments := map[string]interface{}{
		"last_seen_at":   time.Now(),
		"sighting_count": gorm.Expr("discovered_agents.sighting_count + 1"),
		"updated_at":     time.Now(),
		// A sighting is positive evidence the workload exists right now, so it is
		// also a runtime observation — but only if it is NEWER than whatever last set
		// the runtime state. Without this guard a sighting delayed in the agent's
		// retry queue would resurrect an agent that was deleted after it was
		// enqueued, and the inventory would show a destroyed agent as running.
		"runtime_status": gorm.Expr(`CASE
			WHEN discovered_agents.runtime_observed_at IS NULL
			  OR excluded.runtime_observed_at >= discovered_agents.runtime_observed_at
			THEN excluded.runtime_status
			ELSE discovered_agents.runtime_status END`),
		"runtime_reason": gorm.Expr(`CASE
			WHEN discovered_agents.runtime_observed_at IS NULL
			  OR excluded.runtime_observed_at >= discovered_agents.runtime_observed_at
			THEN excluded.runtime_reason
			ELSE discovered_agents.runtime_reason END`),
		// GREATEST ignores NULL inputs in Postgres, so a first-ever runtime
		// observation lands correctly without a special case.
		"runtime_observed_at": gorm.Expr(
			"GREATEST(excluded.runtime_observed_at, discovered_agents.runtime_observed_at)"),
		// Refresh the descriptive fields, but keep the stored value when the
		// connector sends nothing.
		"display_name": gorm.Expr(
			"CASE WHEN excluded.display_name <> '' THEN excluded.display_name ELSE discovered_agents.display_name END"),
		"metadata": gorm.Expr(
			"CASE WHEN excluded.metadata <> '{}'::jsonb THEN excluded.metadata ELSE discovered_agents.metadata END"),
		"discovery_source_id": gorm.Expr(
			"COALESCE(excluded.discovery_source_id, discovered_agents.discovery_source_id)"),
		// deployment_origin is a heuristic, so only refresh it while the row is
		// still unregistered — an admin's correction must never be overwritten by
		// the next sighting.
		"deployment_origin": gorm.Expr(
			"CASE WHEN discovered_agents.status = 'unregistered' THEN excluded.deployment_origin ELSE discovered_agents.deployment_origin END"),
		"archetype": gorm.Expr(
			"CASE WHEN discovered_agents.archetype = '' THEN excluded.archetype ELSE discovered_agents.archetype END"),
	}
	// Deliberately NOT updated on conflict: status, matched_client_id,
	// owner_user_id, claimed_*, quarantined_*, first_seen_at. Those are human
	// governance decisions and a machine sighting may not move them.

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: "source"}, {Name: "fingerprint"},
			},
			DoUpdates: clause.Assignments(assignments),
		},
		clause.Returning{},
	).Create(a).Error
	if err != nil {
		return nil, false, err
	}

	return a, a.ID == proposedID, nil
}

/* ---------------------------- lifecycle events -------------------------- */

// ApplyLifecycleEvent appends the event and folds its assertion into the agent's
// runtime columns, in one transaction.
//
// The event is recorded even when no agent row matches the fingerprint. That is
// the whole point of allowing a null discovered_agent_id: an agent created and
// destroyed between two resyncs, or deleted while the reporting queue was backed
// up, leaves this event as the only evidence it ever existed. Dropping it would
// erase that.
func (r *discoveryRepository) ApplyLifecycleEvent(e *models.DiscoveredAgentEvent) (*models.DiscoveredAgent, error) {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.ObservedAt.IsZero() {
		e.ObservedAt = time.Now()
	}

	var out *models.DiscoveredAgent

	err := r.db.Transaction(func(tx *gorm.DB) error {
		var agent models.DiscoveredAgent
		findErr := tx.First(&agent, "workspace_id = ? AND source = ? AND fingerprint = ?",
			e.WorkspaceID, e.Source, e.Fingerprint).Error

		switch {
		case findErr == nil:
			e.DiscoveredAgentID = &agent.ID
			if e.DiscoverySourceID == nil {
				e.DiscoverySourceID = agent.DiscoverySourceID
			}
			// An observation landing on a row we had written off is worth its own
			// event kind: "the agent you were told was destroyed is back" is a
			// governance signal, not a routine sighting.
			if e.Event == models.AgentEventObserved &&
				(agent.RuntimeStatus == models.RuntimeStatusGone ||
					agent.RuntimeStatus == models.RuntimeStatusStopped) {
				e.Event = models.AgentEventReappeared
			}
		case errors.Is(findErr, gorm.ErrRecordNotFound):
			// Leave DiscoveredAgentID nil; the event still gets written.
		default:
			return findErr
		}

		if err := tx.Create(e).Error; err != nil {
			return err
		}

		// Nothing to fold: either no row, or a purely informational event such as a
		// controller-owned pod being rescheduled, which asserts no runtime state.
		if e.DiscoveredAgentID == nil || e.RuntimeStatus == "" {
			if e.DiscoveredAgentID != nil {
				out = &agent
			}
			return nil
		}

		fields := map[string]interface{}{
			"runtime_status":      e.RuntimeStatus,
			"runtime_reason":      e.Reason,
			"runtime_observed_at": e.ObservedAt,
			"updated_at":          time.Now(),
		}
		// Termination attribution is history, not current state: keep the first
		// answer to "who destroyed this" rather than overwriting it if the agent is
		// later recreated and deleted again by someone else. COALESCE on the stored
		// value would hide that, so only set it when it is currently unset.
		if e.RuntimeStatus == models.RuntimeStatusGone {
			fields["terminated_at"] = e.ObservedAt
			if e.Actor != "" && agent.TerminatedBy == "" {
				fields["terminated_by"] = e.Actor
			}
		}

		// The monotonic guard. Admission and resync observe independently and their
		// reports can arrive out of order — a resync that started before a delete can
		// land after it. Applying only observations at least as recent as the stored
		// one means late evidence is ignored rather than believed.
		res := tx.Model(&models.DiscoveredAgent{}).
			Where("id = ? AND workspace_id = ?", agent.ID, e.WorkspaceID).
			Where("runtime_observed_at IS NULL OR runtime_observed_at <= ?", e.ObservedAt).
			Updates(fields)
		if res.Error != nil {
			return res.Error
		}

		var refreshed models.DiscoveredAgent
		if err := tx.First(&refreshed, "id = ?", agent.ID).Error; err != nil {
			return err
		}
		out = &refreshed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *discoveryRepository) ListAgentEvents(workspaceID, agentID uuid.UUID, limit int) ([]models.DiscoveredAgentEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var events []models.DiscoveredAgentEvent
	err := r.db.Where("workspace_id = ? AND discovered_agent_id = ?", workspaceID, agentID).
		Order("observed_at DESC").
		Limit(limit).
		Find(&events).Error
	return events, err
}

// MarkAbsent folds a completed sweep into the inventory: agents in the swept
// scope that the sweep did not observe are marked gone.
//
// Three scoping conditions, each of which prevents a specific false positive:
//
//   - cluster_name — one workspace can hold agents from many clusters, and a sweep
//     of cluster A says nothing whatsoever about cluster B.
//   - namespace IN swept — the agent never looked outside its configured scope, so
//     absence there is not evidence.
//   - last_seen_at < sweep start — an agent created WHILE the sweep was running is
//     legitimately missing from the manifest. Comparing against the sweep's start
//     rather than its end is what stops the reconciler from immediately retiring
//     a workload that admission reported seconds earlier.
func (r *discoveryRepository) MarkAbsent(in MarkAbsentInput) ([]string, error) {
	if in.WorkspaceID == uuid.Nil || in.Source == "" {
		return nil, errors.New("workspace and source are required to reconcile a manifest")
	}
	if len(in.Namespaces) == 0 {
		// A sweep with no scope observed nothing, so it can prove nothing. Refusing
		// is important: an empty scope with an empty fingerprint list would otherwise
		// read as "the whole cluster is empty" and retire the entire inventory.
		return nil, errors.New("a manifest must name the namespaces it swept")
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now()
	}
	sweepStart := in.SweepStartedAt
	if sweepStart.IsZero() {
		sweepStart = in.ObservedAt
	}

	q := r.db.Model(&models.DiscoveredAgent{}).
		Where("workspace_id = ? AND source = ?", in.WorkspaceID, in.Source).
		Where("runtime_status <> ?", models.RuntimeStatusGone).
		Where("metadata #>> '{cluster,name}' = ?", in.ClusterName).
		Where("metadata #>> '{kubernetes,namespace}' IN ?", in.Namespaces).
		Where("last_seen_at < ?", sweepStart).
		Where("runtime_observed_at IS NULL OR runtime_observed_at <= ?", in.ObservedAt)

	if len(in.Present) > 0 {
		q = q.Where("fingerprint NOT IN ?", in.Present)
	}

	// Read the victims first so the caller can write an event per fingerprint. The
	// blind UPDATE would be cheaper, but then "this agent was retired" would exist
	// nowhere a human could later find it.
	var victims []models.DiscoveredAgent
	if err := q.Session(&gorm.Session{}).Find(&victims).Error; err != nil {
		return nil, err
	}
	if len(victims) == 0 {
		return nil, nil
	}

	ids := make([]uuid.UUID, 0, len(victims))
	fingerprints := make([]string, 0, len(victims))
	for _, v := range victims {
		ids = append(ids, v.ID)
		fingerprints = append(fingerprints, v.Fingerprint)
	}

	reason := in.Reason
	if reason == "" {
		reason = "absent from a complete resync sweep of this cluster"
	}

	err := r.db.Model(&models.DiscoveredAgent{}).
		Where("id IN ?", ids).
		Updates(map[string]interface{}{
			"runtime_status":      models.RuntimeStatusGone,
			"runtime_reason":      reason,
			"runtime_observed_at": in.ObservedAt,
			// terminated_by is deliberately NOT set. A sweep can prove that something
			// is absent; it can never say who removed it. Writing a guess here would
			// put an unattributable deletion in front of a reviewer as if it were
			// attributed.
			"terminated_at": in.ObservedAt,
			"updated_at":    time.Now(),
		}).Error
	if err != nil {
		return nil, err
	}
	return fingerprints, nil
}

/* --------------------------- claim / quarantine ------------------------- */

func (r *discoveryRepository) ClaimAgent(in ClaimAgentInput) (*models.DiscoveredAgent, error) {
	now := time.Now()

	fields := map[string]interface{}{
		"matched_client_id": in.MatchedClientID,
		"owner_user_id":     in.OwnerUserID,
		"status":            models.DiscoveredAgentRegistered,
		"claimed_by":        in.ClaimedBy,
		"claimed_at":        now,
		"updated_at":        now,
	}
	if in.Archetype != "" {
		fields["archetype"] = in.Archetype
	}

	// Conditional update: only an unregistered row may be claimed. Doing the
	// guard in the WHERE clause (rather than read-then-write) means two admins
	// racing to claim the same agent cannot both succeed.
	res := r.db.Model(&models.DiscoveredAgent{}).
		Where("id = ? AND workspace_id = ? AND status = ?",
			in.AgentID, in.WorkspaceID, models.DiscoveredAgentUnregistered).
		Updates(fields)
	if res.Error != nil {
		return nil, res.Error
	}

	if res.RowsAffected == 0 {
		// Nothing matched — say why, so the caller can return the right status.
		current, err := r.GetAgent(in.WorkspaceID, in.AgentID)
		if err != nil {
			return nil, err
		}
		switch current.Status {
		case models.DiscoveredAgentQuarantined:
			return nil, fmt.Errorf("%w: %s", ErrQuarantined, current.QuarantineReason)
		case models.DiscoveredAgentRegistered:
			return nil, fmt.Errorf("agent is already registered")
		default:
			return nil, fmt.Errorf("agent cannot be claimed from status %q", current.Status)
		}
	}

	return r.GetAgent(in.WorkspaceID, in.AgentID)
}

func (r *discoveryRepository) QuarantineAgent(workspaceID, id uuid.UUID, reason string, by *uuid.UUID) (*models.DiscoveredAgent, error) {
	now := time.Now()

	res := r.db.Model(&models.DiscoveredAgent{}).
		Where("id = ? AND workspace_id = ?", id, workspaceID).
		Updates(map[string]interface{}{
			"status":            models.DiscoveredAgentQuarantined,
			"quarantine_reason": reason,
			"quarantined_by":    by,
			"quarantined_at":    now,
			"updated_at":        now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return r.GetAgent(workspaceID, id)
}

// ReleaseQuarantine lifts a quarantine and returns the agent to the status it held
// before it was quarantined.
//
// The previous status is DERIVED rather than stored, and the predicate is chosen to
// match discovered_agents_registered_chk EXACTLY — that constraint requires a
// 'registered' agent to have both matched_client_id and owner_user_id, so deriving
// from the same two columns means this update can never violate it.
//
// Deriving from claimed_at instead would be a latent trap: both of those columns are
// ON DELETE SET NULL, so deleting the owning user or the OAuth client leaves
// claimed_at set with the ids gone. The release would then try to write 'registered'
// without an owner, hit the constraint, and fail — leaving the agent stuck quarantined
// with no way out, in exactly the situation where releasing it matters most.
//
// So an agent whose owner was deleted comes back 'unregistered', which is also the
// honest answer: it has no accountable owner, so it needs a fresh claim decision.
// claimed_at survives, so the history that it was once claimed is not lost.
//
// quarantined_at / quarantined_by / quarantine_reason are NOT cleared either. They are
// the record that this agent was quarantined and why; erasing them on release would
// destroy exactly the history a reviewer needs. quarantine_released_at is what marks
// the quarantine as history.
func (r *discoveryRepository) ReleaseQuarantine(workspaceID, id uuid.UUID,
	by *uuid.UUID) (*models.DiscoveredAgent, error) {

	now := time.Now()

	// Guard in the WHERE clause, as ClaimAgent does: two admins racing to release the
	// same agent cannot both succeed, and the loser gets a truthful error rather than
	// a second release enqueuing a duplicate instruction.
	res := r.db.Model(&models.DiscoveredAgent{}).
		Where("id = ? AND workspace_id = ? AND status = ?",
			id, workspaceID, models.DiscoveredAgentQuarantined).
		Updates(map[string]interface{}{
			"status": gorm.Expr(
				"CASE WHEN matched_client_id IS NOT NULL AND owner_user_id IS NOT NULL "+
					"THEN ? ELSE ? END",
				models.DiscoveredAgentRegistered, models.DiscoveredAgentUnregistered),
			"quarantine_released_at": now,
			"quarantine_released_by": by,
			// Enforcement state describes what is true NOW, so it does not survive the
			// release. Leaving a stale "not enforced" error on a released agent would
			// read as a live enforcement failure.
			"quarantine_enforced_at":       nil,
			"quarantine_enforcement_error": "",
			"updated_at":                   now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		// Say why nothing matched, so the caller can pick the right HTTP status.
		current, err := r.GetAgent(workspaceID, id)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("agent is not quarantined (status %q), so there is "+
			"nothing to release", current.Status)
	}
	return r.GetAgent(workspaceID, id)
}

/* -------------------------------- coverage ------------------------------ */

func (r *discoveryRepository) Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error) {
	out := &models.AgentCoverage{
		WorkspaceID:     workspaceID,
		ByOrigin:        map[string]*models.CoverageBucket{},
		BySource:        map[string]int64{},
		ByRuntimeStatus: map[string]int64{},
		GeneratedAt:     time.Now(),
	}

	// One grouped scan over (deployment_origin, source, status, runtime_status)
	// covers every number below — cheaper and more consistent than a query per
	// counter.
	type row struct {
		DeploymentOrigin string
		Source           string
		Status           string
		RuntimeStatus    string
		OwnerPresent     bool
		Count            int64
	}
	var rows []row
	err := r.db.Model(&models.DiscoveredAgent{}).
		Select("deployment_origin, source, status, runtime_status, "+
			"(owner_user_id IS NOT NULL) AS owner_present, COUNT(*) AS count").
		Where("workspace_id = ?", workspaceID).
		Group("deployment_origin, source, status, runtime_status, owner_present").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	for _, rw := range rows {
		out.Total += rw.Count
		out.BySource[rw.Source] += rw.Count
		out.ByRuntimeStatus[rw.RuntimeStatus] += rw.Count

		// The actionable queue: unregistered AND not known to be destroyed. Counting
		// long-deleted agents as ungoverned is why a diligent team could otherwise
		// watch coverage stall short of 100% with nothing left to claim.
		if rw.Status == models.DiscoveredAgentUnregistered &&
			rw.RuntimeStatus != models.RuntimeStatusGone {
			out.LiveUnregistered += rw.Count
		}

		if !rw.OwnerPresent {
			out.UnownedAgents += rw.Count
		}

		switch rw.Status {
		case models.DiscoveredAgentRegistered:
			out.Registered += rw.Count
		case models.DiscoveredAgentUnregistered:
			out.Unregistered += rw.Count
		case models.DiscoveredAgentQuarantined:
			out.Quarantined += rw.Count
		case models.DiscoveredAgentIgnored:
			out.Ignored += rw.Count
		}

		bucket := out.ByOrigin[rw.DeploymentOrigin]
		if bucket == nil {
			bucket = &models.CoverageBucket{}
			out.ByOrigin[rw.DeploymentOrigin] = bucket
		}
		bucket.Total += rw.Count
		if rw.Status == models.DiscoveredAgentRegistered {
			bucket.Registered += rw.Count
		}
	}

	out.CoveragePercent = coveragePercent(out.Registered, out.Total)
	for _, bucket := range out.ByOrigin {
		bucket.CoveragePercent = coveragePercent(bucket.Registered, bucket.Total)
	}

	return out, nil
}

// coveragePercent returns part/whole as a percentage rounded to two decimals.
func coveragePercent(part, whole int64) float64 {
	if whole == 0 {
		return 0
	}
	pct := float64(part) / float64(whole) * 100
	return float64(int64(pct*100+0.5)) / 100
}
