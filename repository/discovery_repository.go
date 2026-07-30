package repositories

import (
	"errors"
	"fmt"
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
	UpdateSource(s *models.DiscoverySource) error
	DeleteSource(workspaceID, id uuid.UUID) error

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

	// ClaimAgent links a sighting to a governed identity and an accountable
	// owner in one conditional update. Refuses a quarantined or already-claimed
	// agent.
	ClaimAgent(in ClaimAgentInput) (*models.DiscoveredAgent, error)

	// QuarantineAgent flags an agent untrusted, which blocks a later claim.
	QuarantineAgent(workspaceID, id uuid.UUID, reason string, by *uuid.UUID) (*models.DiscoveredAgent, error)

	// Coverage returns registered-over-total segmented by origin and source.
	Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error)
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
	Limit            int
	Offset           int
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

/* ------------------------------- sources -------------------------------- */

func (r *discoveryRepository) CreateSource(s *models.DiscoverySource) error {
	return r.db.Create(s).Error
}

func (r *discoveryRepository) GetSource(workspaceID, id uuid.UUID) (*models.DiscoverySource, error) {
	var s models.DiscoverySource
	if err := r.db.First(&s, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, err
	}
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
	err := q.Order("kind, display_name").Find(&sources).Error
	return sources, err
}

func (r *discoveryRepository) UpdateSource(s *models.DiscoverySource) error {
	return r.db.Save(s).Error
}

func (r *discoveryRepository) DeleteSource(workspaceID, id uuid.UUID) error {
	res := r.db.Delete(&models.DiscoverySource{}, "id = ? AND workspace_id = ?", id, workspaceID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Manual origin first, then unknown, then automated — the report should lead
	// with the agents nobody can attribute.
	var agents []models.DiscoveredAgent
	err := q.Order("CASE deployment_origin WHEN 'manual' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END").
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

/* -------------------------------- coverage ------------------------------ */

func (r *discoveryRepository) Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error) {
	out := &models.AgentCoverage{
		WorkspaceID: workspaceID,
		ByOrigin:    map[string]*models.CoverageBucket{},
		BySource:    map[string]int64{},
		GeneratedAt: time.Now(),
	}

	// One grouped scan over (deployment_origin, source, status) covers every
	// number below — cheaper and more consistent than a query per counter.
	type row struct {
		DeploymentOrigin string
		Source           string
		Status           string
		OwnerPresent     bool
		Count            int64
	}
	var rows []row
	err := r.db.Model(&models.DiscoveredAgent{}).
		Select("deployment_origin, source, status, (owner_user_id IS NOT NULL) AS owner_present, COUNT(*) AS count").
		Where("workspace_id = ?", workspaceID).
		Group("deployment_origin, source, status, owner_present").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	for _, rw := range rows {
		out.Total += rw.Count
		out.BySource[rw.Source] += rw.Count

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
