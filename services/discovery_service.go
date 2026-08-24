package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// DiscoveryManager holds the business rules for agent discovery: connector
// registration, the quarantine-first inventory, and the claim / quarantine
// decisions that bring a discovered agent under management.
//
// The governing invariant: a sighting never grants access. Everything a
// connector reports lands as unregistered, and only a human decision moves it
// forward.
type DiscoveryManager interface {
	CreateSource(workspaceID uuid.UUID, createdBy string, in DiscoverySourceInput) (*models.DiscoverySource, error)
	GetSource(workspaceID, id uuid.UUID) (*models.DiscoverySource, error)
	ListSources(workspaceID uuid.UUID, kind string, enabledOnly bool) ([]models.DiscoverySource, error)
	UpdateSource(workspaceID, id uuid.UUID, in DiscoverySourceUpdateInput) (*models.DiscoverySource, error)
	DeleteSource(workspaceID, id uuid.UUID) error

	// ReportSighting is the ONLY way an inventory row is created. It is an
	// idempotent upsert on (workspace, source, fingerprint), so a connector may
	// re-report the same agent on every scan.
	ReportSighting(workspaceID uuid.UUID, reportedBy string, in SightingInput) (agent *models.DiscoveredAgent, created bool, err error)

	GetAgent(workspaceID, id uuid.UUID) (*models.DiscoveredAgent, error)
	GetAgentByFingerprint(workspaceID uuid.UUID, source, fingerprint string) (*models.DiscoveredAgent, error)
	ListAgents(workspaceID uuid.UUID, f repositories.AgentFilter) ([]models.DiscoveredAgent, int64, error)
	UpdateAgent(workspaceID, id uuid.UUID, in AgentUpdateInput) (*models.DiscoveredAgent, error)
	DeleteAgent(workspaceID, id uuid.UUID) error

	// ClaimAgent links a sighting to a governed identity plus an accountable
	// owner. Quarantine blocks it; an owner is mandatory.
	ClaimAgent(workspaceID, agentID uuid.UUID, in ClaimInput) (*models.DiscoveredAgent, error)

	// QuarantineAgent flags an agent untrusted, which blocks a later claim. The
	// reason is required because the decision is audited.
	QuarantineAgent(workspaceID, agentID uuid.UUID, reason string, by *uuid.UUID) (*models.DiscoveredAgent, error)

	// Coverage is the headline governance KPI: the share of discovered agents
	// that have been brought under management, segmented by origin.
	Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error)
}

// DiscoverySourceInput is the validated create payload for a connector.
type DiscoverySourceInput struct {
	Kind        string
	DisplayName string
	Config      map[string]interface{}
	Enabled     *bool
}

// DiscoverySourceUpdateInput captures the patchable fields on a connector.
// LastStatus / LastError are how a connector run reports its own outcome.
type DiscoverySourceUpdateInput struct {
	DisplayName *string
	Config      map[string]interface{}
	Enabled     *bool
	LastStatus  *string
	LastError   *string
}

// SightingInput is what a connector reports. Fingerprint is the stable key that
// makes the report idempotent.
type SightingInput struct {
	Source            string
	DiscoverySourceID *uuid.UUID
	Fingerprint       string
	DisplayName       string
	Metadata          map[string]interface{}
	DeploymentOrigin  string
	Archetype         string
}

// AgentUpdateInput captures the operator-editable fields on an inventory row.
// Claim and quarantine are deliberately NOT here — they are their own audited
// transitions with their own permissions.
type AgentUpdateInput struct {
	DisplayName      *string
	Metadata         map[string]interface{}
	DeploymentOrigin *string
	Archetype        *string
	Status           *string
	OwnerUserID      *uuid.UUID
}

// ClaimInput carries the two mandatory halves of a claim — the identity every
// token will trace to, and the human who is accountable for the agent.
type ClaimInput struct {
	MatchedClientID uuid.UUID
	OwnerUserID     uuid.UUID
	Archetype       string
	ClaimedBy       *uuid.UUID
}

type discoveryManager struct {
	repo repositories.DiscoveryRepository
}

// NewDiscoveryManager constructs a DiscoveryManager.
func NewDiscoveryManager(repo repositories.DiscoveryRepository) DiscoveryManager {
	return &discoveryManager{repo: repo}
}

/* ------------------------------- sources -------------------------------- */

func (m *discoveryManager) CreateSource(workspaceID uuid.UUID, createdBy string, in DiscoverySourceInput) (*models.DiscoverySource, error) {
	if in.DisplayName == "" {
		return nil, errors.New("display_name is required")
	}
	if !containsString(models.ValidDiscoverySourceKinds(), in.Kind) {
		return nil, fmt.Errorf("unknown discovery source kind %q", in.Kind)
	}

	configJSON, err := marshalDiscoveryConfig(in.Config)
	if err != nil {
		return nil, err
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	src := &models.DiscoverySource{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		Kind:        in.Kind,
		DisplayName: in.DisplayName,
		Config:      configJSON,
		Enabled:     enabled,
		CreatedBy:   createdBy,
	}
	if err := m.repo.CreateSource(src); err != nil {
		return nil, err
	}
	return src, nil
}

func (m *discoveryManager) GetSource(workspaceID, id uuid.UUID) (*models.DiscoverySource, error) {
	return m.repo.GetSource(workspaceID, id)
}

func (m *discoveryManager) ListSources(workspaceID uuid.UUID, kind string, enabledOnly bool) ([]models.DiscoverySource, error) {
	if kind != "" && !containsString(models.ValidDiscoverySourceKinds(), kind) {
		return nil, fmt.Errorf("unknown discovery source kind %q", kind)
	}
	return m.repo.ListSources(workspaceID, kind, enabledOnly)
}

func (m *discoveryManager) UpdateSource(workspaceID, id uuid.UUID, in DiscoverySourceUpdateInput) (*models.DiscoverySource, error) {
	src, err := m.repo.GetSource(workspaceID, id)
	if err != nil {
		return nil, err
	}

	if in.DisplayName != nil {
		if *in.DisplayName == "" {
			return nil, errors.New("display_name cannot be empty")
		}
		src.DisplayName = *in.DisplayName
	}
	if in.Config != nil {
		configJSON, err := marshalDiscoveryConfig(in.Config)
		if err != nil {
			return nil, err
		}
		src.Config = configJSON
	}
	if in.Enabled != nil {
		src.Enabled = *in.Enabled
	}
	// A connector run reporting its own outcome also stamps last_sync_at.
	if in.LastStatus != nil {
		src.LastStatus = *in.LastStatus
		now := time.Now()
		src.LastSyncAt = &now
	}
	if in.LastError != nil {
		src.LastError = *in.LastError
	}

	if err := m.repo.UpdateSource(src); err != nil {
		return nil, err
	}
	return src, nil
}

func (m *discoveryManager) DeleteSource(workspaceID, id uuid.UUID) error {
	return m.repo.DeleteSource(workspaceID, id)
}

/* ------------------------------- sightings ------------------------------ */

func (m *discoveryManager) ReportSighting(workspaceID uuid.UUID, reportedBy string, in SightingInput) (*models.DiscoveredAgent, bool, error) {
	if in.Fingerprint == "" {
		return nil, false, errors.New("fingerprint is required: it is the stable key for a sighting")
	}
	if !containsString(models.ValidDiscoverySourceKinds(), in.Source) {
		return nil, false, fmt.Errorf("unknown discovery source %q", in.Source)
	}
	if in.Archetype != "" && !containsString(models.ValidAgentArchetypes(), in.Archetype) {
		return nil, false, fmt.Errorf("unknown archetype %q", in.Archetype)
	}

	origin := in.DeploymentOrigin
	if origin == "" {
		origin = models.DeploymentOriginUnknown
	}
	if !containsString(models.ValidDeploymentOrigins(), origin) {
		return nil, false, fmt.Errorf("unknown deployment origin %q", origin)
	}
	// A repo scan needs no inference: anything it finds came from a
	// version-controlled declaration, so it is automated by construction.
	if in.Source == models.DiscoverySourceRepoScan {
		origin = models.DeploymentOriginAutomated
	}

	// If the connector names a source, it must be one in this workspace —
	// otherwise the row would point at another workspace's connector.
	if in.DiscoverySourceID != nil {
		if _, err := m.repo.GetSource(workspaceID, *in.DiscoverySourceID); err != nil {
			return nil, false, fmt.Errorf("unknown discovery_source_id for this workspace: %w", err)
		}
	}

	metadataJSON, err := marshalDiscoveryConfig(in.Metadata)
	if err != nil {
		return nil, false, err
	}

	// Always built as unregistered: discovery only makes an agent visible.
	agent := &models.DiscoveredAgent{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		Source:            in.Source,
		DiscoverySourceID: in.DiscoverySourceID,
		Fingerprint:       in.Fingerprint,
		DisplayName:       in.DisplayName,
		Metadata:          metadataJSON,
		DeploymentOrigin:  origin,
		Archetype:         in.Archetype,
		Status:            models.DiscoveredAgentUnregistered,
		SightingCount:     1,
		CreatedBy:         reportedBy,
	}

	stored, created, err := m.repo.UpsertSighting(agent)
	if err != nil {
		return nil, false, err
	}

	// Record that this source is alive. Best-effort by design: a failed liveness
	// stamp must never cost us the sighting itself, which is the actual payload.
	if in.DiscoverySourceID != nil {
		if terr := m.repo.TouchSource(workspaceID, *in.DiscoverySourceID, "ok"); terr != nil {
			log.Printf("[discovery] could not stamp source %s as live: %v",
				in.DiscoverySourceID, terr)
		}
	}
	return stored, created, nil
}

/* -------------------------------- agents -------------------------------- */

func (m *discoveryManager) GetAgent(workspaceID, id uuid.UUID) (*models.DiscoveredAgent, error) {
	return m.repo.GetAgent(workspaceID, id)
}

func (m *discoveryManager) GetAgentByFingerprint(workspaceID uuid.UUID, source, fingerprint string) (*models.DiscoveredAgent, error) {
	if fingerprint == "" {
		return nil, errors.New("fingerprint is required")
	}
	return m.repo.GetAgentByFingerprint(workspaceID, source, fingerprint)
}

func (m *discoveryManager) ListAgents(workspaceID uuid.UUID, f repositories.AgentFilter) ([]models.DiscoveredAgent, int64, error) {
	if f.Status != "" && !containsString(models.ValidDiscoveredAgentStatuses(), f.Status) {
		return nil, 0, fmt.Errorf("unknown status %q", f.Status)
	}
	if f.DeploymentOrigin != "" && !containsString(models.ValidDeploymentOrigins(), f.DeploymentOrigin) {
		return nil, 0, fmt.Errorf("unknown deployment origin %q", f.DeploymentOrigin)
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return m.repo.ListAgents(workspaceID, f)
}

func (m *discoveryManager) UpdateAgent(workspaceID, id uuid.UUID, in AgentUpdateInput) (*models.DiscoveredAgent, error) {
	current, err := m.repo.GetAgent(workspaceID, id)
	if err != nil {
		return nil, err
	}

	fields := map[string]interface{}{}

	if in.DisplayName != nil {
		fields["display_name"] = *in.DisplayName
	}
	if in.Metadata != nil {
		metadataJSON, err := marshalDiscoveryConfig(in.Metadata)
		if err != nil {
			return nil, err
		}
		fields["metadata"] = metadataJSON
	}
	// An admin correcting a misclassified origin is a legitimate, audited edit.
	if in.DeploymentOrigin != nil {
		if !containsString(models.ValidDeploymentOrigins(), *in.DeploymentOrigin) {
			return nil, fmt.Errorf("unknown deployment origin %q", *in.DeploymentOrigin)
		}
		fields["deployment_origin"] = *in.DeploymentOrigin
	}
	if in.Archetype != nil {
		if *in.Archetype != "" && !containsString(models.ValidAgentArchetypes(), *in.Archetype) {
			return nil, fmt.Errorf("unknown archetype %q", *in.Archetype)
		}
		fields["archetype"] = *in.Archetype
	}
	if in.OwnerUserID != nil {
		fields["owner_user_id"] = *in.OwnerUserID
	}

	if in.Status != nil {
		if !containsString(models.ValidDiscoveredAgentStatuses(), *in.Status) {
			return nil, fmt.Errorf("unknown status %q", *in.Status)
		}
		// Forward-only. Nothing returns to unregistered once a human has acted.
		if *in.Status == models.DiscoveredAgentUnregistered &&
			current.Status != models.DiscoveredAgentUnregistered {
			return nil, repositories.ErrForwardOnly
		}
		// Registering goes through ClaimAgent, which is the audited transition
		// that supplies both an identity and an owner.
		if *in.Status == models.DiscoveredAgentRegistered &&
			current.Status != models.DiscoveredAgentRegistered {
			return nil, errors.New("use the claim endpoint to register an agent")
		}
		fields["status"] = *in.Status
	}

	return m.repo.UpdateAgent(workspaceID, id, fields)
}

func (m *discoveryManager) DeleteAgent(workspaceID, id uuid.UUID) error {
	return m.repo.DeleteAgent(workspaceID, id)
}

/* --------------------------- claim / quarantine ------------------------- */

func (m *discoveryManager) ClaimAgent(workspaceID, agentID uuid.UUID, in ClaimInput) (*models.DiscoveredAgent, error) {
	if in.MatchedClientID == uuid.Nil {
		return nil, errors.New("matched_client_id is required: every token and action must trace to one principal")
	}
	if in.OwnerUserID == uuid.Nil {
		return nil, errors.New("owner_user_id is required: an agent must have an accountable human owner")
	}
	if in.Archetype != "" && !containsString(models.ValidAgentArchetypes(), in.Archetype) {
		return nil, fmt.Errorf("unknown archetype %q", in.Archetype)
	}

	return m.repo.ClaimAgent(repositories.ClaimAgentInput{
		WorkspaceID:     workspaceID,
		AgentID:         agentID,
		MatchedClientID: in.MatchedClientID,
		OwnerUserID:     in.OwnerUserID,
		Archetype:       in.Archetype,
		ClaimedBy:       in.ClaimedBy,
	})
}

func (m *discoveryManager) QuarantineAgent(workspaceID, agentID uuid.UUID, reason string, by *uuid.UUID) (*models.DiscoveredAgent, error) {
	if reason == "" {
		return nil, errors.New("reason is required: the quarantine decision is audited")
	}
	return m.repo.QuarantineAgent(workspaceID, agentID, reason, by)
}

/* -------------------------------- coverage ------------------------------ */

func (m *discoveryManager) Coverage(workspaceID uuid.UUID) (*models.AgentCoverage, error) {
	return m.repo.Coverage(workspaceID)
}

/* -------------------------------- helpers ------------------------------- */

// marshalDiscoveryConfig turns a config/metadata map into jsonb, defaulting to
// an empty object so the NOT NULL column always has a value.
func marshalDiscoveryConfig(m map[string]interface{}) (json.RawMessage, error) {
	if len(m) == 0 {
		return json.RawMessage("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return b, nil
}
