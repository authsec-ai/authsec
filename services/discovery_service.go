package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
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

	// RegisterAgent records a heartbeat from a deployed discovery agent, creating
	// its connector row on first contact. Idempotent on (workspace, kind,
	// instance), so the agent may call it on a timer forever.
	RegisterAgent(workspaceID uuid.UUID, in AgentRegistrationInput) (source *models.DiscoverySource, created bool, err error)

	// RecordLifecycleEvent records one observation of an agent's runtime lifecycle
	// and folds it into the inventory. Returns nil for the agent when the
	// fingerprint is unknown — the event is still kept.
	RecordLifecycleEvent(workspaceID uuid.UUID, in LifecycleEventInput) (*models.DiscoveredAgent, *models.DiscoveredAgentEvent, error)

	// ReconcileManifest diffs a completed resync sweep against the inventory and
	// retires agents the sweep proves absent. A PARTIAL sweep retires nothing.
	ReconcileManifest(workspaceID uuid.UUID, in ManifestInput) (*ManifestResult, error)

	// ListAgentEvents returns one agent's lifecycle history, newest first.
	ListAgentEvents(workspaceID, agentID uuid.UUID, limit int) ([]models.DiscoveredAgentEvent, error)

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
	// ReleaseQuarantine lifts a quarantine and queues the in-cluster release, so the
	// deny NetworkPolicy is actually removed rather than left behind.
	ReleaseQuarantine(workspaceID, agentID uuid.UUID, by *uuid.UUID) (*models.DiscoveredAgent, error)

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
	// ObservedAt is when the connector SAW this, not when we received it. It orders
	// runtime-state transitions, so a sighting that sat in a retry queue cannot
	// resurrect an agent deleted after it was enqueued. Defaults to now.
	ObservedAt *time.Time
}

// AgentRegistrationInput is a heartbeat from a deployed discovery agent.
//
// InstanceID is the upsert key. Everything else is a refreshed snapshot, which is
// why this is a heartbeat rather than a create: the agent restarts, upgrades, and
// gets rescheduled constantly, and none of that should mint a new connector.
type AgentRegistrationInput struct {
	Kind         string
	InstanceID   string
	DisplayName  string
	ClusterName  string
	ClusterUID   string
	AgentVersion string
	// Status is the agent's own health assessment: "healthy" or "degraded".
	Status string
	Error  string
	// Runtime is a free-form snapshot (pod, node, uptime, resolved config,
	// counters). Observability only — nothing reads it to make a decision.
	Runtime map[string]interface{}
	// ReportedSightings > 0 advances last_sync_at. A heartbeat alone must not: an
	// idle cluster's agent is healthy but has nothing to sync, and conflating the
	// two would make it look stalled.
	ReportedSightings int64
}

// LifecycleEventInput is one observation of an agent's runtime lifecycle.
type LifecycleEventInput struct {
	Source            string
	DiscoverySourceID *uuid.UUID
	Fingerprint       string
	Event             string
	Reason            string
	// Actor is the principal the API server attributed the change to. Only ever
	// meaningful on the admission channel.
	Actor       string
	Channel     string
	ClusterName string
	Metadata    map[string]interface{}
	ObservedAt  *time.Time
}

// ManifestInput is a completed resync sweep: everything the connector observed,
// plus the scope it observed it in.
type ManifestInput struct {
	Source            string
	DiscoverySourceID *uuid.UUID
	ClusterName       string
	ScanKind          string
	// Complete is false when any LIST in the sweep failed. A partial sweep retires
	// nothing — see ReconcileManifest.
	Complete       bool
	Namespaces     []string
	Fingerprints   []string
	SweepStartedAt *time.Time
	ObservedAt     *time.Time
}

// ManifestResult reports what a manifest changed, so the connector's logs and the
// console agree on what happened.
type ManifestResult struct {
	Accepted     bool     `json:"accepted"`
	Reconciled   bool     `json:"reconciled"`
	Reason       string   `json:"reason,omitempty"`
	Observed     int      `json:"observed"`
	Namespaces   int      `json:"namespaces"`
	MarkedGone   int      `json:"marked_gone"`
	Fingerprints []string `json:"fingerprints,omitempty"`
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
	// Connected / SecondsSinceHeartbeat are filled by DiscoverySource.AfterFind.
	return m.repo.GetSource(workspaceID, id)
}

func (m *discoveryManager) ListSources(workspaceID uuid.UUID, kind string, enabledOnly bool) ([]models.DiscoverySource, error) {
	if kind != "" && !containsString(models.ValidDiscoverySourceKinds(), kind) {
		return nil, fmt.Errorf("unknown discovery source kind %q", kind)
	}
	// Liveness is derived on read by DiscoverySource.AfterFind, not stored: a stored
	// boolean would need a sweeper to flip it and would be stale between sweeps.
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

/* --------------------------- self-registration -------------------------- */

// RegisterAgent records a heartbeat from a deployed discovery agent.
//
// Why an agent registers itself at all: one control plane serves agents in many
// clusters, and without this the only trace of which cluster a sighting came from
// is a string inside its metadata jsonb. That is enough to read one row and far
// too little to answer the operational questions — which clusters are reporting,
// what version does each run, and has one gone quiet? A connector row per cluster
// makes those a query, and returning its id lets every subsequent sighting carry a
// real discovery_source_id foreign key instead of nothing.
func (m *discoveryManager) RegisterAgent(workspaceID uuid.UUID, in AgentRegistrationInput) (*models.DiscoverySource, bool, error) {
	if !containsString(models.ValidDiscoverySourceKinds(), in.Kind) {
		return nil, false, fmt.Errorf("unknown discovery source kind %q", in.Kind)
	}
	if strings.TrimSpace(in.InstanceID) == "" {
		return nil, false, errors.New("instance_id is required: it is the stable key this agent re-registers under")
	}
	if strings.TrimSpace(in.ClusterName) == "" {
		return nil, false, errors.New("cluster_name is required: it is how an operator tells one reporting cluster from another")
	}
	// The agent asserts its own health, so constrain the vocabulary — an arbitrary
	// string here would end up rendered as a status badge in the console.
	status := in.Status
	switch status {
	case "":
		status = "healthy"
	case "healthy", "degraded":
	default:
		return nil, false, fmt.Errorf("status must be healthy or degraded, got %q", status)
	}

	display := strings.TrimSpace(in.DisplayName)
	if display == "" {
		display = in.ClusterName
	}

	runtimeJSON, err := marshalDiscoveryConfig(in.Runtime)
	if err != nil {
		return nil, false, err
	}

	now := time.Now()
	src := &models.DiscoverySource{
		ID:          uuid.New(),
		WorkspaceID: workspaceID,
		Kind:        in.Kind,
		DisplayName: display,
		// Config is the admin-owned half and is never written by a heartbeat; the
		// machine-owned snapshot goes to Runtime instead.
		Config:          json.RawMessage("{}"),
		Enabled:         true,
		InstanceID:      in.InstanceID,
		ClusterName:     in.ClusterName,
		ClusterUID:      in.ClusterUID,
		AgentVersion:    in.AgentVersion,
		LastHeartbeatAt: &now,
		LastStatus:      status,
		LastError:       in.Error,
		SelfRegistered:  true,
		Runtime:         runtimeJSON,
		CreatedBy:       "self-registered:" + in.Kind,
	}
	// last_sync_at means "last produced useful output", which a bare heartbeat is
	// not. Only advance it when the agent reports it has actually sent sightings.
	if in.ReportedSightings > 0 {
		src.LastSyncAt = &now
	}

	stored, created, err := m.repo.UpsertSelfRegistration(src)
	if err != nil {
		return nil, false, err
	}
	// Explicit here because AfterFind does not fire for a Create with RETURNING.
	stored.DeriveConnected(now)
	return stored, created, nil
}

/* ---------------------------- lifecycle events -------------------------- */

// RecordLifecycleEvent records one observation of an agent's runtime lifecycle.
//
// The channel bounds what the event may claim. An admission event carries an actor
// the API server authenticated; a resync event cannot, because absence has no
// author. Silently accepting an actor on a resync event would put an
// unattributable deletion in front of a reviewer as though it were attributed, so
// it is dropped rather than trusted.
func (m *discoveryManager) RecordLifecycleEvent(workspaceID uuid.UUID, in LifecycleEventInput) (*models.DiscoveredAgent, *models.DiscoveredAgentEvent, error) {
	if in.Fingerprint == "" {
		return nil, nil, errors.New("fingerprint is required: it is how an event is matched to an agent")
	}
	if !containsString(models.ValidDiscoverySourceKinds(), in.Source) {
		return nil, nil, fmt.Errorf("unknown discovery source %q", in.Source)
	}
	if !containsString(models.ValidAgentEvents(), in.Event) {
		return nil, nil, fmt.Errorf("unknown lifecycle event %q", in.Event)
	}

	channel := in.Channel
	if channel == "" {
		channel = models.DiscoveryChannelAdmission
	}
	switch channel {
	case models.DiscoveryChannelAdmission, models.DiscoveryChannelResync, models.DiscoveryChannelControlPlane:
	default:
		return nil, nil, fmt.Errorf("unknown discovery channel %q", channel)
	}

	actor := in.Actor
	if channel != models.DiscoveryChannelAdmission {
		actor = ""
	}

	if in.DiscoverySourceID != nil {
		if _, err := m.repo.GetSource(workspaceID, *in.DiscoverySourceID); err != nil {
			return nil, nil, fmt.Errorf("unknown discovery_source_id for this workspace: %w", err)
		}
	}

	observedAt := time.Now()
	if in.ObservedAt != nil && !in.ObservedAt.IsZero() {
		observedAt = *in.ObservedAt
	}

	metadataJSON, err := marshalDiscoveryConfig(in.Metadata)
	if err != nil {
		return nil, nil, err
	}

	event := &models.DiscoveredAgentEvent{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		DiscoverySourceID: in.DiscoverySourceID,
		Source:            in.Source,
		Fingerprint:       in.Fingerprint,
		Event:             in.Event,
		RuntimeStatus:     runtimeStatusFor(in.Event),
		Reason:            in.Reason,
		Actor:             actor,
		Channel:           channel,
		ClusterName:       in.ClusterName,
		Metadata:          metadataJSON,
		ObservedAt:        observedAt,
	}

	agent, err := m.repo.ApplyLifecycleEvent(event)
	if err != nil {
		return nil, nil, err
	}
	return agent, event, nil
}

// runtimeStatusFor maps an event to the runtime state it asserts.
//
// pod_terminated asserts NOTHING, and that is the important case. A rollout,
// eviction, or node drain destroys pods without removing the agent — and during a
// rolling update the old pod's DELETE can be observed AFTER the new pod's CREATE,
// so treating it as "gone" would leave a running agent permanently marked
// destroyed. It is recorded for the history and folded into no state.
func runtimeStatusFor(event string) string {
	switch event {
	case models.AgentEventObserved, models.AgentEventReappeared:
		return models.RuntimeStatusRunning
	case models.AgentEventDeleted, models.AgentEventAbsent:
		return models.RuntimeStatusGone
	default:
		return ""
	}
}

func (m *discoveryManager) ListAgentEvents(workspaceID, agentID uuid.UUID, limit int) ([]models.DiscoveredAgentEvent, error) {
	return m.repo.ListAgentEvents(workspaceID, agentID, limit)
}

/* ------------------------- manifest reconciliation ---------------------- */

// ReconcileManifest diffs a completed sweep against the inventory and retires the
// agents it proves absent.
//
// A PARTIAL manifest reconciles nothing. This is the single most important rule
// here: the connector sets complete=false when any LIST in its sweep failed, and
// treating absence from a partial sweep as deletion would let one transient RBAC
// error or API timeout retire a large part of a customer's inventory in a single
// request. A partial manifest is still accepted and acknowledged — it is evidence
// of what WAS seen — it just cannot be evidence of what was not.
//
// The connector deliberately reports facts ("at T, sweeping these namespaces,
// these were present, and my sweep was complete") and takes no position on what
// absence means, because that is a governance policy question. This function is
// where that policy lives.
func (m *discoveryManager) ReconcileManifest(workspaceID uuid.UUID, in ManifestInput) (*ManifestResult, error) {
	if !containsString(models.ValidDiscoverySourceKinds(), in.Source) {
		return nil, fmt.Errorf("unknown discovery source %q", in.Source)
	}
	if strings.TrimSpace(in.ClusterName) == "" {
		// Absence is only meaningful within one cluster. Without a cluster name the
		// diff would span every cluster in the workspace and retire agents in
		// clusters this sweep never touched.
		return nil, errors.New("cluster is required: absence in one cluster says nothing about another")
	}
	if in.DiscoverySourceID != nil {
		if _, err := m.repo.GetSource(workspaceID, *in.DiscoverySourceID); err != nil {
			return nil, fmt.Errorf("unknown discovery_source_id for this workspace: %w", err)
		}
	}

	observedAt := time.Now()
	if in.ObservedAt != nil && !in.ObservedAt.IsZero() {
		observedAt = *in.ObservedAt
	}
	sweepStart := observedAt
	if in.SweepStartedAt != nil && !in.SweepStartedAt.IsZero() {
		sweepStart = *in.SweepStartedAt
	}

	result := &ManifestResult{
		Accepted:   true,
		Observed:   len(in.Fingerprints),
		Namespaces: len(in.Namespaces),
	}

	if !in.Complete {
		result.Reason = "sweep was incomplete, so absence is not evidence of deletion; " +
			"nothing was retired"
		return result, nil
	}
	if len(in.Namespaces) == 0 {
		result.Reason = "sweep named no namespaces, so it observed nothing and can prove nothing"
		return result, nil
	}

	gone, err := m.repo.MarkAbsent(repositories.MarkAbsentInput{
		WorkspaceID:    workspaceID,
		Source:         in.Source,
		SourceID:       in.DiscoverySourceID,
		ClusterName:    in.ClusterName,
		Present:        in.Fingerprints,
		Namespaces:     in.Namespaces,
		SweepStartedAt: sweepStart,
		ObservedAt:     observedAt,
		Reason: fmt.Sprintf("absent from a complete %s sweep of cluster %q covering %d namespace(s)",
			defaultString(in.ScanKind, "resync"), in.ClusterName, len(in.Namespaces)),
	})
	if err != nil {
		return nil, err
	}

	result.Reconciled = true
	result.MarkedGone = len(gone)
	result.Fingerprints = gone

	// One event per retired agent, so "this was retired by a sweep, not by a
	// person" is discoverable later. Recorded after the state change: the update is
	// the fact, these are its explanation, and failing to write one must not undo a
	// correct retirement.
	for _, fp := range gone {
		_, _, evErr := m.RecordLifecycleEvent(workspaceID, LifecycleEventInput{
			Source:            in.Source,
			DiscoverySourceID: in.DiscoverySourceID,
			Fingerprint:       fp,
			Event:             models.AgentEventAbsent,
			Reason:            result.Reason,
			Channel:           models.DiscoveryChannelResync,
			ClusterName:       in.ClusterName,
			ObservedAt:        &observedAt,
		})
		if evErr != nil {
			// Surfaced in the response rather than failing the request: the inventory
			// is already correct, and a connector retrying would only re-run a diff
			// that is now a no-op.
			result.Reason += fmt.Sprintf(" (warning: could not record event for %s: %v)", fp, evErr)
		}
	}

	return result, nil
}

func defaultString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
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
	// A repo scan finding is a DECLARATION, not a deployment: the file may
	// never have run, and nothing in it says how it would be deployed if it
	// did. This function used to force "automated" here regardless of what
	// the caller passed, on the reasoning that anything version-controlled is
	// automated by construction — that reasoning was rejected when the GitHub
	// scanner was built (services/discovery_github_scanner.go now passes
	// "unknown" explicitly for exactly this reason), but this second,
	// independent override sat downstream of it and silently put "automated"
	// back on every repo_scan row regardless. Removed rather than special-cased
	// again: origin is the caller's call, this function's job is validation.

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

	observedAt := time.Now()
	if in.ObservedAt != nil && !in.ObservedAt.IsZero() {
		observedAt = *in.ObservedAt
	}

	// Always built as unregistered: discovery only makes an agent visible.
	//
	// RuntimeStatus is running, not unknown: a sighting is direct evidence the
	// workload exists. The upsert applies it under a monotonic guard on
	// RuntimeObservedAt, so this cannot resurrect an agent that was deleted after
	// this sighting was observed but before it arrived.
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
		RuntimeStatus:     models.RuntimeStatusRunning,
		RuntimeReason:     "observed by the " + in.Source + " connector",
		RuntimeObservedAt: &observedAt,
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

	// Offer this sighting to the correlated IGA estate, so a workload seen running
	// in a cluster can be recognised as an agent the organisation already knows
	// about from another channel.
	//
	// Only on FIRST sighting: the proposal depends on the display name, which the
	// upsert does not change, so re-running it on every re-sighting would be pure
	// load for an identical answer. It also only ever PROPOSES -- the two models
	// share no identifier, so the link needs a human, and the database refuses to
	// accept a weak one without a recorded decision.
	//
	// Best-effort for the same reason as the liveness stamp: correlation is a
	// convenience laid on top of the inventory, and losing a sighting to protect
	// it would invert the priority.
	if created {
		if db := m.repo.DB(); db != nil {
			if _, lerr := NewIGABridgeManager(db).ProposeForAgent(workspaceID, stored.ID); lerr != nil {
				log.Printf("[discovery] could not propose an IGA correlation for agent %s: %v",
					stored.ID, lerr)
			}
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
	if f.RuntimeStatus != "" && !containsString(models.ValidRuntimeStatuses(), f.RuntimeStatus) {
		return nil, 0, fmt.Errorf("unknown runtime status %q (want one of running, stopped, gone, unknown)", f.RuntimeStatus)
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
	agent, err := m.repo.QuarantineAgent(workspaceID, agentID, reason, by)
	if err != nil {
		return nil, err
	}

	// Queue the network deny that makes the decision real. Until phase 5 this status
	// was purely advisory — nothing in the codebase enforced it.
	//
	// Best-effort on purpose: the decision is already committed, so a cluster with no
	// actuation agent must not prevent an admin from recording that an agent is
	// untrusted. The gap stays VISIBLE instead — quarantine_enforced_at remains null, so
	// the console can show "quarantined but not blocked", which is the dangerous state.
	if db := m.repo.DB(); db != nil {
		actor := ""
		if by != nil {
			actor = by.String()
		}
		if queued, why := EnforceQuarantine(db, workspaceID, agent, false, actor); !queued && why != "" {
			if uerr := db.Model(&models.DiscoveredAgent{}).Where("id = ?", agent.ID).
				Update("quarantine_enforcement_error",
					"not enforced in-cluster: "+why).Error; uerr == nil {
				agent.QuarantineEnforcementError = "not enforced in-cluster: " + why
			}
		}
	}
	return agent, nil
}

// ReleaseQuarantine lifts a quarantine and queues the in-cluster release.
//
// Until this existed, quarantine was one-way through the API: the deny NetworkPolicy
// stayed until somebody ran `kubectl delete networkpolicy` by hand. Every other piece
// was already present — the agent implements the unquarantine instruction and
// EnforceQuarantine takes a release flag — but nothing ever called it.
//
// The decision-then-best-effort-enforcement shape mirrors QuarantineAgent exactly,
// but the failure direction is the opposite one and that matters. A quarantine that
// cannot be enforced fails OPEN (the agent keeps running), so the error is recorded on
// the row for the console to show. A release that cannot be enforced fails CLOSED (the
// agent stays blocked) — inconvenient, not dangerous — so the release still commits
// and the leftover policy is reported rather than blocking the decision.
func (m *discoveryManager) ReleaseQuarantine(workspaceID, agentID uuid.UUID,
	by *uuid.UUID) (*models.DiscoveredAgent, error) {

	agent, err := m.repo.ReleaseQuarantine(workspaceID, agentID, by)
	if err != nil {
		return nil, err
	}

	if db := m.repo.DB(); db != nil {
		actor := ""
		if by != nil {
			actor = by.String()
		}
		if queued, why := EnforceQuarantine(db, workspaceID, agent, true, actor); !queued && why != "" {
			// Recorded on the row because the operator has to know the policy is still
			// there. Phrased as what is true rather than as an enforcement failure: the
			// governance decision succeeded, the cleanup did not.
			msg := "released, but the in-cluster NetworkPolicy was NOT removed (" + why +
				"); delete it manually: kubectl delete networkpolicy -n <ns> " +
				"-l authsec.ai/quarantine=true"
			if uerr := db.Model(&models.DiscoveredAgent{}).Where("id = ?", agent.ID).
				Update("quarantine_enforcement_error", msg).Error; uerr == nil {
				agent.QuarantineEnforcementError = msg
			}
		}
	}
	return agent, nil
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
