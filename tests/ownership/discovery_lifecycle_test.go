// Discovery self-registration and runtime-lifecycle regression tests.
//
// These go through the real repository layer against a real Postgres, because the
// risky part of both features is SQL that GORM generates rather than SQL anyone
// wrote by hand:
//
//   - UpsertSelfRegistration relies on ON CONFLICT inferring a PARTIAL unique index,
//     which Postgres only does when the statement repeats the index predicate. If
//     GORM drops the TargetWhere, every heartbeat becomes a failed insert.
//   - The runtime-status monotonic guard is a CASE expression over `excluded` and the
//     stored row. Getting it backwards would silently resurrect deleted agents, and
//     no unit test with a fake DB would catch it.
//
// Requires TEST_DATABASE_URL, and skips without it, like the rest of this package.
package ownership

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// gormFor opens a GORM handle onto the same schema setupSchema just built.
func gormFor(t *testing.T, raw *sql.DB) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: raw}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db
}

func discoveryRepo(t *testing.T) (repositories.DiscoveryRepository, uuid.UUID) {
	t.Helper()
	raw := setupSchema(t)
	seedBaseline(t, raw)
	return repositories.NewDiscoveryRepository(gormFor(t, raw)), uuid.MustParse(wsA)
}

func selfReg(ws uuid.UUID, instance, cluster, version string) *models.DiscoverySource {
	now := time.Now()
	return &models.DiscoverySource{
		ID:              uuid.New(),
		WorkspaceID:     ws,
		Kind:            models.DiscoverySourceK8sWebhook,
		DisplayName:     cluster,
		Config:          json.RawMessage("{}"),
		Runtime:         json.RawMessage(`{"pod":"agent-1"}`),
		Enabled:         true,
		InstanceID:      instance,
		ClusterName:     cluster,
		AgentVersion:    version,
		LastHeartbeatAt: &now,
		LastStatus:      "healthy",
		SelfRegistered:  true,
	}
}

// The partial-index upsert must resolve to ONE row per cluster, however many times
// the agent heartbeats. If ON CONFLICT loses the index predicate this fails outright.
func TestSelfRegistrationHeartbeatIsIdempotent(t *testing.T) {
	repo, ws := discoveryRepo(t)

	first, created, err := repo.UpsertSelfRegistration(selfReg(ws, "k8s:prod-1", "prod-1", "0.2.0"))
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if !created {
		t.Error("the first registration should report created=true")
	}

	// Heartbeat with a newer agent version, as an upgraded pod would.
	second, created, err := repo.UpsertSelfRegistration(selfReg(ws, "k8s:prod-1", "prod-1", "0.2.1"))
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if created {
		t.Error("a heartbeat must be an update, not a create")
	}
	if second.ID != first.ID {
		t.Errorf("heartbeat produced a NEW connector row (%s vs %s); the control plane "+
			"would accumulate one row per pod restart", second.ID, first.ID)
	}
	if second.AgentVersion != "0.2.1" {
		t.Errorf("agent_version = %q, want the heartbeat's 0.2.1", second.AgentVersion)
	}

	sources, err := repo.ListSources(ws, models.DiscoverySourceK8sWebhook, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected exactly 1 connector row for one cluster, got %d", len(sources))
	}
	if !sources[0].Connected {
		t.Error("a connector that just heartbeated must read as connected")
	}
}

// Two clusters in one workspace are two connectors. Same statement, different
// instance id.
func TestTwoClustersGetSeparateConnectors(t *testing.T) {
	repo, ws := discoveryRepo(t)

	for _, c := range []string{"prod-1", "stage-1"} {
		if _, _, err := repo.UpsertSelfRegistration(selfReg(ws, "k8s:"+c, c, "0.2.0")); err != nil {
			t.Fatalf("register %s: %v", c, err)
		}
	}
	sources, err := repo.ListSources(ws, models.DiscoverySourceK8sWebhook, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 connectors for 2 clusters, got %d", len(sources))
	}
}

// A heartbeat is machine-owned but must not clobber admin-owned fields. An admin who
// disables or renames a connector would otherwise see it undone 60 seconds later.
func TestHeartbeatDoesNotOverwriteAdminDecisions(t *testing.T) {
	repo, ws := discoveryRepo(t)

	stored, _, err := repo.UpsertSelfRegistration(selfReg(ws, "k8s:prod-1", "prod-1", "0.2.0"))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// An admin renames it and turns it off.
	stored.DisplayName = "Production (US East)"
	stored.Enabled = false
	if err := repo.UpdateSource(stored); err != nil {
		t.Fatalf("admin update: %v", err)
	}

	after, _, err := repo.UpsertSelfRegistration(selfReg(ws, "k8s:prod-1", "prod-1", "0.2.2"))
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if after.DisplayName != "Production (US East)" {
		t.Errorf("heartbeat overwrote the admin's display_name: %q", after.DisplayName)
	}
	if after.Enabled {
		t.Error("heartbeat re-enabled a connector an admin had disabled")
	}
	if after.AgentVersion != "0.2.2" {
		t.Errorf("machine-owned agent_version should still refresh, got %q", after.AgentVersion)
	}
}

// helper: report a sighting the way the service layer does.
func sight(ws uuid.UUID, fp, cluster, ns string, observedAt time.Time) *models.DiscoveredAgent {
	meta := `{"cluster":{"name":"` + cluster + `"},"kubernetes":{"namespace":"` + ns + `"}}`
	return &models.DiscoveredAgent{
		ID:                uuid.New(),
		WorkspaceID:       ws,
		Source:            models.DiscoverySourceK8sWebhook,
		Fingerprint:       fp,
		DisplayName:       "agent " + fp,
		Metadata:          json.RawMessage(meta),
		DeploymentOrigin:  models.DeploymentOriginAutomated,
		Status:            models.DiscoveredAgentUnregistered,
		SightingCount:     1,
		RuntimeStatus:     models.RuntimeStatusRunning,
		RuntimeReason:     "observed",
		RuntimeObservedAt: &observedAt,
	}
}

// THE test that protects against the worst failure mode: a report delayed in the
// agent's retry queue must not resurrect an agent that was deleted after that report
// was observed. Getting the CASE expression backwards would show destroyed agents as
// running, which is precisely the bug lifecycle tracking exists to fix.
func TestLateSightingCannotResurrectADeletedAgent(t *testing.T) {
	repo, ws := discoveryRepo(t)

	t0 := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	tDelete := t0.Add(5 * time.Minute)
	tLate := t0.Add(2 * time.Minute) // observed BEFORE the delete, delivered after
	tFresh := t0.Add(10 * time.Minute)

	if _, _, err := repo.UpsertSighting(sight(ws, "fp-abc", "prod-1", "default", t0)); err != nil {
		t.Fatalf("first sighting: %v", err)
	}

	agent, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID:   ws,
		Source:        models.DiscoverySourceK8sWebhook,
		Fingerprint:   "fp-abc",
		Event:         models.AgentEventDeleted,
		RuntimeStatus: models.RuntimeStatusGone,
		Reason:        "deleted by alice@corp",
		Actor:         "alice@corp",
		Channel:       models.DiscoveryChannelAdmission,
		ObservedAt:    tDelete,
	})
	if err != nil {
		t.Fatalf("delete event: %v", err)
	}
	if agent == nil || agent.RuntimeStatus != models.RuntimeStatusGone {
		t.Fatalf("expected runtime_status=gone, got %+v", agent)
	}
	if agent.TerminatedBy != "alice@corp" {
		t.Errorf("terminated_by = %q; attribution is the point of the admission channel", agent.TerminatedBy)
	}

	// The late sighting arrives.
	late, _, err := repo.UpsertSighting(sight(ws, "fp-abc", "prod-1", "default", tLate))
	if err != nil {
		t.Fatalf("late sighting: %v", err)
	}
	if late.RuntimeStatus != models.RuntimeStatusGone {
		t.Fatalf("a sighting observed at %s must NOT override a deletion observed at %s; "+
			"runtime_status = %q", tLate, tDelete, late.RuntimeStatus)
	}
	if late.RuntimeReason != "deleted by alice@corp" {
		t.Errorf("the deletion's reason must survive, got %q", late.RuntimeReason)
	}

	// A genuinely fresh sighting (recreated workload) does flip it back.
	fresh, _, err := repo.UpsertSighting(sight(ws, "fp-abc", "prod-1", "default", tFresh))
	if err != nil {
		t.Fatalf("fresh sighting: %v", err)
	}
	if fresh.RuntimeStatus != models.RuntimeStatusRunning {
		t.Errorf("a newer sighting must set running again, got %q", fresh.RuntimeStatus)
	}
	if fresh.TerminatedBy != "alice@corp" {
		t.Error("terminated_by is history and must be kept after a recreate")
	}
}

// The two status axes must stay independent: deleting a claimed agent must not
// un-claim it, or the audit trail dies with the workload.
func TestDeletionDoesNotAlterGovernanceStatus(t *testing.T) {
	raw := setupSchema(t)
	seedBaseline(t, raw)
	repo := repositories.NewDiscoveryRepository(gormFor(t, raw))
	ws := uuid.MustParse(wsA)

	stored, _, err := repo.UpsertSighting(sight(ws, "fp-claimed", "prod-1", "default", time.Now()))
	if err != nil {
		t.Fatalf("sighting: %v", err)
	}

	// Claim it, which requires a client identity and an owner.
	clientID := "cccccccc-0000-0000-0000-000000000001"
	// mcp_oauth_clients scopes by home_workspace_id, not workspace_id.
	exec(t, raw,
		"INSERT INTO mcp_oauth_clients (id, client_id, hydra_client_id, client_name, home_workspace_id) "+
			"VALUES ($1,'c-1','hydra-c-1','agent',$2)",
		clientID, wsA)
	claimed, err := repo.ClaimAgent(repositories.ClaimAgentInput{
		WorkspaceID:     ws,
		AgentID:         stored.ID,
		MatchedClientID: uuid.MustParse(clientID),
		OwnerUserID:     uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001"),
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed.Status != models.DiscoveredAgentRegistered {
		t.Fatalf("status = %q, want registered", claimed.Status)
	}

	// Now the workload is deleted.
	after, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID:   ws,
		Source:        models.DiscoverySourceK8sWebhook,
		Fingerprint:   "fp-claimed",
		Event:         models.AgentEventDeleted,
		RuntimeStatus: models.RuntimeStatusGone,
		Reason:        "deleted by bob@corp",
		Actor:         "bob@corp",
		Channel:       models.DiscoveryChannelAdmission,
		ObservedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("delete event: %v", err)
	}
	if after.RuntimeStatus != models.RuntimeStatusGone {
		t.Errorf("runtime_status = %q, want gone", after.RuntimeStatus)
	}
	if after.Status != models.DiscoveredAgentRegistered {
		t.Errorf("status = %q — deleting a workload must NOT un-claim the agent; the "+
			"governance decision and its audit trail have to outlive the workload", after.Status)
	}
	if after.MatchedClientID == nil || after.OwnerUserID == nil {
		t.Error("the claim's identity and owner must survive the deletion")
	}
}

// A controller-owned pod dying asserts no runtime state, so it must leave a running
// agent running. This is the rollout false-positive, checked at the DB layer.
func TestPodTerminatedLeavesRuntimeStatusAlone(t *testing.T) {
	repo, ws := discoveryRepo(t)

	if _, _, err := repo.UpsertSighting(sight(ws, "fp-rollout", "prod-1", "default", time.Now())); err != nil {
		t.Fatalf("sighting: %v", err)
	}

	after, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID: ws,
		Source:      models.DiscoverySourceK8sWebhook,
		Fingerprint: "fp-rollout",
		Event:       models.AgentEventPodTerminated,
		// No runtime status asserted — that is the whole point.
		RuntimeStatus: "",
		Reason:        "controller-owned pod rescheduled",
		Channel:       models.DiscoveryChannelAdmission,
		ObservedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("pod_terminated event: %v", err)
	}
	if after.RuntimeStatus != models.RuntimeStatusRunning {
		t.Errorf("runtime_status = %q — a rollout must leave the agent running", after.RuntimeStatus)
	}
	if after.TerminatedAt != nil {
		t.Error("a reschedule must not stamp terminated_at")
	}
}

// An event for an unknown fingerprint is still recorded: an agent created and
// destroyed between two sweeps leaves this as the only evidence it existed.
func TestEventForUnknownFingerprintIsStillKept(t *testing.T) {
	raw := setupSchema(t)
	seedBaseline(t, raw)
	repo := repositories.NewDiscoveryRepository(gormFor(t, raw))
	ws := uuid.MustParse(wsA)

	agent, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID:   ws,
		Source:        models.DiscoverySourceK8sWebhook,
		Fingerprint:   "fp-never-seen",
		Event:         models.AgentEventDeleted,
		RuntimeStatus: models.RuntimeStatusGone,
		Reason:        "deleted by carol@corp",
		Actor:         "carol@corp",
		Channel:       models.DiscoveryChannelAdmission,
		ObservedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("event for unknown fingerprint should be accepted: %v", err)
	}
	if agent != nil {
		t.Error("no agent row should have matched")
	}

	var n int
	if err := raw.QueryRow(
		"SELECT count(*) FROM discovered_agent_events WHERE fingerprint = 'fp-never-seen'").Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n != 1 {
		t.Errorf("the event must be persisted even with no matching agent, found %d rows", n)
	}
}

// Observing an agent that had been written off is its own event kind — "the agent you
// were told was destroyed is back" is a governance signal, not routine telemetry.
func TestObservingAGoneAgentRecordsReappeared(t *testing.T) {
	raw := setupSchema(t)
	seedBaseline(t, raw)
	repo := repositories.NewDiscoveryRepository(gormFor(t, raw))
	ws := uuid.MustParse(wsA)

	t0 := time.Now().Add(-time.Hour)
	if _, _, err := repo.UpsertSighting(sight(ws, "fp-back", "prod-1", "default", t0)); err != nil {
		t.Fatalf("sighting: %v", err)
	}
	if _, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID: ws, Source: models.DiscoverySourceK8sWebhook, Fingerprint: "fp-back",
		Event: models.AgentEventDeleted, RuntimeStatus: models.RuntimeStatusGone,
		Channel: models.DiscoveryChannelAdmission, ObservedAt: t0.Add(time.Minute),
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	after, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID: ws, Source: models.DiscoverySourceK8sWebhook, Fingerprint: "fp-back",
		Event: models.AgentEventObserved, RuntimeStatus: models.RuntimeStatusRunning,
		Reason: "seen by a resync sweep", Channel: models.DiscoveryChannelResync,
		ObservedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("observed event: %v", err)
	}
	if after.RuntimeStatus != models.RuntimeStatusRunning {
		t.Errorf("runtime_status = %q, want running", after.RuntimeStatus)
	}

	var kind string
	if err := raw.QueryRow(`SELECT event FROM discovered_agent_events
	    WHERE fingerprint = 'fp-back' ORDER BY observed_at DESC LIMIT 1`).Scan(&kind); err != nil {
		t.Fatalf("read latest event: %v", err)
	}
	if kind != models.AgentEventReappeared {
		t.Errorf("latest event = %q, want %q", kind, models.AgentEventReappeared)
	}
}

// A complete sweep retires only what it can actually prove absent. Every exclusion
// here is a false retirement that would otherwise happen.
func TestMarkAbsentRetiresOnlyWhatTheSweepProves(t *testing.T) {
	repo, ws := discoveryRepo(t)

	sweepStart := time.Now()
	old := sweepStart.Add(-time.Hour)

	seed := []struct {
		fp, cluster, ns string
		seen            time.Time
	}{
		{"fp-present", "prod-1", "default", old},                          // observed by the sweep
		{"fp-stale", "prod-1", "default", old},                            // the only true absence
		{"fp-othercluster", "stage-1", "default", old},                    // different cluster
		{"fp-otherns", "prod-1", "unswept", old},                          // namespace never swept
		{"fp-midsweep", "prod-1", "default", sweepStart.Add(time.Minute)}, // created mid-sweep
	}
	for _, s := range seed {
		if _, _, err := repo.UpsertSighting(sight(ws, s.fp, s.cluster, s.ns, s.seen)); err != nil {
			t.Fatalf("seed %s: %v", s.fp, err)
		}
		// last_seen_at is set by the upsert to now(), so force it to the scenario's time.
		if err := forceLastSeen(t, repo, ws, s.fp, s.seen); err != nil {
			t.Fatalf("force last_seen_at for %s: %v", s.fp, err)
		}
	}

	gone, err := repo.MarkAbsent(repositories.MarkAbsentInput{
		WorkspaceID:    ws,
		Source:         models.DiscoverySourceK8sWebhook,
		ClusterName:    "prod-1",
		Present:        []string{"fp-present"},
		Namespaces:     []string{"default"},
		SweepStartedAt: sweepStart,
		ObservedAt:     sweepStart.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("mark absent: %v", err)
	}
	if len(gone) != 1 || gone[0] != "fp-stale" {
		t.Fatalf("expected exactly [fp-stale] to be retired, got %v", gone)
	}
}

// A sweep with no scope proves nothing, and must be refused rather than treated as
// "the whole cluster is empty".
func TestMarkAbsentRefusesAnEmptyScope(t *testing.T) {
	repo, ws := discoveryRepo(t)
	if _, err := repo.MarkAbsent(repositories.MarkAbsentInput{
		WorkspaceID: ws,
		Source:      models.DiscoverySourceK8sWebhook,
		ClusterName: "prod-1",
		ObservedAt:  time.Now(),
	}); err == nil {
		t.Fatal("a manifest naming no namespaces must be refused; otherwise an empty " +
			"scope with an empty fingerprint list would retire the entire inventory")
	}
}

// Coverage must separate the actionable queue from historical rows, or a diligent
// team watches the KPI stall with nothing left to claim.
func TestCoverageSeparatesLiveFromRetired(t *testing.T) {
	repo, ws := discoveryRepo(t)

	for _, fp := range []string{"fp-live-1", "fp-live-2", "fp-dead"} {
		if _, _, err := repo.UpsertSighting(sight(ws, fp, "prod-1", "default", time.Now())); err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
	}
	if _, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID: ws, Source: models.DiscoverySourceK8sWebhook, Fingerprint: "fp-dead",
		Event: models.AgentEventDeleted, RuntimeStatus: models.RuntimeStatusGone,
		Channel: models.DiscoveryChannelAdmission, ObservedAt: time.Now(),
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	cov, err := repo.Coverage(ws)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	if cov.Unregistered != 3 {
		t.Errorf("unregistered = %d, want 3 (all rows, including history)", cov.Unregistered)
	}
	if cov.LiveUnregistered != 2 {
		t.Errorf("live_unregistered = %d, want 2 — a destroyed agent needs no claim "+
			"decision and must not hold the KPI down", cov.LiveUnregistered)
	}
	if cov.ByRuntimeStatus[models.RuntimeStatusGone] != 1 {
		t.Errorf("by_runtime_status[gone] = %d, want 1", cov.ByRuntimeStatus[models.RuntimeStatusGone])
	}
}

// ?live=true is what the actionable Unregistered Agents report uses.
func TestListAgentsLiveOnlyExcludesRetired(t *testing.T) {
	repo, ws := discoveryRepo(t)

	for _, fp := range []string{"fp-a", "fp-b"} {
		if _, _, err := repo.UpsertSighting(sight(ws, fp, "prod-1", "default", time.Now())); err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
	}
	if _, err := repo.ApplyLifecycleEvent(&models.DiscoveredAgentEvent{
		WorkspaceID: ws, Source: models.DiscoverySourceK8sWebhook, Fingerprint: "fp-b",
		Event: models.AgentEventDeleted, RuntimeStatus: models.RuntimeStatusGone,
		Channel: models.DiscoveryChannelAdmission, ObservedAt: time.Now(),
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	all, total, err := repo.ListAgents(ws, repositories.AgentFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if total != 2 {
		t.Errorf("unfiltered total = %d, want 2", total)
	}
	// Retired agents sort last, so the reviewer's attention is not spent on them.
	if len(all) == 2 && all[len(all)-1].Fingerprint != "fp-b" {
		t.Errorf("the retired agent should sort last, got order %s,%s",
			all[0].Fingerprint, all[1].Fingerprint)
	}

	live, liveTotal, err := repo.ListAgents(ws, repositories.AgentFilter{LiveOnly: true, Limit: 50})
	if err != nil {
		t.Fatalf("list live: %v", err)
	}
	if liveTotal != 1 || len(live) != 1 || live[0].Fingerprint != "fp-a" {
		t.Errorf("live-only should return just fp-a, got total=%d rows=%d", liveTotal, len(live))
	}
}

// forceLastSeen backdates last_seen_at, which the upsert always stamps as now().
func forceLastSeen(t *testing.T, repo repositories.DiscoveryRepository,
	ws uuid.UUID, fp string, at time.Time) error {
	t.Helper()
	agent, err := repo.GetAgentByFingerprint(ws, models.DiscoverySourceK8sWebhook, fp)
	if err != nil {
		return err
	}
	_, err = repo.UpdateAgent(ws, agent.ID, map[string]interface{}{"last_seen_at": at})
	return err
}
