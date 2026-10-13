package integration

// Cross-workspace isolation of the discovery, actuation and ingest-token
// statements that filter by workspace (AS-108, group F): workspace B's calls
// naming workspace A's source, agent or token change and reveal nothing of A.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// sightingIn reports one sighting into ws (ingest auth off) and returns the
// agent's id and fingerprint.
func (l *ingestLab) sightingIn(ws, src uuid.UUID) (uuid.UUID, string) {
	l.t.Helper()
	fp := "iso-fp-" + uuid.NewString()[:8]
	code, body := l.post("/sightings", "", map[string]any{
		"workspace_id": ws.String(), "source": "k8s_webhook", "discovery_source_id": src.String(),
		"fingerprint": fp, "display_name": "iso agent"})
	if !is2xx(code) {
		l.t.Fatalf("sighting: %d %v", code, body)
	}
	agent, _ := body["agent"].(map[string]any)
	id, err := uuid.Parse(agent["id"].(string))
	if err != nil {
		l.t.Fatalf("sighting agent id: %v %v", err, body)
	}
	return id, fp
}

func TestP3DiscoveryClusterUIDConflictIsCrossWorkspaceSafe(t *testing.T) {
	l := newIngestLab(t)
	if err := l.db.Exec(`UPDATE discovery_sources SET cluster_uid = 'uid-a', last_status = 'ok', last_error = ''
		WHERE workspace_id = ? AND id = ?`, l.wsA, l.srcA1).Error; err != nil {
		t.Fatal(err)
	}
	status := func() string {
		var s string
		l.db.Table("discovery_sources").Select("last_status").
			Where("workspace_id = ? AND id = ?", l.wsA, l.srcA1).Scan(&s)
		return s
	}
	// Workspace B naming A's source: nothing changes, mismatch or missing.
	for _, uid := range []string{"uid-x", ""} {
		if err := repositories.RecordClusterUIDConflict(l.db, l.wsB, l.srcA1, uid, "iso test"); err != nil {
			t.Fatalf("record (B, %q): %v", uid, err)
		}
		if got := status(); got != "ok" {
			t.Fatalf("B recorded a conflict (%q) on A's source: last_status %q", uid, got)
		}
	}
	// The workspace's own call records it.
	if err := repositories.RecordClusterUIDConflict(l.db, l.wsA, l.srcA1, "uid-x", "iso test"); err != nil {
		t.Fatal(err)
	}
	if got := status(); got != repositories.ClusterUIDConflictStatus {
		t.Fatalf("A's own conflict not recorded: last_status %q", got)
	}
}

func TestP3DiscoveryPresentRuntimeIsCrossWorkspaceSafe(t *testing.T) {
	l := newIngestLab(t)
	agentA, fp := l.sightingIn(l.wsA, l.srcA1)
	if err := l.db.Exec(`UPDATE discovered_agents
		SET metadata = '{"cluster":{"name":"iso-cluster"}}'::jsonb, runtime_status = 'running'
		WHERE workspace_id = ? AND id = ?`, l.wsA, agentA).Error; err != nil {
		t.Fatal(err)
	}
	repo := repositories.NewDiscoveryRepository(l.db)
	in := repositories.PresentRuntimeInput{WorkspaceID: l.wsB, Source: "k8s_webhook",
		ClusterName: "iso-cluster", Stopped: []string{fp}}
	stopped, _, err := repo.ApplyPresentRuntime(in)
	if err != nil {
		t.Fatal(err)
	}
	runtime := func() string {
		var s string
		l.db.Table("discovered_agents").Select("runtime_status").Where("id = ?", agentA).Scan(&s)
		return s
	}
	if len(stopped) != 0 || runtime() != models.RuntimeStatusRunning {
		t.Fatalf("B's manifest stopped A's agent: %v, runtime %q", stopped, runtime())
	}
	in.WorkspaceID = l.wsA
	if stopped, _, err = repo.ApplyPresentRuntime(in); err != nil || len(stopped) != 1 ||
		runtime() != models.RuntimeStatusStopped {
		t.Fatalf("A's own manifest: %v %v, runtime %q", stopped, err, runtime())
	}

	// A quarantine decided in B cannot name A's agent.
	mgr := services.NewDiscoveryManager(repo)
	if _, err := mgr.QuarantineAgent(l.wsB, agentA, "iso test", nil); err == nil {
		t.Fatal("B quarantined A's agent")
	}
}

// An instruction of workspace B whose agent reference points at A's agent
// (the foreign key is by id only) must not let B's report touch A's agent.
func TestP3ActuationReportCannotTouchAnotherWorkspacesAgent(t *testing.T) {
	l := newIngestLab(t)
	agentA, fp := l.sightingIn(l.wsA, l.srcA1)
	inst := uuid.New()
	if err := l.db.Exec(`INSERT INTO provisioning_instructions
		(id, workspace_id, discovery_source_id, kind, discovered_agent_id, fingerprint, idempotency_key,
		 status, attempts, lease_expires_at, leased_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'leased', 1, now() + interval '1 hour', 'iso-pod')`,
		inst, l.wsB, l.srcB1, models.InstructionQuarantine, agentA, fp, "iso-"+inst.String()).Error; err != nil {
		t.Fatal(err)
	}
	out, err := services.NewActuationManager(l.db).Report(l.srcB1, inst,
		services.ReportInput{Success: true, LeasedBy: "iso-pod"})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if out.WorkspaceID != l.wsB || out.Status != models.InstructionApplied {
		t.Fatalf("instruction after report: %+v", out)
	}
	var enforced int64
	l.db.Table("discovered_agents").Where("id = ? AND quarantine_enforced_at IS NOT NULL", agentA).Count(&enforced)
	if enforced != 0 {
		t.Fatal("B's instruction report marked A's agent quarantine-enforced")
	}

	// A's connector cannot report on B's instruction either.
	if _, err := services.NewActuationManager(l.db).Report(l.srcA1, inst,
		services.ReportInput{Success: true, LeasedBy: "iso-pod"}); err == nil {
		t.Fatal("A's connector reported on B's instruction")
	}
}

func TestP3IngestTokensAreCrossWorkspaceSafe(t *testing.T) {
	l := newIngestLab(t)
	tokA, idA := l.mint(l.wsA, nil)
	tokB, idB := l.mint(l.wsB, nil)

	if _, _, err := l.tokens.Mint(l.wsB, &l.srcA1, "x", "iso", nil); !errors.Is(err, repositories.ErrIngestTokenSourceNotFound) {
		t.Errorf("B minting a token bound to A's source: %v, want source not found", err)
	}
	if _, err := l.tokens.Revoke(l.wsB, idA); !errors.Is(err, repositories.ErrIngestTokenNotFound) {
		t.Errorf("B revoking A's token: %v, want not found", err)
	}
	list, err := l.tokens.List(l.wsB)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range list {
		if tok.WorkspaceID != l.wsB || tok.ID == idA {
			t.Errorf("B's list holds %s of workspace %s", tok.ID, tok.WorkspaceID)
		}
	}
	// A's token still works, and its use touches only its own row.
	d, err := l.tokens.Authorize(services.IngestAuthEnforce, tokA, l.wsA, func() (*uuid.UUID, error) { return nil, nil })
	if err != nil || d.Outcome != services.IngestAccept {
		t.Fatalf("A's token after B's revoke: %+v %v", d, err)
	}
	var touched, untouched int64
	l.db.Table("discovery_ingest_tokens").Where("id = ? AND last_used_at IS NOT NULL", idA).Count(&touched)
	l.db.Table("discovery_ingest_tokens").Where("id = ? AND last_used_at IS NULL", idB).Count(&untouched)
	if touched != 1 || untouched != 1 {
		t.Errorf("last_used_at: A touched %d, B untouched %d; want 1 and 1", touched, untouched)
	}
	// A's token is refused for B's workspace (403 at the ingress).
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	if code, _ := l.post("/sightings", tokA, ingestRoutes[1].body(l.wsB, nil, "")); code != http.StatusForbidden {
		t.Errorf("A's token on B's workspace: %d, want 403", code)
	}
	_ = tokB
}
