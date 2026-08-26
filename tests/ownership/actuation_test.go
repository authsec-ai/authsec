// Phase 5 tests: in-cluster actuation (control-plane half).
//
// The headline property: quarantine was a status column that NOTHING enforced. These
// prove the decision now queues real enforcement, and that the gap between "decided"
// and "enforced" is visible rather than hidden.
//
// Also tested: the token auth (only a hash is stored), the lease model (a crashed
// agent's work returns to the queue), and idempotency (a re-issued instruction
// collapses onto the queued row rather than queuing a second NetworkPolicy write).
package ownership

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// actFixture registers a connector, enables actuation on it, and attributes a
// discovered agent to it.
type actFixture struct {
	provFixture
	am     services.ActuationManager
	dm     services.DiscoveryManager
	source uuid.UUID
	token  string
}

func newActFixture(t *testing.T) actFixture {
	t.Helper()
	f := newProvFixture(t)
	db := gormFor(t, f.raw)

	dm := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	src, _, err := dm.RegisterAgent(f.ws, services.AgentRegistrationInput{
		Kind:        models.DiscoverySourceK8sWebhook,
		InstanceID:  "k8s:prod-1",
		ClusterName: "prod-1",
	})
	if err != nil {
		t.Fatalf("register connector: %v", err)
	}

	am := services.NewActuationManager(db)
	token, err := am.EnableActuation(f.ws, src.ID)
	if err != nil {
		t.Fatalf("enable actuation: %v", err)
	}

	// Attribute the agent to that cluster and give it the workload coordinate a
	// NetworkPolicy selector needs.
	exec(t, f.raw, `UPDATE discovered_agents
	                   SET discovery_source_id = $1,
	                       metadata = '{"cluster":{"name":"prod-1"},"kubernetes":{"namespace":"default",
	                                   "workload_kind":"Deployment","workload_name":"research-agent",
	                                   "labels":{"app.kubernetes.io/name":"research-agent"}}}'
	                 WHERE id = $2`, src.ID, f.agent)

	return actFixture{provFixture: f, am: am, dm: dm, source: src.ID, token: token}
}

/* ---------------------------------- auth --------------------------------- */

// Only a hash is stored, so a leaked database backup yields nothing usable.
func TestActuationTokenIsStoredOnlyAsAHash(t *testing.T) {
	f := newActFixture(t)

	var stored string
	if err := f.raw.QueryRow(`SELECT actuation_token_hash FROM discovery_sources WHERE id = $1`,
		f.source).Scan(&stored); err != nil {
		t.Fatalf("read: %v", err)
	}
	if stored == "" {
		t.Fatal("no hash stored")
	}
	if strings.Contains(stored, f.token) || stored == f.token {
		t.Error("the plaintext token must never be stored")
	}
	if len(stored) != 64 {
		t.Errorf("expected a 64-char sha256 hex, got %d chars", len(stored))
	}

	// And the token authenticates, resolving to its own connector.
	src, err := f.am.AuthenticateAgent(f.token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if src.ID != f.source {
		t.Errorf("token resolved to the wrong connector: %s", src.ID)
	}
}

func TestUnknownActuationTokenIsRejected(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.am.AuthenticateAgent("authsec_act_not-a-real-token"); err == nil {
		t.Fatal("an unknown token must be rejected")
	}
	if _, err := f.am.AuthenticateAgent(""); err == nil {
		t.Fatal("an empty token must be rejected")
	}

	// A disabled connector cannot act, even with a valid token.
	exec(t, f.raw, `UPDATE discovery_sources SET enabled = false WHERE id = $1`, f.source)
	if _, err := f.am.AuthenticateAgent(f.token); err == nil {
		t.Fatal("a disabled connector must not authenticate")
	}
}

// Re-enabling rotates: the old token stops working.
func TestReEnablingRotatesTheToken(t *testing.T) {
	f := newActFixture(t)

	newToken, err := f.am.EnableActuation(f.ws, f.source)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newToken == f.token {
		t.Fatal("rotation must mint a different token")
	}
	if _, err := f.am.AuthenticateAgent(f.token); err == nil {
		t.Error("the old token must stop working after rotation")
	}
	if _, err := f.am.AuthenticateAgent(newToken); err != nil {
		t.Errorf("the new token must work: %v", err)
	}
}

// An admin-configured connector has no agent behind it to do the actuating.
func TestActuationNeedsASelfRegisteredConnector(t *testing.T) {
	f := newActFixture(t)
	src, err := f.dm.CreateSource(f.ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceAWS, DisplayName: "manual-aws",
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	if _, err := f.am.EnableActuation(f.ws, src.ID); err == nil {
		t.Fatal("actuation on an admin-configured connector must be refused: there is " +
			"no agent in a cluster to act")
	}
}

/* ------------------------- quarantine enforcement ------------------------ */

// THE test for phase 5. Quarantining used to set a status column and nothing else.
func TestQuarantineQueuesRealEnforcement(t *testing.T) {
	f := newActFixture(t)

	agent, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration attempt", nil)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if agent.Status != models.DiscoveredAgentQuarantined {
		t.Fatalf("status = %q", agent.Status)
	}
	// The DECISION is committed but not yet ENFORCED — and that distinction is exactly
	// what an admin needs to see.
	if agent.QuarantineEnforcedAt != nil {
		t.Error("enforcement cannot be complete before the agent has applied it")
	}

	instructions, total, err := f.am.ListInstructions(f.ws, true, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 queued instruction, got %d", total)
	}
	inst := instructions[0]
	if inst.Kind != models.InstructionQuarantine {
		t.Errorf("kind = %q", inst.Kind)
	}
	if inst.DiscoverySourceID != f.source {
		t.Error("the instruction must be addressed to the cluster that reported the agent")
	}
	// The payload must carry what a NetworkPolicy selector needs.
	payload := string(inst.Payload)
	for _, want := range []string{"default", "research-agent", "app.kubernetes.io/name"} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q: %s", want, payload)
		}
	}
}

// A cluster with no actuation agent must not prevent an admin recording that an agent
// is untrusted — but the gap has to be VISIBLE, not swallowed.
func TestQuarantineStillSucceedsWithNoActuationAgent(t *testing.T) {
	f := newProvFixture(t)
	dm := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(gormFor(t, f.raw)))

	agent, err := dm.QuarantineAgent(f.ws, f.agent, "suspicious", nil)
	if err != nil {
		t.Fatalf("quarantine must succeed even with nowhere to enforce it: %v", err)
	}
	if agent.Status != models.DiscoveredAgentQuarantined {
		t.Error("the decision must stand")
	}
	if agent.QuarantineEnforcementError == "" {
		t.Error("the un-enforced gap must be recorded, or the console would imply the " +
			"agent is blocked when it is not")
	}
	if !strings.Contains(agent.QuarantineEnforcementError, "not enforced in-cluster") {
		t.Errorf("error should say enforcement did not happen, got %q",
			agent.QuarantineEnforcementError)
	}
}

// Quarantining twice must not queue two NetworkPolicy writes.
func TestQuarantineEnqueueIsIdempotent(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "first", nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "again", nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	_, total, err := f.am.ListInstructions(f.ws, true, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Errorf("expected the repeat to collapse onto the queued row, got %d instructions", total)
	}
}

// Work cannot be queued for a cluster where actuation was never enabled: it would look
// like enforcement is pending when nothing will ever pick it up.
func TestEnqueueRefusesAClusterWithoutActuation(t *testing.T) {
	f := newActFixture(t)
	exec(t, f.raw, `UPDATE discovery_sources SET actuation_token_hash = '' WHERE id = $1`, f.source)

	if _, _, err := f.am.Enqueue(f.ws, services.EnqueueInstructionInput{
		DiscoverySourceID: f.source,
		Kind:              models.InstructionVerifyUptake,
		Fingerprint:       "fp-x",
		Payload:           map[string]interface{}{"namespace": "default", "workload_name": "x"},
	}); err == nil {
		t.Fatal("queuing work for a cluster with no actuation agent must be refused")
	}
}

/* --------------------------------- leases -------------------------------- */

func TestLeaseClaimsWorkAndReportApplies(t *testing.T) {
	f := newActFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	leased, err := f.am.Lease(f.source, "agent-pod-1", 10, time.Minute)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected to lease 1 instruction, got %d", len(leased))
	}
	if leased[0].Status != models.InstructionLeased || leased[0].Attempts != 1 {
		t.Errorf("leasing should mark it leased and count the attempt: %+v", leased[0])
	}

	// A second poll sees nothing: the work is already claimed.
	again, err := f.am.Lease(f.source, "agent-pod-2", 10, time.Minute)
	if err != nil {
		t.Fatalf("second lease: %v", err)
	}
	if len(again) != 0 {
		t.Error("leased work must not be handed to a second poller")
	}

	// The agent reports success, and the outcome folds into the agent's state.
	out, err := f.am.Report(f.source, leased[0].ID, services.ReportInput{
		Success: true,
		Result:  map[string]interface{}{"network_policy": "authsec-quarantine-research-agent"},
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if out.Status != models.InstructionApplied || out.AppliedAt == nil {
		t.Errorf("expected applied with a timestamp: %+v", out)
	}

	var enforcedAt *time.Time
	if err := f.raw.QueryRow(`SELECT quarantine_enforced_at FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&enforcedAt); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if enforcedAt == nil {
		t.Error("a successful quarantine apply must mark the agent as actually enforced — " +
			"that is the difference between 'I quarantined it' and 'it is blocked'")
	}
}

// A crashed agent's work must return to the queue, not be lost.
func TestExpiredLeaseReturnsWorkToTheQueue(t *testing.T) {
	f := newActFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	leased, err := f.am.Lease(f.source, "doomed-pod", 10, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v (%d)", err, len(leased))
	}

	// The agent dies. Force the lease to have expired.
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, leased[0].ID)

	n, err := f.am.ReclaimExpiredLeases()
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 reclaimed lease, got %d", n)
	}

	// A fresh agent picks it up.
	retry, err := f.am.Lease(f.source, "replacement-pod", 10, time.Minute)
	if err != nil {
		t.Fatalf("re-lease: %v", err)
	}
	if len(retry) != 1 {
		t.Fatal("abandoned work must be re-leasable")
	}
	if retry[0].Attempts != 2 {
		t.Errorf("attempts = %d, want 2", retry[0].Attempts)
	}
}

// A failure goes back to pending for a retry, and becomes terminal once attempts are
// exhausted — an instruction that will never apply must stop consuming the queue and
// become visible instead.
func TestFailureRetriesThenBecomesTerminal(t *testing.T) {
	f := newActFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	var instID uuid.UUID
	for i := 0; i < 6; i++ {
		leased, err := f.am.Lease(f.source, "agent", 10, time.Minute)
		if err != nil {
			t.Fatalf("lease %d: %v", i, err)
		}
		if len(leased) == 0 {
			break
		}
		instID = leased[0].ID
		if _, err := f.am.Report(f.source, instID, services.ReportInput{
			Success: false, Error: "the cluster has no NetworkPolicy controller",
		}); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}

	var status, errText string
	if err := f.raw.QueryRow(`SELECT status, error FROM provisioning_instructions WHERE id = $1`,
		instID).Scan(&status, &errText); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.InstructionFailed {
		t.Errorf("status = %q; a permanently failing instruction must become terminal", status)
	}
	if errText == "" {
		t.Error("a failure must say why")
	}

	// And the agent shows quarantined-but-not-enforced, which is the dangerous state an
	// admin has to be able to see.
	var enforcedAt *time.Time
	var enfErr string
	if err := f.raw.QueryRow(`SELECT quarantine_enforced_at, quarantine_enforcement_error
	                            FROM discovered_agents WHERE id = $1`, f.agent).
		Scan(&enforcedAt, &enfErr); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if enforcedAt != nil {
		t.Error("enforcement never succeeded, so it must not be marked enforced")
	}
	if enfErr == "" {
		t.Error("the enforcement failure must be recorded on the agent")
	}
}

// An agent must not be able to report on another cluster's work.
func TestAgentCannotReportOnAnotherClustersInstruction(t *testing.T) {
	f := newActFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	leased, err := f.am.Lease(f.source, "agent", 10, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v", err)
	}

	other, _, err := f.dm.RegisterAgent(f.ws, services.AgentRegistrationInput{
		Kind: models.DiscoverySourceK8sWebhook, InstanceID: "k8s:stage-1", ClusterName: "stage-1",
	})
	if err != nil {
		t.Fatalf("register second cluster: %v", err)
	}

	if _, err := f.am.Report(other.ID, leased[0].ID, services.ReportInput{Success: true}); err == nil {
		t.Fatal("a connector must not be able to report on another cluster's instruction")
	}
}

// verify_uptake's answer lands on the agent, so a mismatch against the provisioned
// anchor is visible.
func TestVerifyUptakeRecordsTheObservedIdentity(t *testing.T) {
	f := newActFixture(t)
	agentID := f.agent
	if _, _, err := f.am.Enqueue(f.ws, services.EnqueueInstructionInput{
		DiscoverySourceID: f.source,
		Kind:              models.InstructionVerifyUptake,
		DiscoveredAgentID: &agentID,
		Fingerprint:       "fp-prov-1",
		Payload:           map[string]interface{}{"namespace": "default", "workload_name": "research-agent"},
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	leased, err := f.am.Lease(f.source, "agent", 10, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v", err)
	}
	if _, err := f.am.Report(f.source, leased[0].ID, services.ReportInput{
		Success: true,
		Result: map[string]interface{}{
			"found":           true,
			"service_account": "default", // NOT the provisioned anchor
		},
	}); err != nil {
		t.Fatalf("report: %v", err)
	}

	var observed string
	var verifiedAt *time.Time
	if err := f.raw.QueryRow(`SELECT observed_service_account, identity_verified_at
	                            FROM discovered_agents WHERE id = $1`, f.agent).
		Scan(&observed, &verifiedAt); err != nil {
		t.Fatalf("read: %v", err)
	}
	if observed != "default" {
		t.Errorf("observed_service_account = %q; the ACTUAL identity must be recorded so a "+
			"mismatch against the provisioned anchor is visible", observed)
	}
	if verifiedAt == nil {
		t.Error("identity_verified_at must be stamped")
	}
}
