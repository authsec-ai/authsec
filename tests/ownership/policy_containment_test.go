// The containment arm — the half of the policy model that makes
// "desired_state: quarantined" mean something.
//
// This was the gap that made everything else advisory: a policy could say
// "quarantine this agent", the reconciler would agree it should, and then record
// a refusal. A policy that states an end state and does not reach it is a note.
//
// What this file defends:
//
//  1. A LIVE RECONCILE ACTUALLY CONTAINS, through the SAME path the console
//     button uses — so a policy-driven containment and a human-driven one produce
//     identical state, instructions and history (PG-6).
//  2. IT NEVER RELEASES. Quarantining narrows; releasing widens. A reconciler that
//     lifts containment could undo a decision a human took during an incident for
//     reasons no policy knows (PG-5).
//  3. A DRY RUN STILL CHANGES NOTHING.
//  4. IT IS IDEMPOTENT — the sweep runs every five minutes forever.
package ownership

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

func agentStatus(t *testing.T, f actFixture, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovered_agents WHERE id = $1`,
		id).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return status
}

// containPolicy attaches a policy asking for quarantine.
func containPolicy(t *testing.T, f actFixture) uuid.UUID {
	t.Helper()
	p, err := policyMgr(t, f.provFixture).Create(f.ws, claimOwner.String(),
		services.AgentPolicyInput{
			Name: "contain the research agent", DiscoveredAgentID: &f.agent,
			DesiredState: models.AgentPolicyStateQuarantined,
		})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	return p.ID
}

// THE headline property. Without this the whole policy model is advisory.
func TestPolicyQuarantineActuallyContainsTheAgent(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)
	pid := containPolicy(t, f)

	if got := agentStatus(t, f, f.agent); got == models.DiscoveredAgentQuarantined {
		t.Fatalf("setup: agent should not start quarantined, got %q", got)
	}

	res, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(res.Errors) > 0 {
		t.Fatalf("reconcile reported errors: %v", res.Errors)
	}

	if got := agentStatus(t, f, f.agent); got != models.DiscoveredAgentQuarantined {
		t.Fatalf("a policy asking for quarantine must CONTAIN the agent, got status %q. "+
			"A policy that states an end state and does not reach it is a note", got)
	}

	// The same path the console button uses, so enforcement is queued identically.
	if n := openInstructions(t, f, models.InstructionQuarantine); n != 1 {
		t.Errorf("want the NetworkPolicy quarantine queued, got %d", n)
	}
	if n := openInstructions(t, f, models.InstructionEvictPods); n != 1 {
		t.Errorf("want the eviction queued too, got %d", n)
	}

	// The reason a human reads on the agent, and a developer reads on the blocked
	// pod, must name the policy rather than saying "automated".
	var reason string
	if err := f.raw.QueryRow(`SELECT quarantine_reason FROM discovered_agents
	                           WHERE id = $1`, f.agent).Scan(&reason); err != nil {
		t.Fatalf("read reason: %v", err)
	}
	if !strings.Contains(reason, pid.String()) {
		t.Errorf("the containment reason must name the policy that caused it, got %q", reason)
	}

	var outcome string
	if err := f.raw.QueryRow(`SELECT outcome FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'quarantined' AND arm = 'cluster'
	    ORDER BY acted_at DESC LIMIT 1`, f.ws).Scan(&outcome); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if outcome != models.PolicyOutcomeApplied {
		t.Errorf("want a recorded 'applied', got %q", outcome)
	}
}

// PG-5 applied to convergence. This is the one direction where a bug would GRANT
// rather than remove.
func TestReconcileNeverReleasesAQuarantine(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)

	// A human contained it during an incident. No policy knows why.
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "incident 4471: exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// And there is a policy, but it asks for 'active'.
	if _, err := policyMgr(t, f.provFixture).Create(f.ws, claimOwner.String(),
		services.AgentPolicyInput{
			Name: "normal operation", DiscoveredAgentID: &f.agent,
			DesiredState: models.AgentPolicyStateActive,
			ScopeCeiling: []string{"read"},
		}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
		if got := agentStatus(t, f, f.agent); got != models.DiscoveredAgentQuarantined {
			t.Fatalf("sweep %d RELEASED a human's containment (status %q). Quarantining "+
				"narrows and releasing widens; a reconciler that lifts containment can "+
				"undo a decision taken for reasons no policy knows", i, got)
		}
	}

	// It is still reported, so the drift is visible — just not acted on.
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'released'`, f.ws).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n == 0 {
		t.Error("the drift must still be REPORTED; silently ignoring it would hide a " +
			"containment nothing is asking for")
	}
	var outcome string
	if err := f.raw.QueryRow(`SELECT outcome FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'released' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&outcome); err != nil {
		t.Fatalf("read: %v", err)
	}
	if outcome == models.PolicyOutcomeApplied {
		t.Error("a release must never be recorded as applied")
	}
	// And nothing was queued to lift it in the cluster.
	if n := openInstructions(t, f, models.InstructionUnquarantine); n != 0 {
		t.Errorf("%d unquarantine instruction(s) queued by a reconciler", n)
	}
}

func TestDryRunContainsNothing(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)
	containPolicy(t, f)

	res, err := policyMgr(t, f.provFixture).Reconcile(f.ws, true)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.WouldQuarantine != 1 {
		t.Errorf("a dry run must still SAY it would contain, got %d", res.WouldQuarantine)
	}
	if got := agentStatus(t, f, f.agent); got == models.DiscoveredAgentQuarantined {
		t.Fatal("a dry run contained the agent")
	}
	if n := openInstructions(t, f, models.InstructionQuarantine); n != 0 {
		t.Errorf("a dry run queued %d instruction(s)", n)
	}
}

// The sweep runs every five minutes forever. A second pass must be a no-op, not a
// second containment and not a second pile of instructions.
func TestContainmentIsIdempotentAcrossSweeps(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)
	containPolicy(t, f)

	pm := policyMgr(t, f.provFixture)
	if _, err := pm.Reconcile(f.ws, false); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	var firstAt time.Time
	if err := f.raw.QueryRow(`SELECT quarantined_at FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&firstAt); err != nil {
		t.Fatalf("read: %v", err)
	}

	for i := 0; i < 3; i++ {
		res, err := pm.Reconcile(f.ws, false)
		if err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
		if len(res.Errors) > 0 {
			t.Fatalf("sweep %d errored: %v", i, res.Errors)
		}
		if res.WouldQuarantine != 0 {
			t.Errorf("sweep %d re-contained an already-contained agent", i)
		}
	}

	var nowAt time.Time
	if err := f.raw.QueryRow(`SELECT quarantined_at FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&nowAt); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !nowAt.Equal(firstAt) {
		t.Error("a later sweep moved quarantined_at; the containment decision has one " +
			"timestamp, and re-stamping it would lose when it actually happened")
	}
	if n := openInstructions(t, f, models.InstructionQuarantine); n != 1 {
		t.Errorf("want one queued quarantine after four sweeps, got %d", n)
	}
}

// on_expiry: quarantine has to fire too — it was planning and never acting.
func TestExpiredQuarantinePolicyContains(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)

	past := time.Now().Add(-time.Hour)
	if _, err := policyMgr(t, f.provFixture).Create(f.ws, claimOwner.String(),
		services.AgentPolicyInput{
			Name: "contain when the engagement ends", DiscoveredAgentID: &f.agent,
			DesiredState: models.AgentPolicyStateActive,
			ExpiresAt:    &past, OnExpiry: models.OnExpiryQuarantine,
		}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := agentStatus(t, f, f.agent); got != models.DiscoveredAgentQuarantined {
		t.Fatalf("an expired on_expiry=quarantine policy must contain the agent, got %q", got)
	}
	var outcome, detail string
	if err := f.raw.QueryRow(`SELECT outcome, detail FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'quarantined' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&outcome, &detail); err != nil {
		t.Fatalf("read: %v", err)
	}
	if outcome != models.PolicyOutcomeApplied {
		t.Errorf("want 'applied', got %q (%s)", outcome, detail)
	}
}

// A containment nobody can enforce must not look like one that is working.
func TestContainingAnUnattributedAgentSaysNothingWillEnforceIt(t *testing.T) {
	f := newActFixture(t)
	exec(t, f.raw, `UPDATE discovered_agents SET discovery_source_id = NULL WHERE id = $1`,
		f.agent)
	containPolicy(t, f)

	if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The decision still stands — it is a governance fact, not a cluster fact.
	if got := agentStatus(t, f, f.agent); got != models.DiscoveredAgentQuarantined {
		t.Errorf("the decision must still be recorded, got %q", got)
	}
	var detail string
	if err := f.raw.QueryRow(`SELECT detail FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'quarantined' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&detail); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(detail, "not attributed") {
		t.Errorf("a quarantine nobody can enforce must say so, got %q", detail)
	}
}
