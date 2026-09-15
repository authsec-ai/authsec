// Workload deletion and the force-delete escalation — phases 7 and 8 of
// ENFORCEMENT-ARCHITECTURE.md §7, control-plane half.
//
// These are the two operations a customer cannot undo by releasing the agent, so
// the properties are about what CANNOT happen:
//
//  1. on_expiry='evict' REVOKES BEFORE IT DESTROYS. If the deletion is queued and
//     the grants are not, a workload recreated by a GitOps reconciler comes back
//     holding the access the policy was expiring — the exact opposite of expiry.
//  2. NOTHING IS QUEUED FOR A CLUSTER THAT CANNOT CARRY IT OUT, and a policy that
//     can do neither FAILS rather than recording a silent success.
//  3. FORCE-DELETE IS AN ESCALATION, not a first resort: it requires a PDB refusal
//     already on record, reported by the agent itself.
//  4. IT CANNOT BE UNATTRIBUTED. The reason and the actor are enforced by a
//     database CHECK, not by whichever code path remembered.
package ownership

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// capable turns on the cluster capabilities an agent would report.
func capable(t *testing.T, f actFixture, evict, del, force bool) {
	t.Helper()
	exec(t, f.raw, `UPDATE discovery_sources
	                   SET enforcement_evict = $2, enforcement_delete = $3,
	                       enforcement_force_evict = $4
	                 WHERE id = $1`, f.source, evict, del, force)
}

// expiredEvictPolicy attaches a confirmed evict-on-expiry policy already past due.
func expiredEvictPolicy(t *testing.T, f actFixture) uuid.UUID {
	t.Helper()
	past := time.Now().Add(-time.Hour)
	p, err := policyMgr(t, f.provFixture).Create(f.ws, claimOwner.String(),
		services.AgentPolicyInput{
			Name: "decommission", DiscoveredAgentID: &f.agent,
			DesiredState: models.AgentPolicyStateQuarantined,
			ExpiresAt:    &past, OnExpiry: models.OnExpiryEvict,
			Reason: "project closed", ConfirmedBy: &claimOwner,
			ConfirmAgentIDs: []uuid.UUID{f.agent},
		})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	return p.ID
}

func instructionsOfKind(t *testing.T, f actFixture, kind string) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM provisioning_instructions
	    WHERE workspace_id = $1 AND kind = $2`, f.ws, kind).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", kind, err)
	}
	return n
}

/* ------------------------- on_expiry: evict, live ------------------------ */

func TestExpiredEvictPolicyQueuesEvictionAndDeletion(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, false)
	expiredEvictPolicy(t, f)

	res, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(res.Errors) > 0 {
		t.Fatalf("reconcile reported errors: %v", res.Errors)
	}
	if instructionsOfKind(t, f, models.InstructionEvictPods) != 1 {
		t.Error("an expired evict policy must queue an eviction to stop the process")
	}
	if instructionsOfKind(t, f, models.InstructionDeleteWorkload) != 1 {
		t.Error("...and a deletion, or the controller reschedules what was evicted")
	}

	var outcome, detail string
	if err := f.raw.QueryRow(`SELECT outcome, detail FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'evicted' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&outcome, &detail); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if outcome != models.PolicyOutcomeApplied {
		t.Errorf("a live run must record 'applied', got %q (%s)", outcome, detail)
	}
}

// If the deletion lands and the grants do not, a GitOps reconciler brings the
// workload back holding exactly the access the policy was expiring.
func TestExpiryRevokesBeforeItDestroys(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, false)

	// A live standing grant for the agent.
	if _, err := f.pm.Provision(f.ws,
		f.provisionInput(nil, true, "needed for the nightly job")); err != nil {
		t.Fatalf("provision: %v", err)
	}
	expiredEvictPolicy(t, f)

	if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var live int
	if err := f.raw.QueryRow(`SELECT count(*) FROM entitlement_provenance
	    WHERE workspace_id = $1 AND discovered_agent_id = $2
	      AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
		f.ws, f.agent).Scan(&live); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if live != 0 {
		t.Errorf("%d grant(s) still live after a destructive expiry. A workload the "+
			"reconciler recreates would come back holding the access the policy was "+
			"expiring", live)
	}
}

// A policy that says "delete this at the deadline" and quietly does nothing is
// worse than one that fails loudly: the operator believes it was handled.
func TestExpiryFailsLoudlyWhenTheClusterCanDoNeither(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, false, false, false)
	expiredEvictPolicy(t, f)

	res, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Fatal("a destructive expiry that cannot be carried out must be reported as " +
			"an error, not silently recorded as done")
	}

	var outcome, detail string
	if err := f.raw.QueryRow(`SELECT outcome, detail FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'evicted' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&outcome, &detail); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if outcome != models.PolicyOutcomeFailed {
		t.Errorf("want a recorded failure, got %q", outcome)
	}
	if !strings.Contains(detail, "enforcement.evict") {
		t.Errorf("the failure must say what would fix it, got %q", detail)
	}
}

// Eviction alone stops the process; the controller reschedules it. Saying so is
// the difference between an operator believing the agent is gone and knowing it
// will be back.
func TestEvictOnlyClusterSaysTheWorkloadWillReturn(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, false, false)
	expiredEvictPolicy(t, f)

	if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if instructionsOfKind(t, f, models.InstructionDeleteWorkload) != 0 {
		t.Error("no deletion may be queued for a cluster that cannot delete")
	}
	var detail string
	if err := f.raw.QueryRow(`SELECT detail FROM agent_policy_actions
	    WHERE workspace_id = $1 AND action = 'evicted' ORDER BY acted_at DESC LIMIT 1`,
		f.ws).Scan(&detail); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if !strings.Contains(detail, "rescheduled") {
		t.Errorf("the outcome must say the pods come back, got %q", detail)
	}
}

// A dry run must remain a dry run even for a policy that is already past due.
func TestDryRunNeverQueuesDestruction(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, true)
	expiredEvictPolicy(t, f)

	if _, err := policyMgr(t, f.provFixture).Reconcile(f.ws, true); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n := instructionsOfKind(t, f, models.InstructionEvictPods); n != 0 {
		t.Errorf("a dry run queued %d eviction(s)", n)
	}
	if n := instructionsOfKind(t, f, models.InstructionDeleteWorkload); n != 0 {
		t.Errorf("a dry run queued %d deletion(s)", n)
	}
}

/* ------------------------ force-delete escalation ------------------------ */

// recordPDBRefusal writes the evidence an agent would report after a budget
// refused an eviction.
func recordPDBRefusal(t *testing.T, f actFixture, pods string) {
	t.Helper()
	exec(t, f.raw, `INSERT INTO provisioning_instructions
	    (workspace_id, discovery_source_id, kind, discovered_agent_id, fingerprint,
	     idempotency_key, status, applied_at, result, payload)
	  VALUES ($1,$2,'evict_pods',$3,'fp-prov-1','evict:test','applied', now(),
	          $4::jsonb, '{}'::jsonb)`,
		f.ws, f.source, f.agent,
		`{"evicted":0,"pdb_blocked":1,"pdb_blocked_pods":`+pods+`}`)
}

func TestForceEvictRequiresAPriorPDBRefusal(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, true)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	agent, err := f.dm.GetAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Nothing has been refused yet.
	if _, err := services.ForceEvict(gormFor(t, f.raw), f.ws, agent,
		services.ForceEvictInput{Actor: "alice", Reason: "compromised"}); err == nil {
		t.Fatal("force-delete with no PDB refusal on record must be refused: it is an " +
			"escalation of a blocked eviction, not a way to skip one")
	}

	recordPDBRefusal(t, f, `["research-agent-7d9fbc4d8f-x2k9"]`)
	out, err := services.ForceEvict(gormFor(t, f.raw), f.ws, agent,
		services.ForceEvictInput{Actor: "alice", Reason: "compromised"})
	if err != nil {
		t.Fatalf("after a real refusal it must be permitted: %v", err)
	}
	if len(out.BlockedPods) != 1 || out.BlockedPods[0] != "research-agent-7d9fbc4d8f-x2k9" {
		t.Errorf("the override must be bounded to the pods actually refused, got %v",
			out.BlockedPods)
	}
}

// Attribution is structural: the database refuses an unattributed override.
func TestUnattributedForceDeleteCannotBeStored(t *testing.T) {
	f := newActFixture(t)
	_, err := f.raw.Exec(`INSERT INTO provisioning_instructions
	    (workspace_id, discovery_source_id, kind, fingerprint, idempotency_key,
	     created_by, payload)
	  VALUES ($1,$2,'force_delete_pods','fp','force:1','', '{"reason":"x"}'::jsonb)`,
		f.ws, f.source)
	if err == nil {
		t.Error("a force-delete with no created_by must be rejected by the schema, not " +
			"only by the code path that happened to remember")
	}
	_, err = f.raw.Exec(`INSERT INTO provisioning_instructions
	    (workspace_id, discovery_source_id, kind, fingerprint, idempotency_key,
	     created_by, payload)
	  VALUES ($1,$2,'force_delete_pods','fp','force:2','alice', '{}'::jsonb)`,
		f.ws, f.source)
	if err == nil {
		t.Error("a force-delete with no reason must be rejected by the schema")
	}
	// And the attributed, justified one is accepted.
	if _, err := f.raw.Exec(`INSERT INTO provisioning_instructions
	    (workspace_id, discovery_source_id, kind, fingerprint, idempotency_key,
	     created_by, payload)
	  VALUES ($1,$2,'force_delete_pods','fp','force:3','alice',
	          '{"reason":"compromised"}'::jsonb)`, f.ws, f.source); err != nil {
		t.Errorf("an attributed, justified force-delete must be accepted: %v", err)
	}
}

func TestForceEvictNeedsTheClusterCapability(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, false) // force off
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	recordPDBRefusal(t, f, `["research-agent-7d9fbc4d8f-x2k9"]`)
	agent, _ := f.dm.GetAgent(f.ws, f.agent)

	_, err := services.ForceEvict(gormFor(t, f.raw), f.ws, agent,
		services.ForceEvictInput{Actor: "alice", Reason: "compromised"})
	if err == nil {
		t.Fatal("permitting workload deletion must not permit overriding a budget")
	}
	if !strings.Contains(err.Error(), "forceEvict") {
		t.Errorf("the refusal must name the switch, got %v", err)
	}
}

func TestForceEvictRefusesWithoutAnActorOrReason(t *testing.T) {
	f := newActFixture(t)
	capable(t, f, true, true, true)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	recordPDBRefusal(t, f, `["p1"]`)
	agent, _ := f.dm.GetAgent(f.ws, f.agent)
	db := gormFor(t, f.raw)

	if _, err := services.ForceEvict(db, f.ws, agent,
		services.ForceEvictInput{Reason: "compromised"}); err == nil {
		t.Error("an unattributed force-delete must be refused")
	}
	if _, err := services.ForceEvict(db, f.ws, agent,
		services.ForceEvictInput{Actor: "alice"}); err == nil {
		t.Error("a force-delete with no reason must be refused")
	}
}
