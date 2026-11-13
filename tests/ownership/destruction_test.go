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

	"github.com/authsec-ai/authsec/services"
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
