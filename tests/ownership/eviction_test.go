// Eviction — phase 5 of ENFORCEMENT-ARCHITECTURE.md §7, control-plane half.
//
// Quarantine writes a NetworkPolicy and leaves the process running. Eviction is the
// half that stops it. What this file defends:
//
//  1. EVICTION IS A SEPARATE SWITCH (EN-5), and it is one the CLUSTER reports, not
//     one the control plane pushes. Queuing an eviction for a cluster that cannot
//     carry one out would fill the console with enforcement errors that are really
//     a configuration choice.
//  2. A RELEASE DOES NOT EVICT. There is nothing to un-evict, and queuing one on
//     release would stop a workload at the moment somebody decided to let it run.
//  3. RE-QUARANTINING AFTER A RELEASE EVICTS AGAIN. Sharing an idempotency key with
//     the first quarantine would collapse the second onto a row already applied,
//     and the agent would never be told to stop the pods the second time.
package ownership

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// openInstructions counts queued instructions of one kind for the fixture's agent.
func openInstructions(t *testing.T, f actFixture, kind string) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM provisioning_instructions
	    WHERE workspace_id = $1 AND kind = $2 AND status IN ('pending','leased')`,
		f.ws, kind).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", kind, err)
	}
	return n
}

// enableEviction marks the connector as able to evict, which is what the agent
// reports on its plan poll.
func enableEviction(t *testing.T, f actFixture) {
	t.Helper()
	exec(t, f.raw, `UPDATE discovery_sources SET enforcement_evict = true WHERE id = $1`, f.source)
}

func TestQuarantineQueuesAnEvictionWhenTheClusterCanEvict(t *testing.T) {
	f := newActFixture(t)
	enableEviction(t, f)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "suspicious egress", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	if got := openInstructions(t, f, models.InstructionQuarantine); got != 1 {
		t.Errorf("want the NetworkPolicy quarantine queued, got %d", got)
	}
	if got := openInstructions(t, f, models.InstructionEvictPods); got != 1 {
		t.Fatalf("want an eviction queued alongside it, got %d — without it the agent "+
			"keeps running with its network cut, which is not what an operator means "+
			"by quarantine", got)
	}

	// The payload has to carry the workload coordinate, or the agent cannot find
	// the pods to evict.
	var ns, kind, name string
	if err := f.raw.QueryRow(`SELECT payload->>'namespace', payload->>'workload_kind',
	                                 payload->>'workload_name'
	                            FROM provisioning_instructions
	                           WHERE workspace_id = $1 AND kind = $2 LIMIT 1`,
		f.ws, models.InstructionEvictPods).Scan(&ns, &kind, &name); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if ns != "default" || kind != "Deployment" || name != "research-agent" {
		t.Errorf("eviction payload names the wrong workload: %s %s/%s", ns, kind, name)
	}
}

// EN-5: the switch is reported by the cluster, not pushed to it.
func TestNoEvictionIsQueuedForAClusterThatCannotEvict(t *testing.T) {
	f := newActFixture(t)
	// enforcement_evict defaults to false — the agent has not enabled it.

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	if got := openInstructions(t, f, models.InstructionQuarantine); got != 1 {
		t.Errorf("the NetworkPolicy quarantine must still be queued, got %d", got)
	}
	if got := openInstructions(t, f, models.InstructionEvictPods); got != 0 {
		t.Errorf("queuing an eviction for a cluster that cannot carry one out fills the "+
			"console with enforcement errors that are really a configuration choice; got %d", got)
	}
}

// There is nothing to un-evict, and queuing one on release would stop a workload at
// the exact moment somebody decided to let it run.
func TestReleaseDoesNotQueueAnEviction(t *testing.T) {
	f := newActFixture(t)
	enableEviction(t, f)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Drain what the quarantine queued so the release starts from a clean slate.
	// applied_at as well as status: a terminal instruction that does not say when
	// it finished cannot be reasoned about later, and the schema enforces that.
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET status = 'applied', applied_at = now()
	                 WHERE workspace_id = $1`, f.ws)

	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := openInstructions(t, f, models.InstructionEvictPods); got != 0 {
		t.Errorf("a release must not evict; got %d queued", got)
	}
	if got := openInstructions(t, f, models.InstructionUnquarantine); got != 1 {
		t.Errorf("the release itself must be queued, got %d", got)
	}
}

// The idempotency key includes WHICH quarantine this is. Keyed on the fingerprint
// alone, the second containment would collapse onto the first — already applied —
// and the agent would never be told to stop the pods again.
func TestRequarantineEvictsAgain(t *testing.T) {
	f := newActFixture(t)
	enableEviction(t, f)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "first", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// applied_at as well as status: a terminal instruction that does not say when
	// it finished cannot be reasoned about later, and the schema enforces that.
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET status = 'applied', applied_at = now()
	                 WHERE workspace_id = $1`, f.ws)
	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	// applied_at as well as status: a terminal instruction that does not say when
	// it finished cannot be reasoned about later, and the schema enforces that.
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET status = 'applied', applied_at = now()
	                 WHERE workspace_id = $1`, f.ws)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "second", nil); err != nil {
		t.Fatalf("re-quarantine: %v", err)
	}
	if got := openInstructions(t, f, models.InstructionEvictPods); got != 1 {
		t.Fatalf("a second containment must evict again, got %d open evictions. Sharing "+
			"an idempotency key with the first would silently drop it", got)
	}

	// Two distinct rows overall, so the history shows both containments.
	var total int
	if err := f.raw.QueryRow(`SELECT count(*) FROM provisioning_instructions
	    WHERE workspace_id = $1 AND kind = $2`, f.ws, models.InstructionEvictPods).
		Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Errorf("want two eviction rows across two containments, got %d", total)
	}
}

// The kind has to be accepted by the schema and by the agent-facing lease.
func TestEvictionIsALeasableInstruction(t *testing.T) {
	f := newActFixture(t)
	enableEviction(t, f)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	items, err := f.am.Lease(f.source, "agent-1", 10, 2*60*1000000000)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	var sawEvict bool
	for i := range items {
		if items[i].Kind == models.InstructionEvictPods {
			sawEvict = true
		}
	}
	if !sawEvict {
		t.Errorf("the agent must be able to lease an eviction; leased %d instruction(s)",
			len(items))
	}
}

// A leaked actuation token must not reach another cluster's evictions.
func TestEvictionIsScopedToItsConnector(t *testing.T) {
	f := newActFixture(t)
	enableEviction(t, f)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	other, _, err := f.dm.RegisterAgent(f.ws, services.AgentRegistrationInput{
		Kind:        models.DiscoverySourceK8sWebhook,
		InstanceID:  "k8s:other",
		ClusterName: "other",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	items, err := f.am.Lease(other.ID, "agent-2", 10, 2*60*1000000000)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("another cluster leased %d of our instructions", len(items))
	}
}
