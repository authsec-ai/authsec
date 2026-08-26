// Releasing a quarantine — the other half of a loop that only went one way.
//
// Quarantine was one-way through the API. Every piece of the release path existed
// except the entry point: the cluster agent implements the `unquarantine` instruction,
// models.InstructionUnquarantine is defined, and EnforceQuarantine takes a `release`
// flag — but the only call site passed release=false and no route reached it. Once an
// agent was quarantined its deny NetworkPolicy stayed until somebody ran
// `kubectl delete networkpolicy` by hand.
//
// Two bugs are pinned here. The missing route, and a subtler one found while fixing
// it: both kinds shared the idempotency key "quarantine:<fingerprint>", and Enqueue
// resolves a key conflict with DoNothing — so a release queued before the cluster
// agent next polled collapsed onto the still-pending quarantine and was SILENTLY
// DROPPED. The stale quarantine then applied, and the console showed a released agent
// that was still blocked.
package ownership

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

/* ------------------------- the release, end to end ----------------------- */

func TestReleaseQueuesTheUnquarantineInstruction(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration attempt", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Drain it, so the release is not merely superseding a pending row.
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET status = 'applied', applied_at = now() WHERE status = 'pending'`)

	agent, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if agent.Status == models.DiscoveredAgentQuarantined {
		t.Error("a released agent must not still read as quarantined")
	}
	if agent.QuarantineReleasedAt == nil {
		t.Error("quarantine_released_at must be stamped: it is what separates a live " +
			"quarantine from a historical one")
	}

	open, total, err := f.am.ListInstructions(f.ws, true, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 open instruction (the release), got %d", total)
	}
	if open[0].Kind != models.InstructionUnquarantine {
		t.Errorf("kind = %q, want %q — without this the deny policy is never removed",
			open[0].Kind, models.InstructionUnquarantine)
	}
	// It must carry the workload coordinate, or the agent cannot name the policy to
	// delete.
	if len(open[0].Payload) == 0 || string(open[0].Payload) == "{}" {
		t.Error("the release carries no workload coordinate, so the agent cannot " +
			"identify which NetworkPolicy to remove")
	}
}

// The quarantine RECORD survives the release. Erasing quarantined_at/by/reason would
// destroy exactly the history a reviewer needs — "was this agent ever contained, and
// why" outlives "is it contained now".
func TestReleaseKeepsTheQuarantineHistory(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "suspicious egress", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	agent, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil)
	if err != nil {
		t.Fatalf("release: %v", err)
	}

	if agent.QuarantinedAt == nil {
		t.Error("quarantined_at was cleared: the record that this agent WAS quarantined " +
			"is audit evidence, not current state")
	}
	if agent.QuarantineReason != "suspicious egress" {
		t.Errorf("quarantine_reason = %q, want it preserved", agent.QuarantineReason)
	}
	// Enforcement state, by contrast, describes what is true NOW — a stale "not
	// enforced" error on a released agent would read as a live enforcement failure.
	if agent.QuarantineEnforcedAt != nil {
		t.Error("quarantine_enforced_at must be cleared on release")
	}
}

/* --------------------------- the status it returns to -------------------- */

// A claimed agent goes back to 'registered'; one that was never claimed to
// 'unregistered'. The previous status is derived, not stored.
func TestReleaseRestoresTheStatusHeldBeforeQuarantine(t *testing.T) {
	f := newActFixture(t)

	// f.agent is claimed by the provisioning fixture, so it must come back registered.
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "r", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	agent, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if agent.Status != models.DiscoveredAgentRegistered {
		t.Errorf("a claimed agent must return to %q, got %q",
			models.DiscoveredAgentRegistered, agent.Status)
	}
}

// THE TRAP. matched_client_id and owner_user_id are both ON DELETE SET NULL, so
// deleting the owning user or the OAuth client leaves claimed_at set with the ids
// gone. discovered_agents_registered_chk requires a 'registered' agent to have BOTH.
//
// Deriving the restored status from claimed_at would therefore try to write
// 'registered' without an owner, hit the constraint, and fail — leaving the agent
// stuck quarantined with NO WAY OUT, in exactly the situation where releasing it
// matters most: the owner has left.
//
// So the predicate matches the constraint instead, and such an agent returns
// 'unregistered' — which is also the honest answer, since it has no accountable owner
// and needs a fresh claim decision.
func TestReleaseSurvivesAnOwnerDeletedWhileQuarantined(t *testing.T) {
	f := newActFixture(t)

	// The shared fixture sets matched_client_id/owner_user_id directly without going
	// through ClaimAgent, so claimed_at is null. Set it, because claimed_at surviving
	// the release is part of what this test asserts.
	exec(t, f.raw, `UPDATE discovered_agents SET claimed_at = now() WHERE id = $1`, f.agent)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "owner left", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Exactly what the ON DELETE SET NULL cascades leave behind.
	exec(t, f.raw, `UPDATE discovered_agents
	                   SET matched_client_id = NULL, owner_user_id = NULL
	                 WHERE id = $1`, f.agent)

	agent, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil)
	if err != nil {
		t.Fatalf("release must not fail when the owner is gone — this is the case that "+
			"most needs it: %v", err)
	}
	if agent.Status != models.DiscoveredAgentUnregistered {
		t.Errorf("an agent with no owner must return to %q, got %q",
			models.DiscoveredAgentUnregistered, agent.Status)
	}
	// claimed_at survives, so the history that it was once claimed is not lost.
	if agent.ClaimedAt == nil {
		t.Error("claimed_at must survive: it records that this agent was once managed")
	}
}

/* ------------------------------- the race -------------------------------- */

// Guarded in the WHERE clause, as ClaimAgent is. Two admins racing to release the
// same agent cannot both succeed, so a duplicate release instruction is never queued.
func TestReleasingTwiceIsRefused(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "r", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err == nil {
		t.Fatal("releasing an agent that is not quarantined must fail, not queue a " +
			"second instruction")
	}
}

func TestReleasingANonQuarantinedAgentIsRefused(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err == nil {
		t.Fatal("an agent that was never quarantined has nothing to release")
	}
}

/* ---------------------- the silently-dropped release --------------------- */

// THE SECOND BUG. Quarantine, then release before the cluster agent polls.
//
// With both kinds sharing one idempotency key and Enqueue doing DoNothing on
// conflict, the release collapsed onto the pending quarantine and vanished — the OLDER
// decision won. The agent then applied the quarantine it had already been told to
// undo, and stayed blocked while the console showed it released.
func TestReleaseBeforeTheAgentPollsSupersedesTheQuarantine(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Deliberately do NOT drain it: the quarantine is still pending, as it would be if
	// the cluster agent had not polled yet.
	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}

	open, total, err := f.am.ListInstructions(f.ws, true, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected exactly 1 OPEN instruction after quarantine-then-release, "+
			"got %d — a quarantine and its release must never both be open", total)
	}
	if open[0].Kind != models.InstructionUnquarantine {
		t.Fatalf("the open instruction is %q, want %q. The NEWEST decision must win; "+
			"applying the superseded quarantine would leave the agent blocked while "+
			"the console showed it released", open[0].Kind, models.InstructionUnquarantine)
	}

	// The overtaken quarantine is retired VISIBLY, not deleted — an operator asking why
	// enforcement did or did not happen needs to see it was overtaken, not find a gap.
	var superseded int
	if err := f.raw.QueryRow(`SELECT count(*) FROM provisioning_instructions
	                           WHERE kind = 'quarantine' AND status = 'superseded'`).
		Scan(&superseded); err != nil {
		t.Fatalf("count superseded: %v", err)
	}
	if superseded != 1 {
		t.Errorf("expected the overtaken quarantine to be marked superseded, found %d",
			superseded)
	}
}

// The mirror case: release, then re-quarantine before the agent polls. The newest
// decision must win in that direction too.
func TestRequarantineBeforeTheAgentPollsSupersedesTheRelease(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "first", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET status = 'applied', applied_at = now() WHERE status = 'pending'`)
	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "changed my mind", nil); err != nil {
		t.Fatalf("re-quarantine: %v", err)
	}

	open, total, err := f.am.ListInstructions(f.ws, true, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 open instruction, got %d", total)
	}
	if open[0].Kind != models.InstructionQuarantine {
		t.Errorf("kind = %q, want %q — a release left open would lift a deny the admin "+
			"has just reinstated, failing OPEN", open[0].Kind, models.InstructionQuarantine)
	}
}

// A leased instruction is NOT superseded: the cluster agent already holds it and will
// report against it by id, so rewriting it underneath would record an outcome for an
// action nobody asked for. Safe to leave, because both kinds are idempotent
// assertions on the same NetworkPolicy — the leased one may land first, then the newer
// instruction lands after it and the cluster converges on the newer decision.
func TestALeasedInstructionIsNotSuperseded(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// The agent leases it.
	leased, err := f.am.Lease(f.source, "pod-a", 10, time.Minute)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(leased) != 1 {
		t.Fatalf("expected to lease 1 instruction, got %d", len(leased))
	}

	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}

	var status string
	if err := f.raw.QueryRow(`SELECT status FROM provisioning_instructions WHERE id = $1`,
		leased[0].ID).Scan(&status); err != nil {
		t.Fatalf("read leased: %v", err)
	}
	if status != models.InstructionLeased {
		t.Errorf("a leased instruction must stay leased, got %q: the agent is already "+
			"applying it and will report against this id", status)
	}
	// And the release is queued alongside it, so the cluster still converges.
	var releases int
	if err := f.raw.QueryRow(`SELECT count(*) FROM provisioning_instructions
	                           WHERE kind = 'unquarantine' AND status = 'pending'`).
		Scan(&releases); err != nil {
		t.Fatalf("count: %v", err)
	}
	if releases != 1 {
		t.Errorf("the release must still be queued behind the leased quarantine, found %d",
			releases)
	}
}

/* ------------------------- degradation, not failure ---------------------- */

// A release must commit even when nothing can enforce it. The failure direction is
// the opposite of a quarantine's and that is what makes it safe: an unenforceable
// quarantine fails OPEN (the agent keeps running), an unenforceable release fails
// CLOSED (the agent stays blocked) — inconvenient, not dangerous. So the decision
// stands and the leftover policy is reported.
func TestReleaseSucceedsWithNoActuationAgent(t *testing.T) {
	f := newProvFixture(t)
	dm := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(gormFor(t, f.raw)))

	if _, err := dm.QuarantineAgent(f.ws, f.agent, "suspicious", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	agent, err := dm.ReleaseQuarantine(f.ws, f.agent, nil)
	if err != nil {
		t.Fatalf("a release must not be blocked by a cluster that cannot enforce it: %v", err)
	}
	if agent.Status == models.DiscoveredAgentQuarantined {
		t.Error("the release must commit even when it cannot be enforced")
	}
	// And the operator is told the policy is still there, with how to remove it.
	if agent.QuarantineEnforcementError == "" {
		t.Error("an unenforced release must say so — otherwise a still-blocked agent " +
			"looks released")
	}
}

// Releasing an agent in another workspace must not work, however valid the ids.
func TestReleaseIsWorkspaceScoped(t *testing.T) {
	f := newActFixture(t)

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "r", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := f.dm.ReleaseQuarantine(uuid.New(), f.agent, nil); err == nil {
		t.Fatal("a release from a foreign workspace must be refused")
	}

	// Still quarantined, and nothing queued.
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&status); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.DiscoveredAgentQuarantined {
		t.Errorf("status = %q, want the quarantine intact", status)
	}
}
