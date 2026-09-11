// Agent policies — phase 1 of ENFORCEMENT-ARCHITECTURE.md §7.
//
// The declarative layer above enforcement: an operator attaches a policy to a claimed
// agent, or to a selector matching many, and a reconciler works toward it. This build
// is DRY-RUN ONLY, so these tests pin the decisions rather than any cluster effect.
//
// The properties worth defending, in order of how badly getting them wrong would hurt:
//
//  1. A destructive expiry cannot exist without a reason and a confirmation, and the
//     confirmation binds to a concrete EXPANSION — so an agent that starts matching a
//     selector later is not deleted under an older authorization.
//  2. Overlapping policies resolve most-restrictively, so a policy bug fails toward
//     LESS access and never widens anything.
//  3. on_expiry is NOT resolved that way — "more restrictive" would mean "more
//     destructive", which is backwards.
//  4. A live reconcile is refused outright.
package ownership

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

func policyMgr(t *testing.T, f provFixture) services.AgentPolicyManager {
	t.Helper()
	return services.NewAgentPolicyManager(gormFor(t, f.raw))
}

// claimedAgent seeds a managed agent with the sighting metadata selectors match on.
func claimedAgent(t *testing.T, f provFixture, name, ns, framework, origin string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status,
	     deployment_origin, matched_client_id, owner_user_id, runtime_status, metadata)
	  VALUES ($1,$2,'k8s_webhook',$3,$4::text,'registered',$5,$6,$7,'running',
	    jsonb_build_object(
	      'cluster',    jsonb_build_object('name','k3s-master'),
	      'kubernetes', jsonb_build_object('namespace',$8::text,
	                      'labels', jsonb_build_object('app.kubernetes.io/name',$4::text)),
	      'detection',  jsonb_build_object('frameworks', jsonb_build_array($9::text))))`,
		id, f.ws, "fp-"+id.String()[:8], name, origin, f.client, claimOwner, ns, framework)
	return id
}

/* --------------------------- authoring guardrails ------------------------ */

func TestPolicyNeedsExactlyOneTarget(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{Name: "neither"}); err == nil {
		t.Error("a policy with no target must be refused — it would look active and apply to nothing")
	}
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "both", DiscoveredAgentID: &agent,
		Selector: &models.AgentPolicySelector{Namespace: "iga-demo"},
	}); err == nil {
		t.Error("a policy with both a target and a selector must be refused as ambiguous")
	}
}

// An empty selector would match the entire workspace. Refusing is the only safe
// reading of it.
func TestEmptySelectorIsRefused(t *testing.T) {
	f := newProvFixture(t)
	if _, err := policyMgr(t, f).Create(f.ws, "u", services.AgentPolicyInput{
		Name: "everything", Selector: &models.AgentPolicySelector{},
	}); err == nil {
		t.Fatal("an empty selector must be refused, not treated as every agent")
	}
}

func TestDestructiveExpiryNeedsReasonAndConfirmation(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	who := claimOwner
	soon := time.Now().Add(time.Hour)

	// No reason.
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "no-reason", DiscoveredAgentID: &agent,
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon, ConfirmedBy: &who,
	}); err == nil {
		t.Error("destructive expiry with no reason must be refused: it executes unattended, " +
			"so the reason is the only explanation anyone will have")
	}
	// No confirmer.
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "no-confirm", DiscoveredAgentID: &agent,
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon, Reason: "trial",
	}); err == nil {
		t.Error("destructive expiry with no attributable confirmation must be refused")
	}
	// Both present — accepted, and the confirmation is recorded.
	p, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "ok", DiscoveredAgentID: &agent,
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon,
		Reason: "30-day PoC", ConfirmedBy: &who,
	})
	if err != nil {
		t.Fatalf("a justified, confirmed destructive policy must be accepted: %v", err)
	}
	if !p.Destructive || p.ConfirmedAt == nil {
		t.Errorf("expected destructive + confirmed, got destructive=%v confirmedAt=%v",
			p.Destructive, p.ConfirmedAt)
	}
	if f.count(t, `SELECT count(*) FROM agent_policy_confirmations WHERE policy_id = $1`, p.ID) != 1 {
		t.Error("a destructive policy must never exist without the confirmation that authorizes it")
	}
}

// A destructive SELECTOR policy must confirm against the expansion, not the selector.
func TestDestructiveSelectorPolicyMustConfirmTheExpansion(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	a1 := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	who := claimOwner
	soon := time.Now().Add(time.Hour)

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "broad-evict", Selector: &models.AgentPolicySelector{Namespace: "iga-demo"},
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon,
		Reason: "cleanup", ConfirmedBy: &who,
	}); err == nil {
		t.Fatal("a destructive selector policy with no confirmed expansion must be refused: " +
			"one confirmation must not authorize deleting workloads nobody enumerated")
	}

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "broad-evict-ok", Selector: &models.AgentPolicySelector{Namespace: "iga-demo"},
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon,
		Reason: "cleanup", ConfirmedBy: &who, ConfirmAgentIDs: []uuid.UUID{a1},
	}); err != nil {
		t.Fatalf("confirming against a named expansion must be accepted: %v", err)
	}
}

// A non-revoke expiry with no clock can never fire. Accepting it would store a
// policy that silently does nothing.
func TestExpiryActionNeedsAClock(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "no-clock", DiscoveredAgentID: &agent, OnExpiry: models.OnExpiryQuarantine,
	}); err == nil {
		t.Fatal("a non-revoke on_expiry with no duration or expires_at must be refused")
	}
}

func TestTwoClocksAreRefused(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	soon := time.Now().Add(time.Hour)
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "two-clocks", DiscoveredAgentID: &agent, Duration: "24h", ExpiresAt: &soon,
	}); err == nil {
		t.Fatal("duration AND expires_at must be refused — which one wins would depend on order")
	}
}

/* -------------------------------- expansion ------------------------------ */

func TestSelectorExpansion(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	inNS := claimedAgent(t, f, "in-ns", "iga-demo", "crewai", "automated")
	claimedAgent(t, f, "other-ns", "default", "crewai", "automated")
	claimedAgent(t, f, "other-fw", "iga-demo", "langgraph", "manual")

	cases := []struct {
		name string
		sel  models.AgentPolicySelector
		want int
	}{
		{"namespace", models.AgentPolicySelector{Namespace: "iga-demo"}, 2},
		{"namespace+framework", models.AgentPolicySelector{Namespace: "iga-demo", Framework: "crewai"}, 1},
		{"cluster", models.AgentPolicySelector{Cluster: "k3s-master"}, 3},
		{"deployment_origin", models.AgentPolicySelector{DeploymentOrigin: "manual"}, 1},
		{"labels", models.AgentPolicySelector{Labels: map[string]string{"app.kubernetes.io/name": "in-ns"}}, 1},
		{"no match", models.AgentPolicySelector{Namespace: "nope"}, 0},
	}
	for _, tc := range cases {
		p := &models.AgentPolicy{WorkspaceID: f.ws, Selector: mustJSON(t, tc.sel)}
		got, err := m.Expand(f.ws, p)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: matched %d agents, want %d", tc.name, len(got), tc.want)
		}
	}
	_ = inNS
}

// An unclaimed sighting has no owner and no entitlements, so a policy has nothing to
// narrow or revoke on it.
func TestExpansionSkipsUnmanagedAgents(t *testing.T) {
	f := newProvFixture(t)
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status, runtime_status, metadata)
	  VALUES (gen_random_uuid(),$1,'k8s_webhook','fp-unclaimed','u','unregistered','running',
	    jsonb_build_object('kubernetes', jsonb_build_object('namespace','iga-demo')))`, f.ws)

	p := &models.AgentPolicy{WorkspaceID: f.ws,
		Selector: mustJSON(t, models.AgentPolicySelector{Namespace: "iga-demo"})}
	got, err := policyMgr(t, f).Expand(f.ws, p)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	for _, a := range got {
		if a.Status == models.DiscoveredAgentUnregistered {
			t.Error("an unclaimed sighting must not be covered by a policy")
		}
	}
}

func TestExpansionIsWorkspaceScoped(t *testing.T) {
	f := newProvFixture(t)
	other := uuid.New()
	exec(t, f.raw, `INSERT INTO workspaces (id,name) VALUES ($1,'other')`, other)
	// 'quarantined' rather than 'registered': discovered_agents_registered_chk
	// requires a client and an owner for a registered agent, and those would have to
	// live in the OTHER workspace. Quarantined is equally covered by expansion.
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status, runtime_status, metadata)
	  VALUES (gen_random_uuid(),$1,'k8s_webhook','fp-foreign','x','quarantined','running',
	    jsonb_build_object('kubernetes', jsonb_build_object('namespace','iga-demo')))`, other)

	p := &models.AgentPolicy{WorkspaceID: f.ws,
		Selector: mustJSON(t, models.AgentPolicySelector{Namespace: "iga-demo"})}
	got, err := policyMgr(t, f).Expand(f.ws, p)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expanded across a workspace boundary: %d agents", len(got))
	}
}

/* ------------------------------- the lattice ----------------------------- */

// Most restrictive wins: quarantined beats active, and scope ceilings INTERSECT.
// That is PG-5 at the policy layer — overlapping policies fail toward less access.
func TestOverlappingPoliciesResolveMostRestrictively(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "broad-active", Selector: &models.AgentPolicySelector{Namespace: "iga-demo"},
		DesiredState: models.AgentPolicyStateActive,
		ScopeCeiling: []string{"read", "write"},
	}); err != nil {
		t.Fatalf("create broad: %v", err)
	}
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "narrow-quarantine", DiscoveredAgentID: &agent,
		DesiredState: models.AgentPolicyStateQuarantined,
		ScopeCeiling: []string{"read"},
	}); err != nil {
		t.Fatalf("create narrow: %v", err)
	}

	eff, err := m.Effective(f.ws, agent)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if eff.DesiredState != models.AgentPolicyStateQuarantined {
		t.Errorf("desired_state = %q, want quarantined — the more restrictive state must win",
			eff.DesiredState)
	}
	if len(eff.ScopeCeiling) != 1 || eff.ScopeCeiling[0] != "read" {
		t.Errorf("scope ceiling = %v, want [read] — ceilings must INTERSECT, never union",
			eff.ScopeCeiling)
	}
	if len(eff.PolicyIDs) != 2 {
		t.Errorf("both contributing policies must be reported for explainability, got %d",
			len(eff.PolicyIDs))
	}
}

func TestNoPolicyMeansActiveAndUnconstrained(t *testing.T) {
	f := newProvFixture(t)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	eff, err := policyMgr(t, f).Effective(f.ws, agent)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if eff.DesiredState != models.AgentPolicyStateActive || len(eff.ScopeCeiling) != 0 {
		t.Errorf("an unpolicied agent must be active and unconstrained, got %+v", eff)
	}
}

/* ------------------------------ reconciliation --------------------------- */

// Phase 2 opened live runs for the ENTITLEMENT arm. A live run must therefore
// succeed — and must still leave the cluster untouched, which
// TestLiveRunStillRefusesTheClusterArm covers in detail.
//
// This test previously asserted the opposite (phase 1 refused every live run). It is
// updated rather than deleted, because "a live run is accepted and does nothing to
// the cluster" is the property that replaced it.
func TestLiveReconcileContainsAndDoesNotReportItselfAsADryRun(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "quarantine-it", DiscoveredAgentID: &agent,
		DesiredState: models.AgentPolicyStateQuarantined,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("a live reconcile must be accepted: %v", err)
	}
	if res.DryRun {
		t.Error("a live run must not report itself as a dry run")
	}

	// Was: "the cluster arm must remain inert until phase 5". The containment arm
	// is live, so the decision must actually land — even here, where the agent has
	// no connector and nothing will enforce it. The DECISION is a governance fact;
	// whether a cluster can act on it is a separate one, and conflating them would
	// make an unenforceable quarantine indistinguishable from no quarantine.
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovered_agents WHERE id=$1`,
		agent).Scan(&status); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.DiscoveredAgentQuarantined {
		t.Errorf("a live reconcile must contain the agent, got %q", status)
	}
}

func TestDryRunReconcilePlansButChangesNothing(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "quarantine-it", DiscoveredAgentID: &agent,
		DesiredState: models.AgentPolicyStateQuarantined,
		ScopeCeiling: []string{"read"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, true)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// WouldNarrow counts ROLE ceilings only. A scope ceiling is evaluated and
	// reported rather than applied (phase 2), because scopes derive from a role's
	// permissions and honouring one would mean synthesising a role.
	if !res.DryRun || res.WouldQuarantine != 1 {
		t.Errorf("expected 1 quarantine planned, got %+v", res)
	}

	// Nothing changed.
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovered_agents WHERE id=$1`, agent).
		Scan(&status); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.DiscoveredAgentRegistered {
		t.Errorf("a dry run must not change the agent; status = %q", status)
	}
	// And every recorded action says so.
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND (NOT dry_run OR outcome <> 'planned')`, f.ws) != 0 {
		t.Error("a dry run recorded an action claiming it applied something")
	}
}

// THE RULE THAT MATTERS MOST. An agent that starts matching a selector after the
// confirmation was given must NOT be evicted under that older authorization.
func TestEvictIsRefusedForAnUnconfirmedAgent(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	confirmed := claimedAgent(t, f, "confirmed", "iga-demo", "crewai", "automated")
	who := claimOwner
	past := time.Now().Add(-time.Hour) // already expired

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "evict-ns", Selector: &models.AgentPolicySelector{Namespace: "iga-demo"},
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &past,
		Reason: "PoC cleanup", ConfirmedBy: &who,
		ConfirmAgentIDs: []uuid.UUID{confirmed},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// A second agent appears in the namespace AFTER the confirmation.
	claimedAgent(t, f, "appeared-later", "iga-demo", "crewai", "automated")

	res, err := m.Reconcile(f.ws, true)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.WouldEvict != 1 {
		t.Errorf("exactly the confirmed agent should be evicted, got %d", res.WouldEvict)
	}
	if res.Refused != 1 {
		t.Fatalf("the later-matching agent must be REFUSED, got %d refusals — otherwise one "+
			"confirmation silently authorizes deleting workloads nobody enumerated", res.Refused)
	}
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND detail LIKE 'REFUSED:%'`, f.ws) != 1 {
		t.Error("the refusal must be recorded, so an operator sees it BEFORE the deadline")
	}
}

/* -------------------------------- lookahead ------------------------------ */

func TestUpcomingSurfacesDestructiveActionsAndTheirRisks(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)

	// A GitOps-managed agent: deleting it will not stick.
	gitops := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, fingerprint, display_name, status,
	     matched_client_id, owner_user_id, runtime_status, metadata)
	  VALUES ($1,$2,'k8s_webhook','fp-gitops','argo-managed','registered',$3,$4,'running',
	    jsonb_build_object('kubernetes', jsonb_build_object('namespace','iga-demo',
	      'labels', jsonb_build_object('app.kubernetes.io/managed-by','argocd'))))`,
		gitops, f.ws, f.client, claimOwner)

	who := claimOwner
	soon := time.Now().Add(48 * time.Hour)
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "evict-soon", DiscoveredAgentID: &gitops,
		OnExpiry: models.OnExpiryEvict, ExpiresAt: &soon,
		Reason: "PoC over", ConfirmedBy: &who,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	up, err := m.Upcoming(f.ws, 7)
	if err != nil {
		t.Fatalf("upcoming: %v", err)
	}
	if len(up) != 1 {
		t.Fatalf("expected 1 upcoming action, got %d", len(up))
	}
	a := up[0]
	if !a.Destructive {
		t.Error("an evict must be flagged destructive")
	}
	if !a.Confirmed {
		t.Error("this agent IS covered by the confirmation and should read as confirmed")
	}
	if !a.GitOpsManaged {
		t.Error("an ArgoCD-managed workload must be flagged: deleting it will not stick, " +
			"and that is worth knowing while there is still time to change the policy")
	}
}

// Nothing scheduled inside the horizon means nothing to show — not an error.
func TestUpcomingIsEmptyWithNoExpiringPolicies(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	agent := claimedAgent(t, f, "a1", "iga-demo", "crewai", "automated")
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "no-clock", DiscoveredAgentID: &agent,
		DesiredState: models.AgentPolicyStateQuarantined,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	up, err := m.Upcoming(f.ws, 7)
	if err != nil {
		t.Fatalf("upcoming: %v", err)
	}
	if len(up) != 0 {
		t.Errorf("a policy with no clock has nothing scheduled, got %d", len(up))
	}
}

// mustJSON marshals a selector for tests that build a policy struct directly rather
// than going through Create.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
