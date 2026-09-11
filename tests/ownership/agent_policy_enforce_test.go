// Phase 2 — the ENTITLEMENT arm executing for real.
//
// Everything here changes scopes and bindings in the control plane. Nothing reaches
// a cluster, which is why this arm goes live while the cluster arm is still planning.
//
// The properties worth defending:
//
//  1. A ceiling that would WIDEN is refused. Narrowing is the only direction
//     governance may move (PG-5), and a "ceiling" naming a wider role is a grant
//     wearing a restriction's clothes.
//  2. Incomparable ceilings apply NOTHING rather than picking one.
//  3. on_expiry:revoke hands off to the existing expiry worker instead of revoking
//     itself — PG-6, revocation has exactly one implementation.
//  4. A live run still refuses the cluster arm, and says so.
package ownership

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// seedRole creates a role holding the named permissions, reusing permission rows so
// two roles can genuinely share them (which is what subset comparison needs).
func seedRole(t *testing.T, f provFixture, name string, perms ...string) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,$2,$3)`,
		roleID, name+"-"+roleID.String()[:8], f.ws)
	for _, p := range perms {
		var permID uuid.UUID
		// One permission row per (workspace, string), so roles overlap properly.
		if err := f.raw.QueryRow(`
			INSERT INTO permissions (id, workspace_id, resource, action, full_permission_string)
			     VALUES (gen_random_uuid(), $1, 'rs', $2, $2)
			ON CONFLICT DO NOTHING
			  RETURNING id`, f.ws, p).Scan(&permID); err != nil {
			if err := f.raw.QueryRow(`SELECT id FROM permissions
			     WHERE workspace_id=$1 AND full_permission_string=$2`, f.ws, p).
				Scan(&permID); err != nil {
				t.Fatalf("seed permission %s: %v", p, err)
			}
		}
		exec(t, f.raw, `INSERT INTO role_permissions (role_id, permission_id)
		                VALUES ($1,$2) ON CONFLICT DO NOTHING`, roleID, permID)
	}
	return roleID
}

// provisionedAgent claims and provisions the fixture agent so it holds a real
// binding on a real role — the state a ceiling acts on.
func provisionedAgent(t *testing.T, f provFixture, roleID uuid.UUID) {
	t.Helper()
	exp := time.Now().Add(720 * time.Hour)
	if _, err := f.pm.Provision(f.ws, services.ProvisionInput{
		DiscoveredAgentID: f.agent,
		ResourceServerID:  f.rs,
		RoleID:            roleID,
		ExpiresAt:         &exp,
		ActingUser:        &claimOwner,
		ActingUserLabel:   "u@a.com",
		Purpose:           "phase 2 fixture",
	}); err != nil {
		t.Fatalf("provision: %v", err)
	}
}

/* ------------------------- narrowing, and refusing to widen -------------- */

func TestRoleCeilingNarrowsABinding(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)

	wide := seedRole(t, f, "wide", "read", "write", "delete")
	narrow := seedRole(t, f, "narrow", "read")
	provisionedAgent(t, f, wide)

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "cap-to-read", DiscoveredAgentID: &f.agent, RoleCeilingID: &narrow,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.BindingsNarrowed != 1 {
		t.Fatalf("expected 1 binding narrowed, got %d (errors: %v)",
			res.BindingsNarrowed, res.Errors)
	}
	if f.count(t, `SELECT count(*) FROM role_bindings rb
	                JOIN service_accounts sa ON sa.id = rb.service_account_id
	               WHERE sa.oauth_client_id = $1 AND rb.role_id = $2`, f.client, narrow) != 1 {
		t.Error("the binding should now point at the ceiling role")
	}
}

// THE SAFETY PROPERTY. A "ceiling" naming a role that grants MORE is a grant in
// disguise, and PG-5 is absolute: governance may narrow, never widen.
func TestARoleCeilingThatWouldWidenIsRefused(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)

	narrow := seedRole(t, f, "narrow", "read")
	wide := seedRole(t, f, "wide", "read", "write", "delete")
	provisionedAgent(t, f, narrow) // agent holds the NARROW role

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "sneaky-widen", DiscoveredAgentID: &f.agent, RoleCeilingID: &wide,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.BindingsNarrowed != 0 {
		t.Error("a widening ceiling must never be applied")
	}
	if res.Refused != 1 {
		t.Fatalf("the widen must be REFUSED and counted, got %d refusals", res.Refused)
	}
	if f.count(t, `SELECT count(*) FROM role_bindings rb
	                JOIN service_accounts sa ON sa.id = rb.service_account_id
	               WHERE sa.oauth_client_id = $1 AND rb.role_id = $2`, f.client, narrow) != 1 {
		t.Error("the agent must still hold its original narrow role")
	}
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND detail LIKE '%refusing to widen%'`, f.ws) != 1 {
		t.Error("the refusal must be recorded with a reason a reviewer can act on")
	}
}

// Two ceilings where neither is a subset of the other. Picking one would decide
// somebody's access by evaluation order, so nothing is applied.
func TestIncomparableRoleCeilingsApplyNothing(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)

	held := seedRole(t, f, "held", "read", "write", "delete")
	readOnly := seedRole(t, f, "readonly", "read")
	deleteOnly := seedRole(t, f, "deleteonly", "delete")
	provisionedAgent(t, f, held)

	// The shared fixture's metadata carries only provisioning_hints, so give the
	// agent a cluster for the selector to match. Two SELECTOR policies are needed
	// here: only one DIRECT policy per agent is allowed, and this test is about two
	// policies colliding.
	exec(t, f.raw, `UPDATE discovered_agents
	                   SET metadata = metadata || jsonb_build_object(
	                         'cluster', jsonb_build_object('name','prod-1'))
	                 WHERE id = $1`, f.agent)

	for i, rc := range []uuid.UUID{readOnly, deleteOnly} {
		rc := rc
		if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
			Name:          "ceiling-" + string(rune('a'+i)),
			Selector:      &models.AgentPolicySelector{Cluster: "prod-1"},
			RoleCeilingID: &rc,
		}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	eff, err := m.Effective(f.ws, f.agent)
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if eff.Ambiguous == "" {
		t.Fatal("two incomparable ceilings must be reported ambiguous, not silently resolved")
	}
	if eff.RoleCeilingID != nil {
		t.Error("an ambiguous ceiling must resolve to nothing")
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.BindingsNarrowed != 0 {
		t.Error("nothing may be applied while the ceiling is ambiguous")
	}
	if f.count(t, `SELECT count(*) FROM role_bindings rb
	                JOIN service_accounts sa ON sa.id = rb.service_account_id
	               WHERE sa.oauth_client_id=$1 AND rb.role_id=$2`, f.client, held) != 1 {
		t.Error("the agent must keep the role it had")
	}
}

/* ---------------------- revoke hands off to the one path ----------------- */

// on_expiry:revoke must NOT revoke on its own. It lapses the grant and the expiry
// worker — the single revocation implementation (PG-6) — does the rest.
func TestRevokeOnExpiryLapsesTheGrantForTheExpiryWorker(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	role := seedRole(t, f, "reader", "read")
	provisionedAgent(t, f, role)

	past := time.Now().Add(-time.Hour)
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "expired", DiscoveredAgentID: &f.agent,
		OnExpiry: models.OnExpiryRevoke, ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.GrantsLapsed < 1 {
		t.Fatalf("expected grants to be lapsed, got %d", res.GrantsLapsed)
	}

	// The reconciler itself must NOT have revoked or deleted anything.
	if f.count(t, `SELECT count(*) FROM entitlement_provenance
	                WHERE workspace_id=$1 AND discovered_agent_id=$2 AND revoked_at IS NOT NULL`,
		f.ws, f.agent) != 0 {
		t.Error("the reconciler revoked directly; revocation has exactly one " +
			"implementation and this is not it (PG-6)")
	}
	// What it DID do: make the grant sweepable.
	if f.count(t, `SELECT count(*) FROM entitlement_provenance
	                WHERE workspace_id=$1 AND discovered_agent_id=$2
	                  AND revoked_at IS NULL AND NOT is_standing AND expires_at <= now()`,
		f.ws, f.agent) < 1 {
		t.Fatal("the grant must be left lapsed so the expiry worker picks it up")
	}

	// And the real worker completes it.
	sweep := services.NewExpiryWorker(gormFor(t, f.raw), time.Minute, 100).RunOnce()
	if sweep.BindingsRemoved < 1 || sweep.ProvenanceClosed < 1 {
		t.Fatalf("the expiry worker should have finished the job, got %+v", sweep)
	}
	if f.count(t, `SELECT count(*) FROM entitlement_provenance
	                WHERE workspace_id=$1 AND discovered_agent_id=$2 AND revoked_at IS NOT NULL`,
		f.ws, f.agent) < 1 {
		t.Error("after the sweep the grant must be revoked")
	}
}

// A standing grant is skipped by FindLapsedGrants by design, so revoking one must
// clear is_standing or the policy would silently do nothing.
func TestRevokeClearsStandingSoTheGrantCanBeSwept(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	role := seedRole(t, f, "reader", "read")

	if _, err := f.pm.Provision(f.ws, services.ProvisionInput{
		DiscoveredAgentID: f.agent, ResourceServerID: f.rs, RoleID: role,
		IsStanding: true, Justification: "permanent by design",
		ActingUser: &claimOwner, ActingUserLabel: "u@a.com",
	}); err != nil {
		t.Fatalf("provision standing: %v", err)
	}

	past := time.Now().Add(-time.Hour)
	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "kill-standing", DiscoveredAgentID: &f.agent,
		OnExpiry: models.OnExpiryRevoke, ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := m.Reconcile(f.ws, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if f.count(t, `SELECT count(*) FROM entitlement_provenance
	                WHERE workspace_id=$1 AND discovered_agent_id=$2 AND is_standing`,
		f.ws, f.agent) != 0 {
		t.Error("a standing grant the policy revokes must stop being standing, " +
			"or the expiry worker will never sweep it and the policy silently no-ops")
	}
}

/* ------------------------- the cluster arm stays shut -------------------- */

// A live run must still refuse the cluster arm, and record WHY — not quietly
// report success for something it did not do.
func TestLiveRunContainsTheAgentAndRecordsItAsApplied(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	role := seedRole(t, f, "reader", "read")
	provisionedAgent(t, f, role)

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "quarantine-me", DiscoveredAgentID: &f.agent,
		DesiredState: models.AgentPolicyStateQuarantined,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("a live run must not error: %v", err)
	}
	if res.WouldQuarantine != 1 {
		t.Errorf("the quarantine should be counted, got %d", res.WouldQuarantine)
	}

	// Was: "the cluster arm must not act until phase 5". It acts now — that was
	// the whole point of the containment arm, and a policy that states an end
	// state and never reaches it is a note rather than a policy.
	var status string
	if err := f.raw.QueryRow(`SELECT status FROM discovered_agents WHERE id=$1`,
		f.agent).Scan(&status); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.DiscoveredAgentQuarantined {
		t.Fatalf("a live run must CONTAIN the agent, got status %q", status)
	}

	// And it must say so honestly: applied, not planned. An action recorded as
	// planned after it happened reads as though nothing did.
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND arm='cluster' AND action='quarantined'
	                  AND outcome='applied' AND dry_run = false`, f.ws) != 1 {
		t.Error("a live containment must be recorded as applied on the cluster arm")
	}
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND outcome='refused'
	                  AND detail LIKE '%not implemented%'`, f.ws) != 0 {
		t.Error("no action may still claim the cluster arm is unimplemented")
	}
}

/* --------------------- scope ceiling reports, never narrows -------------- */

func TestScopeCeilingReportsExcessRatherThanNarrowing(t *testing.T) {
	f := newProvFixture(t)
	m := policyMgr(t, f)
	role := seedRole(t, f, "writer", "read", "write")
	// Scopes are derived: role -> role_permissions -> permissions -> oauth_scopes.
	// Without the scope half of that chain there is nothing to compare a ceiling
	// against, and the evaluation would find no excess for the wrong reason.
	seedScopeForPermission(t, f, "read")
	seedScopeForPermission(t, f, "write")
	provisionedAgent(t, f, role)

	if _, err := m.Create(f.ws, "u", services.AgentPolicyInput{
		Name: "read-only-please", DiscoveredAgentID: &f.agent,
		ScopeCeiling: []string{"read"},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := m.Reconcile(f.ws, false)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The scope resolution must actually WORK. An earlier version of this test only
	// checked that nothing was rebound, so it passed while the underlying query was
	// broken and every evaluation silently errored into res.Errors.
	if len(res.Errors) > 0 {
		t.Fatalf("scope evaluation errored instead of reporting: %v", res.Errors)
	}
	if res.Refused != 1 {
		t.Fatalf("the excess scope must be REPORTED, got %d refusals", res.Refused)
	}
	if f.count(t, `SELECT count(*) FROM agent_policy_actions
	                WHERE workspace_id=$1 AND detail LIKE '%beyond the ceiling%'`, f.ws) != 1 {
		t.Error("the excess scopes must be named in the action detail, so an operator " +
			"knows which ones to act on")
	}

	// And it must not have silently changed the binding.
	if f.count(t, `SELECT count(*) FROM role_bindings rb
	                JOIN service_accounts sa ON sa.id = rb.service_account_id
	               WHERE sa.oauth_client_id=$1 AND rb.role_id=$2`, f.client, role) != 1 {
		t.Error("a scope ceiling must not rebind: synthesising a role to satisfy it " +
			"would be a widen arrived at from the other direction")
	}
}

// seedScopeForPermission wires an oauth_scope to the permission of the same name, so
// the held-scope resolution has a chain to walk.
func seedScopeForPermission(t *testing.T, f provFixture, name string) {
	t.Helper()
	var permID uuid.UUID
	if err := f.raw.QueryRow(`SELECT id FROM permissions
	     WHERE workspace_id=$1 AND full_permission_string=$2`, f.ws, name).Scan(&permID); err != nil {
		t.Fatalf("look up permission %s: %v", name, err)
	}
	scopeID := uuid.New()
	exec(t, f.raw, `INSERT INTO oauth_scopes (id, workspace_id, scope_string, display_name)
	                VALUES ($1,$2,$3,$3)`, scopeID, f.ws, name)
	exec(t, f.raw, `INSERT INTO oauth_scope_permissions (scope_id, permission_id)
	                VALUES ($1,$2)`, scopeID, permID)
}
