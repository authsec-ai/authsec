// Phase 6 tests: human joiner / mover / leaver.
//
// The properties that matter are about the ASYMMETRY between the three. Joiner and
// leaver are unambiguous and automatic; a mover is not, so it is flagged by default.
// Getting that backwards would let one mistyped group membership take somebody's access
// away with nobody in the loop.
//
// Also tested: the reconcile is idempotent (it has no cursor — desired state is
// computable and actual state is in provenance), it reads the AUTHORITATIVE `active`
// column, and a leaver's owned agents are reported rather than killed.
package ownership

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

type jmlFixture struct {
	provFixture
	lm    services.LifecycleManager
	group uuid.UUID
	user  uuid.UUID
}

func newJMLFixture(t *testing.T) jmlFixture {
	t.Helper()
	f := newProvFixture(t)
	db := gormFor(t, f.raw)

	group := uuid.New()
	exec(t, f.raw, `INSERT INTO groups (id,name,workspace_id) VALUES ($1,'engineering',$2)`, group, wsA)

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	exec(t, f.raw, `INSERT INTO user_groups (workspace_id,user_id,group_id) VALUES ($1,$2,$3)`,
		wsA, user, group)

	return jmlFixture{
		provFixture: f,
		lm:          services.NewLifecycleManager(db, services.NewOAuthASService(db)),
		group:       group,
		user:        user,
	}
}

func (f jmlFixture) policy(t *testing.T, dur *time.Duration, onUnmatch, justification string) uuid.UUID {
	t.Helper()
	p, err := f.lm.CreatePolicy(f.ws, "admin@a.com", services.BirthrightInput{
		Name:             "engineering-payments",
		MatchKind:        models.BirthrightMatchGroup,
		MatchGroupID:     &f.group,
		ResourceServerID: f.rs,
		RoleID:           f.role,
		Duration:         dur,
		Justification:    justification,
		OnUnmatch:        onUnmatch,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	return p.ID
}

func hours(n int) *time.Duration { d := time.Duration(n) * time.Hour; return &d }

/* -------------------------------- policies ------------------------------- */

// A standing birthright is the widest blast radius in the system: permanent access for
// everyone in a group. Somebody has to say why.
func TestStandingBirthrightRequiresJustification(t *testing.T) {
	f := newJMLFixture(t)

	if _, err := f.lm.CreatePolicy(f.ws, "admin", services.BirthrightInput{
		Name: "no-justification", MatchKind: models.BirthrightMatchGroup,
		MatchGroupID: &f.group, ResourceServerID: f.rs, RoleID: f.role,
	}); err == nil {
		t.Fatal("a birthright with no duration and no justification must be refused")
	}

	if _, err := f.lm.CreatePolicy(f.ws, "admin", services.BirthrightInput{
		Name: "justified", MatchKind: models.BirthrightMatchGroup,
		MatchGroupID: &f.group, ResourceServerID: f.rs, RoleID: f.role,
		Justification: "every engineer needs read access to payments",
	}); err != nil {
		t.Fatalf("a justified standing birthright should be allowed: %v", err)
	}
}

// A policy must not graft a foreign-workspace role onto every member of a group.
func TestBirthrightRejectsAForeignRole(t *testing.T) {
	f := newJMLFixture(t)
	foreign := uuid.New()
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'foreign',$2)`, foreign, wsB)

	if _, err := f.lm.CreatePolicy(f.ws, "admin", services.BirthrightInput{
		Name: "cross-ws", MatchKind: models.BirthrightMatchGroup, MatchGroupID: &f.group,
		ResourceServerID: f.rs, RoleID: foreign, Duration: hours(1),
	}); err == nil {
		t.Fatal("a foreign-workspace role must be refused")
	}
}

// An 'all' policy applies to everyone, so it must not also look scoped.
func TestAllPolicyMustNotNameAGroup(t *testing.T) {
	f := newJMLFixture(t)
	if _, err := f.lm.CreatePolicy(f.ws, "admin", services.BirthrightInput{
		Name: "confused", MatchKind: models.BirthrightMatchAll, MatchGroupID: &f.group,
		ResourceServerID: f.rs, RoleID: f.role, Duration: hours(1),
	}); err == nil {
		t.Fatal("an 'all' policy naming a group must be refused")
	}
}

/* --------------------------------- joiner -------------------------------- */

// The joiner half: a matching policy produces a real, explained, expiring grant.
func TestJoinerGrantsFromBirthright(t *testing.T) {
	f := newJMLFixture(t)
	pid := f.policy(t, hours(24), models.OnUnmatchFlag, "")

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{ActorLabel: "test"})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.GrantsCreated != 1 {
		t.Fatalf("expected 1 grant, got %+v", res)
	}

	// A real binding, RS-scoped, that expires.
	var expires *time.Time
	var src string
	if err := f.raw.QueryRow(`SELECT expires_at, assignment_source FROM role_bindings
	                           WHERE user_id = $1 AND scope_id = $2`, f.user, f.rs).
		Scan(&expires, &src); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if expires == nil {
		t.Error("a birthright with a duration must produce an expiring binding")
	}
	if src != "birthright" {
		t.Errorf("assignment_source = %q, want birthright", src)
	}

	// Explained, and tied back to the policy that produced it — which is what makes the
	// mover diff possible at all.
	var origin, snapshot, justification string
	if err := f.raw.QueryRow(`SELECT origin, entitlement_snapshot::text, justification
	                            FROM entitlement_provenance WHERE subject_id = $1
	                             AND origin = 'birthright'`, f.user).
		Scan(&origin, &snapshot, &justification); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if !strings.Contains(snapshot, pid.String()) {
		t.Error("the snapshot must record WHICH policy granted this, or a later pass " +
			"cannot tell whether the grant still has a matching policy")
	}
	if justification == "" {
		t.Error("a birthright grant must carry a justification")
	}
}

// No cursor, so the reconcile must be safe to run forever.
func TestReconcileIsIdempotent(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")

	first, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.GrantsCreated != 1 || second.GrantsCreated != 0 {
		t.Errorf("expected 1 then 0 grants, got %d then %d",
			first.GrantsCreated, second.GrantsCreated)
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 1 {
		t.Errorf("expected exactly 1 binding after two passes, got %d", n)
	}
}

// A birthright policy's blast radius is a whole group, so seeing the plan before it
// executes matters.
func TestDryRunChangesNothing(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !res.DryRun || res.GrantsCreated != 1 {
		t.Errorf("a dry run must still report what it WOULD do: %+v", res)
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 0 {
		t.Error("a dry run must not create anything")
	}
}

// SoD guards birthrights too: a control that only covers some entry points is not a
// control.
func TestBirthrightIsRefusedBySoD(t *testing.T) {
	f := newJMLFixture(t)
	grantRolePermission(t, f.provFixture, f.role, "governance:admin")
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'no-governance','prohibition','critical','any','governance authority',
	            '{governance:admin}','block')`, wsA)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile should not fail wholesale: %v", err)
	}
	if res.GrantsCreated != 0 {
		t.Error("a birthright that would breach SoD must not be granted")
	}
	if len(res.Errors) == 0 {
		t.Error("the refusal must be reported, not silently skipped")
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 0 {
		t.Error("no binding should exist")
	}
}

/* --------------------------------- mover --------------------------------- */

// THE asymmetry. A group change is ambiguous — a correction, a secondment, a mistake —
// so the default is to FLAG, not revoke.
func TestMoverFlagsByDefaultAndDoesNotRevoke(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")
	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("initial: %v", err)
	}

	// The user moves out of the group.
	exec(t, f.raw, `DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2`, f.user, f.group)

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.StaleFlagged != 1 {
		t.Errorf("expected the grant to be FLAGGED, got %+v", res)
	}
	if res.StaleRevoked != 0 {
		t.Error("the default must not revoke: one mistyped group membership would " +
			"otherwise take somebody's access away with nobody in the loop")
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 1 {
		t.Error("the binding must survive a flag")
	}

	// And it surfaces in the mover queue with a reason a human can act on.
	stale, err := f.lm.StaleBirthrights(f.ws)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale birthright, got %d", len(stale))
	}
	if !strings.Contains(stale[0].Reason, "no longer matches") {
		t.Errorf("the reason should explain what changed, got %q", stale[0].Reason)
	}
}

// Opting in to revoke does revoke, through the standard path.
func TestMoverRevokesWhenPolicySaysSo(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchRevoke, "")
	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("initial: %v", err)
	}
	exec(t, f.raw, `DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2`, f.user, f.group)

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.StaleRevoked != 1 {
		t.Errorf("expected the grant to be revoked, got %+v", res)
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 0 {
		t.Error("the binding should be gone")
	}
	// Provenance survives, closed and attributed.
	var via string
	if err := f.raw.QueryRow(`SELECT revoked_via FROM entitlement_provenance
	                           WHERE subject_id = $1 AND origin = 'birthright'`, f.user).
		Scan(&via); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if via == "" {
		t.Error("the revocation must be recorded on the provenance row")
	}
}

// Deleting a policy stops future grants; it is not a mass-revocation instruction.
func TestDeletingAPolicyLeavesGrantsAsStale(t *testing.T) {
	f := newJMLFixture(t)
	pid := f.policy(t, hours(24), models.OnUnmatchRevoke, "")
	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("initial: %v", err)
	}
	if err := f.lm.DeletePolicy(f.ws, pid); err != nil {
		t.Fatalf("delete: %v", err)
	}

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The policy is gone, so there is no on_unmatch to honour — flag, never revoke.
	if res.StaleRevoked != 0 {
		t.Error("deleting a policy must not mass-revoke: it stops future grants only")
	}
	if res.StaleFlagged != 1 {
		t.Errorf("the orphaned grant should be flagged, got %+v", res)
	}
	stale, _ := f.lm.StaleBirthrights(f.ws)
	if len(stale) != 1 || !strings.Contains(stale[0].Reason, "deleted or disabled") {
		t.Errorf("the reason should say the policy is gone, got %+v", stale)
	}
}

/* --------------------------------- leaver -------------------------------- */

// The leaver half: unambiguous, so automatic and immediate.
func TestLeaverLosesEverythingAndTokensAreKilled(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")
	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("initial: %v", err)
	}

	// A live token the person holds.
	jti := uuid.New()
	exec(t, f.raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','user',$3,'c',$4,'authsec://rs/payments','read',
	            now(), now() + interval '55 minutes')`, jti, wsA, f.user, f.rs)

	// They leave. `active` is the authoritative column — models.User.Active, and what
	// the SCIM controller writes. Reading `is_active` instead would make this invisible.
	exec(t, f.raw, `UPDATE users SET active = false WHERE id = $1`, f.user)

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.LeaversProcessed != 1 {
		t.Fatalf("expected 1 leaver, got %+v", res)
	}
	if res.BindingsRevoked != 1 {
		t.Errorf("bindings_revoked = %d, want 1", res.BindingsRevoked)
	}
	if res.TokensRevoked != 1 {
		t.Errorf("tokens_revoked = %d, want 1 — otherwise the leaver keeps working for "+
			"up to their token's remaining lifetime", res.TokensRevoked)
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 0 {
		t.Error("a leaver must hold no bindings")
	}
	if n := f.count(t, `SELECT count(*) FROM revoked_tokens WHERE jti = $1::text`, jti); n != 1 {
		t.Error("the live token was not killed")
	}

	// Bookkeeping, so an operator can see it was handled.
	var summary string
	var revokedAt *time.Time
	if err := f.raw.QueryRow(`SELECT access_revoked_summary, access_revoked_at
	                            FROM users WHERE id = $1`, f.user).Scan(&summary, &revokedAt); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if revokedAt == nil || summary == "" {
		t.Errorf("the leaver should be recorded: at=%v summary=%q", revokedAt, summary)
	}
}

// A leaver must not be re-granted their birthright on the next pass — otherwise the
// reconcile would fight itself forever.
func TestLeaverIsNotRegrantedOnTheNextPass(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")
	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("initial: %v", err)
	}
	// Still in the group — only deactivated.
	exec(t, f.raw, `UPDATE users SET active = false WHERE id = $1`, f.user)

	if _, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{}); err != nil {
		t.Fatalf("leaver pass: %v", err)
	}
	again, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again.GrantsCreated != 0 {
		t.Error("a deactivated user still in the group must NOT be re-granted: the " +
			"leaver check has to come before the joiner check")
	}
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE user_id = $1`, f.user); n != 0 {
		t.Error("no binding should have been recreated")
	}
}

// THE judgement call. Agents the leaver owned are REPORTED, not killed: a person
// changing jobs says nothing about whether the workload they registered should keep
// running, and taking down production agents is its own incident.
func TestLeaversAgentsAreReportedNotKilled(t *testing.T) {
	f := newJMLFixture(t)
	exec(t, f.raw, `UPDATE mcp_oauth_clients SET owner_user_id = $1, governance_status = 'active'
	                 WHERE id = $2`, f.user, f.client)
	exec(t, f.raw, `UPDATE users SET active = false WHERE id = $1`, f.user)

	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.OrphanedAgents != 1 {
		t.Errorf("orphaned_agents = %d, want 1", res.OrphanedAgents)
	}

	// The agent is untouched — still governed, still running.
	var status string
	if err := f.raw.QueryRow(`SELECT governance_status FROM mcp_oauth_clients WHERE id = $1`,
		f.client).Scan(&status); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if status != models.GovernanceStatusActive {
		t.Errorf("governance_status = %q; the agent must NOT be deprovisioned just "+
			"because its owner left", status)
	}

	// But it surfaces for somebody to re-own or deprovision deliberately.
	orphans, err := f.lm.OrphanedAgents(f.ws)
	if err != nil {
		t.Fatalf("orphans: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphaned agent, got %d", len(orphans))
	}
	if orphans[0].OwnerUserID != f.user || orphans[0].OwnerEmail == "" {
		t.Errorf("the report must name the departed owner: %+v", orphans[0])
	}
}

// An 'all' policy reaches users in no group at all.
func TestAllPolicyGrantsToEveryone(t *testing.T) {
	f := newJMLFixture(t)
	exec(t, f.raw, `DELETE FROM user_groups WHERE user_id = $1`, f.user)

	if _, err := f.lm.CreatePolicy(f.ws, "admin", services.BirthrightInput{
		Name: "everyone-payments", MatchKind: models.BirthrightMatchAll,
		ResourceServerID: f.rs, RoleID: f.role, Duration: hours(24),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := f.lm.Reconcile(f.ws, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.GrantsCreated != 1 {
		t.Errorf("an 'all' policy must reach a user in no group: %+v", res)
	}
}

// A single user can be reconciled directly, for an admin acting on one joiner or leaver.
func TestReconcileSingleUser(t *testing.T) {
	f := newJMLFixture(t)
	f.policy(t, hours(24), models.OnUnmatchFlag, "")

	res, err := f.lm.ReconcileUser(f.ws, f.user, services.ReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile user: %v", err)
	}
	if res.UsersScanned != 1 || res.GrantsCreated != 1 {
		t.Errorf("expected a single-user pass to grant once: %+v", res)
	}
	if _, err := f.lm.ReconcileUser(f.ws, uuid.New(), services.ReconcileOptions{}); err == nil {
		t.Error("an unknown user should be reported, not silently succeed")
	}
}
