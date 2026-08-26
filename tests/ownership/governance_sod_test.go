// Phase 3 tests: separation of duties.
//
// The headline case is the seeded self-modification control: an agent that can grant
// itself permissions is not governed, whatever the inventory says. That control has to
// hold at the PROVISIONING boundary (refused before the binding exists), not merely be
// reported after the fact.
//
// Subject expansion is tested against the real chain — role_bindings → roles →
// role_permissions → permissions — because PG-7's whole point is that SoD sees exactly
// what enforcement grants. A hand-rolled fixture would prove nothing about that.
package ownership

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// grantRolePermission attaches a permission to a role, creating the permission if the
// bootstrap has not already seeded it.
func grantRolePermission(t *testing.T, f provFixture, roleID uuid.UUID, permString string) {
	t.Helper()
	parts := strings.SplitN(permString, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("permission %q must be resource:action", permString)
	}
	var permID uuid.UUID
	err := f.raw.QueryRow(
		`SELECT id FROM permissions WHERE full_permission_string = $1 AND workspace_id IS NULL`,
		permString).Scan(&permID)
	if err != nil {
		permID = uuid.New()
		exec(t, f.raw, `INSERT INTO permissions (id, workspace_id, resource, action, full_permission_string)
		                VALUES ($1, NULL, $2, $3, $4)
		                ON CONFLICT (resource, action) WHERE workspace_id IS NULL DO NOTHING`,
			permID, parts[0], parts[1], permString)
		// Re-read: a concurrent/conflicting insert means the surviving row's id wins.
		if rerr := f.raw.QueryRow(
			`SELECT id FROM permissions WHERE full_permission_string = $1 AND workspace_id IS NULL`,
			permString).Scan(&permID); rerr != nil {
			t.Fatalf("resolve permission %s: %v", permString, rerr)
		}
	}
	exec(t, f.raw, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1,$2)
	                ON CONFLICT DO NOTHING`, roleID, permID)
}

/* --------------------------- the seeded control --------------------------- */

// THE test for Phase 3. An agent must not be able to acquire governance or
// role-management authority, and the refusal must happen at the provisioning boundary —
// before the binding exists — not be reported afterwards.
func TestAgentCannotBeGrantedGovernanceAuthority(t *testing.T) {
	f := newProvFixture(t)
	// The role an operator is about to hand the agent happens to carry governance:admin.
	grantRolePermission(t, f, f.role, "governance:admin")

	_, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, ""))
	if err == nil {
		t.Fatal("an agent must not be provisionable into a role carrying governance:admin")
	}
	if !strings.Contains(err.Error(), "agent-self-modification") {
		t.Errorf("the refusal should name the rule that caused it, got: %v", err)
	}

	// PG-2 still holds: the refused provision left nothing behind.
	if n := f.count(t, `SELECT count(*) FROM role_bindings`); n != 0 {
		t.Errorf("the binding must not exist, found %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM entitlement_provenance`); n != 0 {
		t.Errorf("no provenance should have been written, found %d", n)
	}

	// The ATTEMPT is recorded as evidence, on its own connection, so it survives the
	// rolled-back transaction.
	if n := f.count(t, `SELECT count(*) FROM sod_violations WHERE detected_via = 'preventive'`); n != 1 {
		t.Errorf("expected the refused attempt to be recorded as a preventive violation, found %d", n)
	}
	var ruleName, evidence string
	if err := f.raw.QueryRow(`SELECT rule_name, left_evidence::text FROM sod_violations LIMIT 1`).
		Scan(&ruleName, &evidence); err != nil {
		t.Fatalf("read violation: %v", err)
	}
	if ruleName != "agent-self-modification" {
		t.Errorf("rule_name = %q", ruleName)
	}
	if !strings.Contains(evidence, "governance:admin") {
		t.Errorf("the evidence must name the offending capability, got %s", evidence)
	}
}

// The same role is fine for a HUMAN. subject_scope='agents' has to actually narrow the
// rule, or the control would break ordinary administration.
func TestTheSameRoleIsAllowedForAHuman(t *testing.T) {
	f := newProvFixture(t)
	grantRolePermission(t, f, f.role, "governance:admin")

	pm := f.pm.(interface {
		GrantEntitlement(uuid.UUID, services.GrantEntitlementInput) (*services.GrantResult, error)
	})
	out, err := pm.GrantEntitlement(f.ws, services.GrantEntitlementInput{
		ResourceServerID: f.rs,
		ClientID:         "agent-client-1",
		RoleID:           &f.role,
		SubjectType:      "user",
		SubjectID:        uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001"),
		Origin:           models.GrantOriginAdmin,
		ExpiresAt:        future(time.Hour),
	})
	if err != nil {
		t.Fatalf("a human administrator may hold governance:admin: %v", err)
	}
	if out.RoleBindingID == nil {
		t.Error("expected the binding to be created")
	}
	if n := f.count(t, `SELECT count(*) FROM sod_violations`); n != 0 {
		t.Errorf("no violation should have been recorded for a human, found %d", n)
	}
}

// A benign role must provision normally — a control that blocks everything is not a
// control.
func TestAgentWithABenignRoleProvisionsNormally(t *testing.T) {
	f := newProvFixture(t)
	grantRolePermission(t, f, f.role, "payments:read")

	if _, err := f.pm.Provision(f.ws, f.provisionInput(future(time.Hour), false, "")); err != nil {
		t.Fatalf("a benign role must provision: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM sod_violations`); n != 0 {
		t.Errorf("no violation expected, found %d", n)
	}
}

// The system rule must be un-editable. A control an attacker can switch off before
// escalating is not a control.
func TestSystemRuleIsMarkedImmutableAndGlobal(t *testing.T) {
	f := newProvFixture(t)

	var isSystem bool
	var wsID *uuid.UUID
	var enforcement, kind, scope string
	if err := f.raw.QueryRow(`SELECT is_system, workspace_id, enforcement, kind, subject_scope
	                            FROM sod_rules WHERE name = 'agent-self-modification'`).
		Scan(&isSystem, &wsID, &enforcement, &kind, &scope); err != nil {
		t.Fatalf("the seeded rule should exist: %v", err)
	}
	if !isSystem {
		t.Error("the self-modification rule must be flagged is_system so the API refuses edits")
	}
	if wsID != nil {
		t.Error("it must be GLOBAL (workspace_id NULL) so it applies in every workspace")
	}
	if enforcement != models.SoDEnforcementBlock {
		t.Errorf("enforcement = %q, want block", enforcement)
	}
	if kind != models.SoDKindProhibition || scope != models.SoDScopeAgents {
		t.Errorf("expected a prohibition scoped to agents, got kind=%q scope=%q", kind, scope)
	}
}

/* ------------------------------ conflict rules ---------------------------- */

// The classic two-sided shape: each side alone is fine, both together is the violation.
func TestConflictRuleNeedsBothSides(t *testing.T) {
	f := newProvFixture(t)
	sod := services.NewSoDManager(gormFor(t, f.raw))

	raiseRole := f.role
	approveRole := uuid.New()
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'approver',$2)`, approveRole, wsA)
	grantRolePermission(t, f, raiseRole, "orders:create")
	grantRolePermission(t, f, approveRole, "payments:approve")

	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,
	     right_label,right_permissions,enforcement)
	    VALUES ($1,'raise-vs-approve','conflict','high','any','raise orders','{orders:create}',
	            'approve payments','{payments:approve}','block')`, wsA)

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")

	// One side only: allowed.
	bindRoleTo(t, f, raiseRole, user)
	dec, err := sod.Check(nil, f.ws, services.SoDCheckInput{
		SubjectType: models.ProvenanceSubjectUser, SubjectID: user,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("holding only one side must be allowed: %+v", dec.Blocking)
	}

	// Contemplating the other side: refused, before it is granted.
	dec, err = sod.Check(nil, f.ws, services.SoDCheckInput{
		SubjectType: models.ProvenanceSubjectUser, SubjectID: user, AddingRoleID: approveRole,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if dec.Allowed {
		t.Fatal("holding both sides must be refused")
	}
	if len(dec.Blocking) != 1 || dec.Blocking[0].RuleName != "raise-vs-approve" {
		t.Errorf("unexpected blocking set: %+v", dec.Blocking)
	}
	hit := dec.Blocking[0]
	if len(hit.LeftHits) == 0 || len(hit.RightHits) == 0 {
		t.Error("a conflict hit must report evidence from BOTH sides")
	}
	if !strings.Contains(hit.Explanation, "must stay separate") {
		t.Errorf("explanation should read for a human, got %q", hit.Explanation)
	}
}

// 'warn' lets a rule be rolled out in observation mode: the violation is recorded, the
// grant is allowed.
func TestWarnRuleRecordsButDoesNotBlock(t *testing.T) {
	f := newProvFixture(t)
	sod := services.NewSoDManager(gormFor(t, f.raw))
	grantRolePermission(t, f, f.role, "governance:admin")

	// A warn-mode duplicate of the seeded control, scoped to this workspace.
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'observe-only','prohibition','medium','any','governance authority',
	            '{governance:admin}','warn')`, wsA)

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	bindRoleTo(t, f, f.role, user)

	dec, err := sod.Check(nil, f.ws, services.SoDCheckInput{
		SubjectType: models.ProvenanceSubjectUser, SubjectID: user,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("a warn-mode rule must not block: %+v", dec.Blocking)
	}
	if len(dec.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(dec.Warnings))
	}
}

// A LAPSED binding grants nothing, so it must not create a violation either — SoD has
// to read the same expiry filter enforcement reads (PG-7).
func TestExpiredBindingDoesNotCreateAViolation(t *testing.T) {
	f := newProvFixture(t)
	sod := services.NewSoDManager(gormFor(t, f.raw))
	grantRolePermission(t, f, f.role, "governance:admin")

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	bid := bindRoleTo(t, f, f.role, user)
	exec(t, f.raw, `UPDATE role_bindings SET expires_at = now() - interval '1 minute' WHERE id = $1`, bid)

	// Scoped to 'any' so the human/agent distinction is not what is being tested here.
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'no-governance','prohibition','high','any','governance authority',
	            '{governance:admin}','block')`, wsA)

	dec, err := sod.Check(nil, f.ws, services.SoDCheckInput{
		SubjectType: models.ProvenanceSubjectUser, SubjectID: user,
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("an expired binding grants nothing and must not violate: %+v", dec.Blocking)
	}
}

/* ------------------------------ detective scan ---------------------------- */

// The detective pass catches what predates a rule — otherwise writing a rule would
// only ever govern the future.
func TestDetectiveScanFindsAndThenClearsViolations(t *testing.T) {
	f := newProvFixture(t)
	sod := services.NewSoDManager(gormFor(t, f.raw))
	grantRolePermission(t, f, f.role, "governance:admin")

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	bid := bindRoleTo(t, f, f.role, user)
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'no-governance','prohibition','critical','any','governance authority',
	            '{governance:admin}','block')`, wsA)

	res, err := sod.Scan(f.ws)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.ViolationsNew != 1 || res.ViolationsOpen != 1 {
		t.Errorf("expected 1 new open violation, got %+v", res)
	}

	// Re-scanning refreshes rather than duplicating, so the count means "how many
	// problems" and not "how many times the scan ran".
	again, err := sod.Scan(f.ws)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if again.ViolationsNew != 0 {
		t.Errorf("a rescan must not create duplicates, got %d new", again.ViolationsNew)
	}
	if n := f.count(t, `SELECT count(*) FROM sod_violations WHERE status='open'`); n != 1 {
		t.Errorf("expected exactly 1 open violation row, found %d", n)
	}

	// Remove the offending access; the next scan closes it rather than leaving a false
	// alarm open forever.
	exec(t, f.raw, `DELETE FROM role_bindings WHERE id = $1`, bid)
	cleared, err := sod.Scan(f.ws)
	if err != nil {
		t.Fatalf("scan after remediation: %v", err)
	}
	if cleared.ViolationsCleared != 1 {
		t.Errorf("expected the violation to be auto-closed, got %+v", cleared)
	}
	var status, note string
	if err := f.raw.QueryRow(`SELECT status, resolution_note FROM sod_violations LIMIT 1`).
		Scan(&status, &note); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != models.SoDViolationRemediated || note == "" {
		t.Errorf("expected remediated with a note, got status=%q note=%q", status, note)
	}
}

// Resolving is a decision somebody answers for, so the note is mandatory.
func TestResolvingAViolationRequiresANote(t *testing.T) {
	f := newProvFixture(t)
	sod := services.NewSoDManager(gormFor(t, f.raw))
	grantRolePermission(t, f, f.role, "governance:admin")

	user := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	bindRoleTo(t, f, f.role, user)
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'no-governance','prohibition','high','any','governance authority',
	            '{governance:admin}','block')`, wsA)
	if _, err := sod.Scan(f.ws); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var vid uuid.UUID
	if err := f.raw.QueryRow(`SELECT id FROM sod_violations LIMIT 1`).Scan(&vid); err != nil {
		t.Fatalf("read violation: %v", err)
	}

	if _, err := sod.ResolveViolation(f.ws, vid, models.SoDViolationAccepted, "", nil); err == nil {
		t.Fatal("accepting a violation with no note must be refused")
	}
	if _, err := sod.ResolveViolation(f.ws, vid, "invented-status", "note", nil); err == nil {
		t.Fatal("an unknown status must be refused")
	}

	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	out, err := sod.ResolveViolation(f.ws, vid, models.SoDViolationAccepted,
		"break-glass account, reviewed by security 2026-08-21", &owner)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Status != models.SoDViolationAccepted || out.ResolvedAt == nil || out.ResolvedBy == nil {
		t.Errorf("acceptance must record who, when, and why: %+v", out)
	}
}

// bindRoleTo binds a role to a user and returns the binding id.
func bindRoleTo(t *testing.T, f provFixture, roleID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.raw, `INSERT INTO role_bindings (id,workspace_id,role_id,user_id,role_name)
	                VALUES ($1,$2,$3,$4,'r')`, id, wsA, roleID, userID)
	return id
}
