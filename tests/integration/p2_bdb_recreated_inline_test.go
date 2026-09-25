package integration

// B21's inline half (SPEC-iga-phase2-graph.md §7.3 B21; §2.4 "an inline policy
// lives and dies with its holder"; §2.7 l.611; §7.1 E8(a)): a role recreated
// under the same name with a same-named inline policy. Through the REAL scan
// worker and projector. TestP2RecreatedRoleIsANewObject checks the two
// incarnations' lifecycle and that no statement key is shared (it catches this
// file's mutation too), and its own mutation (M19) disables IDENTITY
// recreation, so it fails at the identities first; it asserts nothing of the
// new statements (new ids, first_seen events), the old statements' retired
// reason, or how the old inline assignment and grants end. This test does.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// B21, inline: SharedToolRole holds the inline policy ToolsInline -- one
// Sid-keyed and one Sid-less statement -- and runs ticket-tools. It is deleted
// and recreated under the same name (a new RoleId) with the same inline
// document. Then:
//
//   - two ToolsInline policies: the old incarnation retired 'recreated' with
//     the old RoleId as its creation boundary, the new one active with the new;
//   - the old statements retired 'policy_recreated', each with that retired
//     event in the recreating run; the new statements are NEW rows -- new ids,
//     new source keys, first seen by the recreating pass with a first_seen
//     event -- and no statement key or id is shared across incarnations;
//   - the old inline assignment and its grants ENDED, with a reason: the
//     holder's recreation ends them first (subject_recreated), before the
//     policy's own recreation cascade runs; the new incarnation's assignment
//     and grants are new rows on the new identity.
//
// The spec does not name the old inline policy's retired_reason (§2.7 l.611:
// "retires with the old role's incarnation"); the implementation takes the
// policy recreation branch, which is what B21's "Passes when" column names.
//
// Safeguard (mutation-checked): an inline policy's incarnation key is built
// from its holder's ENDPOINT key (the immutable RoleId), never the holder's
// ARN (PolicyIncarnationKey).
func TestP2BdbRecreatedRoleInlinePolicyIsANewIncarnation(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b21-inline", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROAOLDOLDOLDOLDOLD1")
	inline := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"ReadTickets","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::support-tickets"}]}`
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": inline}
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	l.scanAndProject(a)
	oldRole := bdbIdentity(t, l, "SharedToolRole")

	a.role("SharedToolRole", "AROANEWNEWNEWNEWNEW2") // same name, new RoleId
	time.Sleep(10 * time.Millisecond)
	run2 := l.scanAndProject(a)
	at2, rev2 := bdbPublishedAt(t, l, run2.ID), bdbRevOf(t, l, run2.ID)
	newRole := bdbIdentity(t, l, "SharedToolRole")
	if newRole == oldRole {
		t.Fatal("setup: the recreated role reused the old identity")
	}

	// Two incarnations of the policy.
	pols := bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at FROM iga_policy
	                         WHERE workspace_id = ? AND display_name = 'ToolsInline' ORDER BY first_seen_at, id`, l.ws)
	if len(pols) != 2 || pols[0].Lifecycle != models.IGALifecycleRetired || pols[0].RetiredReason != models.RetiredRecreated ||
		pols[0].ImmutableKey != "AROAOLDOLDOLDOLDOLD1" || pols[1].Lifecycle != models.IGALifecycleActive ||
		pols[1].ImmutableKey != "AROANEWNEWNEWNEWNEW2" || !pols[1].FirstSeenAt.Equal(at2) {
		t.Fatalf("ToolsInline policies = %+v, want the old incarnation retired 'recreated' (old RoleId) and a new one first seen at %s", pols, at2)
	}
	oldPol, newPol := pols[0].ID, pols[1].ID
	if ev := bdbEventsOf(t, l, "policy_id", oldPol); len(ev) != 2 || ev[1].Event != models.LifecycleRetired ||
		ev[1].Reason != models.RetiredRecreated || ev[1].Rev != rev2 {
		t.Errorf("old ToolsInline events = %+v, want first_seen then retired 'recreated' at rev %d", ev, rev2)
	}
	if ev := bdbEventsOf(t, l, "policy_id", newPol); len(ev) != 1 || ev[0].Event != models.LifecycleFirstSeen || ev[0].Rev != rev2 {
		t.Errorf("new ToolsInline events = %+v, want one first_seen at rev %d", ev, rev2)
	}

	// Statements: the old ones retired with their policy, the new ones new.
	type stmt struct {
		ID            uuid.UUID
		PolicyID      uuid.UUID
		SourceKey     string
		Sid           string
		Lifecycle     string
		RetiredReason string
		FirstSeenAt   time.Time
	}
	var stmts []stmt
	l.db.Raw(`SELECT id, policy_id, source_key, sid, lifecycle, retired_reason, first_seen_at FROM iga_entitlements
	           WHERE workspace_id = ? AND provider = 'aws' AND policy_id IN (?, ?) ORDER BY first_seen_at, statement_index`,
		l.ws, oldPol, newPol).Scan(&stmts)
	byPolicy := map[uuid.UUID][]stmt{}
	keys := map[string]int{}
	for _, s := range stmts {
		byPolicy[s.PolicyID] = append(byPolicy[s.PolicyID], s)
		keys[s.SourceKey]++
	}
	if len(byPolicy[oldPol]) != 2 || len(byPolicy[newPol]) != 2 {
		t.Fatalf("statements = %+v, want two per incarnation", stmts)
	}
	for _, s := range byPolicy[oldPol] {
		if s.Lifecycle != models.IGALifecycleRetired || s.RetiredReason != models.RetiredPolicyRecreated {
			t.Errorf("old statement %q = %+v, want retired 'policy_recreated'", s.Sid, s)
		}
		if ev := bdbEventsOf(t, l, "entitlement_id", s.ID); len(ev) != 2 || ev[1].Event != models.LifecycleRetired ||
			ev[1].Reason != models.RetiredPolicyRecreated || ev[1].Rev != rev2 {
			t.Errorf("old statement %q events = %+v, want first_seen then retired 'policy_recreated' at rev %d", s.Sid, ev, rev2)
		}
	}
	for _, s := range byPolicy[newPol] {
		if s.Lifecycle != models.IGALifecycleActive || !s.FirstSeenAt.Equal(at2) {
			t.Errorf("new statement %q = %+v, want active, first seen by the recreating pass %s", s.Sid, s, at2)
		}
		if ev := bdbEventsOf(t, l, "entitlement_id", s.ID); len(ev) != 1 || ev[0].Event != models.LifecycleFirstSeen || ev[0].Rev != rev2 {
			t.Errorf("new statement %q events = %+v, want one first_seen at rev %d (a new object, not a continuation)", s.Sid, ev, rev2)
		}
	}
	for key, n := range keys {
		if n != 1 {
			t.Errorf("statement key %q is used by %d rows: the incarnations share a statement key", key, n)
		}
	}

	// Assignment and grants: the old ones ended with a reason, the new ones new.
	var asg []struct {
		ID          uuid.UUID
		PolicyID    uuid.UUID
		Holder      uuid.UUID
		Kind        string
		State       string
		EndedReason string
		ValidTo     *time.Time
	}
	l.db.Raw(`SELECT id, policy_id, holder_identity_account_id AS holder, assignment_kind AS kind, state, ended_reason, valid_to
	            FROM iga_policy_assignment WHERE workspace_id = ? AND policy_id IN (?, ?) ORDER BY valid_from, id`,
		l.ws, oldPol, newPol).Scan(&asg)
	if len(asg) != 2 || asg[0].PolicyID != oldPol || asg[0].Holder != oldRole || asg[0].Kind != models.CloudAttachmentInline ||
		asg[0].State != models.RelEnded || asg[0].EndedReason != models.EndedSubjectRecreate || asg[0].ValidTo == nil ||
		!asg[0].ValidTo.Equal(at2) ||
		asg[1].PolicyID != newPol || asg[1].Holder != newRole || asg[1].State != models.RelCurrent {
		t.Errorf("inline assignments = %+v, want the old one (old role) ended subject_recreated at %s and a new current one on the new role", asg, at2)
	}
	for _, g := range l.grants() {
		if g.Policy != "ToolsInline" {
			continue
		}
		switch {
		case len(asg) == 2 && g.Assignment == asg[0].ID:
			if g.State != models.RelEnded || g.EndedReason != models.EndedSubjectRecreate {
				t.Errorf("old incarnation's grant %s (%s) = %s %q, want ended subject_recreated", g.ID, g.Sid, g.State, g.EndedReason)
			}
		case len(asg) == 2 && g.Assignment == asg[1].ID:
			if g.State != models.RelCurrent {
				t.Errorf("new incarnation's grant %s (%s) = %s, want current", g.ID, g.Sid, g.State)
			}
		default:
			t.Errorf("ToolsInline grant %+v through neither incarnation's assignment", g)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges g JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                  WHERE g.workspace_id = ? AND e.policy_id = ?`, l.ws, newPol); n != 2 {
		t.Errorf("grants on the new incarnation's statements = %d, want 2", n)
	}
}
