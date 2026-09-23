package integration

// T5.4 Changes and rule 7 (§3 036: "every grant query joins its statement with
// effect = 'allow'") applied to HISTORY: a grant is judged by its statement as
// it stood when the grant started -- the statement revision in force at its
// valid_from -- never by the statement's current effect. What remains (D-28)
// is judged at the current revision.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const changesDocNoDeletes = `{"Version":"2012-10-17","Statement":[{"Sid":"NoDeletes","Effect":"Deny",` +
	`"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`

// changesGrantEvents are the grant_started / grant_ended events of one grant.
func changesGrantEvents(events []map[string]any, grant uuid.UUID) (started, ended []map[string]any) {
	return changesPick(events, "grant_started", "subject", refOf("grant", grant)),
		changesPick(events, "grant_ended", "subject", refOf("grant", grant))
}

// A Sid-keyed Allow edited to Deny keeps its statement id (§2.6), so its
// effect is updated in place and reconciliation ends its grant. The grant's
// history stays: grant_started in the first run, grant_ended in the edit run
// with the path that remains (ToolboxRead) -- on the identity, on the
// resource it named and on the workload running as the identity. The same
// holds for an assignment's end: ArchiveRead, edited to Deny and detached in
// one run, still names the target its grant reached.
//
// The defence rule 7 exists for still holds: a grant row for a statement that
// was Deny when the row started (seeded directly -- UpsertGrant refuses one,
// so the fakes cannot produce it) is never a Changes event and never a
// remaining path; nor is a live grant of a statement that is Deny NOW (also
// seeded: reconciliation ends it), whatever it was when it started.
//
// Safeguards (mutation-checked): the Allow check reads the revision in force
// at the grant's start, in the holders' branch, the resource branch, the
// grant loader and the detached assignment's targets; the remaining
// candidates keep the current effect (D-27g).
func TestP2ChangesAllowEditedToDeny(t *testing.T) {
	l := newP2Lab(t, "p2-changes-allow-deny", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	archive := changesManaged(a, "ArchiveRead", changesDocArchive)
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", changesManaged(a, "ToolboxRead", docToolboxRead))
	a.attach("SharedToolRole", changesManaged(a, "NoDeletes", changesDocNoDeletes))
	a.attach("SharedToolRole", archive)
	a.attach("OtherRole", archive) // keeps ArchiveRead attached, so the edit is read
	a.lambda("us-east-1", "ticket-tools", role)
	run1 := l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")
	stmtOf := func(policy string) uuid.UUID {
		return changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?`,
			l.ws, changesPolicy(t, l, policy))
	}
	grantOf := func(stmt uuid.UUID) uuid.UUID {
		return changesIDOf(t, l, `SELECT id FROM iga_access_edges WHERE workspace_id = ? AND entitlement_id = ?
		                           AND subject_identity_account_id = ?`, l.ws, stmt, roleID)
	}
	ticketStmt, archiveStmt, denyStmt := stmtOf("TicketRead"), stmtOf("ArchiveRead"), stmtOf("NoDeletes")
	ticketGrant, archiveGrant := grantOf(ticketStmt), grantOf(archiveStmt)

	a.iam.managedPolicies[ticket] = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets","Effect":"Deny",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`
	a.iam.policyVersions[ticket] = "v4"
	a.iam.managedPolicies[archive] = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadArchive","Effect":"Deny",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"}]}`
	a.iam.policyVersions[archive] = "v4"
	a.detach("SharedToolRole", archive)
	run2 := l.scanAndProject(a)

	// Setup: the same statements, now Deny; their grants ended in run 2.
	for stmt, grant := range map[uuid.UUID]uuid.UUID{ticketStmt: ticketGrant, archiveStmt: archiveGrant} {
		var row struct {
			Effect    string
			State     string
			LastRunID uuid.UUID
		}
		l.db.Raw(`SELECT e.effect, g.state, p.scan_run_id AS last_run_id FROM iga_entitlements e
		           JOIN iga_access_edges g ON g.workspace_id = e.workspace_id AND g.id = ?
		           JOIN iga_publication p ON p.workspace_id = g.workspace_id AND p.published_at = g.valid_to
		          WHERE e.id = ?`, grant, stmt).Scan(&row)
		if row.Effect != models.EffectDeny || row.State != models.RelEnded || row.LastRunID != run2.ID {
			t.Fatalf("setup: statement %s / grant %s = %+v, want the same statement now deny and its grant ended in run 2",
				stmt, grant, row)
		}
	}

	// The rule-7 probe: a CURRENT grant row for the Deny statement, as a
	// projector defect would write it -- a copy of the ended TicketRead grant
	// pointed at NoDeletes and its assignment, started in run 2.
	denyAsg := changesIDOf(t, l, `SELECT id FROM iga_policy_assignment WHERE workspace_id = ? AND policy_id = ?
	                               AND holder_identity_account_id = ?`, l.ws, changesPolicy(t, l, "NoDeletes"), roleID)
	var seeded uuid.UUID
	if err := l.db.Raw(`INSERT INTO iga_access_edges
	                    SELECT (jsonb_populate_record(NULL::iga_access_edges, to_jsonb(g) || jsonb_build_object(
	                             'id', gen_random_uuid(), 'entitlement_id', ?::uuid, 'assignment_id', ?::uuid,
	                             'source_key', 'changes-seeded-deny-grant', 'state', 'current', 'valid_to', NULL,
	                             'ended_reason', '', 'valid_from', p.published_at, 'last_confirmed_at', p.published_at,
	                             'last_confirmed_by', p.scan_run_id))).*
	                      FROM iga_access_edges g
	                      JOIN iga_publication p ON p.workspace_id = g.workspace_id AND p.scan_run_id = ?
	                     WHERE g.id = ?
	                    RETURNING id`, denyStmt, denyAsg, run2.ID, ticketGrant).Row().Scan(&seeded); err != nil {
		t.Fatalf("seed a grant for the Deny statement: %v", err)
	}
	// And a CURRENT copy of the ended TicketRead grant, started in run 1 while
	// the statement was still Allow (seeded: reconciliation ended the real
	// one). Its history is an Allow grant's, but TicketRead is Deny NOW, so it
	// is never a path that remains: the candidates keep the current effect.
	var wasAllow uuid.UUID
	if err := l.db.Raw(`INSERT INTO iga_access_edges
	                    SELECT (jsonb_populate_record(NULL::iga_access_edges, to_jsonb(g) || jsonb_build_object(
	                             'id', gen_random_uuid(), 'source_key', 'changes-seeded-was-allow-grant',
	                             'state', 'current', 'valid_to', NULL, 'ended_reason', '',
	                             'last_confirmed_at', p.published_at, 'last_confirmed_by', p.scan_run_id))).*
	                      FROM iga_access_edges g
	                      JOIN iga_publication p ON p.workspace_id = g.workspace_id AND p.scan_run_id = ?
	                     WHERE g.id = ?
	                    RETURNING id`, run2.ID, ticketGrant).Row().Scan(&wasAllow); err != nil {
		t.Fatalf("seed a current grant for the statement now Deny: %v", err)
	}

	api := l.api()
	tickets, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	views := map[string][]map[string]any{
		"identity": changesAll(t, api, "identity", roleID, "configuration"),
		"resource": changesAll(t, api, "resource", tickets, "configuration"),
		"workload": changesAll(t, api, "workload", wl, "configuration"),
	}
	for name, events := range views {
		changesAssertAttributed(t, l, events)
		started, ended := changesGrantEvents(events, ticketGrant)
		if len(started) != 1 || digs(started[0], "run") != refOf("cloud_scan_run", run1.ID) {
			t.Errorf("%s: the edited statement's grant_started = %d events, want 1 in run 1:%s", name, len(started), changesDump(events))
		}
		if len(ended) != 1 || digs(ended[0], "run") != refOf("cloud_scan_run", run2.ID) {
			t.Fatalf("%s: the edited statement's grant_ended = %d events, want 1 in run 2:%s", name, len(ended), changesDump(events))
		}
		if pols, paths := changesRemainingOf(ended[0]); len(pols) != 1 || pols["ToolboxRead"] != models.RelCurrent ||
			len(paths) != 1 || paths["arn:aws:s3:::support-tickets/*"] != "current" {
			t.Errorf("%s: grant_ended remaining = %v paths %v, want exactly ToolboxRead current (never a grant "+
				"of a statement Deny now) and support-tickets/* current", name, pols, paths)
		}
		for _, rm := range digl(ended[0], "remaining") {
			if g := digs(rm, "grant"); g == refOf("grant", seeded) || g == refOf("grant", wasAllow) {
				t.Errorf("%s: grant_ended names %s, a grant of a statement Deny now, as remaining", name, g)
			}
		}
		if name == "workload" && digs(ended[0], "via") != refOf("identity", roleID) {
			t.Errorf("workload: grant_ended via %q, want the role", digs(ended[0], "via"))
		}
		for _, e := range events {
			grantEvent := digs(e, "event") == "grant_started" || digs(e, "event") == "grant_ended"
			if digs(e, "subject") == refOf("grant", seeded) ||
				(grantEvent && digs(e, "detail", "statement") == refOf("statement", denyStmt)) {
				t.Errorf("%s: a grant of a Deny statement is on Changes: %s %s", name, digs(e, "event"), digs(e, "subject"))
			}
		}
	}

	// The identity still sees the edit itself.
	rv := changesOne(t, views["identity"], "statement_revised", "subject", refOf("statement", ticketStmt))
	if digs(rv, "before", "statement", "Effect") != "Allow" || digs(rv, "after", "statement", "Effect") != "Deny" {
		t.Errorf("statement_revised = %v -> %v, want Allow -> Deny", dig(rv, "before"), dig(rv, "after"))
	}

	// ArchiveRead, edited to Deny and detached in one run: its grant's
	// history, and the detach naming the target that grant reached.
	events := views["identity"]
	if started, ended := changesGrantEvents(events, archiveGrant); len(started) != 1 || len(ended) != 1 {
		t.Errorf("ArchiveRead grant: %d started / %d ended, want 1 / 1:%s", len(started), len(ended), changesDump(events))
	}
	det := changesOne(t, events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, "ArchiveRead")))
	if pols, paths := changesRemainingOf(det); len(pols) != 0 || len(paths) != 1 ||
		paths["arn:aws:s3:::ticket-archive/*"] != "none" {
		t.Errorf("ArchiveRead detach remaining = %v paths %v, want nothing remaining and ticket-archive/* none", pols, paths)
	}
}
