package integration

// T5.4 Changes over E7, E8, B24 and D-68's workload window, through the real
// route table over the P2-0 lab.

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// changesDocToolboxTwo is ToolboxRead with a second Sid-less statement.
const changesDocToolboxTwo = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"},` +
	`{"Effect":"Allow","Action":"s3:GetObjectTagging","Resource":"arn:aws:s3:::support-tickets/*"}]}`

// E7: (a) a Sid-keyed edit is statement_revised on the SAME statement with
// before and after (content and policy version, D-69); (b) a Sid-less edit is
// statement_replaced -- one statement ending and another beginning -- and the
// old grant's end says the path remains through the new grant; (c) a reattach
// is a NEW assignment period (policy_attached), the earlier detach untouched;
// (d) a Sid-less statement simply deleted is NOT a replacement.
//
// Safeguard (mutation-checked): a replacement's statements ended and began in
// the SAME run.
func TestP2ChangesPolicyEdits(t *testing.T) {
	l := newP2Lab(t, "p2-changes-edits", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	toolbox := changesManaged(a, "ToolboxRead", changesDocToolboxTwo)
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", toolbox)
	l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")
	ticketID := changesPolicy(t, l, "TicketRead")
	stmt := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?`, l.ws, ticketID)

	// (a) Sid edit, with a new default version.
	a.iam.managedPolicies[ticket] = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets","Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:ListBucket"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	a.iam.policyVersions[ticket] = "v4"
	runA := l.scanAndProject(a)

	// (b) Sid-less edit of the first statement.
	a.iam.managedPolicies[toolbox] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Effect":"Allow","Action":"s3:GetObjectTagging","Resource":"arn:aws:s3:::support-tickets/*"}]}`
	runB := l.scanAndProject(a)

	// (c) Detach, then reattach.
	a.detach("SharedToolRole", ticket)
	l.scanAndProject(a)
	a.attach("SharedToolRole", ticket)
	runC := l.scanAndProject(a)

	// (d) The second Sid-less statement deleted, nothing in its place.
	a.iam.managedPolicies[toolbox] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	runD := l.scanAndProject(a)

	api := l.api()
	events := changesAll(t, api, "identity", roleID, "configuration")
	changesAssertAttributed(t, l, events)

	// (a)
	rv := changesOne(t, events, "statement_revised", "subject", refOf("statement", stmt))
	if digs(rv, "run") != refOf("cloud_scan_run", runA.ID) || digs(rv, "detail", "policy") != refOf("policy", ticketID) {
		t.Errorf("statement_revised = run %s policy %s, want run %s policy %s",
			digs(rv, "run"), digs(rv, "detail", "policy"), runA.ID, ticketID)
	}
	before, after := dig(rv, "before", "statement", "Action"), changesStrings(dig(rv, "after", "statement", "Action"))
	if before != "s3:GetObject" || len(after) != 2 || after[1] != "s3:ListBucket" {
		t.Errorf("statement_revised before/after actions = %v / %v, want s3:GetObject / [s3:GetObject s3:ListBucket]",
			before, after)
	}
	if digs(rv, "before", "policy_version_id") != "v3" || digs(rv, "after", "policy_version_id") != "v4" ||
		digs(rv, "before", "content_hash") == digs(rv, "after", "content_hash") {
		t.Errorf("statement_revised versions/hashes = %v -> %v, want v3 -> v4 with a changed hash",
			dig(rv, "before"), dig(rv, "after"))
	}
	if digs(rv, "labels", refOf("statement", stmt)) != "ReadTickets" {
		t.Errorf("statement label = %q, want its Sid", digs(rv, "labels", refOf("statement", stmt)))
	}
	// The Sid edit left its grant alone: no grant_ended for TicketRead in run A.
	for _, e := range changesPick(events, "grant_ended", "policy", refOf("policy", ticketID)) {
		if digs(e, "run") == refOf("cloud_scan_run", runA.ID) {
			t.Errorf("a Sid-keyed edit ended its grant: %v", e)
		}
	}

	// (b)
	toolboxID := changesPolicy(t, l, "ToolboxRead")
	rp := changesOne(t, events, "statement_replaced", "subject", refOf("policy", toolboxID))
	if digs(rp, "run") != refOf("cloud_scan_run", runB.ID) {
		t.Errorf("statement_replaced run = %s, want %s", digs(rp, "run"), runB.ID)
	}
	// (d) is a statement's end and its grant's -- not a replacement.
	var deletedEnd int
	for _, e := range changesPick(events, "grant_ended", "policy", refOf("policy", toolboxID)) {
		if digs(e, "run") == refOf("cloud_scan_run", runD.ID) {
			deletedEnd++
		}
	}
	if deletedEnd != 1 {
		t.Errorf("the deleted statement's grant_ended in run D = %d, want 1:%s", deletedEnd, changesDump(events))
	}
	olds, news := digl(rp, "before", "statements"), digl(rp, "after", "statements")
	if len(olds) != 1 || len(news) != 1 || digs(olds[0], "statement") == digs(news[0], "statement") {
		t.Fatalf("statement_replaced before/after = %v / %v, want one ended and one new statement", olds, news)
	}
	if acts := changesStrings(dig(news[0], "content", "Action")); len(acts) != 2 {
		t.Errorf("statement_replaced new content actions = %v, want the edited two", acts)
	}
	if acts := dig(olds[0], "content", "Action"); acts != "s3:GetObject" {
		t.Errorf("statement_replaced old content action = %v, want the statement as it was", acts)
	}
	var oldEnd map[string]any
	for _, e := range changesPick(events, "grant_ended", "statement", digs(olds[0], "statement")) {
		oldEnd = e
	}
	if oldEnd == nil {
		t.Fatalf("no grant_ended for the replaced statement:%s", changesDump(events))
	}
	if pols, paths := changesRemainingOf(oldEnd); pols["ToolboxRead"] != models.RelCurrent ||
		paths["arn:aws:s3:::support-tickets/*"] != "current" {
		t.Errorf("replaced statement's grant end remaining = %v paths %v, want the new ToolboxRead grant current", pols, paths)
	}
	changesOne(t, events, "grant_started", "statement", digs(news[0], "statement"))

	// (c)
	var attached, detached []map[string]any
	attached = changesPick(events, "policy_attached", "policy", refOf("policy", ticketID))
	detached = changesPick(events, "policy_detached", "policy", refOf("policy", ticketID))
	if len(attached) != 2 || len(detached) != 1 {
		t.Fatalf("TicketRead attached %d / detached %d, want 2 / 1:%s", len(attached), len(detached), changesDump(events))
	}
	// Newest first: the reattach is attached[0], a NEW assignment.
	if digs(attached[0], "run") != refOf("cloud_scan_run", runC.ID) ||
		digs(attached[0], "subject") == digs(detached[0], "subject") ||
		digs(attached[1], "subject") != digs(detached[0], "subject") {
		t.Errorf("reattach = %s (run %s), earlier period %s ended %s: want a new assignment in run %s",
			digs(attached[0], "subject"), digs(attached[0], "run"), digs(attached[1], "subject"),
			digs(detached[0], "subject"), runC.ID)
	}

	// The resource sees the revision and the replacement of the statements
	// naming it (D-68).
	tickets, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	revents := changesAll(t, api, "resource", tickets, "configuration")
	changesAssertAttributed(t, l, revents)
	changesOne(t, revents, "statement_revised", "subject", refOf("statement", stmt))
	changesOne(t, revents, "statement_replaced", "subject", refOf("policy", toolboxID))
}

// E8 (a): a role deleted and recreated under the same name (with a same-named
// inline policy) is a new object. The old role's Changes end: retired
// (recreated), its relationships, assignments and grants ended; the new role's
// start at its own first_seen and carry nothing of the old history. (b) A
// policy recreated under the same ARN: the role sees the old incarnation's
// assignment and grants end policy_recreated and the new ones start.
func TestP2ChangesRecreatedRoleAndPolicy(t *testing.T) {
	l := newP2Lab(t, "p2-changes-recreated", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROAOLDOLDOLDOLDOLD1")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	a.attach("SharedToolRole", ticket)
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": changesDocArchive}
	a.lambda("us-east-1", "ticket-tools", role)
	l.scanAndProject(a)
	oldRole := changesIdentity(t, l, "SharedToolRole")

	a.role("SharedToolRole", "AROANEWNEWNEWNEWNEW2") // same name, new RoleId
	runR := l.scanAndProject(a)
	newRole := changesIdentity(t, l, "SharedToolRole")
	if newRole == oldRole {
		t.Fatal("setup: the recreated role kept its id")
	}

	api := l.api()
	old := changesAll(t, api, "identity", oldRole, "configuration")
	changesAssertAttributed(t, l, old)
	ret := changesOne(t, old, "retired", "subject", refOf("identity", oldRole))
	if digs(ret, "reason") != models.RetiredRecreated || digs(ret, "run") != refOf("cloud_scan_run", runR.ID) {
		t.Errorf("old role retired = reason %q run %s, want recreated in run %s", digs(ret, "reason"), digs(ret, "run"), runR.ID)
	}
	for _, ev := range []string{"relationship_ended", "policy_detached", "grant_ended"} {
		got := changesPick(old, ev, "", "")
		if len(got) == 0 {
			t.Errorf("old role has no %s:%s", ev, changesDump(old))
		}
		for _, e := range got {
			if digs(e, "reason") != models.EndedSubjectRecreate || digs(e, "run") != refOf("cloud_scan_run", runR.ID) {
				t.Errorf("old role %s %s = reason %q run %s, want subject_recreated in run %s",
					ev, digs(e, "subject"), digs(e, "reason"), digs(e, "run"), runR.ID)
			}
		}
	}

	fresh := changesAll(t, api, "identity", newRole, "configuration")
	changesAssertAttributed(t, l, fresh)
	body := changesGet(t, api, changesPath("identity", newRole))
	begins := digs(body, "meta", "history_begins")
	fs := changesOne(t, fresh, "first_seen", "subject", refOf("identity", newRole))
	if begins == "" || digs(fs, "at") != begins || digs(fs, "run") != refOf("cloud_scan_run", runR.ID) {
		t.Errorf("new role first_seen at %s run %s, history_begins %s; want both the recreation run %s",
			digs(fs, "at"), digs(fs, "run"), begins, runR.ID)
	}
	for _, e := range fresh {
		if digs(e, "at") < begins || digs(e, "event") == "retired" || digs(e, "event") == "relationship_ended" ||
			digs(e, "event") == "policy_detached" || digs(e, "event") == "grant_ended" {
			t.Errorf("the new role inherited history: %s %s at %s", digs(e, "event"), digs(e, "subject"), digs(e, "at"))
		}
	}
	// A new inline policy: a different object from the old role's.
	oldInline := changesPick(old, "policy_attached", "", "")
	newInline := changesPick(fresh, "policy_attached", "", "")
	oldPolicies, newPolicies := map[string]bool{}, map[string]bool{}
	for _, e := range oldInline {
		oldPolicies[digs(e, "detail", "policy")] = true
	}
	for _, e := range newInline {
		if oldPolicies[digs(e, "detail", "policy")] && digs(e, "labels", digs(e, "detail", "policy")) == "ToolsInline" {
			t.Errorf("the new role's inline policy is the old role's object %s", digs(e, "detail", "policy"))
		}
		newPolicies[digs(e, "labels", digs(e, "detail", "policy"))] = true
	}
	if !newPolicies["ToolsInline"] || !newPolicies["TicketRead"] {
		t.Errorf("new role attached = %v, want TicketRead and a new ToolsInline", newPolicies)
	}

	// The workload: the old edge ended and a new one started, in that run, and
	// the old role's grants ended through it while the new role's started.
	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	wevents := changesAll(t, api, "workload", wl, "configuration")
	changesAssertAttributed(t, l, wevents)
	var endedVia, startedVia int
	for _, e := range wevents {
		switch {
		case digs(e, "event") == "grant_ended" && digs(e, "via") == refOf("identity", oldRole):
			endedVia++
		case digs(e, "event") == "grant_started" && digs(e, "via") == refOf("identity", newRole):
			startedVia++
		}
	}
	if endedVia == 0 || startedVia == 0 || len(changesPick(wevents, "relationship_ended", "type", "executes_as")) != 1 {
		t.Errorf("workload: %d grants ended via the old role, %d started via the new, want both > 0 and one "+
			"executes_as ended:%s", endedVia, startedVia, changesDump(wevents))
	}

	// (b) The policy recreated under the same ARN.
	oldTicket := changesPolicy(t, l, "TicketRead")
	a.iam.policyIDs[ticket] = "ANPARECREATEDTICKET2"
	runP := l.scanAndProject(a)
	newTicket := changesPolicy(t, l, "TicketRead")
	if newTicket == oldTicket {
		t.Fatal("setup: the recreated policy kept its id")
	}
	fresh = changesAll(t, api, "identity", newRole, "configuration")
	det := changesOne(t, fresh, "policy_detached", "policy", refOf("policy", oldTicket))
	if digs(det, "reason") != models.EndedPolicyRecreated || digs(det, "run") != refOf("cloud_scan_run", runP.ID) {
		t.Errorf("old TicketRead detach = reason %q run %s, want policy_recreated in run %s",
			digs(det, "reason"), digs(det, "run"), runP.ID)
	}
	att := changesOne(t, fresh, "policy_attached", "policy", refOf("policy", newTicket))
	if digs(att, "run") != refOf("cloud_scan_run", runP.ID) {
		t.Errorf("new TicketRead attached in run %s, want %s", digs(att, "run"), runP.ID)
	}
	// Its grant end names the path it leaves: the new incarnation's grant.
	var oldGrantEnd map[string]any
	for _, e := range changesPick(fresh, "grant_ended", "policy", refOf("policy", oldTicket)) {
		oldGrantEnd = e
	}
	if oldGrantEnd == nil || digs(oldGrantEnd, "reason") != models.EndedPolicyRecreated {
		t.Fatalf("old TicketRead grant end = %v, want ended policy_recreated", oldGrantEnd)
	}
	if pols, _ := changesRemainingOf(oldGrantEnd); pols["TicketRead"] != models.RelCurrent {
		t.Errorf("old TicketRead grant end remaining = %v, want the new TicketRead grant", pols)
	}
}

// B24 (§7.3): retire -> restore -> further upserts. Both lifecycle events are
// still in Changes, each with its revision, run and reason, although the node
// row now reads lifecycle 'active' with no retired_reason. Safeguard
// (mutation-checked): lifecycle events come from iga_lifecycle_event, never
// the node row.
func TestP2ChangesLifecycleSurvivesNodeRewrites(t *testing.T) {
	l := newP2Lab(t, "p2-changes-b24", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", changesManaged(a, "TicketRead", docTicketRead))
	run1 := l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")

	saved := a.iam.roles
	a.iam.roles = nil // the role is gone from a clean scan: support ends, it retires
	runRetire := l.scanAndProject(a)
	var life string
	l.db.Raw(`SELECT lifecycle FROM iga_identity_accounts WHERE id = ?`, roleID).Scan(&life)
	if life != models.IGALifecycleRetired {
		t.Fatalf("setup: the role is %q after a clean scan without it, want retired", life)
	}
	a.iam.roles = saved // back with the same RoleId: restored, same id
	runRestore := l.scanAndProject(a)
	l.scanAndProject(a) // two more passes overwrite the node row
	l.scanAndProject(a)

	var row struct {
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_identity_accounts WHERE id = ?`, roleID).Scan(&row)
	if row.Lifecycle != models.IGALifecycleActive || row.RetiredReason != "" {
		t.Fatalf("setup: node row = %+v, want active with no retired_reason (overwritten)", row)
	}

	events := changesAll(t, l.api(), "identity", roleID, "configuration")
	changesAssertAttributed(t, l, events)
	want := []struct {
		event, reason string
		run           string
	}{
		{"first_seen", "", refOf("cloud_scan_run", run1.ID)},
		{"retired", models.RetiredUnsupported, refOf("cloud_scan_run", runRetire.ID)},
		{"restored", "", refOf("cloud_scan_run", runRestore.ID)},
	}
	for _, w := range want {
		e := changesOne(t, events, w.event, "subject", refOf("identity", roleID))
		if digs(e, "reason") != w.reason || digs(e, "run") != w.run || num(e, "rev") != changesRunRev(t, l, refUUID(t, w.run)) {
			t.Errorf("%s = reason %q run %s rev %d, want reason %q run %s", w.event, digs(e, "reason"),
				digs(e, "run"), num(e, "rev"), w.reason, w.run)
		}
	}
	// Its relationships did not survive the gap: the trust edge ended with the
	// retirement and a NEW one started with the restoration (§2.15).
	var ended, started int
	for _, e := range events {
		if digs(e, "detail", "type") != models.RelTypeCanAssume {
			continue
		}
		switch {
		case digs(e, "event") == "relationship_ended" && digs(e, "run") == refOf("cloud_scan_run", runRetire.ID):
			ended++
		case digs(e, "event") == "relationship_started" && digs(e, "run") == refOf("cloud_scan_run", runRestore.ID):
			started++
		}
	}
	if ended != 1 || started != 1 {
		t.Errorf("can_assume ended at retirement %d, started at restoration %d; want 1 and 1:%s", ended, started, changesDump(events))
	}
}

// D-68: a workload's Changes carry its execution identity's permission events
// ONLY while it executed as that identity. Before the switch RoleB's history
// is not the workload's; after it RoleA's is not.
//
// Safeguard (mutation-checked): the executes_as validity window.
func TestP2ChangesWorkloadWindowOnItsRole(t *testing.T) {
	l := newP2Lab(t, "p2-changes-window", true)
	a := l.account(accountA)
	roleA := a.role("RoleA", "AROAROLEAAAAAAAAAAAA")
	roleB := a.role("RoleB", "AROAROLEBBBBBBBBBBBB")
	polA := changesManaged(a, "PolicyA", docTicketRead)
	a.attach("RoleA", polA)
	a.attach("RoleB", changesManaged(a, "PolicyB", changesDocArchive))
	a.lambda("us-east-1", "fn", roleA)
	l.scanAndProject(a)

	a.lambda("us-east-1", "fn", roleB) // the switch
	runSwitch := l.scanAndProject(a)

	a.detach("RoleA", polA) // after the switch: RoleA's, not the workload's
	a.attach("RoleB", changesManaged(a, "PolicyB2", changesDocArchiveWrite))
	runAfter := l.scanAndProject(a)

	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	events := changesAll(t, l.api(), "workload", wl, "configuration")
	changesAssertAttributed(t, l, events)
	a1 := changesIdentity(t, l, "RoleA")
	b1 := changesIdentity(t, l, "RoleB")

	changesOne(t, events, "policy_attached", "policy", refOf("policy", changesPolicy(t, l, "PolicyA")))
	if got := changesPick(events, "policy_attached", "policy", refOf("policy", changesPolicy(t, l, "PolicyB"))); len(got) != 0 {
		t.Errorf("RoleB's attachment from BEFORE the workload ran as it is on the workload's Changes:%s", changesDump(events))
	}
	if got := changesPick(events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, "PolicyA"))); len(got) != 0 {
		t.Errorf("RoleA's detach from AFTER the workload stopped running as it is on the workload's Changes:%s",
			changesDump(events))
	}
	b2 := changesOne(t, events, "policy_attached", "policy", refOf("policy", changesPolicy(t, l, "PolicyB2")))
	if digs(b2, "via") != refOf("identity", b1) || digs(b2, "run") != refOf("cloud_scan_run", runAfter.ID) {
		t.Errorf("PolicyB2 attach = via %s run %s, want via RoleB in run %s", digs(b2, "via"), digs(b2, "run"), runAfter.ID)
	}
	ended := changesOne(t, events, "relationship_ended", "target", refOf("identity", a1))
	started := changesOne(t, events, "relationship_started", "target", refOf("identity", b1))
	if digs(ended, "run") != refOf("cloud_scan_run", runSwitch.ID) || digs(started, "run") != refOf("cloud_scan_run", runSwitch.ID) {
		t.Errorf("role switch: RoleA ended in %s, RoleB started in %s, want both %s",
			digs(ended, "run"), digs(started, "run"), runSwitch.ID)
	}
}

// A Sid-keyed statement removed from its policy and later put back unchanged
// is restored (same statement id), and the revision reopened on it has the
// content of the one that closed: that is a restoration -- its grant ended and
// a new one started -- never a statement_revised with before equal to after.
//
// Safeguard (mutation-checked): a revision event needs a predecessor whose
// content DIFFERS.
func TestP2ChangesRestoredStatementIsNotARevision(t *testing.T) {
	l := newP2Lab(t, "p2-changes-restored-stmt", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	both := `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Sid":"ReadArchive","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"}]}`
	ticket := changesManaged(a, "TicketRead", both)
	a.attach("SharedToolRole", ticket)
	l.scanAndProject(a)
	archiveStmt := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' AND sid = 'ReadArchive'`, l.ws)

	a.iam.managedPolicies[ticket] = docTicketRead // ReadArchive removed
	runGone := l.scanAndProject(a)
	a.iam.managedPolicies[ticket] = both // and back, unchanged
	runBack := l.scanAndProject(a)

	var life string
	l.db.Raw(`SELECT lifecycle FROM iga_entitlements WHERE id = ?`, archiveStmt).Scan(&life)
	if life != "active" || l.count(`SELECT count(*) FROM iga_statement_revision WHERE entitlement_id = ?`, archiveStmt) != 2 {
		t.Fatalf("setup: ReadArchive is %q with %d revisions, want restored (active) with a reopened revision",
			life, l.count(`SELECT count(*) FROM iga_statement_revision WHERE entitlement_id = ?`, archiveStmt))
	}

	api := l.api()
	archive, _ := l.resourceID("arn:aws:s3:::ticket-archive/*")
	for name, events := range map[string][]map[string]any{
		"identity": changesAll(t, api, "identity", changesIdentity(t, l, "SharedToolRole"), "configuration"),
		"resource": changesAll(t, api, "resource", archive, "configuration"),
	} {
		changesAssertAttributed(t, l, events)
		if got := changesPick(events, "statement_revised", "", ""); len(got) != 0 {
			t.Errorf("%s: a restoration is shown as a revision:%s", name, changesDump(got))
		}
		var ended, started bool
		for _, e := range changesPick(events, "grant_ended", "statement", refOf("statement", archiveStmt)) {
			ended = ended || digs(e, "run") == refOf("cloud_scan_run", runGone.ID)
		}
		for _, e := range changesPick(events, "grant_started", "statement", refOf("statement", archiveStmt)) {
			started = started || digs(e, "run") == refOf("cloud_scan_run", runBack.ID)
		}
		if !ended || !started {
			t.Errorf("%s: ReadArchive grant ended in the removal run %v, started in the return run %v; want both:%s",
				name, ended, started, changesDump(events))
		}
	}
}
