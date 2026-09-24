package integration

// §7.1 E6 (detach one of two equivalent grants), E7 (policy edits and
// detach/reattach) and E8 (replace a role, and a policy): the backend halves,
// every step through the real §5.3 routes over the §7.1 lab
// (p2_egates_lab_test.go), each rescan by the REAL worker and projector. What
// the console must draw from these answers -- "The path remains through
// ToolboxRead", a solid canvas line, each event worded per §2.6 -- is M3's
// Playwright run against real AWS; here the API those words are drawn from is
// asserted field by field.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// egatesTicketsLines is the workload's Resources tab row for
// support-tickets/*: its grant lines by policy name (a name seen twice
// fails: every E6-E8 step holds at most one line per policy). include_ended
// adds ended lines (D-12).
func egatesTicketsLines(t *testing.T, api *readAPI, workload string, includeEnded bool) map[string]map[string]any {
	t.Helper()
	path := egatesRoute(t, workload, "/resources")
	if includeEnded {
		path += qs("include_ended", "true")
	}
	body := egatesGet(t, api, path)
	egatesNoAccessWording(t, path, body)
	out := map[string]map[string]any{}
	for _, row := range digl(body, "data") {
		if digs(row, "resource", "text") != egatesTickets {
			continue
		}
		for _, ln := range digl(row, "grants") {
			name := digs(ln, "policy", "name")
			if _, dup := out[name]; dup {
				t.Fatalf("%s: two %s lines on support-tickets/*: %s", path, name, egatesJSON(row))
			}
			out[name] = ln.(map[string]any)
		}
	}
	return out
}

// egatesIDSet reads a column of ids into a set.
func egatesIDSet(t *testing.T, l *p2Lab, q string, args ...any) map[uuid.UUID]bool {
	t.Helper()
	var ids []uuid.UUID
	if err := l.db.Raw(q, args...).Scan(&ids).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	out := map[uuid.UUID]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// E6. Detach TicketRead from SharedToolRole and rescan. Database: TicketRead's
// assignment and grant ended with valid_to set; ToolboxRead's grant current.
// API: the Resources tab shows ONE current line (and, with include_ended, the
// ended one beside it); Changes has policy_detached naming the grant that
// remains -- "The path remains through ToolboxRead"; the graph's grant group
// keeps a current member (the canvas line stays solid) and the path search
// still finds the path, through ToolboxRead.
//
// Safeguards (mutation-checked): ended grant lines are not listed by default
// (D-12); a policy_detached's remaining grants are the holder's non-ended
// grants on the same target (D-28).
func TestP2EgatesE6DetachOneOfTwoEquivalentGrants(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e6", true)
	a := egatesProduction(t, l)
	egatesCycle(l, a)
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	role := egatesIdentity(t, l, egatesSharedRole)
	tickets := egatesResource(t, l, egatesTickets)
	ticketStmt, toolboxStmt := graphStatementOf(t, l, egatesTicketRead), graphStatementOf(t, l, egatesToolbox)

	before := egatesTicketsLines(t, api, w, false)
	if len(before) != 2 || digs(before[egatesTicketRead], "state") != models.RelCurrent ||
		digs(before[egatesToolbox], "state") != models.RelCurrent {
		t.Fatalf("setup: support-tickets/* lines before the detach = %s, want TicketRead and ToolboxRead current", egatesJSON(before))
	}
	ticketGrant := digs(before[egatesTicketRead], "claim")

	a.detach(egatesSharedRole, a.policyARN(egatesTicketRead))
	run := egatesCycle(l, a)
	pub := egatesPublicationOf(t, l, run.ID)

	// Database: one assignment and one grant ended, the other current.
	asg := l.assignments(egatesTicketRead)
	if len(asg) != 1 || asg[0].State != models.RelEnded || asg[0].ValidTo == nil || asg[0].EndedReason != models.EndedNotSeen {
		t.Errorf("TicketRead assignments = %+v, want one, ended not_seen with valid_to", asg)
	}
	grants := l.grants()
	if tr := grantsOf(grants, egatesTicketRead); len(tr) != 1 || tr[0].State != models.RelEnded || tr[0].ValidTo == nil ||
		refOf("grant", tr[0].ID) != ticketGrant {
		t.Errorf("TicketRead grants = %+v, want the one grant %s ended with valid_to", tr, ticketGrant)
	}
	if tb := grantsOf(grants, egatesToolbox); len(tb) != 1 || tb[0].State != models.RelCurrent || tb[0].ValidTo != nil {
		t.Errorf("ToolboxRead grants = %+v, want one current", tb)
	}
	if asg := l.assignments(egatesToolbox); len(asg) != 1 || asg[0].State != models.RelCurrent {
		t.Errorf("ToolboxRead assignments = %+v, want one current", asg)
	}
	// The detached policy still exists: its statement is not retired.
	if n := l.count(`SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND id = ? AND lifecycle = 'active'`,
		l.ws, refUUID(t, ticketStmt)); n != 1 {
		t.Errorf("TicketRead's statement is no longer active after a detach (the policy was not deleted)")
	}

	// Resources: ONE current line; the ended one only on request.
	now := egatesTicketsLines(t, api, w, false)
	if len(now) != 1 || now[egatesToolbox] == nil || digs(now[egatesToolbox], "state") != models.RelCurrent ||
		digs(now[egatesToolbox], "statement", "ref") != toolboxStmt {
		t.Errorf("support-tickets/* lines after the detach = %s, want exactly ToolboxRead's, current", egatesJSON(now))
	}
	all := egatesTicketsLines(t, api, w, true)
	ended := all[egatesTicketRead]
	if len(all) != 2 || ended == nil || digs(ended, "state") != models.RelEnded || digs(ended, "claim") != ticketGrant ||
		digs(ended, "valid_to") != s2TS(&pub.PublishedAt) || digs(ended, "ended_reason") != models.EndedNotSeen ||
		digs(all[egatesToolbox], "state") != models.RelCurrent {
		t.Errorf("include_ended lines = %s, want TicketRead ended at %s (not_seen) beside ToolboxRead current",
			egatesJSON(all), s2TS(&pub.PublishedAt))
	}

	// Changes: policy_detached, with the path remaining through ToolboxRead.
	events := changesAll(t, api, "identity", refUUID(t, role), "configuration")
	changesAssertAttributed(t, l, events)
	det := changesOne(t, events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, egatesTicketRead)))
	if num(det, "rev") != pub.Rev || digs(det, "run") != refOf("cloud_scan_run", run.ID) || digs(det, "reason") != models.EndedNotSeen ||
		digs(det, "subject") != refOf("assignment", asg[0].ID) {
		t.Errorf("policy_detached = %s, want assignment %s ended not_seen at rev %d", egatesJSON(det), asg[0].ID, pub.Rev)
	}
	pols, paths := changesRemainingOf(det)
	if len(pols) != 1 || pols[egatesToolbox] != models.RelCurrent || len(paths) != 1 || paths[egatesTickets] != "current" {
		t.Errorf("policy_detached remaining = %v paths = %v, want \"the path remains through ToolboxRead\" (current)", pols, paths)
	}
	if rem := digl(det, "remaining"); len(rem) != 1 || digs(rem[0], "statement") != toolboxStmt ||
		digs(rem[0], "grant") != digs(now[egatesToolbox], "claim") {
		t.Errorf("remaining = %s, want ToolboxRead's grant %s on statement %s", egatesJSON(rem),
			digs(now[egatesToolbox], "claim"), toolboxStmt)
	}
	ge := changesOne(t, events, "grant_ended", "statement", ticketStmt)
	if pols, paths := changesRemainingOf(ge); pols[egatesToolbox] != models.RelCurrent || paths[egatesTickets] != "current" {
		t.Errorf("grant_ended remaining = %v paths = %v, want ToolboxRead current", pols, paths)
	}
	// The workload sees the same detach through the role (D-68).
	wdet := changesOne(t, changesAll(t, api, "workload", refUUID(t, w), "configuration"), "policy_detached", "", "")
	if digs(wdet, "via") != role || digs(wdet, "subject") != digs(det, "subject") {
		t.Errorf("workload policy_detached = %s, want the role's, via %s", egatesJSON(wdet), role)
	}

	// The graph: the path is still drawn, solid. Both statements share one
	// group key (one canvas line); by default only the current grant is on
	// it, and with ended edges the line is "1 current · 1 ended".
	g := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward"))
	grantsNow := graphEdgesOfKind(graphEdges(t, digl(g, "data", "edges")), "grant")
	if len(grantsNow) != 1 || grantsNow[0].To != toolboxStmt || grantsNow[0].State != models.RelCurrent {
		t.Errorf("graph grants after the detach = %+v, want ToolboxRead's, current", grantsNow)
	}
	ge2 := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward", "include_ended", "true"))
	nodes := graphNodes(t, digl(ge2, "data", "nodes"))
	byState := map[string]int{}
	for _, e := range graphEdgesOfKind(graphEdges(t, digl(ge2, "data", "edges")), "grant") {
		if digs(nodes[e.To], "group_key") != digs(nodes[toolboxStmt], "group_key") {
			t.Errorf("grant %s -> %s is not on the support-tickets/* line", e.Claim, e.To)
		}
		byState[e.State]++
	}
	if byState[models.RelCurrent] != 1 || byState[models.RelEnded] != 1 || len(byState) != 2 {
		t.Errorf("the grouped line with ended edges = %v, want 1 current · 1 ended", byState)
	}
	path := egatesGet(t, api, "/graph/path"+qs("from", w, "to", tickets))
	ps := digl(path, "data", "paths")
	if digs(path, "data", "outcome") != "found" || len(ps) != 1 || dig(path, "data", "more_paths") != false {
		t.Fatalf("path after the detach = %s, want found, one path", egatesJSON(dig(path, "data")))
	}
	if refs := graphRefsOfKind(digl(ps[0], "nodes"), "statement"); len(refs) != 1 || refs[0] != toolboxStmt {
		t.Errorf("the remaining path runs through %v, want ToolboxRead's statement %s", refs, toolboxStmt)
	}

	// The ended grant's evidence says it ended, when and why.
	ev := evidenceGet(t, api, ticketGrant)
	if digs(ev, "data", "status", "lifecycle") != models.RelEnded || digs(ev, "data", "freshness", "valid_to") != s2TS(&pub.PublishedAt) ||
		digs(ev, "data", "freshness", "ended_reason") != models.EndedNotSeen {
		t.Errorf("ended grant evidence status/freshness = %s / %s", egatesJSON(dig(ev, "data", "status")), egatesJSON(dig(ev, "data", "freshness")))
	}
	// The resource and the identity say the same: one current holder line.
	acc := egatesGet(t, api, egatesRoute(t, tickets, "/access"))
	if rows := digl(acc, "data", "access"); len(rows) != 1 || digs(rows[0], "policy", "name") != egatesToolbox {
		t.Errorf("support-tickets/* access = %s, want ToolboxRead's grant only", egatesJSON(rows))
	}
	perms := egatesGet(t, api, egatesRoute(t, role, "/permissions"))
	if names := listsField(digl(perms, "data", "policies"), "name"); len(names) != 1 || names[0] != egatesToolbox {
		t.Errorf("SharedToolRole permissions after the detach = %v, want ToolboxRead only", names)
	}
}

// E7, from E6 (TicketRead detached): (a) ReadTickets' actions edited -- the
// SAME statement with a new revision, Changes statement_revised with before
// and after; (b) ToolboxRead's Sid-less statement edited -- the old statement
// retired and a new statement and grant, Changes statement_replaced (never
// shown as an edit); (c) TicketRead reattached -- a NEW assignment row, the
// ended period unchanged, Changes policy_attached.
//
// statement_revised in (a) is on the resource: the role held no grant to
// ReadTickets while it was detached, so D-27d keeps it off the role's and the
// workload's Changes.
//
// Safeguards (mutation-checked): a Sid-keyed edit keeps its statement (a
// statement_revised, never a replacement); a reattach is a new assignment.
func TestP2EgatesE7PolicyEditsAndReattach(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e7", true)
	a := egatesProduction(t, l)
	egatesCycle(l, a)
	a.detach(egatesSharedRole, a.policyARN(egatesTicketRead))
	egatesCycle(l, a) // E6
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	role := egatesIdentity(t, l, egatesSharedRole)
	tickets := egatesResource(t, l, egatesTickets)
	ticketStmt := graphStatementOf(t, l, egatesTicketRead)
	oldToolboxStmt := graphStatementOf(t, l, egatesToolbox)
	e6Assignment := l.assignments(egatesTicketRead)
	if len(e6Assignment) != 1 || e6Assignment[0].ValidTo == nil {
		t.Fatalf("setup: TicketRead's assignment after E6 = %+v", e6Assignment)
	}
	e6End := *e6Assignment[0].ValidTo

	// (a) Edit ReadTickets' actions, with a new default version.
	ticketARN := a.policyARN(egatesTicketRead)
	a.iam.managedPolicies[ticketARN] = evidenceDoc(
		`{"Sid":"ReadTickets","Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"` + egatesTickets + `"}`)
	a.iam.policyVersions[ticketARN] = "v4"
	runA := egatesCycle(l, a)
	if got := graphStatementOf(t, l, egatesTicketRead); got != ticketStmt {
		t.Errorf("(a) the Sid-keyed edit created statement %s, want the same statement %s", got, ticketStmt)
	}
	if n := l.count(`SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?`,
		l.ws, changesPolicy(t, l, egatesTicketRead)); n != 1 {
		t.Errorf("(a) TicketRead has %d statements, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_statement_revision WHERE workspace_id = ? AND entitlement_id = ?`,
		l.ws, refUUID(t, ticketStmt)); n != 2 {
		t.Errorf("(a) ReadTickets revisions = %d, want 2 (the original and the edit)", n)
	}
	revents := changesAll(t, api, "resource", refUUID(t, tickets), "configuration")
	changesAssertAttributed(t, l, revents)
	rv := changesOne(t, revents, "statement_revised", "subject", ticketStmt)
	if digs(rv, "run") != refOf("cloud_scan_run", runA.ID) || dig(rv, "before", "statement", "Action") != "s3:GetObject" ||
		strings.Join(changesStrings(dig(rv, "after", "statement", "Action")), ",") != "s3:GetObject,s3:ListBucket" ||
		digs(rv, "before", "policy_version_id") != "v3" || digs(rv, "after", "policy_version_id") != "v4" {
		t.Errorf("(a) statement_revised = %s, want run %s, s3:GetObject -> [s3:GetObject s3:ListBucket], v3 -> v4",
			egatesJSON(rv), runA.ID)
	}
	if got := changesPick(revents, "statement_replaced", "subject", refOf("policy", changesPolicy(t, l, egatesTicketRead))); len(got) != 0 {
		t.Errorf("(a) a Sid-keyed edit is shown as a replacement:%s", changesDump(got))
	}
	for name, evs := range map[string][]map[string]any{
		"identity": changesAll(t, api, "identity", refUUID(t, role), "configuration"),
		"workload": changesAll(t, api, "workload", refUUID(t, w), "configuration"),
	} {
		if got := changesPick(evs, "statement_revised", "subject", ticketStmt); len(got) != 0 {
			t.Errorf("(a) the %s's Changes carry the revision of a statement it held no grant to at the time (D-27d):%s",
				name, changesDump(got))
		}
	}

	// (b) Edit ToolboxRead's Sid-less statement: a replacement.
	a.iam.managedPolicies[a.policyARN(egatesToolbox)] = evidenceDoc(
		`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"` + egatesTickets + `"}`)
	runB := egatesCycle(l, a)
	newToolboxStmt := graphStatementOf(t, l, egatesToolbox)
	if newToolboxStmt == oldToolboxStmt {
		t.Fatalf("(b) the Sid-less edit kept statement %s, want a new statement", oldToolboxStmt)
	}
	var old struct{ Lifecycle, RetiredReason string }
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_entitlements WHERE id = ?`, refUUID(t, oldToolboxStmt)).Scan(&old)
	if old.Lifecycle != models.IGALifecycleRetired {
		t.Errorf("(b) the replaced statement is %+v, want retired", old)
	}
	tb := grantsOf(l.grants(), egatesToolbox)
	if len(tb) != 2 || tb[0].State != models.RelEnded || refOf("statement", tb[0].StatementID) != oldToolboxStmt ||
		tb[1].State != models.RelCurrent || refOf("statement", tb[1].StatementID) != newToolboxStmt {
		t.Errorf("(b) ToolboxRead grants = %+v, want the old statement's ended and a new current grant on %s", tb, newToolboxStmt)
	}
	events := changesAll(t, api, "identity", refUUID(t, role), "configuration")
	changesAssertAttributed(t, l, events)
	rp := changesOne(t, events, "statement_replaced", "subject", refOf("policy", changesPolicy(t, l, egatesToolbox)))
	if digs(rp, "run") != refOf("cloud_scan_run", runB.ID) || len(digl(rp, "before", "statements")) != 1 ||
		digs(rp, "before", "statements", 0, "statement") != oldToolboxStmt || len(digl(rp, "after", "statements")) != 1 ||
		digs(rp, "after", "statements", 0, "statement") != newToolboxStmt {
		t.Errorf("(b) statement_replaced = %s, want %s replaced by %s in run %s", egatesJSON(rp), oldToolboxStmt, newToolboxStmt, runB.ID)
	}
	for _, s := range []string{oldToolboxStmt, newToolboxStmt} {
		if got := changesPick(events, "statement_revised", "subject", s); len(got) != 0 {
			t.Errorf("(b) the Sid-less edit is shown as an edit of %s:%s", s, changesDump(got))
		}
	}
	lines := egatesTicketsLines(t, api, w, false)
	if len(lines) != 1 || digs(lines[egatesToolbox], "statement", "ref") != newToolboxStmt ||
		strings.Join(wdetailStrings(dig(lines[egatesToolbox], "statement", "actions")), ",") != "s3:GetObject,s3:GetObjectVersion" {
		t.Errorf("(b) support-tickets/* lines = %s, want the new ToolboxRead statement only", egatesJSON(lines))
	}

	// (c) Reattach TicketRead: a NEW assignment row, the ended one untouched.
	a.attach(egatesSharedRole, ticketARN)
	runC := egatesCycle(l, a)
	asg := l.assignments(egatesTicketRead)
	if len(asg) != 2 || asg[0].ID != e6Assignment[0].ID || asg[0].State != models.RelEnded || asg[0].ValidTo == nil ||
		!asg[0].ValidTo.Equal(e6End) || asg[1].ID == asg[0].ID || asg[1].State != models.RelCurrent || asg[1].ValidTo != nil {
		t.Errorf("(c) TicketRead assignments = %+v, want the E6 period ended at %s unchanged and a new current row", asg, e6End)
	}
	tr := grantsOf(l.grants(), egatesTicketRead)
	if len(tr) != 2 || tr[0].State != models.RelEnded || tr[1].State != models.RelCurrent || tr[1].Assignment != asg[1].ID ||
		tr[1].StatementID != refUUID(t, ticketStmt) {
		t.Errorf("(c) TicketRead grants = %+v, want the old one ended and a new one through assignment %s on the same statement", tr, asg[1].ID)
	}
	events = changesAll(t, api, "identity", refUUID(t, role), "configuration")
	changesAssertAttributed(t, l, events)
	att := changesPick(events, "policy_attached", "policy", refOf("policy", changesPolicy(t, l, egatesTicketRead)))
	if len(att) != 2 || digs(att[0], "subject") != refOf("assignment", asg[1].ID) || digs(att[0], "run") != refOf("cloud_scan_run", runC.ID) ||
		digs(att[1], "subject") != refOf("assignment", asg[0].ID) {
		t.Errorf("(c) policy_attached = %s, want the new assignment %s (run %s) newest, the first period's after it",
			changesDump(att), asg[1].ID, runC.ID)
	}
	det := changesPick(events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, egatesTicketRead)))
	if len(det) != 1 || digs(det[0], "subject") != refOf("assignment", asg[0].ID) || digs(det[0], "at") != egatesMicro(e6End) {
		t.Fatalf("(c) the E6 detach = %s, want one, of the first period, at %s", changesDump(det), egatesMicro(e6End))
	}
	// What REMAINS is read at the current revision (D-28): the holder's
	// NON-ENDED grants on the detached period's target -- the new ToolboxRead
	// grant of (b) and the reattached TicketRead of (c) -- never the ToolboxRead
	// grant (b) ended, and never a grant of the detached period itself.
	if len(tb) != 2 || len(tr) != 2 {
		t.Fatalf("setup: ToolboxRead grants %+v, TicketRead grants %+v, want two of each", tb, tr)
	}
	newToolbox := tb[1]
	want := map[string]bool{refOf("grant", newToolbox.ID): true, refOf("grant", tr[1].ID): true}
	got := map[string]string{}
	for _, rm := range digl(det[0], "remaining") {
		got[digs(rm, "grant")] = digs(rm, "state")
	}
	if len(got) != len(want) || got[refOf("grant", newToolbox.ID)] != models.RelCurrent || got[refOf("grant", tr[1].ID)] != models.RelCurrent {
		t.Errorf("(c) the E6 detach's remaining = %s, want exactly the current grants %v (not ToolboxRead's ended %s)",
			egatesJSON(dig(det[0], "remaining")), want, refOf("grant", tb[0].ID))
	}
	if _, paths := changesRemainingOf(det[0]); len(paths) != 1 || paths[egatesTickets] != "current" {
		t.Errorf("(c) the E6 detach's paths = %v, want support-tickets/* remains current", paths)
	}
	lines = egatesTicketsLines(t, api, w, false)
	if len(lines) != 2 || digs(lines[egatesTicketRead], "statement", "ref") != ticketStmt ||
		strings.Join(wdetailStrings(dig(lines[egatesTicketRead], "statement", "actions")), ",") != "s3:GetObject,s3:ListBucket" ||
		digs(lines[egatesTicketRead], "claim") != refOf("grant", tr[1].ID) {
		t.Errorf("(c) support-tickets/* lines = %s, want the revised ReadTickets (new grant %s) beside ToolboxRead", egatesJSON(lines), tr[1].ID)
	}
}

// E8, from E3 with an inline policy ToolsInline on SharedToolRole: (a) the
// role deleted and recreated under the same name with the same inline policy;
// (b) TicketRead deleted and recreated under the same ARN and Sid. Every old
// object stays readable with lifecycle retired; every new one is current with
// NEW ids and keys; the old edges end subject_recreated / policy_recreated; a
// lifecycle event records every transition; nothing of the old history
// appears on the new objects.
//
// Safeguards (mutation-checked): an identity's key is its immutable RoleId,
// so a recreation under the same ARN is a new object.
func TestP2EgatesE8ReplaceRoleAndPolicy(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e8", true)
	a := egatesProduction(t, l)
	a.iam.inlineRolePolicies[egatesSharedRole] = map[string]string{"ToolsInline": evidenceDoc(
		`{"Sid":"ReadArchive","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"}`)}
	pub0 := egatesPublicationOf(t, l, egatesCycle(l, a).ID)
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	oldRole := egatesIdentity(t, l, egatesSharedRole)
	oldInline := changesPolicy(t, l, "ToolsInline")
	oldInlineStmt := graphStatementOf(t, l, "ToolsInline")
	type key struct{ Source, Immutable string }
	keyOf := func(table string, id uuid.UUID) key {
		var k key
		l.db.Raw(`SELECT source_key AS source, immutable_key AS immutable FROM `+table+` WHERE id = ?`, id).Scan(&k)
		return k
	}
	oldRoleKey := keyOf("iga_identity_accounts", refUUID(t, oldRole))
	oldEdges := egatesIDSet(t, l, `SELECT id FROM iga_relationship WHERE workspace_id = ? AND target_identity_account_id = ?
	                                UNION ALL SELECT id FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
	                                UNION ALL SELECT id FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?`,
		l.ws, refUUID(t, oldRole), l.ws, refUUID(t, oldRole), l.ws, refUUID(t, oldRole))
	if len(oldEdges) < 7 { // 2 executes_as, 3 assignments, 3 grants
		t.Fatalf("setup: the old role has %d edges, want its executes_as, assignments and grants", len(oldEdges))
	}

	// (a) The role recreated: same name, new RoleId, same inline policy.
	a.role(egatesSharedRole, "AROAEGATESSHAREDNEW2")
	runR := egatesCycle(l, a)
	newRole := egatesIdentity(t, l, egatesSharedRole)
	newInline := changesPolicy(t, l, "ToolsInline")
	newInlineStmt := graphStatementOf(t, l, "ToolsInline")
	if newRole == oldRole || newInline == oldInline || newInlineStmt == oldInlineStmt {
		t.Fatalf("(a) the recreation reused ids: role %s/%s inline %s/%s statement %s/%s",
			oldRole, newRole, oldInline, newInline, oldInlineStmt, newInlineStmt)
	}
	// A node's recognition key is its ARN (§2.4) and may repeat across a
	// recreation; its creation boundary -- the immutable key -- may not, and
	// neither may any key built from it: statement keys (the policy
	// incarnation) and every edge key (the holder's endpoint, §4.4).
	if k := keyOf("iga_identity_accounts", refUUID(t, newRole)); k.Immutable == "" || k.Immutable == oldRoleKey.Immutable {
		t.Errorf("(a) the new role's immutable key %+v reuses the old role's %+v", k, oldRoleKey)
	}
	if keyOf("iga_policy", newInline).Immutable == keyOf("iga_policy", oldInline).Immutable ||
		keyOf("iga_entitlements", refUUID(t, newInlineStmt)).Source == keyOf("iga_entitlements", refUUID(t, oldInlineStmt)).Source {
		t.Error("(a) the new inline policy's incarnation or its statement's key is the old one's")
	}
	oldEdgeKeys := egatesIDSet(t, l, `SELECT md5(source_key)::uuid FROM iga_relationship WHERE workspace_id = ? AND target_identity_account_id = ?
	                                   UNION ALL SELECT md5(source_key)::uuid FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
	                                   UNION ALL SELECT md5(source_key)::uuid FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?`,
		l.ws, refUUID(t, oldRole), l.ws, refUUID(t, oldRole), l.ws, refUUID(t, oldRole))
	newEdgeKeys := egatesIDSet(t, l, `SELECT md5(source_key)::uuid FROM iga_relationship WHERE workspace_id = ? AND target_identity_account_id = ?
	                                   UNION ALL SELECT md5(source_key)::uuid FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
	                                   UNION ALL SELECT md5(source_key)::uuid FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?`,
		l.ws, refUUID(t, newRole), l.ws, refUUID(t, newRole), l.ws, refUUID(t, newRole))
	if len(newEdgeKeys) < len(oldEdges) {
		t.Errorf("(a) the new role has %d edge keys, want at least the old role's %d edges again", len(newEdgeKeys), len(oldEdges))
	}
	for k := range newEdgeKeys {
		if oldEdgeKeys[k] {
			t.Errorf("(a) a new role edge reuses an old edge key (md5 %s)", k)
		}
	}
	// Database: the old role retired recreated; every one of its edges ended
	// subject_recreated; the old inline policy and its statement retired.
	var life struct{ Lifecycle, RetiredReason string }
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_identity_accounts WHERE id = ?`, refUUID(t, oldRole)).Scan(&life)
	if life.Lifecycle != models.IGALifecycleRetired || life.RetiredReason != models.RetiredRecreated {
		t.Errorf("(a) old role = %+v, want retired recreated", life)
	}
	for id := range oldEdges {
		var e struct{ State, EndedReason string }
		l.db.Raw(`SELECT state, ended_reason FROM iga_relationship WHERE id = ?
		          UNION ALL SELECT state, ended_reason FROM iga_policy_assignment WHERE id = ?
		          UNION ALL SELECT state, ended_reason FROM iga_access_edges WHERE id = ?`, id, id, id).Scan(&e)
		if e.State != models.RelEnded || e.EndedReason != models.EndedSubjectRecreate {
			t.Errorf("(a) old role's edge %s = %+v, want ended subject_recreated", id, e)
		}
	}
	for what, id := range map[string]uuid.UUID{"inline policy": oldInline, "inline statement": refUUID(t, oldInlineStmt)} {
		table := map[string]string{"inline policy": "iga_policy", "inline statement": "iga_entitlements"}[what]
		l.db.Raw(`SELECT lifecycle, retired_reason FROM `+table+` WHERE id = ?`, id).Scan(&life)
		if life.Lifecycle != models.IGALifecycleRetired {
			t.Errorf("(a) old %s = %+v, want retired", what, life)
		}
	}
	// A lifecycle event for every transition of the run.
	type lev struct {
		Event, Reason string
		Subject       uuid.UUID
	}
	var evs []lev
	l.db.Raw(`SELECT event, reason, COALESCE(identity_account_id, policy_id, entitlement_id) AS subject
	            FROM iga_lifecycle_event WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, runR.ID).Scan(&evs)
	want := map[uuid.UUID]string{refUUID(t, oldRole): "retired", refUUID(t, newRole): "first_seen",
		oldInline: "retired", newInline: "first_seen", refUUID(t, oldInlineStmt): "retired", refUUID(t, newInlineStmt): "first_seen"}
	got := map[uuid.UUID]string{}
	for _, e := range evs {
		got[e.Subject] = e.Event
	}
	for id, ev := range want {
		if got[id] != ev {
			t.Errorf("(a) lifecycle event of %s = %q, want %q (events %+v)", id, got[id], ev, evs)
		}
	}

	// API: the old role readable, retired; the new one current; the workload
	// runs as the new one; no old history on the new.
	od := egatesGet(t, api, egatesRoute(t, oldRole))
	// §5.2 "Retired objects": lifecycle, retired_reason and last_confirmed_at
	// -- the last pass that saw the OLD role (the first), never the
	// recreation's.
	if digs(od, "data", "lifecycle") != models.IGALifecycleRetired || digs(od, "data", "retired_reason") != models.RetiredRecreated ||
		digs(od, "data", "ref") != oldRole || digs(od, "data", "last_confirmed_at") != s2TS(&pub0.PublishedAt) {
		t.Errorf("(a) GET old role = %s, want it readable, retired recreated, last confirmed at %s",
			egatesJSON(dig(od, "data")), s2TS(&pub0.PublishedAt))
	}
	nd := egatesGet(t, api, egatesRoute(t, newRole))
	if digs(nd, "data", "lifecycle") != models.IGALifecycleActive || digs(nd, "data", "state") != models.RelCurrent ||
		num(nd, "data", "used_by_count", "value") != 2 {
		t.Errorf("(a) GET new role = %s, want active, current, used by 2", egatesJSON(dig(nd, "data")))
	}
	if ex := digl(egatesGet(t, api, egatesRoute(t, w, "/identities")), "data", "execution", "items"); len(ex) != 1 ||
		digs(ex[0], "identity", "ref") != newRole {
		t.Errorf("(a) ticket-tools execution = %s, want the new role", egatesJSON(ex))
	}
	if used := egatesGet(t, api, egatesRoute(t, oldRole, "/used-by")); len(digl(used, "data", "workloads", "items")) != 0 {
		t.Errorf("(a) the old role is still used by %s", egatesJSON(digl(used, "data", "workloads", "items")))
	}
	fresh := changesGet(t, api, changesPath("identity", refUUID(t, newRole), "limit", "200"))
	begins := digs(fresh, "meta", "history_begins")
	for _, e := range digl(fresh, "data") {
		if digs(e, "at") < begins || digs(e, "run") != refOf("cloud_scan_run", runR.ID) {
			t.Errorf("(a) the new role's Changes carry %s %s from %s (run %s): old history", digs(e, "event"),
				digs(e, "subject"), digs(e, "at"), digs(e, "run"))
		}
	}
	oldEvents := changesAll(t, api, "identity", refUUID(t, oldRole), "configuration")
	if ret := changesOne(t, oldEvents, "retired", "subject", oldRole); digs(ret, "reason") != models.RetiredRecreated {
		t.Errorf("(a) old role's retired event = %s", egatesJSON(ret))
	}

	// (b) TicketRead recreated under the same ARN and Sid (a new PolicyId).
	oldTicket := changesPolicy(t, l, egatesTicketRead)
	oldTicketStmt := graphStatementOf(t, l, egatesTicketRead)
	oldTicketGrant := grantsOf(l.grants(), egatesTicketRead)
	a.iam.policyIDs[a.policyARN(egatesTicketRead)] = "ANPAEGATESTICKETNEW2"
	runP := egatesCycle(l, a)
	newTicket := changesPolicy(t, l, egatesTicketRead)
	newTicketStmt := graphStatementOf(t, l, egatesTicketRead)
	if newTicket == oldTicket || newTicketStmt == oldTicketStmt ||
		keyOf("iga_entitlements", refUUID(t, newTicketStmt)).Source == keyOf("iga_entitlements", refUUID(t, oldTicketStmt)).Source {
		t.Fatalf("(b) the recreated policy reused an id or key: policy %s/%s statement %s/%s", oldTicket, newTicket, oldTicketStmt, newTicketStmt)
	}
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_policy WHERE id = ?`, oldTicket).Scan(&life)
	if life.Lifecycle != models.IGALifecycleRetired || life.RetiredReason != models.RetiredRecreated {
		t.Errorf("(b) old TicketRead = %+v, want retired recreated", life)
	}
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_entitlements WHERE id = ?`, refUUID(t, oldTicketStmt)).Scan(&life)
	if life.Lifecycle != models.IGALifecycleRetired || life.RetiredReason != models.RetiredPolicyRecreated {
		t.Errorf("(b) old ReadTickets statement = %+v, want retired policy_recreated", life)
	}
	var liveOldGrants int
	for _, g := range grantsOf(l.grants(), egatesTicketRead) {
		for _, o := range oldTicketGrant {
			if g.ID == o.ID && o.State != models.RelEnded && (g.State != models.RelEnded || g.EndedReason != models.EndedPolicyRecreated) {
				liveOldGrants++
			}
		}
	}
	if liveOldGrants != 0 {
		t.Errorf("(b) %d grants of the old TicketRead did not end policy_recreated", liveOldGrants)
	}
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ? AND scan_run_id = ?
	                  AND ((policy_id = ? AND event = 'retired') OR (policy_id = ? AND event = 'first_seen')
	                    OR (entitlement_id = ? AND event = 'retired') OR (entitlement_id = ? AND event = 'first_seen'))`,
		l.ws, runP.ID, oldTicket, newTicket, refUUID(t, oldTicketStmt), refUUID(t, newTicketStmt)); n != 4 {
		t.Errorf("(b) lifecycle events for the policy and statement transitions = %d, want 4", n)
	}
	// API: the old statement readable and retired on its grant's evidence;
	// the Resources tab names only the new statement.
	lines := egatesTicketsLines(t, api, w, false)
	if digs(lines[egatesTicketRead], "statement", "ref") != newTicketStmt || digs(lines[egatesTicketRead], "state") != models.RelCurrent {
		t.Errorf("(b) TicketRead line = %s, want the new statement %s", egatesJSON(lines[egatesTicketRead]), newTicketStmt)
	}
	var endedOld string
	for _, g := range grantsOf(l.grants(), egatesTicketRead) {
		if g.StatementID == refUUID(t, oldTicketStmt) && g.EndedReason == models.EndedPolicyRecreated {
			endedOld = refOf("grant", g.ID)
		}
	}
	if endedOld == "" {
		t.Fatalf("(b) no old TicketRead grant ended policy_recreated: %+v", l.grants())
	}
	if ev := evidenceGet(t, api, endedOld); digs(ev, "data", "status", "lifecycle") != models.RelEnded ||
		digs(ev, "data", "freshness", "ended_reason") != models.EndedPolicyRecreated {
		t.Errorf("(b) old grant evidence = %s / %s", egatesJSON(dig(ev, "data", "status")), egatesJSON(dig(ev, "data", "freshness")))
	}
	events := changesAll(t, api, "identity", refUUID(t, newRole), "configuration")
	changesAssertAttributed(t, l, events)
	if det := changesOne(t, events, "policy_detached", "policy", refOf("policy", oldTicket)); digs(det, "reason") != models.EndedPolicyRecreated ||
		digs(det, "run") != refOf("cloud_scan_run", runP.ID) {
		t.Errorf("(b) old TicketRead detach = %s, want policy_recreated in run %s", egatesJSON(det), runP.ID)
	}
	if att := changesOne(t, events, "policy_attached", "policy", refOf("policy", newTicket)); digs(att, "run") != refOf("cloud_scan_run", runP.ID) {
		t.Errorf("(b) new TicketRead attached = %s, want run %s", egatesJSON(att), runP.ID)
	}
	// The recreation's times are the pass's own (D-26).
	pub := egatesPublicationOf(t, l, runP.ID)
	var firstSeen time.Time
	l.db.Raw(`SELECT first_seen_at FROM iga_policy WHERE id = ?`, newTicket).Scan(&firstSeen)
	if !firstSeen.Equal(pub.PublishedAt) {
		t.Errorf("(b) new TicketRead first_seen_at %s, want the recreation's publication %s", firstSeen, pub.PublishedAt)
	}
}
