package integration

// T5.4 Changes, read side (§5.3 Changes; P2-DECISIONS D-26..D-28, D-68..D-70),
// through the REAL route table over the P2-0 lab: the real scan worker and
// projector with AWS fakes. Each test names the safeguard whose removal must
// make it fail.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const (
	changesDocArchive = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadArchive","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"}]}`
	changesDocArchiveWrite = `{"Version":"2012-10-17","Statement":[{"Sid":"WriteArchive","Effect":"Allow",` +
		`"Action":"s3:PutObject","Resource":"arn:aws:s3:::ticket-archive/*"}]}`
)

// changesRemainingOf returns an end event's remaining grants' policy labels
// and states, and its paths as target label -> remains.
func changesRemainingOf(e map[string]any) (policies map[string]string, paths map[string]string) {
	labels, _ := e["labels"].(map[string]any)
	name := func(ref string) string {
		if s, ok := labels[ref].(string); ok {
			return s
		}
		return ref
	}
	policies, paths = map[string]string{}, map[string]string{}
	for _, r := range digl(e, "remaining") {
		policies[name(digs(r, "policy"))] = digs(r, "state")
	}
	for _, p := range digl(e, "paths") {
		paths[name(digs(p, "target"))] = digs(p, "remains")
	}
	return policies, paths
}

// E6 / T5.4 gate: detach one of two policies granting the same path. Changes
// has policy_detached (and the grant's grant_ended) naming the grant that
// REMAINS -- "the path remains through ToolboxRead" -- with its revision and
// run; the workload that runs as the role shows the same event via the role;
// detaching the last one says no path remains. And the wireframe's case: the
// s3:PutObject grant on ticket-archive/* ends while ArchiveRead's s3:GetObject
// remains on the same target.
//
// Safeguards (mutation-checked): the remaining grants are the SAME HOLDER's
// (OtherRole loses TicketRead in the same run and keeps no path, although
// SharedToolRole's ToolboxRead names the same bucket), on the SAME TARGET
// (ArchiveRead names ticket-archive/*, not support-tickets/*), and non-ended
// (TicketRead's ended grant is no path when ToolboxRead is detached last).
func TestP2ChangesDetachNamesRemainingGrant(t *testing.T) {
	l := newP2Lab(t, "p2-changes-detach", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	toolbox := changesManaged(a, "ToolboxRead", docToolboxRead)
	archiveWrite := changesManaged(a, "ArchiveWrite", changesDocArchiveWrite)
	a.attach("SharedToolRole", ticket)
	a.attach("OtherRole", ticket)
	a.attach("SharedToolRole", toolbox)
	a.attach("SharedToolRole", changesManaged(a, "ArchiveRead", changesDocArchive))
	a.attach("SharedToolRole", archiveWrite)
	a.lambda("us-east-1", "ticket-tools", role)
	run1 := l.scanAndProject(a)
	rev1 := changesRunRev(t, l, run1.ID)

	a.detach("SharedToolRole", ticket)
	a.detach("OtherRole", ticket)
	a.detach("SharedToolRole", archiveWrite)
	run := l.scanAndProject(a)
	rev := changesRunRev(t, l, run.ID)

	api := l.api()
	roleID := changesIdentity(t, l, "SharedToolRole")
	ticketRef := refOf("policy", changesPolicy(t, l, "TicketRead"))
	events := changesAll(t, api, "identity", roleID, "configuration")
	changesAssertAttributed(t, l, events)

	det := changesOne(t, events, "policy_detached", "policy", ticketRef)
	if digs(det, "reason") != models.EndedNotSeen || num(det, "rev") != rev ||
		digs(det, "run") != refOf("cloud_scan_run", run.ID) {
		t.Errorf("policy_detached = reason %q rev %d run %s, want not_seen at rev %d run %s",
			digs(det, "reason"), num(det, "rev"), digs(det, "run"), rev, run.ID)
	}
	pols, paths := changesRemainingOf(det)
	if len(pols) != 1 || pols["ToolboxRead"] != models.RelCurrent {
		t.Errorf("policy_detached remaining = %v, want exactly ToolboxRead's current grant "+
			"(not OtherRole's TicketRead, not ArchiveRead)", pols)
	}
	if len(paths) != 1 || paths["arn:aws:s3:::support-tickets/*"] != "current" {
		t.Errorf("policy_detached paths = %v, want support-tickets/* remains current", paths)
	}
	// A start is attributed to the pass that STARTED it, not a later one that
	// merely confirmed it.
	tbRef := refOf("policy", changesPolicy(t, l, "ToolboxRead"))
	if att := changesOne(t, events, "policy_attached", "policy", tbRef); num(att, "rev") != rev1 ||
		digs(att, "run") != refOf("cloud_scan_run", run1.ID) {
		t.Errorf("ToolboxRead policy_attached = rev %d run %s, want rev %d run %s",
			num(att, "rev"), digs(att, "run"), rev1, run1.ID)
	}
	// "Grant ended s3:PutObject on ticket-archive/* ... the path remains."
	aw := changesOne(t, events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, "ArchiveWrite")))
	if pols, paths := changesRemainingOf(aw); len(pols) != 1 || pols["ArchiveRead"] != models.RelCurrent ||
		len(paths) != 1 || paths["arn:aws:s3:::ticket-archive/*"] != "current" {
		t.Errorf("ArchiveWrite detach remaining = %v paths %v, want exactly ArchiveRead, ticket-archive/* current", pols, paths)
	}

	// The grant's own end carries the same answer.
	var ended []map[string]any
	for _, e := range changesPick(events, "grant_ended", "", "") {
		if digs(e, "detail", "policy") == ticketRef {
			ended = append(ended, e)
		}
	}
	if len(ended) != 1 {
		t.Fatalf("grant_ended for TicketRead = %d, want 1:%s", len(ended), changesDump(events))
	}
	if pols, paths := changesRemainingOf(ended[0]); len(pols) != 1 || pols["ToolboxRead"] != models.RelCurrent ||
		paths["arn:aws:s3:::support-tickets/*"] != "current" {
		t.Errorf("grant_ended remaining = %v paths %v, want ToolboxRead current", pols, paths)
	}
	if acts := changesStrings(dig(ended[0], "detail", "actions")); len(acts) != 1 || acts[0] != "s3:GetObject" {
		t.Errorf("grant_ended actions = %v, want [s3:GetObject]", acts)
	}
	// Labels name the policy the path remains through.
	if got := digs(det, "labels", ticketRef); got != "TicketRead" {
		t.Errorf("labels[%s] = %q, want TicketRead", ticketRef, got)
	}

	// The workload running as the role shows the detach through it (D-68).
	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	wevents := changesAll(t, api, "workload", wl, "configuration")
	changesAssertAttributed(t, l, wevents)
	wdet := changesOne(t, wevents, "policy_detached", "policy", ticketRef)
	if digs(wdet, "via") != refOf("identity", roleID) {
		t.Errorf("workload policy_detached via = %q, want identity:%s", digs(wdet, "via"), roleID)
	}
	changesOne(t, wevents, "first_seen", "subject", refOf("workload", wl))
	changesOne(t, wevents, "relationship_started", "type", models.RelTypeExecutesAs)
	// OtherRole's grants are not the workload's (it never executes as it).
	for _, e := range wevents {
		if h := digs(e, "detail", "holder"); h != "" && h != refOf("identity", roleID) {
			t.Errorf("workload Changes carries %s for holder %s, which it never executes as", digs(e, "event"), h)
		}
	}

	// The resource: grant events of the statements naming it -- the detached
	// grant ended -- and no assignment events (D-68).
	tickets, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	revents := changesAll(t, api, "resource", tickets, "configuration")
	changesAssertAttributed(t, l, revents)
	if n := len(changesPick(revents, "policy_detached", "", "")); n != 0 {
		t.Errorf("resource Changes has %d policy_detached, want none (D-68)", n)
	}
	otherID := changesIdentity(t, l, "OtherRole")
	byHolder := map[string]map[string]any{}
	for _, e := range changesPick(revents, "grant_ended", "", "") {
		if digs(e, "detail", "policy") == ticketRef {
			byHolder[digs(e, "detail", "holder")] = e
		}
	}
	if len(byHolder) != 2 {
		t.Fatalf("resource grant_ended for TicketRead = %d holders, want SharedToolRole and OtherRole:%s",
			len(byHolder), changesDump(revents))
	}
	// Each end is judged for ITS holder: SharedToolRole keeps the path through
	// ToolboxRead; OtherRole has none left, though the same page holds
	// SharedToolRole's remaining grant.
	if pols, paths := changesRemainingOf(byHolder[refOf("identity", roleID)]); len(pols) != 1 ||
		pols["ToolboxRead"] != models.RelCurrent || paths["arn:aws:s3:::support-tickets/*"] != "current" {
		t.Errorf("resource: SharedToolRole's end remaining = %v paths %v, want ToolboxRead current", pols, paths)
	}
	if pols, paths := changesRemainingOf(byHolder[refOf("identity", otherID)]); len(pols) != 0 ||
		paths["arn:aws:s3:::support-tickets/*"] != "none" {
		t.Errorf("resource: OtherRole's end remaining = %v paths %v, want nothing remaining (another holder's "+
			"grant is not OtherRole's path)", pols, paths)
	}

	// Detach the last policy on the path: no path remains.
	a.detach("SharedToolRole", toolbox)
	l.scanAndProject(a)
	events = changesAll(t, api, "identity", roleID, "configuration")
	last := changesOne(t, events, "policy_detached", "policy", tbRef)
	if pols, paths := changesRemainingOf(last); len(pols) != 0 || paths["arn:aws:s3:::support-tickets/*"] != "none" {
		t.Errorf("last detach remaining = %v paths %v, want none remaining and the path none", pols, paths)
	}
}

// D-28: when only a STALE grant remains, the path remains and is marked
// stale -- never "no path remains". ToolboxRead is an attached AWS-managed
// policy whose document becomes unreadable (D-51), so its grant goes stale in
// the same run that detaches TicketRead.
func TestP2ChangesRemainingStaleGrant(t *testing.T) {
	l := newP2Lab(t, "p2-changes-stale-remaining", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	toolbox := "arn:aws:iam::aws:policy/ToolboxRead"
	a.iam.managedPolicies[toolbox] = docToolboxRead
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", toolbox)
	l.scanAndProject(a)

	a.iam.failPolicyVersion[toolbox] = denied("iam:GetPolicyVersion")
	a.detach("SharedToolRole", ticket)
	l.scanAndProject(a)

	if tb := grantsOf(l.grants(), "ToolboxRead"); len(tb) != 1 || tb[0].State != models.RelStale {
		t.Fatalf("setup: ToolboxRead grants = %+v, want one stale", tb)
	}
	events := changesAll(t, l.api(), "identity", changesIdentity(t, l, "SharedToolRole"), "configuration")
	det := changesOne(t, events, "policy_detached", "policy", refOf("policy", changesPolicy(t, l, "TicketRead")))
	pols, paths := changesRemainingOf(det)
	if pols["ToolboxRead"] != models.RelStale || paths["arn:aws:s3:::support-tickets/*"] != "stale" {
		t.Errorf("remaining = %v paths %v, want ToolboxRead stale and the path remaining stale", pols, paths)
	}
	for _, r := range digl(det, "remaining") {
		if digs(r, "last_confirmed_at") == "" {
			t.Errorf("a remaining grant without its last_confirmed_at: %v", r)
		}
	}
}

// changesUnused keeps the uuid import honest in files that only use it via
// helpers.
var _ = uuid.Nil
