package integration

// T5.4 Changes: statement_replaced's identity and its policy versions (D-27c,
// D-69), through the real route table over the P2-0 lab.

import (
	"strings"
	"testing"
)

const (
	changesDocToolboxB = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	changesDocToolboxC = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	changesDocInlineOne = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":"s3:ListBucket","Resource":"arn:aws:s3:::ticket-archive"}]}`
	changesDocInlineTwo = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:ListBucket","s3:GetBucketLocation"],"Resource":"arn:aws:s3:::ticket-archive"}]}`
)

// changesReplacedByRun maps each statement_replaced of one policy to its run.
func changesReplacedByRun(t *testing.T, events []map[string]any, policyRef string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, e := range changesPick(events, "statement_replaced", "subject", policyRef) {
		run := digs(e, "run")
		if out[run] != nil {
			t.Errorf("two statement_replaced for %s in run %s: one event per (policy, run)", policyRef, run)
		}
		out[run] = e
	}
	return out
}

// changesVersions is an event's before/after policy_version_id, "<null>" for
// null and "<absent>" for a missing key.
func changesVersions(e map[string]any) (before, after string) {
	side := func(k string) string {
		m, _ := e[k].(map[string]any)
		v, ok := m["policy_version_id"]
		switch {
		case !ok:
			return "<absent>"
		case v == nil:
			return "<null>"
		}
		s, _ := v.(string)
		return s
	}
	return side("before"), side("after")
}

// A customer-managed policy edited Sid-less three times -- v3 -> v4, a quiet
// rescan, v4 -> v5, then its default set back to v4 -- is three
// statement_replaced events: three ids (D-27: id is unique and stable; one
// event per (policy, run), D-27c), the same three on the resource the
// statements name. Each carries the policy's version before and after
// (D-69), taken from the policy-version observations: after, the version the
// replacing run read; before, the version read by the run that last confirmed
// the ended statement, before the replacement. A version is claimed only
// while the data proves it: once the default returns to v4, the statement run
// C ended is restored and confirmed again (its support row keeps only that
// later confirmation) and the v4 observation's last confirmation moves on, so
// the middle event's before -- read by the quiet rescan -- is no longer
// retained: null, never a guess. An inline policy has no versions: "" on both
// sides, as its revisions store.
//
// Safeguards (mutation-checked): the id is derived from (policy, run); the
// before side reads the ended statements' last confirming runs published
// before the replacement, the after side the replacing run.
func TestP2ChangesReplacementVersionsAndIDs(t *testing.T) {
	l := newP2Lab(t, "p2-changes-replaced", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	toolbox := changesManaged(a, "ToolboxRead", docToolboxRead) // the fake's default version: v3
	a.attach("SharedToolRole", toolbox)
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": changesDocInlineOne}
	l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")

	a.iam.managedPolicies[toolbox] = changesDocToolboxB
	a.iam.policyVersions[toolbox] = "v4"
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": changesDocInlineTwo}
	runB := l.scanAndProject(a)
	l.scanAndProject(a) // the quiet rescan: v4 confirmed again
	a.iam.managedPolicies[toolbox] = changesDocToolboxC
	a.iam.policyVersions[toolbox] = "v5"
	runC := l.scanAndProject(a)

	api := l.api()
	toolboxRef := refOf("policy", changesPolicy(t, l, "ToolboxRead"))
	runRef := func(id string) string { return "cloud_scan_run:" + id }

	// Between C and the revert: C's before is proven by the quiet rescan's
	// confirmation of the v4 observation.
	mid := changesReplacedByRun(t, changesAll(t, api, "identity", roleID, "configuration"), toolboxRef)
	if b, af := changesVersions(mid[runRef(runC.ID.String())]); b != "v4" || af != "v5" {
		t.Errorf("run C's replacement before the revert = %s -> %s, want v4 -> v5", b, af)
	}

	a.iam.managedPolicies[toolbox] = changesDocToolboxB // the default set back to v4
	a.iam.policyVersions[toolbox] = "v4"
	runD := l.scanAndProject(a)

	events := changesAll(t, api, "identity", roleID, "configuration")
	changesAssertAttributed(t, l, events)
	byRun := changesReplacedByRun(t, events, toolboxRef)
	want := []struct {
		run, before, after string
	}{
		{runB.ID.String(), "v3", "v4"},
		{runC.ID.String(), "<null>", "v5"}, // v4's read by the quiet rescan is no longer proven
		{runD.ID.String(), "v5", "v4"},
	}
	if len(byRun) != len(want) {
		t.Fatalf("ToolboxRead statement_replaced = %d events, want %d:%s", len(byRun), len(want), changesDump(events))
	}
	ids := map[string]bool{}
	for _, w := range want {
		e := byRun[runRef(w.run)]
		if e == nil {
			t.Fatalf("no statement_replaced for ToolboxRead in run %s:%s", w.run, changesDump(events))
		}
		if b, af := changesVersions(e); b != w.before || af != w.after {
			t.Errorf("run %s replacement policy_version_id = %s -> %s, want %s -> %s", w.run, b, af, w.before, w.after)
		}
		id := digs(e, "id")
		if ids[id] || !strings.HasPrefix(id, "statement_replaced:") || id == "statement_replaced:"+strings.TrimPrefix(toolboxRef, "policy:") {
			t.Errorf("run %s replacement id %q: want a statement_replaced id of its own, not the policy's", w.run, id)
		}
		ids[id] = true
		if len(digl(e, "before", "statements")) != 1 || len(digl(e, "after", "statements")) != 1 {
			t.Errorf("run %s replacement = %v -> %v, want one statement each side", w.run, dig(e, "before"), dig(e, "after"))
		}
	}

	// The inline policy's replacement: no versions exist, "" on both sides.
	inline := changesReplacedByRun(t, events, refOf("policy", changesPolicy(t, l, "ToolsInline")))
	if e := inline[runRef(runB.ID.String())]; e == nil {
		t.Errorf("no statement_replaced for ToolsInline in run B:%s", changesDump(events))
	} else if b, af := changesVersions(e); b != "" || af != "" {
		t.Errorf("inline replacement policy_version_id = %q -> %q, want \"\" -> \"\"", b, af)
	}

	// The resource names the same three events by the same ids.
	tickets, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	for run, e := range changesReplacedByRun(t, changesAll(t, api, "resource", tickets, "configuration"), toolboxRef) {
		if !ids[digs(e, "id")] {
			t.Errorf("resource: run %s replacement id %s is not the identity's", run, digs(e, "id"))
		}
		delete(ids, digs(e, "id"))
	}
	if len(ids) != 0 {
		t.Errorf("resource: missing replacements %v", ids)
	}
}
