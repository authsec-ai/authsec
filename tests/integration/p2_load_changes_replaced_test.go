package integration

// T6.10 follow-up: statement_replaced after the Changes rewrite.
//
// T6.10 rewrote both statement_replaced branches for speed (internal/igaread
// changes.go): the holders' branch probes the (policy, run) pairs in which a
// statement began as one set (changesBegunInRunSQL), and the resource's
// branch judges each (policy, run) group of lifecycle events with window
// aggregates -- did a statement begin in it (begun), did one that names the
// resource (begun_naming). Two things each rewrite must keep, which the
// earlier Changes suites did not reach:
//
//   - "in the same policy in the same run" (§5.3 l.6050, D-27c): a Sid-less
//     statement deleted in a run in which only ANOTHER policy began a
//     statement is its grant's end, never a replacement. Every earlier lab
//     that deletes a Sid-less statement does it in a run where no other
//     policy changed, so a correlation on the run alone passed them all.
//   - a resource's replacement reached from the NEW side (D-68, D-27c): the
//     statement that began in the ended one's place names the resource, the
//     ended one did not (D-27f: it keeps its last targets). Every earlier
//     replacement named the same resource on both sides.
//
// Both labs run through the REAL scans and projections; nothing is inserted.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// loadSplitBucket is the one reference every statement of the first lab
// names, so the resource's Changes sees both policies.
const loadSplitBucket = "arn:aws:s3:::split-bucket/*"

// loadDocSidless is a policy of Sid-less Allow statements, one per action, all
// naming resource.
func loadDocSidless(resource string, actions ...string) string {
	doc := `{"Version":"2012-10-17","Statement":[`
	for i, a := range actions {
		if i > 0 {
			doc += ","
		}
		doc += `{"Effect":"Allow","Action":"` + a + `","Resource":"` + resource + `"}`
	}
	return doc + `]}`
}

// loadRunOf is the events of one run.
func loadRunOf(events []map[string]any, run uuid.UUID) []map[string]any {
	var out []map[string]any
	for _, e := range events {
		if digs(e, "run") == refOf("cloud_scan_run", run) {
			out = append(out, e)
		}
	}
	return out
}

// A holder attached to two policies naming one bucket. In ONE pass a
// Sid-less statement of SplitOld is deleted (nothing begins in SplitOld) and
// a statement is added to SplitNew. Nothing was replaced: on the identity,
// on the workload that runs as it, and on the bucket, that run shows the
// deleted statement's grant ending and the new one's starting -- and no
// statement_replaced, of either policy.
//
// Safeguards (mutation-checked): the holders' branch correlates the begun
// statement with the ended one's POLICY as well as its run
// (changesBegunInRunSQL); the resource's branch windows by policy and run,
// not by run alone.
func TestP2LoadChangesReplacementStaysInItsPolicy(t *testing.T) {
	l := newP2Lab(t, "p2-load-changes-split", true)
	a := l.account(accountA)
	role := a.role("SplitRole", "AROASPLITROLE0000001")
	oldPol := changesManaged(a, "SplitOld", loadDocSidless(loadSplitBucket, "s3:GetObject", "s3:ListBucket"))
	newPol := changesManaged(a, "SplitNew", loadDocSidless(loadSplitBucket, "s3:GetObjectTagging"))
	a.attach("SplitRole", oldPol)
	a.attach("SplitRole", newPol)
	a.lambda("us-east-1", "splitter", role)
	l.scanAndProject(a)

	oldID, newID := changesPolicy(t, l, "SplitOld"), changesPolicy(t, l, "SplitNew")
	deleted := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?
	                                AND native_rights::text LIKE '%s3:ListBucket%'`, l.ws, oldID)

	a.iam.managedPolicies[oldPol] = loadDocSidless(loadSplitBucket, "s3:GetObject")
	a.iam.policyVersions[oldPol] = "v4"
	a.iam.managedPolicies[newPol] = loadDocSidless(loadSplitBucket, "s3:GetObjectTagging", "s3:PutObject")
	a.iam.policyVersions[newPol] = "v4"
	run := l.scanAndProject(a)

	// The state that makes the correlation matter: in the run, SplitOld's
	// Sid-less statement retired unsupported with nothing beginning in
	// SplitOld, while a statement of SplitNew began.
	added := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?
	                              AND native_rights::text LIKE '%s3:PutObject%'`, l.ws, newID)
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ? AND scan_run_id = ?
	                  AND entitlement_id = ? AND event = 'retired' AND reason = ?`,
		l.ws, run.ID, deleted, models.RetiredUnsupported); n != 1 {
		t.Fatalf("setup: SplitOld's deleted statement retired unsupported in the run %d times, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event le JOIN iga_entitlements e
	                    ON e.workspace_id = le.workspace_id AND e.id = le.entitlement_id
	                  WHERE le.workspace_id = ? AND le.scan_run_id = ? AND e.policy_id = ?
	                    AND le.event IN ('first_seen', 'restored')`, l.ws, run.ID, oldID); n != 0 {
		t.Fatalf("setup: %d statements of SplitOld began in the run, want none", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ? AND scan_run_id = ?
	                  AND entitlement_id = ? AND event = 'first_seen'`, l.ws, run.ID, added); n != 1 {
		t.Fatalf("setup: SplitNew's added statement first seen in the run %d times, want 1", n)
	}

	api := l.api()
	bucket, _ := l.resourceID(loadSplitBucket)
	for _, c := range []struct {
		name    string
		refType string
		id      uuid.UUID
	}{
		{"identity SplitRole", "identity", changesIdentity(t, l, "SplitRole")},
		{"workload splitter", "workload", changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)},
		{"resource split-bucket/*", "resource", bucket},
	} {
		t.Run(c.name, func(t *testing.T) {
			all := changesAll(t, api, c.refType, c.id, "configuration")
			changesAssertAttributed(t, l, all)
			inRun := loadRunOf(all, run.ID)
			if got := changesPick(inRun, "statement_replaced", "", ""); len(got) != 0 {
				t.Errorf("a Sid-less deletion in SplitOld beside a new statement in SplitNew is shown as a replacement"+
					" (SplitOld is %s, SplitNew %s):%s", refOf("policy", oldID), refOf("policy", newID), changesDump(got))
			}
			// What the run did change is there: the deletion and the addition.
			if len(changesPick(inRun, "grant_ended", "statement", refOf("statement", deleted))) != 1 ||
				len(changesPick(inRun, "grant_started", "statement", refOf("statement", added))) != 1 {
				t.Errorf("in the run: want SplitOld's deleted statement's grant_ended and SplitNew's added one's grant_started, once each:%s",
					changesDump(inRun))
			}
		})
	}
}

// A policy's one Sid-less statement naming move-from/* is replaced, in one
// pass, by a Sid-less statement naming move-to/*. The replacement is an
// event of BOTH references (D-68: statement events of the statements naming
// them): move-from/* through the statement that ended (a retired statement
// keeps its last targets, D-27f), move-to/* through the one that began in
// its place -- the only side that names it.
//
// Safeguard (mutation-checked): the resource's replacement branch accepts a
// (policy, run) group in which a statement NAMING the resource began
// (begun_naming), not only one whose ended statement names it.
func TestP2LoadChangesReplacementReachesTheNewTarget(t *testing.T) {
	l := newP2Lab(t, "p2-load-changes-move", true)
	a := l.account(accountA)
	a.role("MoveRole", "AROAMOVEROLE00000001")
	pol := changesManaged(a, "MoveRead", loadDocSidless("arn:aws:s3:::move-from/*", "s3:GetObject"))
	a.attach("MoveRole", pol)
	l.scanAndProject(a)
	polID := changesPolicy(t, l, "MoveRead")
	ended := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ?`, l.ws, polID)

	a.iam.managedPolicies[pol] = loadDocSidless("arn:aws:s3:::move-to/*", "s3:GetObject")
	a.iam.policyVersions[pol] = "v4"
	run := l.scanAndProject(a)
	began := changesIDOf(t, l, `SELECT id FROM iga_entitlements WHERE workspace_id = ? AND policy_id = ? AND id <> ?`,
		l.ws, polID, ended)
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ? AND scan_run_id = ?
	                  AND ((entitlement_id = ? AND event = 'retired' AND reason = ?) OR (entitlement_id = ? AND event = 'first_seen'))`,
		l.ws, run.ID, ended, models.RetiredUnsupported, began); n != 2 {
		t.Fatalf("setup: the run retired the move-from statement (unsupported) and first saw the move-to one in %d of 2 events", n)
	}

	api := l.api()
	for _, text := range []string{"arn:aws:s3:::move-from/*", "arn:aws:s3:::move-to/*"} {
		t.Run(text, func(t *testing.T) {
			id, _ := l.resourceID(text)
			if id == uuid.Nil {
				t.Fatalf("setup: no resource %s", text)
			}
			all := changesAll(t, api, "resource", id, "configuration")
			changesAssertAttributed(t, l, all)
			got := changesPick(all, "statement_replaced", "subject", refOf("policy", polID))
			if len(got) != 1 || digs(got[0], "run") != refOf("cloud_scan_run", run.ID) {
				t.Fatalf("MoveRead's statement_replaced on %s = %d events, want 1 in the replacing run:%s",
					text, len(got), changesDump(all))
			}
			olds, news := digl(got[0], "before", "statements"), digl(got[0], "after", "statements")
			if len(olds) != 1 || len(news) != 1 || digs(olds[0], "statement") != refOf("statement", ended) ||
				digs(news[0], "statement") != refOf("statement", began) {
				t.Errorf("statement_replaced before/after on %s = %v / %v, want the move-from statement / the move-to one",
					text, olds, news)
			}
		})
	}
}
