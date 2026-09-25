package integration

// B8 (SPEC-iga-phase2-graph.md §7.3; §4.6 "restoration"; §2.4 continuity) and
// B24 (§7.3 lifecycle history), through the REAL scan worker and projector:
// support ends and reappears under the same immutable key -> the SAME object
// comes back; what ended during the gap stays ended; a recognition-only
// workload that returns is a NEW object; and the lifecycle history survives
// every later rewrite of the node row.

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// bdbRestoreLab is a role (immutable RoleId) running a Lambda, holding
// TicketRead -- one cycle, clean.
func bdbRestoreLab(t *testing.T, name string) (*p2Lab, *p2Account) {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	l.scanAndProject(a)
	return l, a
}

// bdbNodeRow is a node's identity-bearing columns.
type bdbNodeRow struct {
	ID            uuid.UUID
	Lifecycle     string
	RetiredReason string
	ImmutableKey  string
	FirstSeenAt   time.Time
}

func bdbNodes(t *testing.T, l *p2Lab, q string, args ...any) []bdbNodeRow {
	t.Helper()
	var out []bdbNodeRow
	if err := l.db.Raw(q, args...).Scan(&out).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return out
}

// bdbEdgesOf is every edge (relationship, assignment, grant) incident on an
// identity, keyed by id.
func bdbEdgesOf(t *testing.T, l *p2Lab, identity uuid.UUID) map[uuid.UUID]bdbEdge {
	t.Helper()
	var rows []bdbEdge
	if err := l.db.Raw(`
		SELECT id, relationship_type AS kind, state, valid_from, valid_to, ended_reason,
		       last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_relationship WHERE workspace_id = ?
		   AND (target_identity_account_id = ? OR source_identity_account_id = ?)
		UNION ALL
		SELECT id, 'assignment', state, valid_from, valid_to, ended_reason, last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
		UNION ALL
		SELECT id, 'grant', state, valid_from, valid_to, ended_reason, last_confirmed_at, last_confirmed_by, connector_id
		  FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws' AND subject_identity_account_id = ?`,
		l.ws, identity, identity, l.ws, identity, l.ws, identity).Scan(&rows).Error; err != nil {
		t.Fatalf("edges of %s: %v", identity, err)
	}
	out := map[uuid.UUID]bdbEdge{}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out
}

// B8, the identity: SharedToolRole is deleted (a clean IAM read no longer
// lists it), so its support ends and it retires unsupported; then it comes
// back with the SAME RoleId. It is RESTORED -- the same row, the same id and
// first_seen_at, its one support row current again with no ended_reason --
// and nothing that ended during the gap is revived: the executes_as, the
// TicketRead assignment and its grant from before stay exactly as they ended,
// and the edges projected on its return are NEW rows (§4.6: "restoring the
// object does not reopen its edges").
//
// Safeguard (mutation-checked): the restoration branch of projectIdentities --
// without it the returning role is treated as a recreation (a new object).
func TestP2BdbRestoredIdentityKeepsItsIdentity(t *testing.T) {
	l, a := bdbRestoreLab(t, "p2-bdb-b8-identity")
	roleID := bdbIdentity(t, l, "SharedToolRole")
	before := bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at
	                            FROM iga_identity_accounts WHERE id = ?`, roleID)[0]
	support := func() []bdbSupport {
		var out []bdbSupport
		for _, s := range bdbSupports(t, l) {
			if s.Object == roleID {
				out = append(out, s)
			}
		}
		return out
	}
	sup1 := support()
	if len(sup1) != 1 {
		t.Fatalf("setup: the role has %d support rows, want 1", len(sup1))
	}
	edges1 := bdbEdgesOf(t, l, roleID)
	for _, k := range []string{models.RelTypeExecutesAs, "assignment", "grant"} {
		found := false
		for _, e := range edges1 {
			found = found || (e.Kind == k && e.State == models.RelCurrent)
		}
		if !found {
			t.Fatalf("setup: no current %s on the role: %+v", k, edges1)
		}
	}

	// The gap: gone from a clean read (iam_roles reached, and the Lambda's
	// role now names nothing in the inventory).
	saved := a.iam.roles
	a.iam.roles = nil
	time.Sleep(10 * time.Millisecond)
	gap := l.scanAndProject(a)
	if cov := models.DecodeScanCoverage(gap.Coverage).Surfaces[models.SurfaceIAMRoles]; cov.State != models.CloudCoverageReached {
		t.Fatalf("setup: iam_roles = %+v on the gap scan, want reached", cov)
	}
	gone := bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at
	                          FROM iga_identity_accounts WHERE id = ?`, roleID)[0]
	if gone.Lifecycle != models.IGALifecycleRetired || gone.RetiredReason != models.RetiredUnsupported {
		t.Fatalf("setup: after the gap the role is %+v, want retired unsupported", gone)
	}
	if s := support(); len(s) != 1 || s[0].State != models.RelEnded || s[0].EndedReason == "" {
		t.Fatalf("setup: the role's support after the gap = %+v, want its one row ended", s)
	}
	edgesGap := bdbEdgesOf(t, l, roleID)
	for id, e := range edgesGap {
		if e.State != models.RelEnded || e.ValidTo == nil {
			t.Fatalf("setup: %s %s = %+v after the gap, want ended", e.Kind, id, e)
		}
	}

	// The return: the SAME RoleId, a clean read.
	a.iam.roles = saved
	time.Sleep(10 * time.Millisecond)
	back := l.scanAndProject(a)

	rows := bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at
	                          FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                           AND display_name = 'SharedToolRole'`, l.ws)
	if len(rows) != 1 {
		t.Fatalf("SharedToolRole rows after its return = %+v, want ONE (restored, not recreated)", rows)
	}
	got := rows[0]
	if got.ID != roleID || !got.FirstSeenAt.Equal(before.FirstSeenAt) || got.ImmutableKey != before.ImmutableKey ||
		got.Lifecycle != models.IGALifecycleActive || got.RetiredReason != "" {
		t.Errorf("returned role = %+v, want the same id %s, first_seen_at %s, active with no retired_reason",
			got, roleID, before.FirstSeenAt)
	}
	// Its support: the SAME row, current, ended_reason cleared, confirmed by
	// the return run (§4.6: UpsertObjectSupport clears ended_reason).
	sup3 := support()
	if len(sup3) != 1 || sup3[0].ID != sup1[0].ID || sup3[0].State != models.RelCurrent || sup3[0].EndedReason != "" ||
		sup3[0].PartitionKey != sup1[0].PartitionKey || sup3[0].ConnectorID != a.conn ||
		sup3[0].LastConfirmedAt == nil || !sup3[0].LastConfirmedAt.Equal(bdbPublishedAt(t, l, back.ID)) {
		t.Errorf("support after the return = %+v, want the same row %s current, no ended_reason, confirmed by the return",
			sup3, sup1[0].ID)
	}
	// Nothing ended during the gap is revived; what the return projects is new.
	edges3 := bdbEdgesOf(t, l, roleID)
	for id, g := range edgesGap {
		e := edges3[id]
		if e.State != models.RelEnded || e.ValidTo == nil || !e.ValidTo.Equal(*g.ValidTo) || e.EndedReason != g.EndedReason {
			t.Errorf("%s %s ended during the gap is now %+v, want it unchanged (%+v)", g.Kind, id, e, g)
		}
	}
	fresh := map[string]int{}
	for id, e := range edges3 {
		if _, old := edgesGap[id]; old {
			continue
		}
		if e.State != models.RelCurrent || !e.ValidFrom.Equal(bdbPublishedAt(t, l, back.ID)) {
			t.Errorf("new %s %s = %+v, want current from the return's pass", e.Kind, id, e)
		}
		fresh[e.Kind]++
	}
	for _, k := range []string{models.RelTypeExecutesAs, "assignment", "grant"} {
		if fresh[k] != 1 {
			t.Errorf("new %s rows on the return = %d, want exactly 1 (a new period, never the old row reopened)", k, fresh[k])
		}
	}
}

// B8, the policy and its statements: a customer-managed policy deleted from
// the account (a clean LocalManagedPolicy read) retires unsupported with its
// statements; recreated with the SAME PolicyId it is restored -- the same
// iga_policy id and first_seen_at, the same statement ids (Sid-keyed and
// Sid-less alike: an unchanged statement keeps its key), each with a
// 'restored' lifecycle event in the return run -- while its assignment is a
// NEW period and the old one stays ended.
//
// Safeguard (mutation-checked): the restoration branches of projectPolicies
// and upsertStatement.
func TestP2BdbRestoredPolicyKeepsItsStatements(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b8-policy", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	doc := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"ReadArchive","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"},` +
		`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::ticket-archive"}]}`
	arn := a.managed("ArchiveRead", doc)
	a.iam.policyIDs[arn] = "ANPAARCHIVEREADARCH1"
	a.attach("SharedToolRole", arn)
	l.scanAndProject(a)

	policy := func() []bdbNodeRow {
		return bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at FROM iga_policy
		                        WHERE workspace_id = ? AND native_ref = ? ORDER BY first_seen_at, id`, l.ws, arn)
	}
	statements := func(policyID uuid.UUID) []bdbNodeRow {
		return bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at FROM iga_entitlements
		                        WHERE workspace_id = ? AND provider = 'aws' AND policy_id = ? ORDER BY statement_index, id`,
			l.ws, policyID)
	}
	p1 := policy()
	if len(p1) != 1 {
		t.Fatalf("setup: ArchiveRead policies = %+v, want 1", p1)
	}
	s1 := statements(p1[0].ID)
	if len(s1) != 2 {
		t.Fatalf("setup: ArchiveRead statements = %+v, want 2", s1)
	}
	asg1 := l.assignments("ArchiveRead")

	// Deleted: detached, and gone from the listing.
	a.detach("SharedToolRole", arn)
	delete(a.iam.managedPolicies, arn)
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	if p := policy(); len(p) != 1 || p[0].Lifecycle != models.IGALifecycleRetired || p[0].RetiredReason != models.RetiredUnsupported {
		t.Fatalf("setup: after deletion the policy is %+v, want retired unsupported", p)
	}
	for _, s := range statements(p1[0].ID) {
		if s.Lifecycle != models.IGALifecycleRetired || s.RetiredReason != models.RetiredUnsupported {
			t.Fatalf("setup: after deletion statement %+v, want retired unsupported", s)
		}
	}

	// Recreated with the SAME PolicyId and the same document, reattached.
	a.managed("ArchiveRead", doc)
	a.attach("SharedToolRole", arn)
	time.Sleep(10 * time.Millisecond)
	back := l.scanAndProject(a)
	backRev := bdbRevOf(t, l, back.ID)

	p3 := policy()
	if len(p3) != 1 || p3[0].ID != p1[0].ID || !p3[0].FirstSeenAt.Equal(p1[0].FirstSeenAt) ||
		p3[0].Lifecycle != models.IGALifecycleActive || p3[0].RetiredReason != "" {
		t.Fatalf("policy after the return = %+v, want ONE row, the same id %s and first_seen_at, active", p3, p1[0].ID)
	}
	s3 := statements(p1[0].ID)
	if len(s3) != len(s1) {
		t.Fatalf("statements after the return = %+v, want the same %d", s3, len(s1))
	}
	for i := range s1 {
		if s3[i].ID != s1[i].ID || !s3[i].FirstSeenAt.Equal(s1[i].FirstSeenAt) ||
			s3[i].Lifecycle != models.IGALifecycleActive || s3[i].RetiredReason != "" {
			t.Errorf("statement %d after the return = %+v, want the same id %s, active", i, s3[i], s1[i].ID)
		}
		if ev := bdbEventsOf(t, l, "entitlement_id", s1[i].ID); len(ev) != 3 || ev[2].Event != models.LifecycleRestored ||
			ev[2].Rev != backRev {
			t.Errorf("statement %d events = %+v, want first_seen, retired, restored at rev %d", i, ev, backRev)
		}
	}
	if ev := bdbEventsOf(t, l, "policy_id", p1[0].ID); len(ev) != 3 || ev[2].Event != models.LifecycleRestored || ev[2].Rev != backRev {
		t.Errorf("policy events = %+v, want first_seen, retired, restored at rev %d", ev, backRev)
	}
	asg3 := l.assignments("ArchiveRead")
	if len(asg1) != 1 || len(asg3) != 2 || asg3[0].ID != asg1[0].ID || asg3[0].State != models.RelEnded ||
		asg3[1].State != models.RelCurrent || asg3[1].ID == asg1[0].ID {
		t.Errorf("assignments = %+v (first %+v), want the old period ended and a NEW current one", asg3, asg1)
	}
}

// B8's other half (§2.4, §4.6's table): a workload is RECOGNITION-ONLY -- no
// creation boundary proves that the function which comes back is the one that
// left. A Lambda confirmed absent (its region's listing reached, the function
// gone) retires unsupported; when a function of the same name returns it is a
// NEW iga_workload row, first seen by the return, and the old row stays
// retired with its own history.
//
// Safeguard (mutation-checked): LoadExisting takes only live workloads as the
// continuing object -- a retired row treated as live would hand the returning
// function the old first_seen_at, and no first_seen event.
func TestP2BdbReturningWorkloadIsANewObject(t *testing.T) {
	l, a := bdbRestoreLab(t, "p2-bdb-b8-workload")
	workloads := func() []bdbNodeRow {
		return bdbNodes(t, l, `SELECT id, lifecycle, retired_reason, immutable_key, first_seen_at FROM iga_workload
		                        WHERE workspace_id = ? AND display_name = 'ticket-tools' ORDER BY first_seen_at, id`, l.ws)
	}
	w1 := workloads()
	if len(w1) != 1 {
		t.Fatalf("setup: workloads = %+v, want 1", w1)
	}

	listsFunctions(a, "us-east-1") // gone, from a clean listing
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	if w := workloads(); len(w) != 1 || w[0].Lifecycle != models.IGALifecycleRetired || w[0].RetiredReason != models.RetiredUnsupported {
		t.Fatalf("setup: after its absence the workload is %+v, want retired unsupported", w)
	}

	listsFunctions(a, "us-east-1", "ticket-tools", a.roleARN("SharedToolRole"))
	time.Sleep(10 * time.Millisecond)
	back := l.scanAndProject(a)
	backAt := bdbPublishedAt(t, l, back.ID)

	w3 := workloads()
	if len(w3) != 2 {
		t.Fatalf("workloads after the return = %+v, want TWO: the old one retired, a new one", w3)
	}
	old, neu := w3[0], w3[1]
	if old.ID != w1[0].ID || old.Lifecycle != models.IGALifecycleRetired || old.RetiredReason != models.RetiredUnsupported {
		t.Errorf("old workload = %+v, want %s still retired unsupported", old, w1[0].ID)
	}
	if neu.ID == old.ID || neu.Lifecycle != models.IGALifecycleActive || !neu.FirstSeenAt.Equal(backAt) {
		t.Errorf("returned workload = %+v, want a NEW active row first seen by the return (%s)", neu, backAt)
	}
	if ev := bdbEventsOf(t, l, "workload_id", neu.ID); len(ev) != 1 || ev[0].Event != models.LifecycleFirstSeen ||
		ev[0].ScanRunID != back.ID {
		t.Errorf("returned workload events = %+v, want exactly one first_seen, by the return run", ev)
	}
	if ev := bdbEventsOf(t, l, "workload_id", old.ID); len(ev) != 2 || ev[0].Event != models.LifecycleFirstSeen ||
		ev[1].Event != models.LifecycleRetired {
		t.Errorf("old workload events = %+v, want first_seen and retired only (never restored)", ev)
	}
	// The new object's execution identity is its own edge.
	var execs []struct {
		Source uuid.UUID
		State  string
	}
	l.db.Raw(`SELECT source_workload_id AS source, state FROM iga_relationship
	           WHERE workspace_id = ? AND relationship_type = 'executes_as' ORDER BY valid_from`, l.ws).Scan(&execs)
	if len(execs) != 2 || execs[0].Source != old.ID || execs[0].State != models.RelEnded ||
		execs[1].Source != neu.ID || execs[1].State != models.RelCurrent {
		t.Errorf("executes_as = %+v, want the old workload's ended and the new one's current", execs)
	}
}

// B24 (§7.3): retire -> restore -> two FURTHER projections that rewrite the
// node row (the role's tags change each time, so provider_attrs and
// last_seen_at are overwritten). The identity's history is still exactly
// first_seen, retired (reason unsupported), restored -- each carrying the
// revision its OWN run published (joined on the run, not merely an existing
// rev), that run, and the pass's timestamp -- and the two later passes add no
// event. The node row alone now says active with no retired_reason; only
// iga_lifecycle_event remembers.
//
// Safeguard (mutation-checked): the projector's EventLog.Restored.
func TestP2BdbLifecycleHistorySurvivesRewrites(t *testing.T) {
	l, a := bdbRestoreLab(t, "p2-bdb-b24")
	roleID := bdbIdentity(t, l, "SharedToolRole")
	var run1 uuid.UUID
	if err := l.db.Raw(`SELECT scan_run_id FROM iga_publication WHERE workspace_id = ? ORDER BY rev LIMIT 1`,
		l.ws).Row().Scan(&run1); err != nil {
		t.Fatalf("first publication: %v", err)
	}

	saved := a.iam.roles
	a.iam.roles = nil
	time.Sleep(10 * time.Millisecond)
	retire := l.scanAndProject(a)
	a.iam.roles = saved
	time.Sleep(10 * time.Millisecond)
	restore := l.scanAndProject(a)

	var attrs []string
	for i, tag := range []string{"platform", "payments"} {
		s3aEditRole(t, a, "SharedToolRole", func(r *iamtypes.Role) {
			r.Tags = []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String(tag)}}
		})
		time.Sleep(10 * time.Millisecond)
		l.scanAndProject(a)
		var pa string
		l.db.Raw(`SELECT provider_attrs::text FROM iga_identity_accounts WHERE id = ?`, roleID).Scan(&pa)
		attrs = append(attrs, pa)
		if i > 0 && attrs[i] == attrs[i-1] {
			t.Fatalf("setup: provider_attrs did not change between the further passes (%s): the node row was not rewritten", pa)
		}
	}
	var row struct {
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT lifecycle, retired_reason FROM iga_identity_accounts WHERE id = ?`, roleID).Scan(&row)
	if row.Lifecycle != models.IGALifecycleActive || row.RetiredReason != "" {
		t.Fatalf("setup: the node row = %+v, want active with no retired_reason (overwritten)", row)
	}

	ev := bdbEventsOf(t, l, "identity_account_id", roleID)
	want := []struct {
		event, reason string
		run           uuid.UUID
	}{
		{models.LifecycleFirstSeen, "", run1},
		{models.LifecycleRetired, models.RetiredUnsupported, retire.ID},
		{models.LifecycleRestored, "", restore.ID},
	}
	if len(ev) != len(want) {
		t.Fatalf("identity events = %+v, want exactly first_seen, retired, restored (the later passes add none)", ev)
	}
	for i, w := range want {
		e := ev[i]
		if e.Event != w.event || e.Reason != w.reason || e.ScanRunID != w.run {
			t.Errorf("event %d = %+v, want %s reason %q in run %s", i, e, w.event, w.reason, w.run)
		}
		if e.PubRev == nil || e.Rev != *e.PubRev || e.PubAt == nil || !e.OccurredAt.Equal(*e.PubAt) {
			t.Errorf("event %d = rev %d at %s; its run published rev %v at %v -- want the same rev and the pass's time",
				i, e.Rev, e.OccurredAt, e.PubRev, e.PubAt)
		}
	}
}
