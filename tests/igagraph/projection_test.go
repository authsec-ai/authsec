package igagraph_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

const region = "eu-central-1"

// oneLambdaEstate is the P2-0 slice: Lambda -> IAM role -> declared
// entitlement -> resource reference. Nothing else.
type oneLambdaEstate struct {
	role     models.CloudIdentity
	workload models.CloudWorkload
	resource models.CloudResource
	perm     models.CloudPermission
}

func newEstate(roleARN, roleUniqueID string) oneLambdaEstate {
	attrs, _ := json.Marshal(models.AWSIdentityAttrs{UniqueID: roleUniqueID})
	role := models.CloudIdentity{
		ID: uuid.New(), Kind: models.CloudIdentityIAMRole,
		NativeID: roleARN, Name: "refund-lambda-role", Attrs: attrs,
	}
	res := models.CloudResource{
		ID: uuid.New(), Kind: "s3_bucket",
		NativeID: "arn:aws:s3:::refunds-bucket/*", Name: "refunds-bucket",
	}
	return oneLambdaEstate{
		role: role,
		workload: models.CloudWorkload{
			ID: uuid.New(), RuntimeKind: models.WorkloadLambdaFunction,
			NativeID:   "arn:aws:lambda:" + region + ":1234:function:refund-processor",
			Name:       "refund-processor",
			Region:     region,
			IdentityID: &role.ID,
		},
		resource: res,
		perm: models.CloudPermission{
			ID: uuid.New(), IdentityID: role.ID, ResourceID: &res.ID,
			NativeID: "arn:aws:iam::1234:policy/RefundS3Access#s0",
			Effect:   "allow", Actions: pq.StringArray{"s3:GetObject"},
			ScopeKind: "resource", ConstraintState: "unconstrained",
		},
	}
}

func (e oneLambdaEstate) snapshot(f *fixture, run models.CloudScanRun, cov map[string]models.SurfaceCoverage) *igagraph.Snapshot {
	var conn models.CloudConnector
	if err := f.gorm.First(&conn, "id = ?", run.ConnectorID).Error; err != nil {
		f.t.Fatalf("load connector: %v", err)
	}
	return &igagraph.Snapshot{
		Run: run, Connector: conn, Generation: run.Generation,
		Identities:  []models.CloudIdentity{e.role},
		Workloads:   []models.CloudWorkload{e.workload},
		Resources:   []models.CloudResource{e.resource},
		Permissions: []models.CloudPermission{e.perm},
		Coverage:    cov,
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	}
}

/* ============================ acceptance item 1 =========================== */

// ACCEPTANCE 1 / P2-0 scenario 1: an unchanged rescan keeps every id and every
// first_seen_at, advances last_seen_at, and leaves row counts equal.
//
// This is the exit gate's first clause and the reason 027 exists at all:
// before it there was no column a rescan could match on.
func TestRepeatScanKeepsIDs(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run1, cleanCoverage(region)))

	type row struct {
		ID          uuid.UUID
		FirstSeenAt time.Time
		LastSeenAt  time.Time
	}
	snapshotOf := func(table string) map[string]row {
		out := map[string]row{}
		rs, err := f.db.Query(`SELECT source_key, id, first_seen_at, last_seen_at FROM ` + table)
		if err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}
		defer rs.Close()
		for rs.Next() {
			var k string
			var r row
			if err := rs.Scan(&k, &r.ID, &r.FirstSeenAt, &r.LastSeenAt); err != nil {
				t.Fatalf("scan row: %v", err)
			}
			out[k] = r
		}
		return out
	}

	tables := []string{"iga_identity_accounts", "iga_workload", "iga_resources", "iga_entitlements"}
	before := map[string]map[string]row{}
	counts := map[string]int{}
	for _, tbl := range tables {
		before[tbl] = snapshotOf(tbl)
		counts[tbl] = f.scalar(`SELECT count(*) FROM ` + tbl)
		if counts[tbl] == 0 {
			t.Fatalf("%s: first projection wrote nothing -- the test would be vacuous", tbl)
		}
	}
	edgesBefore := f.scalar(`SELECT count(*) FROM iga_access_edges`)
	relsBefore := f.scalar(`SELECT count(*) FROM iga_relationship`)

	// Second scan, same account, nothing changed. Later clock so an advanced
	// last_seen_at is observable and an advanced first_seen_at would be too.
	f.clock = f.clock.Add(24 * time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run2, cleanCoverage(region)))

	for _, tbl := range tables {
		after := snapshotOf(tbl)
		if got := f.scalar(`SELECT count(*) FROM ` + tbl); got != counts[tbl] {
			t.Errorf("%s: row count %d -> %d; a rescan duplicated rows", tbl, counts[tbl], got)
		}
		for key, b := range before[tbl] {
			a, ok := after[key]
			if !ok {
				t.Errorf("%s: source_key %q vanished on rescan", tbl, key)
				continue
			}
			if a.ID != b.ID {
				t.Errorf("%s[%s]: id changed %s -> %s", tbl, key, b.ID, a.ID)
			}
			if !a.FirstSeenAt.Equal(b.FirstSeenAt) {
				t.Errorf("%s[%s]: first_seen_at advanced %s -> %s", tbl, key, b.FirstSeenAt, a.FirstSeenAt)
			}
			if !a.LastSeenAt.After(b.LastSeenAt) {
				t.Errorf("%s[%s]: last_seen_at did not advance (%s)", tbl, key, a.LastSeenAt)
			}
		}
	}
	if got := f.scalar(`SELECT count(*) FROM iga_access_edges`); got != edgesBefore {
		t.Errorf("access edges %d -> %d on an unchanged rescan", edgesBefore, got)
	}
	if got := f.scalar(`SELECT count(*) FROM iga_relationship`); got != relsBefore {
		t.Errorf("relationships %d -> %d on an unchanged rescan", relsBefore, got)
	}
	// Nothing may have ended: this run saw everything.
	if n := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state = 'ended'`); n != 0 {
		t.Errorf("an unchanged rescan ended %d access edges", n)
	}
}

/* ============================ acceptance item 2 =========================== */

// ACCEPTANCE 2 / P2-0 scenario 2: the Lambda is repointed from RoleA to RoleB.
// The old executes_as ENDS with a valid_to, the new one is current, and BOTH
// are readable.
//
// This is what the relationship key naming BOTH endpoints buys. A key naming
// only the workload computes the same value for both, so the upsert would
// overwrite the target in place -- no ended edge, no history, and the exit
// gate silently failing.
func TestRoleReplacementClosesOldEdge(t *testing.T) {
	f := newFixture(t)
	estA := newEstate("arn:aws:iam::1234:role/RoleA", "AROAAAAAAAAAAAAAAAAAA")

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(estA.snapshot(f, run1, cleanCoverage(region)))

	if n := f.scalar(`SELECT count(*) FROM iga_relationship
	                   WHERE relationship_type='executes_as' AND state='current'`); n != 1 {
		t.Fatalf("want 1 current executes_as after the first scan, got %d", n)
	}

	// Same Lambda, now running as RoleB. Both roles exist in the estate.
	estB := newEstate("arn:aws:iam::1234:role/RoleB", "AROABBBBBBBBBBBBBBBBB")
	estB.workload = estA.workload
	estB.workload.IdentityID = &estB.role.ID

	f.clock = f.clock.Add(time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	snap := estB.snapshot(f, run2, cleanCoverage(region))
	// RoleA is gone from the account; only RoleB is read this run.
	f.mustProject(snap)

	var ended, current int
	if err := f.db.QueryRow(`
		SELECT count(*) FILTER (WHERE state='ended'),
		       count(*) FILTER (WHERE state='current')
		  FROM iga_relationship WHERE relationship_type='executes_as'`).
		Scan(&ended, &current); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ended != 1 {
		t.Errorf("want the RoleA edge ended, got %d ended", ended)
	}
	if current != 1 {
		t.Errorf("want the RoleB edge current, got %d current", current)
	}

	// The ended row must carry a valid_to and a reason -- 030's CHECKs demand
	// both, and a reviewer reading history needs them.
	var validTo *time.Time
	var reason string
	if err := f.db.QueryRow(`SELECT valid_to, ended_reason FROM iga_relationship
	                          WHERE relationship_type='executes_as' AND state='ended'`).
		Scan(&validTo, &reason); err != nil {
		t.Fatalf("read ended edge: %v", err)
	}
	if validTo == nil {
		t.Error("an ended edge must carry valid_to")
	}
	if reason == "" {
		t.Error("an ended edge must carry ended_reason")
	}
	// BOTH readable: history is never deleted.
	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE relationship_type='executes_as'`); n != 2 {
		t.Errorf("want both edges retained, got %d rows", n)
	}
}

/* ============================ acceptance item 4 =========================== */

// ACCEPTANCE 4 / P2-8: a role deleted and recreated under the SAME NAME is a
// NEW OBJECT.
//
// Same ARN, therefore the same source_key -- but a different RoleId, which is
// the creation boundary. Merging them would carry last quarter's ownership
// decision and review history onto an unrelated principal.
func TestRecreatedRoleIsANewObject(t *testing.T) {
	f := newFixture(t)
	est1 := newEstate("arn:aws:iam::1234:role/deploy", "AROAOLDOLDOLDOLDOLDO")

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est1.snapshot(f, run1, cleanCoverage(region)))

	var oldID uuid.UUID
	var oldFirstSeen time.Time
	if err := f.db.QueryRow(`SELECT id, first_seen_at FROM iga_identity_accounts
	                          WHERE account_kind='iam_role'`).Scan(&oldID, &oldFirstSeen); err != nil {
		t.Fatalf("read original role: %v", err)
	}

	// Deleted and recreated: same name, same ARN, NEW RoleId.
	est2 := newEstate("arn:aws:iam::1234:role/deploy", "AROANEWNEWNEWNEWNEWN")
	f.clock = f.clock.Add(48 * time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	f.mustProject(est2.snapshot(f, run2, cleanCoverage(region)))

	// Two rows: the old one retired 'recreated', the new one active with its
	// OWN first_seen_at.
	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE account_kind='iam_role'`); n != 2 {
		t.Fatalf("want 2 identity rows after a recreate, got %d", n)
	}
	var retiredReason string
	if err := f.db.QueryRow(`SELECT retired_reason FROM iga_identity_accounts
	                          WHERE id=$1 AND lifecycle='retired'`, oldID).Scan(&retiredReason); err != nil {
		t.Fatalf("old row should be retired: %v", err)
	}
	if retiredReason != models.RetiredRecreated {
		t.Errorf("want retired_reason %q, got %q", models.RetiredRecreated, retiredReason)
	}

	var newID uuid.UUID
	var newFirstSeen time.Time
	if err := f.db.QueryRow(`SELECT id, first_seen_at FROM iga_identity_accounts
	                          WHERE account_kind='iam_role' AND lifecycle='active'`).
		Scan(&newID, &newFirstSeen); err != nil {
		t.Fatalf("read new role: %v", err)
	}
	if newID == oldID {
		t.Error("a recreated role must get a NEW id")
	}
	if !newFirstSeen.After(oldFirstSeen) {
		t.Errorf("a recreated role must get a fresh first_seen_at (old %s, new %s)", oldFirstSeen, newFirstSeen)
	}

	// The retired row KEEPS its source_key -- the partial unique index depends
	// on it to let both rows coexist.
	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts
	                   WHERE lifecycle='retired' AND source_key <> ''`); n != 1 {
		t.Error("a retired row must keep its source_key")
	}
	// Its edges ended, with the recreate reason.
	if n := f.scalar(`SELECT count(*) FROM iga_relationship
	                   WHERE state='ended' AND ended_reason=$1`, models.EndedSubjectRecreate); n == 0 {
		t.Error("a recreate must end the old object's relationships")
	}
}

/* ============================ acceptance item 8 =========================== */

// ACCEPTANCE 8 / P2-0 scenario: A DENIED SCAN NEVER ENDS ANYTHING.
//
// IAM is denied on the second scan, so no identities, workloads or
// permissions are read. Everything moves to stale with its last confirmation
// time INTACT, and ZERO ROWS END. This is the reason canEnd exists.
func TestDeniedScanEndsNothing(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run1, cleanCoverage(region)))

	edges := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='current'`)
	rels := f.scalar(`SELECT count(*) FROM iga_relationship WHERE state='current'`)
	if edges == 0 || rels == 0 {
		t.Fatal("first projection wrote no live edges -- the test would be vacuous")
	}
	var confirmedBefore time.Time
	if err := f.db.QueryRow(`SELECT min(last_confirmed_at) FROM iga_relationship`).
		Scan(&confirmedBefore); err != nil {
		t.Fatalf("read last_confirmed_at: %v", err)
	}

	// Second run: the whole scan was denied -- IAM AND the compute regions the
	// first run reached. A realistic "access revoked mid-life" outage denies
	// across the board; a fixture that named only IAM would leave the
	// executes_as partition out of run 2's list entirely (no region attempted),
	// and the edge would stay current for lack of a partition to mark it,
	// rather than for any reconciliation decision.
	deniedCov := map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:        denied(),
		models.SurfaceIAMUsers:        denied(),
		models.SurfaceIAMPolicies:     denied(),
		"lambda:" + region:            denied(),
		"ecs:" + region:               denied(),
		"ec2:" + region:               denied(),
		"bedrock-agents:" + region:    denied(),
		"bedrock-agentcore:" + region: denied(),
	}
	f.clock = f.clock.Add(6 * 24 * time.Hour)
	run2 := f.publishedRun(f.connector, 2, deniedCov)
	var conn models.CloudConnector
	if err := f.gorm.First(&conn, "id = ?", f.connector).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	empty := &igagraph.Snapshot{
		Run: run2, Connector: conn, Generation: 2,
		Coverage:    deniedCov,
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	}
	f.mustProject(empty)

	if n := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='ended'`); n != 0 {
		t.Errorf("a denied scan ended %d access edges; it must end ZERO", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE state='ended'`); n != 0 {
		t.Errorf("a denied scan ended %d relationships; it must end ZERO", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_relationship WHERE state='stale'`); n != rels {
		t.Errorf("want all %d relationships stale, got %d", rels, n)
	}
	// No node may be retired either -- support went stale, not ended.
	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE lifecycle='retired'`); n != 0 {
		t.Errorf("a denied scan retired %d identities; it must retire ZERO", n)
	}

	// last_confirmed_at is NOT refreshed: it is the honest answer to "how old
	// is this?", and advancing it would launder an outage into a confirmation.
	var confirmedAfter time.Time
	if err := f.db.QueryRow(`SELECT min(last_confirmed_at) FROM iga_relationship`).
		Scan(&confirmedAfter); err != nil {
		t.Fatalf("read last_confirmed_at: %v", err)
	}
	if !confirmedAfter.Equal(confirmedBefore) {
		t.Errorf("a denied scan refreshed last_confirmed_at %s -> %s", confirmedBefore, confirmedAfter)
	}
}

// NON-VACUITY for the test above: the SAME empty snapshot under CLEAN coverage
// DOES end everything. Without this, a reconciler that never ended anything
// would pass TestDeniedScanEndsNothing.
func TestCleanScanThatSeesNothingDoesEnd(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")

	run1 := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run1, cleanCoverage(region)))
	if f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='current'`) == 0 {
		t.Fatal("first projection wrote no live edges")
	}

	// Clean coverage, empty inventory: the account really was emptied.
	f.clock = f.clock.Add(time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	var conn models.CloudConnector
	if err := f.gorm.First(&conn, "id = ?", f.connector).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	f.mustProject(&igagraph.Snapshot{
		Run: run2, Connector: conn, Generation: 2,
		Coverage:    cleanCoverage(region),
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	})

	if n := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='ended'`); n == 0 {
		t.Error("a clean scan that saw nothing must end the edges it no longer sees")
	}
	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts
	                   WHERE lifecycle='retired' AND retired_reason=$1`,
		models.RetiredUnsupported); n == 0 {
		t.Error("an identity no source still supports must retire as unsupported")
	}
}

/* ========================= §2.10B -- shared nodes ========================== */

// §2.10B: two AWS accounts in one workspace both name the SAME bucket.
//
//	A and B both support resource R
//	B scans last, so a node-level connector_id would record B as its owner
//	B stops naming it
//	B's reconciliation retires R -- WHILE A STILL HOLDS IT
//
// Serialization does not help; the sequence is already sequential and still
// wrong. Support rows are what make it correct.
func TestSharedResourceSurvivesOneAccountDroppingIt(t *testing.T) {
	f := newFixture(t)
	connB := f.addConnector("222222222222")

	// Account A names the bucket.
	estA := newEstate("arn:aws:iam::1111:role/a-role", "AROAAAAAAAAAAAAAAAAAA")
	runA := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(estA.snapshot(f, runA, cleanCoverage(region)))

	// Account B names the SAME bucket -- same ARN, therefore ONE object.
	estB := newEstate("arn:aws:iam::2222:role/b-role", "AROABBBBBBBBBBBBBBBBB")
	estB.resource = estA.resource // the identical ARN
	estB.perm.ResourceID = &estB.resource.ID
	f.clock = f.clock.Add(time.Hour)
	runB := f.publishedRun(connB, 1, cleanCoverage(region))
	f.mustProject(estB.snapshot(f, runB, cleanCoverage(region)))

	// ONE resource object, TWO support rows (§2.12's first table row).
	if n := f.scalar(`SELECT count(*) FROM iga_resources WHERE lifecycle='active'`); n != 1 {
		t.Fatalf("one bucket ARN must be ONE object, got %d", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_object_support
	                   WHERE object_type='resource' AND state='current'`); n != 2 {
		t.Fatalf("want 2 support rows for the shared bucket, got %d", n)
	}

	// B rescans and no longer names the bucket, under CLEAN coverage.
	f.clock = f.clock.Add(time.Hour)
	runB2 := f.publishedRun(connB, 2, cleanCoverage(region))
	var conn models.CloudConnector
	if err := f.gorm.First(&conn, "id = ?", connB).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	f.mustProject(&igagraph.Snapshot{
		Run: runB2, Connector: conn, Generation: 2,
		Identities:  []models.CloudIdentity{estB.role},
		Coverage:    cleanCoverage(region),
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	})

	// B's support ended; A's did not; the OBJECT SURVIVES.
	if n := f.scalar(`SELECT count(*) FROM iga_object_support
	                   WHERE object_type='resource' AND connector_id=$1 AND state='ended'`, connB); n != 1 {
		t.Error("B's support of the bucket should have ended")
	}
	if n := f.scalar(`SELECT count(*) FROM iga_object_support
	                   WHERE object_type='resource' AND connector_id=$1 AND state='ended'`, f.connector); n != 0 {
		t.Error("B's scan must not touch A's support")
	}
	if n := f.scalar(`SELECT count(*) FROM iga_resources WHERE lifecycle='active'`); n != 1 {
		t.Error("the bucket must survive: account A still holds it")
	}
}

// A scan of account A must close NOTHING in account B. The partition's scope
// and connector are the evidence boundary, and reconciliation never crosses it.
func TestScanOfOneAccountClosesNothingInAnother(t *testing.T) {
	f := newFixture(t)
	connB := f.addConnector("222222222222")

	estA := newEstate("arn:aws:iam::1111:role/deploy", "AROAAAAAAAAAAAAAAAAAA")
	estB := newEstate("arn:aws:iam::2222:role/deploy", "AROABBBBBBBBBBBBBBBBB")
	estB.resource.NativeID = "arn:aws:s3:::b-bucket/*"
	estB.perm.NativeID = "arn:aws:iam::2222:policy/BAccess#s0"

	f.mustProject(estA.snapshot(f, f.publishedRun(f.connector, 1, cleanCoverage(region)), cleanCoverage(region)))
	f.clock = f.clock.Add(time.Hour)
	f.mustProject(estB.snapshot(f, f.publishedRun(connB, 1, cleanCoverage(region)), cleanCoverage(region)))

	// Two roles named `deploy` in two accounts are TWO objects: the ARNs differ
	// in the account segment, and equal display names never merge.
	if n := f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE display_name='refund-lambda-role'`); n != 2 {
		t.Fatalf("two accounts' roles must be two objects, got %d", n)
	}

	bEdgesBefore := f.scalar(`SELECT count(*) FROM iga_access_edges
	                           WHERE connector_id=$1 AND state='current'`, connB)
	if bEdgesBefore == 0 {
		t.Fatal("account B has no live edges -- the test would be vacuous")
	}

	// A rescans, unchanged. B must be untouched.
	f.clock = f.clock.Add(time.Hour)
	f.mustProject(estA.snapshot(f, f.publishedRun(f.connector, 2, cleanCoverage(region)), cleanCoverage(region)))

	if n := f.scalar(`SELECT count(*) FROM iga_access_edges
	                   WHERE connector_id=$1 AND state='current'`, connB); n != bEdgesBefore {
		t.Errorf("a scan of A changed B's live edges: %d -> %d", bEdgesBefore, n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_access_edges
	                   WHERE connector_id=$1 AND state='ended'`, connB); n != 0 {
		t.Errorf("a scan of A ended %d of B's edges", n)
	}
}

/* ====================== acceptance item 11 -- rebuildable ================== */

// ACCEPTANCE 11: projecting the same published run twice produces the same
// state, and DROP-AND-RE-PROJECT reproduces the graph.
//
// Both are the same guarantee from different directions: iga_* is a
// projection, rebuildable from cloud_* at any time.
func TestProjectionIsIdempotentAndRebuildable(t *testing.T) {
	f := newFixture(t)
	est := newEstate("arn:aws:iam::1234:role/refund-lambda-role", "AROA5XK7QEXAMPLE")
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(est.snapshot(f, run, cleanCoverage(region)))

	shape := func() map[string]int {
		out := map[string]int{}
		for _, tbl := range []string{
			"iga_identity_accounts", "iga_workload", "iga_resources",
			"iga_entitlements", "iga_access_edges", "iga_relationship",
			"iga_object_support", "iga_estate_scopes",
		} {
			out[tbl] = f.scalar(`SELECT count(*) FROM ` + tbl)
		}
		return out
	}
	first := shape()
	for tbl, n := range first {
		if n == 0 && tbl != "iga_object_support" {
			t.Fatalf("%s empty after projection -- the test would be vacuous", tbl)
		}
	}

	// Re-projecting the SAME run is a no-op: the generation is not ahead of
	// the watermark, so it is refused as obsolete rather than reapplied.
	err := f.project(est.snapshot(f, run, cleanCoverage(region)))
	if err == nil {
		t.Error("re-projecting the same generation should be refused as obsolete")
	}
	if got := shape(); !sameShape(first, got) {
		t.Errorf("re-projecting the same run changed the graph:\n before %v\n after  %v", first, got)
	}

	// Drop every iga_* row and re-project: the graph must come back.
	for _, tbl := range []string{
		"iga_access_edge_evidence", "iga_relationship_evidence",
		"iga_access_edges", "iga_relationship", "iga_object_support",
		"iga_projection_state", "iga_entitlements", "iga_resources",
		"iga_workload", "iga_credentials", "iga_agent_instances",
		"iga_agents", "iga_identity_accounts", "iga_estate_scopes",
	} {
		f.exec(`DELETE FROM ` + tbl)
	}
	f.mustProject(est.snapshot(f, run, cleanCoverage(region)))

	if got := shape(); !sameShape(first, got) {
		t.Errorf("drop-and-re-project did not reproduce the graph:\n before %v\n after  %v", first, got)
	}
}

func sameShape(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

/* ========================= §2.6 -- entitlement grain ====================== */

// §2.6, end to end against the database: two roles attached to ONE managed
// policy produce ONE entitlement and TWO access edges.
//
// That is what makes "detach the policy from one role and only that role's
// grant ends" true rather than aspirational.
func TestManagedPolicySharedOneEntitlementTwoEdges(t *testing.T) {
	f := newFixture(t)

	attrsA, _ := json.Marshal(models.AWSIdentityAttrs{UniqueID: "AROAAAAAAAAAAAAAAAAAA"})
	attrsB, _ := json.Marshal(models.AWSIdentityAttrs{UniqueID: "AROABBBBBBBBBBBBBBBBB"})
	roleA := models.CloudIdentity{ID: uuid.New(), Kind: models.CloudIdentityIAMRole,
		NativeID: "arn:aws:iam::1234:role/alpha", Name: "alpha", Attrs: attrsA}
	roleB := models.CloudIdentity{ID: uuid.New(), Kind: models.CloudIdentityIAMRole,
		NativeID: "arn:aws:iam::1234:role/beta", Name: "beta", Attrs: attrsB}
	res := models.CloudResource{ID: uuid.New(), Kind: "s3_bucket",
		NativeID: "arn:aws:s3:::refunds-bucket/*", Name: "refunds-bucket"}

	// The SAME managed policy statement, attached to both roles.
	const policy = "arn:aws:iam::1234:policy/RefundS3Access#s0"
	permA := models.CloudPermission{ID: uuid.New(), IdentityID: roleA.ID, ResourceID: &res.ID,
		NativeID: policy, Effect: "allow", Actions: pq.StringArray{"s3:GetObject"},
		ScopeKind: "resource", ConstraintState: "unconstrained"}
	permB := permA
	permB.ID = uuid.New()
	permB.IdentityID = roleB.ID

	var conn models.CloudConnector
	if err := f.gorm.First(&conn, "id = ?", f.connector).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	f.mustProject(&igagraph.Snapshot{
		Run: run, Connector: conn, Generation: 1,
		Identities:  []models.CloudIdentity{roleA, roleB},
		Resources:   []models.CloudResource{res},
		Permissions: []models.CloudPermission{permA, permB},
		Coverage:    cleanCoverage(region),
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	})

	if n := f.scalar(`SELECT count(*) FROM iga_entitlements`); n != 1 {
		t.Errorf("a shared managed policy must produce ONE entitlement, got %d", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_access_edges`); n != 2 {
		t.Errorf("two roles holding it must produce TWO access edges, got %d", n)
	}

	// Detach from roleB only: roleA's edge survives, the entitlement survives.
	f.clock = f.clock.Add(time.Hour)
	run2 := f.publishedRun(f.connector, 2, cleanCoverage(region))
	f.mustProject(&igagraph.Snapshot{
		Run: run2, Connector: conn, Generation: 2,
		Identities:  []models.CloudIdentity{roleA, roleB},
		Resources:   []models.CloudResource{res},
		Permissions: []models.CloudPermission{permA}, // B detached
		Coverage:    cleanCoverage(region),
		ConfirmedBy: map[igagraph.SubjectRef][]uuid.UUID{},
	})

	if n := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='ended'`); n != 1 {
		t.Errorf("detaching from one role must end exactly one edge, got %d ended", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state='current'`); n != 1 {
		t.Errorf("the other role's edge must survive, got %d current", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_entitlements WHERE lifecycle='active'`); n != 1 {
		t.Errorf("the shared entitlement must survive, got %d active", n)
	}
}
