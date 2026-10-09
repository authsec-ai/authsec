package integration

// B4 (SPEC-iga-phase2-graph.md §7.3; §2.7 "IAM read denied"; §4.10 canEnd;
// §7.1 E9a): IAM denied on a rescan ends NOTHING, and -- the non-vacuity the
// B4 row demands -- the same fixture with every surface reached, and the IAM
// objects genuinely gone, DOES end the same rows. Through the REAL scan worker
// and projector.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// bdbIAMFixture is one account with every IAM-partition edge kind: a Lambda
// running as SharedToolRole (executes_as), the role's Lambda trust
// (can_assume), TicketRead attached to the role (assignment, grant), and priya
// in group ops (member_of) with OpsRead attached to the group. One clean cycle.
func bdbIAMFixture(t *testing.T, name string) (*p2Lab, *p2Account) {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aJoin(a, "priya", "ops")
	s3aGroupAttach(t, a, "ops", a.managed("OpsRead", s3aDoc("OpsRead", "s3:GetObject", "arn:aws:s3:::ops-runbooks/*")))
	l.scanAndProject(a)

	kinds := map[string]int{}
	for _, e := range bdbEdges(t, l) {
		if e.State == models.RelCurrent {
			kinds[e.Kind]++
		}
	}
	for _, k := range []string{"assignment", "grant", models.RelTypeMemberOf, models.RelTypeExecutesAs, models.RelTypeCanAssume} {
		if kinds[k] == 0 {
			t.Fatalf("setup: no current %s edge (edges by kind: %v) -- the fixture must carry every IAM edge kind", k, kinds)
		}
	}
	return l, a
}

// bdbIAMSurfaces are the four IAM listings §4.10's permission and identity
// partitions require.
var bdbIAMSurfaces = []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups, models.SurfaceIAMPolicies}

// bdbTransitions counts, per edge kind and per support class, the rows that
// were current before and are in state `to` after.
func bdbTransitions(beforeE, afterE map[uuid.UUID]bdbEdge, beforeS, afterS map[uuid.UUID]bdbSupport, to string) map[string]int {
	out := map[string]int{}
	for id, b := range beforeE {
		if b.State == models.RelCurrent && afterE[id].State == to {
			out["edge:"+b.Kind]++
		}
	}
	for id, b := range beforeS {
		if b.State == models.RelCurrent && afterS[id].State == to {
			out["support:"+b.Class]++
		}
	}
	return out
}

// bdbKeys renders a transition count stably, for comparison and messages.
func bdbKeys(m map[string]int) string {
	ks := make([]string, 0, len(m))
	for k, v := range m {
		ks = append(ks, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(ks)
	return strings.Join(ks, " ")
}

// B4: IAM denied on the rescan. Every IAM listing is refused
// (GetAccountAuthorizationDetails, all four filters), the Lambda listing is
// clean and unchanged. ZERO rows end, NO node retires, every row of an IAM
// partition moves current -> stale with last_confirmed_at (and the confirming
// run) UNTOUCHED -- refreshing it would launder the outage (§4.10 markStale).
// The workload itself, whose own surface was reached, is confirmed.
//
// Then the non-vacuity half: the SAME fixture, with the IAM reads succeeding
// and the role, user, group and both policies genuinely gone. Exactly the rows
// that went stale above END (the same kinds, the same counts): assignment,
// grant, member_of, executes_as and can_assume ended not_seen, the IAM
// supports ended, the identities, policies, statements and resource
// references retired unsupported. A canEnd that returned false for everything
// would pass the denied half alone.
//
// Safeguard (mutation-checked): canEnd refuses a required surface that is
// present but not reached (reconcile.go) -- trusting its presence alone, the
// denied half ends everything.
func TestP2BdbIAMDeniedEndsNothing(t *testing.T) {
	// Skip the whole test without a database: "reached" needs "denied" to have
	// run, and a skipped "denied" must not read as a failure of "reached".
	igaDB(t)
	var keptStale map[string]int

	t.Run("denied", func(t *testing.T) {
		l, a := bdbIAMFixture(t, "p2-bdb-b4-denied")
		beforeE, beforeS, beforeL := bdbEdges(t, l), bdbSupports(t, l), bdbLifecycles(t, l)

		time.Sleep(10 * time.Millisecond)
		a.iam.fail["GetAccountAuthorizationDetails"] = denied("iam:GetAccountAuthorizationDetails")
		run := l.scanAndProject(a)

		cov := models.DecodeScanCoverage(run.Coverage).Surfaces
		for _, s := range bdbIAMSurfaces {
			if cov[s].State == models.CloudCoverageReached {
				t.Fatalf("setup: %s = %+v on the denied rescan, want not reached", s, cov[s])
			}
		}
		if st := cov["lambda:us-east-1"].State; st != models.CloudCoverageReached {
			t.Fatalf("setup: lambda:us-east-1 = %q, want reached (only IAM is denied)", st)
		}

		afterE, afterS, afterL := bdbEdges(t, l), bdbSupports(t, l), bdbLifecycles(t, l)
		if len(afterE) != len(beforeE) {
			t.Errorf("edges %d -> %d: a denied rescan must neither write nor drop an edge", len(beforeE), len(afterE))
		}
		for id, b := range beforeE {
			a := afterE[id]
			if a.State == models.RelEnded || a.ValidTo != nil {
				t.Errorf("%s edge %s ENDED on a denied rescan: %+v", b.Kind, id, a)
				continue
			}
			if b.State != models.RelCurrent {
				continue
			}
			// Every edge in the fixture sits in an IAM partition: assignment and
			// grant (iam_*), member_of (iam_users, iam_groups), executes_as
			// (lambda:<region> AND iam_roles), can_assume trust (iam_roles).
			if a.State != models.RelStale {
				t.Errorf("%s edge %s = %s after IAM was denied, want stale", b.Kind, id, a.State)
			}
			if !a.LastConfirmedAt.Equal(b.LastConfirmedAt) || !sameRun(a.LastConfirmedBy, b.LastConfirmedBy) {
				t.Errorf("%s edge %s: last confirmed %s by %v -> %s by %v; a stale row keeps its last confirmation",
					b.Kind, id, b.LastConfirmedAt, b.LastConfirmedBy, a.LastConfirmedAt, a.LastConfirmedBy)
			}
		}
		for id, b := range beforeS {
			a := afterS[id]
			if a.State == models.RelEnded {
				t.Errorf("%s support %s ENDED on a denied rescan", b.Class, id)
				continue
			}
			if b.State != models.RelCurrent {
				continue
			}
			if b.Class == models.ObjectWorkload {
				// lambda:us-east-1 was reached: the workload is confirmed by this run.
				if a.State != models.RelCurrent || a.LastConfirmedAt == nil || !a.LastConfirmedAt.After(*b.LastConfirmedAt) {
					t.Errorf("workload support = %+v, want current and re-confirmed (its surface was reached)", a)
				}
				continue
			}
			if a.State != models.RelStale {
				t.Errorf("%s support %s = %s after IAM was denied, want stale", b.Class, id, a.State)
			}
			if a.LastConfirmedAt == nil || b.LastConfirmedAt == nil || !a.LastConfirmedAt.Equal(*b.LastConfirmedAt) {
				t.Errorf("%s support %s: last_confirmed_at %v -> %v; a stale row keeps its last confirmation",
					b.Class, id, b.LastConfirmedAt, a.LastConfirmedAt)
			}
		}
		for id, b := range beforeL {
			if a := afterL[id]; a != b {
				t.Errorf("node %s lifecycle %v -> %v on a denied rescan", id, b, a)
			}
		}
		keptStale = bdbTransitions(beforeE, afterE, beforeS, afterS, models.RelStale)
		t.Logf("kept stale: %s", bdbKeys(keptStale))
	})

	t.Run("reached", func(t *testing.T) {
		if keptStale == nil {
			t.Fatal("the denied half did not run")
		}
		l, a := bdbIAMFixture(t, "p2-bdb-b4-reached")
		beforeE, beforeS, beforeL := bdbEdges(t, l), bdbSupports(t, l), bdbLifecycles(t, l)

		// Genuinely gone, read in full: every listing succeeds and is empty.
		// The Lambda still names the role's ARN, as a function whose role was
		// deleted does.
		a.iam.roles, a.iam.users, a.iam.groups = nil, nil, nil
		a.iam.userGroups = map[string][]string{}
		a.iam.attachedRolePolicies = map[string][]iamtypes.AttachedPolicy{}
		for arn := range a.iam.managedPolicies {
			delete(a.iam.managedPolicies, arn)
		}
		time.Sleep(10 * time.Millisecond)
		run := l.scanAndProject(a)
		cov := models.DecodeScanCoverage(run.Coverage).Surfaces
		for _, s := range bdbIAMSurfaces {
			if cov[s].State != models.CloudCoverageReached {
				t.Fatalf("setup: %s = %+v, want reached", s, cov[s])
			}
		}
		pubAt := bdbPublishedAt(t, l, run.ID)

		afterE, afterS, afterL := bdbEdges(t, l), bdbSupports(t, l), bdbLifecycles(t, l)
		for id, b := range beforeE {
			if b.State != models.RelCurrent {
				continue
			}
			a := afterE[id]
			// Ended by its PARTITION (not_seen), before any retirement cascade
			// could (D-67).
			if a.State != models.RelEnded || a.ValidTo == nil || !a.ValidTo.Equal(pubAt) || a.EndedReason != models.EndedNotSeen {
				t.Errorf("%s edge %s = %+v, want ended not_seen at the pass's published_at %s", b.Kind, id, a, pubAt)
			}
		}
		for id, b := range beforeS {
			if b.State != models.RelCurrent || b.Class == models.ObjectWorkload {
				continue
			}
			if a := afterS[id]; a.State != models.RelEnded {
				t.Errorf("%s support %s = %s, want ended", b.Class, id, a.State)
			}
		}
		retired := 0
		for id, b := range beforeL {
			a := afterL[id]
			if bdbNodeClass(t, l, id) == models.ObjectWorkload {
				if a[0] != models.IGALifecycleActive {
					t.Errorf("workload %s = %v, want active (its surface was reached and it is still there)", id, a)
				}
				continue
			}
			if b[0] == models.IGALifecycleActive {
				if a[0] != models.IGALifecycleRetired || a[1] != models.RetiredUnsupported {
					t.Errorf("node %s = %v, want retired unsupported", id, a)
				}
				retired++
			}
		}
		if retired == 0 {
			t.Error("no node retired: the reached half proves nothing")
		}

		ended := bdbTransitions(beforeE, afterE, beforeS, afterS, models.RelEnded)
		// The IAM supports and edges the denied half kept stale are exactly
		// those this half ends.
		if bdbKeys(ended) != bdbKeys(keptStale) {
			t.Errorf("reached ended   %s\ndenied kept stale %s\nwant the same rows (non-vacuity)", bdbKeys(ended), bdbKeys(keptStale))
		}
	})
}

// sameRun compares two nullable run ids.
func sameRun(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// bdbPublishedAt is the published_at of the run's publication: the pass's one
// timestamp (D-26), which every valid_to that pass writes carries.
func bdbPublishedAt(t *testing.T, l *p2Lab, run uuid.UUID) time.Time {
	t.Helper()
	var at time.Time
	if err := l.db.Raw(`SELECT published_at FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`,
		l.ws, run).Row().Scan(&at); err != nil {
		t.Fatalf("publication of %s: %v", run, err)
	}
	return at
}

// bdbNodeClass says which node table an id is in.
func bdbNodeClass(t *testing.T, l *p2Lab, id uuid.UUID) string {
	t.Helper()
	for _, class := range models.NodeClasses {
		if l.count(`SELECT count(*) FROM `+models.NodeTable(class)+` WHERE workspace_id = ? AND id = ?`, l.ws, id) == 1 {
			return class
		}
	}
	t.Fatalf("node %s is in no node table", id)
	return ""
}
