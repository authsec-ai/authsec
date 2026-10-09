package integration

// EKS Pod Identity through the REAL pipeline, once T4.7 makes the pod-identity
// can_assume partition reconcile (SPEC-iga-phase2-graph.md §1.4 eks_pod_identity,
// §2.7 canEnd, §4.8, §4.10; P2-DECISIONS D-42): what a failed describe does to
// a binding, and where the binding's evidence comes from.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// trustFlakyEKS is the EKS fake with DescribePodIdentityAssociation failing
// for the association ids in failDescribe -- one binding's describe refused
// while its neighbours on the same cluster read.
type trustFlakyEKS struct {
	*fakeEKS
	failDescribe map[string]error
}

func (f *trustFlakyEKS) DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput,
	opts ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if err := f.failDescribe[aws.ToString(in.AssociationId)]; err != nil {
		f.calls["DescribePodIdentityAssociation"]++
		return nil, err
	}
	return f.fakeEKS.DescribePodIdentityAssociation(ctx, in, opts...)
}

// trustPodEdgeRow is one pod-identity can_assume, by its source's subject.
type trustPodEdgeRow struct {
	ID            uuid.UUID
	Subject       string
	State         string
	EndedReason   string
	ValidFrom     time.Time
	LastConfirmed time.Time
}

func trustPodEdges(l *p2Lab) map[string]trustPodEdgeRow {
	l.t.Helper()
	var rows []trustPodEdgeRow
	if err := l.db.Raw(`
		SELECT r.id, ep.subject_claim AS subject, r.state, r.ended_reason, r.valid_from,
		       r.last_confirmed_at AS last_confirmed
		  FROM iga_relationship r JOIN iga_external_principal ep ON ep.id = r.source_external_principal_id
		 WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume' AND r.mechanism = ?
		 ORDER BY r.created_at, r.id`, l.ws, models.MechanismEKSPodIdentity).Scan(&rows).Error; err != nil {
		l.t.Fatalf("read pod-identity can_assume: %v", err)
	}
	out := map[string]trustPodEdgeRow{}
	for _, r := range rows {
		if _, dup := out[r.Subject]; dup {
			l.t.Fatalf("two pod-identity edges from %s: a binding was recreated as a new row", r.Subject)
		}
		out[r.Subject] = r
	}
	return out
}

// §2.7 "could-not-look is never the same as gone", for the one detail call
// eks_pod_identity cannot do without (DescribePodIdentityAssociation carries
// the role). Two bindings on one cluster; one describe is throttled. The
// surface reads PARTIAL, not reached: the binding that was read is confirmed,
// the one that was not goes STALE -- never ended not_seen, which would lose it
// and recreate it as a new edge, its id, valid_from and history gone, on the
// next good scan. On that scan it is current again: the same row.
func TestP2TrustPodIdentityDescribeFailureKeepsTheEdge(t *testing.T) {
	l := newP2Lab(t, "p2-trust-pod-describe", true)
	a := l.account(accountA)
	roleARN := trustRole(a, "ledger-role", "AROALEDGERROLELEDGER",
		trustDoc(trustAllow(`{"Service":"pods.eks.amazonaws.com"}`, "sts:AssumeRole")))
	base := podIdentityEKS(roleARN)
	base.associations["prod-cluster"] = append(base.associations["prod-cluster"], ekstypes.PodIdentityAssociation{
		AssociationId:  aws.String("a-2222222222"),
		AssociationArn: aws.String("arn:aws:eks:us-east-1:" + accountA + ":podidentityassociation/prod-cluster/a-2222222222"),
		ClusterName:    aws.String("prod-cluster"),
		Namespace:      aws.String("payments"),
		ServiceAccount: aws.String("auditor"),
		RoleArn:        aws.String(roleARN),
	})
	eksFake := &trustFlakyEKS{fakeEKS: base, failDescribe: map[string]error{}}
	ledger := "pod:system:serviceaccount:payments:ledger-agent"
	auditor := "pod:system:serviceaccount:payments:auditor"

	trustCycle(l, a, eksFake)
	first := trustPodEdges(l)
	if len(first) != 2 || first[ledger].State != models.RelCurrent || first[auditor].State != models.RelCurrent {
		t.Fatalf("setup: pod-identity edges = %+v, want both bindings current", first)
	}

	time.Sleep(10 * time.Millisecond)
	eksFake.failDescribe["a-2222222222"] = throttled("eks:DescribePodIdentityAssociation")
	run := trustCycle(l, a, eksFake)
	cov := models.DecodeScanCoverage(run.Coverage).Surfaces[models.SurfaceEKSPodIdentity]
	if cov.State != models.CloudCoveragePartial || !strings.Contains(cov.Error, "1 of 2") {
		t.Errorf("eks_pod_identity = %s (%q), want partial naming 1 of 2 associations: a failed detail call is not a reached read",
			cov.State, cov.Error)
	}
	second := trustPodEdges(l)
	if got := second[ledger]; got.State != models.RelCurrent || !got.LastConfirmed.After(first[ledger].LastConfirmed) {
		t.Errorf("the binding that WAS read = %s, confirmed %s -> %s; want current and confirmed by this run",
			got.State, first[ledger].LastConfirmed, got.LastConfirmed)
	}
	if got := second[auditor]; got.ID != first[auditor].ID || got.State != models.RelStale || got.EndedReason != "" {
		t.Errorf("the binding whose describe failed = %s/%q (row %s, was %s), want the same row STALE: it was not read, not gone",
			got.State, got.EndedReason, got.ID, first[auditor].ID)
	}
	// Phase 1's own table is not reconciled on an incomplete read either.
	var legacy int64
	l.db.Raw(`SELECT count(*) FROM cloud_assume_edge WHERE workspace_id = ? AND mechanism = ?`,
		l.ws, models.AssumeMechanismEKSPodIdentity).Scan(&legacy)
	if legacy != 2 {
		t.Errorf("cloud_assume_edge pod-identity rows = %d, want both kept", legacy)
	}

	delete(eksFake.failDescribe, "a-2222222222")
	trustCycle(l, a, eksFake)
	third := trustPodEdges(l)
	if got := third[auditor]; got.ID != first[auditor].ID || got.State != models.RelCurrent ||
		!got.ValidFrom.Equal(first[auditor].ValidFrom) {
		t.Errorf("after a good read the binding = %s (row %s, valid_from %s); want the SAME row %s current, valid_from %s kept",
			got.State, got.ID, got.ValidFrom, first[auditor].ID, first[auditor].ValidFrom)
	}
	if len(third) != 2 {
		t.Errorf("pod-identity edges = %d, want the two bindings and no replacement", len(third))
	}
}

// T4.9 for can_assume on a lab account WITH a pod-identity association, and
// §8's ratchet for the one gap this branch cannot close (see
// trustPodEvidenceWriterLanded): nothing stands in for T3.5's writer here --
// the real scan, the real projector. Every trust-document can_assume has the
// role's observation. The pod-identity edge has evidence only once the
// collector writes the association's observation; until then the gap is held
// at exactly one bare edge, and the test fails the moment that changes.
func TestP2TrustPodIdentityEvidenceRatchet(t *testing.T) {
	l := newP2Lab(t, "p2-trust-pod-evidence", true)
	a := l.account(accountA)
	roleARN := trustRole(a, "ledger-role", "AROALEDGERROLELEDGER",
		trustDoc(trustAllow(`{"Service":"pods.eks.amazonaws.com"}`, "sts:AssumeRole")))
	trustCycle(l, a, podIdentityEKS(roleARN))

	count := func(q string) int64 {
		t.Helper()
		var n int64
		if err := l.db.Raw(q, l.ws, models.MechanismEKSPodIdentity).Scan(&n).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	const bare = ` AND NOT EXISTS (SELECT 1 FROM iga_relationship_evidence e WHERE e.relationship_id = r.id)`
	pods := count(`SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume'
	                 AND r.state = 'current' AND r.mechanism = ?`)
	barePods := count(`SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume'
	                     AND r.mechanism = ?` + bare)
	bareTrust := count(`SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ? AND r.relationship_type = 'can_assume'
	                      AND r.mechanism <> ?` + bare)
	if pods != 1 {
		t.Fatalf("setup: %d current pod-identity can_assume, want the association's one", pods)
	}
	if bareTrust != 0 {
		t.Errorf("%d trust-document can_assume edges without the role's observation (T4.9 requires zero)", bareTrust)
	}
	switch {
	case !trustPodEvidenceWriterLanded && barePods != 1:
		t.Errorf("RATCHET MOVED: %d bare pod-identity edges, the known gap is 1. If T3.5's association observation "+
			"now links, set trustPodEvidenceWriterLanded = true so this asserts T4.9's zero.", barePods)
	case !trustPodEvidenceWriterLanded:
		t.Logf("KNOWN GAP (§8 ratchet): 1 pod-identity can_assume without evidence until T3.5's writer lands")
	case barePods != 0:
		t.Errorf("%d pod-identity can_assume edges without the association's observation (T4.9 requires zero)", barePods)
	}
}
