package integration

// eks_pod_identity across regions (SPEC-iga-phase2-graph.md §1.4, T3.6, T3.8):
// the surface is read by one EKS reader per selected region and one
// association listing per cluster, and its coverage must name EVERY failure --
// not the first reader's -- with a listing that returned nothing outranking
// detail calls that failed. A region whose EKS endpoint does not resolve is
// partial: EKS is offered in every region, so a name that does not resolve is
// a resolver failure, never "not offered".

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// s3bDNSEKS fails ListClusters the way the SDK does when EKS's regional
// endpoint does not exist: a *net.DNSError (IsNotFound) inside the HTTP
// client's *url.Error.
type s3bDNSEKS struct {
	*fakeEKS
	host string
}

func (f *s3bDNSEKS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	return nil, &smithy.OperationError{ServiceID: "EKS", OperationName: "ListClusters",
		Err: &url.Error{Op: "Get", URL: "https://" + f.host + "/clusters", Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: &net.DNSError{Err: "no such host", Name: f.host, IsNotFound: true}}}}
}

// s3bTwoAssociations is one cluster whose two associations bind two service
// accounts to role; the describe of the one with id failID fails.
func s3bTwoAssociations(cluster, idA, idB, role, failID string) *s3bOneDescribeFails {
	f := newFakeEKS()
	f.clusters[cluster] = eksIssuerURL
	for _, a := range []struct{ id, sa string }{{idA, "ledger-agent"}, {idB, "audit-agent"}} {
		f.associations[cluster] = append(f.associations[cluster], ekstypes.PodIdentityAssociation{
			AssociationId:  aws.String(a.id),
			AssociationArn: aws.String("arn:aws:eks:us-east-1:429418377036:podidentityassociation/" + cluster + "/" + a.id),
			ClusterName:    aws.String(cluster), Namespace: aws.String(cluster + "-ns"),
			ServiceAccount: aws.String(a.sa), RoleArn: aws.String(role),
		})
	}
	return &s3bOneDescribeFails{fakeEKS: f, failID: failID}
}

// s3bTwoRegionEKS onboards a connector selecting us-east-1 and eu-west-1, runs
// the real IAM scan, and returns a permission scanner whose EKS client is
// chosen per region from byRegion.
func s3bTwoRegionEKS(t *testing.T, db *gorm.DB, ws uuid.UUID, byRegion map[string]awsdiscovery.EKSAPI,
) (*services.AWSPermissionScanner, *services.IAMSnapshot) {
	t.Helper()
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	scanner := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iamFake).
		WithRegionalEKSAPI(func(region string) awsdiscovery.EKSAPI { return byRegion[region] })
	return scanner, snap
}

func s3bPermissionScan(t *testing.T, scanner *services.AWSPermissionScanner, ws uuid.UUID, snap *services.IAMSnapshot,
) (*services.PermissionSnapshot, models.SurfaceCoverage) {
	t.Helper()
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	return out, out.Surfaces[models.SurfaceEKSPodIdentity]
}

// §1.4 "the report names how many", across regions: each region's describe
// failures are SUMMED (it used to report the first region's alone), and a
// listing that failed outright in any region outranks them -- denied, or
// throttled when every failed listing was a throttle -- with api/error_code
// naming that listing (D-71). The partial the first region found is still
// named beside it.
//
// Safeguards (mutation-checked): the Merge of each reader's tally
// (podIdentityFailures.add); the listing-over-partial precedence and the
// throttled-only-when-all-throttled rule in podIdentityCoverage.
func TestP2S3bPodIdentityCoverageNamesEveryFailure(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-eks-every-failure")
	defer cleanPermissionTables(t, db, ws)

	east := s3bTwoAssociations("east-cluster", "a-e1", "a-e2", plainRoleARN, "a-e2")
	west := s3bTwoAssociations("west-cluster", "a-w1", "a-w2", plainRoleARN, "a-w2")
	scanner, snap := s3bTwoRegionEKS(t, db, ws, map[string]awsdiscovery.EKSAPI{"us-east-1": east, "eu-west-1": west})

	out, cov := s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoveragePartial || !strings.Contains(cov.Error, "2 of 4 pod identity associations") ||
		cov.API != "eks:DescribePodIdentityAssociation" || cov.ErrorCode != "AccessDenied" || cov.Count != 2 {
		t.Fatalf("one describe failing in each region = %+v, want partial, 2 of 4, api/error_code of the describe, count 2", cov)
	}
	if out.Complete {
		t.Fatal("a partial eks_pod_identity must block the permission scan's reconciliation")
	}

	// ---- a later region's listing is denied ---------------------------------
	west.fail["ListClusters"] = denied("eks:ListClusters")
	snap.Generation++
	_, cov = s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoverageDenied || cov.API != "eks:ListClusters" || cov.ErrorCode != "AccessDenied" ||
		!strings.Contains(cov.Error, "eks:ListClusters") || !strings.Contains(cov.Error, "1 of 2 pod identity associations") {
		t.Fatalf("eu-west-1 ListClusters denied after us-east-1's partial = %+v, want denied naming the listing, "+
			"the partial still named", cov)
	}

	// ---- throttled, when the only failed listing is a throttle ---------------
	west.fail["ListClusters"] = throttled("eks:ListClusters")
	snap.Generation++
	_, cov = s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoverageThrottled || cov.API != "eks:ListClusters" {
		t.Fatalf("eu-west-1 ListClusters throttled = %+v, want throttled naming the listing", cov)
	}

	// ---- a throttle and a denial: denied, naming the denial -------------------
	east.fail["ListClusters"] = throttled("eks:ListClusters")
	west.fail["ListClusters"] = denied("eks:ListClusters")
	snap.Generation++
	_, cov = s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoverageDenied || cov.ErrorCode != "AccessDenied" || !strings.Contains(cov.Error, "2 listings failed") {
		t.Fatalf("one region throttled, one denied = %+v, want denied, AccessDenied, both listings counted", cov)
	}
}

// s3bPlantPodEdge records a pod-identity binding an EARLIER scan wrote, with
// the given attrs, for plainRoleARN.
func s3bPlantPodEdge(t *testing.T, db *gorm.DB, ws uuid.UUID, snap *services.IAMSnapshot, subject, attrs string) {
	t.Helper()
	if err := db.Exec(`INSERT INTO cloud_assume_edge (workspace_id, connector_id, identity_id, subject_kind, subject,
	                           mechanism, k8s_ref, attrs, last_seen_generation)
	                   SELECT ?, ?, id, ?, ?, ?, ?, ?::jsonb, ? FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`,
		ws, snap.ConnectorID, models.AssumeSubjectK8sSA, subject, models.AssumeMechanismEKSPodIdentity, subject,
		attrs, snap.Generation-1, ws, plainRoleARN).Error; err != nil {
		t.Fatalf("plant pod edge: %v", err)
	}
}

func s3bPodEdgeCount(t *testing.T, db *gorm.DB, ws uuid.UUID, subject string) int64 {
	t.Helper()
	var n int64
	db.Raw(`SELECT count(*) FROM cloud_assume_edge WHERE workspace_id = ? AND subject = ?`, ws, subject).Scan(&n)
	return n
}

// Review P1-11 (T3.8 / E9, revised): a selected region whose EKS endpoint does
// not resolve is NOT "EKS is not offered there" -- EKS is offered in every
// region of its partition, so a name that fails to resolve is a resolver
// failure. eks_pod_identity is partial (never reached or unsupported, so
// nothing reads it as "no bindings"), names eks:ListClusters, and the permission
// scan's reconciliation is blocked: the bindings recorded for the unread region
// -- with or without an attrs region -- are kept.
//
// Safeguards (mutation-checked): listErr on eks:ListClusters (the resolver
// branch); podIdentityCoverage's partial for an unreachable listing.
func TestP2S3bPodIdentityUnresolvableRegionIsPartialAndKeepsBindings(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-eks-not-offered")
	defer cleanPermissionTables(t, db, ws)

	scanner, snap := s3bTwoRegionEKS(t, db, ws, map[string]awsdiscovery.EKSAPI{
		"us-east-1": podIdentityEKS(plainRoleARN),
		"eu-west-1": &s3bDNSEKS{fakeEKS: newFakeEKS(), host: "eks.eu-west-1.amazonaws.com"},
	})
	stale := awsdiscovery.K8sSubject("payments", "retired-agent")
	s3bPlantPodEdge(t, db, ws, snap, stale, `{"region": "us-east-1"}`)
	west := awsdiscovery.K8sSubject("payments", "west-agent")
	s3bPlantPodEdge(t, db, ws, snap, west, `{"region": "eu-west-1"}`)

	out, cov := s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoveragePartial || cov.API != "eks:ListClusters" || cov.ErrorCode != "" ||
		!strings.Contains(cov.Error, "DNSNameNotFound") {
		t.Fatalf("eks_pod_identity with eu-west-1 not resolving = %+v, want partial naming eks:ListClusters and "+
			"DNSNameNotFound, with no AWS code", cov)
	}
	if out.Complete {
		t.Fatal("an EKS endpoint that did not resolve must block the permission scan's reconciliation")
	}
	if n := s3bPodEdgeCount(t, db, ws, stale); n != 1 {
		t.Fatal("a binding was deleted while a selected region's EKS listing failed")
	}
	if n := s3bPodEdgeCount(t, db, ws, west); n != 1 {
		t.Fatal("the unread region's binding was deleted")
	}

	// ---- a binding recorded before edges said where ---------------------------
	db.Exec(`UPDATE cloud_assume_edge SET attrs = '{}'::jsonb WHERE workspace_id = ? AND subject = ?`, ws, west)
	snap.Generation++
	out, cov = s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoveragePartial || out.Complete || s3bPodEdgeCount(t, db, ws, west) != 1 {
		t.Fatalf("a region-less binding with eu-west-1 unresolvable = %+v (complete=%v): must block and be kept",
			cov, out.Complete)
	}
}

// s3bDNSAfterFirstPage lists its clusters on page 1, then fails page 2 as an
// endpoint that does not resolve.
type s3bDNSAfterFirstPage struct{ *s3bDNSEKS }

func (f *s3bDNSAfterFirstPage) ListClusters(ctx context.Context, in *eks.ListClustersInput, opts ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if in.NextToken == nil {
		out, err := f.fakeEKS.ListClusters(ctx, in, opts...)
		if err == nil {
			out.NextToken = aws.String("page-2")
		}
		return out, err
	}
	return f.s3bDNSEKS.ListClusters(ctx, in, opts...)
}

// A region whose endpoint answered page 1 of ListClusters and then stopped
// resolving is a listing failure there, like any other unresolvable endpoint:
// partial -- the clusters it did list are not read as the whole.
func TestP2S3bPodIdentityRegionThatListedThenFailedIsPartial(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-s3b-eks-listed-then-dns")
	defer cleanPermissionTables(t, db, ws)

	west := podIdentityEKS(plainRoleARN)
	scanner, snap := s3bTwoRegionEKS(t, db, ws, map[string]awsdiscovery.EKSAPI{
		"us-east-1": newFakeEKS(),
		"eu-west-1": &s3bDNSAfterFirstPage{&s3bDNSEKS{fakeEKS: west, host: "eks.eu-west-1.amazonaws.com"}},
	})
	out, cov := s3bPermissionScan(t, scanner, ws, snap)
	if cov.State != models.CloudCoveragePartial || cov.API != "eks:ListClusters" || out.Complete {
		t.Fatalf("eu-west-1 listing clusters, then not resolving = %+v (complete=%v), want partial", cov, out.Complete)
	}
}
