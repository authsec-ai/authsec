package integration

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The EKS Pod Identity surface, against a real database.
//
// This is the only path by which a Kubernetes service account can be linked to
// an IAM role: a Pod Identity role's trust policy names
// pods.eks.amazonaws.com and never the service account, so trust-policy
// parsing alone cannot see the binding. The AWS boundary is a fake EKSAPI;
// the reader, the scanner, the upsert and the reconciliation gate are real.

/* ------------------------------- the fake EKS ------------------------------ */

type fakeEKS struct {
	// clusterName -> OIDC issuer URL, as EKS reports it (with scheme).
	clusters map[string]string
	// clusterName -> associations
	associations map[string][]ekstypes.PodIdentityAssociation

	fail  map[string]error
	calls map[string]int
}

func newFakeEKS() *fakeEKS {
	return &fakeEKS{
		clusters:     map[string]string{},
		associations: map[string][]ekstypes.PodIdentityAssociation{},
		fail:         map[string]error{},
		calls:        map[string]int{},
	}
}

func (f *fakeEKS) track(op string) error {
	f.calls[op]++
	return f.fail[op]
}

func (f *fakeEKS) ListClusters(_ context.Context, _ *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if err := f.track("ListClusters"); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.clusters))
	for name := range f.clusters {
		names = append(names, name)
	}
	return &eks.ListClustersOutput{Clusters: names}, nil
}

func (f *fakeEKS) DescribeCluster(_ context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	if err := f.track("DescribeCluster"); err != nil {
		return nil, err
	}
	name := aws.ToString(in.Name)
	issuer, ok := f.clusters[name]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "no such cluster"}
	}
	cluster := &ekstypes.Cluster{
		Name: aws.String(name),
		Arn:  aws.String("arn:aws:eks:us-east-1:429418377036:cluster/" + name),
	}
	if issuer != "" {
		cluster.Identity = &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: aws.String(issuer)}}
	}
	return &eks.DescribeClusterOutput{Cluster: cluster}, nil
}

func (f *fakeEKS) ListPodIdentityAssociations(_ context.Context, in *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	if err := f.track("ListPodIdentityAssociations"); err != nil {
		return nil, err
	}
	var summaries []ekstypes.PodIdentityAssociationSummary
	for _, a := range f.associations[aws.ToString(in.ClusterName)] {
		// The list response deliberately omits RoleArn, exactly as AWS does --
		// which is what forces the per-association describe.
		summaries = append(summaries, ekstypes.PodIdentityAssociationSummary{
			AssociationId:  a.AssociationId,
			AssociationArn: a.AssociationArn,
			ClusterName:    a.ClusterName,
			Namespace:      a.Namespace,
			ServiceAccount: a.ServiceAccount,
		})
	}
	return &eks.ListPodIdentityAssociationsOutput{Associations: summaries}, nil
}

func (f *fakeEKS) DescribePodIdentityAssociation(_ context.Context, in *eks.DescribePodIdentityAssociationInput, _ ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	if err := f.track("DescribePodIdentityAssociation"); err != nil {
		return nil, err
	}
	for _, a := range f.associations[aws.ToString(in.ClusterName)] {
		if aws.ToString(a.AssociationId) == aws.ToString(in.AssociationId) {
			assoc := a
			return &eks.DescribePodIdentityAssociationOutput{Association: &assoc}, nil
		}
	}
	return nil, &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "no such association"}
}

// Compile-time proof the fake satisfies the real interface. If the EKS surface
// ever needs another operation, this fails until the fake grows it.
var _ awsdiscovery.EKSAPI = (*fakeEKS)(nil)

/* -------------------------------- fixtures -------------------------------- */

const (
	eksIssuerURL   = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E"
	eksIssuerNoSch = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0539D4633E53DE1B716D3041E"
)

// podIdentityEKS is one cluster with one association, bound to the role the
// IAM fixture already records.
func podIdentityEKS(roleARN string) *fakeEKS {
	f := newFakeEKS()
	f.clusters["prod-cluster"] = eksIssuerURL
	f.associations["prod-cluster"] = []ekstypes.PodIdentityAssociation{{
		AssociationId:  aws.String("a-1111111111"),
		AssociationArn: aws.String("arn:aws:eks:us-east-1:429418377036:podidentityassociation/prod-cluster/a-1111111111"),
		ClusterName:    aws.String("prod-cluster"),
		Namespace:      aws.String("payments"),
		ServiceAccount: aws.String("ledger-agent"),
		RoleArn:        aws.String(roleARN),
	}}
	return f
}

// singleRegionInput keeps the region loop to one pass, so edge counts in these
// tests are unambiguous. validInput's two regions would drive the same injected
// fake twice.
func singleRegionInput(externalID string) services.AWSOnboardInput {
	in := validInput(externalID)
	in.Regions = []string{"us-east-1"}
	return in
}

// eksFixture onboards a connector, runs the identity scan so the IAM roles
// exist, and returns a permission scanner wired to both fakes.
func eksFixture(
	t *testing.T, db *gorm.DB, ws uuid.UUID, iamFake *fakeIAM, eksFake *fakeEKS,
) (*services.AWSPermissionScanner, *services.IAMSnapshot) {
	t.Helper()

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).
		Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("identity scan: %v", err)
	}
	return services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iamFake).WithEKSAPI(eksFake), snap
}

/* ---------------------------------- tests --------------------------------- */

// The core of the EKS surface: an association becomes one assume edge carrying
// the service account in the exact format the Kubernetes connector records.
func TestEKSPodIdentityAssociationBecomesAnAssumeEdge(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-eks-pod-identity")
	defer cleanPermissionTables(t, db, ws)

	scanner, snap := eksFixture(t, db, ws, populatedIAM(), podIdentityEKS(plainRoleARN))
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	if out.PodIdentityEdges != 1 {
		t.Fatalf("expected 1 pod identity edge, got %d (skipped=%d)", out.PodIdentityEdges, out.Skipped)
	}
	t.Logf("PASS: %d pod identity edge written", out.PodIdentityEdges)

	grants := repositories.NewCloudPermissionRepository(db)
	edges, _, err := grants.ListAssumeEdges(ws, repositories.CloudPermissionFilter{})
	if err != nil {
		t.Fatalf("list assume edges: %v", err)
	}

	var found *models.CloudAssumeEdge
	for i := range edges {
		if edges[i].Mechanism == models.AssumeMechanismEKSPodIdentity {
			found = &edges[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no eks_pod_identity edge among %d edges", len(edges))
	}

	if found.SubjectKind != models.AssumeSubjectK8sSA {
		t.Fatalf("wrong subject kind: %s", found.SubjectKind)
	}
	// The whole basis of the join with the Kubernetes connector: this string
	// must match byte for byte, so it is asserted literally rather than rebuilt.
	const wantSubject = "system:serviceaccount:payments:ledger-agent"
	if found.Subject != wantSubject {
		t.Fatalf("subject must be the k8s subject-account format, got %q want %q", found.Subject, wantSubject)
	}
	if found.K8sRef == nil || *found.K8sRef != wantSubject {
		t.Fatalf("k8s_ref must carry the same string, got %v", found.K8sRef)
	}
	t.Logf("PASS: subject and k8s_ref are both %q", wantSubject)

	// The issuer is what tells two clusters apart, and it must be stored
	// scheme-less so it matches an IAM OIDC provider ARN's suffix.
	if found.Issuer == nil || *found.Issuer != eksIssuerNoSch {
		t.Fatalf("issuer must be the scheme-less cluster issuer, got %v want %q", found.Issuer, eksIssuerNoSch)
	}
	t.Log("PASS: issuer stored scheme-less, matching the IAM OIDC provider format")

	// The edge hangs off the role that was independently discovered, not an
	// identity this surface invented.
	identity, err := repositories.NewCloudIdentityRepository(db).GetIdentityByNativeID(ws, plainRoleARN)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if found.IdentityID != identity.ID {
		t.Fatalf("edge is attached to the wrong identity")
	}
	t.Log("PASS: edge attached to the separately discovered IAM role")
}

// A role that identity discovery never recorded gets no edge and no invented
// identity. The association names a role in another account, or IAM was denied.
func TestEKSAssociationForAnUnknownRoleIsSkippedNotInvented(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-eks-unknown-role")
	defer cleanPermissionTables(t, db, ws)

	const foreign = "arn:aws:iam::999988887777:role/SomeoneElsesRole"
	scanner, snap := eksFixture(t, db, ws, populatedIAM(), podIdentityEKS(foreign))

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	if out.PodIdentityEdges != 0 {
		t.Fatalf("an unknown role must produce no edge, got %d", out.PodIdentityEdges)
	}
	if out.Skipped == 0 {
		t.Fatal("the skip must be counted, not silently dropped")
	}
	if _, err := repositories.NewCloudIdentityRepository(db).
		GetIdentityByNativeID(ws, foreign); err == nil {
		t.Fatal("the EKS surface must never create an identity of its own")
	}
	t.Logf("PASS: unknown role skipped (skipped=%d), no identity invented", out.Skipped)
}

// The rule the whole schema is built on, applied to this surface: a denied EKS
// read must not let reconciliation conclude that Pod Identity bindings are gone.
func TestEKSDeniedReadBlocksReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-eks-denied")
	defer cleanPermissionTables(t, db, ws)

	eksFake := podIdentityEKS(plainRoleARN)
	scanner, snap := eksFixture(t, db, ws, populatedIAM(), eksFake)

	// Baseline: the edge exists.
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	grants := repositories.NewCloudPermissionRepository(db)
	before, _, _ := grants.ListAssumeEdges(ws, repositories.CloudPermissionFilter{})
	if len(before) == 0 {
		t.Fatal("test setup: baseline should have written edges")
	}

	// Now EKS refuses. The bindings still exist in AWS; we simply cannot see
	// them. A later generation must not age them out.
	eksFake.fail["ListClusters"] = denied("eks:ListClusters")
	snap.Generation++

	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("a denied EKS read must not fail the whole scan: %v", err)
	}
	if out.Complete {
		t.Fatal("a scan whose EKS read was denied must not report complete")
	}
	t.Log("PASS: denied EKS read reported the scan as incomplete")

	after, _, _ := grants.ListAssumeEdges(ws, repositories.CloudPermissionFilter{})
	if len(after) != len(before) {
		t.Fatalf("a denied EKS read deleted edges: %d -> %d", len(before), len(after))
	}
	t.Logf("PASS: %d edge(s) preserved — could-not-read is not found-nothing", len(after))
}
