package awsdiscovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

// The EKS read surface: the AWS side of the Kubernetes identity edge, and
// nothing else.
//
// What this discovers is which IAM role a Kubernetes service account may
// assume. It deliberately does NOT discover pods, deployments or workloads --
// the Kubernetes connector already does that, and discovering them here again
// would put the same agent in the inventory twice.
//
// Two distinct AWS mechanisms connect a service account to a role, and only one
// of them is visible here:
//
//   - IRSA. The role's own trust policy carries a Federated principal and a
//     "sub" condition naming the service account. That arrives with the role in
//     iam.go and is classified in trust_policy.go; this file plays no part.
//   - EKS Pod Identity. The association is a first-class EKS resource, and the
//     role's trust policy names the pods.eks.amazonaws.com service principal
//     rather than any service account. So a trust-policy read alone CANNOT see
//     which service account is attached -- this file is the only way to learn
//     it. That is the whole reason this surface exists.
//
// Unlike IAM, EKS is REGIONAL. One reader talks to one region; the caller loops
// over the connector's selected regions and builds a reader per region.

// EKSAPI is the slice of the EKS client this package uses. Narrow on purpose,
// same as IAMAPI: what is not here cannot be called, so this list and the
// CloudFormation template can be compared by eye.
type EKSAPI interface {
	ListClusters(ctx context.Context, in *eks.ListClustersInput, opts ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, opts ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListPodIdentityAssociations(ctx context.Context, in *eks.ListPodIdentityAssociationsInput, opts ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(ctx context.Context, in *eks.DescribePodIdentityAssociationInput, opts ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

// NewEKSClient builds a real EKS client from an assumed-role config. The
// config's region decides which region's clusters are visible.
func NewEKSClient(cfg aws.Config) EKSAPI { return eks.NewFromConfig(cfg) }

// EKSCluster is one cluster, reduced to what the identity edge needs.
type EKSCluster struct {
	Name string
	ARN  string
	// OIDCIssuer is the issuer with the scheme stripped, so it matches
	// oidcIssuerFromARN byte for byte and an EKS cluster can be joined to the
	// IAM OIDC provider registered for it. Empty when the cluster has no OIDC
	// provider configured, which is legitimate for a Pod Identity-only cluster.
	OIDCIssuer string
}

// PodIdentityAssociation is one service-account-to-role binding.
type PodIdentityAssociation struct {
	ClusterName    string
	Namespace      string
	ServiceAccount string
	// RoleARN is the IAM role the service account may assume. It is NOT in the
	// list response -- only the per-association describe returns it, which is
	// why reading this surface costs two calls per association.
	RoleARN        string
	AssociationARN string
	AssociationID  string
}

// K8sSubject is the service account rendered in the format the Kubernetes
// connector already records for the same pod, and the format
// cloud_assume_edge.k8s_ref is constrained to. Built here rather than at the
// persistence layer so both mechanisms -- IRSA's sub claim and a Pod Identity
// association -- produce the identical string for the identical service
// account, which is the entire basis of the join.
func K8sSubject(namespace, serviceAccount string) string {
	return "system:serviceaccount:" + namespace + ":" + serviceAccount
}

// EKSReader performs the paginated reads for one region.
type EKSReader struct{ api EKSAPI }

// NewEKSReader constructs a reader over the given API.
func NewEKSReader(api EKSAPI) *EKSReader { return &EKSReader{api: api} }

// Clusters lists every cluster in the region and resolves each one's OIDC
// issuer.
//
// DescribeCluster is a second call per cluster and is not avoidable:
// ListClusters returns names only. The issuer is what tells two clusters apart
// when both present the same namespace and service account name, and it is
// part of every pod-identity edge's identity (D-42). So a cluster whose
// describe FAILS is left out of this run's list and the failure is RETURNED
// (*ItemFailures, eks_pod_identity partial): its associations are then not
// rewritten with an empty issuer -- which would re-key their edges -- and
// partial keeps every edge they last confirmed, as stale (§1.4). It used to
// be returned with an empty issuer while the surface read reached.
func (r *EKSReader) Clusters(ctx context.Context) ([]EKSCluster, error) {
	var out []EKSCluster
	var next *string
	details := NewItemFailures("clusters could not be read in detail", true)
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: eks clusters", errTooManyPages)
		}
		resp, err := r.api.ListClusters(ctx, &eks.ListClustersInput{NextToken: next})
		if err != nil {
			// Named (D-71: coverage stamps the call and AWS's code), and an
			// endpoint that does not resolve is ErrServiceNotInRegion, as for
			// every regional listing (T3.8). eks_pod_identity is ONE surface
			// across every region, so the caller never turns that into
			// "unsupported" for the whole surface: it skips the one region
			// when no binding was ever recorded there, and otherwise reports
			// it as the failure it may be (writePodIdentityEdges).
			return out, listErr("eks:ListClusters", err)
		}
		for _, name := range resp.Clusters {
			details.Attempt()
			cluster, derr := r.clusterDetail(ctx, name)
			if derr != nil {
				details.Fail(name, "eks:DescribeCluster", derr)
				continue
			}
			out = append(out, cluster)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, details.Err(nil)
		}
		next = resp.NextToken
	}
}

// clusterDetail enriches a listed cluster name with DescribeCluster.
func (r *EKSReader) clusterDetail(ctx context.Context, name string) (EKSCluster, error) {
	built := EKSCluster{Name: name}

	detail, err := r.api.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
	if err == nil && detail.Cluster == nil {
		err = fmt.Errorf("DescribeCluster returned no cluster for %s", name)
	}
	if err != nil {
		return built, err
	}
	built.ARN = aws.ToString(detail.Cluster.Arn)
	if id := detail.Cluster.Identity; id != nil && id.Oidc != nil {
		built.OIDCIssuer = issuerWithoutScheme(aws.ToString(id.Oidc.Issuer))
	}
	return built, nil
}

// PodIdentityAssociations reads one cluster's associations, resolving the role
// for each.
//
// A describe that fails skips that one association -- an edge without its role
// would be a binding pointing at nothing -- and is COUNTED: the associations
// read are returned beside an *ItemFailures error, so eks_pod_identity reads
// partial and the skipped association's edge is kept as stale, never ended
// (§1.4). It used to be skipped silently while the surface read reached, which
// let reconciliation end a binding it had simply failed to read.
func (r *EKSReader) PodIdentityAssociations(ctx context.Context, clusterName string) ([]PodIdentityAssociation, error) {
	var out []PodIdentityAssociation
	var next *string
	details := NewItemFailures("pod identity associations could not be read in detail", true)
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: pod identity associations", errTooManyPages)
		}
		resp, err := r.api.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: aws.String(clusterName), NextToken: next,
		})
		if err != nil {
			return out, withCallName("eks:ListPodIdentityAssociations", err)
		}
		for _, summary := range resp.Associations {
			id := aws.ToString(summary.AssociationId)
			if id == "" {
				continue
			}
			details.Attempt()
			assoc, ok, derr := r.associationDetail(ctx, clusterName, id)
			if derr != nil {
				details.Fail(id, "eks:DescribePodIdentityAssociation", derr)
				continue
			}
			if !ok {
				continue
			}
			out = append(out, assoc)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, details.Err(nil)
		}
		next = resp.NextToken
	}
}

// associationDetail resolves the role ARN, which the list response omits. An
// error means the describe failed; ok=false with no error means AWS answered
// with an association this package cannot bind (no role, or half a service
// account), which is skipped as before.
func (r *EKSReader) associationDetail(
	ctx context.Context, clusterName, associationID string,
) (PodIdentityAssociation, bool, error) {

	detail, err := r.api.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		ClusterName: aws.String(clusterName), AssociationId: aws.String(associationID),
	})
	if err == nil && detail.Association == nil {
		err = fmt.Errorf("DescribePodIdentityAssociation returned no association for %s", associationID)
	}
	if err != nil {
		return PodIdentityAssociation{}, false, err
	}
	a := detail.Association

	built := PodIdentityAssociation{
		ClusterName:    clusterName,
		Namespace:      aws.ToString(a.Namespace),
		ServiceAccount: aws.ToString(a.ServiceAccount),
		RoleARN:        aws.ToString(a.RoleArn),
		AssociationARN: aws.ToString(a.AssociationArn),
		AssociationID:  associationID,
	}
	// Without a role there is no edge to record, and without both halves of the
	// service account the k8s_ref would not match what the Kubernetes connector
	// wrote for the same pod.
	if built.RoleARN == "" || built.Namespace == "" || built.ServiceAccount == "" {
		return PodIdentityAssociation{}, false, nil
	}
	return built, true, nil
}

// issuerWithoutScheme strips https:// from an EKS OIDC issuer URL.
//
// EKS reports the issuer as a URL; an IAM OIDC provider ARN carries the same
// value with no scheme. cloud_assume_edge.issuer stores the scheme-less form,
// so the two sources agree and a cluster can be matched to its provider.
func issuerWithoutScheme(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	issuer = strings.TrimPrefix(issuer, "https://")
	issuer = strings.TrimPrefix(issuer, "http://")
	return strings.TrimSuffix(issuer, "/")
}
