package services

import (
	"log"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Evidence for two surfaces §1.4 says persist "with an observation added"
// (T3.5): iam_access_keys and eks_pod_identity. Both are called from the
// scanner that owns the surface, right after the row they explain is written,
// and -- like every other evidence write -- a failure is logged, never fatal:
// losing the explanation for a row is bad, losing the row is worse.
//
// Both observations have an IDENTITY as their typed subject (cloud_observation
// has no column for a credential or an association), so neither may use the
// identity's own ARN as subject_native_id: the projector joins evidence on
// (kind, subject_native_id), and an identity-ARN key would make an access key
// or a pod binding "supporting evidence" for every grant, assignment and
// member_of edge the identity holds. Each is keyed by the igagraph helper
// that names it instead.

// recordAccessKeyEvidence writes one access key's observation:
// iam:ListAccessKeys under iam_access_keys, subject the user, keyed by the key
// id (igagraph.AccessKeyEvidenceKey) -- the credential's own key, which
// cloud_secret.native_id and iga_credentials.key_identifier also hold.
//
// LAST USED IS DELIBERATELY NOT A FACT. The content hash is the dedupe key
// (022), and an active key's last-used date moves on almost every scan, so
// hashing it would write a NEW observation per active key per scan -- exactly
// the growth the flat-storage dedupe exists to prevent -- while saying nothing
// the credential row does not: last_used_at is persisted on cloud_secret (and
// projected to iga_credentials), where it is overwritten in place. What the
// observation evidences is what changes rarely and matters when it does: the
// key exists, its status, when it was created. A status flip (Active ->
// Inactive) is a new fact and a new observation, as it should be.
func (s *AWSIAMScanner) recordAccessKeyEvidence(userIdentityID uuid.UUID, key awsdiscovery.IAMAccessKey) {
	if s.evidence == nil || key.KeyID == "" {
		return
	}
	// observed_at is the provider's own time where it gave one, as for every
	// identity observation: a delayed scan must not look like a change.
	observed := time.Now()
	if key.CreatedAt != nil {
		observed = *key.CreatedAt
	}
	if err := s.evidence.Record(
		IdentitySubject(userIdentityID), "iam:ListAccessKeys",
		models.SurfaceIAMAccessKeys, s.evidenceSurfaceState(models.SurfaceIAMAccessKeys),
		observed, igagraph.AccessKeyEvidenceKey(key.KeyID),
		map[string]any{
			"kind":       models.CloudSecretAccessKey,
			"key_id":     key.KeyID,
			"user_name":  key.UserName,
			"status":     key.Status,
			"created_at": key.CreatedAt,
		},
	); err != nil {
		log.Printf("aws iam scan: access key evidence for %s: %v", key.KeyID, err)
	}
}

// recordPodIdentityEvidence writes one EKS Pod Identity association's
// observation: eks:DescribePodIdentityAssociation under eks_pod_identity,
// subject the ROLE the service account may assume, keyed by
// igagraph.PodIdentityEvidenceKey(role ARN, the edge's issuer, the edge's
// subject) -- all three read back off the cloud_assume_edge row just written,
// so the projector's pod-identity can_assume pass rebuilds the same key from
// its snapshot (§4.8: "pod identity: the association's observation").
func (s *AWSPermissionScanner) recordPodIdentityEvidence(
	roleIdentityID uuid.UUID, cluster awsdiscovery.EKSCluster,
	assoc awsdiscovery.PodIdentityAssociation, edge *models.CloudAssumeEdge,
) {
	if s.evidence == nil || edge == nil {
		return
	}
	issuer := ""
	if edge.Issuer != nil {
		issuer = *edge.Issuer
	}
	if err := s.evidence.Record(
		IdentitySubject(roleIdentityID), "eks:DescribePodIdentityAssociation",
		models.SurfaceEKSPodIdentity, "", time.Now(),
		igagraph.PodIdentityEvidenceKey(assoc.RoleARN, issuer, edge.Subject),
		map[string]any{
			"region":          arnField(cluster.ARN, 3),
			"cluster_name":    cluster.Name,
			"cluster_arn":     cluster.ARN,
			"oidc_issuer":     cluster.OIDCIssuer,
			"namespace":       assoc.Namespace,
			"service_account": assoc.ServiceAccount,
			"k8s_subject":     edge.Subject,
			"role_arn":        assoc.RoleARN,
			"association_arn": assoc.AssociationARN,
			"association_id":  assoc.AssociationID,
		},
	); err != nil {
		log.Printf("aws permission scan: pod identity evidence for %s: %v", assoc.AssociationID, err)
	}
}

// arnField returns field i of an ARN (arn:partition:service:region:account:...),
// "" when the ARN is shorter. Region is field 3.
func arnField(arn string, i int) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || i >= len(parts) {
		return ""
	}
	return parts[i]
}
