package igagraph

// Evidence subject keys for observations whose typed subject is an IDENTITY
// but which are NOT evidence about that identity's own configuration (T3.5).
//
// indexObservations keys evidence by (subject kind, subject_native_id) only.
// An identity's own observation is keyed by its ARN, and attachEvidence links
// SubjectRef{identity, <holder ARN>} to every grant, assignment and member_of
// edge the identity holds (§4.8). An access key or a pod-identity association
// recorded under the same key would become "supporting evidence" for all of
// them -- a key's last rotation cited as proof that a policy is attached. So
// each gets a key of its own, built HERE, once, for the collector that writes
// it and for any projector or reader that joins on it: the two cannot drift.

// AccessKeyEvidenceKey is the subject_native_id of an access key's observation
// (iam:ListAccessKeys): the key id itself. Access key ids are globally unique,
// never an ARN, and are what cloud_secret.native_id and
// iga_credentials.key_identifier already hold, so the credential joins to its
// evidence without a separator and without colliding with any identity key.
func AccessKeyEvidenceKey(keyID string) string { return keyID }

// PodIdentityEvidenceKey is the subject_native_id of an EKS Pod Identity
// association's observation (eks:DescribePodIdentityAssociation), whose typed
// subject is the ROLE the service account may assume: aws ␟ pod_identity ␟
// role ARN ␟ issuer ␟ Kubernetes subject. Every part is on the collected
// cloud_assume_edge row (the role through identity_id, then issuer and
// subject), so the projector's pod-identity can_assume pass (§4.8: "pod
// identity: the association's observation") rebuilds the key from its
// snapshot exactly. The issuer is the one the edge row stores, "" when the
// cluster has none -- D-42 leaves such an association without an edge, so
// nothing joins on that key.
//
// The "pod_identity" segment keeps it clear of the role's own observation
// (the bare ARN) and of every other key shape. It is the string the trust
// projection (T4.7) builds for the same join; the two must stay byte-equal.
func PodIdentityEvidenceKey(roleARN, issuer, k8sSubject string) string {
	return Key("aws", "pod_identity", roleARN, issuer, k8sSubject)
}
