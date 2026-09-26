// Package igagraph holds the pure logic of the cloud_* -> iga_* projection:
// recognition keys, continuity, the projection decisions and the
// reconciliation gate. Nothing in this package opens a database connection of
// its own, and nothing in it ever writes cloud_* -- the projection is one-way
// by construction, and scripts/ci-iga-isolation-check.sh enforces it.
//
// SPEC-iga-phase2-graph.md §2.4 and §4.4.
package igagraph

import (
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// Sep is the unit separator that joins the segments of a source key.
//
// It cannot occur in an ARN, a policy name, or a Kubernetes reference, so no
// join is ambiguous and no segment needs escaping.
const Sep = "\x1f"

// Continuity values. Mirrors the CHECK added by migration 028.
const (
	// ContinuityImmutable means the provider gives a creation-boundary id, so
	// a delete-and-recreate under the same name is detectable.
	ContinuityImmutable = models.ContinuityImmutable
	// ContinuityRecognitionOnly means the name is the strongest claim
	// available. Stored rather than implied so the console can say so instead
	// of suggesting a continuity we never verified.
	ContinuityRecognitionOnly = models.ContinuityRecognitionOnly
)

// Key builds a namespaced source key: provider ␟ part ␟ part ...
//
// THIS IS THE ONLY PLACE A SOURCE KEY IS FORMATTED. Never build one inline:
// two spellings of the key is the duplication bug in a new costume.
func Key(provider string, parts ...string) string {
	return provider + Sep + strings.Join(parts, Sep)
}

// IdentityKey is the recognition key of an IAM role, user or group: its ARN.
func IdentityKey(i models.CloudIdentity) string { return IdentityARNKey(i.NativeID) }

// IdentityARNKey is IdentityKey spelled from the ARN alone -- how a trust
// principal naming an identity in ANOTHER account finds its live row, which
// this run did not collect.
func IdentityARNKey(arn string) string { return Key("aws", arn) }

// ImmutableKey reads the creation boundary the collector wrote into attrs:
// RoleId (AROA…), UserId (AIDA…) or GroupId (AGPA…). "" where there is none.
//
// Continuity and ImmutableKey must agree: 028's CHECK rejects 'immutable' with
// an empty key, and that loud failure is correct -- fix the mapping, never
// relax the check.
func ImmutableKey(ci models.CloudIdentity) string { return ci.AWSAttrs().UniqueID }

// EndpointKey names an identity INSIDE AN EDGE KEY: its immutable key when it
// has one, so a role recreated under the same ARN yields different edge keys
// and inherits none of the old role's relationships.
func EndpointKey(ci models.CloudIdentity) string {
	if imm := ImmutableKey(ci); imm != "" {
		return Key("aws", "uid", imm)
	}
	return IdentityKey(ci)
}

// WorkloadKey is the recognition key of a runtime: its ARN, CONSTRUCTED where
// the collector stores a bare id (EC2 instances, and rows a collector wrote
// before it constructed Bedrock agent and gateway ARNs itself), so the key
// never changes with a transient failure.
func WorkloadKey(w models.CloudWorkload, partition, account string) string {
	return Key("aws", WorkloadARN(w, partition, account))
}

// WorkloadARN returns the collected ARN, or constructs one from the bare id in
// the connector's PARTITION ("" means aws). It delegates to
// awsdiscovery.WorkloadARN -- the same constructor the collector keys a
// Bedrock agent or gateway with when its detail call fails -- so a row the
// collector keyed by a constructed ARN and a row the graph keys by one agree
// byte for byte, in aws-us-gov and aws-cn as in aws (§1.3, T3.6).
func WorkloadARN(w models.CloudWorkload, partition, account string) string {
	return awsdiscovery.WorkloadARN(partition, w.RuntimeKind, w.Region, account, w.NativeID)
}

// PolicyKey is the RECOGNITION key of a policy: what it is called. Managed
// policies are one object across holders and accounts; inline policies belong
// to their holder. Used only to find the live object and detect recreation.
func PolicyKey(p models.CloudPolicy, holder *models.CloudIdentity) string {
	if p.PolicyKind == models.CloudPolicyInline && holder != nil {
		return Key("aws", "inline", holder.NativeID, p.Name)
	}
	return Key("aws", p.NativeID) // the policy ARN
}

// PolicyImmutableKey is the policy's creation boundary: the PolicyId for a
// managed policy; the holder's immutable key for an inline policy, because an
// inline policy lives and dies with its holder.
func PolicyImmutableKey(p models.CloudPolicy, holder *models.CloudIdentity) string {
	if p.PolicyKind == models.CloudPolicyInline {
		if holder == nil {
			return ""
		}
		return ImmutableKey(*holder)
	}
	return p.PolicyID
}

// PolicyIncarnationKey names ONE incarnation of a policy. Every descendant key
// -- statements, assignments, grants -- is built from this, never from the ARN,
// so a recreated policy shares no key with its predecessor (§2.4).
//
// immutable is the incarnation's creation boundary, normally
// PolicyImmutableKey(p, holder). It is passed in because an UNREADABLE policy
// whose GetPolicy failed has no PolicyId this run, and must keep the
// incarnation the graph already holds rather than mint an empty one.
func PolicyIncarnationKey(p models.CloudPolicy, holder *models.CloudIdentity, immutable string) string {
	if p.PolicyKind == models.CloudPolicyInline && holder != nil {
		return Key("aws", "inline", EndpointKey(*holder), p.Name)
	}
	return Key("aws", "policy", immutable)
}

// PolicyKind maps the collected row to iga_policy.policy_kind.
func PolicyKind(p models.CloudPolicy) string {
	switch {
	case p.PolicyKind == models.CloudPolicyInline:
		return models.PolicyKindInline
	case p.AWSManaged:
		return models.PolicyKindAWSManaged
	default:
		return models.PolicyKindCustomerManaged
	}
}

// StatementKey implements §2.6: sid:<Sid> when the Sid is unique within the
// document, else h:<content hash>#n where n disambiguates identical Sid-less
// statements by their order among equals. `sids` counts Sid occurrences in the
// document; `hashSeen` counts content hashes seen so far, in document order.
//
// A reorder keeps every key. A Sid-keyed edit keeps the key (and records a
// revision); a Sid-less edit changes the hash, so the old statement ends and a
// new one begins.
func StatementKey(policyIncarnation string, st awsdiscovery.PolicyStatement,
	sids map[string]int, hashSeen map[string]int) (key, hash string) {
	hash = st.ContentHash()
	if st.Sid != "" && sids[st.Sid] == 1 {
		return Key("aws", policyIncarnation, "stmt", "sid:"+st.Sid), hash
	}
	hashSeen[hash]++
	return Key("aws", policyIncarnation, "stmt", fmt.Sprintf("h:%s#%d", hash, hashSeen[hash])), hash
}

// SidKeyed reports whether a statement key is Sid-keyed, which is what earns
// it revisions rather than replacement.
func SidKeyed(statementKey string) bool {
	return strings.Contains(statementKey, Sep+"sid:")
}

// CountSids counts each Sid's occurrences in a document, for StatementKey.
func CountSids(stmts []awsdiscovery.PolicyStatement) map[string]int {
	out := map[string]int{}
	for _, st := range stmts {
		if st.Sid != "" {
			out[st.Sid]++
		}
	}
	return out
}

// ResourceRefKey keys a resource reference by the text the statement used. An
// exact ARN and a pattern are different objects; "*" is one workspace-wide
// selector node, supported per connector.
func ResourceRefKey(resource string) string { return Key("aws", "ref", resource) }

// AssignmentKey: policy incarnation ␟ holder endpoint ␟ kind.
func AssignmentKey(policyIncarnation, holderEndpoint, kind string) string {
	return Key("aws", "assign", policyIncarnation, holderEndpoint, kind)
}

// GrantKey: assignment ␟ statement.
func GrantKey(assignmentKey, statementKey string) string {
	return Key("aws", "grant", assignmentKey, statementKey)
}

// RelationshipKey names both endpoints, so moving a Lambda from RoleA to
// RoleB computes a NEW key and the old edge ends instead of being overwritten.
func RelationshipKey(relType, sourceKey, targetEndpoint string) string {
	return Key("aws", relType, sourceKey, targetEndpoint)
}

// ExternalPrincipalKey is an external principal's recognition key: issuer ␟
// subject (§2.4, §4.4), exactly as §4.4 spells it. The kind is NOT part of it,
// so the normalisation must keep kinds apart by subject: D-42's issuers and
// subjects do (and PodIdentitySubject is why an IRSA node and a pod-identity
// node for one service account do not collide).
//
// It is also the principal's ENDPOINT key inside a can_assume edge key (D-41).
func ExternalPrincipalKey(issuer, subject string) string {
	return Key("aws", "ext", issuer, subject)
}

// IdentityAccountEndpointKey is EndpointKey spelled from a graph row -- how a
// trust principal names an identity this run did not collect (another
// connector's, §4.7) inside an edge key. The same two spellings as EndpointKey:
// the immutable key when the row has one, else its source key (the ARN key).
// So an identity reached through its own connector and through another
// account's trust document is one endpoint, never two.
func IdentityAccountEndpointKey(a models.IGAIdentityAccount) string {
	if a.ImmutableKey != "" {
		return Key("aws", "uid", a.ImmutableKey)
	}
	return a.SourceKey
}

// TrustStatementKey names one statement of a role's trust document, as
// StatementKey names a policy statement (§2.6, §4.7): the role's endpoint key
// ␟ trust ␟ sid:<Sid> when the Sid is unique in the document, else h:<content
// hash>#n, n numbering identical Sid-less statements by their order among
// equals. The hash covers Principal and NotPrincipal (D-46).
//
// Built from the role's ENDPOINT key, so a role recreated under the same ARN
// shares no statement -- and no edge -- with its predecessor.
func TrustStatementKey(roleEndpoint string, st awsdiscovery.TrustStatement,
	sids map[string]int, hashSeen map[string]int) (key, hash string) {
	hash = st.ContentHash()
	if st.Sid != "" && sids[st.Sid] == 1 {
		return Key("aws", roleEndpoint, "trust", "sid:"+st.Sid), hash
	}
	hashSeen[hash]++
	return Key("aws", roleEndpoint, "trust", fmt.Sprintf("h:%s#%d", hash, hashSeen[hash])), hash
}

// CountTrustSids counts each Sid's occurrences in a trust document, for
// TrustStatementKey.
func CountTrustSids(stmts []awsdiscovery.TrustStatement) map[string]int {
	out := map[string]int{}
	for _, st := range stmts {
		if st.Sid != "" {
			out[st.Sid]++
		}
	}
	return out
}

// PodIdentityStatementKey names the declaration behind a pod-identity
// can_assume: no trust statement names the service account, the EKS
// association does -- one per (role, cluster issuer, service account). k8sRef
// is system:serviceaccount:<ns>:<sa>.
func PodIdentityStatementKey(roleEndpoint, issuer, k8sRef string) string {
	return Key("aws", roleEndpoint, "pod_identity", issuer, k8sRef)
}

// CanAssumeKey names a can_assume edge by the declaring statement, the SOURCE
// endpoint and the TARGET endpoint (§4.4, §4.6, §4.7; P2-DECISIONS D-41) --
// RelationshipKey with the statement added, so two statements naming one
// principal under different conditions are two edges.
//
// sourceEndpoint is the source's endpoint key: EndpointKey (or
// IdentityAccountEndpointKey) for an identity, ExternalPrincipalKey for an
// external principal. Never a principal's ARN standing in for an identity
// (B7's ARN-only defect): a recreated source or target yields a new key, and
// no edge is ever re-pointed from one source to another in place. What
// continues across a far account connecting is the external principal NODE
// (its derived resolution, §2.12), not a re-sourced edge.
func CanAssumeKey(sourceEndpoint, targetEndpoint, statementKey string) string {
	return Key("aws", models.RelTypeCanAssume, sourceEndpoint, targetEndpoint, statementKey)
}

// PodIdentitySubject is the subject_claim of the k8s_service_account node an
// EKS Pod Identity association names (D-42): system:serviceaccount:<ns>:<sa>
// prefixed "pod:". An IRSA trust statement names the same service account as
// an `oidc` node under the same issuer; ExternalPrincipalKey omits the kind,
// so without the prefix the two would collide on
// uq_iga_external_principal_key (D-42's Raise, until decided).
func PodIdentitySubject(k8sRef string) string { return "pod:" + k8sRef }

// PodIdentitySubjectKey is the subject_native_id of a pod-identity
// association's observation (§4.8: its can_assume evidence is "the
// association's observation"; §1.4: eks_pod_identity "observation added").
// The writer (T3.5) records it with the ROLE as the typed subject and this
// key, so it indexes as SubjectRef{identity, key} beside -- never colliding
// with -- the role's own observation, keyed by the bare ARN. Built from values
// both the collector and Snapshot.PodIdentity carry: the role ARN, the
// cluster's scheme-less OIDC issuer and system:serviceaccount:<ns>:<sa>.
func PodIdentitySubjectKey(roleARN, issuer, k8sRef string) string {
	return Key("aws", "pod_identity", roleARN, issuer, k8sRef)
}

// CredentialKey: holder ARN ␟ key id (§2.4).
func CredentialKey(holder models.CloudIdentity, keyID string) string {
	return Key("aws", holder.NativeID, keyID)
}

// ScopeKey is the estate scope's recognition key: for AWS, the connected
// account (§4.8).
func ScopeKey(provider, scopeKind, scopeID string) string {
	return Key(provider, scopeKind, scopeID)
}

// Continuity reports whether a kind has a provider-given creation boundary.
//
// Roles, users and groups carry RoleId / UserId / GroupId; managed policies a
// PolicyId; inline policies their holder's. Workloads, resource references and
// external principals do not: the name is the strongest claim available, and
// continuity says so rather than implying a check we never made.
func Continuity(kind string) string {
	switch kind {
	case models.CloudIdentityIAMRole, models.CloudIdentityIAMUser, models.CloudIdentityIAMGroup,
		"managed_policy", "inline_policy":
		return ContinuityImmutable
	default:
		return ContinuityRecognitionOnly
	}
}

// PolicyContinuityKind is the Continuity() kind for a collected policy.
func PolicyContinuityKind(p models.CloudPolicy) string {
	if p.PolicyKind == models.CloudPolicyInline {
		return "inline_policy"
	}
	return "managed_policy"
}

// PermissionSubjectKey is the qualifying subject_native_id of a cloud_permission
// observation: holder ␟ statement native id ␟ resource. Kept for Cloud
// Inventory's evidence (§1.5); the projector no longer reads permission
// observations -- grants are evidenced by the policy version and the holder.
func PermissionSubjectKey(p models.CloudPermission, holderNativeID, resourceNativeID string) string {
	if resourceNativeID == "" {
		resourceNativeID = "*"
	}
	return strings.Join([]string{holderNativeID, p.NativeID, resourceNativeID}, Sep)
}

// Qualified reports whether a stored subject_native_id carries the separator,
// i.e. was written by the qualifying writer.
func Qualified(subjectNativeID string) bool {
	return strings.Contains(subjectNativeID, Sep)
}

// EscapeSegment percent-encodes bytes that would make a joined source key
// ambiguous. Existing AWS keys do not use this — an ARN cannot contain the
// unit separator — but AD forest names are untrusted directory text.
//
// Encoding: each of 0x00–0x1F (including the unit separator), 0x7F, '%', '/'
// and '\\' becomes '%' plus two uppercase hex digits. The escape character
// itself is encoded, so a literal "%1F" cannot collide with an encoded
// separator. Commas and '=' are not separators in this scheme and are left
// as-is, which keeps a DN readable. Apply it to every AD segment before Key.
func EscapeSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F || c == '%' || c == '/' || c == '\\' {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ADIdentityKey is the recognition key of an AD object (§4.2):
//
//	ad ␟ escaped(forest ID) ␟ canonical objectGUID
//
// Forest ID is rootDSE rootDomainNamingContext. The GUID is the canonical
// text after the AD mixed-endian conversion, not the raw RFC 4122 reading of
// the bytes. The SID is not part of the key — it is a secondary identifier —
// and neither is the DN, so a rename (modrdn) keeps the identity. A different
// objectGUID is a different object even when the names match.
func ADIdentityKey(forestID, canonicalGUID string) (string, error) {
	forestID = strings.TrimSpace(forestID)
	canonicalGUID = strings.ToLower(strings.TrimSpace(canonicalGUID))
	if forestID == "" || canonicalGUID == "" {
		return "", fmt.Errorf("ad identity key requires a forest id and a canonical objectGUID")
	}
	return Key("ad", EscapeSegment(forestID), EscapeSegment(canonicalGUID)), nil
}

// UnescapeSegment reverses EscapeSegment. A truncated or non-hex escape is an error.
func UnescapeSegment(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated escape in %q", s)
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

func segment(name, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return EscapeSegment(value), nil
}

func parts(pairs ...[2]string) ([]string, error) {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		s, err := segment(p[0], p[1])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// HostKey is the local host. The server estate bound at enrollment is the
// key. machine-id is not a component: a clone keeps its machine-id and must
// not become the same host.
func HostKey(estateID string) (string, error) {
	p, err := parts([2]string{"estate", estateID})
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"host"}, p...)...), nil
}

// SystemdWorkloadKey is the durable unit. An invocation id is a run, not this key.
func SystemdWorkloadKey(estateID, unit string) (string, error) {
	p, err := parts([2]string{"estate", estateID}, [2]string{"unit", unit})
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"systemd"}, p...)...), nil
}

// UnmanagedProcessGroupKey is one boot's process lineage. The executable path
// is not a component.
func UnmanagedProcessGroupKey(estateID, bootID, rootPID, startTicks string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"boot", bootID},
		[2]string{"root pid", rootPID},
		[2]string{"start ticks", startTicks},
	)
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"process-group"}, p...)...), nil
}

// ProcessRuntimeKey includes start ticks so a reused PID is a different runtime.
func ProcessRuntimeKey(estateID, bootID, pidNS, pid, startTicks string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"boot", bootID},
		[2]string{"pid namespace", pidNS},
		[2]string{"pid", pid},
		[2]string{"start ticks", startTicks},
	)
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"process"}, p...)...), nil
}

// LocalIdentityKey is estate + user namespace + UID. The account name is not
// a component, so a rename keeps the identity. UID 1000 on two estates is
// two identities.
func LocalIdentityKey(estateID, userNS, uid string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"user namespace", userNS},
		[2]string{"uid", uid},
	)
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"uid"}, p...)...), nil
}

// KubernetesWorkloadKey does not include the object UID. The UID is the
// incarnation, recorded separately. slot distinguishes containers of one object.
func KubernetesWorkloadKey(estateID, group, kind, namespace, name, slot string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"group", group},
		[2]string{"kind", kind},
		[2]string{"namespace", namespace},
		[2]string{"name", name},
		[2]string{"slot", slot},
	)
	if err != nil {
		return "", err
	}
	return Key("kubernetes", append([]string{"workload"}, p...)...), nil
}

// KubernetesRuntimeKey is one container execution. A new restart or runtime
// id is a new row.
func KubernetesRuntimeKey(estateID, podUID, container, restart, runtimeID string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"pod uid", podUID},
		[2]string{"container", container},
		[2]string{"restart", restart},
		[2]string{"runtime id", runtimeID},
	)
	if err != nil {
		return "", err
	}
	return Key("kubernetes", append([]string{"runtime"}, p...)...), nil
}

// KubernetesServiceAccountKey is namespace + name. The ServiceAccount UID is
// the incarnation, not the recognition key.
func KubernetesServiceAccountKey(estateID, namespace, name string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"namespace", namespace},
		[2]string{"name", name},
	)
	if err != nil {
		return "", err
	}
	return Key("kubernetes", append([]string{"sa"}, p...)...), nil
}

// FileResourceKey escapes the path so a slash or a unit separator cannot
// change how many segments the key has.
func FileResourceKey(estateID, mntNS, path string) (string, error) {
	p, err := parts(
		[2]string{"estate", estateID},
		[2]string{"mount namespace", mntNS},
		[2]string{"path", path},
	)
	if err != nil {
		return "", err
	}
	return Key("linux", append([]string{"file"}, p...)...), nil
}

// NetworkEndpointKey is the network endpoint. It is not EndpointKey, which
// names an AWS identity inside an edge. A private address includes the estate
// so two hosts do not share it. A public address does not.
func NetworkEndpointKey(family, address, port, protocol, estate string, private bool) (string, error) {
	if private && strings.TrimSpace(estate) == "" {
		return "", fmt.Errorf("a private endpoint requires an estate")
	}
	p, err := parts(
		[2]string{"family", family},
		[2]string{"address", address},
		[2]string{"port", port},
		[2]string{"protocol", protocol},
	)
	if err != nil {
		return "", err
	}
	if private {
		est, err := segment("estate", estate)
		if err != nil {
			return "", err
		}
		p = append(p, est)
	}
	return Key("network", p...), nil
}

// SecretRefKey names a secret reference. There is no value parameter: a
// secret value must not enter a key.
func SecretRefKey(provider, estateOrIssuer, namespace, name, key string) (string, error) {
	p, err := parts(
		[2]string{"provider", provider},
		[2]string{"estate or issuer", estateOrIssuer},
		[2]string{"namespace", namespace},
		[2]string{"name", name},
	)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(key) != "" {
		k, err := segment("key", key)
		if err != nil {
			return "", err
		}
		p = append(p, k)
	}
	return Key("secret", p...), nil
}
