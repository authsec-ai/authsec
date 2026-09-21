// Package igagraph holds the pure logic of the cloud_* -> iga_* projection:
// recognition keys, continuity, the projection decisions and the
// reconciliation gate. Nothing in this package opens a database connection of
// its own, and nothing in it ever writes cloud_* -- the projection is one-way
// by construction, and scripts/ci-iga-isolation-check.sh enforces it.
//
// SPEC-iga-phase2-graph.md §2.4 and §4.4.
package igagraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
)

// Sep is the unit separator that joins the segments of a source key.
//
// It cannot occur in an ARN, a policy name, or a Kubernetes reference, so no
// join is ambiguous and no segment needs escaping. Exported because the
// observation writer builds the qualified permission subject key with the same
// separator -- see PermissionSubjectKey -- and two spellings of that separator
// would silently stop evidence matching its edge.
const Sep = "\x1f"

// Continuity values. Mirrors the CHECK added by migration 027.
const (
	// ContinuityImmutable means the provider gives a creation-boundary id, so
	// a delete-and-recreate under the same name is detectable.
	ContinuityImmutable = "immutable"
	// ContinuityRecognitionOnly means the name is the strongest claim
	// available. Stored rather than implied so the console can say so instead
	// of suggesting a continuity we never verified.
	ContinuityRecognitionOnly = "recognition_only"
)

// Key builds a namespaced source key.
//
// A bare native id is never unique: two AWS accounts, two providers and two
// regions can all produce the same string. The stored form is
//
//	provider | partition | account-or-project | region-if-regional | native-id
//
// An ARN already carries partition, account and (where regional) region, so
// for AWS the provider prefix plus the ARN satisfies that shape on its own.
// The generalised form exists so GitHub and Kubernetes keys cannot collide
// with AWS or with each other.
//
// This is the ONLY place a source key is formatted. Never build one inline:
// two spellings of the key is the same duplication bug in a new costume.
func Key(provider string, parts ...string) string {
	return provider + Sep + strings.Join(parts, Sep)
}

// IdentityKey is the recognition key of an IAM role or user: its ARN.
func IdentityKey(i models.CloudIdentity) string { return Key("aws", i.NativeID) }

// WorkloadKey is the recognition key of a runtime: its function, task
// definition or instance ARN.
func WorkloadKey(w models.CloudWorkload) string { return Key("aws", w.NativeID) }

// ResourceKey is the recognition key of a resource: its ARN, or the selector
// that named it when the selector never resolved. A selector is still a
// distinct grant target, so it still earns a key.
func ResourceKey(r models.CloudResource) string { return Key("aws", r.NativeID) }

// EntitlementKey keys one grant occurrence by its policy scope (§2.6).
//
// cloud_permission.native_id is "<source>#s<n>", where <source> is a managed
// policy ARN or "inline:<name>" (services/cloud_aws_permission_scan.go), and
// the row's grain is (identity, statement, resource) per
// uq_cloud_permission_grant (013:178) -- so one statement naming three
// resources produces three rows and therefore three entitlements.
//
// resourceKey is the projected resource's source key, or "" for an
// account-wide or wildcard grant, which keys as "*".
func EntitlementKey(p models.CloudPermission, holder models.CloudIdentity, resourceKey string) string {
	if resourceKey == "" {
		// An unresolved or wildcard selector is still a distinct grant, and
		// must not collide with a grant that names a resource.
		resourceKey = "*"
	}
	return Key("aws", policyScope(p, holder), p.NativeID, resourceKey)
}

// policyScope decides whether an entitlement is SHARED.
//
// A managed policy is one object two roles can both attach, so both must
// resolve to ONE entitlement -- that is what makes "detach from one role ends
// that grant, the entitlement and the other role's grant survive" true rather
// than aspirational.
//
// An inline policy is not shared. Two roles can each have one named ReadData
// and they are different grants, because the inline name is unique only WITHIN
// an identity. Scoping by the holder's ARN keeps them apart.
func policyScope(p models.CloudPermission, holder models.CloudIdentity) string {
	source, _, _ := strings.Cut(p.NativeID, "#")
	if strings.HasPrefix(source, "inline:") {
		return holder.NativeID
	}
	return source
}

// PermissionSubjectKey is the fully-qualifying subject_native_id for a
// permission observation (§4.8).
//
// A permission's native id alone is ambiguous: one statement produces one
// cloud_permission row per resource, and two holders of the same managed
// policy produce more. Once migration 024 made cloud_observation's subject FKs
// ON DELETE SET NULL, the row id stops being available at all -- the observation
// outlives its subject and subject_native_id is what remains. So the evidence
// has to carry its own unambiguous identity at write time.
//
// Both the observation writer and the projector's evidence pass call this, so
// the key written and the key looked up cannot drift.
func PermissionSubjectKey(p models.CloudPermission, holderNativeID, resourceNativeID string) string {
	if resourceNativeID == "" {
		resourceNativeID = "*"
	}
	return strings.Join([]string{holderNativeID, p.NativeID, resourceNativeID}, Sep)
}

// Qualified reports whether a stored subject_native_id carries the separator,
// i.e. whether it was written by the qualifying writer.
//
// Observations collected before that change cannot be attributed to one grant
// without guessing, so they are never attached as supporting evidence -- see
// indexObservations and §4.8.
func Qualified(subjectNativeID string) bool {
	return strings.Contains(subjectNativeID, Sep)
}

// Continuity reports whether a kind has a provider-given creation boundary.
//
// Only IAM roles and users do, via AWSIdentityAttrs.UniqueID (AROA.../AIDA...),
// which the collector already writes.
//
// EC2 INSTANCES ARE DELIBERATELY NOT immutable HERE, though §4.4 of the spec
// lists them. Verified against the collector: AWSWorkloadAttrs has no
// instance-id or creation-boundary field, and cloud_aws_workload_scan.go
// writes only ExecutionRoleARN, InstanceProfileARN, EnvVarNames,
// FoundationModel and Status. Claiming 'immutable' with nothing to put in
// immutable_key makes 027's CHECK reject every EC2 workload row. The spec's
// own instruction for exactly this case is to fix the mapping or downgrade the
// kind -- never to relax the CHECK. Downgrading is correct until a collector
// records InstanceId; at that point add the case here and to ImmutableKey
// together, never one without the other.
//
// This also resolves §4.4 against §4.6, which states that every runtime kind
// Phase 2 collects is recognition_only: with EC2 downgraded, no workload or
// resource kind is immutable, and only identities are.
func Continuity(kind string) string {
	switch kind {
	case models.CloudIdentityIAMRole, models.CloudIdentityIAMUser:
		return ContinuityImmutable
	default:
		// Lambda, ECS task definition, Bedrock, S3 bucket, EC2 instance: the
		// name is the strongest claim available. Stored so the console can say
		// exactly that rather than implying a continuity we cannot verify.
		return ContinuityRecognitionOnly
	}
}

// ImmutableKey reads the provider's creation-boundary id out of the collected
// attrs, and returns "" where the provider exposes none.
//
// Continuity and ImmutableKey must agree: 027's CHECK rejects a row claiming
// 'immutable' with an empty immutable_key, deliberately -- a silent
// disagreement here disables delete-and-recreate detection entirely, which is
// a failure nothing downstream could detect.
//
// Uses the typed accessor, never a hand-rolled json.Unmarshal of a guessed
// field name: a wrong key returns "" silently while Continuity still says
// 'immutable', and then 027's CHECK rejects every IAM identity.
//
// Note AWSAttrs returns one value, not (attrs, error) -- it decodes to the
// zero value rather than failing a read.
func ImmutableKey(ci models.CloudIdentity) string {
	return ci.AWSAttrs().UniqueID
}

// ScopeKey is the estate scope's recognition key: for AWS, the connected
// account.
//
// cloud_connector.ScopeKind is "account" for AWS -- models.CloudScopeAccount,
// constrained by cloud_connector_scope_kind_chk to
// account|project|folder|org|subscription. It is NOT "aws_account"; the
// provider is carried by the key's own prefix.
func ScopeKey(provider, scopeKind, scopeID string) string {
	return Key(provider, scopeKind, scopeID)
}
