package igagraph

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

func identity(nativeID, kind, uniqueID string) models.CloudIdentity {
	attrs, _ := json.Marshal(models.AWSIdentityAttrs{UniqueID: uniqueID})
	return models.CloudIdentity{NativeID: nativeID, Kind: kind, Attrs: attrs}
}

func perm(nativeID string) models.CloudPermission {
	return models.CloudPermission{NativeID: nativeID}
}

// P2-3 gate: a bare native id is never unique, so the key must namespace it.
func TestKeyIsNamespaced(t *testing.T) {
	k := Key("aws", "arn:aws:iam::1234:role/foo")
	if !strings.HasPrefix(k, "aws"+Sep) {
		t.Fatalf("key is not provider-namespaced: %q", k)
	}
	// The separator cannot occur in an ARN, so the segment count is exact.
	if got := strings.Count(k, Sep); got != 1 {
		t.Fatalf("want 1 separator, got %d in %q", got, k)
	}
	// A GitHub key with the same native id must not collide with the AWS one.
	if Key("github", "arn:aws:iam::1234:role/foo") == k {
		t.Fatal("github and aws keys collided")
	}
}

// P2-3 gate: two accounts with the same role name produce DIFFERENT keys.
// §2.12 -- ARNs differ in the account segment, and equal display names never
// merge.
func TestSameRoleNameDifferentAccountsDiffer(t *testing.T) {
	a := IdentityKey(identity("arn:aws:iam::111111111111:role/deploy", models.CloudIdentityIAMRole, "AROAA"))
	b := IdentityKey(identity("arn:aws:iam::222222222222:role/deploy", models.CloudIdentityIAMRole, "AROAB"))
	if a == b {
		t.Fatalf("two accounts' deploy roles produced one key: %q", a)
	}
}

// P2-3 gate: the SAME role seen through two connectors produces the SAME key.
// An integration is a route, not an identity -- reconnecting must not mint a
// new object.
func TestSameRoleTwoConnectorsMatch(t *testing.T) {
	const arn = "arn:aws:iam::111111111111:role/deploy"
	viaA := identity(arn, models.CloudIdentityIAMRole, "AROAA")
	viaB := identity(arn, models.CloudIdentityIAMRole, "AROAA")
	// Different connector rows entirely; the key must not notice.
	if IdentityKey(viaA) != IdentityKey(viaB) {
		t.Fatal("one role through two connectors produced two keys")
	}
}

// P2-3 gate, §2.6: two roles EACH with an inline policy named ReadData produce
// DIFFERENT entitlement keys. The inline name is unique only within an
// identity, so an unscoped key would silently merge two unrelated grants.
func TestInlinePolicyNameCollisionKeysApart(t *testing.T) {
	roleA := identity("arn:aws:iam::1234:role/alpha", models.CloudIdentityIAMRole, "AROAA")
	roleB := identity("arn:aws:iam::1234:role/beta", models.CloudIdentityIAMRole, "AROAB")
	p := perm("inline:ReadData#s0")

	ka := EntitlementKey(p, roleA, "aws\x1farn:aws:s3:::bucket")
	kb := EntitlementKey(p, roleB, "aws\x1farn:aws:s3:::bucket")
	if ka == kb {
		t.Fatalf("two roles' inline ReadData collapsed into one entitlement: %q", ka)
	}
	// Each must be scoped by its own holder ARN, not by the policy name.
	if !strings.Contains(ka, roleA.NativeID) || !strings.Contains(kb, roleB.NativeID) {
		t.Fatalf("inline entitlement key is not holder-scoped:\n  a=%q\n  b=%q", ka, kb)
	}
}

// P2-3 gate, §2.6: two roles attached to the SAME managed policy produce the
// SAME entitlement key -- one entitlement, two access edges. This is what
// makes "detach from one role ends that grant, the entitlement and the other
// role's grant survive" true rather than aspirational.
func TestManagedPolicySharedAcrossRoles(t *testing.T) {
	roleA := identity("arn:aws:iam::1234:role/alpha", models.CloudIdentityIAMRole, "AROAA")
	roleB := identity("arn:aws:iam::1234:role/beta", models.CloudIdentityIAMRole, "AROAB")
	p := perm("arn:aws:iam::1234:policy/RefundS3Access#s0")

	ka := EntitlementKey(p, roleA, "aws\x1farn:aws:s3:::refunds/*")
	kb := EntitlementKey(p, roleB, "aws\x1farn:aws:s3:::refunds/*")
	if ka != kb {
		t.Fatalf("one managed policy produced two entitlements:\n  a=%q\n  b=%q", ka, kb)
	}
	// And it must be scoped by the POLICY, never by a holder.
	if strings.Contains(ka, roleA.NativeID) || strings.Contains(ka, roleB.NativeID) {
		t.Fatalf("managed entitlement key leaked a holder ARN: %q", ka)
	}
}

// P2-3 gate, §2.6: one statement naming three resources produces THREE
// distinct entitlement keys -- that is uq_cloud_permission_grant's grain
// (identity, statement, resource) carried into the canonical model.
func TestOneStatementThreeResourcesThreeKeys(t *testing.T) {
	holder := identity("arn:aws:iam::1234:role/alpha", models.CloudIdentityIAMRole, "AROAA")
	p := perm("arn:aws:iam::1234:policy/Multi#s0")

	seen := map[string]bool{}
	for _, res := range []string{
		"aws\x1farn:aws:s3:::one/*",
		"aws\x1farn:aws:s3:::two/*",
		"aws\x1farn:aws:s3:::three/*",
	} {
		seen[EntitlementKey(p, holder, res)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("want 3 distinct entitlement keys, got %d: %v", len(seen), seen)
	}
}

// A wildcard or account-wide grant keys as "*" and must not collide with a
// grant that names a resource.
func TestWildcardGrantKeysAsStar(t *testing.T) {
	holder := identity("arn:aws:iam::1234:role/alpha", models.CloudIdentityIAMRole, "AROAA")
	p := perm("arn:aws:iam::1234:policy/Wide#s0")

	star := EntitlementKey(p, holder, "")
	named := EntitlementKey(p, holder, "aws\x1farn:aws:s3:::one/*")
	if star == named {
		t.Fatal("wildcard grant collided with a named-resource grant")
	}
	if !strings.HasSuffix(star, Sep+"*") {
		t.Fatalf("wildcard grant did not key as *: %q", star)
	}
}

// §2.4 / roadmap §3.2: continuity is 'immutable' ONLY where the provider gives
// a creation-boundary id. Every other kind must say recognition_only so the
// console can state that "same name" is the strongest claim available.
func TestContinuityTable(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want string
	}{
		{models.CloudIdentityIAMRole, ContinuityImmutable},
		{models.CloudIdentityIAMUser, ContinuityImmutable},
		// Workload runtime kinds: none carries a creation boundary the
		// collector records. See Continuity's comment on EC2.
		{models.WorkloadLambdaFunction, ContinuityRecognitionOnly},
		{models.WorkloadECSTaskDefinition, ContinuityRecognitionOnly},
		{models.WorkloadEC2Instance, ContinuityRecognitionOnly},
		{models.WorkloadBedrockAgent, ContinuityRecognitionOnly},
		{"s3_bucket", ContinuityRecognitionOnly},
		{"", ContinuityRecognitionOnly},
	} {
		if got := Continuity(tc.kind); got != tc.want {
			t.Errorf("Continuity(%q) = %q, want %q", tc.kind, got, tc.want)
		}
	}
}

// Continuity and ImmutableKey must AGREE: 027's CHECK rejects a row claiming
// 'immutable' with an empty immutable_key. A silent disagreement here disables
// delete-and-recreate detection entirely, so it is asserted rather than
// assumed.
func TestContinuityAgreesWithImmutableKey(t *testing.T) {
	role := identity("arn:aws:iam::1234:role/alpha", models.CloudIdentityIAMRole, "AROA5XK7QEXAMPLE")
	if Continuity(role.Kind) != ContinuityImmutable {
		t.Fatal("iam_role must be immutable")
	}
	if ImmutableKey(role) == "" {
		t.Fatal("iam_role claims immutable but ImmutableKey is empty -- 027's CHECK would reject it")
	}

	// An identity whose attrs carry no unique id must NOT be silently treated
	// as immutable-with-empty-key; the caller has to see the empty string.
	bare := models.CloudIdentity{NativeID: "arn:aws:iam::1234:role/bare", Kind: models.CloudIdentityIAMRole}
	if ImmutableKey(bare) != "" {
		t.Fatal("want empty immutable key when the collector recorded none")
	}
}

// §4.8: a permission observation's subject key must be fully qualifying --
// holder, statement and resource -- so it survives the subject FK going NULL
// and cannot be confused between two holders of one managed policy.
func TestPermissionSubjectKeyDisambiguatesHolders(t *testing.T) {
	p := perm("arn:aws:iam::1234:policy/RefundS3Access#s0")
	a := PermissionSubjectKey(p, "arn:aws:iam::1234:role/alpha", "arn:aws:s3:::refunds/*")
	b := PermissionSubjectKey(p, "arn:aws:iam::1234:role/beta", "arn:aws:s3:::refunds/*")
	if a == b {
		t.Fatal("two holders of one managed policy produced the same evidence key")
	}
	if !Qualified(a) || !Qualified(b) {
		t.Fatal("qualified keys must carry the separator")
	}
	// A pre-qualification key has no separator and must be recognisable as
	// such, so it is never attached as supporting evidence.
	if Qualified("arn:aws:iam::1234:policy/RefundS3Access#s0") {
		t.Fatal("an unqualified legacy key must not read as qualified")
	}
}

// One statement, three resources: the evidence keys must be distinct too, or
// evidence from one grant would attach to another.
func TestPermissionSubjectKeyDistinguishesResources(t *testing.T) {
	p := perm("arn:aws:iam::1234:policy/Multi#s0")
	const holder = "arn:aws:iam::1234:role/alpha"
	seen := map[string]bool{}
	for _, r := range []string{"arn:aws:s3:::one/*", "arn:aws:s3:::two/*", ""} {
		seen[PermissionSubjectKey(p, holder, r)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("want 3 distinct evidence keys, got %d: %v", len(seen), seen)
	}
}
