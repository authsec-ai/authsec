package igagov

import (
	"regexp"
	"strings"
)

// KMS keys in access policies (step 8, block only). Read is getting data out
// (decrypt, and grants that hand decrypting to others); write is using the
// key to produce (encrypt, data keys, sign, MAC) and administering it; delete
// is anything that makes its data unrecoverable (deletion, disabling, deleting
// imported material). A multi-region key ("mrk-") is denied in every region:
// its replicas share the key ID. The action table was checked against the AWS
// service reference for kms (servicereference.us-east-1.amazonaws.com,
// 2026-10-24).

// KMS access-policy names.
const (
	AccessTypeKMSKey = "kms_key"
	AccessSidKey     = "AuthSecAccessKey"
)

var (
	kmsRead  = []string{"kms:Decrypt", "kms:ReEncryptFrom", "kms:Decapsulate", "kms:CreateGrant", "kms:TagResource", "kms:UntagResource"}
	kmsWrite = []string{"kms:Encrypt", "kms:ReEncryptTo", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair",
		"kms:GenerateDataKeyPairWithoutPlaintext", "kms:GenerateMac", "kms:Sign", "kms:Encapsulate", "kms:DeriveSharedSecret",
		"kms:PutKeyPolicy", "kms:UpdateKeyDescription", "kms:EnableKey", "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:RotateKeyOnDemand",
		"kms:ImportKeyMaterial", "kms:ReplicateKey", "kms:UpdatePrimaryRegion", "kms:CreateGrant", "kms:RetireGrant", "kms:RevokeGrant",
		"kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"}
	kmsDelete = []string{"kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:DeleteImportedKeyMaterial"}
)

var reKMSKeyARN = regexp.MustCompile(`^arn:(aws[a-z-]*):kms:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):key/(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// KMSKeyTarget is one key.
type KMSKeyTarget struct {
	Partition, Region, Account, Key string
}

// ParseKMSKeyARN reads a key ARN (an alias names no key IAM checks).
func ParseKMSKeyARN(arn string) (KMSKeyTarget, bool) {
	m := reKMSKeyARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return KMSKeyTarget{}, false
	}
	return KMSKeyTarget{Partition: m[1], Region: m[2], Account: m[3], Key: m[4]}, true
}

// MultiRegion: the key's replicas share its ID.
func (t KMSKeyTarget) MultiRegion() bool { return strings.HasPrefix(t.Key, "mrk-") }

func (t KMSKeyTarget) arnIn(region string) string {
	return "arn:" + t.Partition + ":kms:" + region + ":" + t.Account + ":key/" + t.Key
}

// KMSKeyTarget is an AWSAccessTarget.
func (t KMSKeyTarget) Type() string         { return AccessTypeKMSKey }
func (t KMSKeyTarget) Service() string      { return "kms" }
func (t KMSKeyTarget) Noun() string         { return "key" }
func (t KMSKeyTarget) ARN() string          { return t.arnIn(t.Region) }
func (t KMSKeyTarget) Name() string         { return t.Key }
func (t KMSKeyTarget) ARNAccount() string   { return t.Account }
func (t KMSKeyTarget) ARNRegion() string    { return t.Region }
func (t KMSKeyTarget) ARNPartition() string { return t.Partition }
func (t KMSKeyTarget) Where() string {
	return "KMS key " + t.Key + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the key's block document; an allow is refused.
func (t KMSKeyTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	acts := levelActions(access, "kms:*", kmsRead, kmsWrite, kmsDelete)
	if len(acts) == 0 {
		return nil, nil
	}
	res := t.ARN()
	if t.MultiRegion() {
		res = t.arnIn("*")
	}
	return []AccessStatement{{Sid: AccessSidKey, Actions: acts, Resources: []string{res}}}, nil
}

// Notes is the preview's warnings for a key.
func (t KMSKeyTarget) Notes(effect string, access []string) []AccessNote {
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if accessHas(access, AccessRead, AccessAll) {
		add("services_covered", "Services that use the key for these roles (S3, EBS, DynamoDB, Secrets Manager...) are refused too: they call KMS as the role.")
		add("data_keys_not_covered", "Data keys the roles already decrypted, and data already decrypted, are not covered.")
	}
	if accessHas(access, AccessDelete) && !accessHas(access, AccessAll) {
		add("delete_is_destroy", "Delete covers scheduling the key's deletion, disabling it and deleting its imported material: each makes its data unreadable.")
	}
	if t.MultiRegion() {
		add("replicas_covered", "This is a multi-Region key: the block covers its replicas in every Region.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t KMSKeyTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups, the key policy and grants made to others are unchanged."
}
