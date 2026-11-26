package igagov

import (
	"errors"
	"regexp"
	"strings"
)

// Secrets Manager secrets in access policies (step 3, block only). A block is
// a Deny on every secret named N in the account, in every region: the
// secret's own ARN ends in a random 6-character suffix, and a Deny on
// "<N>-??????" covers its replicas (same suffix, other regions), a secret
// re-created under the name, and a pick through a "<N>-??????" selector row
// alike. The action table was checked against the AWS Service Authorization
// Reference for Secrets Manager (2026-10-24).
//
// Unverified against a live account, so chosen to fail safe:
//   - which ARN CreateSecret is checked on when it overwrites a replica: the
//     overwrite statement names "*" and conditions on the secret's name;
//   - an allow (refused in this release: it needs the exact suffix and
//     conditions not yet confirmed).

// Secrets Manager access-policy names.
const (
	AccessTypeSecretsManagerSecret = "secretsmanager_secret"
	AccessSidSecret                = "AuthSecAccessSecret"
	AccessSidOverwrite             = "AuthSecAccessOverwrite"
	CondBool                       = "Bool"
	KeySMName                      = "secretsmanager:Name"
	KeySMForceOverwrite            = "secretsmanager:ForceOverwriteReplicaSecret"
	smAll                          = "secretsmanager:*"
)

// ErrAccessBlockOnly: the type takes blocks only in this release.
var ErrAccessBlockOnly = errors.New("this resource type can be blocked only")

// The actions per level a block denies on the secret.
var (
	// read: the value, and every path that hands it to another principal or
	// region (replicate, rotate with a function the caller picks, resource
	// policy, tags satisfying another principal's tag-based Allow).
	smRead = []string{"secretsmanager:GetSecretValue", "secretsmanager:ReplicateSecretToRegions", "secretsmanager:RotateSecret",
		"secretsmanager:PutResourcePolicy", "secretsmanager:DeleteResourcePolicy", "secretsmanager:TagResource", "secretsmanager:UntagResource"}
	smWrite = []string{"secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:UpdateSecretVersionStage",
		"secretsmanager:RotateSecret", "secretsmanager:CancelRotateSecret", "secretsmanager:RestoreSecret",
		"secretsmanager:ReplicateSecretToRegions", "secretsmanager:StopReplicationToReplica", "secretsmanager:TagResource", "secretsmanager:UntagResource"}
	// delete: the secret, its replicas, and moving version labels (a version
	// left without labels is deleted once the secret has more than 100).
	smDelete = []string{"secretsmanager:DeleteSecret", "secretsmanager:RemoveRegionsFromReplication",
		"secretsmanager:ReplicateSecretToRegions", "secretsmanager:UpdateSecretVersionStage"}
)

// SecretTarget is one secret: Suffix is "" when it was picked through a
// "<name>-??????" row.
type SecretTarget struct {
	Partition, Region, Account, Secret, Suffix string
}

// A secret ARN, or a selector naming exactly one secret name: the name is
// literal (names use A-Za-z0-9/_+=.@- only, so "?" cannot be part of one) and
// the suffix is the random six characters or exactly six "?".
var reSecretARN = regexp.MustCompile(`^arn:(aws[a-z-]*):secretsmanager:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):secret:([A-Za-z0-9/_+=.@-]{1,512})-([A-Za-z0-9]{6}|\?{6})$`)

// ParseSecretsManagerSecretARN reads the secret an ARN or selector names.
func ParseSecretsManagerSecretARN(arn string) (SecretTarget, bool) {
	m := reSecretARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return SecretTarget{}, false
	}
	t := SecretTarget{Partition: m[1], Region: m[2], Account: m[3], Secret: m[4], Suffix: m[5]}
	if t.Suffix == "??????" {
		t.Suffix = ""
	}
	return t, true
}

func (t SecretTarget) arnIn(region, suffix string) string {
	return "arn:" + t.Partition + ":secretsmanager:" + region + ":" + t.Account + ":secret:" + t.Secret + "-" + suffix
}

// NameARN is every secret named N in the account, in any region.
func (t SecretTarget) NameARN() string { return t.arnIn("*", "??????") }

// SecretTarget is an AWSAccessTarget.
func (t SecretTarget) Type() string    { return AccessTypeSecretsManagerSecret }
func (t SecretTarget) Service() string { return "secretsmanager" }
func (t SecretTarget) Noun() string    { return "secret" }
func (t SecretTarget) ARN() string {
	if t.Suffix != "" {
		return t.arnIn(t.Region, t.Suffix)
	}
	return t.arnIn(t.Region, "??????")
}
func (t SecretTarget) Name() string         { return t.Secret }
func (t SecretTarget) ARNAccount() string   { return t.Account }
func (t SecretTarget) ARNRegion() string    { return t.Region }
func (t SecretTarget) ARNPartition() string { return t.Partition }
func (t SecretTarget) Where() string {
	return "Secrets Manager secret " + t.Secret + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the secret's block document; an allow is refused.
func (t SecretTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	all := accessHas(access, AccessAll)
	read, write, del := accessHas(access, AccessRead), accessHas(access, AccessWrite), accessHas(access, AccessDelete)
	var acts []string
	switch {
	case all:
		acts = []string{smAll}
	default:
		if read {
			acts = append(acts, smRead...)
		}
		if write {
			acts = append(acts, smWrite...)
		}
		if del {
			acts = append(acts, smDelete...)
		}
	}
	if len(acts) == 0 {
		return nil, nil
	}
	stmts := []AccessStatement{{Sid: AccessSidSecret, Actions: sortedUnique(acts), Resources: []string{t.NameARN()}}}
	if write || del || all {
		// Creating a secret that overwrites one named N (a replica) is
		// checked on CreateSecret: its own ARN is not confirmed, so it names
		// "*" and the condition holds it to the name.
		stmts = append(stmts, AccessStatement{Sid: AccessSidOverwrite, Actions: []string{"secretsmanager:CreateSecret"}, Resources: []string{"*"},
			Cond: map[string]any{CondBool: map[string]any{KeySMForceOverwrite: "true"}, CondStringEquals: map[string]any{KeySMName: t.Secret}}})
	}
	return stmts, nil
}

// Notes is the preview's warnings for a secret, in a fixed order.
func (t SecretTarget) Notes(effect string, access []string) []AccessNote {
	all := accessHas(access, AccessAll)
	read, write, del := accessHas(access, AccessRead), accessHas(access, AccessWrite), accessHas(access, AccessDelete)
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if read && !all {
		add("read_copies_blocked", "Replicating, rotating, tagging and changing the resource policy of this secret are refused too: each can hand its value to another principal or region.")
	}
	if read && !write && !all {
		add("value_check_not_covered", "A role that can still write can confirm a guessed value: putting a value under an existing version's token succeeds only when it matches. AWS has no permission or condition that stops this.")
	}
	if (write || del) && !all {
		add("overwrite_by_name_blocked", "Creating or replicating a secret that overwrites one named "+t.Secret+" is refused too.")
	}
	if del && !all {
		add("version_stage_blocked", "Moving version labels is refused too: a version left without labels is deleted once the secret has more than 100.")
	}
	if del && !write && !all {
		add("overwrite_not_covered", "Putting a new value or updating the secret can still replace its value.")
	}
	if read || all {
		add("copies_not_covered", "Copies outside Secrets Manager are not covered: values already read by services that use their own role (Lambda, ECS, CodeBuild, a rotation function), CloudFormation stacks run with a service role, caches and other systems.")
	}
	add("same_name_covered", "The block covers every secret named "+t.Secret+" in account "+t.Account+" in every region: its replicas, a secret re-created under this name, and any other secret with this name.")
	return out
}

// OtherPaths is the other_paths warning.
func (t SecretTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and the secret's resource policy are unchanged."
}
