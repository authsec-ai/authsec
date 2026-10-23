package igagov

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Access policies (decision, Aditya, 2026-10-13): an admin blocks or allows
// roles on an S3 bucket (optionally a key prefix) for a time window. AuthSec
// attaches one AuthSec-owned managed policy per role per version under
// /authsec/, named AuthSecAccess-<RoleId>-<policy 8hex>-v<no>; AWS enforces
// it, and its aws:CurrentTime conditions make it inert outside the window
// even if AuthSec is down. This file is the pure part: the intent, its
// validation, the S3 action table and the document.

// Access-policy names and limits.
const (
	AccessPolicyPrefix   = "AuthSecAccess-"
	AccessSidObjects     = "AuthSecAccessObjects"
	AccessSidBucket      = "AuthSecAccessBucket"
	AccessSidBucketNone  = "AuthSecAccessBucketNoPrefix"
	TagAccessPolicy      = "authsec:policy"
	TagAccessVersion     = "authsec:version"
	TagAccessDeployment  = "authsec:deployment"
	CondDateGreaterThan  = "DateGreaterThan"
	CondStringLike       = "StringLike"
	CondNull             = "Null"
	KeyS3Prefix          = "s3:prefix"
	AccessEffectBlock    = "block"
	AccessEffectAllow    = "allow"
	AccessRead           = "read"
	AccessWrite          = "write"
	AccessDelete         = "delete"
	AccessAll            = "all"
	MaxAccessRoles       = 20
	MaxAccessNameChars   = 200
	MaxAccessPrefixChars = 512
	MinAccessWindow      = 15 * time.Minute
	MaxAllowWindow       = 30 * 24 * time.Hour
	MaxAccessStartLead   = 30 * 24 * time.Hour
)

// MaxListGuardPrefix is the longest folder whose leading fragments a Block
// lists out one by one (see accessListGuard): the fragments grow with the
// square of the length and the document has 6144 characters.
const MaxListGuardPrefix = 48

// AccessNoEnd is the stored expiry of a block without an end: the deployment
// row needs a time, the document carries no DateLessThan.
var AccessNoEnd = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)

// AccessResource names the bucket by its Discovery resource id.
type AccessResource struct {
	ResourceID string `json:"resource_id"`
	Prefix     string `json:"prefix,omitempty"`
}

// AccessRole names a role by its Discovery identity id.
type AccessRole struct {
	IdentityAccountID string `json:"identity_account_id"`
}

// AccessIntent is what the admin sends (and what a version stores).
type AccessIntent struct {
	Effect   string         `json:"effect"`
	Resource AccessResource `json:"resource"`
	Roles    []AccessRole   `json:"roles"`
	Access   []string       `json:"access"`
	StartsAt *time.Time     `json:"starts_at"`
	EndsAt   *time.Time     `json:"ends_at"`
}

// AccessFieldError is one invalid field (access_policy_invalid).
type AccessFieldError struct {
	Field   string
	Message string
}

func (e *AccessFieldError) Error() string { return e.Field + ": " + e.Message }

func accessInvalid(field, format string, args ...any) error {
	return &AccessFieldError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// NormalizeAccessIntent validates in against now and returns its canonical
// form: lower-case effect and access (sorted, unique; "all" alone), roles
// unique in the given order, the prefix without a leading "/", times in UTC
// to the second.
func NormalizeAccessIntent(in AccessIntent, now time.Time) (AccessIntent, error) {
	out := AccessIntent{}
	now = now.UTC().Truncate(time.Second)
	out.Effect = strings.ToLower(strings.TrimSpace(in.Effect))
	if out.Effect != AccessEffectBlock && out.Effect != AccessEffectAllow {
		return out, accessInvalid("effect", "effect is block or allow")
	}
	out.Resource.ResourceID = strings.ToLower(strings.TrimSpace(in.Resource.ResourceID))
	if !reUUID.MatchString(out.Resource.ResourceID) {
		return out, accessInvalid("resource.resource_id", "resource_id must be a Discovery resource id")
	}
	p := strings.TrimLeft(strings.TrimSpace(in.Resource.Prefix), "/")
	if len(p) > MaxAccessPrefixChars {
		return out, accessInvalid("resource.prefix", "prefix is at most %d characters", MaxAccessPrefixChars)
	}
	if strings.ContainsAny(p, "*?") {
		return out, accessInvalid("resource.prefix", "prefix is a literal key prefix (no * or ?)")
	}
	out.Resource.Prefix = p

	if len(in.Roles) == 0 || len(in.Roles) > MaxAccessRoles {
		return out, accessInvalid("roles", "choose 1 to %d roles", MaxAccessRoles)
	}
	seen := map[string]bool{}
	for i, r := range in.Roles {
		id := strings.ToLower(strings.TrimSpace(r.IdentityAccountID))
		if !reUUID.MatchString(id) {
			return out, accessInvalid(fmt.Sprintf("roles[%d].identity_account_id", i), "must be a Discovery identity id")
		}
		if !seen[id] {
			seen[id] = true
			out.Roles = append(out.Roles, AccessRole{IdentityAccountID: id})
		}
	}

	levels := map[string]bool{}
	for _, a := range in.Access {
		a = strings.ToLower(strings.TrimSpace(a))
		switch a {
		case AccessRead, AccessWrite, AccessDelete, AccessAll:
			levels[a] = true
		default:
			return out, accessInvalid("access", "access is read, write, delete or all")
		}
	}
	switch {
	case len(levels) == 0:
		return out, accessInvalid("access", "choose at least one of read, write, delete")
	case levels[AccessAll] && out.Effect != AccessEffectBlock:
		return out, accessInvalid("access", "all is allowed for block only")
	case levels[AccessAll]:
		out.Access = []string{AccessAll}
	default:
		for a := range levels {
			out.Access = append(out.Access, a)
		}
		sort.Strings(out.Access)
	}

	if in.StartsAt != nil {
		s := in.StartsAt.UTC().Truncate(time.Second)
		if s.Before(now) || s.After(now.Add(MaxAccessStartLead)) {
			return out, accessInvalid("starts_at", "starts_at is between now and 30 days ahead")
		}
		if !s.Equal(now) {
			out.StartsAt = &s
		}
	}
	from := now
	if out.StartsAt != nil {
		from = *out.StartsAt
	}
	if in.EndsAt != nil {
		e := in.EndsAt.UTC().Truncate(time.Second)
		if e.Before(now.Add(MinAccessWindow)) {
			return out, accessInvalid("ends_at", "ends_at is at least 15 minutes from now")
		}
		if !e.After(from) {
			return out, accessInvalid("ends_at", "ends_at is after starts_at")
		}
		if out.Effect == AccessEffectAllow && e.After(from.Add(MaxAllowWindow)) {
			return out, accessInvalid("ends_at", "an allow lasts at most 30 days")
		}
		if e.Sub(from) < MinAccessWindow {
			return out, accessInvalid("ends_at", "the window is at least 15 minutes")
		}
		out.EndsAt = &e
	} else if out.Effect == AccessEffectAllow {
		return out, accessInvalid("ends_at", "an allow needs ends_at (15 minutes to 30 days)")
	}
	return out, nil
}

// AccessIntentHash is the version's intent hash.
func AccessIntentHash(in AccessIntent) (string, error) {
	return HashCanonicalTagged("authsec.igagov.access_policy.intent.v1", in)
}

// S3Target is the resolved bucket and optional prefix.
type S3Target struct {
	Partition string
	Bucket    string
	Prefix    string
}

var reS3ARN = regexp.MustCompile(`^arn:(aws[a-z-]*):s3:::([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(/.*)?$`)

// ParseS3BucketARN reads arn:<partition>:s3:::<bucket>[/...] (an object or
// selector ARN names its bucket). ok=false for anything else.
func ParseS3BucketARN(arn string) (S3Target, bool) {
	m := reS3ARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return S3Target{}, false
	}
	return S3Target{Partition: m[1], Bucket: m[2]}, true
}

// BucketARN is arn:<partition>:s3:::<bucket>.
func (t S3Target) BucketARN() string { return "arn:" + t.partition() + ":s3:::" + t.Bucket }

// ObjectARN is the bucket's objects under the prefix (all objects without one).
func (t S3Target) ObjectARN() string { return t.BucketARN() + "/" + IAMLiteral(t.Prefix) + "*" }

// IAMLiteral writes s so a policy document reads it literally: "${" starts a
// policy variable in the 2012-10-17 language, so every "$" is written "${$}".
// A key prefix may contain "$"; nothing else AuthSec writes does.
func IAMLiteral(s string) string { return strings.ReplaceAll(s, "$", "${$}") }

func (t S3Target) partition() string {
	if t.Partition == "" {
		return "aws"
	}
	return t.Partition
}

// AccessActions is the S3 action table: object actions on ObjectARN, bucket
// actions on BucketARN (s3:ListBucket is limited to the prefix by s3:prefix
// when a prefix is set).
func AccessActions(access []string, prefix string) (object, bucket []string) {
	add := func(dst *[]string, a ...string) { *dst = append(*dst, a...) }
	for _, a := range access {
		switch a {
		case AccessRead:
			add(&object, "s3:GetObject", "s3:GetObjectVersion")
			add(&bucket, "s3:ListBucket")
		case AccessWrite:
			add(&object, "s3:PutObject", "s3:AbortMultipartUpload")
		case AccessDelete:
			add(&object, "s3:DeleteObject", "s3:DeleteObjectVersion")
		case AccessAll:
			add(&object, "s3:*")
			if prefix == "" {
				add(&bucket, "s3:*")
			} else {
				add(&bucket, "s3:ListBucket")
			}
		}
	}
	return sortedUnique(object), sortedUnique(bucket)
}

// accessActionsFor is AccessActions plus, for a Block, the read-side actions
// that expose the same keys or their metadata: listing versions and in-flight
// multipart uploads (both honour s3:prefix) and the attribute reads. An Allow
// never gains them: it must not widen beyond what the person chose.
func accessActionsFor(effect string, access []string, prefix string) (object, bucket []string) {
	object, bucket = AccessActions(access, prefix)
	if effect != AccessEffectBlock {
		return object, bucket
	}
	for _, a := range access {
		switch a {
		case AccessRead:
			object = append(object, "s3:GetObjectAttributes", "s3:GetObjectVersionAttributes")
			bucket = append(bucket, "s3:ListBucketVersions", "s3:ListBucketMultipartUploads")
		case AccessAll:
			if prefix != "" {
				bucket = append(bucket, "s3:ListBucketVersions", "s3:ListBucketMultipartUploads")
			}
		}
	}
	return sortedUnique(object), sortedUnique(bucket)
}

// AccessListGuardPartial reports that a Block of this folder cannot list out
// every leading fragment of it, so a list request for a fragment such as
// "sand" (for folder "sandbox/") is not denied.
func AccessListGuardPartial(effect, prefix string) bool {
	return effect == AccessEffectBlock && len([]rune(prefix)) > MaxListGuardPrefix
}

// accessListGuard is the s3:prefix values a Block's listing Deny matches for a
// folder. A Deny with only "<folder>*" is skipped by a list request that names
// no prefix, the empty prefix, or a fragment of the folder ("sand"), and any of
// those returns the folder's keys. So it also matches "" and, up to
// MaxListGuardPrefix characters, every proper leading fragment. A request that
// names no prefix at all carries no s3:prefix key: accessNoPrefixStatement.
func accessListGuard(prefix string) []string {
	vals := []string{prefix + "*", ""}
	if len([]rune(prefix)) <= MaxListGuardPrefix {
		r := []rune(prefix)
		for i := 1; i < len(r); i++ {
			vals = append(vals, string(r[:i]))
		}
	}
	return sortedUnique(vals)
}

// S3Target is an AWSAccessTarget.
func (t S3Target) Type() string         { return AccessTypeS3Bucket }
func (t S3Target) Service() string      { return "s3" }
func (t S3Target) Noun() string         { return "bucket" }
func (t S3Target) ARN() string          { return t.BucketARN() }
func (t S3Target) Name() string         { return t.Bucket }
func (t S3Target) ARNAccount() string   { return "" }
func (t S3Target) ARNRegion() string    { return "" }
func (t S3Target) ARNPartition() string { return t.partition() }
func (t S3Target) Where() string        { return "s3://" + t.Bucket + "/" + t.Prefix + "*" }

// Statements is the S3 document: the object actions on ObjectARN, the bucket
// actions on BucketARN (limited by s3:prefix under a prefix: the folder for
// an Allow, the list guard for a Block), and for a Block under a prefix a
// second listing Deny for a request that names no prefix.
func (t S3Target) Statements(effect string, access []string) ([]AccessStatement, error) {
	object, bucket := accessActionsFor(effect, access, t.Prefix)
	if len(object) == 0 {
		return nil, nil
	}
	stmts := []AccessStatement{{Sid: AccessSidObjects, Actions: object, Resources: []string{t.ObjectARN()}}}
	if len(bucket) > 0 {
		var cond map[string]any
		if t.Prefix != "" {
			var like any = IAMLiteral(t.Prefix) + "*"
			if effect == AccessEffectBlock {
				guard := accessListGuard(t.Prefix)
				for i := range guard {
					guard[i] = IAMLiteral(guard[i])
				}
				like = guard
			}
			cond = map[string]any{CondStringLike: map[string]any{KeyS3Prefix: like}}
		}
		stmts = append(stmts, AccessStatement{Sid: AccessSidBucket, Actions: bucket, Resources: []string{t.BucketARN()}, Cond: cond})
		if t.Prefix != "" && effect == AccessEffectBlock {
			// A list request without a prefix has no s3:prefix key, so
			// StringLike cannot match it: a second Deny catches it.
			stmts = append(stmts, AccessStatement{Sid: AccessSidBucketNone, Actions: bucket, Resources: []string{t.BucketARN()},
				Cond: map[string]any{CondNull: map[string]any{KeyS3Prefix: "true"}}})
		}
	}
	return stmts, nil
}

// Notes: an Allow may also need the bucket policy; a Block of reads under a
// prefix also blocks listing the root and the folder's leading fragments
// (only some of them for a long folder).
func (t S3Target) Notes(effect string, access []string) []AccessNote {
	var out []AccessNote
	if effect == AccessEffectAllow {
		out = append(out, AccessNote{Code: "allow_needs_bucket_policy",
			Message: "If the bucket is in another AWS account, its bucket policy must allow the role as well."})
	}
	if effect == AccessEffectBlock && t.Prefix != "" && accessHas(access, AccessRead, AccessAll) {
		out = append(out, AccessNote{Code: "list_root_blocked",
			Message: "To keep the folder's keys from being listed, these roles also cannot list the bucket root or a prefix that starts like the folder."})
		if AccessListGuardPartial(effect, t.Prefix) {
			out = append(out, AccessNote{Code: "list_partial_prefix",
				Message: "The folder name is too long to block listing of every leading fragment of it; a list request for a short fragment of the name is not blocked."})
		}
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t S3Target) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and bucket policies are unchanged."
}

// AccessDocument is the policy of one role: Deny (block) or Allow (allow) of
// the access levels' actions on t, inside the window. It returns the
// canonical document, its hash, and every action and resource it names.
func AccessDocument(effect string, access []string, t AWSAccessTarget, startsAt, endsAt *time.Time) ([]byte, string, []string, []string, error) {
	stmts, err := t.Statements(effect, access)
	if err != nil {
		return nil, "", nil, nil, err
	}
	return BuildAccessDocument(effect, stmts, startsAt, endsAt)
}

// AccessPolicyName is AuthSecAccess-<RoleId>-<policy 8hex>-v<no>.
func AccessPolicyName(roleID, policyID string, versionNo int) string {
	return fmt.Sprintf("%s%s-%s-v%d", AccessPolicyPrefix, roleID, strings.ReplaceAll(policyID, "-", "")[:8], versionNo)
}

// AccessDeploymentHash is what a deployment row binds (its request_hash).
func AccessDeploymentHash(roleID, accountID, versionID, documentHash string) (string, error) {
	return HashCanonicalTagged("authsec.igagov.access_policy.deployment.v1", struct {
		RoleID    string `json:"role_id"`
		AccountID string `json:"account_id"`
		VersionID string `json:"version_id"`
		Document  string `json:"document_hash"`
	}{roleID, accountID, versionID, documentHash})
}

// AccessSentence is the preview's one plain sentence.
func AccessSentence(in AccessIntent, t AWSAccessTarget, roleNames []string) string {
	verb := "Block"
	if in.Effect == AccessEffectAllow {
		verb = "Allow"
	}
	what := strings.Join(in.Access, ", ")
	if len(in.Access) == 1 && in.Access[0] == AccessAll {
		what = "all access"
	}
	who := strings.Join(roleNames, ", ")
	s := fmt.Sprintf("%s %s on %s for %s", verb, what, t.Where(), who)
	if in.StartsAt != nil {
		s += " from " + in.StartsAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	if in.EndsAt != nil {
		s += " until " + in.EndsAt.UTC().Format("2006-01-02 15:04 UTC")
	} else {
		s += ", with no end date"
	}
	return s + "."
}
