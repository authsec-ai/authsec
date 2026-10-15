package igagov

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Access policies (decision, Aditya, 2026-10-13): an admin blocks or allows
// roles on an S3 bucket (optionally a key prefix), a DynamoDB table or SSM
// parameters for a time window. AuthSec
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
	TagAccessPolicy      = "authsec:policy"
	TagAccessVersion     = "authsec:version"
	TagAccessDeployment  = "authsec:deployment"
	CondDateGreaterThan  = "DateGreaterThan"
	CondStringLike       = "StringLike"
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

// Access-policy services (S3 since v1; DynamoDB and SSM Parameter Store
// added 2026-10-15).
const (
	AccessServiceS3       = "s3"
	AccessServiceDynamoDB = "dynamodb"
	AccessServiceSSM      = "ssm"
	AccessSidTable        = "AuthSecAccessTable"
	AccessSidParameters   = "AuthSecAccessParameters"
)

// AccessTarget is the resolved resource of an access policy: an S3 bucket
// (with an optional key prefix), a DynamoDB table, or SSM parameters (one
// parameter, or a path ending in "*").
type AccessTarget struct {
	Service   string
	Partition string
	Region    string // DynamoDB, SSM
	Account   string // DynamoDB, SSM (an S3 ARN names none)
	// Name: the bucket; the table; the parameter name as the ARN writes it
	// after "parameter/" (e.g. "prod/db/password", or "prod/db/*" for a path).
	Name   string
	Prefix string // S3 only: a key prefix
}

var (
	reS3ARN       = regexp.MustCompile(`^arn:(aws[a-z-]*):s3:::([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(/.*)?$`)
	reDynamoDBARN = regexp.MustCompile(`^arn:(aws[a-z-]*):dynamodb:([a-z0-9-]+):([0-9]{12}):table/([A-Za-z0-9_.\-]{3,255})(/.*)?$`)
	reSSMARN      = regexp.MustCompile(`^arn:(aws[a-z-]*):ssm:([a-z0-9-]+):([0-9]{12}):parameter/([A-Za-z0-9_.\-/]+\*?)$`)
)

// ParseAccessResourceARN reads the ARN of a Discovery resource into the
// target an access policy can name: an S3 bucket (an object or selector ARN
// names its bucket), a DynamoDB table (an index or stream ARN names its
// table), or SSM parameters (one parameter, or a path ending in "*"; a "*"
// anywhere else, or a wildcard region or account, is refused). ok=false for
// anything else.
func ParseAccessResourceARN(arn string) (AccessTarget, bool) {
	arn = strings.TrimSpace(arn)
	if m := reS3ARN.FindStringSubmatch(arn); m != nil {
		return AccessTarget{Service: AccessServiceS3, Partition: m[1], Name: m[2]}, true
	}
	if m := reDynamoDBARN.FindStringSubmatch(arn); m != nil {
		return AccessTarget{Service: AccessServiceDynamoDB, Partition: m[1], Region: m[2], Account: m[3], Name: m[4]}, true
	}
	if m := reSSMARN.FindStringSubmatch(arn); m != nil {
		return AccessTarget{Service: AccessServiceSSM, Partition: m[1], Region: m[2], Account: m[3], Name: m[4]}, true
	}
	return AccessTarget{}, false
}

func (t AccessTarget) partition() string {
	if t.Partition == "" {
		return "aws"
	}
	return t.Partition
}

// ResourceARN is the bucket, table or parameter ARN.
func (t AccessTarget) ResourceARN() string {
	switch t.Service {
	case AccessServiceDynamoDB:
		return "arn:" + t.partition() + ":dynamodb:" + t.Region + ":" + t.Account + ":table/" + t.Name
	case AccessServiceSSM:
		return "arn:" + t.partition() + ":ssm:" + t.Region + ":" + t.Account + ":parameter/" + t.Name
	}
	return "arn:" + t.partition() + ":s3:::" + t.Name
}

// ObjectARN is an S3 bucket's objects under the prefix (all without one).
func (t AccessTarget) ObjectARN() string { return t.ResourceARN() + "/" + t.Prefix + "*" }

// IsPath reports SSM parameters named by a path ("prod/db/*").
func (t AccessTarget) IsPath() bool { return t.Service == AccessServiceSSM && strings.HasSuffix(t.Name, "*") }

// Display is how the preview names the target.
func (t AccessTarget) Display() string {
	switch t.Service {
	case AccessServiceDynamoDB:
		return "DynamoDB table " + t.Name + " (" + t.Region + ")"
	case AccessServiceSSM:
		name := t.Name
		if strings.Contains(name, "/") {
			name = "/" + name
		}
		if t.IsPath() {
			return "SSM parameters " + name + " (" + t.Region + ")"
		}
		return "SSM parameter " + name + " (" + t.Region + ")"
	}
	return "s3://" + t.Name + "/" + t.Prefix + "*"
}

// ValidateAccessTarget checks the rule against its target's service: a
// prefix is an S3 key prefix only; SSM is block-only for now (an allow of a
// SecureString would also need kms:Decrypt on its key, which the policy
// does not grant).
func ValidateAccessTarget(in AccessIntent, t AccessTarget) error {
	if t.Service != AccessServiceS3 && in.Resource.Prefix != "" {
		return accessInvalid("resource.prefix", "a prefix applies to S3 buckets only")
	}
	if t.Service == AccessServiceSSM && in.Effect == AccessEffectAllow {
		return accessInvalid("effect", "Allow is not available for SSM parameters yet: a SecureString value would also need kms:Decrypt on its key")
	}
	return nil
}

// accessStatement is one statement of an access policy.
type accessStatement struct {
	Sid       string
	Actions   []string
	Resources []string
	Extra     map[string]any
}

// AccessStatements is the action table of each service.
//
//	S3        read   s3:GetObject, s3:GetObjectVersion on bucket/prefix*; s3:ListBucket on the bucket (s3:prefix-limited)
//	          write  s3:PutObject, s3:AbortMultipartUpload
//	          delete s3:DeleteObject, s3:DeleteObjectVersion
//	          all    s3:* (block only; with a prefix only ListBucket on the bucket)
//	DynamoDB  read   GetItem, BatchGetItem, Query, Scan, ConditionCheckItem on the table and its indexes
//	          write  PutItem, UpdateItem, BatchWriteItem
//	          delete DeleteItem, BatchWriteItem (a batch write can delete, so it is in both)
//	          all    dynamodb:* on the table and everything under it (block only)
//	SSM       read   GetParameter, GetParameters, GetParameterHistory, GetParametersByPath
//	          write  PutParameter, LabelParameterVersion
//	          delete DeleteParameter, DeleteParameters
//	          all    ssm:* (block only); a path also covers reading the path itself
func AccessStatements(access []string, t AccessTarget) []accessStatement {
	add := func(dst *[]string, a ...string) { *dst = append(*dst, a...) }
	switch t.Service {
	case AccessServiceDynamoDB:
		var acts []string
		res := []string{t.ResourceARN(), t.ResourceARN() + "/index/*"}
		for _, a := range access {
			switch a {
			case AccessRead:
				add(&acts, "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:ConditionCheckItem")
			case AccessWrite:
				add(&acts, "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:BatchWriteItem")
			case AccessDelete:
				add(&acts, "dynamodb:DeleteItem", "dynamodb:BatchWriteItem")
			case AccessAll:
				add(&acts, "dynamodb:*")
				res = []string{t.ResourceARN(), t.ResourceARN() + "/*"}
			}
		}
		return []accessStatement{{Sid: AccessSidTable, Actions: sortedUnique(acts), Resources: res}}
	case AccessServiceSSM:
		var acts []string
		res := []string{t.ResourceARN()}
		if t.IsPath() {
			// GetParametersByPath is authorised on the path itself.
			path := strings.TrimSuffix(strings.TrimSuffix(t.ResourceARN(), "*"), "/")
			res = append(res, path)
		}
		for _, a := range access {
			switch a {
			case AccessRead:
				add(&acts, "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:GetParametersByPath")
			case AccessWrite:
				add(&acts, "ssm:PutParameter", "ssm:LabelParameterVersion")
			case AccessDelete:
				add(&acts, "ssm:DeleteParameter", "ssm:DeleteParameters")
			case AccessAll:
				add(&acts, "ssm:*")
			}
		}
		return []accessStatement{{Sid: AccessSidParameters, Actions: sortedUnique(acts), Resources: sortedUnique(res)}}
	}
	var object, bucket []string
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
			if t.Prefix == "" {
				add(&bucket, "s3:*")
			} else {
				add(&bucket, "s3:ListBucket")
			}
		}
	}
	out := []accessStatement{{Sid: AccessSidObjects, Actions: sortedUnique(object), Resources: []string{t.ObjectARN()}}}
	if len(bucket) > 0 {
		var extra map[string]any
		if t.Prefix != "" {
			extra = map[string]any{CondStringLike: map[string]any{KeyS3Prefix: t.Prefix + "*"}}
		}
		out = append(out, accessStatement{Sid: AccessSidBucket, Actions: sortedUnique(bucket), Resources: []string{t.ResourceARN()}, Extra: extra})
	}
	return out
}

// AccessDocument is the policy of one role: Deny (block) or Allow (allow) of
// the access levels' actions, inside the window. It returns the canonical
// document, its hash, and every action and resource it names.
func AccessDocument(effect string, access []string, t AccessTarget, startsAt, endsAt *time.Time) ([]byte, string, []string, []string, error) {
	eff := EffectAllow
	if effect == AccessEffectBlock {
		eff = EffectDeny
	}
	stmts := AccessStatements(access, t)
	if len(stmts) == 0 || len(stmts[0].Actions) == 0 {
		return nil, "", nil, nil, errors.New("no action for the access levels")
	}
	window := map[string]any{}
	if startsAt != nil {
		window[CondDateGreaterThan] = map[string]any{KeyCurrentTime: AWSTime(*startsAt)}
	}
	if endsAt != nil && !endsAt.Equal(AccessNoEnd) {
		window[CondDateLessThan] = map[string]any{KeyCurrentTime: AWSTime(*endsAt)}
	}
	var docStmts []any
	var actions, resources []string
	for _, st := range stmts {
		var action any = st.Actions
		if len(st.Actions) == 1 {
			action = st.Actions[0]
		}
		var resource any = st.Resources
		if len(st.Resources) == 1 {
			resource = st.Resources[0]
		}
		s := map[string]any{"Sid": st.Sid, "Effect": eff, "Action": action, "Resource": resource}
		cond := map[string]any{}
		for k, v := range window {
			cond[k] = v
		}
		for k, v := range st.Extra {
			cond[k] = v
		}
		if len(cond) > 0 {
			s["Condition"] = cond
		}
		docStmts = append(docStmts, s)
		actions = append(actions, st.Actions...)
		resources = append(resources, st.Resources...)
	}
	doc := map[string]any{"Version": PolicyVersion20121017, "Statement": docStmts}
	c, err := CanonicalizeValue(doc)
	if err != nil {
		return nil, "", nil, nil, err
	}
	if PolicyChars(c) > MaxPolicyChars {
		return nil, "", nil, nil, fmt.Errorf("the policy document is larger than %d characters", MaxPolicyChars)
	}
	return c, ContentHash(c), sortedUnique(actions), sortedUnique(resources), nil
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
func AccessSentence(in AccessIntent, t AccessTarget, roleNames []string) string {
	verb := "Block"
	if in.Effect == AccessEffectAllow {
		verb = "Allow"
	}
	what := strings.Join(in.Access, ", ")
	if len(in.Access) == 1 && in.Access[0] == AccessAll {
		what = "all access"
	}
	where := t.Display()
	who := strings.Join(roleNames, ", ")
	s := fmt.Sprintf("%s %s on %s for %s", verb, what, where, who)
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
