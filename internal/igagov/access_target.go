package igagov

import (
	"errors"
	"fmt"
	"time"
)

// Access-policy resource types. A type is one AWS resource kind an access
// policy can name; each has a target (the parsed ARN) that writes its own
// statements, preview notes and sentence, and BuildAccessDocument turns the
// statements into the one document every type shares (effect, window,
// canonical form, size limit, hash). A later service plugs in with one
// target and one AccessKinds entry.
const AccessTypeS3Bucket = "s3_bucket"

// AccessStatement is one statement of an access document before the effect
// and the window are added. Cond holds the statement's own conditions; the
// window's are merged into it.
type AccessStatement struct {
	Sid       string
	Actions   []string
	Resources []string
	Cond      map[string]any
}

// AccessNote is one preview warning a target adds about what its document
// does or cannot do.
type AccessNote struct {
	Code    string
	Message string
}

// AWSAccessTarget is the resolved resource of an AWS access policy.
type AWSAccessTarget interface {
	// Type is the AccessKinds type ("s3_bucket"); Service the IAM service
	// prefix ("s3"); Noun the resource in plain words ("bucket").
	Type() string
	Service() string
	Noun() string
	// ARN is the resource's own ARN (the bucket, not its objects); Name its
	// name.
	ARN() string
	Name() string
	// ARNAccount and ARNRegion are what the ARN names: "" when it names none
	// (S3). ARNPartition is the ARN's partition ("aws" when unset).
	ARNAccount() string
	ARNRegion() string
	ARNPartition() string
	// Where is the resource as the preview's sentence names it.
	Where() string
	// Statements is the document's statements for a normalized effect and
	// access, the first one the main statement.
	Statements(effect string, access []string) ([]AccessStatement, error)
	// Notes is the preview's warnings for the effect and access, in order;
	// never other_paths (the caller adds it last with OtherPaths).
	Notes(effect string, access []string) []AccessNote
	OtherPaths() string
}

// AccessKind is one resource type: Parse reads an ARN of that type (any
// Discovery row that points at one resource of it), Prefix says whether a
// key prefix applies.
type AccessKind struct {
	Type    string
	Service string
	Noun    string
	Prefix  bool
	// BlockOnly: the type takes no allow in this release.
	BlockOnly bool
	Parse     func(arn string) (AWSAccessTarget, bool)
}

// ErrAccessNotSupported is an ARN no access kind reads.
var ErrAccessNotSupported = errors.New("resource type not supported")

// AccessKinds is every resource type an AWS access policy can name, in the
// order ParseAWSAccessTarget tries them.
func AccessKinds() []AccessKind {
	return []AccessKind{
		{Type: AccessTypeS3Bucket, Service: "s3", Noun: "bucket", Prefix: true, Parse: func(arn string) (AWSAccessTarget, bool) {
			t, ok := ParseS3BucketARN(arn)
			return t, ok
		}},
		{Type: AccessTypeDynamoDBTable, Service: "dynamodb", Noun: "table", Parse: func(arn string) (AWSAccessTarget, bool) {
			t, ok := ParseDynamoDBTableARN(arn)
			return t, ok
		}},
		{Type: AccessTypeSecretsManagerSecret, Service: "secretsmanager", Noun: "secret", BlockOnly: true, Parse: func(arn string) (AWSAccessTarget, bool) {
			t, ok := ParseSecretsManagerSecretARN(arn)
			return t, ok
		}},
	}
}

// AccessTypes is the types of AccessKinds.
func AccessTypes() []string {
	kinds := AccessKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k.Type)
	}
	return out
}

// AccessKindOf is the kind of a type.
func AccessKindOf(typ string) (AccessKind, bool) {
	for _, k := range AccessKinds() {
		if k.Type == typ {
			return k, true
		}
	}
	return AccessKind{}, false
}

// AccessBlockOnlyTypes is the types that take blocks only.
func AccessBlockOnlyTypes() []string {
	out := []string{}
	for _, k := range AccessKinds() {
		if k.BlockOnly {
			out = append(out, k.Type)
		}
	}
	return out
}

// ParseAWSAccessTarget reads arn with the first kind that accepts it and
// applies prefix (an S3 key prefix). A prefix on a kind without one is an
// AccessFieldError on resource.prefix; an ARN no kind reads is
// ErrAccessNotSupported.
func ParseAWSAccessTarget(arn, prefix string) (AWSAccessTarget, error) {
	for _, k := range AccessKinds() {
		t, ok := k.Parse(arn)
		if !ok {
			continue
		}
		if prefix != "" && !k.Prefix {
			return nil, &AccessFieldError{Field: "resource.prefix", Message: "A prefix applies to S3 buckets only."}
		}
		if s, ok := t.(S3Target); ok {
			s.Prefix = prefix
			t = s
		}
		return t, nil
	}
	return nil, ErrAccessNotSupported
}

// BuildAccessDocument is the policy of one role: the statements as Deny
// (block) or Allow (allow), each inside the window (no DateLessThan for
// AccessNoEnd). A one-item Action or Resource is written as a string. It
// returns the canonical document, its hash, and every action and resource it
// names (sorted, unique).
func BuildAccessDocument(effect string, stmts []AccessStatement, startsAt, endsAt *time.Time) ([]byte, string, []string, []string, error) {
	if len(stmts) == 0 || len(stmts[0].Actions) == 0 {
		return nil, "", nil, nil, errors.New("no action for the access levels")
	}
	eff := EffectAllow
	if effect == AccessEffectBlock {
		eff = EffectDeny
	}
	window := map[string]any{}
	if startsAt != nil {
		window[CondDateGreaterThan] = map[string]any{KeyCurrentTime: AWSTime(*startsAt)}
	}
	if endsAt != nil && !endsAt.Equal(AccessNoEnd) {
		window[CondDateLessThan] = map[string]any{KeyCurrentTime: AWSTime(*endsAt)}
	}
	one := func(v []string) any {
		if len(v) == 1 {
			return v[0]
		}
		return v
	}
	var actions, resources []string
	out := make([]any, 0, len(stmts))
	for _, st := range stmts {
		acts, res := sortedUnique(st.Actions), sortedUnique(st.Resources)
		if len(acts) == 0 || len(res) == 0 {
			return nil, "", nil, nil, fmt.Errorf("statement %s has no action or resource", st.Sid)
		}
		s := map[string]any{"Sid": st.Sid, "Effect": eff, "Action": one(acts), "Resource": one(res)}
		cond := map[string]any{}
		for k, v := range window {
			cond[k] = v
		}
		for k, v := range st.Cond {
			cond[k] = v
		}
		if len(cond) > 0 {
			s["Condition"] = cond
		}
		out = append(out, s)
		actions = append(actions, acts...)
		resources = append(resources, res...)
	}
	doc := map[string]any{"Version": PolicyVersion20121017, "Statement": out}
	c, err := CanonicalizeValue(doc)
	if err != nil {
		return nil, "", nil, nil, err
	}
	if PolicyChars(c) > MaxPolicyChars {
		return nil, "", nil, nil, fmt.Errorf("the policy document is larger than %d characters", MaxPolicyChars)
	}
	return c, ContentHash(c), sortedUnique(actions), sortedUnique(resources), nil
}

// accessHas reports that access holds any of levels.
func accessHas(access []string, levels ...string) bool {
	for _, a := range access {
		for _, l := range levels {
			if a == l {
				return true
			}
		}
	}
	return false
}
