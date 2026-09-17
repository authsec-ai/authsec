package awsdiscovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Permission-policy parsing: turning a managed or inline policy document into
// statements, and typing the resource ARNs those statements name.
//
// This file knows AWS and nothing about AuthSec, same as iam.go and
// trust_policy.go.

// PolicyStatement is one statement from a policy document, normalised.
//
// Every field AWS uses to decide whether a request is allowed is kept, because
// a statement stripped of its negations and conditions reads as broader than it
// is. Nothing here is evaluated: this layer records what the document says.
type PolicyStatement struct {
	// Effect is lowercased ("allow" | "deny") to match the cloud_permission
	// schema's enum directly.
	Effect string
	// Actions is the Action element. Empty when the statement used NotAction.
	Actions []string
	// NotActions is the NotAction element: "every action except these". A
	// statement carrying it is NOT dropped -- dropping it loses a Deny
	// entirely, which is the most dangerous possible parse failure.
	NotActions []string
	// Resources is the Resource element. Empty when the statement used
	// NotResource, or named no resource at all.
	Resources []string
	// NotResources is the NotResource element: "every resource except these".
	// Kept verbatim. It must never be widened to "*" -- that turns a bounded
	// exclusion into an unbounded grant, and a reviewer cannot tell the
	// difference afterwards.
	NotResources []string
	// Condition is the Condition block as it appeared, compact JSON, or "" when
	// the statement had none.
	//
	// Stored, never evaluated. A conditional grant rendered as unconditional
	// over-reports access: "GetObject on reports/*" and "GetObject on reports/*
	// when PrincipalTag/Team is operations" are different facts.
	Condition string
	// Index is this statement's position in the ORIGINAL document, counting
	// every statement including ones that could not be used.
	//
	// Callers key stored rows on it, so it must not shift when an unusable
	// statement is skipped: renumbering would silently repoint an existing row
	// at a different statement.
	Index int
	// Sid is the statement id where the author set one. Useful for pointing a
	// customer at the exact statement; not an identity, since it is optional
	// and not unique across documents.
	Sid string
}

// Unbounded reports whether the statement names no concrete resource at all --
// no Resource and no NotResource. That is genuinely account-wide.
//
// A statement with NotResource is NOT unbounded: it excludes something, and
// callers must not collapse the two.
func (s PolicyStatement) Unbounded() bool {
	return len(s.Resources) == 0 && len(s.NotResources) == 0
}

type permissionStatement struct {
	Sid         string          `json:"Sid"`
	Effect      string          `json:"Effect"`
	Action      stringOrSlice   `json:"Action"`
	NotAction   stringOrSlice   `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Condition   json.RawMessage `json:"Condition"`
}

type permissionStatementList []permissionStatement

func (l *permissionStatementList) UnmarshalJSON(b []byte) error {
	var one permissionStatement
	if err := json.Unmarshal(b, &one); err == nil && one.Effect != "" {
		*l = []permissionStatement{one}
		return nil
	}
	var many []permissionStatement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

type permissionPolicyDocument struct {
	Statement permissionStatementList `json:"Statement"`
}

// ErrMalformedPolicy is returned when a document cannot be parsed at all.
//
// It exists so a broken policy is a coverage failure rather than an empty
// result: "this policy grants nothing" and "we could not read this policy" are
// different answers, and silently returning zero statements makes the second
// one look like the first.
var ErrMalformedPolicy = errors.New("awsdiscovery: malformed policy document")

// ParsePolicyDocument reads every statement in a decoded policy document.
//
// A document that will not parse returns ErrMalformedPolicy. Individual
// statements that carry no Effect, or neither Action nor NotAction, are skipped
// and counted in the returned skip count -- one unusable statement must not
// discard the rest of the document, but the caller still needs to know it
// happened.
func ParsePolicyDocument(doc string) (statements []PolicyStatement, skipped int, err error) {
	if strings.TrimSpace(doc) == "" {
		return nil, 0, nil
	}
	var parsed permissionPolicyDocument
	if uerr := json.Unmarshal([]byte(doc), &parsed); uerr != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrMalformedPolicy, uerr)
	}

	out := make([]PolicyStatement, 0, len(parsed.Statement))
	for i, stmt := range parsed.Statement {
		// A statement needs an Effect, and needs to say which actions it is
		// about -- through Action or NotAction. A Deny written with NotAction
		// used to vanish here, taking the denial with it.
		if stmt.Effect == "" || (len(stmt.Action) == 0 && len(stmt.NotAction) == 0) {
			skipped++
			continue
		}
		out = append(out, PolicyStatement{
			Index:        i,
			Sid:          stmt.Sid,
			Effect:       strings.ToLower(stmt.Effect),
			Actions:      stmt.Action,
			NotActions:   stmt.NotAction,
			Resources:    decodeResourceField(stmt.Resource),
			NotResources: decodeResourceField(stmt.NotResource),
			Condition:    compactJSON(stmt.Condition),
		})
	}
	return out, skipped, nil
}

// compactJSON returns the raw message with insignificant whitespace removed, so
// the same condition block from two APIs stores identically. Invalid JSON is
// returned as-is rather than dropped: the caller asked to preserve what AWS
// said, and an unparseable condition is still evidence that a condition exists.
func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// decodeResourceField reads a Resource or NotResource element, which AWS allows
// to be either a single string or an array of them.
func decodeResourceField(resource json.RawMessage) []string {
	if len(resource) == 0 {
		return nil
	}
	var single stringOrSlice
	if err := json.Unmarshal(resource, &single); err != nil {
		return nil
	}
	return single
}

/* ------------------------------ resource typing ---------------------------- */

// TypedResource is a resource ARN, typed by service, ready to become a
// cloud_resource row.
type TypedResource struct {
	// Kind is e.g. "s3_bucket", "dynamodb_table", or "<service>" when no more
	// specific label applies. Never an enum -- see the migration's header.
	Kind string
	Name string
	// NativeID is the ARN, verbatim.
	NativeID string
	// Service is the ARN's raw service segment ("s3", "kms", "iam", ...),
	// kept alongside Kind so a caller can classify sensitivity by service
	// without re-parsing the ARN or the Kind string it derived.
	Service string
}

// ClassifyResourceScope reports what one Resource entry from a statement means
// for cloud_permission.scope_kind, and the ARN to type when it names one.
//
//   - "*"                      -> account_wide, no resource
//   - contains "*" or "?" elsewhere -> prefix, no resource -- see the plan's
//     rule that a partial wildcard is a scope, not a thing
//   - a concrete ARN            -> resource, typed via TypeResourceARN
//
// A value that is not an ARN at all (malformed policy, or a non-ARN condition
// key some services allow) is treated as prefix: broad and unnamed, which is
// the safe default when the shape cannot be trusted enough to type it.
func ClassifyResourceScope(resource string) (scopeKind string, typed *TypedResource) {
	switch {
	case resource == "*":
		return PermissionScopeAccountWide, nil
	case strings.ContainsAny(resource, "*?"):
		return PermissionScopePrefix, nil
	case strings.HasPrefix(resource, "arn:"):
		return PermissionScopeResource, TypeResourceARN(resource)
	default:
		return PermissionScopePrefix, nil
	}
}

// Scope/effect/plane/derivation constants live in models, alongside the schema
// they describe. This package cannot import models (see the file header on
// trust_policy.go), so the three scope_kind strings this function returns are
// declared here, equal by value to their models.Permission* counterparts.
const (
	PermissionScopeAccountWide = "account_wide"
	PermissionScopePrefix      = "prefix"
	PermissionScopeResource    = "resource"
)

// TypeResourceARN parses a resource ARN into a typed resource.
//
// arn:<partition>:<service>:<region>:<account>:<resource>, where <resource>
// itself varies by service: "bucket-name" for S3, "table/Name" for DynamoDB,
// "db:instance-id" for RDS, "secret:name-suffix" for Secrets Manager,
// "queue-name" for SQS, and either "type/id" or "type:id" for most everything
// else. The five named here are the plan's own examples; anything else falls
// back to "<service>_<resourcetype>" or plain "<service>", which is additive --
// naming a sixth service correctly later needs no schema change.
func TypeResourceARN(arn string) *TypedResource {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return &TypedResource{Kind: "unknown", NativeID: arn}
	}
	service := parts[2]
	resource := parts[5]

	switch service {
	case "s3":
		// arn:aws:s3:::bucket, or arn:aws:s3:::bucket/key. No resourcetype
		// segment -- S3 is the one AWS service whose ARN omits it.
		bucket := resource
		if i := strings.Index(bucket, "/"); i >= 0 {
			bucket = bucket[:i]
		}
		return &TypedResource{Kind: "s3_bucket", Name: bucket, NativeID: arn, Service: service}

	case "sqs":
		// arn:aws:sqs:region:account:queue-name. No resourcetype segment.
		return &TypedResource{Kind: "sqs_queue", Name: resource, NativeID: arn, Service: service}

	case "dynamodb":
		if name, ok := afterSeparator(resource, "table/"); ok {
			return &TypedResource{Kind: "dynamodb_table", Name: name, NativeID: arn, Service: service}
		}

	case "rds":
		// arn:aws:rds:region:account:db:instance-id -- colon-separated, and the
		// resourcetype "db" reads better to an operator as "instance".
		if name, ok := afterSeparator(resource, "db:"); ok {
			return &TypedResource{Kind: "rds_instance", Name: name, NativeID: arn, Service: service}
		}

	case "secretsmanager":
		if name, ok := afterSeparator(resource, "secret:"); ok {
			return &TypedResource{Kind: "secretsmanager_secret", Name: name, NativeID: arn, Service: service}
		}
	}

	// Generic fallback: split on the first "/" or ":" inside the resource part,
	// whichever appears. Most AWS services use one of the two.
	if rtype, name, ok := splitResourceType(resource); ok {
		return &TypedResource{Kind: service + "_" + rtype, Name: name, NativeID: arn, Service: service}
	}
	return &TypedResource{Kind: service, Name: resource, NativeID: arn, Service: service}
}

func afterSeparator(resource, prefix string) (string, bool) {
	if !strings.HasPrefix(resource, prefix) {
		return "", false
	}
	return resource[len(prefix):], true
}

// splitResourceType splits "type/id" or "type:id" into its two halves. Neither
// separator is preferred; AWS itself is inconsistent across services.
func splitResourceType(resource string) (rtype, name string, ok bool) {
	if i := strings.Index(resource, "/"); i > 0 {
		return resource[:i], resource[i+1:], true
	}
	if i := strings.Index(resource, ":"); i > 0 {
		return resource[:i], resource[i+1:], true
	}
	return "", "", false
}
