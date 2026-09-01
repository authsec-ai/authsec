package awsdiscovery

import (
	"encoding/json"
	"strings"
)

// Permission-policy parsing: turning a managed or inline policy document into
// statements, and typing the resource ARNs those statements name.
//
// This file knows AWS and nothing about AuthSec, same as iam.go and
// trust_policy.go.

// PolicyStatement is one statement from a policy document, normalised.
type PolicyStatement struct {
	// Effect is lowercased ("allow" | "deny") to match the cloud_permission
	// schema's enum directly.
	Effect  string
	Actions []string
	// Resources is nil for a statement written with NotResource: AWS defines
	// that as "every resource except these", which is inherently broad and has
	// no finite list to report -- treated as unresourced rather than guessed.
	Resources []string
}

type permissionStatement struct {
	Effect      string          `json:"Effect"`
	Action      stringOrSlice   `json:"Action"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
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

// ParsePolicyDocument reads every statement in a decoded policy document.
//
// A statement missing an Effect, or a document that fails to parse, yields no
// statements rather than an error: one malformed managed policy must not abort
// the scan of every other policy attached to the identity.
func ParsePolicyDocument(doc string) []PolicyStatement {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var parsed permissionPolicyDocument
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}

	out := make([]PolicyStatement, 0, len(parsed.Statement))
	for _, stmt := range parsed.Statement {
		if stmt.Effect == "" || len(stmt.Action) == 0 {
			continue
		}
		out = append(out, PolicyStatement{
			Effect:    strings.ToLower(stmt.Effect),
			Actions:   stmt.Action,
			Resources: decodeResourceField(stmt.Resource, stmt.NotResource),
		})
	}
	return out
}

func decodeResourceField(resource, notResource json.RawMessage) []string {
	if len(notResource) > 0 {
		return nil
	}
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
