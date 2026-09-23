package awsdiscovery

import (
	"errors"
	"strings"

	"github.com/aws/smithy-go"
)

// Naming the call that failed, never a guess at the missing permission
// (SPEC-iga-phase2-graph.md §2.14.13, §5.3 GET /coverage: error_code, api).
//
// An AccessDenied says which API call AWS refused. It does not say which
// permission is missing: an SCP, a permissions boundary on the discovery role
// or a region opt-out produce the same response. So coverage records exactly
// two facts the SDK reported -- the operation and the error code -- and
// nothing inferred from them.

// classifiedError is what classify returns: the sentinel for the caller's
// status mapping, the message exactly as classify has always written it, and
// the SDK's own error kept in the chain. Before, classify formatted the SDK
// error into a string and dropped it, so the operation name and the error code
// were unrecoverable by the time a scanner recorded coverage.
type classifiedError struct {
	msg      string
	sentinel error // nil for an unclassified AWS error
	cause    error
}

func (e *classifiedError) Error() string { return e.msg }

// Unwrap exposes both: errors.Is finds the sentinel, errors.As finds the
// smithy.APIError and smithy.OperationError inside the cause.
func (e *classifiedError) Unwrap() []error {
	if e.sentinel == nil {
		return []error{e.cause}
	}
	return []error{e.sentinel, e.cause}
}

// FailedCall reports the AWS call an error came from and the error code AWS
// returned, as the SDK stated them. Either is "" when the error does not carry
// it -- a fake, a network failure before any response, a local validation
// error -- and callers must then record nothing rather than a guess.
//
// api is "<iam prefix>:<Operation>" (iam:GetAccountAuthorizationDetails) for
// the services discovery calls, which is also how AWS names the call in
// CloudTrail and in its own AccessDenied messages. For a service outside that
// table it is "<SDK service id>:<Operation>" verbatim: still the SDK's own
// words, never a mapping invented here.
//
// When an assume-role failed underneath a regional call (the credential
// provider assumes lazily, so STS's error arrives wrapped in the EC2 or Lambda
// operation), the INNERMOST operation is the one that failed, and it is the
// one reported.
func FailedCall(err error) (api, code string) {
	if err == nil {
		return "", ""
	}
	ops := operationErrors(err)
	if n := len(ops); n > 0 {
		op := ops[n-1]
		api = apiName(op.Service(), op.Operation())
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
	}
	return api, code
}

// assumeFailed reports whether an STS operation failed somewhere in err's
// chain: the role could not be assumed, whatever call triggered the assume.
func assumeFailed(err error) bool {
	for _, op := range operationErrors(err) {
		if op.Service() == "STS" {
			return true
		}
	}
	return false
}

// operationErrors lists every smithy.OperationError in err's chain, outermost
// first. errors.As stops at the first; a lazily-assumed credential nests
// STS's operation inside the calling service's.
func operationErrors(err error) []*smithy.OperationError {
	var out []*smithy.OperationError
	var walk func(error, int)
	walk = func(e error, depth int) {
		if e == nil || depth > 32 {
			return
		}
		if op, ok := e.(*smithy.OperationError); ok {
			out = append(out, op)
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, inner := range u.Unwrap() {
				walk(inner, depth+1)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap(), depth+1)
		}
	}
	walk(err, 0)
	return out
}

// iamPrefixBySDKService maps the SDK's service id to the IAM action prefix,
// for exactly the services this package calls.
var iamPrefixBySDKService = map[string]string{
	"IAM":                       "iam",
	"STS":                       "sts",
	"Lambda":                    "lambda",
	"ECS":                       "ecs",
	"EC2":                       "ec2",
	"EKS":                       "eks",
	"Bedrock Agent":             "bedrock",
	"Bedrock AgentCore Control": "bedrock-agentcore",
	"CloudTrail":                "cloudtrail",
	"S3":                        "s3",
	"KMS":                       "kms",
}

func apiName(service, operation string) string {
	if operation == "" {
		return ""
	}
	if prefix, ok := iamPrefixBySDKService[service]; ok {
		return prefix + ":" + operation
	}
	if service == "" {
		return operation
	}
	return strings.TrimSpace(service) + ":" + operation
}
