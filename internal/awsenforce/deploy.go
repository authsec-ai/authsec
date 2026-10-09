package awsenforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// The enforcement-role side of one deployment (SPEC-iga-phase3-policy.md
// §3.5, §4.4, §8.1, §8.5; T3.10): which session the writes use, how an op of
// a compiled plan becomes ONE concrete IAM request (the ${deployment_id}
// placeholder substituted, a version selector resolved to one version), the
// request hash the write-ahead attempt records, and how what AWS answered is
// turned into igagov's response kinds. Nothing here touches the database: the
// executor (services/iga_gov_aws_executor.go) wraps every Send in an
// IGAGovAttemptLog attempt.

// DeploymentSessionName is §3.6 / §4.4's RoleSessionName of a deployment's
// enforcement session: authsec-enforce-<deployment id 16hex>, so CloudTrail
// names the deployment in every AuthSec write.
func DeploymentSessionName(deploymentID uuid.UUID) string {
	return "authsec-enforce-" + strings.ReplaceAll(deploymentID.String(), "-", "")[:16]
}

// Request is one IAM write, fully resolved: no placeholder, no selector. Its
// canonical form is what the attempt's request_hash covers (§8.1 "sha256 of
// the canonical request parameters"); the document travels by hash (the body
// is iga_gov_document's canonical text for that hash).
type Request struct {
	Op           string            `json:"op"`
	RoleName     string            `json:"role_name,omitempty"`
	PolicyARN    string            `json:"policy_arn,omitempty"`
	PolicyName   string            `json:"policy_name,omitempty"`
	Path         string            `json:"path,omitempty"`
	DocumentHash string            `json:"document_hash,omitempty"`
	SetAsDefault bool              `json:"set_as_default,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	// VersionID is the version a DeletePolicyVersion deletes, resolved from
	// the op's selector against a fresh read (D46).
	VersionID string `json:"version_id,omitempty"`
}

// ErrUnresolvedOp: an op that still carries a placeholder outside a tag
// value, a selector without a resolved version, or an op this adapter does
// not run (the dedicated-identity steps of §11 are IaC-only).
var ErrUnresolvedOp = errors.New("awsenforce: the op cannot be sent as it is")

// ErrOpRoleMismatch: a role op names a role other than the control's (or a
// policy op names a role at all). Terminal: the plan is never sent.
var ErrOpRoleMismatch = errors.New("awsenforce: the op names a role other than the control's")

// NewRequest resolves an op of a direct plan for one deployment of the
// control whose role is controlRole (its role NAME, the last segment of the
// control's role ARN): every ${deployment_id} (igagov.DeploymentPlaceholder,
// D27) in a tag value becomes the deployment id, and a DeletePolicyVersion
// names versionID. The placeholder anywhere else is refused, as is a
// selector op without a version, or a version for any other op.
//
// A role op (PutRolePermissionsBoundary, DeleteRolePermissionsBoundary) must
// name exactly controlRole, and a policy op must name no role: a stored plan
// whose op would write another role's boundary is refused with
// ErrOpRoleMismatch before anything is prepared or sent.
func NewRequest(op igagov.Op, deploymentID uuid.UUID, versionID, controlRole string) (Request, error) {
	switch op.Op {
	case igagov.OpCreatePolicy, igagov.OpCreatePolicyVersion, igagov.OpDeletePolicyVersion, igagov.OpTagPolicy,
		igagov.OpDeletePolicy, igagov.OpPutRolePermissionsBoundary, igagov.OpDeleteRolePermissionsBoundary:
	default:
		return Request{}, fmt.Errorf("%w: %s is not an enforcement-role write", ErrUnresolvedOp, op.Op)
	}
	if op.RoleARN != "" {
		return Request{}, fmt.Errorf("%w: %s names another role (%s); only the control's role is written directly", ErrUnresolvedOp, op.Op, op.RoleARN)
	}
	if err := CheckOpRole(op, controlRole); err != nil {
		return Request{}, err
	}
	r := Request{Op: op.Op, RoleName: op.RoleName, PolicyARN: op.PolicyARN, PolicyName: op.PolicyName, Path: op.Path,
		DocumentHash: op.DocumentHash, SetAsDefault: op.SetAsDefault}
	if len(op.Tags) > 0 {
		r.Tags = make(map[string]string, len(op.Tags))
		for k, v := range op.Tags {
			if strings.Contains(k, igagov.DeploymentPlaceholder) {
				return Request{}, fmt.Errorf("%w: placeholder in tag key %q", ErrUnresolvedOp, k)
			}
			r.Tags[k] = strings.ReplaceAll(v, igagov.DeploymentPlaceholder, deploymentID.String())
		}
	}
	for _, f := range []string{r.RoleName, r.PolicyARN, r.PolicyName, r.Path, r.DocumentHash} {
		if strings.Contains(f, "${") {
			return Request{}, fmt.Errorf("%w: unresolved placeholder in %q", ErrUnresolvedOp, f)
		}
	}
	switch {
	case op.Op == igagov.OpDeletePolicyVersion && versionID == "":
		return Request{}, fmt.Errorf("%w: DeletePolicyVersion %s selector %q was not resolved to a version", ErrUnresolvedOp, op.PolicyARN, op.Select)
	case op.Op != igagov.OpDeletePolicyVersion && versionID != "":
		return Request{}, fmt.Errorf("%w: %s takes no version", ErrUnresolvedOp, op.Op)
	}
	r.VersionID = versionID
	if needsDocument(r.Op) && r.DocumentHash == "" {
		return Request{}, fmt.Errorf("%w: %s carries no document hash", ErrUnresolvedOp, r.Op)
	}
	return r, nil
}

// CheckOpRole is NewRequest's role rule on its own: a role op names exactly
// controlRole (non-empty), any other op names no role.
func CheckOpRole(op igagov.Op, controlRole string) error {
	switch op.Op {
	case igagov.OpPutRolePermissionsBoundary, igagov.OpDeleteRolePermissionsBoundary:
		if controlRole == "" || op.RoleName != controlRole {
			return fmt.Errorf("%w: %s names role %q, the control's role is %q", ErrOpRoleMismatch, op.Op, op.RoleName, controlRole)
		}
	default:
		if op.RoleName != "" {
			return fmt.Errorf("%w: %s is a policy op but names role %q", ErrOpRoleMismatch, op.Op, op.RoleName)
		}
	}
	return nil
}

// needsDocument reports whether the request sends a policy document.
func needsDocument(op string) bool {
	return op == igagov.OpCreatePolicy || op == igagov.OpCreatePolicyVersion
}

// SendsDocument reports whether the request carries a document body (the
// executor loads it from iga_gov_document by DocumentHash).
func (r Request) SendsDocument() bool { return needsDocument(r.Op) }

// Hash is the attempt's request_hash: the content hash of the request's RFC
// 8785 form, after substitution and resolution (§8.1).
func (r Request) Hash() (string, error) {
	c, err := igagov.CanonicalizeValue(r)
	if err != nil {
		return "", err
	}
	return igagov.ContentHash(c), nil
}

// Response is how one call ended, as AuthSec can know it.
type Response struct {
	// Kind is RespOK, RespError (a definitive AWS error, ErrorCode set) or
	// RespNoAnswer (timeout, connection error, 5xx: AWS may have applied it).
	Kind      igagov.ResponseKind
	ErrorCode string
	Message   string
	RequestID string
	// VersionID is what CreatePolicyVersion returned.
	VersionID string
	// Err is the call's error, if any.
	Err error
}

// Send makes the one IAM call of req with document (the canonical text whose
// hash is req.DocumentHash, for CreatePolicy and CreatePolicyVersion). The
// client must have SDK retries off (LiveAssumer's has): Send never retries.
// The request id of a successful call is captured when the client records it
// (WithRequestIDRecorder); an error's request id is read from the error.
func Send(ctx context.Context, c IAM, req Request, document string) Response {
	ctx, requestID := WithRequestIDRecorder(ctx)
	var err error
	var version string
	switch req.Op {
	case igagov.OpCreatePolicy:
		_, err = c.CreatePolicy(ctx, CreatePolicyInput{Path: req.Path, Name: req.PolicyName, Document: document, Tags: req.Tags})
	case igagov.OpCreatePolicyVersion:
		version, err = c.CreatePolicyVersion(ctx, req.PolicyARN, document, req.SetAsDefault)
	case igagov.OpDeletePolicyVersion:
		err = c.DeletePolicyVersion(ctx, req.PolicyARN, req.VersionID)
	case igagov.OpTagPolicy:
		err = c.TagPolicy(ctx, req.PolicyARN, req.Tags)
	case igagov.OpDeletePolicy:
		err = c.DeletePolicy(ctx, req.PolicyARN)
	case igagov.OpPutRolePermissionsBoundary:
		err = c.PutRolePermissionsBoundary(ctx, req.RoleName, req.PolicyARN)
	case igagov.OpDeleteRolePermissionsBoundary:
		err = c.DeleteRolePermissionsBoundary(ctx, req.RoleName)
	default:
		return Response{Kind: igagov.RespError, ErrorCode: "UnsupportedOperation", Message: req.Op,
			Err: fmt.Errorf("%w: %s", ErrUnresolvedOp, req.Op)}
	}
	out := ClassifyCallError(err)
	out.VersionID = version
	if out.RequestID == "" {
		out.RequestID = requestID()
	}
	return out
}

// noAnswerCodes are AWS error codes that do not prove the request was not
// applied (§8.5: "A 5xx/ServiceFailure ... is not retried").
var noAnswerCodes = map[string]bool{
	"ServiceFailure": true, "InternalFailure": true, "ServiceUnavailable": true, "InternalError": true,
	"RequestTimeout": true, "RequestTimeoutException": true,
}

// ClassifyCallError turns a call's error into a Response kind: nil is
// RespOK; an AWS error with a 4xx code is RespError; a 5xx, one of the
// service-failure codes, a timeout, a cancelled context, a connection error
// or anything without an AWS error code is RespNoAnswer, because AWS may have
// applied the request.
func ClassifyCallError(err error) Response {
	if err == nil {
		return Response{Kind: igagov.RespOK}
	}
	out := Response{Err: err, Message: trimMessage(err)}
	var withID interface{ ServiceRequestID() string }
	if errors.As(err, &withID) {
		out.RequestID = withID.ServiceRequestID()
	}
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() == "" {
		out.Kind = igagov.RespNoAnswer
		return out
	}
	out.ErrorCode = api.ErrorCode()
	var re *awshttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() >= 500 {
		out.Kind = igagov.RespNoAnswer
		return out
	}
	if noAnswerCodes[out.ErrorCode] || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		out.Kind = igagov.RespNoAnswer
		return out
	}
	var ne net.Error
	if errors.As(err, &ne) {
		out.Kind = igagov.RespNoAnswer
		return out
	}
	// A 4xx AWS error code is an answer even if ctx ended meanwhile.
	out.Kind = igagov.RespError
	return out
}

type requestIDKey struct{}

type requestIDSlot struct {
	mu sync.Mutex
	id string
}

// WithRequestIDRecorder returns a context whose IAM client may record the
// AWS request id of a successful call (RecordRequestID), and a function that
// reads it.
func WithRequestIDRecorder(ctx context.Context) (context.Context, func() string) {
	s := &requestIDSlot{}
	return context.WithValue(ctx, requestIDKey{}, s), func() string {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.id
	}
}

// RecordRequestID records id in ctx's recorder, if it has one. IAM clients
// (live and fake) call it after a successful call.
func RecordRequestID(ctx context.Context, id string) {
	if s, ok := ctx.Value(requestIDKey{}).(*requestIDSlot); ok && id != "" {
		s.mu.Lock()
		s.id = id
		s.mu.Unlock()
	}
}
