// Package awsdiscovery is the AWS adapter for cloud discovery: the
// CloudFormation template a customer deploys, and the cross-account assume-role
// plumbing every AWS scan runs on top of.
//
// It is an adapter in the same sense as internal/vault — it knows about AWS and
// nothing about AuthSec. Policy (what to validate, what to persist, what to put
// in the secrets store) belongs in services/cloud_aws_onboarding.go. Keeping
// the split means the scanners in later tickets share one authenticated path
// instead of each building their own.
package awsdiscovery

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// CloudFormationTemplate is the template the customer deploys to create the
// read-only role. Embedded rather than hosted so that the template a customer
// runs is exactly the one this build expects, and an air-gapped or
// self-hosted deployment needs no outbound fetch to onboard an account.
//
//go:embed authsec-aws-discovery-role.yaml
var CloudFormationTemplate string

// TemplateVersion identifies the permission set the template grants. Recorded
// on the connector so that when a later ticket adds a surface, an operator can
// find the accounts still running an older stack instead of debugging a
// mysterious AccessDenied.
//
// Bumped by ticket [2], which adds iam:ListOpenIDConnectProviders.
//
// Must match the TemplateVersion output in the YAML.
const TemplateVersion = "2026-09-01"

// maxRetryAttempts bounds the SDK's built-in backoff. Above the SDK default of
// 3 because IAM and CloudTrail throttle readily on a large account and a scan
// that gives up on the first ThrottlingException reports a partial estate as if
// it were the whole one. Standard mode rather than adaptive: adaptive adds
// client-side rate limiting whose behaviour is hard to reason about when a
// scan is already slow for unrelated reasons.
const maxRetryAttempts = 8

// roleARNPattern matches an IAM role ARN and captures the partition and the
// account. Paths are allowed: a role created inside an OU-managed path has an
// ARN of the form arn:aws:iam::123456789012:role/some/path/RoleName.
var roleARNPattern = regexp.MustCompile(
	`^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/(.+)$`)

// regionPattern matches every current AWS region shape, commercial, GovCloud
// and China. Deliberately a shape check and not an allow-list: a hard-coded
// list of regions goes stale every time AWS launches one, and the failure mode
// is refusing to scan a region the customer legitimately uses.
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d{1,2}$`)

// sessionNamePattern is AWS's own constraint on RoleSessionName.
var sessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// Errors the service layer maps to HTTP status codes. Everything else is a 502:
// the failure was AWS's, not the caller's.
var (
	// ErrNotAssumable means AWS refused the assume-role call. Almost always a
	// customer-side mismatch — wrong ExternalId, or a trust policy naming a
	// different principal — so it is a 400, not a 500.
	ErrNotAssumable = errors.New("the role could not be assumed")
	// ErrThrottled means AWS throttled us even after the SDK's own backoff.
	ErrThrottled = errors.New("AWS throttled the request")
	// ErrNoBaseCredentials means AuthSec's OWN AWS identity is missing or
	// unusable. Nothing the customer can fix.
	ErrNoBaseCredentials = errors.New("AuthSec has no usable AWS credentials of its own")
)

// Identity is what sts:GetCallerIdentity reported: proof of who we actually
// became, as opposed to who we asked to become.
type Identity struct {
	// AccountID is the 12-digit account the session landed in. This is the
	// scope_id of the connector — taken from AWS rather than from anything the
	// caller typed.
	AccountID string
	// ARN is the assumed-role ARN
	// (arn:aws:sts::123456789012:assumed-role/Role/Session), not the role ARN.
	ARN string
	// UserID is the RoleId:SessionName pair.
	UserID string
}

// AssumeRequest is everything needed to become a customer's discovery role.
type AssumeRequest struct {
	RoleARN     string
	ExternalID  string
	Region      string
	SessionName string
}

// Verifier proves an AssumeRequest works and reports the identity it produced.
//
// An interface with one method so the onboarding service can be exercised
// without an AWS account: the live implementation is the only one shipped, but
// the seam is what keeps AWS out of every test that touches onboarding.
type Verifier interface {
	Verify(ctx context.Context, req AssumeRequest) (*Identity, error)
}

// ConfigProvider hands back an authenticated AWS config for a request. Kept
// separate from Verifier because proving a connection and authenticating a scan
// are different jobs, and a test double that can do the first has no business
// being forced to fabricate the second.
type ConfigProvider interface {
	Config(ctx context.Context, req AssumeRequest) (aws.Config, error)
}

// LiveVerifier talks to real AWS. It satisfies both Verifier and ConfigProvider.
type LiveVerifier struct{}

// NewLiveVerifier constructs the production verifier.
func NewLiveVerifier() *LiveVerifier { return &LiveVerifier{} }

// Verify assumes the role and calls sts:GetCallerIdentity.
//
// GetCallerIdentity is the right probe for two reasons: it is the only STS call
// that requires no permission at all, so a failure is unambiguously "the assume
// did not work" rather than "the role is missing one read"; and it returns the
// account id, which is how onboarding learns the scope it just connected
// instead of trusting a caller-supplied one.
func (v *LiveVerifier) Verify(ctx context.Context, req AssumeRequest) (*Identity, error) {
	cfg, err := v.Config(ctx, req)
	if err != nil {
		return nil, err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, classify(err)
	}
	return &Identity{
		AccountID: aws.ToString(out.Account),
		ARN:       aws.ToString(out.Arn),
		UserID:    aws.ToString(out.UserId),
	}, nil
}

// Config returns an AWS config whose credentials are the customer's assumed
// discovery role. This is the entry point every later scan surface uses; the
// credentials refresh themselves as the session expires, so a long scan does
// not have to re-assume by hand.
//
// The BASE credentials — AuthSec's own AWS identity, the principal named in the
// customer's trust policy — come from the ambient environment: an instance
// role, IRSA, or environment variables in development. They are never stored
// per workspace, which is why onboarding needs no AuthSec-side secret at all.
func (v *LiveVerifier) Config(ctx context.Context, req AssumeRequest) (aws.Config, error) {
	if err := ValidateAssumeRequest(req); err != nil {
		return aws.Config{}, err
	}

	base, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(req.Region),
		awsconfig.WithRetryMaxAttempts(maxRetryAttempts),
		awsconfig.WithRetryMode(aws.RetryModeStandard),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("%w: %v", ErrNoBaseCredentials, err)
	}

	provider := stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(base), req.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.ExternalID = aws.String(req.ExternalID)
			o.RoleSessionName = req.SessionName
		},
	)

	cfg := base.Copy()
	// The cache is what makes the credentials reusable: without it every AWS
	// call in a scan would trigger its own AssumeRole, which is both slow and a
	// reliable way to get throttled by STS.
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg, nil
}

// ValidateAssumeRequest checks the shape of a request before any network call.
// AWS would reject a malformed ARN too, but its error is generic and arrives
// after a round trip; this one names the field.
func ValidateAssumeRequest(req AssumeRequest) error {
	if _, _, err := ParseRoleARN(req.RoleARN); err != nil {
		return err
	}
	if err := ValidateExternalID(req.ExternalID); err != nil {
		return err
	}
	if err := ValidateRegion(req.Region); err != nil {
		return err
	}
	if !sessionNamePattern.MatchString(req.SessionName) {
		return fmt.Errorf("session name %q is not valid for AWS (2-64 of [A-Za-z0-9_+=,.@-])", req.SessionName)
	}
	return nil
}

// ParseRoleARN validates an IAM role ARN and returns its partition and account.
//
// The account matters beyond validation: onboarding cross-checks it against the
// account sts:GetCallerIdentity actually reports, so a role ARN that resolves
// somewhere other than where it claims is caught rather than recorded.
func ParseRoleARN(arn string) (partition, accountID string, err error) {
	m := roleARNPattern.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return "", "", fmt.Errorf(
			"%q is not an IAM role ARN (expected arn:aws:iam::<account>:role/<name>)", arn)
	}
	return m[1], m[2], nil
}

// ValidateExternalID applies AWS's own constraint on sts:ExternalId, plus a
// floor of 32 characters.
//
// AWS permits 2 characters; that would be trivially guessable, and a guessable
// ExternalId defeats the entire purpose of the mechanism. AuthSec generates
// these, so the floor costs nothing and closes the case where one is
// hand-edited.
func ValidateExternalID(id string) error {
	if len(id) < 32 || len(id) > 1224 {
		return errors.New("external id must be between 32 and 1224 characters")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_+=,.@:/-", r):
		default:
			return fmt.Errorf("external id contains %q, which AWS does not allow", r)
		}
	}
	return nil
}

// ValidateRegion checks a region code's shape.
func ValidateRegion(region string) error {
	if !regionPattern.MatchString(region) {
		return fmt.Errorf("%q is not an AWS region code (for example us-east-1)", region)
	}
	return nil
}

// classify turns an AWS SDK error into one of the sentinels above, keeping the
// original message as context.
//
// The distinction that matters is customer-fixable versus not. AccessDenied on
// an assume-role call means the trust policy or the ExternalId is wrong, which
// the customer must correct in their own account; a throttle means try later;
// anything else is ours to investigate. Collapsing all three into "AWS error"
// sends every case to the same unhelpful place.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "InvalidClientTokenId",
			"SignatureDoesNotMatch", "ExpiredToken", "MalformedPolicyDocument":
			return fmt.Errorf("%w: %s (%s)", ErrNotAssumable, apiErr.ErrorMessage(), apiErr.ErrorCode())
		case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException":
			return fmt.Errorf("%w: %s", ErrThrottled, apiErr.ErrorMessage())
		}
		return fmt.Errorf("aws %s: %s", apiErr.ErrorCode(), apiErr.ErrorMessage())
	}
	return err
}
