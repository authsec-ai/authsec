package awsenforce

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
)

// LiveAssumer assumes a binding's enforcement role against real AWS (§4.4):
// AuthSec's base credentials from the ambient environment, AssumeRole with the
// binding's ExternalId, DurationSeconds 900, the given session name, and
// GetCallerIdentity to prove the session. The returned IAM client has SDK
// retries OFF: every probe is one call, so what AWS answered is what is
// recorded. Credentials are never cached across self-tests or logged.
type LiveAssumer struct{}

// enforcementSessionDuration is §4.4's DurationSeconds.
const enforcementSessionDuration = 900 * time.Second

// baseCredentialTimeout bounds resolving AuthSec's own identity.
const baseCredentialTimeout = 10 * time.Second

// ErrNoBaseCredentials means AuthSec's own AWS identity is unusable.
var ErrNoBaseCredentials = errors.New("AuthSec has no usable AWS credentials of its own")

// AssumeEnforcement implements Assumer.
func (LiveAssumer) AssumeEnforcement(ctx context.Context, in AssumeInput) (IAM, *Identity, error) {
	if err := awsdiscovery.ValidateAssumeRequest(awsdiscovery.AssumeRequest{
		RoleARN: in.RoleARN, ExternalID: in.ExternalID, Region: in.Region, SessionName: in.SessionName,
	}); err != nil {
		return nil, nil, err
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(in.Region))
	if err != nil || base.Credentials == nil {
		return nil, nil, ErrNoBaseCredentials
	}
	credCtx, cancel := context.WithTimeout(ctx, baseCredentialTimeout)
	defer cancel()
	if _, err := base.Credentials.Retrieve(credCtx); err != nil {
		return nil, nil, ErrNoBaseCredentials
	}
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(base), in.RoleARN,
		func(o *stscreds.AssumeRoleOptions) {
			o.ExternalID = aws.String(in.ExternalID)
			o.RoleSessionName = in.SessionName
			o.Duration = enforcementSessionDuration
		})
	cfg := base.Copy()
	cfg.Credentials = aws.NewCredentialsCache(provider)
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, err
	}
	client := iam.NewFromConfig(cfg, func(o *iam.Options) { o.Retryer = aws.NopRetryer{} })
	return liveIAM{c: client, cfg: cfg}, &Identity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

// liveIAM is the enforcement session's client. cfg is the assumed-role
// configuration it was built from, kept for the template v2 Lambda call
// (UpdateFunctionRole), which needs a client in the function's region.
type liveIAM struct {
	c   *iam.Client
	cfg aws.Config
}

func (l liveIAM) CreatePolicy(ctx context.Context, in CreatePolicyInput) (string, error) {
	out, err := l.c.CreatePolicy(ctx, &iam.CreatePolicyInput{
		PolicyName: aws.String(in.Name), Path: aws.String(in.Path),
		PolicyDocument: aws.String(in.Document), Tags: iamTags(in.Tags),
	})
	if err != nil {
		return "", err
	}
	recordMetadata(ctx, out.ResultMetadata)
	if out.Policy == nil {
		return "", nil
	}
	return aws.ToString(out.Policy.Arn), nil
}

func (l liveIAM) CreatePolicyVersion(ctx context.Context, policyARN, document string, setAsDefault bool) (string, error) {
	out, err := l.c.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{
		PolicyArn: aws.String(policyARN), PolicyDocument: aws.String(document), SetAsDefault: setAsDefault,
	})
	if err != nil {
		return "", err
	}
	recordMetadata(ctx, out.ResultMetadata)
	if out.PolicyVersion == nil {
		return "", nil
	}
	return aws.ToString(out.PolicyVersion.VersionId), nil
}

func (l liveIAM) DeletePolicyVersion(ctx context.Context, policyARN, versionID string) error {
	out, err := l.c.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
		PolicyArn: aws.String(policyARN), VersionId: aws.String(versionID),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) PutRolePermissionsBoundary(ctx context.Context, roleName, boundaryARN string) error {
	out, err := l.c.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{
		RoleName: aws.String(roleName), PermissionsBoundary: aws.String(boundaryARN),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DeleteRolePermissionsBoundary(ctx context.Context, roleName string) error {
	out, err := l.c.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{
		RoleName: aws.String(roleName),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DeletePolicy(ctx context.Context, policyARN string) error {
	out, err := l.c.DeletePolicy(ctx, &iam.DeletePolicyInput{PolicyArn: aws.String(policyARN)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) TagPolicy(ctx context.Context, policyARN string, tags map[string]string) error {
	out, err := l.c.TagPolicy(ctx, &iam.TagPolicyInput{PolicyArn: aws.String(policyARN), Tags: iamTags(tags)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

/* ------------------------- enforcement template v2 ------------------------ */

// liveIAM implements IAMv2 (template v2, DECISION R2-14 / R2-15). Whether AWS
// allows each call is the stack's business; every call is one request with
// SDK retries off, like the v1 methods.
var _ IAMv2 = liveIAM{}

func (l liveIAM) AttachRolePolicy(ctx context.Context, roleName, policyARN string) error {
	out, err := l.c.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName: aws.String(roleName), PolicyArn: aws.String(policyARN),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DetachRolePolicy(ctx context.Context, roleName, policyARN string) error {
	out, err := l.c.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName: aws.String(roleName), PolicyArn: aws.String(policyARN),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) PutRolePolicy(ctx context.Context, roleName, policyName, document string) error {
	out, err := l.c.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(policyName), PolicyDocument: aws.String(document),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) DeleteRolePolicy(ctx context.Context, roleName, policyName string) error {
	out, err := l.c.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
		RoleName: aws.String(roleName), PolicyName: aws.String(policyName),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

func (l liveIAM) CreateRole(ctx context.Context, in CreateRoleInput) (string, error) {
	req := &iam.CreateRoleInput{
		RoleName: aws.String(in.Name), AssumeRolePolicyDocument: aws.String(in.TrustDocument), Tags: iamTags(in.Tags),
	}
	if in.Path != "" {
		req.Path = aws.String(in.Path)
	}
	if in.Description != "" {
		req.Description = aws.String(in.Description)
	}
	out, err := l.c.CreateRole(ctx, req)
	if err != nil {
		return "", err
	}
	recordMetadata(ctx, out.ResultMetadata)
	if out.Role == nil {
		return "", nil
	}
	return aws.ToString(out.Role.Arn), nil
}

func (l liveIAM) DeleteRole(ctx context.Context, roleName string) error {
	out, err := l.c.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

// UpdateFunctionRole sets the function's ($LATEST) execution role, through a
// Lambda client in the function ARN's region with SDK retries off.
func (l liveIAM) UpdateFunctionRole(ctx context.Context, functionARN, roleARN string) error {
	region, err := lambdaFunctionRegion(functionARN)
	if err != nil {
		return err
	}
	client := lambda.NewFromConfig(l.cfg, func(o *lambda.Options) {
		o.Region = region
		o.Retryer = aws.NopRetryer{}
	})
	out, err := client.UpdateFunctionConfiguration(ctx, &lambda.UpdateFunctionConfigurationInput{
		FunctionName: aws.String(functionARN), Role: aws.String(roleARN),
	})
	if err == nil {
		recordMetadata(ctx, out.ResultMetadata)
	}
	return err
}

// lambdaFunctionRegion is the region of a Lambda function ARN
// (arn:<partition>:lambda:<region>:<account>:function:<name>[:<qualifier>]).
func lambdaFunctionRegion(functionARN string) (string, error) {
	parts := strings.SplitN(functionARN, ":", 7)
	if len(parts) < 7 || parts[0] != "arn" || parts[2] != "lambda" || parts[3] == "" || parts[5] != "function" || parts[6] == "" {
		return "", fmt.Errorf("%q is not a Lambda function ARN", functionARN)
	}
	return parts[3], nil
}

// iamTags converts a tag map into IAM tags, sorted by key so the request is
// the same whatever the map's iteration order.
func iamTags(tags map[string]string) []iamtypes.Tag {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]iamtypes.Tag, 0, len(keys))
	for _, k := range keys {
		out = append(out, iamtypes.Tag{Key: aws.String(k), Value: aws.String(tags[k])})
	}
	return out
}

// recordMetadata hands the AWS request id of a successful call to the
// recorder in ctx, if any (WithRequestIDRecorder).
func recordMetadata(ctx context.Context, md middleware.Metadata) {
	if id, ok := awsmiddleware.GetRequestIDMetadata(md); ok {
		RecordRequestID(ctx, id)
	}
}
