package awsenforce

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
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
	return liveIAM{c: client}, &Identity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

type liveIAM struct{ c *iam.Client }

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
