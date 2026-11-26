package awsremediate

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
)

// AssumeInput names the remediation role to assume.
type AssumeInput struct {
	RoleARN     string
	ExternalID  string
	Region      string
	SessionName string
}

// Identity is the assumed session's caller identity.
type Identity struct {
	AccountID string
	ARN       string
}

// Assumer assumes a binding's remediation role. LiveAssumer is production;
// tests use a fake account.
type Assumer interface {
	AssumeRemediation(ctx context.Context, in AssumeInput) (Writer, *Identity, error)
}

// SessionName is the remediation session's RoleSessionName:
// authsec-remediate-<remediation id 16hex>. The change event's caller names
// it, which is how the proof tells AuthSec's write from anyone else's.
func SessionName(remediationID string) string {
	h := strings.ReplaceAll(remediationID, "-", "")
	if len(h) > 16 {
		h = h[:16]
	}
	return "authsec-remediate-" + h
}

// remediationSessionDuration is the session's DurationSeconds.
const remediationSessionDuration = 900 * time.Second

// ErrNoBaseCredentials means AuthSec's own AWS identity is unusable.
var ErrNoBaseCredentials = errors.New("AuthSec has no usable AWS credentials of its own")

// LiveAssumer assumes a remediation role against real AWS: AuthSec's base
// credentials from the environment, AssumeRole with the binding's
// ExternalId, 900 s, the given session name, GetCallerIdentity to prove the
// session. SDK retries are off on the writer: what AWS answered is what is
// recorded. Credentials are never cached or logged.
type LiveAssumer struct{}

// AssumeRemediation implements Assumer.
func (LiveAssumer) AssumeRemediation(ctx context.Context, in AssumeInput) (Writer, *Identity, error) {
	if err := awsdiscovery.ValidateAssumeRequest(awsdiscovery.AssumeRequest{
		RoleARN: in.RoleARN, ExternalID: in.ExternalID, Region: in.Region, SessionName: in.SessionName,
	}); err != nil {
		return nil, nil, err
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(in.Region))
	if err != nil || base.Credentials == nil {
		return nil, nil, ErrNoBaseCredentials
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := base.Credentials.Retrieve(cctx); err != nil {
		return nil, nil, ErrNoBaseCredentials
	}
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(base), in.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(in.ExternalID)
		o.RoleSessionName = in.SessionName
		o.Duration = remediationSessionDuration
	})
	cfg := base.Copy()
	cfg.Credentials = aws.NewCredentialsCache(provider)
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, nil, err
	}
	return liveWriter{cfg: cfg, iam: iam.NewFromConfig(cfg, func(o *iam.Options) { o.Retryer = aws.NopRetryer{} })},
		&Identity{AccountID: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

// NewLiveReader is Reader over the connector's DISCOVERY role configuration.
// Reads may retry: repeating a read changes nothing.
func NewLiveReader(cfg aws.Config) Reader { return liveReader{cfg: cfg, iam: iam.NewFromConfig(cfg)} }

type liveWriter struct {
	cfg aws.Config
	iam *iam.Client
}

func (l liveWriter) secrets(arn string) *secretsmanager.Client {
	return secretsmanager.NewFromConfig(l.cfg, func(o *secretsmanager.Options) {
		if r := ARNRegion(arn); r != "" {
			o.Region = r
		}
		o.Retryer = aws.NopRetryer{}
	})
}

func (l liveWriter) DetachPolicy(ctx context.Context, p Principal, arn string) error {
	if p.Kind == PrincipalUser {
		_, err := l.iam.DetachUserPolicy(ctx, &iam.DetachUserPolicyInput{UserName: aws.String(p.Name), PolicyArn: aws.String(arn)})
		return err
	}
	_, err := l.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: aws.String(p.Name), PolicyArn: aws.String(arn)})
	return err
}

func (l liveWriter) AttachPolicy(ctx context.Context, p Principal, arn string) error {
	if p.Kind == PrincipalUser {
		_, err := l.iam.AttachUserPolicy(ctx, &iam.AttachUserPolicyInput{UserName: aws.String(p.Name), PolicyArn: aws.String(arn)})
		return err
	}
	_, err := l.iam.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: aws.String(p.Name), PolicyArn: aws.String(arn)})
	return err
}

func (l liveWriter) CreatePolicy(ctx context.Context, path, name, document string, tags map[string]string) (string, error) {
	var t []iamtypes.Tag
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t = append(t, iamtypes.Tag{Key: aws.String(k), Value: aws.String(tags[k])})
	}
	out, err := l.iam.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyName: aws.String(name), Path: aws.String(path),
		PolicyDocument: aws.String(document), Tags: t})
	if err != nil {
		return "", err
	}
	if out.Policy == nil {
		return "", nil
	}
	return aws.ToString(out.Policy.Arn), nil
}

func (l liveWriter) PutInlinePolicy(ctx context.Context, p Principal, name, document string) error {
	if p.Kind == PrincipalUser {
		_, err := l.iam.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String(p.Name), PolicyName: aws.String(name), PolicyDocument: aws.String(document)})
		return err
	}
	_, err := l.iam.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: aws.String(p.Name), PolicyName: aws.String(name), PolicyDocument: aws.String(document)})
	return err
}

func (l liveWriter) DeleteInlinePolicy(ctx context.Context, p Principal, name string) error {
	if p.Kind == PrincipalUser {
		_, err := l.iam.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: aws.String(p.Name), PolicyName: aws.String(name)})
		return err
	}
	_, err := l.iam.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: aws.String(p.Name), PolicyName: aws.String(name)})
	return err
}

func (l liveWriter) CreatePolicyVersion(ctx context.Context, arn, document string, setDefault bool) (string, error) {
	out, err := l.iam.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: aws.String(arn),
		PolicyDocument: aws.String(document), SetAsDefault: setDefault})
	if err != nil || out.PolicyVersion == nil {
		return "", err
	}
	return aws.ToString(out.PolicyVersion.VersionId), nil
}

func (l liveWriter) DeletePolicyVersion(ctx context.Context, arn, versionID string) error {
	_, err := l.iam.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(versionID)})
	return err
}

func (l liveWriter) CreateAccessKey(ctx context.Context, user string) (NewKey, error) {
	out, err := l.iam.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err != nil {
		return NewKey{}, err
	}
	if out.AccessKey == nil {
		return NewKey{}, errors.New("CreateAccessKey returned no key")
	}
	return NewAccessKey(aws.ToString(out.AccessKey.AccessKeyId), aws.ToString(out.AccessKey.SecretAccessKey)), nil
}

func (l liveWriter) UpdateAccessKey(ctx context.Context, user, keyID string, active bool) error {
	st := iamtypes.StatusTypeInactive
	if active {
		st = iamtypes.StatusTypeActive
	}
	_, err := l.iam.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{UserName: aws.String(user), AccessKeyId: aws.String(keyID), Status: st})
	return err
}

func (l liveWriter) DeleteAccessKey(ctx context.Context, user, keyID string) error {
	_, err := l.iam.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(user), AccessKeyId: aws.String(keyID)})
	return err
}

func (l liveWriter) RotateSecret(ctx context.Context, arn string) (string, error) {
	out, err := l.secrets(arn).RotateSecret(ctx, &secretsmanager.RotateSecretInput{SecretId: aws.String(arn)})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.VersionId), nil
}

func (l liveWriter) PutSecretValue(ctx context.Context, arn, value string) (string, error) {
	out, err := l.secrets(arn).PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(arn), SecretString: aws.String(value)})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.VersionId), nil
}

type liveReader struct {
	cfg aws.Config
	iam *iam.Client
}

func decodePolicy(doc string) string {
	if strings.HasPrefix(strings.TrimSpace(doc), "{") {
		return doc
	}
	if u, err := url.QueryUnescape(doc); err == nil {
		return u
	}
	return doc
}

func (l liveReader) ListAttachedPolicies(ctx context.Context, p Principal) ([]string, error) {
	var out []string
	if p.Kind == PrincipalUser {
		pg := iam.NewListAttachedUserPoliciesPaginator(l.iam, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(p.Name)})
		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, a := range page.AttachedPolicies {
				out = append(out, aws.ToString(a.PolicyArn))
			}
		}
		return out, nil
	}
	pg := iam.NewListAttachedRolePoliciesPaginator(l.iam, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(p.Name)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range page.AttachedPolicies {
			out = append(out, aws.ToString(a.PolicyArn))
		}
	}
	return out, nil
}

func (l liveReader) GetInlinePolicy(ctx context.Context, p Principal, name string) (string, bool, error) {
	var doc string
	var err error
	if p.Kind == PrincipalUser {
		var out *iam.GetUserPolicyOutput
		if out, err = l.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(p.Name), PolicyName: aws.String(name)}); err == nil {
			doc = aws.ToString(out.PolicyDocument)
		}
	} else {
		var out *iam.GetRolePolicyOutput
		if out, err = l.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(p.Name), PolicyName: aws.String(name)}); err == nil {
			doc = aws.ToString(out.PolicyDocument)
		}
	}
	if IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return decodePolicy(doc), true, nil
}

func (l liveReader) GetDefaultPolicyVersion(ctx context.Context, arn string) (string, string, error) {
	out, err := l.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return "", "", err
	}
	v := aws.ToString(out.Policy.DefaultVersionId)
	doc, err := l.GetPolicyVersion(ctx, arn, v)
	return v, doc, err
}

func (l liveReader) GetPolicyVersion(ctx context.Context, arn, versionID string) (string, error) {
	out, err := l.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(versionID)})
	if err != nil {
		return "", err
	}
	return decodePolicy(aws.ToString(out.PolicyVersion.Document)), nil
}

func (l liveReader) ListPolicyVersions(ctx context.Context, arn string) ([]PolicyVersion, error) {
	var out []PolicyVersion
	pg := iam.NewListPolicyVersionsPaginator(l.iam, &iam.ListPolicyVersionsInput{PolicyArn: aws.String(arn)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Versions {
			out = append(out, PolicyVersion{ID: aws.ToString(v.VersionId), IsDefault: v.IsDefaultVersion, Created: aws.ToTime(v.CreateDate)})
		}
	}
	return out, nil
}

func (l liveReader) PolicyExists(ctx context.Context, arn string) (bool, error) {
	_, err := l.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (l liveReader) ListAccessKeys(ctx context.Context, user string) ([]AccessKey, error) {
	out, err := l.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if err != nil {
		return nil, err
	}
	keys := make([]AccessKey, 0, len(out.AccessKeyMetadata))
	for _, k := range out.AccessKeyMetadata {
		keys = append(keys, AccessKey{ID: aws.ToString(k.AccessKeyId), Active: k.Status == iamtypes.StatusTypeActive})
	}
	return keys, nil
}

func (l liveReader) DescribeSecret(ctx context.Context, arn string) (*SecretInfo, error) {
	c := secretsmanager.NewFromConfig(l.cfg, func(o *secretsmanager.Options) {
		if r := ARNRegion(arn); r != "" {
			o.Region = r
		}
	})
	out, err := c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(arn)})
	if err != nil {
		return nil, err
	}
	info := &SecretInfo{ARN: aws.ToString(out.ARN), Name: aws.ToString(out.Name), RotationEnabled: aws.ToBool(out.RotationEnabled),
		RotationLambdaARN: aws.ToString(out.RotationLambdaARN), LastRotated: out.LastRotatedDate, Tags: map[string]string{}}
	for v, stages := range out.VersionIdsToStages {
		for _, s := range stages {
			switch s {
			case "AWSCURRENT":
				info.CurrentVersion = v
			case "AWSPENDING":
				info.PendingVersion = v
			}
		}
	}
	for _, t := range out.Tags {
		info.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return info, nil
}

// Join makes an Account of a reader and a writer.
func Join(r Reader, w Writer) Account { return joined{r, w} }

type joined struct {
	Reader
	Writer
}
