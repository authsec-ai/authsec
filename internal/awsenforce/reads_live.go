package awsenforce

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// NewLiveDiscoveryIAM is DiscoveryIAM over an IAM client built from the
// connector's discovery-role config (AWSOnboardingService.ConfigForConnector).
// Reads may use the SDK's retries: repeating a read changes nothing. Policy
// documents are returned as IAM sends them (URL-encoded); igagov decodes them
// before canonicalising (igagov.DecodePolicyText).
func NewLiveDiscoveryIAM(c *iam.Client) DiscoveryIAM { return liveDiscovery{c: c} }

type liveDiscovery struct{ c *iam.Client }

func tagMap(tags []iamtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return out
}

func (l liveDiscovery) GetRole(ctx context.Context, roleName string) (*RoleInfo, error) {
	out, err := l.c.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, err
	}
	r := out.Role
	info := &RoleInfo{RoleID: aws.ToString(r.RoleId), ARN: aws.ToString(r.Arn), Name: aws.ToString(r.RoleName),
		Path: aws.ToString(r.Path), Tags: tagMap(r.Tags), TrustDocument: aws.ToString(r.AssumeRolePolicyDocument)}
	if r.PermissionsBoundary != nil {
		info.BoundaryARN = aws.ToString(r.PermissionsBoundary.PermissionsBoundaryArn)
	}
	return info, nil
}

func (l liveDiscovery) ListAttachedRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	var out []string
	pg := iam.NewListAttachedRolePoliciesPaginator(l.c, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.AttachedPolicies {
			out = append(out, aws.ToString(p.PolicyArn))
		}
	}
	return out, nil
}

func (l liveDiscovery) ListRolePolicies(ctx context.Context, roleName string) ([]string, error) {
	var out []string
	pg := iam.NewListRolePoliciesPaginator(l.c, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.PolicyNames...)
	}
	return out, nil
}

func (l liveDiscovery) GetRolePolicy(ctx context.Context, roleName, policyName string) (string, error) {
	out, err := l.c.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(roleName), PolicyName: aws.String(policyName)})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.PolicyDocument), nil
}

func (l liveDiscovery) GetPolicy(ctx context.Context, policyARN string) (*PolicyInfo, error) {
	out, err := l.c.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		return nil, err
	}
	p := out.Policy
	return &PolicyInfo{ARN: aws.ToString(p.Arn), Path: aws.ToString(p.Path), Name: aws.ToString(p.PolicyName),
		Tags: tagMap(p.Tags), DefaultVersionID: aws.ToString(p.DefaultVersionId)}, nil
}

func (l liveDiscovery) GetPolicyVersion(ctx context.Context, policyARN, versionID string) (string, error) {
	out, err := l.c.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: aws.String(versionID)})
	if err != nil {
		return "", err
	}
	if out.PolicyVersion == nil {
		return "", nil
	}
	return aws.ToString(out.PolicyVersion.Document), nil
}

func (l liveDiscovery) ListPolicyVersions(ctx context.Context, policyARN string) ([]PolicyVersionInfo, error) {
	var out []PolicyVersionInfo
	pg := iam.NewListPolicyVersionsPaginator(l.c, &iam.ListPolicyVersionsInput{PolicyArn: aws.String(policyARN)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Versions {
			out = append(out, PolicyVersionInfo{VersionID: aws.ToString(v.VersionId), IsDefault: v.IsDefaultVersion,
				CreateDate: aws.ToTime(v.CreateDate)})
		}
	}
	return out, nil
}

func (l liveDiscovery) ListEntitiesForPolicy(ctx context.Context, policyARN string) ([]igagov.AttachedEntity, error) {
	out := []igagov.AttachedEntity{}
	for _, usage := range []iamtypes.PolicyUsageType{iamtypes.PolicyUsageTypePermissionsPolicy, iamtypes.PolicyUsageTypePermissionsBoundary} {
		u := igagov.UsagePermissions
		if usage == iamtypes.PolicyUsageTypePermissionsBoundary {
			u = igagov.UsageBoundary
		}
		pg := iam.NewListEntitiesForPolicyPaginator(l.c, &iam.ListEntitiesForPolicyInput{
			PolicyArn: aws.String(policyARN), PolicyUsageFilter: usage})
		for pg.HasMorePages() {
			page, err := pg.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, r := range page.PolicyRoles {
				out = append(out, igagov.AttachedEntity{Kind: "role", ID: aws.ToString(r.RoleId), Name: aws.ToString(r.RoleName), Usage: u})
			}
			for _, x := range page.PolicyUsers {
				out = append(out, igagov.AttachedEntity{Kind: "user", ID: aws.ToString(x.UserId), Name: aws.ToString(x.UserName), Usage: u})
			}
			for _, g := range page.PolicyGroups {
				out = append(out, igagov.AttachedEntity{Kind: "group", ID: aws.ToString(g.GroupId), Name: aws.ToString(g.GroupName), Usage: u})
			}
		}
	}
	return out, nil
}
