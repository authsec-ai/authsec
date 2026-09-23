package awsdiscovery

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMGroup is one IAM group with the policies attached to it.
//
// Groups are identities (SPEC §2.2): a user's access through a group is NOT
// copied onto the user -- the path is user -> member_of -> group -> grant ->
// statement. So a group needs its own policies, read like any holder's.
type IAMGroup struct {
	ARN       string
	Name      string
	Path      string
	UniqueID  string // GroupId (AGPA...), the creation boundary
	CreatedAt *time.Time
	Policies  IdentityPolicies
}

// GroupsAndMemberships is what one authorization-details read returned about
// groups: every group, and every user's group list keyed by user ARN, the
// groups named by GROUP ARN.
type GroupsAndMemberships struct {
	Groups []IAMGroup
	// Members maps a user ARN to the ARNs of the groups it belongs to.
	Members map[string][]string
}

// GroupsAndMemberships reads every group (with attached and inline policies)
// and every user's group list, through GetAccountAuthorizationDetails
// filtered to Group and User.
//
// Scoped to what M0 needs: SPEC T3.1 moves roles, users, boundaries and
// customer-managed documents onto this same call and retires the per-role
// reads; that is S3 work. Groups had NO read at all before this -- no API call
// and no identity kind -- which left every policy partition unable to close,
// because they require iam_groups (§4.10).
//
// Attached managed policy documents come from managedPolicy's cache, so a
// policy attached to a role and a group is fetched once, and a document that
// cannot be read is recorded on the policy rather than failing the group.
// Inline group documents arrive in the response and need no second call.
func (r *IAMReader) GroupsAndMemberships(ctx context.Context) (GroupsAndMemberships, error) {
	out := GroupsAndMemberships{Members: map[string][]string{}}
	groupARNByName := map[string]string{}
	userGroupNames := map[string][]string{}

	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: authorization details", errTooManyPages)
		}
		resp, err := r.api.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Filter:   []iamtypes.EntityType{iamtypes.EntityTypeGroup, iamtypes.EntityTypeUser},
			MaxItems: aws.Int32(listPageLimit),
			Marker:   marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, g := range resp.GroupDetailList {
			group := IAMGroup{
				ARN:       aws.ToString(g.Arn),
				Name:      aws.ToString(g.GroupName),
				Path:      aws.ToString(g.Path),
				UniqueID:  aws.ToString(g.GroupId),
				CreatedAt: g.CreateDate,
			}
			group.Policies = IdentityPolicies{IdentityARN: group.ARN, IdentityName: group.Name}
			for _, ap := range g.AttachedManagedPolicies {
				group.Policies.Attached = append(group.Policies.Attached,
					r.managedPolicy(ctx, aws.ToString(ap.PolicyArn), aws.ToString(ap.PolicyName)))
			}
			for _, ip := range g.GroupPolicyList {
				group.Policies.Inline = append(group.Policies.Inline, InlinePolicy{
					Name:     aws.ToString(ip.PolicyName),
					Document: decodePolicyDocument(ip.PolicyDocument),
				})
			}
			groupARNByName[group.Name] = group.ARN
			out.Groups = append(out.Groups, group)
		}
		for _, u := range resp.UserDetailList {
			userGroupNames[aws.ToString(u.Arn)] = append(userGroupNames[aws.ToString(u.Arn)], u.GroupList...)
		}
		if !resp.IsTruncated || resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}

	// UserDetail.GroupList names groups by NAME. Resolve to ARNs from the same
	// read, so a membership never points at a group this read did not list.
	for userARN, names := range userGroupNames {
		for _, n := range names {
			if arn, ok := groupARNByName[n]; ok {
				out.Members[userARN] = append(out.Members[userARN], arn)
			}
		}
	}
	return out, nil
}
