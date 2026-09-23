package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// The whole IAM configuration read (SPEC-iga-phase2-graph.md §1.4, T3.1):
// iam:GetAccountAuthorizationDetails, ONE PAGINATED CALL PER FILTER
// (P2-DECISIONS D-48) -- Role, User, Group, LocalManagedPolicy -- replacing
// ListRoles + GetRole per role, ListUsers, and the three-call-per-identity
// policy reads that dominated a scan of a large account.
//
// One call per filter, rather than one call naming all four, because each
// listing is its own coverage surface (iam_roles, iam_users, iam_groups,
// iam_policies): a throttle on page 40 of the users must leave the roles
// reached, and coverage must be able to say "AWS returned Throttling for
// iam:GetAccountAuthorizationDetails (Users)" rather than blame every surface.
//
// The only per-policy calls left are GetPolicy + GetPolicyVersion for each
// AWS-MANAGED policy attached to a role, user or group or set as a
// permissions boundary (D-50), cached per scan (managedPolicy): AWS-managed
// policies are not in the LocalManagedPolicy listing, and asking for the
// AWSManagedPolicy filter would return all ~1000 of them, attached or not.

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

// AuthorizationDetails is what the four listings returned, resolved: every
// principal with its attachments, inline documents and boundary, and every
// managed policy document those name.
type AuthorizationDetails struct {
	Roles  []IAMRole
	Users  []IAMUser
	Groups []IAMGroup

	// ManagedPolicies is every managed policy this read knows, by ARN, exactly
	// once: every customer-managed policy the LocalManagedPolicy listing
	// returned -- ATTACHED OR NOT (§2.15: a detached policy is still a policy in
	// the account and keeps its row) -- and every AWS-managed policy attached
	// to, or set as the boundary of, a principal. One entry per ARN is one
	// cloud_policy row per connector per run, with one state.
	ManagedPolicies map[string]AttachedPolicy

	// Members maps a user ARN to the ARNs of the groups it belongs to, resolved
	// from the user's GroupList (names) against THIS read's Group listing. A
	// name the Group listing did not return is dropped, never guessed into an
	// ARN: a group's ARN carries its path, which the name does not.
	Members map[string][]string

	// The outcome of each listing: nil when it ran to its last page. On an
	// error, what the pages before it returned is still here -- real rows, a
	// floor rather than a total -- and the surface must say so.
	RolesErr, UsersErr, GroupsErr, PoliciesErr error
}

// Authorization-details filters and the names coverage uses for them. The
// label is what an operator reads in "AWS returned AccessDenied for
// iam:GetAccountAuthorizationDetails (Users)" (§2.14.13).
var authDetailsFilters = map[iamtypes.EntityType]string{
	iamtypes.EntityTypeRole:               "Roles",
	iamtypes.EntityTypeUser:               "Users",
	iamtypes.EntityTypeGroup:              "Groups",
	iamtypes.EntityTypeLocalManagedPolicy: "LocalManagedPolicy",
}

// authDetailsCall names one filter's listing as coverage reports it.
func authDetailsCall(filter iamtypes.EntityType) string {
	return "iam:GetAccountAuthorizationDetails (" + authDetailsFilters[filter] + ")"
}

// AuthorizationDetails performs the four listings and resolves every
// attachment against them.
//
// It never fails as a whole: each listing's outcome is recorded on its own
// field, and one policy document that cannot be read is recorded on that
// policy (FetchError), never on the listing that named it (§1.4: "a failure to
// fetch one policy's document does not make it partial").
//
// Order matters twice. LocalManagedPolicy first, so a customer-managed
// attachment resolves to the document that listing carried rather than to a
// second fetch. Group before User, so a user's group NAMES resolve to ARNs
// from the same read.
func (r *IAMReader) AuthorizationDetails(ctx context.Context) AuthorizationDetails {
	out := AuthorizationDetails{
		ManagedPolicies: map[string]AttachedPolicy{},
		Members:         map[string][]string{},
	}

	// ---- customer-managed policies, attached or not -------------------------
	out.PoliciesErr = r.listAuthDetails(ctx, iamtypes.EntityTypeLocalManagedPolicy,
		func(page *iam.GetAccountAuthorizationDetailsOutput) {
			for _, p := range page.Policies {
				lp := localManagedPolicy(p)
				out.ManagedPolicies[lp.ARN] = lp
			}
		})

	// ---- groups ------------------------------------------------------------
	var groups []iamtypes.GroupDetail
	out.GroupsErr = r.listAuthDetails(ctx, iamtypes.EntityTypeGroup,
		func(page *iam.GetAccountAuthorizationDetailsOutput) {
			groups = append(groups, page.GroupDetailList...)
		})
	groupARNByName := make(map[string]string, len(groups))
	for _, g := range groups {
		group := IAMGroup{
			ARN:       aws.ToString(g.Arn),
			Name:      aws.ToString(g.GroupName),
			Path:      aws.ToString(g.Path),
			UniqueID:  aws.ToString(g.GroupId),
			CreatedAt: g.CreateDate,
		}
		group.Policies = r.principalPolicies(ctx, &out, group.ARN, group.Name,
			g.AttachedManagedPolicies, g.GroupPolicyList, nil)
		groupARNByName[group.Name] = group.ARN
		out.Groups = append(out.Groups, group)
	}

	// ---- roles -------------------------------------------------------------
	var roles []iamtypes.RoleDetail
	out.RolesErr = r.listAuthDetails(ctx, iamtypes.EntityTypeRole,
		func(page *iam.GetAccountAuthorizationDetailsOutput) {
			roles = append(roles, page.RoleDetailList...)
		})
	for _, d := range roles {
		role := IAMRole{
			ARN:                    aws.ToString(d.Arn),
			Name:                   aws.ToString(d.RoleName),
			Path:                   aws.ToString(d.Path),
			UniqueID:               aws.ToString(d.RoleId),
			CreatedAt:              d.CreateDate,
			Tags:                   tagMap(d.Tags),
			PermissionsBoundaryARN: boundaryARN(d.PermissionsBoundary),
			TrustPolicy:            decodePolicyDocument(d.AssumeRolePolicyDocument),
		}
		if d.RoleLastUsed != nil {
			role.LastUsedAt = d.RoleLastUsed.LastUsedDate
		}
		for _, ip := range d.InstanceProfileList {
			role.InstanceProfileARNs = append(role.InstanceProfileARNs, aws.ToString(ip.Arn))
		}
		role.Policies = r.principalPolicies(ctx, &out, role.ARN, role.Name,
			d.AttachedManagedPolicies, d.RolePolicyList, d.PermissionsBoundary)
		out.Roles = append(out.Roles, role)
	}

	// ---- users -------------------------------------------------------------
	var users []iamtypes.UserDetail
	out.UsersErr = r.listAuthDetails(ctx, iamtypes.EntityTypeUser,
		func(page *iam.GetAccountAuthorizationDetailsOutput) {
			users = append(users, page.UserDetailList...)
		})
	for _, d := range users {
		user := IAMUser{
			ARN:       aws.ToString(d.Arn),
			Name:      aws.ToString(d.UserName),
			Path:      aws.ToString(d.Path),
			UniqueID:  aws.ToString(d.UserId),
			CreatedAt: d.CreateDate,
			Tags:      tagMap(d.Tags),
			// Users' boundaries were never read before this (§1.3): every user
			// statement was stored unconstrained.
			PermissionsBoundaryARN: boundaryARN(d.PermissionsBoundary),
			GroupNames:             append([]string(nil), d.GroupList...),
		}
		user.Policies = r.principalPolicies(ctx, &out, user.ARN, user.Name,
			d.AttachedManagedPolicies, d.UserPolicyList, d.PermissionsBoundary)
		for _, n := range d.GroupList {
			if arn, ok := groupARNByName[n]; ok {
				out.Members[user.ARN] = append(out.Members[user.ARN], arn)
			}
		}
		out.Users = append(out.Users, user)
	}
	return out
}

// listAuthDetails pages through ONE filter's listing, handing each page to
// `each` as it arrives, so the pages before a failure are kept.
func (r *IAMReader) listAuthDetails(
	ctx context.Context, filter iamtypes.EntityType,
	each func(*iam.GetAccountAuthorizationDetailsOutput),
) error {
	api := authDetailsCall(filter)
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return fmt.Errorf("%w: %s", errTooManyPages, api)
		}
		resp, err := r.api.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Filter:   []iamtypes.EntityType{filter},
			MaxItems: aws.Int32(listPageLimit),
			Marker:   marker,
		})
		if err != nil {
			return callError(api, err)
		}
		each(resp)
		if !resp.IsTruncated || resp.Marker == nil {
			return nil
		}
		marker = resp.Marker
	}
}

// principalPolicies resolves one principal's attachments, inline documents
// and boundary.
//
// Inline documents arrive in the listing itself (URL-encoded), so they need
// no call and cannot fail to fetch -- only to parse, which the collector
// decides (PolicyDocumentError). Attached and boundary policies resolve
// through resolveManaged, which never fails its caller.
func (r *IAMReader) principalPolicies(
	ctx context.Context, out *AuthorizationDetails, arn, name string,
	attached []iamtypes.AttachedPolicy, inline []iamtypes.PolicyDetail,
	boundary *iamtypes.AttachedPermissionsBoundary,
) IdentityPolicies {
	pol := IdentityPolicies{IdentityARN: arn, IdentityName: name}
	for _, ap := range attached {
		pol.Attached = append(pol.Attached,
			r.resolveManaged(ctx, out, aws.ToString(ap.PolicyArn), aws.ToString(ap.PolicyName)))
	}
	for _, ip := range inline {
		pol.Inline = append(pol.Inline, InlinePolicy{
			Name:     aws.ToString(ip.PolicyName),
			Document: decodePolicyDocument(ip.PolicyDocument),
		})
	}
	// A boundary is an ordinary managed policy in a non-granting position: the
	// same resolution, recorded by the caller as kind 'boundary'. It is NEVER
	// merged into Attached -- those grant, this one caps.
	if b := boundaryARN(boundary); b != "" {
		p := r.resolveManaged(ctx, out, b, "")
		pol.Boundary = &p
	}
	return pol
}

// resolveManaged returns the managed policy an attachment names.
//
//   - Customer-managed: the LocalManagedPolicy listing's own entry, document
//     included. No GetPolicy/GetPolicyVersion is made for it.
//   - AWS-managed, attached or a boundary (D-50): GetPolicy + GetPolicyVersion
//     through the per-scan cache.
//   - Customer-managed but NOT in the listing -- the listing failed, or the
//     policy appeared between two non-transactional calls -- is recorded
//     UNREADABLE with the reason. Never guessed at, and never a reason to
//     drop the attachment, which this principal's own entry does prove.
func (r *IAMReader) resolveManaged(ctx context.Context, out *AuthorizationDetails, arn, name string) AttachedPolicy {
	if p, ok := out.ManagedPolicies[arn]; ok {
		return p
	}
	var p AttachedPolicy
	switch {
	case isAWSManagedPolicyARN(arn):
		p = r.managedPolicy(ctx, arn, name)
	default:
		if name == "" {
			name = boundaryPolicyName(arn)
		}
		p = AttachedPolicy{Name: name, ARN: arn}
		api := authDetailsCall(iamtypes.EntityTypeLocalManagedPolicy)
		if out.PoliciesErr != nil {
			p.FetchError = "fetch: " + out.PoliciesErr.Error()
		} else {
			p.FetchError = "fetch: attached but absent from the " + api + " listing"
		}
	}
	if p.Name == "" {
		p.Name = boundaryPolicyName(arn)
	}
	out.ManagedPolicies[arn] = p
	return p
}

// localManagedPolicy reads one LocalManagedPolicy entry: its PolicyId (the
// creation boundary, §2.4), and the document of its DEFAULT version only
// (§2.6: "only the default version is read"). The listing carries every
// version; a non-default one is ignored.
func localManagedPolicy(d iamtypes.ManagedPolicyDetail) AttachedPolicy {
	p := AttachedPolicy{
		Name:      aws.ToString(d.PolicyName),
		ARN:       aws.ToString(d.Arn),
		PolicyID:  aws.ToString(d.PolicyId),
		VersionID: aws.ToString(d.DefaultVersionId),
	}
	// DefaultVersionId names the version; IsDefaultVersion is the fallback
	// for an entry that omits it. Either way exactly one version is read.
	pick := -1
	for i, v := range d.PolicyVersionList {
		if p.VersionID != "" && aws.ToString(v.VersionId) == p.VersionID {
			pick = i
			break
		}
		if pick < 0 && v.IsDefaultVersion {
			pick = i
		}
	}
	if pick >= 0 {
		v := d.PolicyVersionList[pick]
		p.VersionID = aws.ToString(v.VersionId)
		p.Document = decodePolicyDocument(v.Document)
		return p
	}
	// Listed without its default version's document: known to exist, not
	// read. Unreadable, so what it declared goes stale rather than ending.
	p.FetchError = "fetch: " + authDetailsCall(iamtypes.EntityTypeLocalManagedPolicy) +
		" returned no default version document"
	return p
}

func boundaryARN(b *iamtypes.AttachedPermissionsBoundary) string {
	if b == nil {
		return ""
	}
	return aws.ToString(b.PermissionsBoundaryArn)
}

/* ------------------------------- call errors ------------------------------ */

// APICallError is one AWS call that failed, naming the call and the error code
// AWS returned. §2.14.13: "name the call, not a guess at the fix" -- an
// AccessDenied says which call failed, not which permission is missing, so
// this never says which permission to grant.
//
// It unwraps to BOTH the classified sentinel (errors.Is(err, ErrThrottled)
// still decides throttled versus denied) and the SDK's own error
// (errors.As(err, &smithy.APIError) still recovers the code).
type APICallError struct {
	// API is the call, as an operator would search for it:
	// "iam:GetPolicyVersion", "iam:GetAccountAuthorizationDetails (Users)".
	API string
	// Code is AWS's error code ("AccessDenied", "Throttling"); "" when the
	// failure was not an AWS response (a timeout, a closed connection).
	Code    string
	Message string

	classified error
	cause      error
}

func (e *APICallError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("%s failed: %s", e.API, e.Message)
	}
	return fmt.Sprintf("AWS returned %s for %s: %s", e.Code, e.API, e.Message)
}

// Unwrap exposes the classified sentinel and the SDK error.
func (e *APICallError) Unwrap() []error { return []error{e.classified, e.cause} }

// callError wraps a failed call. The message is AWS's own words, never
// classify()'s "the role could not be assumed", which is true of STS and
// misleading for every IAM read.
func callError(api string, err error) error {
	if err == nil {
		return nil
	}
	e := &APICallError{API: api, classified: classify(err), cause: err, Message: err.Error()}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		e.Code = apiErr.ErrorCode()
		e.Message = apiErr.ErrorMessage()
	}
	return e
}
