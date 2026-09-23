package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The IAM read surface: roles, users, access keys and the policy documents
// attached to each identity.
//
// This file knows AWS and nothing about AuthSec. It returns normalised structs;
// deciding what to persist, how to reconcile and what a partial read means is
// the scanner's job in services/cloud_aws_iam_scan.go.

// IAMAPI is the slice of the IAM client this package uses.
//
// Narrow on purpose. *iam.Client satisfies it, and so does a fake, which is how
// the scanner is tested without an AWS account. Listing the operations
// explicitly also makes the permission surface auditable: what is not in this
// interface cannot be called, so the CloudFormation template and this list can
// be compared by eye.
type IAMAPI interface {
	ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GetRole(ctx context.Context, in *iam.GetRoleInput, opts ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListUsers(ctx context.Context, in *iam.ListUsersInput, opts ...func(*iam.Options)) (*iam.ListUsersOutput, error)

	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, opts ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)

	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, in *iam.GetRolePolicyInput, opts ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)

	ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, in *iam.GetUserPolicyInput, opts ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)

	GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)

	// ListOpenIDConnectProviders is ticket [2]'s addition: the account's OIDC
	// providers, as join targets for IRSA and the EKS identity edge.
	ListOpenIDConnectProviders(ctx context.Context, in *iam.ListOpenIDConnectProvidersInput, opts ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)

	// GetAccountAuthorizationDetails reads groups and user group memberships
	// (authdetails.go). Already granted by the role template; the SPEC's T3.1
	// moves the whole IAM read onto it.
	GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, opts ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
}

// NewIAMClient builds a real IAM client from an assumed-role config.
//
// IAM is a global service: every call goes to one endpoint regardless of which
// regions the operator selected. Nothing in this file loops over regions, and
// nothing should.
func NewIAMClient(cfg aws.Config) IAMAPI { return iam.NewFromConfig(cfg) }

// listPageLimit bounds one page. 1000 is IAM's own maximum for these calls;
// asking for it minimises round trips on a large account.
const listPageLimit int32 = 1000

// maxPages bounds a paginated read.
//
// IAM will happily page forever if a marker is echoed back unchanged by a
// broken proxy or an emulator, and an unbounded loop in a scan is an outage
// rather than a bug. At 1000 per page this ceiling is far above any real
// account, so hitting it means something is wrong and the scan should say so
// rather than spin.
const maxPages = 200

var errTooManyPages = errors.New("pagination did not terminate")

/* ------------------------------ normalised types --------------------------- */

// IAMRole is one role, with the detail only GetRole returns.
type IAMRole struct {
	ARN                string
	Name               string
	Path               string
	UniqueID           string
	Description        string
	CreatedAt          *time.Time
	LastUsedAt         *time.Time
	MaxSessionDuration int32
	Tags               map[string]string
	// PermissionsBoundaryARN is the managed policy that caps this role's
	// effective permissions, or "" when none is attached.
	//
	// A boundary does not grant anything; it is a ceiling. A role whose
	// policies allow dynamodb:PutItem but whose boundary denies it cannot do
	// it, so reporting the grant without the boundary over-states access. The
	// field is already in the GetRole response -- it was simply discarded.
	PermissionsBoundaryARN string
	// DetailComplete records whether GetRole succeeded for this role.
	//
	// False means only the ListRoles summary was available: last-used, tags and
	// the permissions boundary are UNKNOWN, not absent. A writer must not treat
	// a partial role as authoritative and overwrite metadata an earlier
	// complete read established -- that turns a transient throttle into
	// permanent data loss, and hides a missing boundary.
	DetailComplete bool
	// TrustPolicy is the decoded AssumeRolePolicyDocument. Retrieved here but
	// NOT parsed and NOT persisted by ticket [1] — it is the input ticket [2]
	// turns into cloud_assume_edge rows.
	TrustPolicy string
}

// IAMUser is one user.
type IAMUser struct {
	ARN              string
	Name             string
	Path             string
	UniqueID         string
	CreatedAt        *time.Time
	PasswordLastUsed *time.Time
}

// IAMAccessKey is one long-lived programmatic key. The key id only — this
// struct has no field that could hold the secret, and the API never returns it
// after creation anyway.
type IAMAccessKey struct {
	KeyID     string
	UserName  string
	Status    string
	CreatedAt *time.Time
	// LastUsedAt is nil when AWS reports the key has never been used. Callers
	// must keep that as unknown rather than coercing it to a zero time.
	LastUsedAt *time.Time
}

// AttachedPolicy is a managed policy and the document of its default version.
type AttachedPolicy struct {
	Name      string
	ARN       string
	VersionID string
	// PolicyID is AWS's PolicyId (ANPA...) from GetPolicy: the policy's
	// CREATION BOUNDARY. A customer-managed policy deleted and recreated under
	// the same ARN has a new one, and every graph key below the policy is
	// built from it (SPEC §2.4). It was in the GetPolicy response all along,
	// and was discarded.
	PolicyID string
	Document string
	// FetchError is non-empty when this policy could not be read this run:
	// "fetch: <reason>". PER-DOCUMENT ISOLATION (§1.4): one unreadable policy
	// is recorded on that policy and the scan continues -- it used to abort
	// every policy of the identity, and then the whole permission scan.
	FetchError string
	// AWSManaged distinguishes an AWS-owned policy from a customer-owned one.
	// Ticket [2] weighs them differently: a customer-authored policy is a local
	// decision, an AWS-managed one is a well-known grant.
	AWSManaged bool
}

// InlinePolicy is a policy defined directly on the identity.
type InlinePolicy struct {
	Name     string
	Document string
	// FetchError: as AttachedPolicy.FetchError.
	FetchError string
}

// IdentityPolicies is everything attached to one identity.
type IdentityPolicies struct {
	IdentityARN  string
	IdentityName string
	Attached     []AttachedPolicy
	Inline       []InlinePolicy
	// Boundary is the permissions-boundary policy document, when the identity
	// has one. It is NOT an attached policy and must never be merged into
	// Attached: those grant, this one caps. Nil when no boundary is set.
	Boundary *AttachedPolicy
}

// OIDCProvider is one OIDC identity provider registered in the account -- a
// join target for IRSA and, in the EKS ticket, for the pod identity edge.
type OIDCProvider struct {
	ARN string
	// Issuer is the host portion only, no scheme: the ARN suffix after
	// "oidc-provider/" already omits it, and that suffix IS the issuer AWS
	// matches a trust policy's Federated principal against. There is no second
	// call to make here -- ListOpenIDConnectProviders returns only ARNs, but
	// for this provider the ARN already contains everything the join needs.
	Issuer string
}

/* --------------------------------- reads ---------------------------------- */

// IAMReader performs the paginated reads and caches managed policy documents.
type IAMReader struct {
	api IAMAPI
	// policyCache is keyed by policy ARN. AWS-managed policies are attached to
	// many roles, and ReadOnlyAccess alone is a six-figure JSON document — a
	// hundred roles sharing it would otherwise mean a hundred identical fetches.
	policyCache map[string]AttachedPolicy
}

// NewIAMReader constructs a reader over the given API.
func NewIAMReader(api IAMAPI) *IAMReader {
	return &IAMReader{api: api, policyCache: map[string]AttachedPolicy{}}
}

// ListRoles reads every role, then fetches the per-role detail.
//
// Two calls per role is what the ticket specifies, and it is not avoidable with
// these operations: ListRoles returns neither RoleLastUsed nor tags, and both
// matter — the first is liveness without CloudTrail, the second is the only
// ownership hint available at this stage.
//
// iam:GetAccountAuthorizationDetails would return roles, users and every policy
// document in one paginated call. The template already grants it. Comparing the
// two on a real account is an open item in the AWS plan; this implementation is
// the one the ticket asks for, and the shape of the rows is identical either
// way, so switching later is a change to this function alone.
func (r *IAMReader) ListRoles(ctx context.Context) ([]IAMRole, error) {
	var out []IAMRole
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: roles", errTooManyPages)
		}
		resp, err := r.api.ListRoles(ctx, &iam.ListRolesInput{
			MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, role := range resp.Roles {
			out = append(out, r.roleDetail(ctx, role))
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
}

// roleDetail enriches a listed role with GetRole.
//
// A failure here degrades one role rather than failing the scan: the role
// itself was listed, so we know it exists, and recording it without its
// last-used date is strictly better than pretending it is not there. The
// summary from ListRoles is kept as the fallback.
func (r *IAMReader) roleDetail(ctx context.Context, role iamtypes.Role) IAMRole {
	built := IAMRole{
		ARN:         aws.ToString(role.Arn),
		Name:        aws.ToString(role.RoleName),
		Path:        aws.ToString(role.Path),
		UniqueID:    aws.ToString(role.RoleId),
		Description: aws.ToString(role.Description),
		CreatedAt:   role.CreateDate,
		TrustPolicy: decodePolicyDocument(role.AssumeRolePolicyDocument),
	}
	if role.MaxSessionDuration != nil {
		built.MaxSessionDuration = *role.MaxSessionDuration
	}

	detail, err := r.api.GetRole(ctx, &iam.GetRoleInput{RoleName: role.RoleName})
	if err != nil || detail.Role == nil {
		// DetailComplete stays false: the caller must record this role as
		// partially collected rather than writing its gaps as facts.
		return built
	}
	d := detail.Role
	if d.RoleLastUsed != nil {
		built.LastUsedAt = d.RoleLastUsed.LastUsedDate
	}
	if doc := decodePolicyDocument(d.AssumeRolePolicyDocument); doc != "" {
		built.TrustPolicy = doc
	}
	if d.Description != nil {
		built.Description = *d.Description
	}
	if d.MaxSessionDuration != nil {
		built.MaxSessionDuration = *d.MaxSessionDuration
	}
	built.Tags = tagMap(d.Tags)
	if d.PermissionsBoundary != nil {
		built.PermissionsBoundaryARN = aws.ToString(d.PermissionsBoundary.PermissionsBoundaryArn)
	}
	built.DetailComplete = true
	return built
}

// ListUsers reads every user.
func (r *IAMReader) ListUsers(ctx context.Context) ([]IAMUser, error) {
	var out []IAMUser
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: users", errTooManyPages)
		}
		resp, err := r.api.ListUsers(ctx, &iam.ListUsersInput{
			MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, u := range resp.Users {
			out = append(out, IAMUser{
				ARN:              aws.ToString(u.Arn),
				Name:             aws.ToString(u.UserName),
				Path:             aws.ToString(u.Path),
				UniqueID:         aws.ToString(u.UserId),
				CreatedAt:        u.CreateDate,
				PasswordLastUsed: u.PasswordLastUsed,
			})
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
}

// OIDCProviders reads the account's registered OIDC identity providers.
//
// No pagination: the API returns the full list in one call, and an account
// with hundreds of these would be a novelty, not a scan concern.
func (r *IAMReader) OIDCProviders(ctx context.Context) ([]OIDCProvider, error) {
	resp, err := r.api.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, classify(err)
	}
	out := make([]OIDCProvider, 0, len(resp.OpenIDConnectProviderList))
	for _, p := range resp.OpenIDConnectProviderList {
		arn := aws.ToString(p.Arn)
		out = append(out, OIDCProvider{ARN: arn, Issuer: oidcIssuerFromARN(arn)})
	}
	return out, nil
}

// oidcIssuerFromARN extracts the issuer host from an OIDC provider ARN:
// arn:<partition>:iam::<account>:oidc-provider/<issuer, no scheme>.
// Returns "" for anything that does not match, rather than a malformed guess.
func oidcIssuerFromARN(arn string) string {
	const marker = ":oidc-provider/"
	i := strings.Index(arn, marker)
	if i < 0 {
		return ""
	}
	return arn[i+len(marker):]
}

// ListAccessKeys reads one user's keys and their last-used dates.
//
// GetAccessKeyLastUsed is a second call per key. It is the only source of the
// date, and the date is the entire point of recording a key: an active key
// nobody has used in two years is the finding.
func (r *IAMReader) ListAccessKeys(ctx context.Context, userName string) ([]IAMAccessKey, error) {
	var out []IAMAccessKey
	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: access keys for %s", errTooManyPages, userName)
		}
		resp, err := r.api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: aws.String(userName), MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, k := range resp.AccessKeyMetadata {
			key := IAMAccessKey{
				KeyID:     aws.ToString(k.AccessKeyId),
				UserName:  aws.ToString(k.UserName),
				Status:    string(k.Status),
				CreatedAt: k.CreateDate,
			}
			if key.UserName == "" {
				key.UserName = userName
			}
			// A failure to read the last-used date leaves it nil, which means
			// unknown — the honest answer. It must never become a zero time,
			// which would read as "used at the epoch".
			if lu, err := r.api.GetAccessKeyLastUsed(ctx,
				&iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId}); err == nil &&
				lu.AccessKeyLastUsed != nil {
				key.LastUsedAt = lu.AccessKeyLastUsed.LastUsedDate
			}
			out = append(out, key)
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
}

// BoundaryPolicy reads the document of a permissions-boundary policy.
//
// A boundary is an ordinary managed policy used in a non-granting position, so
// the read is the same two calls; what differs is how the caller must record
// the result.
func (r *IAMReader) BoundaryPolicy(ctx context.Context, boundaryARN string) (AttachedPolicy, error) {
	p := r.managedPolicy(ctx, boundaryARN, boundaryPolicyName(boundaryARN))
	if p.FetchError != "" {
		// The caller still learns it failed: the identity keeps
		// constraint_state 'bounded' from the ARN alone, and the policy row
		// records the error.
		return p, fmt.Errorf("boundary %s: %s", boundaryARN, p.FetchError)
	}
	return p, nil
}

// boundaryPolicyName recovers the policy name from its ARN. The boundary is
// reported as an ARN only, and managedPolicy wants a name for its error text.
func boundaryPolicyName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return arn
}

// RolePolicies reads the managed and inline policies attached to a role.
func (r *IAMReader) RolePolicies(ctx context.Context, roleARN, roleName string) (IdentityPolicies, error) {
	out := IdentityPolicies{IdentityARN: roleARN, IdentityName: roleName}

	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: attached policies for %s", errTooManyPages, roleName)
		}
		resp, err := r.api.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName), MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, p := range resp.AttachedPolicies {
			// Never fails the identity: an unreadable document is recorded on
			// the policy (FetchError) and the attachment is still listed.
			out.Attached = append(out.Attached,
				r.managedPolicy(ctx, aws.ToString(p.PolicyArn), aws.ToString(p.PolicyName)))
		}
		if !resp.IsTruncated || resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}

	marker = nil
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: inline policies for %s", errTooManyPages, roleName)
		}
		resp, err := r.api.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: aws.String(roleName), MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, name := range resp.PolicyNames {
			doc, err := r.api.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName: aws.String(roleName), PolicyName: aws.String(name),
			})
			if err != nil {
				out.Inline = append(out.Inline, InlinePolicy{
					Name: name, FetchError: "fetch: " + classify(err).Error(),
				})
				continue
			}
			out.Inline = append(out.Inline, InlinePolicy{
				Name: name, Document: decodePolicyDocument(doc.PolicyDocument),
			})
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
}

// UserPolicies reads the managed and inline policies attached to a user.
func (r *IAMReader) UserPolicies(ctx context.Context, userARN, userName string) (IdentityPolicies, error) {
	out := IdentityPolicies{IdentityARN: userARN, IdentityName: userName}

	var marker *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: attached policies for %s", errTooManyPages, userName)
		}
		resp, err := r.api.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(userName), MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, p := range resp.AttachedPolicies {
			// Never fails the identity: an unreadable document is recorded on
			// the policy (FetchError) and the attachment is still listed.
			out.Attached = append(out.Attached,
				r.managedPolicy(ctx, aws.ToString(p.PolicyArn), aws.ToString(p.PolicyName)))
		}
		if !resp.IsTruncated || resp.Marker == nil {
			break
		}
		marker = resp.Marker
	}

	marker = nil
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: inline policies for %s", errTooManyPages, userName)
		}
		resp, err := r.api.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: aws.String(userName), MaxItems: aws.Int32(listPageLimit), Marker: marker,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, name := range resp.PolicyNames {
			doc, err := r.api.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName: aws.String(userName), PolicyName: aws.String(name),
			})
			if err != nil {
				out.Inline = append(out.Inline, InlinePolicy{
					Name: name, FetchError: "fetch: " + classify(err).Error(),
				})
				continue
			}
			out.Inline = append(out.Inline, InlinePolicy{
				Name: name, Document: decodePolicyDocument(doc.PolicyDocument),
			})
		}
		if !resp.IsTruncated || resp.Marker == nil {
			return out, nil
		}
		marker = resp.Marker
	}
}

// managedPolicy fetches a managed policy's default version, through the cache.
//
// Two calls per policy: GetPolicy names the default version (and gives the
// PolicyId), GetPolicyVersion returns the document. There is no single call
// that does both.
//
// It NEVER fails its caller. A failure is recorded on the returned policy as
// FetchError and cached with it, so every holder of that policy in this scan
// sees the same answer -- one row per connector per run, one state.
func (r *IAMReader) managedPolicy(ctx context.Context, policyARN, policyName string) AttachedPolicy {
	if cached, ok := r.policyCache[policyARN]; ok {
		return cached
	}
	built := AttachedPolicy{
		Name:       policyName,
		ARN:        policyARN,
		AWSManaged: isAWSManagedPolicyARN(policyARN),
	}
	defer func() { r.policyCache[policyARN] = built }()

	meta, err := r.api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		built.FetchError = "fetch: " + classify(err).Error()
		return built
	}
	if meta.Policy != nil {
		built.VersionID = aws.ToString(meta.Policy.DefaultVersionId)
		built.PolicyID = aws.ToString(meta.Policy.PolicyId)
		if built.Name == "" {
			built.Name = aws.ToString(meta.Policy.PolicyName)
		}
	}
	if built.VersionID == "" {
		built.FetchError = "fetch: GetPolicy returned no default version"
		return built
	}
	ver, err := r.api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN), VersionId: aws.String(built.VersionID),
	})
	if err != nil {
		built.FetchError = "fetch: " + classify(err).Error()
		return built
	}
	if ver.PolicyVersion != nil {
		built.Document = decodePolicyDocument(ver.PolicyVersion.Document)
	}
	return built
}

/* -------------------------------- helpers --------------------------------- */

// decodePolicyDocument URL-decodes an IAM policy document.
//
// IAM returns every policy document — trust policies, inline policies, managed
// policy versions — URL-ENCODED. Handing the raw string to a JSON parser fails
// on the first "%7B", so the decode has to happen here rather than being
// rediscovered by every consumer. If the decode fails the original is returned:
// some emulators and older responses are already plain, and a document we
// cannot decode is still better than an empty one.
func decodePolicyDocument(doc *string) string {
	if doc == nil || *doc == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(*doc)
	if err != nil {
		return *doc
	}
	return decoded
}

// isAWSManagedPolicyARN reports whether a policy is AWS-owned. AWS-managed
// policies live in the pseudo-account "aws":
// arn:aws:iam::aws:policy/ReadOnlyAccess.
func isAWSManagedPolicyARN(arn string) bool {
	_, account, err := parsePolicyARN(arn)
	return err == nil && account == "aws"
}

func parsePolicyARN(arn string) (partition, account string, err error) {
	// arn:<partition>:iam::<account>:policy/<name>
	const prefix = "arn:"
	if len(arn) < len(prefix) || arn[:len(prefix)] != prefix {
		return "", "", fmt.Errorf("%q is not an ARN", arn)
	}
	parts := splitN(arn, ':', 6)
	if len(parts) < 6 {
		return "", "", fmt.Errorf("%q is not a policy ARN", arn)
	}
	return parts[1], parts[4], nil
}

func splitN(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func tagMap(tags []iamtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return out
}
