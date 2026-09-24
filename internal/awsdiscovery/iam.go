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

// The IAM read surface: access keys, OIDC providers, AWS-managed policy
// documents, and the helpers the authorization-details read (authdetails.go)
// shares. Roles, users, groups and customer-managed policies are read there.
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
	// GetAccountAuthorizationDetails is the whole IAM configuration read: roles,
	// users, groups and customer-managed policies, one paginated call per filter
	// (authdetails.go, SPEC T3.1). It replaced ListRoles, GetRole, ListUsers and
	// the per-identity List*Policies / Get*Policy calls, which are deliberately
	// no longer here: what is not in this interface cannot be called.
	GetAccountAuthorizationDetails(ctx context.Context, in *iam.GetAccountAuthorizationDetailsInput, opts ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)

	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, opts ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)

	// GetPolicy and GetPolicyVersion read AWS-MANAGED policies only -- those
	// attached to a principal or set as a boundary (§1.4, D-50). A
	// customer-managed document comes from the LocalManagedPolicy listing.
	GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)

	// ListOpenIDConnectProviders is ticket [2]'s addition: the account's OIDC
	// providers, as join targets for IRSA and the EKS identity edge.
	ListOpenIDConnectProviders(ctx context.Context, in *iam.ListOpenIDConnectProvidersInput, opts ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error)
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

// IAMRole is one role as its authorization-details entry (RoleDetail)
// returned it.
//
// There is no MaxSessionDuration and no Description here: RoleDetail does not
// carry them, and there is no per-role call left to fetch them. The scanner
// keeps what an earlier read stored for those two (D-48: merged, never
// blanked) rather than writing their absence as a fact.
type IAMRole struct {
	ARN        string
	Name       string
	Path       string
	UniqueID   string
	CreatedAt  *time.Time
	LastUsedAt *time.Time
	Tags       map[string]string
	// PermissionsBoundaryARN is the managed policy that caps this role's
	// effective permissions, or "" when none is attached.
	//
	// A boundary does not grant anything; it is a ceiling. A role whose
	// policies allow dynamodb:PutItem but whose boundary denies it cannot do
	// it, so reporting the grant without the boundary over-states access.
	PermissionsBoundaryARN string
	// TrustPolicy is the decoded AssumeRolePolicyDocument, verbatim. The
	// scanner stores it on cloud_identity.trust_document (035) and the
	// projector parses it; "" when the entry carried none.
	TrustPolicy string
	// InstanceProfiles are the instance profiles the role is in (§1.4). The
	// scanner stores them in the role's attrs, descriptive only (D-52).
	InstanceProfiles []InstanceProfileRef
	// Policies is everything attached to the role, from the same entry.
	Policies IdentityPolicies
}

// InstanceProfileRef is one entry of a RoleDetail's InstanceProfileList: the
// profile's ARN and name, and nothing else -- the profile's own role list is
// what iam:GetInstanceProfile answers for EC2, not this.
type InstanceProfileRef struct {
	ARN  string
	Name string
}

// IAMUser is one user as its authorization-details entry (UserDetail)
// returned it.
type IAMUser struct {
	ARN       string
	Name      string
	Path      string
	UniqueID  string
	CreatedAt *time.Time
	Tags      map[string]string
	// PermissionsBoundaryARN: as IAMRole's. Users' boundaries had no read at
	// all before authorization details (§1.3).
	PermissionsBoundaryARN string
	// GroupNames is the entry's GroupList, verbatim: group NAMES, resolved to
	// ARNs by the reader against the same read's Group listing (Members).
	GroupNames []string
	Policies   IdentityPolicies
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
	// PolicyID is AWS's PolicyId (ANPA...), from the LocalManagedPolicy
	// listing or GetPolicy: the policy's CREATION BOUNDARY. A customer-managed
	// policy deleted and recreated under the same ARN has a new one, and every
	// graph key below the policy is built from it (SPEC §2.4).
	PolicyID string
	Document string
	// FetchError is non-empty when this policy's document could not be read
	// this run: "fetch: <the call, the AWS error code, AWS's message>".
	// PER-DOCUMENT ISOLATION (§1.4): one unreadable policy is recorded on that
	// policy and the scan continues -- it used to abort every policy of the
	// identity, and then the whole permission scan.
	FetchError string
	// FetchAPI and FetchCode are FetchError's structured half (P2-DECISIONS
	// D-71, D-95): the call that failed and the code AWS returned, taken from the
	// APICallError that failed it -- never parsed back out of the prose, and
	// both empty when the fetch did not fail on a call (the listing returned
	// no document, or omitted the policy).
	FetchAPI  string
	FetchCode string
	// AWSManaged distinguishes an AWS-owned policy from a customer-owned one.
	// Ticket [2] weighs them differently: a customer-authored policy is a local
	// decision, an AWS-managed one is a well-known grant.
	AWSManaged bool
}

// InlinePolicy is a policy defined directly on the identity.
type InlinePolicy struct {
	Name     string
	Document string
	// FetchError: as AttachedPolicy.FetchError. Authorization details carry
	// inline documents in the listing itself, so today it is always empty;
	// kept so a document that is not in hand can never read as readable.
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

// OIDCProviders reads the account's registered OIDC identity providers.
//
// No pagination: the API returns the full list in one call, and an account
// with hundreds of these would be a novelty, not a scan concern.
func (r *IAMReader) OIDCProviders(ctx context.Context) ([]OIDCProvider, error) {
	resp, err := r.api.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		// Named with the call and AWS's code (§2.14.13), and still classified
		// underneath, so throttled vs denied is decided as before.
		return nil, callError("iam:ListOpenIDConnectProviders", err)
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
			// classify() alone rendered an IAM denial as "the role could not
			// be assumed", which is false here: the role was assumed, and this
			// one call was refused. Name the call instead (§2.14.13).
			return out, callError("iam:ListAccessKeys", err)
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

// boundaryPolicyName recovers the policy name from its ARN. A boundary is
// reported as an ARN only, and every policy row needs a name.
func boundaryPolicyName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i+1 < len(arn) {
		return arn[i+1:]
	}
	return arn
}

// managedPolicy fetches an AWS-managed policy's default version, through the
// cache. Customer-managed policies never come here: their documents are in
// the LocalManagedPolicy listing (authdetails.go).
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

	// The reason names the call and AWS's error code (§2.14.13, E9: "coverage
	// names the call"), never classify()'s "the role could not be assumed".
	meta, err := r.api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		built.fetchFailed(callError("iam:GetPolicy", err))
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
		built.FetchError = "fetch: iam:GetPolicy returned no default version"
		return built
	}
	ver, err := r.api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN), VersionId: aws.String(built.VersionID),
	})
	if err != nil {
		built.fetchFailed(callError("iam:GetPolicyVersion", err))
		return built
	}
	if ver.PolicyVersion != nil {
		built.Document = decodePolicyDocument(ver.PolicyVersion.Document)
	}
	return built
}

// fetchFailed records that the policy's document could not be fetched because
// a call failed: FetchError in the words it has always had ("fetch: AWS
// returned AccessDenied for iam:GetPolicyVersion: ..."), and beside it the
// call and AWS's code as the APICallError names them (D-95), so coverage can
// report both without reading the prose. An error that names no call leaves
// them empty: unknown is said as unknown.
func (p *AttachedPolicy) fetchFailed(err error) {
	p.FetchError = "fetch: " + err.Error()
	var call *APICallError
	if errors.As(err, &call) {
		p.FetchAPI, p.FetchCode = call.API, call.Code
	}
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
