package awsdiscovery

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// The authorization-details reader (T3.1) and the readability checks (T3.3)
// as pure logic. The end-to-end behaviour -- scanner, projector, coverage --
// is proven in tests/integration/p2_s3a_authdetails_test.go.

// s3aFakeIAM answers GetAccountAuthorizationDetails from canned pages per
// filter, and GetPolicy/GetPolicyVersion for AWS-managed ARNs.
type s3aFakeIAM struct {
	pages     map[iamtypes.EntityType][]*iam.GetAccountAuthorizationDetailsOutput
	fail      map[iamtypes.EntityType]error
	docs      map[string]string // AWS-managed ARN -> document
	filters   [][]iamtypes.EntityType
	getPolicy map[string]int
}

func (f *s3aFakeIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	f.filters = append(f.filters, append([]iamtypes.EntityType(nil), in.Filter...))
	if len(in.Filter) != 1 {
		return nil, errors.New("one filter per call")
	}
	if err := f.fail[in.Filter[0]]; err != nil {
		return nil, err
	}
	pages := f.pages[in.Filter[0]]
	i := 0
	if in.Marker != nil {
		i = int((*in.Marker)[0] - '0')
	}
	if i >= len(pages) {
		return &iam.GetAccountAuthorizationDetailsOutput{}, nil
	}
	out := *pages[i]
	if i+1 < len(pages) {
		out.IsTruncated, out.Marker = true, aws.String(string(rune('0'+i+1)))
	}
	return &out, nil
}

func (f *s3aFakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	arn := aws.ToString(in.PolicyArn)
	f.getPolicy[arn]++
	if _, ok := f.docs[arn]; !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity", Message: "no such policy " + arn}
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn: in.PolicyArn, DefaultVersionId: aws.String("v7"), PolicyId: aws.String("ANPAAWS" + boundaryPolicyName(arn)),
	}}, nil
}

func (f *s3aFakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		VersionId: in.VersionId, Document: aws.String(url.QueryEscape(f.docs[aws.ToString(in.PolicyArn)])),
	}}, nil
}

func (f *s3aFakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil
}
func (f *s3aFakeIAM) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{}, nil
}
func (f *s3aFakeIAM) ListOpenIDConnectProviders(context.Context, *iam.ListOpenIDConnectProvidersInput, ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return &iam.ListOpenIDConnectProvidersOutput{}, nil
}

const (
	s3aAcct      = "arn:aws:iam::111122223333:"
	s3aReadOnly  = "arn:aws:iam::aws:policy/ReadOnlyAccess"
	s3aPowerUser = "arn:aws:iam::aws:policy/PowerUserAccess"
	s3aDocA      = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
)

func s3aAttached(arn string) iamtypes.AttachedPolicy {
	return iamtypes.AttachedPolicy{PolicyArn: aws.String(arn), PolicyName: aws.String(boundaryPolicyName(arn))}
}

// s3aAccount is a small account over two pages of every listing.
func s3aAccount() *s3aFakeIAM {
	local := s3aAcct + "policy/Local"
	unattached := s3aAcct + "policy/Unattached"
	return &s3aFakeIAM{
		getPolicy: map[string]int{},
		docs:      map[string]string{s3aReadOnly: s3aDocA, s3aPowerUser: s3aDocA},
		fail:      map[iamtypes.EntityType]error{},
		pages: map[iamtypes.EntityType][]*iam.GetAccountAuthorizationDetailsOutput{
			iamtypes.EntityTypeLocalManagedPolicy: {
				{Policies: []iamtypes.ManagedPolicyDetail{{
					Arn: aws.String(local), PolicyName: aws.String("Local"), PolicyId: aws.String("ANPALOCAL"),
					DefaultVersionId: aws.String("v2"),
					PolicyVersionList: []iamtypes.PolicyVersion{
						{VersionId: aws.String("v1"), Document: aws.String(url.QueryEscape(`{"superseded":true}`))},
						{VersionId: aws.String("v2"), IsDefaultVersion: true, Document: aws.String(url.QueryEscape(s3aDocA))},
					},
				}}},
				{Policies: []iamtypes.ManagedPolicyDetail{{
					Arn: aws.String(unattached), PolicyName: aws.String("Unattached"), PolicyId: aws.String("ANPAUNATT"),
					DefaultVersionId: aws.String("v1"),
					PolicyVersionList: []iamtypes.PolicyVersion{
						{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: aws.String(url.QueryEscape(s3aDocA))},
					},
				}}},
			},
			iamtypes.EntityTypeGroup: {
				{GroupDetailList: []iamtypes.GroupDetail{{
					Arn: aws.String(s3aAcct + "group/eng/ops"), GroupName: aws.String("ops"), GroupId: aws.String("AGPAOPS"),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{s3aAttached(s3aReadOnly), s3aAttached(local)},
				}}},
				{GroupDetailList: []iamtypes.GroupDetail{{
					Arn: aws.String(s3aAcct + "group/dev"), GroupName: aws.String("dev"), GroupId: aws.String("AGPADEV"),
				}}},
			},
			iamtypes.EntityTypeRole: {
				{RoleDetailList: []iamtypes.RoleDetail{{
					Arn: aws.String(s3aAcct + "role/r1"), RoleName: aws.String("r1"), RoleId: aws.String("AROAR1"),
					AssumeRolePolicyDocument: aws.String(url.QueryEscape(`{"Statement":[]}`)),
					AttachedManagedPolicies:  []iamtypes.AttachedPolicy{s3aAttached(s3aReadOnly)},
					PermissionsBoundary:      &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(s3aPowerUser)},
					RolePolicyList: []iamtypes.PolicyDetail{{
						PolicyName: aws.String("inl"), PolicyDocument: aws.String(url.QueryEscape(s3aDocA)),
					}},
				}}},
				{RoleDetailList: []iamtypes.RoleDetail{{
					Arn: aws.String(s3aAcct + "role/r2"), RoleName: aws.String("r2"), RoleId: aws.String("AROAR2"),
					AttachedManagedPolicies: []iamtypes.AttachedPolicy{s3aAttached(s3aAcct + "policy/Ghost")},
				}}},
			},
			iamtypes.EntityTypeUser: {
				{UserDetailList: []iamtypes.UserDetail{{
					Arn: aws.String(s3aAcct + "user/priya"), UserName: aws.String("priya"), UserId: aws.String("AIDAPRIYA"),
					GroupList:           []string{"ops", "not-listed"},
					PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(local)},
				}}},
				{UserDetailList: []iamtypes.UserDetail{{
					Arn: aws.String(s3aAcct + "user/dan"), UserName: aws.String("dan"), UserId: aws.String("AIDADAN"),
					GroupList: []string{"dev"},
				}}},
			},
		},
	}
}

func TestS3aAuthorizationDetailsOneCallPerFilterAcrossPages(t *testing.T) {
	f := s3aAccount()
	d := NewIAMReader(f).AuthorizationDetails(context.Background())

	for _, filters := range f.filters {
		if len(filters) != 1 {
			t.Fatalf("a call named filters %v; every listing is its own call (D-48)", filters)
		}
	}
	if len(f.filters) != 8 {
		t.Errorf("%d calls, want 2 pages x 4 filters", len(f.filters))
	}
	if d.RolesErr != nil || d.UsersErr != nil || d.GroupsErr != nil || d.PoliciesErr != nil {
		t.Fatalf("listing errors = %v %v %v %v", d.RolesErr, d.UsersErr, d.GroupsErr, d.PoliciesErr)
	}
	if len(d.Roles) != 2 || len(d.Users) != 2 || len(d.Groups) != 2 {
		t.Fatalf("roles %d users %d groups %d, want 2 each across two pages", len(d.Roles), len(d.Users), len(d.Groups))
	}

	// Memberships: resolved against THIS read's groups, by name, path kept;
	// a name the Group listing did not return is dropped, not guessed.
	if got := d.Members[s3aAcct+"user/priya"]; len(got) != 1 || got[0] != s3aAcct+"group/eng/ops" {
		t.Errorf("priya's groups = %v, want only the listed ops group, with its path", got)
	}
	if got := d.Members[s3aAcct+"user/dan"]; len(got) != 1 || got[0] != s3aAcct+"group/dev" {
		t.Errorf("dan's groups = %v, want dev (listed on the second page)", got)
	}

	// Every customer-managed policy, attached or not, from the listing, at its
	// DEFAULT version; never fetched.
	local := d.ManagedPolicies[s3aAcct+"policy/Local"]
	if local.Document != s3aDocA || local.VersionID != "v2" || local.PolicyID != "ANPALOCAL" || local.FetchError != "" {
		t.Errorf("Local = %+v, want the v2 document and its PolicyId", local)
	}
	if u, ok := d.ManagedPolicies[s3aAcct+"policy/Unattached"]; !ok || u.Document == "" {
		t.Errorf("an unattached customer-managed policy is missing: %+v", u)
	}
	for arn, n := range f.getPolicy {
		if !isAWSManagedPolicyARN(arn) {
			t.Errorf("GetPolicy called %d times for customer-managed %s", n, arn)
		}
	}
	// AWS-managed: fetched once however many principals attach it, and as a
	// boundary too (D-50).
	if f.getPolicy[s3aReadOnly] != 1 || f.getPolicy[s3aPowerUser] != 1 {
		t.Errorf("GetPolicy calls = %v, want ReadOnlyAccess and PowerUserAccess once each", f.getPolicy)
	}
	r1 := d.Roles[0]
	if r1.Policies.Boundary == nil || r1.Policies.Boundary.Document != s3aDocA || !r1.Policies.Boundary.AWSManaged {
		t.Errorf("r1's AWS-managed boundary = %+v, want fetched", r1.Policies.Boundary)
	}
	if r1.TrustPolicy != `{"Statement":[]}` || len(r1.Policies.Inline) != 1 || r1.Policies.Inline[0].Document != s3aDocA {
		t.Errorf("r1 = %+v, want its decoded trust document and inline policy", r1)
	}
	if b := d.Users[0].Policies.Boundary; b == nil || b.ARN != s3aAcct+"policy/Local" || b.Document != s3aDocA {
		t.Errorf("priya's customer-managed boundary = %+v, want it resolved from the listing", b)
	}
	// Attached but absent from a COMPLETED listing: unreadable, with the reason.
	ghost := d.Roles[1].Policies.Attached[0]
	if ghost.Document != "" || !strings.Contains(ghost.FetchError, "absent from the iam:GetAccountAuthorizationDetails (LocalManagedPolicy) listing") {
		t.Errorf("Ghost = %+v, want unreadable, absent from the listing", ghost)
	}
}

// Each listing's failure lands on its own surface, named with the call and
// the AWS code; the listings around it still run.
func TestS3aAuthorizationDetailsFailuresArePerFilter(t *testing.T) {
	f := s3aAccount()
	f.fail[iamtypes.EntityTypeGroup] = &smithy.GenericAPIError{Code: "AccessDenied", Message: "no groups for you"}
	f.fail[iamtypes.EntityTypeLocalManagedPolicy] = &smithy.GenericAPIError{Code: "Throttling", Message: "slow down"}
	d := NewIAMReader(f).AuthorizationDetails(context.Background())

	if d.RolesErr != nil || d.UsersErr != nil {
		t.Errorf("roles %v users %v, want reached: another filter failed", d.RolesErr, d.UsersErr)
	}
	if d.GroupsErr == nil || d.GroupsErr.Error() !=
		"AWS returned AccessDenied for iam:GetAccountAuthorizationDetails (Groups): no groups for you" {
		t.Errorf("GroupsErr = %v", d.GroupsErr)
	}
	if !errors.Is(d.PoliciesErr, ErrThrottled) {
		t.Errorf("PoliciesErr = %v, want it to classify as throttled", d.PoliciesErr)
	}
	var apiErr smithy.APIError
	if !errors.As(d.GroupsErr, &apiErr) || apiErr.ErrorCode() != "AccessDenied" {
		t.Errorf("the SDK error must stay reachable for the coverage reader: %v", d.GroupsErr)
	}
	if len(d.Members) != 0 {
		t.Errorf("memberships = %v, want none: no group was listed to resolve against", d.Members)
	}
	// A customer-managed attachment names the listing that failed.
	for _, p := range d.Groups {
		t.Errorf("groups listed despite the failure: %+v", p)
	}
	b := d.Users[0].Policies.Boundary
	if b == nil || b.Document != "" || !strings.Contains(b.FetchError, "Throttling") ||
		!strings.Contains(b.FetchError, "(LocalManagedPolicy)") {
		t.Errorf("priya's boundary = %+v, want unreadable, naming the failed listing", b)
	}
}

func TestS3aPolicyDocumentError(t *testing.T) {
	for _, c := range []struct {
		name, doc, want string
	}{
		{"readable", s3aDocA, ""},
		{"deny with NotAction", `{"Statement":[{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}]}`, ""},
		{"no statements", `{"Version":"2012-10-17","Statement":[]}`, ""},
		{"one unusable (D-49)", `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},` +
			`{"Action":"s3:PutObject","Resource":"*"}]}`, "parse: 1 statement(s) unusable"},
		{"two unusable", `{"Statement":[{"Effect":"Allow","Resource":"*"},{"Action":"s3:PutObject"}]}`,
			"parse: 2 statement(s) unusable"},
	} {
		if got := PolicyDocumentError(c.doc); got != c.want {
			t.Errorf("%s: PolicyDocumentError = %q, want %q", c.name, got, c.want)
		}
	}
	if got := PolicyDocumentError(`{"Statement":[{"Effect":`); !strings.HasPrefix(got, "parse: ") ||
		!strings.Contains(got, ErrMalformedPolicy.Error()) {
		t.Errorf("malformed: PolicyDocumentError = %q, want parse: <malformed>", got)
	}
}

func TestS3aCallErrorNamesTheCallNotAPermission(t *testing.T) {
	err := callError("iam:GetPolicyVersion", &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"})
	if err.Error() != "AWS returned AccessDenied for iam:GetPolicyVersion: not authorized" {
		t.Errorf("callError = %q", err)
	}
	if strings.Contains(err.Error(), "assumed") {
		t.Errorf("callError = %q: an IAM read denial is not an assume-role failure", err)
	}
	if !errors.Is(err, ErrNotAssumable) {
		// Still classified, so existing sentinels keep working for callers.
		t.Errorf("callError lost the classified sentinel: %v", err)
	}
	plain := callError("iam:GetPolicy", context.DeadlineExceeded)
	if plain.Error() != "iam:GetPolicy failed: context deadline exceeded" || !errors.Is(plain, context.DeadlineExceeded) {
		t.Errorf("non-AWS failure = %q", plain)
	}
	if callError("x", nil) != nil {
		t.Error("callError(nil) must be nil")
	}
}

func TestS3aLocalManagedPolicyReadsOnlyTheDefaultVersion(t *testing.T) {
	enc := func(s string) *string { return aws.String(url.QueryEscape(s)) }
	// DefaultVersionId names v3 even though an entry is also flagged default:
	// the named version wins.
	p := localManagedPolicy(iamtypes.ManagedPolicyDetail{
		Arn: aws.String(s3aAcct + "policy/P"), PolicyName: aws.String("P"), DefaultVersionId: aws.String("v3"),
		PolicyVersionList: []iamtypes.PolicyVersion{
			{VersionId: aws.String("v1"), IsDefaultVersion: true, Document: enc(`{"old":1}`)},
			{VersionId: aws.String("v3"), Document: enc(s3aDocA)},
		},
	})
	if p.VersionID != "v3" || p.Document != s3aDocA || p.FetchError != "" {
		t.Errorf("named default = %+v", p)
	}
	// No DefaultVersionId: the flagged entry.
	p = localManagedPolicy(iamtypes.ManagedPolicyDetail{
		Arn: aws.String(s3aAcct + "policy/Q"), PolicyName: aws.String("Q"),
		PolicyVersionList: []iamtypes.PolicyVersion{
			{VersionId: aws.String("v1"), Document: enc(`{"old":1}`)},
			{VersionId: aws.String("v2"), IsDefaultVersion: true, Document: enc(s3aDocA)},
		},
	})
	if p.VersionID != "v2" || p.Document != s3aDocA {
		t.Errorf("flagged default = %+v", p)
	}
	// Neither: known to exist, not read.
	p = localManagedPolicy(iamtypes.ManagedPolicyDetail{
		Arn: aws.String(s3aAcct + "policy/R"), PolicyName: aws.String("R"), DefaultVersionId: aws.String("v9"),
	})
	if p.Document != "" || !strings.HasPrefix(p.FetchError, "fetch: ") {
		t.Errorf("no default version document = %+v, want unreadable", p)
	}
}

var _ IAMAPI = (*s3aFakeIAM)(nil)
