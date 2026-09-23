package integration

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IAM identity discovery, against a real database.
//
// The AWS boundary is a fake IAMAPI: it serves GetAccountAuthorizationDetails
// from its state one filter at a time and paginates like IAM does, URL-encodes
// policy documents like IAM does, and can be told to deny or throttle a
// specific operation or one filter's listing. Everything else — the reader, the
// scanner, the upserts, the reconciliation gate and the coverage report — is
// the real thing.

/* ------------------------------- the fake IAM ------------------------------ */

type fakeIAM struct {
	// roles and users are the account's principals. Each one's attachments,
	// inline documents and group list below are served in its authorization-
	// details entry; Tags, PermissionsBoundary, RoleLastUsed and the trust
	// document come from the struct itself. (Description and
	// MaxSessionDuration are NOT served: RoleDetail does not carry them.)
	roles      []iamtypes.Role
	users      []iamtypes.User
	keys       map[string][]iamtypes.AccessKeyMetadata // by user name
	keyLastUse map[string]*time.Time                   // by key id

	attachedRolePolicies map[string][]iamtypes.AttachedPolicy
	inlineRolePolicies   map[string]map[string]string // role -> policy -> document
	// instanceProfiles is each role's InstanceProfileList, by role name.
	instanceProfiles     map[string][]iamtypes.InstanceProfile
	attachedUserPolicies map[string][]iamtypes.AttachedPolicy
	inlineUserPolicies   map[string]map[string]string

	// managedPolicies is every managed policy document by ARN. A
	// customer-managed one (any account but "aws") is in the LocalManagedPolicy
	// listing, attached or not; an AWS-managed one is served by GetPolicy /
	// GetPolicyVersion only.
	managedPolicies map[string]string

	// policyIDs is each managed policy's PolicyId. Unset derives a stable one
	// from the ARN; a test RECREATES a policy under the same ARN by changing it.
	policyIDs map[string]string
	// policyVersions is each managed policy's default version id ("v3" unset).
	policyVersions map[string]string
	// failPolicyVersion makes GetPolicyVersion fail for ONE policy ARN -- the
	// per-document isolation scenario, on an attached AWS-managed policy (D-51).
	failPolicyVersion map[string]error

	// groups and userGroups back the Group listing and each user's GroupList.
	// A group's GroupPolicyList documents are served as set (fixtures encode).
	groups     []iamtypes.GroupDetail
	userGroups map[string][]string // user name -> group names

	// fail maps an operation name to the error it should return. For
	// authorization details, "GetAccountAuthorizationDetails" fails every
	// listing and "GetAccountAuthorizationDetails:<Filter>" (Role, User, Group,
	// LocalManagedPolicy) fails that one.
	fail map[string]error
	// calls counts every operation, so a test can assert on call volume.
	calls map[string]int
	// pageSize forces pagination when > 0.
	pageSize int
}

func newFakeIAM() *fakeIAM {
	return &fakeIAM{
		keys:                 map[string][]iamtypes.AccessKeyMetadata{},
		keyLastUse:           map[string]*time.Time{},
		attachedRolePolicies: map[string][]iamtypes.AttachedPolicy{},
		inlineRolePolicies:   map[string]map[string]string{},
		instanceProfiles:     map[string][]iamtypes.InstanceProfile{},
		attachedUserPolicies: map[string][]iamtypes.AttachedPolicy{},
		inlineUserPolicies:   map[string]map[string]string{},
		managedPolicies:      map[string]string{},
		policyIDs:            map[string]string{},
		policyVersions:       map[string]string{},
		failPolicyVersion:    map[string]error{},
		userGroups:           map[string][]string{},
		fail:                 map[string]error{},
		calls:                map[string]int{},
	}
}

func (f *fakeIAM) track(op string) error {
	f.calls[op]++
	return f.fail[op]
}

func denied(op string) error {
	return &smithy.GenericAPIError{
		Code: "AccessDenied", Message: "not authorized to perform " + op,
	}
}

func throttled(op string) error {
	return &smithy.GenericAPIError{Code: "Throttling", Message: "rate exceeded on " + op}
}

// page slices a list according to the fake's page size and an integer marker.
func (f *fakeIAM) page(total int, marker *string) (from, to int, next *string) {
	size := f.pageSize
	if size <= 0 || size > total {
		size = total
	}
	from = 0
	if marker != nil {
		fmt.Sscanf(*marker, "%d", &from)
	}
	to = from + size
	if to >= total {
		return from, total, nil
	}
	m := fmt.Sprintf("%d", to)
	return from, to, &m
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if err := f.track("ListAccessKeys"); err != nil {
		return nil, err
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys[aws.ToString(in.UserName)]}, nil
}

func (f *fakeIAM) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if err := f.track("GetAccessKeyLastUsed"); err != nil {
		return nil, err
	}
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
			LastUsedDate: f.keyLastUse[aws.ToString(in.AccessKeyId)],
		},
	}, nil
}

// s3aPolicyMeta is a managed policy's default version id and PolicyId, as both
// GetPolicy and the LocalManagedPolicy listing report them.
func (f *fakeIAM) s3aPolicyMeta(arn string) (version, policyID string) {
	version = f.policyVersions[arn]
	if version == "" {
		version = "v3"
	}
	policyID = f.policyIDs[arn]
	if policyID == "" {
		policyID = "ANPA" + strings.ToUpper(fmt.Sprintf("%x", len(arn)*7919+int(arn[len(arn)-1])))
	}
	return version, policyID
}

// GetPolicy and GetPolicyVersion also count per ARN ("GetPolicy:<arn>"), so a
// test can prove a customer-managed policy is never fetched this way.
func (f *fakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	arn := aws.ToString(in.PolicyArn)
	f.calls["GetPolicy:"+arn]++
	if err := f.track("GetPolicy"); err != nil {
		return nil, err
	}
	if _, ok := f.managedPolicies[arn]; !ok {
		return nil, &smithy.GenericAPIError{Code: "NoSuchEntity", Message: "no such policy"}
	}
	version, policyID := f.s3aPolicyMeta(arn)
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn: in.PolicyArn, DefaultVersionId: aws.String(version),
		PolicyId:   aws.String(policyID),
		PolicyName: aws.String(arn[strings.LastIndex(arn, "/")+1:]),
	}}, nil
}

func (f *fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	f.calls["GetPolicyVersion:"+aws.ToString(in.PolicyArn)]++
	if err := f.track("GetPolicyVersion"); err != nil {
		return nil, err
	}
	if err := f.failPolicyVersion[aws.ToString(in.PolicyArn)]; err != nil {
		return nil, err
	}
	doc := f.managedPolicies[aws.ToString(in.PolicyArn)]
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		VersionId: in.VersionId, Document: aws.String(url.QueryEscape(doc)),
	}}, nil
}

// GetAccountAuthorizationDetails serves the account's whole IAM configuration
// from the fake's state, the way IAM does: every document URL-encoded, each
// listing paginated at pageSize with an integer marker.
//
// ONE FILTER PER CALL. That is the reader's contract (P2-DECISIONS D-48: each
// listing is its own surface), and a request naming several filters -- or
// none, which IAM reads as "all" -- is refused, so a regression to one
// combined call fails every test that scans.
func (f *fakeIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if err := f.track("GetAccountAuthorizationDetails"); err != nil {
		return nil, err
	}
	if len(in.Filter) != 1 {
		return nil, &smithy.GenericAPIError{Code: "ValidationError",
			Message: fmt.Sprintf("the fake serves exactly one filter per call, got %v", in.Filter)}
	}
	filter := in.Filter[0]
	if err := f.track("GetAccountAuthorizationDetails:" + string(filter)); err != nil {
		return nil, err
	}
	out := &iam.GetAccountAuthorizationDetailsOutput{}
	var next *string
	switch filter {
	case iamtypes.EntityTypeRole:
		var from, to int
		from, to, next = f.page(len(f.roles), in.Marker)
		for _, r := range f.roles[from:to] {
			name := aws.ToString(r.RoleName)
			out.RoleDetailList = append(out.RoleDetailList, iamtypes.RoleDetail{
				Arn: r.Arn, RoleName: r.RoleName, RoleId: r.RoleId, Path: r.Path,
				CreateDate: r.CreateDate, AssumeRolePolicyDocument: r.AssumeRolePolicyDocument,
				RoleLastUsed: r.RoleLastUsed, Tags: r.Tags, PermissionsBoundary: r.PermissionsBoundary,
				AttachedManagedPolicies: f.attachedRolePolicies[name],
				RolePolicyList:          s3aInlineDetails(f.inlineRolePolicies[name]),
				InstanceProfileList:     f.instanceProfiles[name],
			})
		}
	case iamtypes.EntityTypeUser:
		var from, to int
		from, to, next = f.page(len(f.users), in.Marker)
		for _, u := range f.users[from:to] {
			name := aws.ToString(u.UserName)
			out.UserDetailList = append(out.UserDetailList, iamtypes.UserDetail{
				Arn: u.Arn, UserName: u.UserName, UserId: u.UserId, Path: u.Path,
				CreateDate: u.CreateDate, Tags: u.Tags, PermissionsBoundary: u.PermissionsBoundary,
				GroupList:               f.userGroups[name],
				AttachedManagedPolicies: f.attachedUserPolicies[name],
				UserPolicyList:          s3aInlineDetails(f.inlineUserPolicies[name]),
			})
		}
	case iamtypes.EntityTypeGroup:
		var from, to int
		from, to, next = f.page(len(f.groups), in.Marker)
		out.GroupDetailList = f.groups[from:to]
	case iamtypes.EntityTypeLocalManagedPolicy:
		var local []string
		for arn := range f.managedPolicies {
			if !strings.Contains(arn, ":iam::aws:policy/") {
				local = append(local, arn)
			}
		}
		sort.Strings(local)
		var from, to int
		from, to, next = f.page(len(local), in.Marker)
		for _, arn := range local[from:to] {
			version, policyID := f.s3aPolicyMeta(arn)
			out.Policies = append(out.Policies, iamtypes.ManagedPolicyDetail{
				Arn: aws.String(arn), PolicyName: aws.String(arn[strings.LastIndex(arn, "/")+1:]),
				PolicyId: aws.String(policyID), DefaultVersionId: aws.String(version),
				// Every version is listed, the superseded one FIRST: a reader
				// that takes anything but the default reads a statement no
				// fixture declares.
				PolicyVersionList: []iamtypes.PolicyVersion{
					{VersionId: aws.String("v0-superseded"), IsDefaultVersion: false,
						Document: aws.String(url.QueryEscape(s3aSupersededVersion))},
					{VersionId: aws.String(version), IsDefaultVersion: true,
						Document: aws.String(url.QueryEscape(f.managedPolicies[arn]))},
				},
			})
		}
	default:
		return nil, &smithy.GenericAPIError{Code: "ValidationError", Message: "unsupported filter " + string(filter)}
	}
	out.IsTruncated, out.Marker = next != nil, next
	return out, nil
}

// s3aSupersededVersion is a non-default policy version no reader may use.
const s3aSupersededVersion = `{"Version":"2012-10-17","Statement":[` +
	`{"Sid":"SupersededVersion","Effect":"Allow","Action":"iam:*","Resource":"*"}]}`

// s3aInlineDetails serves inline documents as IAM does: URL-encoded, and in a
// stable order.
func s3aInlineDetails(docs map[string]string) []iamtypes.PolicyDetail {
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]iamtypes.PolicyDetail, 0, len(names))
	for _, n := range names {
		out = append(out, iamtypes.PolicyDetail{
			PolicyName: aws.String(n), PolicyDocument: aws.String(url.QueryEscape(docs[n])),
		})
	}
	return out
}

// ListOpenIDConnectProviders satisfies awsdiscovery.IAMAPI, added by ticket
// [2]. This fixture only exercises ticket [1]'s IAM identity scan, which never
// calls it -- an empty result is enough to keep fakeIAM implementing the
// interface.
func (f *fakeIAM) ListOpenIDConnectProviders(_ context.Context, _ *iam.ListOpenIDConnectProvidersInput, _ ...func(*iam.Options)) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return &iam.ListOpenIDConnectProvidersOutput{}, nil
}

/* -------------------------------- fixtures -------------------------------- */

func ago(d time.Duration) *time.Time { t := time.Now().Add(-d); return &t }

const (
	agentRoleARN = "arn:aws:iam::429418377036:role/summarizer-agent"
	plainRoleARN = "arn:aws:iam::429418377036:role/ops-readonly"
	ciUserARN    = "arn:aws:iam::429418377036:user/ci-deployer"
)

// populatedIAM is a small but representative account: two roles (one with a
// trust policy and a managed policy, one with an inline policy) and a user with
// two access keys, one of them long-dormant.
func populatedIAM() *fakeIAM {
	f := newFakeIAM()

	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	f.roles = []iamtypes.Role{
		{
			Arn: aws.String(agentRoleARN), RoleName: aws.String("summarizer-agent"),
			RoleId: aws.String("AROAEXAMPLEAGENT"), Path: aws.String("/service-role/"),
			Description: aws.String("runs the summariser"),
			CreateDate:  ago(400 * 24 * time.Hour),
			// URL-encoded, exactly as IAM returns it.
			AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
			MaxSessionDuration:       aws.Int32(3600),
			RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: ago(2 * time.Hour)},
			Tags: []iamtypes.Tag{
				{Key: aws.String("owner"), Value: aws.String("platform@acme.test")},
			},
		},
		{
			Arn: aws.String(plainRoleARN), RoleName: aws.String("ops-readonly"),
			RoleId: aws.String("AROAEXAMPLEOPS"), Path: aws.String("/"),
			CreateDate:               ago(90 * 24 * time.Hour),
			AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
			// No RoleLastUsed: AWS omits it for a role never used. It must stay
			// NULL, not become a zero time.
		},
	}

	f.users = []iamtypes.User{{
		Arn: aws.String(ciUserARN), UserName: aws.String("ci-deployer"),
		UserId: aws.String("AIDAEXAMPLECI"), Path: aws.String("/"),
		CreateDate: ago(900 * 24 * time.Hour),
	}}

	f.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{
		{
			AccessKeyId: aws.String("AKIAOLDANDACTIVE"), UserName: aws.String("ci-deployer"),
			Status: iamtypes.StatusTypeActive, CreateDate: ago(900 * 24 * time.Hour),
		},
		{
			AccessKeyId: aws.String("AKIAROTATEDOUT"), UserName: aws.String("ci-deployer"),
			Status: iamtypes.StatusTypeInactive, CreateDate: ago(30 * 24 * time.Hour),
		},
	}
	f.keyLastUse["AKIAOLDANDACTIVE"] = ago(600 * 24 * time.Hour)
	// AKIAROTATEDOUT deliberately absent: never used, must stay NULL.

	managedARN := "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
	f.managedPolicies[managedARN] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"*"}]}`
	f.attachedRolePolicies["summarizer-agent"] = []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String(managedARN), PolicyName: aws.String("AmazonBedrockFullAccess")},
	}
	f.inlineRolePolicies["ops-readonly"] = map[string]string{
		"read-buckets": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}`,
	}
	f.inlineUserPolicies["ci-deployer"] = map[string]string{
		"deploy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}]}`,
	}
	return f
}

// scanFixture onboards a connector and returns a scanner wired to the fake.
func scanFixture(t *testing.T, db *gorm.DB, ws uuid.UUID, f *fakeIAM) (*services.AWSIAMScanner, uuid.UUID) {
	t.Helper()
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	return services.NewAWSIAMScanner(db, svc).WithIAMAPI(f), c.ID
}

func cleanIdentities(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	db.Exec(`DELETE FROM cloud_secret WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_identity WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
}

/* ---------------------------------- tests --------------------------------- */

// The core of ticket [1]: every role and user becomes one identity row, every
// access key becomes one secret row, and the policy documents come back decoded
// for ticket [2].
func TestIAMScanRecordsIdentitiesSecretsAndPolicies(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-scan")
	defer cleanIdentities(t, db, ws)

	scanner, connectorID := scanFixture(t, db, ws, populatedIAM())
	snap, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if snap.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("a scan that reached every surface should be complete, got %s (%+v)",
			snap.Coverage.Status, snap.Coverage.Surfaces)
	}
	t.Logf("PASS: scan complete, generation %d", snap.Generation)

	repo := repositories.NewCloudIdentityRepository(db)
	identities, total, err := repo.ListIdentities(ws, repositories.CloudIdentityFilter{})
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected 2 roles + 1 user = 3 identities, got %d", total)
	}
	t.Logf("PASS: %d identities recorded", total)

	byARN := map[string]models.CloudIdentity{}
	for _, i := range identities {
		byARN[i.NativeID] = i
	}

	agent, ok := byARN[agentRoleARN]
	if !ok {
		t.Fatal("the agent role was not recorded")
	}
	if agent.Kind != models.CloudIdentityIAMRole {
		t.Fatalf("wrong kind: %s", agent.Kind)
	}
	if agent.ProviderCreatedAt == nil || time.Since(*agent.ProviderCreatedAt) < 300*24*time.Hour {
		t.Fatalf("created_at must be the PROVIDER's date, not the row's: %v", agent.ProviderCreatedAt)
	}
	t.Logf("PASS: created_at is the provider's date (%s), not today", agent.ProviderCreatedAt.Format("2006-01-02"))

	if agent.LastUsedAt == nil {
		t.Fatal("RoleLastUsed should have populated last_used_at")
	}
	attrs := agent.AWSAttrs()
	if attrs.UniqueID != "AROAEXAMPLEAGENT" {
		t.Fatalf("the AWS unique id must be kept so a recreated role is detectable, got %q", attrs.UniqueID)
	}
	if attrs.Tags["owner"] != "platform@acme.test" {
		t.Fatalf("role tags carry the ownership hint, got %v", attrs.Tags)
	}
	if !attrs.HasTrustPolicy {
		t.Fatal("the role has a trust policy and the flag should say so")
	}
	t.Logf("PASS: unique id, tags and trust-policy flag recorded")

	// A role AWS has never reported using must stay NULL, not become a zero time.
	plain := byARN[plainRoleARN]
	if plain.LastUsedAt != nil {
		t.Fatalf("an unused role must have last_used_at NULL (unknown), got %v", plain.LastUsedAt)
	}
	t.Log("PASS: never-used role has last_used_at NULL, not a zero time")

	// Access keys.
	secrets, _, err := repo.ListSecrets(ws, repositories.CloudSecretFilter{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 access keys, got %d", len(secrets))
	}
	byKey := map[string]models.CloudSecret{}
	for _, s := range secrets {
		byKey[s.NativeID] = s
	}
	old := byKey["AKIAOLDANDACTIVE"]
	if old.Status != models.CloudSecretActive {
		t.Fatalf("expected active, got %s", old.Status)
	}
	if old.ProviderCreatedAt == nil || time.Since(*old.ProviderCreatedAt) < 800*24*time.Hour {
		t.Fatal("the key's age is the finding and must be the provider's date")
	}
	if old.LastUsedAt == nil {
		t.Fatal("this key has a last-used date")
	}
	if old.ExpiresAt != nil {
		t.Fatal("AWS access keys do not expire; expires_at must be NULL")
	}
	rotated := byKey["AKIAROTATEDOUT"]
	if rotated.Status != models.CloudSecretInactive {
		t.Fatalf("expected inactive, got %s", rotated.Status)
	}
	if rotated.LastUsedAt != nil {
		t.Fatal("a never-used key must have last_used_at NULL, not a zero time")
	}
	t.Log("PASS: key status, age and never-used-is-NULL all correct")

	// Secrets are ordered oldest first, because age is the finding.
	if secrets[0].NativeID != "AKIAOLDANDACTIVE" {
		t.Fatalf("secrets should be oldest first, got %s", secrets[0].NativeID)
	}

	// Policy documents: retrieved, decoded, and handed to ticket [2] rather than
	// persisted.
	if len(snap.Policies) != 3 {
		t.Fatalf("expected policies for 3 identities, got %d", len(snap.Policies))
	}
	agentPolicies := snap.Policies[agentRoleARN]
	if len(agentPolicies.Attached) != 1 {
		t.Fatalf("expected one managed policy, got %d", len(agentPolicies.Attached))
	}
	doc := agentPolicies.Attached[0].Document
	if !strings.Contains(doc, `"bedrock:InvokeModel"`) {
		t.Fatalf("the policy document must arrive URL-DECODED, got: %s", doc)
	}
	if !agentPolicies.Attached[0].AWSManaged {
		t.Fatal("an arn:aws:iam::aws:policy/... policy is AWS-managed")
	}
	t.Log("PASS: policy documents URL-decoded and AWS-managed flagged")

	if !strings.Contains(snap.TrustPolicies[agentRoleARN], "lambda.amazonaws.com") {
		t.Fatalf("the trust policy must be decoded and handed over: %s", snap.TrustPolicies[agentRoleARN])
	}
	t.Log("PASS: trust policy decoded and handed to ticket [2]")

	// Ticket [1]'s scope line: no write path beyond cloud_connector,
	// cloud_identity and cloud_secret.
	//
	// Every other cloud_* table now exists -- cloud_permission, cloud_resource
	// and cloud_assume_edge from migrations 012/013, cloud_workload and
	// cloud_usage from 015/016 -- so the check that matters is that
	// AWSIAMScanner.Scan wrote no ROWS into any of them. Asserting the tables
	// were absent, which this test used to do, breaks every time a later
	// surface legitimately lands.
	for _, table := range []string{
		"cloud_permission", "cloud_resource", "cloud_assume_edge",
		"cloud_workload", "cloud_usage",
	} {
		var rows int64
		db.Raw(fmt.Sprintf(`SELECT count(*) FROM %s WHERE workspace_id = ?`, table), ws).Scan(&rows)
		if rows > 0 {
			t.Fatalf("%s has %d rows; ticket [1]'s scan must not write to it", table, rows)
		}
	}
	t.Log("PASS: ticket [1]'s scan wrote nothing outside its own tables")
}

// A repeat scan must update, not duplicate — the acceptance criterion stated
// directly.
func TestIAMRepeatScanUpdatesRatherThanDuplicating(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-repeat")
	defer cleanIdentities(t, db, ws)

	fake := populatedIAM()
	scanner, connectorID := scanFixture(t, db, ws, fake)

	first, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	repo := repositories.NewCloudIdentityRepository(db)
	before, err := repo.GetIdentityByNativeID(ws, agentRoleARN)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}

	second, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if second.Generation != first.Generation+1 {
		t.Fatalf("generation should advance: %d -> %d", first.Generation, second.Generation)
	}

	_, total, _ := repo.ListIdentities(ws, repositories.CloudIdentityFilter{})
	if total != 3 {
		t.Fatalf("a repeat scan duplicated rows: %d identities", total)
	}
	after, _ := repo.GetIdentityByNativeID(ws, agentRoleARN)
	if after.ID != before.ID {
		t.Fatalf("the row was replaced rather than updated: %s -> %s", before.ID, after.ID)
	}
	if !after.FirstSeenAt.Equal(before.FirstSeenAt) {
		t.Fatalf("first_seen_at must not move on a repeat scan: %v -> %v",
			before.FirstSeenAt, after.FirstSeenAt)
	}
	if after.LastSeenGeneration != second.Generation {
		t.Fatalf("the generation stamp should advance, got %d want %d",
			after.LastSeenGeneration, second.Generation)
	}
	t.Logf("PASS: same row, first_seen_at held at %s, generation now %d",
		before.FirstSeenAt.Format(time.RFC3339), after.LastSeenGeneration)

	var secretCount int64
	db.Raw(`SELECT count(*) FROM cloud_secret WHERE workspace_id = ?`, ws).Scan(&secretCount)
	if secretCount != 2 {
		t.Fatalf("a repeat scan duplicated secrets: %d", secretCount)
	}
	t.Log("PASS: secrets not duplicated either")
}

// The rule the whole schema is built on: unreached is not missing. A denied
// surface must never let reconciliation conclude something is gone.
func TestIAMPartialScanNeverDeletes(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-partial")
	defer cleanIdentities(t, db, ws)

	fake := populatedIAM()
	scanner, connectorID := scanFixture(t, db, ws, fake)

	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	repo := repositories.NewCloudIdentityRepository(db)
	_, before, _ := repo.ListIdentities(ws, repositories.CloudIdentityFilter{})
	if before != 3 {
		t.Fatalf("expected 3 identities before, got %d", before)
	}

	// Now IAM refuses to list roles. The roles still exist in AWS; we simply
	// cannot see them. Nothing may be deleted.
	fake.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	snap, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("a denied surface must not fail the whole scan: %v", err)
	}

	if snap.Coverage.Status != models.ScanStatusPartial {
		t.Fatalf("expected a partial scan, got %s", snap.Coverage.Status)
	}
	if got := snap.Coverage.Surfaces[models.SurfaceIAMRoles].State; got != models.CloudCoverageDenied {
		t.Fatalf("the roles surface should read denied, got %s", got)
	}
	if snap.Coverage.Complete() {
		t.Fatal("a scan with a denied surface must not report complete coverage")
	}
	t.Logf("PASS: roles denied, scan reported partial")

	_, after, _ := repo.ListIdentities(ws, repositories.CloudIdentityFilter{})
	if after != before {
		t.Fatalf("a partial scan deleted inventory: %d -> %d", before, after)
	}
	if snap.Coverage.Counters["identities_removed"] != 0 {
		t.Fatal("a partial scan must remove nothing")
	}
	t.Log("PASS: nothing deleted — could-not-read is not found-nothing")

	// The users surface was still readable, so it must still report reached.
	if got := snap.Coverage.Surfaces[models.SurfaceIAMUsers].State; got != models.CloudCoverageReached {
		t.Fatalf("a readable surface should still read reached, got %s", got)
	}
	t.Log("PASS: the readable surfaces were still scanned and reported separately")
}

// A complete scan, on the other hand, is allowed to age out what is genuinely
// gone.
func TestIAMCompleteScanReconcilesDeletedPrincipals(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-reconcile")
	defer cleanIdentities(t, db, ws)

	fake := populatedIAM()
	scanner, connectorID := scanFixture(t, db, ws, fake)
	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}

	// The user, and therefore both of its access keys, is deleted in AWS.
	fake.users = nil
	fake.keys = map[string][]iamtypes.AccessKeyMetadata{}

	snap, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snap.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("expected complete, got %s", snap.Coverage.Status)
	}
	if snap.Coverage.Counters["identities_removed"] != 1 {
		t.Fatalf("the deleted user should have been aged out, counters=%v", snap.Coverage.Counters)
	}
	if snap.Coverage.Counters["secrets_removed"] != 2 {
		t.Fatalf("its two access keys should have gone with it, counters=%v", snap.Coverage.Counters)
	}
	t.Log("PASS: complete scan aged out the deleted user and its keys")

	repo := repositories.NewCloudIdentityRepository(db)
	if _, err := repo.GetIdentityByNativeID(ws, ciUserARN); !errors.Is(err, repositories.ErrCloudIdentityNotFound) {
		t.Fatalf("the user should be gone, got %v", err)
	}
	if _, total, _ := repo.ListIdentities(ws, repositories.CloudIdentityFilter{}); total != 2 {
		t.Fatalf("the two roles should survive, got %d", total)
	}
	t.Log("PASS: the surviving roles were untouched")
}

// Throttling is reported as throttling, not as a denial — they lead to
// different operator actions.
func TestIAMThrottlingIsReportedDistinctlyFromDenial(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-throttle")
	defer cleanIdentities(t, db, ws)

	fake := populatedIAM()
	fake.fail["GetAccountAuthorizationDetails:User"] = throttled("iam:GetAccountAuthorizationDetails")
	scanner, connectorID := scanFixture(t, db, ws, fake)

	snap, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := snap.Coverage.Surfaces[models.SurfaceIAMUsers].State; got != models.CloudCoverageThrottled {
		t.Fatalf("expected throttled, got %s", got)
	}
	if got := snap.Coverage.Surfaces[models.SurfaceIAMRoles].State; got != models.CloudCoverageReached {
		t.Fatalf("roles were readable and should read reached, got %s", got)
	}
	if snap.Coverage.Status != models.ScanStatusPartial {
		t.Fatalf("expected partial, got %s", snap.Coverage.Status)
	}
	t.Log("PASS: throttled and denied are distinguishable in the coverage report")
}

// Pagination must run to completion — a scan that silently stops at page one
// reports a fraction of the estate as if it were all of it.
func TestIAMPaginationRunsToCompletion(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-pages")
	defer cleanIdentities(t, db, ws)

	fake := newFakeIAM()
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("role-%02d", i)
		fake.roles = append(fake.roles, iamtypes.Role{
			Arn:        aws.String("arn:aws:iam::429418377036:role/" + name),
			RoleName:   aws.String(name),
			RoleId:     aws.String(fmt.Sprintf("AROAPAGE%02d", i)),
			CreateDate: ago(time.Duration(i) * 24 * time.Hour),
		})
	}
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("user-%02d", i)
		fake.users = append(fake.users, iamtypes.User{
			Arn:        aws.String("arn:aws:iam::429418377036:user/" + name),
			UserName:   aws.String(name),
			UserId:     aws.String(fmt.Sprintf("AIDAPAGE%02d", i)),
			CreateDate: ago(time.Duration(i) * 24 * time.Hour),
		})
	}
	fake.pageSize = 4 // forces 7 pages of roles and 3 of users

	scanner, connectorID := scanFixture(t, db, ws, fake)
	snap, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if got := snap.Coverage.Surfaces[models.SurfaceIAMRoles].Count; got != 25 {
		t.Fatalf("pagination lost roles: got %d of 25", got)
	}
	if got := snap.Coverage.Surfaces[models.SurfaceIAMUsers].Count; got != 12 {
		t.Fatalf("pagination lost users: got %d of 12", got)
	}
	if got := fake.calls["GetAccountAuthorizationDetails:Role"]; got < 7 {
		t.Fatalf("expected at least 7 role pages at size 4, saw %d calls", got)
	}
	_, total, _ := repositories.NewCloudIdentityRepository(db).
		ListIdentities(ws, repositories.CloudIdentityFilter{Limit: 500})
	if total != 37 {
		t.Fatalf("expected 37 identities across all pages, got %d", total)
	}
	t.Logf("PASS: %d roles over %d pages and %d users over %d pages, all persisted",
		25, fake.calls["GetAccountAuthorizationDetails:Role"], 12, fake.calls["GetAccountAuthorizationDetails:User"])
}

// Managed policy documents are cached: AWS-managed policies are attached to
// many roles, and ReadOnlyAccess alone is a very large document.
func TestIAMManagedPolicyDocumentsAreFetchedOncePerPolicy(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-cache")
	defer cleanIdentities(t, db, ws)

	fake := newFakeIAM()
	shared := "arn:aws:iam::aws:policy/ReadOnlyAccess"
	fake.managedPolicies[shared] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("shared-%02d", i)
		fake.roles = append(fake.roles, iamtypes.Role{
			Arn: aws.String("arn:aws:iam::429418377036:role/" + name), RoleName: aws.String(name),
			RoleId: aws.String(fmt.Sprintf("AROASHARED%02d", i)), CreateDate: ago(time.Hour),
		})
		fake.attachedRolePolicies[name] = []iamtypes.AttachedPolicy{
			{PolicyArn: aws.String(shared), PolicyName: aws.String("ReadOnlyAccess")},
		}
	}

	scanner, connectorID := scanFixture(t, db, ws, fake)
	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if fake.calls["GetPolicyVersion"] != 1 {
		t.Fatalf("ten roles sharing one policy should fetch it once, saw %d fetches",
			fake.calls["GetPolicyVersion"])
	}
	t.Logf("PASS: one document fetch served %d roles", 10)
}

// A connector that cannot be authenticated records a failed scan rather than
// leaving the previous report in place, where a broken connection would keep
// displaying a stale all-clear.
func TestIAMScanOnUnusableConnectorIsRecordedAsFailed(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-unusable")
	defer cleanIdentities(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	// No IAM client injected and the stub verifier cannot produce a config, so
	// the scanner cannot authenticate.
	scanner := services.NewAWSIAMScanner(db, svc)

	if _, err := scanner.Scan(context.Background(), ws, c.ID); err == nil {
		t.Fatal("expected the scan to fail")
	}

	reloaded, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	cov := models.DecodeScanCoverage(reloaded.Coverage)
	if cov.Status != models.ScanStatusFailed {
		t.Fatalf("expected a failed scan recorded, got %q", cov.Status)
	}
	if cov.Error == "" {
		t.Fatal("a failed scan must record why")
	}
	if reloaded.ScanGeneration != 0 {
		t.Fatalf("a scan that never ran must not advance the generation, got %d",
			reloaded.ScanGeneration)
	}
	t.Logf("PASS: recorded as failed (%s), generation not advanced", truncate(cov.Error, 60))
}

// Revoking a connector keeps what it found. A revoked connection says "we can
// no longer read this account", not "what we already found is gone" -- the
// customer's own audit trail must survive them disconnecting AWS, and
// re-onboarding the same account later reactivates this same connector rather
// than starting a second, disconnected history.
func TestIAMRevokingConnectorKeepsIdentitiesAndSecrets(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-revoke")
	defer cleanIdentities(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	scanner := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM())
	if _, err := scanner.Scan(context.Background(), ws, c.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var before int64
	db.Raw(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ?`, ws).Scan(&before)
	if before == 0 {
		t.Fatal("test setup: scan should have written identities")
	}

	if err := svc.RevokeConnector(ws, c.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	var identities, secrets int64
	db.Raw(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ?`, ws).Scan(&identities)
	db.Raw(`SELECT count(*) FROM cloud_secret WHERE workspace_id = ?`, ws).Scan(&secrets)
	if identities != before {
		t.Fatalf("revoking should keep discovered identities for audit, had %d before, %d after",
			before, identities)
	}
	if secrets == 0 {
		t.Fatal("revoking should keep discovered secret metadata for audit, found none")
	}
	t.Log("PASS: identities and secret metadata kept, unchanged, after revoke")
}

// No secret value can reach the database, because there is no column for one.
func TestIAMNoSecretValueIsEverPersisted(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-iam-nosecret")
	defer cleanIdentities(t, db, ws)

	scanner, connectorID := scanFixture(t, db, ws, populatedIAM())
	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// cloud_secret has no column that could hold a value. Assert it structurally
	// rather than by checking the rows, so a future column addition fails here.
	var cols []string
	db.Raw(`SELECT column_name FROM information_schema.columns
	        WHERE table_name = 'cloud_secret' ORDER BY column_name`).Scan(&cols)
	for _, c := range cols {
		for _, forbidden := range []string{"value", "secret", "password", "material", "private"} {
			if strings.Contains(c, forbidden) && c != "connector_id" {
				t.Fatalf("cloud_secret.%s looks like it could hold secret material", c)
			}
		}
	}
	t.Logf("PASS: no value-bearing column among %d in cloud_secret", len(cols))

	var dump string
	db.Raw(`SELECT coalesce(string_agg(row_to_json(t)::text, ' '), '') FROM cloud_secret t
	        WHERE workspace_id = ?`, ws).Row().Scan(&dump)
	if !strings.Contains(dump, "AKIAOLDANDACTIVE") {
		t.Fatal("the key IDENTIFIER should be recorded")
	}
	t.Log("PASS: key identifiers recorded, and there is nowhere for a value to go")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Compile-time proof that the fake satisfies the real interface. If the
// scanner ever needs another IAM operation, this fails until the fake grows it
// — which is what stops a new call going untested.
var _ awsdiscovery.IAMAPI = (*fakeIAM)(nil)
