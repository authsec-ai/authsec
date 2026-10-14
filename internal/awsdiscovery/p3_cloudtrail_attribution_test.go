package awsdiscovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// T3.04 (SPEC-iga-phase3-policy.md §8.6): the CloudTrail reader attributes a
// session to its issuer by sessionContext.sessionIssuer (ARN + RoleId), keeps
// the session name, marks only the authorization error codes as denials, and
// classifies the denial from errorMessage's documented phrase -- all from
// recorded CloudTrail records (testdata/cloudtrail), never an AWS call.

const (
	refundRoleARN = "arn:aws:iam::429418377036:role/service-role/RefundTaskRole"
	refundRoleID  = "AROAWJ4EXAMPLEREFUND1"
)

// recordedTrail answers LookupEvents with the recorded records, each wrapped
// the way LookupEvents returns it: the typed fields CloudTrail fills from the
// record, and the record itself as CloudTrailEvent.
type recordedTrail struct{ events []cttypes.Event }

func (r *recordedTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: r.events}, nil
}

func (r *recordedTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (r *recordedTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{}, nil
}

// recorded loads one fixture as LookupEvents would return it. username is
// LookupEvents' own Username for that record: the session name for an
// assumed role, the user name for an IAM user.
func recorded(t *testing.T, file, eventName, username string) cttypes.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cloudtrail", file))
	if err != nil {
		t.Fatalf("read fixture %s: %v", file, err)
	}
	return cttypes.Event{
		EventId: aws.String(file), EventName: aws.String(eventName),
		EventTime: aws.Time(time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)),
		Username:  aws.String(username), CloudTrailEvent: aws.String(string(raw)),
	}
}

func readOne(t *testing.T, e cttypes.Event) TrailEvent {
	t.Helper()
	got, err := NewCloudTrailReader(&recordedTrail{events: []cttypes.Event{e}}).RecentEvents(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("RecentEvents = %v, %v; want one event", got, err)
	}
	return got[0]
}

// The case the old reader got wrong both ways: an assumed-role session whose
// RoleSessionName ("ci-deployer") is an IAM USER's name. LookupEvents' Username
// is the session name, so a Username match filed RefundTaskRole's denied call
// under the user ci-deployer, and never under the role. Attribution is the
// session issuer: the role's ARN (with its path) and its RoleId.
//
// Safeguard (mutation-checked): the session_issuer branch of Attribution.
func TestP3T304AssumedRoleIsAttributedBySessionIssuer(t *testing.T) {
	e := readOne(t, recorded(t, "assumed_role_boundary_denied.json", "ListQueues", "ci-deployer"))

	att := e.Attribution()
	if att.How != AttributionSessionIssuer || att.ARN != refundRoleARN || att.UniqueID != refundRoleID {
		t.Fatalf("attribution = %+v, want the session issuer %s (%s)", att, refundRoleARN, refundRoleID)
	}
	if att.UserName != "" {
		t.Fatalf("attribution carries a user name %q: a session must never be matched by name", att.UserName)
	}
	if e.PrincipalType != "AssumedRole" || e.SessionIssuerType != "Role" ||
		e.SessionIssuerARN != refundRoleARN || e.SessionIssuerPrincipalID != refundRoleID {
		t.Fatalf("principal = %+v", e)
	}
	if e.SessionName != "ci-deployer" {
		t.Fatalf("session name = %q, want the last segment of the assumed-role ARN", e.SessionName)
	}
	if e.ErrorCode != "AccessDenied" || !e.Denied || !e.AuthorizationDenied {
		t.Fatalf("error = %q denied=%v authorization_denied=%v, want an AccessDenied authorization denial",
			e.ErrorCode, e.Denied, e.AuthorizationDenied)
	}
	if e.DenialPolicyType != DenialPermissionsBoundary {
		t.Fatalf("denial_policy_type = %q, want %q (\"because no permissions boundary allows\")",
			e.DenialPolicyType, DenialPermissionsBoundary)
	}
}

// Every recorded record, read through the reader: attribution, the session
// name, which error codes are authorization denials, and the classification.
func TestP3T304RecordedEvents(t *testing.T) {
	for _, tc := range []struct {
		file, eventName, username string
		how, arn, uniqueID        string
		session                   string
		errorCode                 string
		authz                     bool
		denial                    string
	}{
		{"assumed_role_success.json", "ListBuckets", "refund-handler",
			AttributionSessionIssuer, refundRoleARN, refundRoleID, "refund-handler", "", false, ""},
		{"assumed_role_boundary_denied.json", "ListQueues", "ci-deployer",
			AttributionSessionIssuer, refundRoleARN, refundRoleID, "ci-deployer", "AccessDenied", true, DenialPermissionsBoundary},
		// An EC2 instance-profile session: the encoded authorization message
		// names no policy type, so the cause is unknown -- never guessed.
		{"ec2_unauthorized_encoded.json", "RunInstances", "i-0abc1234def567890",
			AttributionSessionIssuer, refundRoleARN, refundRoleID, "i-0abc1234def567890", "Client.UnauthorizedOperation", true, DenialUnknown},
		// A throttle is an error, not a denial: the legacy denied flag stays
		// true (any error code), authorization_denied does not.
		{"assumed_role_throttled.json", "DescribeTable", "refund-handler",
			AttributionSessionIssuer, refundRoleARN, refundRoleID, "refund-handler", "ThrottlingException", false, ""},
		// An IAM user's own call: by its ARN and AIDA id, and no session name.
		{"iam_user_scp_explicit_deny.json", "CreateUser", "ci-deployer",
			AttributionPrincipalARN, "arn:aws:iam::429418377036:user/ci-deployer", "AIDAWJ4EXAMPLEDEPLOY1", "", "AccessDenied", true, DenialSCP},
		// Another account's role calling into this one: its issuer is named
		// (the caller finds no identity of this connector under it).
		{"cross_account_assumed_role.json", "GetBucketPolicy", "partner-sync",
			AttributionSessionIssuer, "arn:aws:iam::905418271234:role/PartnerSync", "AROAZZ9EXAMPLEPARTNR", "partner-sync", "AccessDenied", true, DenialResourcePolicy},
		// An AWS service principal: nothing to attribute to.
		{"aws_service.json", "GenerateDataKey", "",
			"", "", "", "", "", false, ""},
	} {
		t.Run(tc.file, func(t *testing.T) {
			e := readOne(t, recorded(t, tc.file, tc.eventName, tc.username))
			att := e.Attribution()
			if att.How != tc.how || att.ARN != tc.arn || att.UniqueID != tc.uniqueID {
				t.Errorf("attribution = %+v, want {%s %s %s}", att, tc.how, tc.arn, tc.uniqueID)
			}
			if e.SessionName != tc.session {
				t.Errorf("session name = %q, want %q", e.SessionName, tc.session)
			}
			if e.ErrorCode != tc.errorCode || e.Denied != (tc.errorCode != "") {
				t.Errorf("error code = %q denied=%v, want %q", e.ErrorCode, e.Denied, tc.errorCode)
			}
			if e.AuthorizationDenied != tc.authz || e.DenialPolicyType != tc.denial {
				t.Errorf("authorization_denied=%v denial_policy_type=%q, want %v %q",
					e.AuthorizationDenied, e.DenialPolicyType, tc.authz, tc.denial)
			}
		})
	}
}

// A record with no userIdentity (the only shape of the legacy fixtures, and
// of a LookupEvents result whose CloudTrailEvent could not be read) keeps the
// old hint, Username, and says so; a record that does not decode keeps its
// error code from the narrow scan.
func TestP3T304RecordWithoutUserIdentity(t *testing.T) {
	e := readOne(t, cttypes.Event{EventId: aws.String("legacy"), Username: aws.String("ci-deployer"),
		CloudTrailEvent: aws.String(`{"errorCode":"AccessDenied"}`)})
	if att := e.Attribution(); att.How != AttributionUsername || att.UserName != "ci-deployer" || att.ARN != "" {
		t.Fatalf("attribution = %+v, want the username hint", att)
	}
	if !e.AuthorizationDenied || e.DenialPolicyType != DenialUnknown {
		t.Fatalf("authorization_denied=%v denial_policy_type=%q, want true / unknown (no message)", e.AuthorizationDenied, e.DenialPolicyType)
	}

	broken := readOne(t, cttypes.Event{EventId: aws.String("broken"),
		CloudTrailEvent: aws.String(`{"errorCode":"AccessDenied", truncated`)})
	if broken.ErrorCode != "AccessDenied" || !broken.Denied || !broken.AuthorizationDenied {
		t.Fatalf("undecodable record = %+v, want its error code kept", broken)
	}
	if att := broken.Attribution(); att.How != "" {
		t.Fatalf("undecodable record with no username attributed: %+v", att)
	}

	// An assumed role whose record omits its issuer is NOT matched by name.
	noIssuer := readOne(t, cttypes.Event{EventId: aws.String("no-issuer"), Username: aws.String("ci-deployer"),
		CloudTrailEvent: aws.String(`{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::429418377036:assumed-role/X/ci-deployer","principalId":"AROAX:ci-deployer"}}`)})
	if att := noIssuer.Attribution(); att.How != "" {
		t.Fatalf("an assumed role without a session issuer was attributed: %+v", att)
	}
	if noIssuer.SessionName != "ci-deployer" {
		t.Fatalf("session name = %q", noIssuer.SessionName)
	}
}

// ClassifyDenial over AWS's documented phrases, implicit and explicit, and the
// messages that name no type this enum has.
//
// Safeguard (mutation-checked): the anchoring on the reason clause.
func TestP3T304ClassifyDenial(t *testing.T) {
	const pre = "User: arn:aws:sts::429418377036:assumed-role/R/s is not authorized to perform: s3:GetObject on resource: arn:aws:s3:::b/k "
	for msg, want := range map[string]string{
		pre + "because no permissions boundary allows the s3:GetObject action":   DenialPermissionsBoundary,
		pre + "with an explicit deny in a permissions boundary":                  DenialPermissionsBoundary,
		pre + "because no identity-based policy allows the s3:GetObject action":  DenialIdentityPolicy,
		pre + "with an explicit deny in an identity-based policy":                DenialIdentityPolicy,
		pre + "because no service control policy allows the s3:GetObject action": DenialSCP,
		pre + "with an explicit deny in a service control policy":                DenialSCP,
		pre + "with an explicit deny in a resource control policy":               DenialRCP,
		pre + "because no resource-based policy allows the s3:GetObject action":  DenialResourcePolicy,
		pre + "with an explicit deny in a resource-based policy":                 DenialResourcePolicy,
		pre + "because no session policy allows the s3:GetObject action":         DenialSessionPolicy,
		pre + "with an explicit deny in a session policy":                        DenialSessionPolicy,
		pre + "because no VPC endpoint policy allows the s3:GetObject action":    DenialUnknown,
		"Access Denied": DenialUnknown,
		"":              DenialUnknown,
		"You are not authorized to perform this operation. Encoded authorization failure": DenialUnknown,
		// The phrase outside a reason clause is not a reason.
		"Request to the permissions boundary service failed": DenialUnknown,
		// Case of the documented phrase does not matter.
		pre + "Because no Permissions Boundary allows the s3:GetObject action": DenialPermissionsBoundary,
	} {
		if got := ClassifyDenial(msg); got != want {
			t.Errorf("ClassifyDenial(%q) = %q, want %q", msg, got, want)
		}
	}
}
