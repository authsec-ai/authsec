package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
)

// The AWS SDK path, exercised against a server that speaks the real STS wire
// protocol.
//
// This is not a mock of our own code — it is our real LiveVerifier, the real
// aws-sdk-go-v2 client, real SigV4 signing, the real stscreds assume-role
// provider and real XML response parsing. Only the far end is local.
//
// It proves the things that are ours to get wrong: that AssumeRole is actually
// called with the ExternalId and session name we intend, that GetCallerIdentity
// is called with the ASSUMED credentials rather than the base ones, that the
// response is parsed into an Identity correctly, and that an AWS error is
// classified into the right sentinel.
//
// It cannot prove that a real AWS account will accept the call, that the
// template's actions are real IAM actions, or how STS behaves under sustained
// throttling. Those need a live account.

/* ------------------------------ the fake STS ------------------------------ */

type stsWireServer struct {
	mu sync.Mutex
	// requests records the decoded form body of every call, in order.
	requests []map[string]string
	// assumeStatus / assumeBody let a test make AssumeRole fail.
	assumeStatus int
	assumeBody   string
}

const (
	assumedRoleARN = "arn:aws:sts::429418377036:assumed-role/AuthSecCloudDiscovery/authsec-onboarding-deadbeef"
	assumedRoleID  = "AROAEXAMPLEID:authsec-onboarding-deadbeef"
	wireAccount    = "429418377036"
)

func (s *stsWireServer) handler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			form[k] = v[0]
		}
	}
	// The Authorization header proves the request was actually SigV4-signed.
	form["_authorization"] = r.Header.Get("Authorization")

	s.mu.Lock()
	s.requests = append(s.requests, form)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/xml")

	switch form["Action"] {
	case "AssumeRole":
		if s.assumeStatus != 0 {
			w.WriteHeader(s.assumeStatus)
			fmt.Fprint(w, s.assumeBody)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAWIRETESTKEY</AccessKeyId>
      <SecretAccessKey>wire-test-secret</SecretAccessKey>
      <SessionToken>wire-test-session-token</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>%s</Arn>
      <AssumedRoleId>%s</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>req-assume</RequestId></ResponseMetadata>
</AssumeRoleResponse>`, assumedRoleARN, assumedRoleID)

	case "GetCallerIdentity":
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>%s</Arn>
    <UserId>%s</UserId>
    <Account>%s</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>req-identity</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`, assumedRoleARN, assumedRoleID, wireAccount)

	default:
		http.Error(w, "unexpected action "+form["Action"], http.StatusBadRequest)
	}
}

func (s *stsWireServer) callsFor(action string) []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]string
	for _, r := range s.requests {
		if r["Action"] == action {
			out = append(out, r)
		}
	}
	return out
}

// startWireSTS points the SDK at a local server for the duration of a test.
// AWS_ENDPOINT_URL_STS is the SDK's own service-specific endpoint override, so
// no production code changes to make this testable.
func startWireSTS(t *testing.T, srv *stsWireServer) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)

	t.Setenv("AWS_ENDPOINT_URL_STS", ts.URL)
	t.Setenv("AWS_ENDPOINT_URL", ts.URL)
	// Base credentials: AuthSec's own identity. Bogus values are fine — the
	// point is that the SDK signs with them, not that the signature verifies.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAUTHSECBASEKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "authsec-base-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	// Never let a test reach for instance metadata or a developer's real profile.
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_PROFILE", "")
	return ts
}

func wireRequest() AssumeRequest {
	return AssumeRequest{
		RoleARN:     "arn:aws:iam::429418377036:role/AuthSecCloudDiscovery",
		ExternalID:  "a1b2c3d4e5f60718293a4b5c.dGVzdC1zaWduYXR1cmUtdmFsdWUwMTI",
		Region:      "us-east-1",
		SessionName: "authsec-onboarding-deadbeef",
	}
}

/* ---------------------------------- tests --------------------------------- */

// The whole assume-then-identify path over the real SDK.
func TestWireAssumeRoleThenGetCallerIdentity(t *testing.T) {
	srv := &stsWireServer{}
	startWireSTS(t, srv)

	req := wireRequest()
	identity, err := NewLiveVerifier().Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("verify over the wire: %v", err)
	}

	if identity.AccountID != wireAccount {
		t.Fatalf("account not parsed, got %q", identity.AccountID)
	}
	if identity.ARN != assumedRoleARN || identity.UserID != assumedRoleID {
		t.Fatalf("identity not parsed: %+v", identity)
	}
	t.Logf("PASS: parsed account=%s arn=%s", identity.AccountID, identity.ARN)

	// AssumeRole must have carried the ExternalId. This is the single most
	// important field on the call — without it the customer's trust policy
	// condition can never be satisfied, and the failure would only show up
	// against a real account.
	assumes := srv.callsFor("AssumeRole")
	if len(assumes) != 1 {
		t.Fatalf("expected exactly one AssumeRole, got %d", len(assumes))
	}
	a := assumes[0]
	if a["ExternalId"] != req.ExternalID {
		t.Fatalf("ExternalId not sent to AWS: got %q want %q", a["ExternalId"], req.ExternalID)
	}
	if a["RoleArn"] != req.RoleARN {
		t.Fatalf("RoleArn not sent: got %q", a["RoleArn"])
	}
	if a["RoleSessionName"] != req.SessionName {
		t.Fatalf("RoleSessionName not sent: got %q", a["RoleSessionName"])
	}
	t.Logf("PASS: AssumeRole carried ExternalId, RoleArn and RoleSessionName")

	// The request was really SigV4-signed with the BASE credentials.
	if !strings.Contains(a["_authorization"], "AWS4-HMAC-SHA256") ||
		!strings.Contains(a["_authorization"], "AKIAAUTHSECBASEKEY") {
		t.Fatalf("AssumeRole was not signed with the base credentials: %q", a["_authorization"])
	}
	t.Log("PASS: AssumeRole signed with AuthSec's own credentials")

	// GetCallerIdentity must be signed with the ASSUMED credentials, not the
	// base ones. If it were not, the probe would report AuthSec's own identity
	// and every onboarding would record the wrong account.
	ids := srv.callsFor("GetCallerIdentity")
	if len(ids) != 1 {
		t.Fatalf("expected exactly one GetCallerIdentity, got %d", len(ids))
	}
	auth := ids[0]["_authorization"]
	if !strings.Contains(auth, "ASIAWIRETESTKEY") {
		t.Fatalf("GetCallerIdentity was not signed with the assumed credentials: %q", auth)
	}
	if strings.Contains(auth, "AKIAAUTHSECBASEKEY") {
		t.Fatal("GetCallerIdentity was signed with the BASE credentials; it would report the wrong account")
	}
	t.Log("PASS: GetCallerIdentity signed with the assumed role's credentials")
}

// A trust-policy or ExternalId mismatch is what a customer will actually hit.
// It must arrive as ErrNotAssumable so the API answers 400 with
// fault: customer_account, not a 500.
func TestWireAccessDeniedBecomesNotAssumable(t *testing.T) {
	srv := &stsWireServer{
		assumeStatus: http.StatusForbidden,
		assumeBody: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: arn:aws:iam::429418377036:user/authsec is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::429418377036:role/AuthSecCloudDiscovery</Message>
  </Error>
  <RequestId>req-denied</RequestId>
</ErrorResponse>`,
	}
	startWireSTS(t, srv)

	_, err := NewLiveVerifier().Verify(context.Background(), wireRequest())
	if !errors.Is(err, ErrNotAssumable) {
		t.Fatalf("an AccessDenied from STS must classify as ErrNotAssumable, got %v", err)
	}
	if !strings.Contains(err.Error(), "not authorized to perform") {
		t.Fatalf("AWS's own message should survive so the operator can read it: %v", err)
	}
	t.Logf("PASS: classified as not-assumable, AWS message preserved")

	// A denied assume must not retry: it is a permanent answer, and retrying it
	// eight times just makes the console wait.
	if n := len(srv.callsFor("AssumeRole")); n != 1 {
		t.Fatalf("AccessDenied should not be retried, saw %d attempts", n)
	}
	t.Log("PASS: not retried")
}

// The onboarding probe must never reach GetCallerIdentity if the assume failed.
func TestWireFailedAssumeSkipsTheIdentityCall(t *testing.T) {
	srv := &stsWireServer{
		assumeStatus: http.StatusForbidden,
		assumeBody: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied</Message></Error>
</ErrorResponse>`,
	}
	startWireSTS(t, srv)

	if _, err := NewLiveVerifier().Verify(context.Background(), wireRequest()); err == nil {
		t.Fatal("expected failure")
	}
	if n := len(srv.callsFor("GetCallerIdentity")); n != 0 {
		t.Fatalf("identity should not be probed after a failed assume, saw %d calls", n)
	}
	t.Log("PASS: no identity call after a failed assume")
}

// Validation happens before any network call, so a malformed request costs
// nothing and names the field.
func TestWireBadRequestNeverReachesTheNetwork(t *testing.T) {
	srv := &stsWireServer{}
	startWireSTS(t, srv)

	bad := wireRequest()
	bad.ExternalID = "too-short"

	if _, err := NewLiveVerifier().Verify(context.Background(), bad); err == nil {
		t.Fatal("a short external id must be refused")
	}
	if len(srv.requests) != 0 {
		t.Fatalf("nothing should have been sent to AWS, saw %d requests", len(srv.requests))
	}
	t.Log("PASS: refused locally, no request sent")
}

// classify is ours; the retryer is the SDK's. This covers the mapping directly
// rather than trying to provoke sustained throttling over the wire, which would
// mean sitting through the SDK's backoff.
func TestClassifyMapsAWSErrorCodes(t *testing.T) {
	cases := []struct {
		code string
		want error
	}{
		{"AccessDenied", ErrNotAssumable},
		{"AccessDeniedException", ErrNotAssumable},
		{"InvalidClientTokenId", ErrNotAssumable},
		{"SignatureDoesNotMatch", ErrNotAssumable},
		{"ExpiredToken", ErrNotAssumable},
		{"MalformedPolicyDocument", ErrNotAssumable},
		{"Throttling", ErrThrottled},
		{"ThrottlingException", ErrThrottled},
		{"RequestLimitExceeded", ErrThrottled},
		{"TooManyRequestsException", ErrThrottled},
	}
	for _, tc := range cases {
		err := classify(&smithy.GenericAPIError{Code: tc.code, Message: "boom"})
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s should map to %v, got %v", tc.code, tc.want, err)
		}
	}
	// Anything unrecognised stays legible rather than being forced into a
	// sentinel that would send it to the wrong place.
	other := classify(&smithy.GenericAPIError{Code: "ServiceUnavailable", Message: "later"})
	if errors.Is(other, ErrNotAssumable) || errors.Is(other, ErrThrottled) {
		t.Fatalf("an unknown code must not be forced into a sentinel: %v", other)
	}
	if !strings.Contains(other.Error(), "ServiceUnavailable") {
		t.Fatalf("an unknown code must keep its code: %v", other)
	}
	t.Logf("PASS: %d error codes mapped, unknown codes preserved", len(cases))
}

// ParseRoleARN is what stops a user ARN, a wildcard or a different partition
// being recorded as a discovery role.
func TestParseRoleARN(t *testing.T) {
	good := map[string][2]string{
		"arn:aws:iam::429418377036:role/AuthSecCloudDiscovery": {"aws", "429418377036"},
		"arn:aws:iam::429418377036:role/some/path/Nested":      {"aws", "429418377036"},
		"arn:aws-us-gov:iam::429418377036:role/GovRole":        {"aws-us-gov", "429418377036"},
		"arn:aws-cn:iam::429418377036:role/CnRole":             {"aws-cn", "429418377036"},
		"  arn:aws:iam::429418377036:role/Padded  ":            {"aws", "429418377036"},
	}
	for arn, want := range good {
		p, a, err := ParseRoleARN(arn)
		if err != nil {
			t.Fatalf("%q should parse: %v", arn, err)
		}
		if p != want[0] || a != want[1] {
			t.Fatalf("%q gave %s/%s, want %s/%s", arn, p, a, want[0], want[1])
		}
	}
	bad := []string{
		"", "not-an-arn",
		"arn:aws:iam::429418377036:user/someone",
		"arn:aws:iam::429418377036:role/",
		"arn:aws:iam::42941837703:role/TooShortAccount",
		"arn:aws:sts::429418377036:assumed-role/X/Y",
		"arn:aws:iam::*:role/Wildcard",
	}
	for _, arn := range bad {
		if _, _, err := ParseRoleARN(arn); err == nil {
			t.Fatalf("%q should have been refused", arn)
		}
	}
	t.Logf("PASS: %d role ARNs accepted, %d refused", len(good), len(bad))
}

// Region validation is a shape check, deliberately not an allow-list.
func TestValidateRegion(t *testing.T) {
	for _, r := range []string{
		"us-east-1", "eu-west-2", "ap-southeast-3", "ca-central-1",
		"us-gov-west-1", "cn-north-1", "il-central-1", "ap-southeast-7",
	} {
		if err := ValidateRegion(r); err != nil {
			t.Fatalf("%q is a real region: %v", r, err)
		}
	}
	for _, r := range []string{"", "US-EAST-1", "useast1", "moon-central-1", "us-east", "us-east-1a"} {
		if err := ValidateRegion(r); err == nil {
			t.Fatalf("%q should have been refused", r)
		}
	}
	t.Log("PASS: region shape check accepts real regions and refuses malformed ones")
}

// The embedded template and the permission list are what a customer deploys and
// what a reviewer reads. They must stay in step.
func TestTemplateAndPermissionListAgree(t *testing.T) {
	if !strings.Contains(CloudFormationTemplate, "AWSTemplateFormatVersion") {
		t.Fatal("the CloudFormation template did not embed")
	}
	if !strings.Contains(CloudFormationTemplate, "Value: '"+TemplateVersion+"'") {
		t.Fatalf("the template's TemplateVersion output does not match the constant %q", TemplateVersion)
	}
	// Every action the Go list advertises must actually be granted by the
	// template, or the console shows a permission the stack never creates.
	for _, p := range AdditionalPermissions() {
		for _, action := range p.Actions {
			if !strings.Contains(CloudFormationTemplate, action) {
				t.Fatalf("permission list advertises %q but the template does not grant it", action)
			}
		}
	}
	for _, p := range HardDenies() {
		for _, action := range p.Actions {
			if !strings.Contains(CloudFormationTemplate, action) {
				t.Fatalf("permission list advertises a deny on %q but the template does not deny it", action)
			}
		}
	}
	// The denies exist to make "no secret values" structural. If one is ever
	// dropped from the template, this fails.
	for _, must := range []string{
		"secretsmanager:GetSecretValue", "ssm:GetParameter", "kms:Decrypt", "sts:AssumeRole",
	} {
		if !strings.Contains(CloudFormationTemplate, must) {
			t.Fatalf("the template must explicitly deny %s", must)
		}
	}
	t.Log("PASS: template embedded, version matches, and every advertised permission is in it")
}
