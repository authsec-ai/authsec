package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
)

// IGA Phase 2 S2 (T2.1, T2.4): ec2:DescribeRegions through the discovery
// role, the classification of its failures, and the failed-call facts
// coverage records. Over the REAL SDK against a local server speaking the STS
// and EC2 query protocols, like onboarding_wire_test.go: the error chains the
// SDK builds are what FailedCall and the assume/denied split must survive, and
// a hand-built chain would only prove what the test author assumed.

type s2RegionsWire struct {
	mu       sync.Mutex
	requests []map[string]string

	assumeStatus  int
	assumeBody    string
	regionsStatus int
	regionsBody   string
}

func (s *s2RegionsWire) handler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := map[string]string{"_authorization": r.Header.Get("Authorization")}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			form[k] = v[0]
		}
	}
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
      <AccessKeyId>ASIAS2REGIONSKEY</AccessKeyId>
      <SecretAccessKey>s2-secret</SecretAccessKey>
      <SessionToken>s2-session</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser><Arn>%s</Arn><AssumedRoleId>%s</AssumedRoleId></AssumedRoleUser>
  </AssumeRoleResult>
  <ResponseMetadata><RequestId>req-assume</RequestId></ResponseMetadata>
</AssumeRoleResponse>`, assumedRoleARN, assumedRoleID)
	case "DescribeRegions":
		if s.regionsStatus != 0 {
			w.WriteHeader(s.regionsStatus)
			fmt.Fprint(w, s.regionsBody)
			return
		}
		fmt.Fprint(w, `<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <requestId>req-regions</requestId>
  <regionInfo>
    <item><regionName>us-east-1</regionName><regionEndpoint>ec2.us-east-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>
    <item><regionName>me-central-1</regionName><regionEndpoint>ec2.me-central-1.amazonaws.com</regionEndpoint><optInStatus>opted-in</optInStatus></item>
    <item><regionName>eu-central-1</regionName><regionEndpoint>ec2.eu-central-1.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>
  </regionInfo>
</DescribeRegionsResponse>`)
	default:
		http.Error(w, "unexpected action "+form["Action"], http.StatusBadRequest)
	}
}

func (s *s2RegionsWire) calls(action string) []map[string]string {
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

// s2StartWire points every SDK client at srv, with bogus base credentials and
// no route to instance metadata or a developer profile.
func s2StartWire(t *testing.T, srv *s2RegionsWire) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(srv.handler))
	t.Cleanup(ts.Close)
	t.Setenv("AWS_ENDPOINT_URL", ts.URL)
	t.Setenv("AWS_ENDPOINT_URL_STS", ts.URL)
	t.Setenv("AWS_ENDPOINT_URL_EC2", ts.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAUTHSECBASEKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "authsec-base-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_PROFILE", "")
}

func s2Regions(t *testing.T) ([]Region, error) {
	t.Helper()
	cfg, err := NewLiveVerifier().Config(context.Background(), wireRequest())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return EnabledRegions(context.Background(), NewRegionsClient(cfg))
}

// The enabled regions, through the assumed role, asked with AllRegions=false.
func TestS2EnabledRegionsOverTheWire(t *testing.T) {
	srv := &s2RegionsWire{}
	s2StartWire(t, srv)

	regions, err := s2Regions(t)
	if err != nil {
		t.Fatalf("enabled regions: %v", err)
	}
	got := fmt.Sprint(regions)
	want := "[{eu-central-1 opt-in-not-required} {me-central-1 opted-in} {us-east-1 opt-in-not-required}]"
	if got != want {
		t.Fatalf("regions = %s, want %s (sorted, with AWS's opt-in status)", got, want)
	}
	calls := srv.calls("DescribeRegions")
	if len(calls) != 1 {
		t.Fatalf("DescribeRegions calls = %d, want 1", len(calls))
	}
	// AllRegions=false is what makes the answer "ENABLED regions": with true,
	// AWS also lists regions the account never opted in to.
	if calls[0]["AllRegions"] != "false" {
		t.Fatalf("DescribeRegions AllRegions = %q, want false", calls[0]["AllRegions"])
	}
	if !strings.Contains(calls[0]["_authorization"], "ASIAS2REGIONSKEY") {
		t.Fatalf("DescribeRegions was not signed with the ASSUMED role: %q", calls[0]["_authorization"])
	}
}

// A DENIED DescribeRegions is the region grant's failure, NOT the assume's: it
// must never read as ErrNotAssumable (whose remedy is the trust policy), and
// it must name the call and the code AWS returned.
func TestS2DeniedDescribeRegionsIsNotAnAssumeFailure(t *testing.T) {
	srv := &s2RegionsWire{
		regionsStatus: http.StatusForbidden,
		regionsBody: `<Response><Errors><Error><Code>UnauthorizedOperation</Code>` +
			`<Message>You are not authorized to perform this operation.</Message></Error></Errors>` +
			`<RequestID>req-denied</RequestID></Response>`,
	}
	s2StartWire(t, srv)

	_, err := s2Regions(t)
	if !errors.Is(err, ErrRegionsDenied) {
		t.Fatalf("a refused DescribeRegions = %v, want ErrRegionsDenied", err)
	}
	if errors.Is(err, ErrNotAssumable) {
		t.Fatalf("a refused DescribeRegions classified as not-assumable: %v", err)
	}
	api, code := FailedCall(err)
	if api != "ec2:DescribeRegions" || code != "UnauthorizedOperation" {
		t.Fatalf("FailedCall = (%q, %q), want (ec2:DescribeRegions, UnauthorizedOperation)", api, code)
	}
	if !strings.Contains(err.Error(), "not authorized to perform this operation") {
		t.Fatalf("AWS's own message must survive: %v", err)
	}
}

// The credential provider assumes LAZILY, so a refused AssumeRole arrives
// wrapped in the DescribeRegions operation. That is the connection failing,
// and it must stay ErrNotAssumable -- with the INNER call named.
func TestS2AssumeFailureUnderDescribeRegionsIsNotAssumable(t *testing.T) {
	srv := &s2RegionsWire{
		assumeStatus: http.StatusForbidden,
		assumeBody: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code>
  <Message>User is not authorized to perform: sts:AssumeRole</Message></Error>
  <RequestId>req-denied</RequestId>
</ErrorResponse>`,
	}
	s2StartWire(t, srv)

	_, err := s2Regions(t)
	if !errors.Is(err, ErrNotAssumable) {
		t.Fatalf("a refused assume under DescribeRegions = %v, want ErrNotAssumable", err)
	}
	if errors.Is(err, ErrRegionsDenied) {
		t.Fatalf("a refused ASSUME was reported as a refused DescribeRegions: %v", err)
	}
	if api, code := FailedCall(err); api != "sts:AssumeRole" || code != "AccessDenied" {
		t.Fatalf("FailedCall = (%q, %q), want the inner call (sts:AssumeRole, AccessDenied)", api, code)
	}
	if n := len(srv.calls("DescribeRegions")); n != 0 {
		t.Fatalf("DescribeRegions reached AWS %d times with no credentials", n)
	}
}

// classify keeps the SDK error in the chain, so coverage can record the call
// and the code (§5.3 /coverage error_code, api). A fake's bare error carries
// neither, and FailedCall must then say nothing rather than guess.
//
// And a call refused to the ASSUMED role is not an assume failure: the message
// names the call and AWS's code, never "the role could not be assumed" -- a
// cause the response never stated, which used to land in every denied
// surface's coverage.
func TestS2ClassifyKeepsTheFailedCall(t *testing.T) {
	op := &smithy.OperationError{ServiceID: "Lambda", OperationName: "ListFunctions",
		Err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no lambda for you"}}
	err := classify(op)
	if got, want := err.Error(), "AWS refused the call lambda:ListFunctions: no lambda for you (AccessDeniedException)"; got != want {
		t.Fatalf("classify message:\n got %q\nwant %q", got, want)
	}
	if !errors.Is(err, ErrCallDenied) || errors.Is(err, ErrNotAssumable) {
		t.Fatalf("a refused Lambda call = %v, want ErrCallDenied and not ErrNotAssumable", err)
	}
	if api, code := FailedCall(err); api != "lambda:ListFunctions" || code != "AccessDeniedException" {
		t.Fatalf("FailedCall = (%q, %q), want (lambda:ListFunctions, AccessDeniedException)", api, code)
	}
	// STS's own refusal IS the assume failing -- directly, or wrapped in the
	// call whose credentials it was fetching.
	sts := &smithy.OperationError{ServiceID: "STS", OperationName: "AssumeRole",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform sts:AssumeRole"}}
	for name, e := range map[string]error{
		"direct":  sts,
		"wrapped": &smithy.OperationError{ServiceID: "Lambda", OperationName: "ListFunctions", Err: sts},
	} {
		c := classify(e)
		if !errors.Is(c, ErrNotAssumable) || errors.Is(c, ErrCallDenied) ||
			c.Error() != "the role could not be assumed: not authorized to perform sts:AssumeRole (AccessDenied)" {
			t.Fatalf("%s STS refusal = %v, want ErrNotAssumable with its old message", name, c)
		}
	}
	// No operation in the chain: which call failed is unknown, and the old
	// classification stands.
	if bare := classify(&smithy.GenericAPIError{Code: "AccessDenied", Message: "no"}); !errors.Is(bare, ErrNotAssumable) {
		t.Fatalf("a bare AccessDenied = %v, want the unchanged ErrNotAssumable", bare)
	}

	throttle := classify(&smithy.OperationError{ServiceID: "IAM", OperationName: "GetAccountAuthorizationDetails",
		Err: &smithy.GenericAPIError{Code: "Throttling", Message: "slow down"}})
	if !errors.Is(throttle, ErrThrottled) || throttle.Error() != "AWS throttled the request: slow down" {
		t.Fatalf("throttle = %v", throttle)
	}
	if api, code := FailedCall(throttle); api != "iam:GetAccountAuthorizationDetails" || code != "Throttling" {
		t.Fatalf("FailedCall(throttle) = (%q, %q)", api, code)
	}

	other := classify(&smithy.OperationError{ServiceID: "Some New Service", OperationName: "DoThing",
		Err: &smithy.GenericAPIError{Code: "Weird", Message: "odd"}})
	if other.Error() != "aws Weird: odd" {
		t.Fatalf("unclassified message = %q", other.Error())
	}
	// An unknown service is named in the SDK's own words, never mapped.
	if api, _ := FailedCall(other); api != "Some New Service:DoThing" {
		t.Fatalf("unknown service api = %q", api)
	}

	if api, code := FailedCall(errors.New("fake says no")); api != "" || code != "" {
		t.Fatalf("a bare error produced (%q, %q); FailedCall must not guess", api, code)
	}
}

// T2.4: GetGateway and DescribeRegions granted in the template AND advertised,
// and the template version declared the same in all three places.
func TestS2TemplateVersionDeclaredConsistently(t *testing.T) {
	meta := regexp.MustCompile(`(?m)^Metadata:\s*\n\s+AuthSec:\s*\n\s+TemplateVersion:\s*'([^']+)'`).
		FindStringSubmatch(strings.ReplaceAll(CloudFormationTemplate, "\r\n", "\n"))
	if meta == nil || meta[1] != TemplateVersion {
		t.Fatalf("Metadata.AuthSec.TemplateVersion = %v, want %q", meta, TemplateVersion)
	}
	out := regexp.MustCompile(`(?s)TemplateVersion:\s*\n\s+Description:.*?Value:\s*'([^']+)'`).
		FindStringSubmatch(strings.ReplaceAll(CloudFormationTemplate, "\r\n", "\n"))
	if out == nil || out[1] != TemplateVersion {
		t.Fatalf("Outputs.TemplateVersion = %v, want %q", out, TemplateVersion)
	}
	if TemplateVersion <= "2026-09-18" {
		t.Fatalf("TemplateVersion %q was not bumped past the stack that lacked GetGateway", TemplateVersion)
	}

	for _, action := range []string{"bedrock-agentcore:GetGateway", "ec2:DescribeRegions"} {
		if !regexp.MustCompile(`(?m)^\s+- ` + regexp.QuoteMeta(action) + `\s*$`).MatchString(CloudFormationTemplate) {
			t.Errorf("the template does not grant %s", action)
		}
		advertised := false
		for _, p := range AdditionalPermissions() {
			for _, a := range p.Actions {
				advertised = advertised || a == action
			}
		}
		if !advertised {
			t.Errorf("AdditionalPermissions does not advertise %s", action)
		}
	}
	for _, p := range HardDenies() {
		for _, a := range p.Actions {
			if a == "bedrock-agentcore:GetGateway" || a == "ec2:DescribeRegions" {
				t.Errorf("%s is hard-denied", a)
			}
		}
	}
}
