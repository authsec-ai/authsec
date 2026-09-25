package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Quick Create sessions and the CloudFormation callback, end to end inside the
// service: Redis is real (miniredis), Onboard and the regional verifier are
// fakes, and every PUT to CloudFormation is captured instead of sent.

const (
	qcTopicAPS    = "arn:aws:sns:ap-south-1:111111111111:authsec-cfn-callback"
	qcTopicUSE    = "arn:aws:sns:us-east-1:111111111111:authsec-cfn-callback"
	qcAccount     = "222222222222"
	qcPrincipal   = "arn:aws:iam::111111111111:role/AuthSecDiscovery"
	qcResponseURL = "https://cloudformation-custom-resource-response-apsouth1.s3-ap-south-1.amazonaws.com/obj?X-Amz-Signature=supersecretsig"
)

type capturedPut struct {
	url  string
	body awsdiscovery.CFNResponse
}

type fakeTransport struct {
	mu     sync.Mutex
	status int
	puts   []capturedPut
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	var body awsdiscovery.CFNResponse
	_ = json.Unmarshal(raw, &body)
	f.puts = append(f.puts, capturedPut{url: r.URL.String(), body: body})
	if r.Header.Get("Content-Type") != "" {
		return nil, fmt.Errorf("Content-Type must not be sent to a presigned URL")
	}
	status := f.status
	if status == 0 {
		status = 200
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func (f *fakeTransport) last(t *testing.T) awsdiscovery.CFNResponse {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.puts) == 0 {
		t.Fatal("no response was sent to CloudFormation")
	}
	return f.puts[len(f.puts)-1].body
}

func (f *fakeTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}

type fakeRegionVerifier struct{ fail map[string]error }

func (v fakeRegionVerifier) Verify(_ context.Context, req awsdiscovery.AssumeRequest) (*awsdiscovery.Identity, error) {
	if err := v.fail[req.Region]; err != nil {
		return nil, err
	}
	return &awsdiscovery.Identity{AccountID: qcAccount}, nil
}

type qcHarness struct {
	svc        *AWSQuickCreateService
	mr         *miniredis.Miniredis
	transport  *fakeTransport
	onboards   int
	onboardErr func(attempt int) error
	lastInput  AWSOnboardInput
	clock      time.Time
	existing   *models.CloudConnector
	verifier   fakeRegionVerifier
	clockMu    sync.Mutex
}

func newQCHarness(t *testing.T) *qcHarness {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	cfg, err := awsdiscovery.ParseCallbackConfig(
		fmt.Sprintf(`{"ap-south-1":%q,"us-east-1":%q}`, qcTopicAPS, qcTopicUSE),
		"https://sqs.us-east-1.amazonaws.com/111111111111/authsec-cfn-callback",
		"https://bucket.s3.us-east-1.amazonaws.com", "", "af-south-1")
	if err != nil {
		t.Fatal(err)
	}
	h := &qcHarness{mr: mr, transport: &fakeTransport{}, clock: time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)}
	h.verifier = fakeRegionVerifier{fail: map[string]error{}}
	h.svc = &AWSQuickCreateService{
		redis:     redis.NewClient(&redis.Options{Addr: mr.Addr()}),
		cfg:       cfg,
		principal: qcPrincipal,
		http:      &http.Client{Transport: h.transport},
		now:       func() time.Time { h.clockMu.Lock(); defer h.clockMu.Unlock(); return h.clock },
		// Sleeping advances the fake clock, so retry budgets are exercised
		// without waiting for them.
		sleep: func(_ context.Context, d time.Duration) error {
			h.clockMu.Lock()
			defer h.clockMu.Unlock()
			h.clock = h.clock.Add(d)
			return nil
		},
		onboard: func(_ context.Context, ws uuid.UUID, in AWSOnboardInput, _ string) (*models.CloudConnector, bool, error) {
			h.onboards++
			h.lastInput = in
			if h.onboardErr != nil {
				if err := h.onboardErr(h.onboards); err != nil {
					return nil, false, err
				}
			}
			return &models.CloudConnector{ID: uuid.New(), WorkspaceID: ws, ScopeID: qcAccount}, true, nil
		},
		existing:      func(uuid.UUID, string) (*models.CloudConnector, error) { return h.existing, nil },
		templateCheck: func(context.Context, string) error { return nil },
	}
	h.svc.verifier = &h.verifier
	return h
}

func (h *qcHarness) start(t *testing.T, regions ...string) *AWSOnboardingSession {
	t.Helper()
	sess, err := h.svc.StartSession(context.Background(), uuid.New(), "admin@example.com", regions, "")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

type cfnMsg struct {
	requestType, requestID, topic, stackRegion, stackAccount, roleAccount, externalID, responseURL string
}

func (h *qcHarness) body(sess *AWSOnboardingSession, m cfnMsg) string {
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	stackRegion := def(m.stackRegion, "ap-south-1")
	stackAccount := def(m.stackAccount, qcAccount)
	roleName := "AuthSecCloudDiscovery-x"
	if sess != nil {
		roleName = sess.RoleName
	}
	ext := m.externalID
	if ext == "" && sess != nil {
		ext = sess.ExternalID
	}
	req := map[string]any{
		"RequestType":       def(m.requestType, "Create"),
		"RequestId":         def(m.requestID, "req-1"),
		"StackId":           "arn:aws:cloudformation:" + stackRegion + ":" + stackAccount + ":stack/AuthSec-Discovery-x/2d213470-3bbd-11ea-a35f-06b8fd1f0384",
		"ResponseURL":       def(m.responseURL, qcResponseURL),
		"ResourceType":      awsdiscovery.RegistrationResourceType,
		"LogicalResourceId": awsdiscovery.RegistrationLogicalID,
		"ResourceProperties": map[string]string{
			"RoleArn":    "arn:aws:iam::" + def(m.roleAccount, stackAccount) + ":role/" + roleName,
			"ExternalId": ext,
			"AccountId":  stackAccount,
		},
	}
	if m.requestType == "Delete" || m.requestType == "Update" {
		req["PhysicalResourceId"] = "authsec-something"
	}
	raw, _ := json.Marshal(req)
	env, _ := json.Marshal(map[string]string{
		"Type": "Notification", "MessageId": uuid.NewString(), "TopicArn": def(m.topic, qcTopicAPS),
		"Message": string(raw), "Timestamp": h.clock.Format(time.RFC3339Nano),
	})
	return string(env)
}

func (h *qcHarness) handle(t *testing.T, body string) CallbackOutcome {
	t.Helper()
	return h.svc.HandleCallbackMessage(context.Background(), body)
}

func (h *qcHarness) session(t *testing.T, sess *AWSOnboardingSession) *AWSOnboardingSession {
	t.Helper()
	got, err := h.svc.GetSession(context.Background(), sess.WorkspaceID, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

/* --------------------------------- sessions -------------------------------- */

func TestQuickCreateStartSession(t *testing.T) {
	h := newQCHarness(t)

	// Deployment region: the first selected region that can host the stack, and
	// it moves to the front because Onboard probes regions[0].
	sess := h.start(t, "eu-west-1", "ap-south-1", "af-south-1")
	if sess.DeploymentRegion != "ap-south-1" || strings.Join(sess.Regions, ",") != "ap-south-1,eu-west-1,af-south-1" {
		t.Fatalf("deployment %s regions %v", sess.DeploymentRegion, sess.Regions)
	}
	if sess.StackName != "AuthSec-Discovery-"+sess.Suffix || sess.RoleName != "AuthSecCloudDiscovery-"+sess.Suffix ||
		len(sess.RoleName) > 64 {
		t.Fatalf("stack/role names must share the suffix: %s %s", sess.StackName, sess.RoleName)
	}
	for _, want := range []string{"ap-south-1.console.aws.amazon.com", "param_CallbackTopicArn=" + strings.ReplaceAll(qcTopicAPS, ":", "%3A"), "param_RoleName=" + sess.RoleName} {
		if !strings.Contains(sess.QuickCreateURL, want) {
			t.Fatalf("quick create URL missing %q:\n%s", want, sess.QuickCreateURL)
		}
	}

	// No selected region can host the stack: fall back to a supported one.
	if s2 := h.start(t, "eu-west-1"); s2.DeploymentRegion != "ap-south-1" {
		t.Fatalf("fallback deployment region: %s", s2.DeploymentRegion)
	}

	for name, c := range map[string]struct {
		regions []string
		dr      string
	}{
		"govcloud":               {[]string{"us-gov-west-1"}, ""},
		"china":                  {[]string{"cn-north-1"}, ""},
		"opt-in not enabled":     {[]string{"me-south-1"}, ""},
		"empty":                  {nil, ""},
		"unsupported deployment": {[]string{"eu-west-1"}, "eu-west-1"},
		"opt-in deployment":      {[]string{"af-south-1"}, "af-south-1"},
	} {
		_, err := h.svc.StartSession(context.Background(), uuid.New(), "a", c.regions, c.dr)
		var oe *AWSOnbError
		if !errors.As(err, &oe) || oe.Code != AWSOnbCodeInvalidRegions {
			t.Fatalf("%s: expected %s, got %v", name, AWSOnbCodeInvalidRegions, err)
		}
	}

	// Another workspace's session reads as absent.
	if _, err := h.svc.GetSession(context.Background(), uuid.New(), sess.ID); !errors.Is(err, ErrAWSOnbSessionNotFound) {
		t.Fatalf("cross-workspace read must be not-found, got %v", err)
	}

	// Template not published: refuse before a customer gets a broken link.
	h.svc.templateCheck = func(context.Context, string) error { return errors.New("HTTP 404") }
	_, err := h.svc.StartSession(context.Background(), uuid.New(), "a", []string{"ap-south-1"}, "")
	var oe *AWSOnbError
	if !errors.As(err, &oe) || oe.Code != AWSOnbCodeTemplateMissing {
		t.Fatalf("expected %s, got %v", AWSOnbCodeTemplateMissing, err)
	}
}

/* --------------------------------- callback -------------------------------- */

func TestQuickCreateCallbackConnects(t *testing.T) {
	h := newQCHarness(t)
	h.verifier.fail["eu-west-1"] = fmt.Errorf("%w: denied by SCP (AccessDenied)", awsdiscovery.ErrNotAssumable)
	sess := h.start(t, "ap-south-1", "eu-west-1")

	if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackDone {
		t.Fatalf("outcome %s", out)
	}
	resp := h.transport.last(t)
	if resp.Status != awsdiscovery.CFNStatusSuccess || resp.PhysicalResourceID != "authsec-"+sess.ID.String() {
		t.Fatalf("response %+v", resp)
	}
	if h.onboards != 1 || h.lastInput.ExternalID != sess.ExternalID || strings.Join(h.lastInput.Regions, ",") != "ap-south-1,eu-west-1" {
		t.Fatalf("Onboard must run once with the session's values: %d %+v", h.onboards, h.lastInput)
	}
	got := h.session(t, sess)
	if got.Status != AWSOnbConnected || got.AccountID != qcAccount || got.ConnectorID == nil {
		t.Fatalf("session %+v", got)
	}
	if got.RegionStatus["ap-south-1"].Status != "connected" ||
		got.RegionStatus["eu-west-1"].Status != "not_reachable" || got.RegionStatus["eu-west-1"].Reason != "blocked" {
		t.Fatalf("region status %+v", got.RegionStatus)
	}

	// Duplicate delivery of the same request: replayed, never re-onboarded.
	if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackDone || h.onboards != 1 ||
		h.transport.last(t).Status != awsdiscovery.CFNStatusSuccess {
		t.Fatalf("duplicate must replay SUCCESS without Onboard: out=%s onboards=%d", out, h.onboards)
	}

	// Single use: a different role through the same link is refused.
	other := h.body(sess, cfnMsg{requestID: "req-2"})
	other = strings.Replace(other, sess.RoleName, "SomethingElse", 1)
	if out := h.handle(t, other); out != CallbackDone || h.onboards != 1 {
		t.Fatalf("reuse must not onboard: %s", out)
	}
	if r := h.transport.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "already used") {
		t.Fatalf("reuse response %+v", r)
	}
}

func TestQuickCreateCallbackRejectionsNeverOnboard(t *testing.T) {
	cases := map[string]struct {
		msg        cfnMsg
		wantOut    CallbackOutcome
		wantStatus string // "" = nothing sent
		wantReason string
	}{
		"unknown external id": {cfnMsg{externalID: strings.Repeat("a", 24) + "." + strings.Repeat("b", 32)},
			CallbackDone, awsdiscovery.CFNStatusFailed, "expired"},
		"topic region differs from stack": {cfnMsg{topic: qcTopicUSE},
			CallbackDone, awsdiscovery.CFNStatusFailed, "different AWS Region"},
		"role in another account": {cfnMsg{roleAccount: "333333333333"},
			CallbackDone, awsdiscovery.CFNStatusFailed, "different AWS accounts"},
		"foreign topic": {cfnMsg{topic: "arn:aws:sns:ap-south-1:999999999999:authsec-cfn-callback"},
			CallbackReject, "", ""},
		"response URL off the allow-list": {cfnMsg{responseURL: "https://attacker.example/obj?X-Amz-Signature=x"},
			CallbackReject, "", ""},
		"response URL with dashed bucket": {cfnMsg{responseURL: strings.Replace(qcResponseURL, "apsouth1", "ap-south-1", 1)},
			CallbackReject, "", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newQCHarness(t)
			sess := h.start(t, "ap-south-1")
			if out := h.handle(t, h.body(sess, c.msg)); out != c.wantOut {
				t.Fatalf("outcome %s, want %s", out, c.wantOut)
			}
			if h.onboards != 0 {
				t.Fatal("a rejected callback must never reach Onboard")
			}
			if c.wantStatus == "" {
				if h.transport.count() != 0 {
					t.Fatal("a rejected callback must never contact its ResponseURL")
				}
				return
			}
			if r := h.transport.last(t); r.Status != c.wantStatus || !strings.Contains(r.Reason, c.wantReason) {
				t.Fatalf("response %+v", r)
			}
		})
	}
}

func TestQuickCreateDeleteAndUpdateAlwaysSucceed(t *testing.T) {
	for _, rt := range []string{"Delete", "Update"} {
		h := newQCHarness(t)
		// No session at all: a Delete for an unknown or expired stack still
		// succeeds, or the customer could not delete their stack.
		if out := h.handle(t, h.body(nil, cfnMsg{requestType: rt, externalID: "whatever"})); out != CallbackDone {
			t.Fatalf("%s outcome %s", rt, out)
		}
		if r := h.transport.last(t); r.Status != awsdiscovery.CFNStatusSuccess || r.PhysicalResourceID != "authsec-something" {
			t.Fatalf("%s response %+v", rt, r)
		}
		if h.onboards != 0 {
			t.Fatalf("%s must never onboard", rt)
		}
	}
}

func TestQuickCreateRetryClassification(t *testing.T) {
	t.Run("IAM propagation then success", func(t *testing.T) {
		h := newQCHarness(t)
		sess := h.start(t, "ap-south-1")
		h.onboardErr = func(n int) error {
			if n < 3 {
				return fmt.Errorf("%w: AccessDenied", awsdiscovery.ErrNotAssumable)
			}
			return nil
		}
		if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackDone || h.onboards != 3 ||
			h.transport.last(t).Status != awsdiscovery.CFNStatusSuccess {
			t.Fatalf("out=%s onboards=%d", out, h.onboards)
		}
	})
	t.Run("trust never accepted", func(t *testing.T) {
		h := newQCHarness(t)
		sess := h.start(t, "ap-south-1")
		h.onboardErr = func(int) error { return fmt.Errorf("%w: AccessDenied", awsdiscovery.ErrNotAssumable) }
		h.handle(t, h.body(sess, cfnMsg{}))
		if r := h.transport.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "could not assume") {
			t.Fatalf("response %+v", r)
		}
		if got := h.session(t, sess); got.Status != AWSOnbFailed || got.Code != AWSOnbCodeAssumeDenied {
			t.Fatalf("session %s %s", got.Status, got.Code)
		}
	})
	t.Run("AuthSec side until the deadline", func(t *testing.T) {
		h := newQCHarness(t)
		sess := h.start(t, "ap-south-1")
		h.onboardErr = func(int) error { return errors.New("failed to store the external id: vault down") }
		h.handle(t, h.body(sess, cfnMsg{}))
		if r := h.transport.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "Try again later") {
			t.Fatalf("response %+v", r)
		}
		if got := h.session(t, sess); got.Code != AWSOnbCodeAuthSecUnavailable {
			t.Fatalf("code %s", got.Code)
		}
		if h.onboards < 3 {
			t.Fatalf("an AuthSec-side failure must be retried, got %d attempts", h.onboards)
		}
	})
}

func TestQuickCreateDeadResponseURLIsFlagged(t *testing.T) {
	h := newQCHarness(t)
	h.transport.status = 403
	sess := h.start(t, "ap-south-1")
	if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackDone {
		t.Fatalf("outcome %s", out)
	}
	got := h.session(t, sess)
	// The probes save the session after the answer; the flag must survive them.
	if got.Status != AWSOnbConnected || !got.ResponsePutFailed || len(got.RegionStatus) == 0 {
		t.Fatalf("session %+v", got)
	}
}

func TestQuickCreateTransientResponseIsRetried(t *testing.T) {
	h := newQCHarness(t)
	h.transport.status = 503
	sess := h.start(t, "ap-south-1")
	if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackRetry {
		t.Fatalf("a 5xx answer must leave the message for redelivery, got %s", out)
	}
	h.transport.status = 200
	if out := h.handle(t, h.body(sess, cfnMsg{})); out != CallbackDone || h.onboards != 1 {
		t.Fatalf("redelivery must replay without a second Onboard: out=%s onboards=%d", out, h.onboards)
	}
	if got := h.session(t, sess); len(got.RegionStatus) == 0 {
		t.Fatal("probes must run once the answer is finally delivered")
	}
}

func TestQuickCreateLogsNeverCarrySignature(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)

	h := newQCHarness(t)
	h.transport.status = 403
	sess := h.start(t, "ap-south-1")
	h.handle(t, h.body(sess, cfnMsg{}))
	h.handle(t, h.body(sess, cfnMsg{responseURL: "https://attacker.example/obj?X-Amz-Signature=supersecretsig"}))
	if strings.Contains(buf.String(), "supersecretsig") {
		t.Fatalf("a presigned signature reached the logs:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), sess.ExternalID) {
		t.Fatal("the raw ExternalId reached the logs")
	}
}

/* ------------------------------ hardening fixes ---------------------------- */

// B4: a duplicate delivery that finds the session locked must never answer —
// not even past the deadline — or its FAILED could overtake the holder's SUCCESS.
func TestQuickCreateLockContentionNeverAnswers(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.mr.Set(awsOnbLockKey(sess.ID), "someone-else")
	body := h.body(sess, cfnMsg{})
	h.clock = h.clock.Add(awsCallbackDeadline + time.Minute) // past the deadline
	if out := h.svc.HandleCallbackDelivery(context.Background(), body, true); out != CallbackRetry {
		t.Fatalf("contention must retry, got %s", out)
	}
	if h.transport.count() != 0 || h.onboards != 0 {
		t.Fatal("a contended delivery must neither answer nor onboard")
	}
	if v, _ := h.mr.Get(awsOnbLockKey(sess.ID)); v != "someone-else" {
		t.Fatal("another worker's lock must never be released")
	}
}

// B5: once Onboard succeeded, a failed session save still answers SUCCESS.
func TestQuickCreateSaveFailureAfterConnectStillSucceeds(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.onboardErr = func(int) error {
		h.mr.SetError("READONLY You can't write against a read only replica")
		return nil
	}
	h.handle(t, h.body(sess, cfnMsg{}))
	h.mr.SetError("")
	if r := h.transport.last(t); r.Status != "SUCCESS" {
		t.Fatalf("a proven connection must be answered SUCCESS, got %+v", r)
	}
}

// B6: AuthSec's own bad credentials are AuthSec's fault, not the customer's.
func TestQuickCreateAuthSecCredentialErrorIsNotCustomerFault(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.onboardErr = func(int) error {
		return fmt.Errorf("%w: The security token included in the request is invalid. (InvalidClientTokenId)",
			awsdiscovery.ErrNotAssumable)
	}
	h.handle(t, h.body(sess, cfnMsg{}))
	if got := h.session(t, sess); got.Code != AWSOnbCodeAuthSecUnavailable {
		t.Fatalf("expected %s, got %s", AWSOnbCodeAuthSecUnavailable, got.Code)
	}
}

// B15: an AuthSec-side failure that does not heal fails fast, not at the deadline.
func TestQuickCreatePersistentAuthSecErrorFailsFast(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	start := h.clock
	h.onboardErr = func(int) error { return errors.New("failed to store the external id: 404 no handler for route kv/") }
	h.handle(t, h.body(sess, cfnMsg{}))
	if waited := h.clock.Sub(start); waited > 2*awsAuthSecErrorBudget {
		t.Fatalf("waited %s; a persistent AuthSec error must fail within about %s", waited, awsAuthSecErrorBudget)
	}
	if got := h.session(t, sess); got.Code != AWSOnbCodeAuthSecUnavailable {
		t.Fatalf("code %s", got.Code)
	}
}

// B3: a failure that does heal is retried, but no attempt starts once the
// answer reserve is near, so the answer always beats the deadline.
func TestQuickCreateRetryStopsBeforeAnswerReserve(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	body := h.body(sess, cfnMsg{})
	published := h.clock
	h.onboardErr = func(int) error { return fmt.Errorf("%w: rate exceeded", awsdiscovery.ErrThrottled) }
	h.handle(t, body)
	lastStart := published.Add(awsCallbackDeadline - awsAnswerReserve - awsOnboardingTimeout)
	if h.clock.After(lastStart) {
		t.Fatalf("retrying ran to %s, past the last allowed start %s", h.clock, lastStart)
	}
	if r := h.transport.last(t); r.Status != "FAILED" {
		t.Fatalf("expected FAILED, got %+v", r)
	}
}

// B13: past the attempt cap nothing is written, so forged messages cannot grow
// the session or keep it alive.
func TestQuickCreateCappedSessionIsNotWritten(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	for i := 0; i < awsCallbackMaxAttempts+3; i++ {
		h.handle(t, h.body(sess, cfnMsg{requestID: fmt.Sprintf("forged-%d", i), topic: qcTopicUSE}))
	}
	got := h.session(t, sess)
	if got.Attempts != awsCallbackMaxAttempts {
		t.Fatalf("attempts %d, want the cap %d", got.Attempts, awsCallbackMaxAttempts)
	}
	if len(got.Results) > awsCallbackMaxAttempts {
		t.Fatalf("%d results stored past the cap", len(got.Results))
	}
}

// B13: a finished session's lifetime is fixed when it finishes.
func TestQuickCreateTerminalLifetimeIsFixed(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.handle(t, h.body(sess, cfnMsg{}))
	first := h.session(t, sess).ExpiresAt
	h.clock = h.clock.Add(30 * time.Minute)
	h.handle(t, h.body(sess, cfnMsg{requestID: "late", roleAccount: "333333333333"}))
	if got := h.session(t, sess).ExpiresAt; !got.Equal(first) {
		t.Fatalf("a later message extended the session from %s to %s", first, got)
	}
}

// B10: an opt-in region is never the one Onboard probes when a default-enabled
// region is selected.
func TestQuickCreateOptInRegionIsNeverProbedFirst(t *testing.T) {
	h := newQCHarness(t)
	sess, err := h.svc.StartSession(context.Background(), uuid.New(), "a", []string{"af-south-1", "eu-west-1"}, "ap-south-1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Regions[0] != "eu-west-1" {
		t.Fatalf("regions %v: an opt-in region must not come first", sess.Regions)
	}
}

// The launch link goes back only to the user who started the session — decided
// on the per-user id, because the actor can be a client id every user shares.
func TestQuickCreateStartedBy(t *testing.T) {
	s := &AWSOnboardingSession{CreatedBy: "shared-client", CreatorUserID: "user-a"}
	if !s.StartedBy("user-a", "shared-client") {
		t.Fatal("the creator must be recognised")
	}
	if s.StartedBy("user-b", "shared-client") {
		t.Fatal("another user with the same shared client id must not be treated as the creator")
	}
	if s.StartedBy("", "shared-client") {
		t.Fatal("an unknown user must not be treated as the creator")
	}
	legacy := &AWSOnboardingSession{CreatedBy: "user-a"}
	if !legacy.StartedBy("", "user-a") || legacy.StartedBy("", "user-b") {
		t.Fatal("a session without a recorded user id falls back to the actor")
	}
}

func TestAWSCallbackConcurrencyFromEnv(t *testing.T) {
	for in, want := range map[string]int{"": awsCallbackConcurrency, "abc": awsCallbackConcurrency,
		"0": awsCallbackConcurrency, "40": 40, "100000": awsCallbackMaxConcurrency} {
		t.Setenv(envAWSCallbackConcurrency, in)
		if got := awsCallbackConcurrencyFromEnv(); got != want {
			t.Fatalf("%q: got %d want %d", in, got, want)
		}
	}
}
