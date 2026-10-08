package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
)

// T3.09 (SPEC-iga-phase3-policy.md §3.5, §3.6, §4.4, §7.9; A17, A22): the
// enforcement binding against real PostgreSQL. AWS is a fake account whose
// every IAM decision simulates the enforcement role's policy from the
// embedded template (internal/awsenforce/enforcetest); Vault is the memory
// store; CloudFormation answers are captured instead of PUT.
//
// Safeguards (mutation-checked): the callback's ExternalId check (workspace
// signature + Vault equality); the cross-workspace refusal; the self-test
// role name check; verified only when every capability is ok; revoke
// deleting the ExternalId; the routes' gate and 404 for another workspace.

const (
	enfTopic       = "arn:aws:sns:us-east-1:111111111111:authsec-cfn-callback"
	enfPrincipal   = "arn:aws:iam::111111111111:role/AuthSecPrincipal"
	enfResponseURL = "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/obj?X-Amz-Signature=sig"
)

type enfPuts struct {
	mu   sync.Mutex
	puts []awsdiscovery.CFNResponse
}

func (p *enfPuts) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var body awsdiscovery.CFNResponse
	_ = json.Unmarshal(raw, &body)
	p.mu.Lock()
	p.puts = append(p.puts, body)
	p.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func (p *enfPuts) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.puts) }

func (p *enfPuts) last(t *testing.T) awsdiscovery.CFNResponse {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.puts) == 0 {
		t.Fatal("nothing was answered to CloudFormation")
	}
	return p.puts[len(p.puts)-1]
}

// enfAccount is one fake AWS account shared by the workspaces that connect
// it; fakes are per binding (each stack has its own roles and ExternalId).
type enfAWS struct {
	mu    sync.Mutex
	fakes map[string]*enforcetest.FakeAWS // by enforcement role ARN
	// edit, when set, changes each fake as it is built (e.g. A22).
	edit func(*enforcetest.FakeAWS)
}

func (a *enfAWS) AssumeEnforcement(ctx context.Context, in awsenforce.AssumeInput) (awsenforce.IAM, *awsenforce.Identity, error) {
	a.mu.Lock()
	f := a.fakes[in.RoleARN]
	a.mu.Unlock()
	if f == nil {
		return nil, nil, enforcetest.APIError("AccessDenied", "no such role")
	}
	return f.AssumeEnforcement(ctx, in)
}

// deploy creates the stack of a binding in the fake account: the enforcement
// role trusting the binding's ExternalId, and its self-test role.
func (a *enfAWS) deploy(t *testing.T, account, suffix, ext string) *enforcetest.FakeAWS {
	t.Helper()
	f, err := enforcetest.NewFakeAWSFromTemplate(awsdiscovery.EnforcementCloudFormationTemplate, account, suffix, ext)
	if err != nil {
		t.Fatal(err)
	}
	if a.edit != nil {
		a.edit(f)
	}
	a.mu.Lock()
	a.fakes[f.RoleARN] = f
	a.mu.Unlock()
	return f
}

type enfClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *enfClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *enfClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return nil
}

// enfWorkspace is one workspace with a user and an AWS connector for testAccount.
type enfWorkspace struct {
	ws, user  uuid.UUID
	connector *models.CloudConnector
}

type enfLab struct {
	db    *gorm.DB
	vault *memVault
	aws   *enfAWS
	puts  *enfPuts
	clock *enfClock
	svc   *services.EnforcementBindingService
	qc    *services.AWSQuickCreateService
	a     enfWorkspace
}

// enfPurgeOnCleanup deletes a workspace in a purge transaction, the only way
// past iga_gov_event's append-only trigger.
func enfPurgeOnCleanup(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Cleanup(func() {
		_ = db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(`SELECT set_config('authsec.workspace_purge', 'on', true)`).Error; err != nil {
				return err
			}
			return tx.Exec(`DELETE FROM workspaces WHERE id = ?`, ws).Error
		})
	})
}

func (l *enfLab) newWorkspace(t *testing.T, name string) enfWorkspace {
	t.Helper()
	ws := newWorkspace(t, l.db, name)
	enfPurgeOnCleanup(t, l.db, ws)
	user := uuid.New()
	if err := l.db.Exec(`INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`,
		user, user.String()+"@p3enf.test", ws).Error; err != nil {
		t.Fatal(err)
	}
	onb := services.NewAWSOnboardingService(l.db, l.vault).WithVerifier(okVerifier())
	c, _, err := onb.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	return enfWorkspace{ws: ws, user: user, connector: c}
}

func newEnfLab(t *testing.T) *enfLab {
	t.Helper()
	db := igaDB(t)
	cfg, err := awsdiscovery.ParseCallbackConfig(fmt.Sprintf(`{"us-east-1":%q}`, enfTopic),
		"https://sqs.us-east-1.amazonaws.com/111111111111/authsec-cfn-callback",
		"https://bucket.s3.us-east-1.amazonaws.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	l := &enfLab{db: db, vault: newMemVault(), aws: &enfAWS{fakes: map[string]*enforcetest.FakeAWS{}},
		puts: &enfPuts{}, clock: &enfClock{t: time.Now().UTC()}}
	l.svc = services.NewEnforcementBindingService(db, l.vault, cfg, enfPrincipal).
		WithAssumer(l.aws).WithClock(l.clock.now).WithSleep(l.clock.sleep).
		WithHTTPClient(&http.Client{Transport: l.puts}).
		WithTemplateCheck(func(context.Context, string) error { return nil })
	l.qc = services.NewAWSQuickCreateService(nil, nil, cfg, enfPrincipal).WithEnforcementHandler(l.svc)
	l.a = l.newWorkspace(t, "p3-enf-a")
	return l
}

func (l *enfLab) start(t *testing.T, w enfWorkspace) *services.EnforcementSession {
	t.Helper()
	sess, err := l.svc.StartSession(context.Background(), w.ws, w.connector.ID, w.user, "us-east-1")
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	return sess
}

func (l *enfLab) binding(t *testing.T, id uuid.UUID) models.CloudEnforcementBinding {
	t.Helper()
	var b models.CloudEnforcementBinding
	if err := l.db.Where("id = ?", id).First(&b).Error; err != nil {
		t.Fatal(err)
	}
	return b
}

func (l *enfLab) events(t *testing.T, ws uuid.UUID) []string {
	t.Helper()
	var names []string
	if err := l.db.Raw(`SELECT event FROM iga_gov_event WHERE workspace_id = ? ORDER BY id`, ws).Scan(&names).Error; err != nil {
		t.Fatal(err)
	}
	return names
}

// cfnBody builds the SNS notification CloudFormation's custom resource
// produces for a session's stack. mutate edits the request before encoding.
func (l *enfLab) cfnBody(sess *services.EnforcementSession, requestType string, mutate func(req map[string]any, props map[string]string)) string {
	props := map[string]string{
		"RoleArn":         "arn:aws:iam::" + sess.AccountID + ":role/" + sess.RoleName,
		"SelfTestRoleArn": "arn:aws:iam::" + sess.AccountID + ":role/" + sess.SelfTestRoleName,
		"ExternalId":      sess.ExternalID,
		"AccountId":       sess.AccountID,
		"TemplateVersion": awsdiscovery.EnforcementTemplateVersion,
	}
	req := map[string]any{
		"RequestType":       requestType,
		"RequestId":         "req-" + sess.Suffix,
		"StackId":           "arn:aws:cloudformation:us-east-1:" + sess.AccountID + ":stack/" + sess.StackName + "/2d213470-3bbd-11ea-a35f-06b8fd1f0384",
		"ResponseURL":       enfResponseURL,
		"ResourceType":      awsdiscovery.EnforcementRegistrationResourceType,
		"LogicalResourceId": awsdiscovery.EnforcementRegistrationLogicalID,
	}
	topic := enfTopic
	if mutate != nil {
		mutate(req, props)
		if v, ok := req["_topic"].(string); ok {
			topic = v
			delete(req, "_topic")
		}
	}
	req["ResourceProperties"] = props
	raw, _ := json.Marshal(req)
	env, _ := json.Marshal(map[string]string{
		"Type": "Notification", "MessageId": uuid.NewString(), "TopicArn": topic,
		"Message": string(raw), "Timestamp": l.clock.now().Format(time.RFC3339Nano),
	})
	return string(env)
}

func (l *enfLab) deliver(body string) services.CallbackOutcome {
	return l.qc.HandleCallbackDelivery(context.Background(), body, false)
}

/* ---------------------------------- tests ---------------------------------- */

// A session issues the enforcement ExternalId (Vault, cloud-enforcement path,
// never the discovery one and not usable as one), a pending binding, the
// Quick Create link for the enforcement template, and an event.
func TestP3EnfSessionIssuesExternalIDAndLink(t *testing.T) {
	l := newEnfLab(t)
	sess := l.start(t, l.a)
	b := l.binding(t, sess.BindingID)
	path := services.EnforcementExternalIDPath(l.a.ws, testAccount)
	if b.State != models.EnforcementBindingPending || b.AuthRef != path || b.AccountID != testAccount ||
		b.ConsentedBy != l.a.user || b.RoleARN != "" {
		t.Fatalf("binding = %+v, want pending with auth_ref %s", b, path)
	}
	if !strings.Contains(path, "/cloud-enforcement/aws/"+testAccount) {
		t.Fatalf("vault path %s", path)
	}
	sec, err := l.vault.ReadSecret(path)
	if err != nil || sec["external_id"] != sess.ExternalID || sess.ExternalID == "" {
		t.Fatalf("vault %v %v, want the session's ExternalId", sec, err)
	}
	disc, _ := l.vault.ReadSecret(l.a.connector.AuthRef)
	if disc["external_id"] == sess.ExternalID {
		t.Fatal("the enforcement ExternalId equals the discovery one")
	}
	if services.VerifyExternalIDBinding(l.a.ws, sess.ExternalID) == nil {
		t.Fatal("the enforcement ExternalId verifies as a discovery one")
	}
	if services.VerifyEnforcementExternalID(l.a.ws, disc["external_id"].(string)) == nil {
		t.Fatal("the discovery ExternalId verifies as an enforcement one")
	}
	if services.VerifyEnforcementExternalID(uuid.New(), sess.ExternalID) == nil {
		t.Fatal("the ExternalId verifies for another workspace")
	}
	if !sess.Automatic || !strings.Contains(sess.QuickCreateURL, "param_NameSuffix="+sess.Suffix) ||
		!strings.Contains(sess.QuickCreateURL, "AuthSec-Enforcement-"+sess.Suffix) ||
		!strings.Contains(sess.TemplateURL, "/aws/enforcement/"+awsdiscovery.EnforcementTemplateVersion+"/") ||
		sess.StackParameters["NameSuffix"] != sess.Suffix || sess.SelfTestRoleName != "AuthSecEnforcementSelfTest-"+sess.Suffix {
		t.Fatalf("session = %+v", sess)
	}
	// A second session re-opens the same pending binding with the same
	// ExternalId (stable per workspace + account).
	again := l.start(t, l.a)
	if again.BindingID != sess.BindingID || again.ExternalID != sess.ExternalID {
		t.Fatalf("second session %s/%s, want the same binding and ExternalId", again.BindingID, again.ExternalID)
	}
	if ev := l.events(t, l.a.ws); len(ev) != 2 || ev[0] != services.EventEnforcementSessionStarted {
		t.Fatalf("events = %v", ev)
	}
	// The poll hides the ExternalId from anyone but the consenting user.
	other, err := l.svc.GetSession(l.a.ws, l.a.connector.ID, sess.ID, uuid.New())
	if err != nil || other.ExternalID != "" || other.Status != "waiting_for_stack" {
		t.Fatalf("poll by another user: %+v %v", other, err)
	}
	mine, err := l.svc.GetSession(l.a.ws, l.a.connector.ID, sess.ID, l.a.user)
	if err != nil || mine.ExternalID != sess.ExternalID {
		t.Fatalf("poll by the consenting user: %+v %v", mine, err)
	}
}

// The callback binds the stack to the workspace and account, answers
// SUCCESS, and the self-test verifies every capability. A duplicate delivery
// replays SUCCESS without binding again; Delete and Update change nothing.
func TestP3EnfCallbackBindsAndVerifies(t *testing.T) {
	l := newEnfLab(t)
	sess := l.start(t, l.a)
	l.aws.deploy(t, sess.AccountID, sess.Suffix, sess.ExternalID)

	if out := l.deliver(l.cfnBody(sess, "Create", nil)); out != services.CallbackDone {
		t.Fatalf("outcome %s", out)
	}
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusSuccess || r.PhysicalResourceID != "authsec-enforcement-"+sess.BindingID.String() {
		t.Fatalf("answer = %+v", r)
	}
	b := l.binding(t, sess.BindingID)
	if b.State != models.EnforcementBindingVerified || b.VerifiedAt == nil ||
		b.RoleARN != "arn:aws:iam::"+testAccount+":role/AuthSecEnforcement-"+sess.Suffix ||
		b.SelftestRoleARN != "arn:aws:iam::"+testAccount+":role/AuthSecEnforcementSelfTest-"+sess.Suffix ||
		b.TemplateVersion != awsdiscovery.EnforcementTemplateVersion {
		t.Fatalf("binding = %+v, want verified", b)
	}
	var caps map[string]awsenforce.CapabilityResult
	_ = json.Unmarshal(b.Capabilities, &caps)
	for _, c := range awsenforce.Capabilities {
		if caps[c].Status != awsenforce.StatusOK {
			t.Errorf("capability %s = %+v", c, caps[c])
		}
	}
	if ev := l.events(t, l.a.ws); strings.Join(ev, ",") != strings.Join([]string{services.EventEnforcementSessionStarted,
		services.EventEnforcementBound, services.EventEnforcementSelfTest}, ",") {
		t.Fatalf("events = %v", ev)
	}
	if err := l.svc.RequireVerified(l.a.ws, l.a.connector.ID); err != nil {
		t.Fatalf("J3 gate on a verified binding: %v", err)
	}

	// Duplicate delivery: SUCCESS replayed, nothing written.
	n := l.puts.count()
	if out := l.deliver(l.cfnBody(sess, "Create", nil)); out != services.CallbackDone || l.puts.count() != n+1 ||
		l.puts.last(t).Status != awsdiscovery.CFNStatusSuccess {
		t.Fatalf("duplicate: %s %+v", out, l.puts.last(t))
	}
	// The same link naming other roles: FAILED (single use).
	l.deliver(l.cfnBody(sess, "Create", func(_ map[string]any, p map[string]string) {
		p["RoleArn"] = "arn:aws:iam::" + testAccount + ":role/SomethingElse"
	}))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "already used") {
		t.Fatalf("reuse with other roles: %+v", r)
	}
	for _, rt := range []string{"Update", "Delete"} {
		l.deliver(l.cfnBody(sess, rt, func(req map[string]any, _ map[string]string) {
			req["PhysicalResourceId"] = "authsec-enforcement-" + sess.BindingID.String()
		}))
		if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusSuccess {
			t.Fatalf("%s answered %+v", rt, r)
		}
	}
	if got := l.binding(t, sess.BindingID); got.State != models.EnforcementBindingVerified || got.RoleARN != b.RoleARN {
		t.Fatalf("after duplicate/Update/Delete: %+v", got)
	}
	if ev := l.events(t, l.a.ws); len(ev) != 3 {
		t.Fatalf("events after replays = %v", ev)
	}
}

// The callback is authenticated like discovery's: every forged or mismatched
// message is refused, and nothing is bound.
func TestP3EnfCallbackAuthentication(t *testing.T) {
	l := newEnfLab(t)
	sess := l.start(t, l.a)
	l.aws.deploy(t, sess.AccountID, sess.Suffix, sess.ExternalID)
	discoveryExt, _ := l.vault.ReadSecret(l.a.connector.AuthRef)
	otherWSExt, _ := services.MintEnforcementExternalID(uuid.New())
	cases := []struct {
		name    string
		mutate  func(req map[string]any, props map[string]string)
		outcome services.CallbackOutcome
		reason  string // substring of a FAILED reason; "" = not answered
	}{
		{"not our topic", func(req map[string]any, _ map[string]string) {
			req["_topic"] = "arn:aws:sns:us-east-1:999999999999:attacker"
		}, services.CallbackReject, ""},
		{"response URL host not CloudFormation's", func(req map[string]any, _ map[string]string) {
			req["ResponseURL"] = "https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com.evil.example/x?X-Amz-Signature=s"
		}, services.CallbackReject, ""},
		{"discovery ExternalId", func(_ map[string]any, p map[string]string) {
			p["ExternalId"] = discoveryExt["external_id"].(string)
		}, services.CallbackDone, "expired, or the values"},
		{"another workspace's enforcement ExternalId", func(_ map[string]any, p map[string]string) {
			p["ExternalId"] = otherWSExt
		}, services.CallbackDone, "expired, or the values"},
		{"well-signed but not the stored ExternalId", func(_ map[string]any, p map[string]string) {
			p["ExternalId"], _ = services.MintEnforcementExternalID(l.a.ws)
		}, services.CallbackDone, "expired, or the values"},
		{"role in another account", func(_ map[string]any, p map[string]string) {
			p["RoleArn"] = "arn:aws:iam::999999999999:role/AuthSecEnforcement-" + sess.Suffix
		}, services.CallbackDone, "different AWS accounts"},
		{"stack in another account", func(req map[string]any, _ map[string]string) {
			req["StackId"] = "arn:aws:cloudformation:us-east-1:999999999999:stack/" + sess.StackName + "/2d213470-3bbd-11ea-a35f-06b8fd1f0384"
		}, services.CallbackDone, "different AWS accounts"},
		{"stack region is not the topic's", func(req map[string]any, _ map[string]string) {
			req["StackId"] = "arn:aws:cloudformation:eu-west-1:" + testAccount + ":stack/" + sess.StackName + "/2d213470-3bbd-11ea-a35f-06b8fd1f0384"
			req["ResponseURL"] = "https://cloudformation-custom-resource-response-euwest1.s3.eu-west-1.amazonaws.com/obj?X-Amz-Signature=s"
		}, services.CallbackDone, "different AWS Region"},
		{"self-test role is a customer role", func(_ map[string]any, p map[string]string) {
			p["SelfTestRoleArn"] = "arn:aws:iam::" + testAccount + ":role/payments-prod"
		}, services.CallbackDone, "invalid roles"},
		{"unknown template version", func(_ map[string]any, p map[string]string) {
			p["TemplateVersion"] = "2020-01-01"
		}, services.CallbackDone, "invalid roles"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := l.puts.count()
			if out := l.deliver(l.cfnBody(sess, "Create", c.mutate)); out != c.outcome {
				t.Fatalf("outcome %s, want %s", out, c.outcome)
			}
			if c.reason == "" {
				if l.puts.count() != before {
					t.Fatalf("a rejected message was answered: %+v", l.puts.last(t))
				}
			} else if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, c.reason) {
				t.Fatalf("answer %+v, want FAILED containing %q", r, c.reason)
			}
			if b := l.binding(t, sess.BindingID); b.RoleARN != "" || b.State != models.EnforcementBindingPending {
				t.Fatalf("binding changed: %+v", b)
			}
		})
	}
	// An expired link is refused too.
	if err := l.db.Exec(`UPDATE cloud_enforcement_binding SET updated_at = now() - interval '2 hours' WHERE id = ?`, sess.BindingID).Error; err != nil {
		t.Fatal(err)
	}
	l.deliver(l.cfnBody(sess, "Create", nil))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "expired") {
		t.Fatalf("expired link answered %+v", r)
	}
	if b := l.binding(t, sess.BindingID); b.RoleARN != "" {
		t.Fatalf("expired link bound: %+v", b)
	}
	// AWS refusing the assume (trust edited) fails the stack and leaves the
	// binding unbound in error; a new session may start again.
	l.db.Exec(`UPDATE cloud_enforcement_binding SET updated_at = now() WHERE id = ?`, sess.BindingID)
	l.aws.mu.Lock()
	for _, f := range l.aws.fakes {
		f.ExternalID = "enfchanged.00000000000000000000000000000000"
	}
	l.aws.mu.Unlock()
	l.deliver(l.cfnBody(sess, "Create", nil))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "could not assume") {
		t.Fatalf("assume denied answered %+v", r)
	}
	if b := l.binding(t, sess.BindingID); b.State != models.EnforcementBindingError || b.RoleARN != "" || b.LastErrorCode != services.AWSOnbCodeAssumeDenied {
		t.Fatalf("after assume denied: %+v", b)
	}
	// Single use: a redelivery after the FAILED answer (even one that would now
	// assume) is refused; only a new session reopens the binding.
	l.aws.mu.Lock()
	for _, f := range l.aws.fakes {
		f.ExternalID = sess.ExternalID
	}
	l.aws.mu.Unlock()
	l.deliver(l.cfnBody(sess, "Create", nil))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "already used") {
		t.Fatalf("redelivery after FAILED answered %+v", r)
	}
	if b := l.binding(t, sess.BindingID); b.RoleARN != "" {
		t.Fatalf("redelivery after FAILED bound: %+v", b)
	}
	if again := l.start(t, l.a); again.BindingID != sess.BindingID || again.Status != "waiting_for_stack" {
		t.Fatalf("restart after a failed bind: %+v", again)
	}
}

// A17: one AWS account connected to two workspaces. Only one may bind it
// for enforcement; the other is refused with artifact_owned_elsewhere at
// session start, at the callback and on the manual path -- and never sees
// the first workspace's id. Another workspace's connector id is 404.
func TestP3EnfCrossWorkspaceRefusal(t *testing.T) {
	l := newEnfLab(t)
	b := l.newWorkspace(t, "p3-enf-b") // same testAccount
	ctx := context.Background()

	sessA := l.start(t, l.a)
	sessB := l.start(t, b) // B opens a session before A binds
	if sessA.ExternalID == sessB.ExternalID {
		t.Fatal("two workspaces share an enforcement ExternalId")
	}
	l.aws.deploy(t, sessA.AccountID, sessA.Suffix, sessA.ExternalID)
	l.aws.deploy(t, sessB.AccountID, sessB.Suffix, sessB.ExternalID)
	l.deliver(l.cfnBody(sessA, "Create", nil))
	if got := l.binding(t, sessA.BindingID); got.State != models.EnforcementBindingVerified {
		t.Fatalf("A = %+v", got)
	}

	// B's callback: FAILED, B unbound with the code.
	l.deliver(l.cfnBody(sessB, "Create", nil))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusFailed || !strings.Contains(r.Reason, "another AuthSec workspace") ||
		strings.Contains(r.Reason, l.a.ws.String()) {
		t.Fatalf("B's callback answered %+v", r)
	}
	if got := l.binding(t, sessB.BindingID); got.RoleARN != "" || got.LastErrorCode != services.EnfCodeOwnedElsewhere {
		t.Fatalf("B = %+v", got)
	}
	// B's new session and manual bind: 409 artifact_owned_elsewhere.
	_, err := l.svc.StartSession(ctx, b.ws, b.connector.ID, b.user, "")
	wantEnfCode(t, err, 409, services.EnfCodeOwnedElsewhere)
	if ee, _ := err.(*services.EnforcementError); ee != nil && strings.Contains(fmt.Sprint(ee.Detail), l.a.ws.String()) {
		t.Fatalf("the refusal names the other workspace: %v", ee.Detail)
	}
	if err := l.db.Exec(`UPDATE cloud_enforcement_binding SET state = 'pending', last_error_code = '' WHERE id = ?`, sessB.BindingID).Error; err != nil {
		t.Fatal(err)
	}
	_, err = l.svc.BindManual(ctx, b.ws, b.connector.ID, b.user,
		"arn:aws:iam::"+testAccount+":role/"+sessB.RoleName, "arn:aws:iam::"+testAccount+":role/"+sessB.SelfTestRoleName, "")
	wantEnfCode(t, err, 409, services.EnfCodeOwnedElsewhere)

	// B cannot see or act on A's connector: 404 on every operation.
	_, err = l.svc.Get(b.ws, l.a.connector.ID)
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.StartSession(ctx, b.ws, l.a.connector.ID, b.user, "")
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.GetSession(b.ws, l.a.connector.ID, sessA.ID, b.user)
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.GetSession(b.ws, b.connector.ID, sessA.ID, b.user) // A's session id under B's connector
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.Verify(ctx, b.ws, l.a.connector.ID, services.EnforcementActor{Kind: "user"})
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.Revoke(ctx, b.ws, l.a.connector.ID, b.user, "")
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.VerifyBinding(ctx, b.ws, sessA.BindingID, services.EnforcementActor{Kind: "system"})
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)

	// Once A revokes, B may bind.
	if _, err := l.svc.Revoke(ctx, l.a.ws, l.a.connector.ID, l.a.user, "moving to B"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.svc.BindManual(ctx, b.ws, b.connector.ID, b.user,
		"arn:aws:iam::"+testAccount+":role/"+sessB.RoleName, "arn:aws:iam::"+testAccount+":role/"+sessB.SelfTestRoleName, ""); err != nil {
		t.Fatalf("B after A revoked: %v", err)
	}
}

func wantEnfCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	ee, ok := err.(*services.EnforcementError)
	if !ok || ee.Status != status || ee.Code != code {
		t.Fatalf("err = %v, want %d %s", err, status, code)
	}
}

// A22: the stack without DeleteRolePermissionsBoundary. The binding is
// partial with detach_boundary: denied, and J3 is refused naming it. Fixing
// the stack and re-running the self-test verifies it. A fresh verified
// result is reused within the hour, a stale one is re-tested.
func TestP3EnfSelfTestPartialA22(t *testing.T) {
	l := newEnfLab(t)
	l.aws.edit = func(f *enforcetest.FakeAWS) { f.RemoveStatement("DetachOnlyAuthSecBoundaries") }
	sess := l.start(t, l.a)
	f := l.aws.deploy(t, sess.AccountID, sess.Suffix, sess.ExternalID)
	l.deliver(l.cfnBody(sess, "Create", nil))
	if r := l.puts.last(t); r.Status != awsdiscovery.CFNStatusSuccess {
		t.Fatalf("a partial binding must still answer SUCCESS (the stack exists): %+v", r)
	}
	b := l.binding(t, sess.BindingID)
	var caps map[string]awsenforce.CapabilityResult
	_ = json.Unmarshal(b.Capabilities, &caps)
	if b.State != models.EnforcementBindingPartial || caps["detach_boundary"].Status != awsenforce.StatusDenied ||
		caps["detach_boundary"].ErrorCode != "AccessDenied" || b.LastErrorCode != services.EnfCodePartial ||
		!strings.Contains(b.LastError, "detach_boundary: denied") || b.VerifiedAt != nil {
		t.Fatalf("binding = %+v caps %v", b, caps)
	}
	err := l.svc.RequireVerified(l.a.ws, l.a.connector.ID)
	wantEnfCode(t, err, 409, services.EnfCodePartial)
	if !strings.Contains(fmt.Sprint(err.(*services.EnforcementError).Detail["failing"]), "detach_boundary: denied") {
		t.Fatalf("J3 refusal does not name the capability: %v", err.(*services.EnforcementError).Detail)
	}
	view, _ := l.svc.Get(l.a.ws, l.a.connector.ID)
	if view.SetupState != "partial" || len(view.Failing) == 0 || view.Failing[0] != "detach_boundary: denied (AccessDenied)" {
		t.Fatalf("view = %+v", view)
	}

	// The customer fixes the stack; the next self-test verifies.
	fixed, _ := enforcetest.NewFakeAWSFromTemplate(awsdiscovery.EnforcementCloudFormationTemplate, testAccount, sess.Suffix, sess.ExternalID)
	f.Policy = fixed.Policy
	for _, r := range f.Roles {
		r.Boundary = "" // the operator removes the leftover test boundary by hand
	}
	v, err := l.svc.Verify(context.Background(), l.a.ws, l.a.connector.ID, services.EnforcementActor{Kind: "user", ID: l.a.user.String()})
	if err != nil || v.State != models.EnforcementBindingVerified || len(v.Failing) != 0 || v.LastSelfTestAt == nil {
		t.Fatalf("after the fix: %+v %v", v, err)
	}
	if err := l.svc.RequireVerified(l.a.ws, l.a.connector.ID); err != nil {
		t.Fatal(err)
	}
	// EnsureFresh: reused within the hour (no assume), re-run after.
	assumes := len(f.Assumes)
	if _, err := l.svc.EnsureFresh(context.Background(), l.a.ws, sess.BindingID, services.EnforcementSelfTestReuse); err != nil || len(f.Assumes) != assumes {
		t.Fatalf("fresh result re-tested: %v (%d -> %d assumes)", err, assumes, len(f.Assumes))
	}
	l.clock.sleep(context.Background(), 2*time.Hour)
	if _, err := l.svc.EnsureFresh(context.Background(), l.a.ws, sess.BindingID, services.EnforcementSelfTestReuse); err != nil || len(f.Assumes) == assumes {
		t.Fatalf("stale result not re-tested: %v", err)
	}
	// The binding's role leaving the account (stack deleted): error.
	f.AssumeErr = enforcetest.APIError("AccessDenied", "role gone")
	v, err = l.svc.Verify(context.Background(), l.a.ws, l.a.connector.ID, services.EnforcementActor{Kind: "user", ID: l.a.user.String()})
	if err != nil || v.State != models.EnforcementBindingError || v.Capabilities["assume"].Status != awsenforce.StatusDenied {
		t.Fatalf("assume lost: %+v %v", v, err)
	}
	wantEnfCode(t, l.svc.RequireVerified(l.a.ws, l.a.connector.ID), 409, services.EnfCodeNotVerified)
}

// The manual path, its checks, and revoke.
func TestP3EnfManualPathAndRevoke(t *testing.T) {
	l := newEnfLab(t)
	ctx := context.Background()
	roleARN := func(name string) string { return "arn:aws:iam::" + testAccount + ":role/" + name }

	// No session yet: the ExternalId has not been issued.
	_, err := l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN("AuthSecEnforcement-x"), roleARN("AuthSecEnforcementSelfTest-x"), "")
	wantEnfCode(t, err, 409, services.EnfCodeSessionRequired)

	sess := l.start(t, l.a)
	f := l.aws.deploy(t, sess.AccountID, sess.Suffix, sess.ExternalID)
	// The self-test target must be this binding's self-test role.
	for _, bad := range []string{roleARN("payments-prod"), roleARN("AuthSecEnforcementSelfTest-other"),
		"arn:aws:iam::" + testAccount + ":role/team/" + sess.SelfTestRoleName, "arn:aws:iam::999999999999:role/" + sess.SelfTestRoleName} {
		_, err := l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN(sess.RoleName), bad, "")
		wantEnfCode(t, err, 422, services.EnfCodeValidation)
	}
	_, err = l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, "arn:aws:iam::999999999999:role/"+sess.RoleName, roleARN(sess.SelfTestRoleName), "")
	wantEnfCode(t, err, 422, services.EnfCodeValidation)
	_, err = l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN(sess.RoleName), roleARN(sess.SelfTestRoleName), "1999-01-01")
	wantEnfCode(t, err, 422, services.EnfCodeValidation)
	if len(f.Assumes) != 0 {
		t.Fatalf("a refused manual bind assumed the role: %v", f.Assumes)
	}
	// The wrong role (not trusting this ExternalId): 422, unbound, retryable.
	_, err = l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN("NotTheEnforcementRole"), roleARN(sess.SelfTestRoleName), "")
	wantEnfCode(t, err, 422, services.EnfCodeAssumeFailed)
	if b := l.binding(t, sess.BindingID); b.State != models.EnforcementBindingError || b.RoleARN != "" {
		t.Fatalf("after a failed manual bind: %+v", b)
	}
	v, err := l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN(sess.RoleName), roleARN(sess.SelfTestRoleName), "")
	if err != nil || v.State != models.EnforcementBindingVerified || v.RoleARN != roleARN(sess.RoleName) {
		t.Fatalf("manual bind: %+v %v", v, err)
	}
	// Bound: a new session or manual bind is binding_exists.
	_, err = l.svc.StartSession(ctx, l.a.ws, l.a.connector.ID, l.a.user, "")
	wantEnfCode(t, err, 409, services.EnfCodeBindingExists)
	_, err = l.svc.BindManual(ctx, l.a.ws, l.a.connector.ID, l.a.user, roleARN(sess.RoleName), roleARN(sess.SelfTestRoleName), "")
	wantEnfCode(t, err, 409, services.EnfCodeBindingExists)

	// Revoke: revoked, the ExternalId deleted, J3 refused, an event; nothing
	// in AWS is touched.
	calls := len(f.Calls)
	res, err := l.svc.Revoke(ctx, l.a.ws, l.a.connector.ID, l.a.user, "test")
	if err != nil || res.Binding.State != models.EnforcementBindingRevoked || res.ArtifactsInAWS == nil {
		t.Fatalf("revoke: %+v %v", res, err)
	}
	if _, err := l.vault.ReadSecret(services.EnforcementExternalIDPath(l.a.ws, testAccount)); err == nil {
		t.Fatal("the enforcement ExternalId survived revoke")
	}
	if _, err := l.vault.ReadSecret(l.a.connector.AuthRef); err != nil {
		t.Fatal("revoke deleted the DISCOVERY ExternalId")
	}
	if len(f.Calls) != calls {
		t.Fatalf("revoke called AWS: %v", f.Calls[calls:])
	}
	wantEnfCode(t, l.svc.RequireVerified(l.a.ws, l.a.connector.ID), 409, services.EnfCodeNotVerified)
	view, _ := l.svc.Get(l.a.ws, l.a.connector.ID)
	if view.State != "off" || view.BindingID != nil {
		t.Fatalf("after revoke GET = %+v", view)
	}
	_, err = l.svc.Revoke(ctx, l.a.ws, l.a.connector.ID, l.a.user, "")
	wantEnfCode(t, err, 404, services.EnfCodeNotFound)
	_, err = l.svc.Verify(ctx, l.a.ws, l.a.connector.ID, services.EnforcementActor{Kind: "user"})
	wantEnfCode(t, err, 409, services.EnfCodeNotBound)
	ev := l.events(t, l.a.ws)
	if ev[len(ev)-1] != services.EventEnforcementRevoked {
		t.Fatalf("events = %v", ev)
	}
	// A later session mints a NEW ExternalId (the old stack no longer works).
	again := l.start(t, l.a)
	if again.ExternalID == sess.ExternalID || again.BindingID == sess.BindingID {
		t.Fatalf("after revoke: same ExternalId or binding (%s)", again.BindingID)
	}
}

/* ---------------------------------- routes --------------------------------- */

var enfMetricsOnce sync.Once

type enfRouteLab struct {
	*enfLab
	eng    *gin.Engine
	secret string
}

func newEnfRouteLab(t *testing.T, gate *services.PolicyGate) *enfRouteLab {
	t.Helper()
	l := newEnfLab(t)
	gin.SetMode(gin.TestMode)
	const secret = "p3-t309-jwt-secret"
	t.Setenv("JWT_SDK_SECRET", secret)
	t.Setenv("JWT_DEF_SECRET", secret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	eng := gin.New()
	discovery := eng.Group("/authsec/discovery")
	discovery.Use(middlewares.AuthMiddleware())
	platform.RegisterEnforcementBindingRoutes(discovery,
		platform.NewCloudEnforcementBindingController(l.db).WithService(l.svc).WithPolicyGate(gate), middlewares.Require)
	return &enfRouteLab{enfLab: l, eng: eng, secret: secret}
}

func (r *enfRouteLab) token(t *testing.T, w enfWorkspace, scope string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": "authsec-ai/auth-manager", "exp": time.Now().Add(time.Hour).Unix(),
		"workspace_id": w.ws.String(), "user_id": w.user.String(), "scope": scope}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(r.secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (r *enfRouteLab) call(method, path, bearer string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/authsec/discovery"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// The §7.9 routes through the production auth and permission middleware:
// the IGA_POLICY gate first, discovery:read to read and governance:enforce
// to change, the workspace from the token, 404 for another workspace's
// connector, the Phase 3 envelope, and audit_events for every mutation.
func TestP3EnfRoutes(t *testing.T) {
	db := igaDB(t)
	graphOn := p3GraphOn(t, db)
	verified := services.NewPolicyGate(true, "", graphOn)
	if err := verified.Verify(db); err != nil {
		t.Fatal(err)
	}
	base := func(c uuid.UUID) string { return "/aws/connectors/" + c.String() + "/enforcement" }

	t.Run("gate off: every route 503 policy_unavailable", func(t *testing.T) {
		r := newEnfRouteLab(t, services.NewPolicyGate(false, "", graphOn))
		tok := r.token(t, r.a, "discovery:read governance:enforce")
		p := base(r.a.connector.ID)
		for _, rt := range [][2]string{{"GET", p}, {"POST", p}, {"DELETE", p}, {"POST", p + "/sessions"},
			{"GET", p + "/sessions/" + uuid.NewString()}, {"POST", p + "/verify"}} {
			code, body := r.call(rt[0], rt[1], tok, nil)
			if code != http.StatusServiceUnavailable || errCode(body) != "policy_unavailable" {
				t.Errorf("%s %s = %d %v", rt[0], rt[1], code, body)
			}
		}
	})

	r := newEnfRouteLab(t, verified)
	prevAudit := config.AuditLogger
	enfMetricsOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics() // the audit logger's logrus logger
		}
	})
	config.AuditLogger = monitoring.NewAuditLogger(db)
	t.Cleanup(func() { config.AuditLogger = prevAudit })
	enforce := r.token(t, r.a, "discovery:read governance:enforce")
	reader := r.token(t, r.a, "discovery:read")
	p := base(r.a.connector.ID)

	if code, body := r.call("GET", p, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d %v", code, body)
	}
	code, body := r.call("GET", p, reader, nil)
	if code != http.StatusOK || digs(body, "data", "state") != "off" || digs(body, "data", "current_template_version") != awsdiscovery.EnforcementTemplateVersion {
		t.Fatalf("GET off: %d %v", code, body)
	}
	for _, rt := range [][2]string{{"POST", p + "/sessions"}, {"POST", p}, {"DELETE", p}, {"POST", p + "/verify"},
		{"GET", p + "/sessions/" + uuid.NewString()}} {
		if code, body := r.call(rt[0], rt[1], reader, map[string]any{}); code != http.StatusForbidden || errCode(body) == "" {
			t.Errorf("%s %s with discovery:read only = %d %v, want 403 in the envelope", rt[0], rt[1], code, body)
		}
	}

	code, body = r.call("POST", p+"/sessions", enforce, map[string]any{"deployment_region": "us-east-1",
		"workspace_id": uuid.NewString()}) // a body workspace is ignored
	if code != http.StatusCreated || digs(body, "data", "status") != "waiting_for_stack" || digs(body, "data", "quick_create_url") == "" {
		t.Fatalf("POST sessions: %d %v", code, body)
	}
	sid := digs(body, "data", "id")
	suffix := digs(body, "data", "suffix")
	ext := digs(body, "data", "external_id")
	if code, body := r.call("GET", p+"/sessions/"+sid, enforce, nil); code != http.StatusOK || digs(body, "data", "status") != "waiting_for_stack" {
		t.Fatalf("poll: %d %v", code, body)
	}
	r.aws.deploy(t, testAccount, suffix, ext)
	code, body = r.call("POST", p, enforce, map[string]any{
		"role_arn":          "arn:aws:iam::" + testAccount + ":role/AuthSecEnforcement-" + suffix,
		"selftest_role_arn": "arn:aws:iam::" + testAccount + ":role/AuthSecEnforcementSelfTest-" + suffix})
	if code != http.StatusOK || digs(body, "data", "state") != "verified" {
		t.Fatalf("manual bind: %d %v", code, body)
	}
	if code, body := r.call("POST", p+"/verify", enforce, nil); code != http.StatusOK || digs(body, "data", "state") != "verified" ||
		digs(body, "data", "capabilities", "refuses_foreign_boundary", "status") != "ok" {
		t.Fatalf("verify: %d %v", code, body)
	}
	if code, body := r.call("GET", p, reader, nil); code != http.StatusOK || digs(body, "data", "state") != "verified" ||
		dig(body, "data", "last_self_test_at") == nil || dig(body, "meta", "as_of") == nil {
		t.Fatalf("GET verified: %d %v", code, body)
	}

	// Another workspace's token on A's connector: 404 everywhere; a malformed id is 404 too.
	other := r.newWorkspace(t, "p3-enf-routes-b")
	otherTok := r.token(t, other, "discovery:read governance:enforce")
	for _, rt := range [][2]string{{"GET", p}, {"POST", p}, {"DELETE", p}, {"POST", p + "/sessions"},
		{"GET", p + "/sessions/" + sid}, {"POST", p + "/verify"}, {"GET", "/aws/connectors/not-a-uuid/enforcement"}} {
		if code, body := r.call(rt[0], rt[1], otherTok, map[string]any{}); code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("other workspace %s %s = %d %v, want 404 not_found", rt[0], rt[1], code, body)
		}
	}
	// ...and its own session for the same account is refused (A17).
	if code, body := r.call("POST", base(other.connector.ID)+"/sessions", otherTok, nil); code != http.StatusConflict ||
		errCode(body) != services.EnfCodeOwnedElsewhere || digs(body, "error", "message") == "" {
		t.Fatalf("other workspace session: %d %v", code, body)
	}

	if code, body := r.call("DELETE", p, enforce, map[string]any{"reason": "done"}); code != http.StatusOK ||
		digs(body, "data", "binding", "state") != "revoked" || dig(body, "data", "artifacts_in_aws") == nil {
		t.Fatalf("revoke: %d %v", code, body)
	}

	// Every mutation wrote its iga_gov_event (in the service's transaction)
	// and an audit_events row (asynchronously).
	ev := r.events(t, r.a.ws)
	want := []string{services.EventEnforcementSessionStarted, services.EventEnforcementBound, services.EventEnforcementSelfTest,
		services.EventEnforcementSelfTest, services.EventEnforcementRevoked}
	if strings.Join(ev, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", ev, want)
	}
	wantAudit := map[string]bool{"start_enforcement_session": true, "bind_enforcement": true, "verify_enforcement": true, "revoke_enforcement": true}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var actions []string
		db.Raw(`SELECT action FROM audit_events WHERE workspace_id = ? AND resource = 'cloud_enforcement_binding'`, r.a.ws.String()).Scan(&actions)
		got := map[string]bool{}
		for _, a := range actions {
			got[a] = true
		}
		missing := []string{}
		for a := range wantAudit {
			if !got[a] {
				missing = append(missing, a)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit_events missing %v (have %v)", missing, actions)
		}
		time.Sleep(100 * time.Millisecond)
	}
	db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, r.a.ws.String())
}
