package integration

// Review P2 (template version): the discovery template version recorded on
// a connector is the one the customer's STACK reports, through the REAL
// Quick Create callback (AWSQuickCreateService over the REAL
// AWSOnboardingService and PostgreSQL), and a stack Update refreshes it. The
// gates that read it -- resource-policy collection (§3.9) and isolation's
// MigrationEvidence (§11, LoadIaCConnectorFacts) -- then see an old stack as
// old. CloudFormation's response PUT is captured; nothing reaches AWS.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

type p3tvLab struct {
	t    *testing.T
	env  *rpEnv
	onb  *services.AWSOnboardingService
	qc   *services.AWSQuickCreateService
	puts *enfPuts
}

func newP3tvLab(t *testing.T, name string) *p3tvLab {
	t.Helper()
	db := igaDB(t)
	ws := newWorkspace(t, db, name)
	onb := services.NewAWSOnboardingService(db, newMemVault()).WithVerifier(okVerifier())
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	cfg, err := awsdiscovery.ParseCallbackConfig(fmt.Sprintf(`{"us-east-1":%q}`, enfTopic),
		"https://sqs.us-east-1.amazonaws.com/111111111111/authsec-cfn-callback",
		"https://bucket.s3.us-east-1.amazonaws.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	puts := &enfPuts{}
	qc := services.NewAWSQuickCreateService(onb, redis.NewClient(&redis.Options{Addr: mr.Addr()}), cfg, enfPrincipal).
		WithHTTPClient(&http.Client{Transport: puts}).
		WithTemplateCheck(func(context.Context, string) error { return nil })
	return &p3tvLab{t: t, env: &rpEnv{db: db, ws: ws, svc: onb}, onb: onb, qc: qc, puts: puts}
}

// body is the SNS notification the discovery stack's registration resource
// produces, reporting templateVersion.
func (l *p3tvLab) body(requestType, roleName, externalID, templateVersion string) string {
	req := map[string]any{
		"RequestType":       requestType,
		"RequestId":         "req-" + uuid.NewString()[:8],
		"StackId":           "arn:aws:cloudformation:us-east-1:" + testAccount + ":stack/AuthSec-Discovery-x/2d213470-3bbd-11ea-a35f-06b8fd1f0384",
		"ResponseURL":       enfResponseURL,
		"ResourceType":      awsdiscovery.RegistrationResourceType,
		"LogicalResourceId": awsdiscovery.RegistrationLogicalID,
		"ResourceProperties": map[string]string{
			"RoleArn": "arn:aws:iam::" + testAccount + ":role/" + roleName, "ExternalId": externalID,
			"AccountId": testAccount, "TemplateVersion": templateVersion,
		},
	}
	if requestType != awsdiscovery.CFNRequestCreate {
		req["PhysicalResourceId"] = "authsec-something"
	}
	raw, _ := json.Marshal(req)
	env, _ := json.Marshal(map[string]string{
		"Type": "Notification", "MessageId": uuid.NewString(), "TopicArn": enfTopic,
		"Message": string(raw), "Timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	return string(env)
}

func (l *p3tvLab) deliver(body string) {
	l.t.Helper()
	if out := l.qc.HandleCallbackDelivery(context.Background(), body, false); out != services.CallbackDone {
		l.t.Fatalf("callback outcome %s", out)
	}
	if r := l.puts.last(l.t); r.Status != awsdiscovery.CFNStatusSuccess {
		l.t.Fatalf("CloudFormation answered %+v, want SUCCESS", r)
	}
}

// facts are what the gates read for the connector.
func (l *p3tvLab) facts(conn uuid.UUID) (recorded string, migration, collects bool) {
	l.t.Helper()
	f, err := services.LoadIaCConnectorFacts(l.env.db, l.env.ws, conn)
	if err != nil {
		l.t.Fatal(err)
	}
	l.env.conn = conn
	out := l.env.collect(l.t, newRPWorld(), l.env.run(l.t))
	return f.TemplateVersion, f.MigrationEvidence, out.TemplateCurrent
}

func TestP3CovTemplateVersionFromTheStack(t *testing.T) {
	l := newP3tvLab(t, "p3-cov-template")
	sess, err := l.qc.StartSession(context.Background(), l.env.ws, "admin", []string{"us-east-1", "eu-west-1"}, "")
	if err != nil {
		t.Fatalf("start session: %v", err)
	}

	// An OLD stack (the 2026-09-24 template, before resource-policy
	// collection) connects through the callback: it is recorded old.
	const old = "2026-09-24"
	l.deliver(l.body(awsdiscovery.CFNRequestCreate, sess.RoleName, sess.ExternalID, old))
	got, err := l.qc.GetSession(context.Background(), l.env.ws, sess.ID)
	if err != nil || got.Status != services.AWSOnbConnected || got.ConnectorID == nil {
		t.Fatalf("session %+v: %v", got, err)
	}
	conn := *got.ConnectorID
	if v, mig, col := l.facts(conn); v != old || mig || col {
		t.Fatalf("old stack: recorded %q, migration evidence %v, collects %v; want %q, false, false", v, mig, col, old)
	}

	// A forged Update (wrong ExternalId) changes nothing.
	l.deliver(l.body(awsdiscovery.CFNRequestUpdate, sess.RoleName, "AuthSec-forged-"+uuid.NewString(), awsdiscovery.TemplateVersion))
	if v, _, _ := l.facts(conn); v != old {
		t.Fatalf("a forged Update recorded %q", v)
	}
	// An Update for another role of the account changes nothing either.
	l.deliver(l.body(awsdiscovery.CFNRequestUpdate, "SomeOtherRole", sess.ExternalID, awsdiscovery.TemplateVersion))
	if v, _, _ := l.facts(conn); v != old {
		t.Fatalf("an Update of another role recorded %q", v)
	}

	// The customer updates the stack to the current template: its Update
	// refreshes the recorded version, and both gates open.
	l.deliver(l.body(awsdiscovery.CFNRequestUpdate, sess.RoleName, sess.ExternalID, awsdiscovery.TemplateVersion))
	if v, mig, col := l.facts(conn); v != awsdiscovery.TemplateVersion || !mig || !col {
		t.Fatalf("updated stack: recorded %q, migration evidence %v, collects %v; want current", v, mig, col)
	}

	// The update's rollback reports the old version again: old again.
	l.deliver(l.body(awsdiscovery.CFNRequestUpdate, sess.RoleName, sess.ExternalID, old))
	if v, mig, _ := l.facts(conn); v != old || mig {
		t.Fatalf("rolled-back stack: recorded %q, migration evidence %v", v, mig)
	}

	// A malformed version is unknown, which every gate reads as older.
	l.deliver(l.body(awsdiscovery.CFNRequestUpdate, sess.RoleName, sess.ExternalID, "9999-latest"))
	if v, mig, col := l.facts(conn); v != "" || mig || col {
		t.Fatalf("malformed version: recorded %q, migration %v, collects %v", v, mig, col)
	}

	var c models.CloudConnector
	if err := l.env.db.First(&c, "id = ?", conn).Error; err != nil || c.AWSAttrs().RoleARN != "arn:aws:iam::"+testAccount+":role/"+sess.RoleName {
		t.Fatalf("connector %+v: %v", c.AWSAttrs(), err)
	}
}

// A NEW stack connecting through the callback is recorded current.
func TestP3CovTemplateVersionNewStackIsCurrent(t *testing.T) {
	l := newP3tvLab(t, "p3-cov-template-new")
	sess, err := l.qc.StartSession(context.Background(), l.env.ws, "admin", []string{"us-east-1"}, "")
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	l.deliver(l.body(awsdiscovery.CFNRequestCreate, sess.RoleName, sess.ExternalID, awsdiscovery.TemplateVersion))
	got, _ := l.qc.GetSession(context.Background(), l.env.ws, sess.ID)
	if got == nil || got.ConnectorID == nil {
		t.Fatalf("session %+v", got)
	}
	if v, mig, col := l.facts(*got.ConnectorID); v != awsdiscovery.TemplateVersion || !mig || !col {
		t.Fatalf("new stack: recorded %q, migration evidence %v, collects %v", v, mig, col)
	}
}
