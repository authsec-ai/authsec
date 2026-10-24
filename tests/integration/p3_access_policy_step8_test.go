package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// Step 8: Lambda (block, allow of invoking; a public function URL the last
// scan saw is warned), KMS keys (block only), SQS queues (block and allow),
// SNS topics (block, allow of publishing).

// functionPolicyScan publishes a scan whose Lambda collection in us-east-1 is
// complete and read fn's resource policy as doc.
func (l *apLab) functionPolicyScan(fn, doc string) {
	l.t.Helper()
	run := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
		VALUES (?, ?, ?, (SELECT COALESCE(max(generation), 0) + 1 FROM cloud_scan_run WHERE workspace_id = ? AND connector_id = ?), 'published', now())`,
		run, l.ws, l.conn.ID, l.ws, l.conn.ID)
	p3exec(l.t, l.db, `INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
		VALUES (?, ?, ?, 'lambda_function', 'us-east-1', 'complete', 1, 1)`, l.ws, l.conn.ID, run)
	canon, hash, err := igagov.CanonicalDocument(doc)
	if err != nil {
		l.t.Fatal(err)
	}
	p3exec(l.t, l.db, `INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)
		ON CONFLICT DO NOTHING`, l.ws, hash, string(canon), string(canon))
	p3exec(l.t, l.db, `INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn,
		policy_present, document_hash, parse_state, read_at) VALUES (?, ?, 'lambda_function', 'us-east-1', ?, true, ?, 'parsed', now())`,
		l.ws, run, fn, hash)
}

func TestAccessPolicyStep8(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	role := l.role("AgentRunner")
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	intent := func(effect string, res uuid.UUID, access ...string) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: role.String()}}, Access: access, EndsAt: &end}
	}

	// Lambda: a block of read on a function with a public URL is warned.
	fn := "arn:aws:lambda:us-east-1:" + testAccount + ":function:book-flight"
	fnRes := l.resourceOf(fn+":prod", "lambda_function", &l.conn.ID)
	pv, err := l.svc.Preview(ctx, l.ws, intent("block", fnRes, "read"))
	if err != nil || len(pv.Blockers) != 0 || hasWarning(pv, services.GovCodeFunctionURLPublic) || !hasWarning(pv, "handoff_blocked") {
		t.Fatalf("lambda block, no scan: %+v %v", pv, err)
	}
	l.functionPolicyScan(fn, `{"Version":"2012-10-17","Statement":[{"Sid":"FunctionURLAllowPublicAccess","Effect":"Allow","Principal":"*",
		"Action":"lambda:InvokeFunctionUrl","Resource":"`+fn+`","Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`)
	pv, err = l.svc.Preview(ctx, l.ws, intent("block", fnRes, "read"))
	if err != nil || len(pv.Blockers) != 0 || !hasWarning(pv, services.GovCodeFunctionURLPublic) {
		t.Fatalf("lambda block, public URL: %+v %v", pv, err)
	}
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", fnRes, "read"), Name: "No booking", Reason: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("AgentRunner")
	if len(att) != 1 {
		t.Fatalf("attached: %v", att)
	}
	if _, _, doc, _, _ := l.fake.PolicyState(att[0]); !strings.Contains(doc, `"lambda:InvokeFunction"`) || !strings.Contains(doc, fn+`:*`) {
		t.Fatalf("lambda document: %s", doc)
	}
	l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"})
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusEnded || v.Resource.Name != "book-flight" || v.Resource.ResourceType != igagov.AccessTypeLambdaFunction {
		t.Fatalf("lambda ended: %s %+v", v.Status, v.Resource)
	}

	// SQS: an allow of read and write is applied.
	queue := l.resourceOf("arn:aws:sqs:us-east-1:"+testAccount+":orders", "sqs_queue", &l.conn.ID)
	a, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("allow", queue, "read", "write"), Name: "Orders", Reason: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	l.run(a.ID)
	att = l.attachedAuthSec("AgentRunner")
	if len(att) != 1 {
		t.Fatalf("sqs attached: %v", att)
	}
	if _, _, doc, _, _ := l.fake.PolicyState(att[0]); !strings.Contains(doc, `"Allow"`) || !strings.Contains(doc, "sqs:SendMessage") || strings.Contains(doc, "sqs:PurgeQueue") {
		t.Fatalf("sqs document: %s", doc)
	}

	// Refusals.
	key := l.resourceOf("arn:aws:kms:us-east-1:"+testAccount+":key/1234abcd-12ab-34cd-56ef-1234567890ab", "kms_key", &l.conn.ID)
	alias := l.resourceOf("arn:aws:kms:us-east-1:"+testAccount+":alias/app", "kms_alias", &l.conn.ID)
	topic := l.resourceOf("arn:aws:sns:us-east-1:"+testAccount+":alerts", "sns", &l.conn.ID)
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"an allow on a key", intent("allow", key, "read"), services.GovCodeAccessInvalid},
		{"a key alias", intent("block", alias, "read"), services.GovCodeResourceNotSupported},
		{"an allow of changing a function", intent("allow", fnRes, "write"), services.GovCodeAccessInvalid},
		{"an allow of subscribing to a topic", intent("allow", topic, "read"), services.GovCodeAccessInvalid},
		{"an allow of all on a queue", intent("allow", queue, "all"), services.GovCodeAccessInvalid},
	} {
		if got := previewCode(l.svc.Preview(ctx, l.ws, c.in)); got != c.code {
			t.Errorf("%s: %s, want %s", c.name, got, c.code)
		}
	}
	for _, in := range []igagov.AccessIntent{intent("block", key, "read", "write", "delete"), intent("allow", topic, "write"), intent("block", topic, "read")} {
		if pv, err := l.svc.Preview(ctx, l.ws, in); err != nil || len(pv.Blockers) != 0 {
			t.Errorf("%s %v: %+v %v", in.Effect, in.Access, pv, err)
		}
	}

	// Another workspace's queue is 404.
	other := p3NewGov(t, l.db, "step8-other")
	foreign := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'sqs_queue', ?, 'aws', ?)`, foreign, other.ws, "arn:aws:sqs:us-east-1:"+testAccount+":orders", "aws\x1fref\x1fforeign-sqs")
	if got := previewCode(l.svc.Preview(ctx, l.ws, intent("block", foreign, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's queue: %s", got)
	}
	var n int64
	l.db.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND family = 'time_bound'", l.ws).Count(&n)
	if n != 2 {
		t.Fatalf("policies stored: %d", n)
	}
}
