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

// Access policies on Bedrock (step 6, block only): a model picked through a
// cross-region inference profile row, and a Bedrock agent or AgentCore
// runtime picked by its discovered workload id (most IAM policies name agents
// through "*", so Discovery's workload scan is how they are found).

const testClaude = "anthropic.claude-3-5-sonnet-20240620-v1:0"

// workload adds a discovered workload seen by the lab's connector.
func (l *apLab) workload(kind, arn string) uuid.UUID {
	l.t.Helper()
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key)
		VALUES (?, ?, ?, ?, 'us-east-1', ?)`, id, l.ws, kind, arn[strings.LastIndex(arn, "/")+1:], "aws\x1f"+arn)
	p3exec(l.t, l.db, `INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
		VALUES (?, ?, ?, ?)`, l.ws, id, l.conn.ID, "aws:"+testAccount)
	return id
}

func TestAccessPolicyBedrockLifecycle(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	caller := l.role("ModelCaller")
	profile := l.resourceOf("arn:aws:bedrock:us-east-1:"+testAccount+":inference-profile/us."+testClaude, "bedrock_inference-profile", &l.conn.ID)
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: profile.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: caller.String()}}, Access: []string{"read"}, EndsAt: &end}

	pv, err := l.svc.Preview(ctx, l.ws, in)
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "Block read on Bedrock model "+testClaude+" (every region)") {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	want, _, _, _, _ := igagov.AccessDocument("block", []string{"read"}, igagov.BedrockModelTarget{Partition: "aws", Model: testClaude}, nil, &end)
	if string(pv.Documents[0].Document) != string(want) {
		t.Fatalf("document:\n got %s\nwant %s", pv.Documents[0].Document, want)
	}
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "No Claude", Reason: "cost"})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("ModelCaller")
	if len(att) != 1 {
		t.Fatalf("attached: %v", att)
	}
	if _, _, doc, _, _ := l.fake.PolicyState(att[0]); doc != string(want) {
		t.Fatalf("policy in AWS: %s", doc)
	}
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusActive || v.Resource.ResourceType != igagov.AccessTypeBedrockModel ||
		v.Resource.Name != testClaude || v.Resource.AccountID != testAccount {
		t.Fatalf("after apply: %s %+v", v.Status, v.Resource)
	}
	l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"})
	l.run(v.ID)
	if len(l.attachedAuthSec("ModelCaller")) != 0 {
		t.Fatal("not removed at the end")
	}

	// A discovered AgentCore runtime, by its workload id.
	invoker := l.role("RuntimeInvoker")
	rtARN := "arn:aws:bedrock-agentcore:us-east-1:" + testAccount + ":runtime/travel_agent-AbCdEf1234"
	rt := l.workload(models.WorkloadBedrockAgentCoreRT, rtARN)
	in = igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: rt.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: invoker.String()}}, Access: []string{"read"}, EndsAt: &end}
	pv, err = l.svc.Preview(ctx, l.ws, in)
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "AgentCore runtime travel_agent-AbCdEf1234") ||
		!hasWarning(pv, "oauth_callers_not_covered") {
		t.Fatalf("runtime preview: %+v %v", pv, err)
	}
	v, err = l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "Pause travel agent", Reason: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	att = l.attachedAuthSec("RuntimeInvoker")
	if len(att) != 1 {
		t.Fatalf("runtime attached: %v", att)
	}
	if _, _, doc, _, _ := l.fake.PolicyState(att[0]); !strings.Contains(doc, "bedrock-agentcore:InvokeAgentRuntime") || !strings.Contains(doc, rtARN+"/runtime-endpoint/*") {
		t.Fatalf("runtime document: %s", doc)
	}
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Resource.ResourceType != igagov.AccessTypeAgentCoreRuntime || v.Resource.Kind != models.WorkloadBedrockAgentCoreRT ||
		v.Resource.ARN != rtARN {
		t.Fatalf("runtime view: %+v", v.Resource)
	}
	if list, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{}); err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}
}

func TestAccessPolicyBedrockRefusals(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	role := l.role("BedrockRefused")
	model := l.resourceOf("arn:aws:bedrock:us-east-1::foundation-model/"+testClaude, "bedrock_foundation-model", &l.conn.ID)
	pattern := l.resourceOf("arn:aws:bedrock:us-east-1::foundation-model/anthropic.*", "selector", &l.conn.ID)
	agent := l.workload(models.WorkloadBedrockAgent, "arn:aws:bedrock:us-east-1:"+testAccount+":agent/AGENT12345")
	lambda := l.workload(models.WorkloadLambdaFunction, "arn:aws:lambda:us-east-1:"+testAccount+":function:f")
	end := time.Now().Add(time.Hour)
	intent := func(effect string, res uuid.UUID, access ...string) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: role.String()}}, Access: access, EndsAt: &end}
	}
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"an allow on a model", intent("allow", model, "read"), services.GovCodeAccessInvalid},
		{"delete on a model", intent("block", model, "read", "delete"), services.GovCodeAccessInvalid},
		{"a model pattern", intent("block", pattern, "read"), services.GovCodeResourceNotSupported},
		{"an allow on an agent", intent("allow", agent, "read"), services.GovCodeAccessInvalid},
		{"a workload that is no agent", intent("block", lambda, "read"), services.GovCodeResourceNotFound},
	} {
		if got := previewCode(l.svc.Preview(ctx, l.ws, c.in)); got != c.code {
			t.Errorf("%s: preview %s, want %s", c.name, got, c.code)
		}
		if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: c.in, Name: "r " + uuid.NewString()[:8], Reason: "t"}); apCode(err) != c.code {
			t.Errorf("%s: create %v, want %s", c.name, err, c.code)
		}
	}
	if pv, err := l.svc.Preview(ctx, l.ws, intent("block", agent, "read", "write", "delete")); err != nil || len(pv.Blockers) != 0 ||
		!strings.Contains(pv.Sentence, "Bedrock agent AGENT12345") {
		t.Fatalf("agent block: %+v %v", pv, err)
	}

	// Another workspace's agent is 404.
	other := p3NewGov(t, l.db, "bedrock-other")
	foreign := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key)
		VALUES (?, ?, 'bedrock_agent', 'theirs', 'us-east-1', ?)`, foreign, other.ws, "aws\x1farn:aws:bedrock:us-east-1:"+testAccount+":agent/THEIRS1234")
	if got := previewCode(l.svc.Preview(ctx, l.ws, intent("block", foreign, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's agent: %s", got)
	}
	var n int64
	l.db.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND family = 'time_bound'", l.ws).Count(&n)
	if n != 0 {
		t.Fatalf("refusals stored %d policies", n)
	}
}
