package services

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/models"
)

// Unit tests of rule aws_agent_suggest_v1, the labels, the findings' pure
// parts and the resolver's subject, over in-memory state (no database).

func arTestWorkload(name string, graph bool, classification string) *arWorkload {
	w := &arWorkload{ID: uuid.New(), RuntimeKind: models.WorkloadLambdaFunction, Name: name,
		NativeID: "arn:aws:lambda:us-east-1:111122223333:function:" + name, Region: "us-east-1",
		Classification: classification}
	if graph {
		g := uuid.New()
		w.GraphID = &g
	}
	return w
}

func arTestUsage(calls, denied int, other map[string]int) agentruntime.ModelCallUsage {
	return agentruntime.ModelCallUsage{Calls: calls, Denied: denied, OtherServices: other,
		Models: map[string]int{"anthropic.claude": calls}}
}

func TestSuggestEligible(t *testing.T) {
	acting := map[string]int{"s3.amazonaws.com": 4, "secretsmanager.amazonaws.com": 1}
	one := arTestWorkload("support-bot", true, models.ClassificationUnclassified)
	cases := []struct {
		name       string
		u          agentruntime.ModelCallUsage
		one        *arWorkload
		candidates int
		want       bool
		why        string
	}{
		{"model calls and other services on a dedicated role", arTestUsage(3, 0, acting), one, 1, true, ""},
		{"refused model calls count as model calls (§5.4)", arTestUsage(0, 2, acting), one, 1, true, ""},
		{"no model calls", arTestUsage(0, 0, acting), one, 1, false, suggestNoModelCalls},
		{"shared role: never a suggestion (§10 Q1)", arTestUsage(3, 0, acting), nil, 2, false, suggestSharedRole},
		{"one EKS service account and no workload", arTestUsage(3, 0, acting), nil, 1, false, suggestSharedRole},
		{"not projected yet", arTestUsage(3, 0, acting), arTestWorkload("x", false, ""), 1, false, suggestNotProjected},
		{"already an agent", arTestUsage(3, 0, acting), arTestWorkload("x", true, models.ClassificationClassified), 1, false, suggestClassified},
		{"provider native", arTestUsage(3, 0, acting), arTestWorkload("x", true, models.ClassificationProviderAgent), 1, false, suggestClassified},
		{"model calls only: an AI workload, not a suggestion", arTestUsage(3, 0, nil), one, 1, false, suggestNoOtherService},
		{"only telemetry and other model endpoints", arTestUsage(3, 0, map[string]int{
			"logs.amazonaws.com": 9, "bedrock-agentcore.amazonaws.com": 2, "xray.amazonaws.com": 1}), one, 1, false, suggestNoOtherService},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := suggestEligible(c.u, c.one, c.candidates)
			if got != c.want || why != c.why {
				t.Fatalf("suggestEligible = %v %q, want %v %q", got, why, c.want, c.why)
			}
		})
	}
}

func TestActedElsewhereDropsModelEndpointsAndTelemetry(t *testing.T) {
	got := actedElsewhere(arTestUsage(1, 0, map[string]int{
		"s3.amazonaws.com": 2, "bedrock.amazonaws.com": 5, "bedrock-mantle.amazonaws.com": 1,
		"monitoring.amazonaws.com": 3, "sts.amazonaws.com": 1, "dynamodb.amazonaws.com": 0}))
	want := map[string]int{"s3.amazonaws.com": 2, "sts.amazonaws.com": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actedElsewhere = %v, want %v", got, want)
	}
}

func TestAgentEnvVarNamesAreNamesOnly(t *testing.T) {
	got := AgentEnvVarNames([]string{"LANGCHAIN_API_KEY", "PATH", "MCP_SERVER_URL", "openai_api_key",
		"ANTHROPIC_API_KEY", "LANGSMITH_PROJECT", "OPENAI_ORG", "DB_PASSWORD"})
	want := []string{"ANTHROPIC_API_KEY", "LANGCHAIN_API_KEY", "LANGSMITH_PROJECT", "MCP_SERVER_URL", "openai_api_key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AgentEnvVarNames = %v, want %v", got, want)
	}
	if got := AgentEnvVarNames(nil); len(got) != 0 {
		t.Fatalf("no names: %v", got)
	}
}

func TestModelKeySecretNames(t *testing.T) {
	cases := map[string]string{
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:openai-api-key-AbCdEf": "openai-api-key",
		"arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/anthropic-x1Y2z3": "prod/anthropic",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:db-password-QwErTy":    "db-password",
		"arn:aws:s3:::not-a-secret": "",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:stripe_apikey-ZZZZZZ":     "stripe_apikey",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:gemini-llm-config-123456": "gemini-llm-config",
	}
	for arn, name := range cases {
		if got := SecretNameFromARN(arn); got != name {
			t.Errorf("SecretNameFromARN(%s) = %q, want %q", arn, got, name)
		}
	}
	for name, want := range map[string]bool{
		"openai-api-key": true, "prod/anthropic": true, "gemini-llm-config": true, "stripe_apikey": true,
		"service-api_key": true, "db-password": false, "slack-token": false, "LLM": true,
	} {
		if got := IsModelKeySecretName(name); got != want {
			t.Errorf("IsModelKeySecretName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestGrantsSecretRead(t *testing.T) {
	for _, c := range []struct {
		actions []string
		want    bool
	}{
		{[]string{"secretsmanager:GetSecretValue"}, true},
		{[]string{"secretsmanager:Get*"}, true},
		{[]string{"secretsmanager:*"}, true},
		{[]string{"*"}, true},
		{[]string{"s3:GetObject", "secretsmanager:DescribeSecret"}, false},
		{[]string{"secretsmanager:List*"}, false},
	} {
		if got := grantsSecretRead(c.actions); got != c.want {
			t.Errorf("grantsSecretRead(%v) = %v, want %v", c.actions, got, c.want)
		}
	}
}

func TestWorkloadLayerNames(t *testing.T) {
	attrs, _ := json.Marshal(map[string]any{"layers": []string{
		"arn:aws:lambda:us-east-1:111122223333:layer:langchain-deps:7", "plain-name",
		"arn:aws:lambda:us-east-1:111122223333:layer:langchain-deps:8"}})
	got := workloadLayerNames(attrs)
	if want := []string{"langchain-deps", "plain-name"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("workloadLayerNames = %v, want %v", got, want)
	}
	if got := workloadLayerNames(nil); len(got) != 0 {
		t.Fatalf("no attrs: %v", got)
	}
}

// Session names are weak, unverified evidence: matched to candidates by name,
// never used to attribute the calls.
func TestSessionNameEvidenceIsWeakAndUnverified(t *testing.T) {
	a, b := arTestWorkload("refunds", true, ""), arTestWorkload("orders", true, "")
	got := sessionNameEvidence([]string{"refunds", "i-0abc"}, []*arWorkload{a, b})
	if got.Verified {
		t.Fatal("session names must be reported unverified")
	}
	if len(got.Matches) != 1 || got.Matches[0].CloudWorkloadID != a.ID || got.Matches[0].Strength != "weak_unverified" {
		t.Fatalf("matches = %+v", got.Matches)
	}
}

func arTestState(ident *arIdentity, u agentruntime.ModelCallUsage, wls []*arWorkload, k8s []string) *agentRuntimeState {
	st := &agentRuntimeState{
		connectors: map[uuid.UUID]arConnector{}, identities: map[uuid.UUID]*arIdentity{ident.ID: ident},
		usage:     map[uuid.UUID]*arUsage{ident.ID: {ID: uuid.New(), IdentityID: ident.ID, usage: u}},
		workloads: map[uuid.UUID][]*arWorkload{ident.ID: wls}, k8s: map[uuid.UUID][]string{},
		saml: map[uuid.UUID]bool{}, suggestions: map[uuid.UUID]*arSuggestion{}, openFindings: map[uuid.UUID]int{},
	}
	if len(k8s) > 0 {
		st.k8s[ident.ID] = k8s
	}
	return st
}

func arTestRole(name string) *arIdentity {
	return &arIdentity{ID: uuid.New(), ConnectorID: uuid.New(), Kind: models.CloudIdentityIAMRole,
		NativeID: "arn:aws:iam::111122223333:role/" + name, Name: name, Attrs: json.RawMessage(`{"unique_id":"AROAEXAMPLE"}`)}
}

func TestLabels(t *testing.T) {
	acting := map[string]int{"s3.amazonaws.com": 1}
	t.Run("model calls only is an AI workload", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, nil), []*arWorkload{arTestWorkload("w", true, models.ClassificationUnclassified)}, nil)
		ais := st.aiWorkloads()
		if len(ais) != 1 || ais[0].Label != agentruntime.LabelAIWorkload || ais[0].SharedRole {
			t.Fatalf("got %+v", ais)
		}
	})
	t.Run("acting elsewhere on a dedicated role is a suggested agent", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, acting), []*arWorkload{arTestWorkload("w", true, models.ClassificationUnclassified)}, nil)
		if l := st.aiWorkloads()[0].Label; l != agentruntime.LabelSuggestedAgent {
			t.Fatalf("label %q", l)
		}
	})
	t.Run("a dismissed incarnation is never suggested again", func(t *testing.T) {
		w := arTestWorkload("w", true, models.ClassificationUnclassified)
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, acting), []*arWorkload{w}, nil)
		st.suggestions[*w.GraphID] = &arSuggestion{ID: uuid.New(), WorkloadID: *w.GraphID, State: SuggestionDismissed, Reason: "pipeline"}
		ai := st.aiWorkloads()[0]
		if ai.Label != agentruntime.LabelAIWorkload || ai.Suggestion == nil || ai.Suggestion.State != SuggestionDismissed {
			t.Fatalf("got %q %+v", ai.Label, ai.Suggestion)
		}
	})
	t.Run("a shared role is an AI workload even when it acts elsewhere", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, acting), []*arWorkload{
			arTestWorkload("a", true, models.ClassificationUnclassified), arTestWorkload("b", true, models.ClassificationUnclassified)}, nil)
		ai := st.aiWorkloads()[0]
		if ai.Label != agentruntime.LabelAIWorkload || !ai.SharedRole || len(ai.Workloads) != 2 {
			t.Fatalf("got %+v", ai)
		}
	})
	t.Run("an EKS service account makes the role shared", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, acting), []*arWorkload{arTestWorkload("a", true, models.ClassificationUnclassified)},
			[]string{"system:serviceaccount:ai:bot"})
		if ai := st.aiWorkloads()[0]; !ai.SharedRole || ai.Label != agentruntime.LabelAIWorkload {
			t.Fatalf("got %+v", ai)
		}
	})
	t.Run("a classified workload is an agent", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(2, 0, nil), []*arWorkload{arTestWorkload("w", true, models.ClassificationClassified)}, nil)
		if l := st.aiWorkloads()[0].Label; l != agentruntime.LabelAgent {
			t.Fatalf("label %q", l)
		}
	})
	t.Run("no calls and no refusals is not an AI workload", func(t *testing.T) {
		st := arTestState(arTestRole("r"), arTestUsage(0, 0, acting), []*arWorkload{arTestWorkload("w", true, "")}, nil)
		if ais := st.aiWorkloads(); len(ais) != 0 {
			t.Fatalf("got %+v", ais)
		}
	})
}

func TestSubjectFromState(t *testing.T) {
	ident := arTestRole("support")
	agent := arTestWorkload("support-bot", true, models.ClassificationProviderAgent)
	other := arTestWorkload("cron", true, models.ClassificationUnclassified)
	st := arTestState(ident, arTestUsage(0, 0, nil), []*arWorkload{agent, other}, nil)
	sub := subjectFromState(st, ident)
	if sub.IdentityID != ident.ID || sub.Label != agentruntime.LabelAgent || !sub.SharedRole || len(sub.WorkloadIDs) != 2 || sub.Name != "support" {
		t.Fatalf("shared role with an agent on it: %+v", sub)
	}

	solo := arTestRole("solo")
	w := arTestWorkload("solo-fn", true, models.ClassificationUnclassified)
	st = arTestState(solo, arTestUsage(1, 0, nil), []*arWorkload{w}, nil)
	sub = subjectFromState(st, solo)
	if sub.Label != agentruntime.LabelAIWorkload || sub.SharedRole || sub.Name != "solo-fn" {
		t.Fatalf("dedicated AI workload: %+v", sub)
	}

	idle := arTestRole("idle")
	st = arTestState(idle, arTestUsage(0, 0, nil), nil, nil)
	if sub = subjectFromState(st, idle); sub.Label != "" {
		t.Fatalf("no evidence: %+v", sub)
	}
}

func TestIsHumanSession(t *testing.T) {
	sso := &arIdentity{Kind: models.CloudIdentityIAMRole,
		NativeID: "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123", Name: "AWSReservedSSO_Admin_0123"}
	plain := arTestRole("lambda-exec")
	user := &arIdentity{Kind: models.CloudIdentityIAMUser, NativeID: "arn:aws:iam::111122223333:user/ci"}
	if !isHumanSession(sso, false) || isHumanSession(plain, false) || !isHumanSession(plain, true) || isHumanSession(user, true) {
		t.Fatal("isHumanSession: Identity Center and SAML roles are human sessions; other roles and users are not")
	}
}

func TestIdentitySubjectKeyCarriesIncarnation(t *testing.T) {
	r := arTestRole("x")
	if got := r.subjectKey(); got != r.NativeID+"#AROAEXAMPLE" {
		t.Fatalf("subjectKey = %q", got)
	}
	r.Attrs = nil
	if got := r.subjectKey(); got != r.NativeID {
		t.Fatalf("subjectKey without unique id = %q", got)
	}
}

func TestARCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 5, 10, 0, 0, 123456789, time.UTC)
	id := uuid.New()
	c, err := decodeARCursor(encodeARCursor(at, id))
	if err != nil || !c.At.Equal(at) || c.ID != id {
		t.Fatalf("round trip: %+v %v", c, err)
	}
	if _, err := decodeARCursor("not-a-cursor"); err == nil {
		t.Fatal("a forged cursor must not decode")
	}
}

func TestAWSAgentSighting(t *testing.T) {
	conn := arConnector{ID: uuid.New(), ScopeID: "111122223333"}
	now := time.Now()
	native := arTestWorkload("bedrock-agent", true, models.ClassificationProviderAgent)
	native.RuntimeKind = models.WorkloadBedrockAgent
	s := awsAgentSighting(uuid.New(), conn, native, nil, now)
	if s.Source != models.DiscoverySourceAWS || s.EvidenceMode != models.EvidenceDeclared ||
		s.Fingerprint != "aws:111122223333:bedrock_agent:"+native.NativeID || s.LastObservedRunningAt != nil ||
		s.Status != models.DiscoveredAgentUnregistered {
		t.Fatalf("provider-native sighting: %+v", s)
	}
	classified := arTestWorkload("support-fn", true, models.ClassificationClassified)
	if s := awsAgentSighting(uuid.New(), conn, classified, nil, now); s.EvidenceMode != models.EvidenceInferred {
		t.Fatalf("classified sighting mode %q", s.EvidenceMode)
	}
}
