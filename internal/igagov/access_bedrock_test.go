package igagov

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const claude = "anthropic.claude-3-5-sonnet-20240620-v1:0"

var (
	bedrockClaude = BedrockModelTarget{Partition: "aws", Model: claude}
	bedrockAgent  = BedrockAgentTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Agent: "AGENT12345"}
	acRuntime     = AgentCoreRuntimeTarget{Partition: "aws", Region: "us-east-1", Account: "111122223333", Runtime: "travel_agent-AbCdEf1234"}
)

func blockDoc(t *testing.T, tg AWSAccessTarget, access ...string) map[string]any {
	t.Helper()
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	doc, _, _, _, err := AccessDocument(AccessEffectBlock, access, tg, nil, &end)
	if err != nil {
		t.Fatalf("%v: %v", access, err)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sameDoc(t *testing.T, name string, got map[string]any, want string) {
	t.Helper()
	var w map[string]any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("%s: bad want: %v", name, err)
	}
	if !reflect.DeepEqual(got, w) {
		g, _ := json.Marshal(got)
		t.Errorf("%s:\n got %s\nwant %s", name, g, mustCompact(t, want))
	}
}

// TestBedrockAccessDocuments states the intended documents by hand (the
// action tables in access_bedrock.go, checked against the AWS service
// reference) and compares them as JSON.
func TestBedrockAccessDocuments(t *testing.T) {
	window := `"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"}}`
	const M = "arn:aws:bedrock:*::foundation-model/" + claude
	const IP = "arn:aws:bedrock:*:*:inference-profile/*." + claude
	const G = "arn:aws:bedrock:::foundation-model/" + claude
	routes := `{"Sid":"AuthSecAccessModelRoutes","Effect":"Deny","Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"Resource":"*",
		"Condition":{"DateLessThan":{"aws:CurrentTime":"2026-11-01T00:00:00Z"},"StringLike":{"bedrock:ModelArn":"` + M + `"}}}`
	sameDoc(t, "model read", blockDoc(t, bedrockClaude, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessModel","Effect":"Deny","Resource":["`+IP+`","`+M+`","`+G+`"],`+window+`,
			"Action":["bedrock:CreateModelInvocationJob","bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"]},`+routes+`]}`)
	sameDoc(t, "model write", blockDoc(t, bedrockClaude, AccessWrite), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessModel","Effect":"Deny","Resource":["`+M+`","`+G+`"],`+window+`,"Action":["bedrock:CreateAdvancedPromptOptimizationJob",
			"bedrock:CreateEvaluationJob","bedrock:CreateInferenceProfile","bedrock:CreateModelCustomizationJob","bedrock:CreateModelEvaluationJob",
			"bedrock:CreatePromptRouter","bedrock:CreateProvisionedModelThroughput","bedrock:UpdateProvisionedModelThroughput"]}]}`)
	sameDoc(t, "model all", blockDoc(t, bedrockClaude, AccessAll), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessModel","Effect":"Deny","Action":"bedrock:*","Resource":["`+IP+`","`+M+`","`+G+`"],`+window+`},`+routes+`]}`)

	const AG = "arn:aws:bedrock:us-east-1:111122223333:agent/AGENT12345"
	const AL = "arn:aws:bedrock:us-east-1:111122223333:agent-alias/AGENT12345/*"
	sameDoc(t, "agent read", blockDoc(t, bedrockAgent, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessAgent","Effect":"Deny","Resource":["`+AL+`","`+AG+`"],`+window+`,"Action":["bedrock:GetAgentMemory","bedrock:InvokeAgent"]}]}`)
	sameDoc(t, "agent delete", blockDoc(t, bedrockAgent, AccessDelete), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessAgent","Effect":"Deny","Resource":["`+AL+`","`+AG+`"],`+window+`,"Action":["bedrock:DeleteAgent","bedrock:DeleteAgentActionGroup",
			"bedrock:DeleteAgentAlias","bedrock:DeleteAgentMemory","bedrock:DeleteAgentVersion"]}]}`)

	const RT = "arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/travel_agent-AbCdEf1234"
	sameDoc(t, "runtime read", blockDoc(t, acRuntime, AccessRead), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessRuntime","Effect":"Deny","Resource":["`+RT+`","`+RT+`/runtime-endpoint/*"],`+window+`,"Action":[
			"bedrock-agentcore:GetAgentCard","bedrock-agentcore:InvokeAgentRuntime","bedrock-agentcore:InvokeAgentRuntimeCommand",
			"bedrock-agentcore:InvokeAgentRuntimeCommandShell","bedrock-agentcore:InvokeAgentRuntimeForUser",
			"bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream","bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser"]}]}`)
	sameDoc(t, "runtime all", blockDoc(t, acRuntime, AccessAll), `{"Version":"2012-10-17","Statement":[
		{"Sid":"AuthSecAccessRuntime","Effect":"Deny","Action":"bedrock-agentcore:*","Resource":["`+RT+`","`+RT+`/runtime-endpoint/*"],`+window+`}]}`)

	// A model has nothing to delete.
	end := AccessNoEnd
	var fe *AccessFieldError
	for _, access := range [][]string{{AccessDelete}, {AccessRead, AccessDelete}} {
		if _, _, _, _, err := AccessDocument(AccessEffectBlock, access, bedrockClaude, nil, &end); !errors.As(err, &fe) || fe.Field != "access" {
			t.Fatalf("model %v: %v", access, err)
		}
	}
}

func TestParseBedrockARNs(t *testing.T) {
	for arn, want := range map[string]BedrockModelTarget{
		"arn:aws:bedrock:us-east-1::foundation-model/" + claude:                               bedrockClaude,
		"arn:aws:bedrock:*::foundation-model/" + claude:                                       bedrockClaude,
		"arn:aws:bedrock:::foundation-model/" + claude:                                        bedrockClaude,
		"arn:aws:bedrock:us-east-1:111122223333:inference-profile/us." + claude:               bedrockClaude,
		"arn:aws:bedrock:eu-west-1:111122223333:inference-profile/global." + claude:           bedrockClaude,
		"arn:aws-us-gov:bedrock:us-gov-west-1::foundation-model/amazon.titan-embed-text-v2:0": {Partition: "aws-us-gov", Model: "amazon.titan-embed-text-v2:0"},
	} {
		got, ok := ParseBedrockModelARN(arn)
		if !ok || got != want {
			t.Errorf("%s: %v %+v", arn, ok, got)
		}
	}
	for _, arn := range []string{
		"arn:aws:bedrock:us-east-1::foundation-model/*",
		"arn:aws:bedrock:us-east-1::foundation-model/anthropic.*",
		"arn:aws:bedrock:us-east-1:111122223333:inference-profile/xx." + claude,
		"arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/abc123",
		"arn:aws:bedrock:us-east-1:111122223333:custom-model/abc",
	} {
		if _, ok := ParseBedrockModelARN(arn); ok {
			t.Errorf("%s parsed as a model", arn)
		}
	}
	for arn, ok := range map[string]bool{
		"arn:aws:bedrock:us-east-1:111122223333:agent/AGENT12345":                  true,
		"arn:aws:bedrock:us-east-1:111122223333:agent-alias/AGENT12345/TSTALIASID": true,
		"arn:aws:bedrock:us-east-1:111122223333:agent-alias/AGENT12345/*":          true,
		"arn:aws:bedrock:us-east-1:111122223333:agent/*":                           false,
		"arn:aws:bedrock:us-east-1:111122223333:agent/AGENT":                       false,
	} {
		got, parsed := ParseBedrockAgentARN(arn)
		if parsed != ok || (ok && got != bedrockAgent) {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	for arn, ok := range map[string]bool{
		"arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/travel_agent-AbCdEf1234":                          true,
		"arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/travel_agent-AbCdEf1234/runtime-endpoint/DEFAULT": true,
		"arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/*":                                                false,
		"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/gw-1":                                             false,
	} {
		got, parsed := ParseAgentCoreRuntimeARN(arn)
		if parsed != ok || (ok && got != acRuntime) {
			t.Errorf("%s: %v %+v", arn, parsed, got)
		}
	}
	// The registry reads each; a model has no account.
	got, err := ParseAWSAccessTarget("arn:aws:bedrock:us-east-1:111122223333:inference-profile/us."+claude, "")
	if err != nil || got.Type() != AccessTypeBedrockModel || got.ARNAccount() != "" || got.Name() != claude {
		t.Fatalf("profile row: %#v %v", got, err)
	}
	if got, err := ParseAWSAccessTarget("arn:aws:bedrock:us-east-1:111122223333:agent-alias/AGENT12345/*", ""); err != nil || got.Type() != AccessTypeBedrockAgent {
		t.Fatalf("alias row: %#v %v", got, err)
	}
}

// Every combination fits the limits, refuses an allow, and names only the
// target's own ARNs (or "*" under the model-ARN condition).
func TestBedrockAccessProperties(t *testing.T) {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	combos := [][]string{{AccessRead}, {AccessWrite}, {AccessDelete}, {AccessRead, AccessWrite}, {AccessRead, AccessDelete},
		{AccessWrite, AccessDelete}, {AccessRead, AccessWrite, AccessDelete}, {AccessAll}}
	for _, tg := range []AWSAccessTarget{bedrockClaude, bedrockAgent, acRuntime} {
		own := map[string]bool{}
		switch x := tg.(type) {
		case BedrockModelTarget:
			own[x.ModelARN()], own[x.GlobalModelARN()], own[x.ProfileARN()], own["*"] = true, true, true, true
		case BedrockAgentTarget:
			own[x.ARN()], own[x.AliasesARN()] = true, true
		case AgentCoreRuntimeTarget:
			own[x.ARN()], own[x.EndpointsARN()] = true, true
		}
		for _, access := range combos {
			if _, _, _, _, err := AccessDocument(AccessEffectAllow, access, tg, &start, &end); !errors.Is(err, ErrAccessBlockOnly) {
				t.Fatalf("%s allow %v: %v", tg.Type(), access, err)
			}
			doc, _, actions, resources, err := AccessDocument(AccessEffectBlock, access, tg, &start, &end)
			if tg.Type() == AccessTypeBedrockModel && accessHas(access, AccessDelete) {
				if err == nil {
					t.Fatalf("model %v accepted", access)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s %v: %v", tg.Type(), access, err)
			}
			if PolicyChars(doc) > MaxPolicyChars || len(actions) < 1 || len(actions) > 50 || len(resources) < 1 || len(resources) > 20 {
				t.Fatalf("%s %v: %d chars, %d actions, %d resources", tg.Type(), access, PolicyChars(doc), len(actions), len(resources))
			}
			if strings.Count(string(doc), `"DateGreaterThan"`) != strings.Count(string(doc), `"Sid"`) {
				t.Fatalf("%s %v: a statement without the window", tg.Type(), access)
			}
			for _, r := range resources {
				if !own[r] {
					t.Fatalf("%s %v names %s", tg.Type(), access, r)
				}
			}
			if strings.Contains(string(doc), `"Resource":"*"`) && !strings.Contains(string(doc), KeyBedrockModelArn) {
				t.Fatalf("%s %v: * without the model condition", tg.Type(), access)
			}
		}
	}
}

func TestBedrockAccessNotes(t *testing.T) {
	codes := func(tg AWSAccessTarget, access ...string) string {
		var out []string
		for _, n := range tg.Notes(AccessEffectBlock, access) {
			out = append(out, n.Code)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		tg   AWSAccessTarget
		want string
		acc  []string
	}{
		{bedrockClaude, "model_routes_blocked,app_profiles_unverified,other_models_not_covered", []string{AccessRead}},
		{bedrockClaude, "", []string{AccessWrite}},
		{bedrockAgent, "aliases_covered,agent_role_unchanged", []string{AccessRead}},
		{bedrockAgent, "aliases_covered", []string{AccessDelete}},
		{acRuntime, "endpoints_covered,oauth_callers_not_covered,agent_role_unchanged", []string{AccessAll}},
	} {
		if got := codes(c.tg, c.acc...); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.tg.Type(), c.acc, got, c.want)
		}
	}
	in := AccessIntent{Effect: AccessEffectBlock, Access: []string{AccessRead}}
	if s := AccessSentence(in, bedrockClaude, []string{"X"}); s != "Block read on Bedrock model "+claude+" (every region) for X, with no end date." {
		t.Fatalf("sentence %q", s)
	}
	if s := AccessSentence(in, acRuntime, []string{"X"}); !strings.HasPrefix(s, "Block read on AgentCore runtime travel_agent-AbCdEf1234 (us-east-1, account 111122223333)") {
		t.Fatalf("sentence %q", s)
	}
}
