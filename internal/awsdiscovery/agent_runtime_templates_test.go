package awsdiscovery_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
)

// The agent runtime templates (SPEC-agent-runtime-visibility.md §5.4 as
// amended in §10, §5.6), asserted structurally: what the event stream
// forwards and how it authenticates, and what the tag gate denies, to whom,
// and with which exception.

func parseAgentTemplate(t *testing.T, name, src string) map[string]any {
	t.Helper()
	tpl, err := enforcetest.ParseTemplate(src)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if v := enforcetest.Dig(tpl, "Metadata", "AuthSec", "TemplateVersion"); v != awsdiscovery.AgentRuntimeTemplateVersion {
		t.Errorf("%s: Metadata.AuthSec.TemplateVersion %v, want %s", name, v, awsdiscovery.AgentRuntimeTemplateVersion)
	}
	if v := enforcetest.Dig(tpl, "Outputs", "TemplateVersion", "Value"); v != awsdiscovery.AgentRuntimeTemplateVersion {
		t.Errorf("%s: TemplateVersion output %v, want %s", name, v, awsdiscovery.AgentRuntimeTemplateVersion)
	}
	return tpl
}

func strs(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			} else if m, ok := x.(map[string]any); ok {
				if r, ok := m["Ref"].(string); ok {
					out = append(out, "ref:"+r)
				}
			}
		}
	}
	return out
}

func TestAgentEventStreamTemplate(t *testing.T) {
	tpl := parseAgentTemplate(t, "event stream", awsdiscovery.AgentEventStreamTemplate)

	rule := enforcetest.Dig(tpl, "Resources", "AuthSecEventRule", "Properties")
	if s := enforcetest.Dig(rule, "State"); s != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" {
		t.Fatalf("rule state %v: read-only management events would never arrive", s)
	}
	dt := strs(enforcetest.Dig(rule, "EventPattern", "detail-type"))
	sort.Strings(dt)
	if strings.Join(dt, "|") != "AWS API Call via CloudTrail|AWS Service Event via CloudTrail" {
		t.Errorf("detail-type %v", dt)
	}
	// The sources are spread over the pattern's $or branches (the busy ones
	// filtered by event name, readOnly, errorCode and invokedBy).
	branches, _ := enforcetest.Dig(rule, "EventPattern", "detail", "$or").([]any)
	seen := map[string]bool{}
	var got []string
	for _, b := range branches {
		for _, src := range strs(enforcetest.Dig(b, "eventSource")) {
			if !seen[src] {
				seen[src] = true
				got = append(got, src)
			}
		}
	}
	want := []string{
		"bedrock.amazonaws.com", "ref:MantleEventSource", "bedrock-agentcore.amazonaws.com",
		"iam.amazonaws.com", "sts.amazonaws.com", "secretsmanager.amazonaws.com", "ssm.amazonaws.com",
		"kms.amazonaws.com", "cloudtrail.amazonaws.com", "s3.amazonaws.com", "lambda.amazonaws.com",
		"logs.amazonaws.com",
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("event sources\n got %v\nwant %v", got, want)
	}

	conn := enforcetest.Dig(tpl, "Resources", "AuthSecEventConnection", "Properties")
	if enforcetest.Dig(conn, "AuthorizationType") != "API_KEY" ||
		enforcetest.Dig(conn, "AuthParameters", "ApiKeyAuthParameters", "ApiKeyName") != "X-AuthSec-Event-Secret" {
		t.Errorf("connection must send the secret as X-AuthSec-Event-Secret: %v", conn)
	}
	if enforcetest.Dig(tpl, "Parameters", "EventSecret", "NoEcho") != true {
		t.Error("EventSecret must be NoEcho")
	}
	dest := enforcetest.Dig(tpl, "Resources", "AuthSecEventApiDestination", "Properties")
	if enforcetest.Dig(dest, "HttpMethod") != "POST" {
		t.Errorf("API destination method: %v", enforcetest.Dig(dest, "HttpMethod"))
	}
	// The invoke role may invoke the API destination and nothing else.
	stmts, _ := enforcetest.Dig(tpl, "Resources", "AuthSecEventInvokeRole", "Properties", "Policies", 0,
		"PolicyDocument", "Statement").([]any)
	if len(stmts) != 1 || enforcetest.Dig(stmts[0], "Action") != "events:InvokeApiDestination" {
		t.Errorf("invoke role policy: %v", stmts)
	}
	// The trail and its bucket exist only when asked for.
	for _, r := range []string{"AuthSecTrail", "AuthSecTrailBucket", "AuthSecTrailBucketPolicy"} {
		if c := enforcetest.Dig(tpl, "Resources", r, "Condition"); c != "CreateTrailCond" {
			t.Errorf("%s must be conditional on CreateTrail, got %v", r, c)
		}
	}
	// Every data-event kind is opt-in and off by default.
	for _, p := range []string{"DataEventsBedrockAgents", "DataEventsBedrockMantle", "DataEventsAgentCore", "DataEventsS3", "CreateTrail"} {
		if d := enforcetest.Dig(tpl, "Parameters", p, "Default"); d != "false" {
			t.Errorf("%s default %v, want 'false'", p, d)
		}
	}
	if !strings.Contains(awsdiscovery.AgentEventStreamTemplate, "UNVERIFIED") {
		t.Error("the mantle event source must be marked UNVERIFIED")
	}
}

// gateStatements returns the gate policy's statements by Sid.
func gateStatements(t *testing.T, name string, content any) map[string]any {
	t.Helper()
	stmts, ok := enforcetest.Dig(content, "Statement").([]any)
	if !ok {
		t.Fatalf("%s: no statements", name)
	}
	out := map[string]any{}
	for _, s := range stmts {
		sid, _ := enforcetest.Dig(s, "Sid").(string)
		if enforcetest.Dig(s, "Effect") != "Deny" {
			t.Errorf("%s: %s is not a Deny: the gate only ever denies", name, sid)
		}
		out[sid] = s
	}
	return out
}

func checkGate(t *testing.T, name string, content any) {
	t.Helper()
	st := gateStatements(t, name, content)
	model := st["DenyUntaggedModelCalls"]
	if model == nil {
		t.Fatalf("%s: no DenyUntaggedModelCalls", name)
	}
	actions := strs(enforcetest.Dig(model, "Action"))
	for _, a := range []string{"bedrock:InvokeModel*", "bedrock:Converse*", "bedrock:InvokeAgent",
		"bedrock:CreateModelInvocationJob", "bedrock-agentcore:InvokeAgentRuntime*", "bedrock-mantle:CreateInference"} {
		if !contains(actions, a) {
			t.Errorf("%s: model deny lacks %s", name, a)
		}
	}
	if v := enforcetest.Dig(model, "Condition", "Null", "aws:PrincipalTag/authsec:agent"); v != "true" {
		t.Errorf("%s: model deny must apply only without the authsec:agent principal tag, got %v", name, v)
	}
	for _, sid := range []string{"DenyAgentTagByKey", "DenyAgentTagByRequest"} {
		s := st[sid]
		if s == nil {
			t.Fatalf("%s: no %s (bypass through tags)", name, sid)
		}
		acts := strs(enforcetest.Dig(s, "Action"))
		for _, a := range []string{"sts:TagSession", "sts:AssumeRole", "iam:TagRole"} {
			if !contains(acts, a) {
				t.Errorf("%s/%s lacks %s", name, sid, a)
			}
		}
		if r, _ := enforcetest.Dig(s, "Condition", "ArnNotLike", "aws:PrincipalArn").(map[string]any); r["Ref"] != "AdminPrincipalArns" {
			t.Errorf("%s/%s: administrators must be excepted by aws:PrincipalArn = AdminPrincipalArns", name, sid)
		}
	}
	if !contains(strs(enforcetest.Dig(st["DenyAgentTagByKey"], "Action")), "iam:UntagRole") {
		t.Errorf("%s: removing the tag must be denied too", name)
	}
	if k := strs(enforcetest.Dig(st["DenyAgentTagByKey"], "Condition", "ForAnyValue:StringEqualsIgnoreCase", "aws:TagKeys")); !contains(k, "authsec:agent") {
		t.Errorf("%s: tag-key deny must name authsec:agent, got %v", name, k)
	}
	if v := enforcetest.Dig(st["DenyAgentTagByRequest"], "Condition", "Null", "aws:RequestTag/authsec:agent"); v != "false" {
		t.Errorf("%s: request-tag deny must match a request carrying authsec:agent, got %v", name, v)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func TestModelAccessSCPTemplate(t *testing.T) {
	tpl := parseAgentTemplate(t, "scp", awsdiscovery.ModelAccessSCPTemplate)
	p := enforcetest.Dig(tpl, "Resources", "AuthSecModelAccessGate")
	if enforcetest.Dig(p, "Type") != "AWS::Organizations::Policy" ||
		enforcetest.Dig(p, "Properties", "Type") != "SERVICE_CONTROL_POLICY" {
		t.Fatalf("SCP form must be an Organizations service control policy: %v", p)
	}
	checkGate(t, "scp", enforcetest.Dig(p, "Properties", "Content"))
}

func TestModelAccessPolicyTemplate(t *testing.T) {
	tpl := parseAgentTemplate(t, "policy", awsdiscovery.ModelAccessPolicyTemplate)
	p := enforcetest.Dig(tpl, "Resources", "AuthSecModelAccessGate")
	// Outside /authsec/: the enforcement role may rewrite and detach every
	// policy there.
	if enforcetest.Dig(p, "Type") != "AWS::IAM::ManagedPolicy" || enforcetest.Dig(p, "Properties", "Path") != "/authsec-gate/" {
		t.Fatalf("policy form must be a managed policy under /authsec-gate/: %v", p)
	}
	if r, _ := enforcetest.Dig(p, "Properties", "Roles").(map[string]any); r["Ref"] != "RoleNames" {
		t.Errorf("policy form is attached to the chosen roles, got %v", enforcetest.Dig(p, "Properties", "Roles"))
	}
	if strings.Contains(awsdiscovery.ModelAccessPolicyTemplate, "PermissionsBoundary") {
		t.Error("no permissions-boundary form (spec §10)")
	}
	checkGate(t, "policy", enforcetest.Dig(p, "Properties", "PolicyDocument"))
}

func TestModelAccessAuditDocument(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(awsdiscovery.ModelAccessAuditDocument, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["template_version"] != awsdiscovery.AgentRuntimeTemplateVersion || doc["mode"] != "audit" || doc["denies"] != false {
		t.Fatalf("audit document header: %v", doc)
	}
	if _, ok := doc["tagging_guide"].([]any); !ok {
		t.Error("audit mode must carry a tagging guide")
	}
	aff, _ := doc["affected"].(map[string]any)
	if aff["scp"] == nil || aff["rcp"] == nil || aff["policy"] == nil {
		t.Error("audit mode must say what each form would affect")
	}
}
