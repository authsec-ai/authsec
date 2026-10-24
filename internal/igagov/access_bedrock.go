package igagov

import (
	"regexp"
	"strings"
)

// Bedrock models, Bedrock agents and AgentCore runtimes in access policies
// (step 6, block only). Action tables were checked against the AWS service
// reference for bedrock and bedrock-agentcore
// (servicereference.us-east-1.amazonaws.com, 2026-10-24).
//
// A model block denies the foundation model in every region (a call through a
// cross-region inference profile is also checked on the model in the region
// it lands in), the system inference profiles routing to it, and -- held to
// bedrock:ModelArn -- InvokeModel on any other resource that names the model
// (an application inference profile, a prompt router). Unverified against a
// live account, so chosen to fail safe: when the key is absent that
// statement matches nothing.

// Bedrock and AgentCore access-policy names.
const (
	AccessTypeBedrockModel     = "bedrock_model"
	AccessTypeBedrockAgent     = "bedrock_agent"
	AccessTypeAgentCoreRuntime = "agentcore_runtime"
	AccessSidModel             = "AuthSecAccessModel"
	AccessSidModelRoutes       = "AuthSecAccessModelRoutes"
	AccessSidAgent             = "AuthSecAccessAgent"
	AccessSidRuntime           = "AuthSecAccessRuntime"
	KeyBedrockModelArn         = "bedrock:ModelArn"
)

// noDeleteErr refuses delete on a type that has nothing to delete.
func noDeleteErr(noun string) error {
	return &AccessFieldError{Field: "access", Message: "A " + noun + " has nothing to delete; choose read, write or all."}
}

/* --------------------------------- model ---------------------------------- */

var (
	bedrockInvoke = []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}
	// read: calling the model (Converse and ConverseStream authorize as
	// InvokeModel and InvokeModelWithResponseStream) and batch inference.
	bedrockModelRead = append([]string{"bedrock:CreateModelInvocationJob"}, bedrockInvoke...)
	// write: building on the model.
	bedrockModelWrite = []string{"bedrock:CreateModelCustomizationJob", "bedrock:CreateProvisionedModelThroughput", "bedrock:UpdateProvisionedModelThroughput",
		"bedrock:CreateInferenceProfile", "bedrock:CreatePromptRouter", "bedrock:CreateEvaluationJob", "bedrock:CreateModelEvaluationJob",
		"bedrock:CreateAdvancedPromptOptimizationJob"}
)

// The geography prefixes of system inference profiles ("us.anthropic...").
var bedrockGeos = map[string]bool{"us": true, "eu": true, "apac": true, "us-gov": true, "jp": true, "au": true, "ca": true, "global": true}

const reModelID = `([a-z0-9-]+\.[A-Za-z0-9._:-]{1,200})`

var (
	reFoundationModelARN = regexp.MustCompile(`^arn:(aws[a-z-]*):bedrock:(?:[a-z]{2}(?:-[a-z]+)+-\d+|\*)?::foundation-model/` + reModelID + `$`)
	reInferenceProfARN   = regexp.MustCompile(`^arn:(aws[a-z-]*):bedrock:[a-z]{2}(?:-[a-z]+)+-\d+:\d{12}:inference-profile/([a-z-]+)\.` + reModelID + `$`)
)

// BedrockModelTarget is one foundation model, in every region.
type BedrockModelTarget struct {
	Partition, Model string
}

// ParseBedrockModelARN reads the model a foundation-model ARN, or a system
// inference profile routing to one, names.
func ParseBedrockModelARN(arn string) (BedrockModelTarget, bool) {
	arn = strings.TrimSpace(arn)
	if m := reFoundationModelARN.FindStringSubmatch(arn); m != nil {
		return BedrockModelTarget{Partition: m[1], Model: m[2]}, true
	}
	if m := reInferenceProfARN.FindStringSubmatch(arn); m != nil && bedrockGeos[m[2]] {
		return BedrockModelTarget{Partition: m[1], Model: m[3]}, true
	}
	return BedrockModelTarget{}, false
}

// ModelARN is the model in every region; ProfileARN every system inference
// profile routing to it.
// GlobalModelARN is the model as a global cross-Region inference profile
// names it: with no Region ("arn:aws:bedrock:::foundation-model/..."), per the
// Bedrock inference-profile prerequisites. Denied explicitly rather than
// trusting the Region wildcard to match an empty field.
func (t BedrockModelTarget) GlobalModelARN() string {
	return "arn:" + t.Partition + ":bedrock:::foundation-model/" + t.Model
}

func (t BedrockModelTarget) ModelARN() string {
	return "arn:" + t.Partition + ":bedrock:*::foundation-model/" + t.Model
}
func (t BedrockModelTarget) ProfileARN() string {
	return "arn:" + t.Partition + ":bedrock:*:*:inference-profile/*." + t.Model
}

// BedrockModelTarget is an AWSAccessTarget. Its ARN names no account or
// region: it is placed by the accounts whose scans saw it.
func (t BedrockModelTarget) Type() string         { return AccessTypeBedrockModel }
func (t BedrockModelTarget) Service() string      { return "bedrock" }
func (t BedrockModelTarget) Noun() string         { return "model" }
func (t BedrockModelTarget) ARN() string          { return t.ModelARN() }
func (t BedrockModelTarget) Name() string         { return t.Model }
func (t BedrockModelTarget) ARNAccount() string   { return "" }
func (t BedrockModelTarget) ARNRegion() string    { return "" }
func (t BedrockModelTarget) ARNPartition() string { return t.Partition }
func (t BedrockModelTarget) Where() string        { return "Bedrock model " + t.Model + " (every region)" }

// Statements is the model's block document; an allow is refused.
func (t BedrockModelTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	all, read := accessHas(access, AccessAll), accessHas(access, AccessRead)
	if !all && accessHas(access, AccessDelete) {
		return nil, noDeleteErr("model")
	}
	var acts []string
	switch {
	case all:
		acts = []string{"bedrock:*"}
	default:
		if read {
			acts = append(acts, bedrockModelRead...)
		}
		if accessHas(access, AccessWrite) {
			acts = append(acts, bedrockModelWrite...)
		}
	}
	res := []string{t.ModelARN(), t.GlobalModelARN()}
	if read || all {
		res = append(res, t.ProfileARN())
	}
	stmts := []AccessStatement{{Sid: AccessSidModel, Actions: sortedUnique(acts), Resources: res}}
	if read || all {
		stmts = append(stmts, AccessStatement{Sid: AccessSidModelRoutes, Actions: bedrockInvoke, Resources: []string{"*"},
			Cond: map[string]any{CondStringLike: map[string]any{KeyBedrockModelArn: t.ModelARN()}}})
	}
	return stmts, nil
}

// Notes is the preview's warnings for a model.
func (t BedrockModelTarget) Notes(effect string, access []string) []AccessNote {
	all, read := accessHas(access, AccessAll), accessHas(access, AccessRead)
	var out []AccessNote
	add := func(code, msg string) { out = append(out, AccessNote{Code: code, Message: msg}) }
	if read || all {
		add("model_routes_blocked", "Calling the model through cross-Region and global inference profiles and batch inference jobs is refused too, in every Region.")
		add("app_profiles_unverified", "Calls through an application inference profile or a prompt router are refused only if AWS also checks the model they route to, which AuthSec has not verified: test one before relying on it.")
		add("other_models_not_covered", "Other versions of the model (another model ID) are not covered, nor custom, imported or Marketplace models, or provisioned throughput already bought on this model.")
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t BedrockModelTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users (including those holding Bedrock API keys) and groups are unchanged."
}

/* --------------------------------- agent ---------------------------------- */

var (
	bedrockAgentRead  = []string{"bedrock:InvokeAgent", "bedrock:GetAgentMemory"}
	bedrockAgentWrite = []string{"bedrock:UpdateAgent", "bedrock:PrepareAgent", "bedrock:CreateAgentAlias", "bedrock:UpdateAgentAlias",
		"bedrock:CreateAgentActionGroup", "bedrock:UpdateAgentActionGroup", "bedrock:AssociateAgentCollaborator", "bedrock:DisassociateAgentCollaborator",
		"bedrock:UpdateAgentCollaborator", "bedrock:AssociateAgentKnowledgeBase", "bedrock:DisassociateAgentKnowledgeBase", "bedrock:UpdateAgentKnowledgeBase",
		"bedrock:TagResource", "bedrock:UntagResource"}
	bedrockAgentDelete = []string{"bedrock:DeleteAgent", "bedrock:DeleteAgentAlias", "bedrock:DeleteAgentVersion", "bedrock:DeleteAgentActionGroup",
		"bedrock:DeleteAgentMemory"}
)

var reBedrockAgentARN = regexp.MustCompile(`^arn:(aws[a-z-]*):bedrock:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):(?:agent/([0-9A-Za-z]{10})|agent-alias/([0-9A-Za-z]{10})/(?:[0-9A-Za-z]{10}|\*))$`)

// BedrockAgentTarget is one Bedrock agent, every alias and version.
type BedrockAgentTarget struct {
	Partition, Region, Account, Agent string
}

// ParseBedrockAgentARN reads the agent an agent or agent-alias ARN names.
func ParseBedrockAgentARN(arn string) (BedrockAgentTarget, bool) {
	m := reBedrockAgentARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return BedrockAgentTarget{}, false
	}
	id := m[4]
	if id == "" {
		id = m[5]
	}
	return BedrockAgentTarget{Partition: m[1], Region: m[2], Account: m[3], Agent: id}, true
}

func (t BedrockAgentTarget) base() string {
	return "arn:" + t.Partition + ":bedrock:" + t.Region + ":" + t.Account + ":"
}

// AliasesARN is every alias of the agent.
func (t BedrockAgentTarget) AliasesARN() string { return t.base() + "agent-alias/" + t.Agent + "/*" }

// BedrockAgentTarget is an AWSAccessTarget.
func (t BedrockAgentTarget) Type() string         { return AccessTypeBedrockAgent }
func (t BedrockAgentTarget) Service() string      { return "bedrock" }
func (t BedrockAgentTarget) Noun() string         { return "agent" }
func (t BedrockAgentTarget) ARN() string          { return t.base() + "agent/" + t.Agent }
func (t BedrockAgentTarget) Name() string         { return t.Agent }
func (t BedrockAgentTarget) ARNAccount() string   { return t.Account }
func (t BedrockAgentTarget) ARNRegion() string    { return t.Region }
func (t BedrockAgentTarget) ARNPartition() string { return t.Partition }
func (t BedrockAgentTarget) Where() string {
	return "Bedrock agent " + t.Agent + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the agent's block document; an allow is refused.
func (t BedrockAgentTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	acts := levelActions(access, "bedrock:*", bedrockAgentRead, bedrockAgentWrite, bedrockAgentDelete)
	if len(acts) == 0 {
		return nil, nil
	}
	return []AccessStatement{{Sid: AccessSidAgent, Actions: acts, Resources: []string{t.ARN(), t.AliasesARN()}}}, nil
}

// Notes is the preview's warnings for an agent.
func (t BedrockAgentTarget) Notes(effect string, access []string) []AccessNote {
	out := []AccessNote{{Code: "aliases_covered", Message: "The block covers every alias and version of the agent."}}
	if accessHas(access, AccessRead, AccessAll) {
		out = append(out, AccessNote{Code: "agent_role_unchanged",
			Message: "What the agent itself does runs as its own service role, which this block does not change."})
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t BedrockAgentTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users and groups are unchanged."
}

/* ------------------------------ AgentCore runtime ------------------------------ */

var (
	runtimeRead = []string{"bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeAgentRuntimeForUser",
		"bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream", "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
		"bedrock-agentcore:InvokeAgentRuntimeCommand", "bedrock-agentcore:InvokeAgentRuntimeCommandShell", "bedrock-agentcore:GetAgentCard"}
	runtimeWrite = []string{"bedrock-agentcore:UpdateAgentRuntime", "bedrock-agentcore:CreateAgentRuntimeEndpoint", "bedrock-agentcore:UpdateAgentRuntimeEndpoint",
		"bedrock-agentcore:PutResourcePolicy", "bedrock-agentcore:DeleteResourcePolicy", "bedrock-agentcore:StopRuntimeSession",
		"bedrock-agentcore:TagResource", "bedrock-agentcore:UntagResource"}
	runtimeDelete = []string{"bedrock-agentcore:DeleteAgentRuntime", "bedrock-agentcore:DeleteAgentRuntimeEndpoint"}
)

var reRuntimeARN = regexp.MustCompile(`^arn:(aws[a-z-]*):bedrock-agentcore:([a-z]{2}(?:-[a-z]+)+-\d+):(\d{12}):runtime/([A-Za-z][A-Za-z0-9_-]{0,99})(?:/runtime-endpoint/(?:[A-Za-z0-9_-]+|\*))?$`)

// AgentCoreRuntimeTarget is one AgentCore runtime and its endpoints.
type AgentCoreRuntimeTarget struct {
	Partition, Region, Account, Runtime string
}

// ParseAgentCoreRuntimeARN reads the runtime a runtime or endpoint ARN names.
func ParseAgentCoreRuntimeARN(arn string) (AgentCoreRuntimeTarget, bool) {
	m := reRuntimeARN.FindStringSubmatch(strings.TrimSpace(arn))
	if m == nil {
		return AgentCoreRuntimeTarget{}, false
	}
	return AgentCoreRuntimeTarget{Partition: m[1], Region: m[2], Account: m[3], Runtime: m[4]}, true
}

// AgentCoreRuntimeTarget is an AWSAccessTarget.
func (t AgentCoreRuntimeTarget) Type() string    { return AccessTypeAgentCoreRuntime }
func (t AgentCoreRuntimeTarget) Service() string { return "bedrock-agentcore" }
func (t AgentCoreRuntimeTarget) Noun() string    { return "agent runtime" }
func (t AgentCoreRuntimeTarget) ARN() string {
	return "arn:" + t.Partition + ":bedrock-agentcore:" + t.Region + ":" + t.Account + ":runtime/" + t.Runtime
}

// EndpointsARN is every endpoint of the runtime.
func (t AgentCoreRuntimeTarget) EndpointsARN() string { return t.ARN() + "/runtime-endpoint/*" }
func (t AgentCoreRuntimeTarget) Name() string         { return t.Runtime }
func (t AgentCoreRuntimeTarget) ARNAccount() string   { return t.Account }
func (t AgentCoreRuntimeTarget) ARNRegion() string    { return t.Region }
func (t AgentCoreRuntimeTarget) ARNPartition() string { return t.Partition }
func (t AgentCoreRuntimeTarget) Where() string {
	return "AgentCore runtime " + t.Runtime + " (" + t.Region + ", account " + t.Account + ")"
}

// Statements is the runtime's block document; an allow is refused.
func (t AgentCoreRuntimeTarget) Statements(effect string, access []string) ([]AccessStatement, error) {
	if effect != AccessEffectBlock {
		return nil, ErrAccessBlockOnly
	}
	acts := levelActions(access, "bedrock-agentcore:*", runtimeRead, runtimeWrite, runtimeDelete)
	if len(acts) == 0 {
		return nil, nil
	}
	return []AccessStatement{{Sid: AccessSidRuntime, Actions: acts, Resources: []string{t.ARN(), t.EndpointsARN()}}}, nil
}

// Notes is the preview's warnings for a runtime.
func (t AgentCoreRuntimeTarget) Notes(effect string, access []string) []AccessNote {
	out := []AccessNote{{Code: "endpoints_covered", Message: "The block covers every endpoint of the runtime."}}
	if accessHas(access, AccessRead, AccessAll) {
		out = append(out,
			AccessNote{Code: "oauth_callers_not_covered", Message: "Callers that present an OAuth token to a runtime set up with a JWT authorizer do not go through IAM and are not covered."},
			AccessNote{Code: "agent_role_unchanged", Message: "What the agent itself does runs as its own execution role, which this block does not change."})
	}
	return out
}

// OtherPaths is the other_paths warning.
func (t AgentCoreRuntimeTarget) OtherPaths() string {
	return "This changes only the chosen roles. Other roles, users, groups and the runtime's resource policy are unchanged."
}

// levelActions is the union of the levels' actions, or all for "all".
func levelActions(access []string, all string, read, write, del []string) []string {
	if accessHas(access, AccessAll) {
		return []string{all}
	}
	var acts []string
	if accessHas(access, AccessRead) {
		acts = append(acts, read...)
	}
	if accessHas(access, AccessWrite) {
		acts = append(acts, write...)
	}
	if accessHas(access, AccessDelete) {
		acts = append(acts, del...)
	}
	return sortedUnique(acts)
}
