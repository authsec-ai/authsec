package agentactivity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SemconvPin is the OpenTelemetry GenAI semantic conventions revision the
// normaliser follows (status Development; spec §5).
const SemconvPin = "open-telemetry/semantic-conventions-genai@aa3b7f4394245fec260013898049780975a407a4 (gen-ai-dev/1.42.0-dev)"

// Span is one span, decoded from OTLP (protobuf or JSON) or from an AgentCore
// span record. Attribute values are string, bool, int64, float64, []any or
// map[string]any.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Kind         string // internal | server | client | producer | consumer | ""
	Start, End   time.Time
	// Status is "ok", "error" or "" (unset). The status message is never kept.
	Status   string
	Attrs    map[string]any
	Resource map[string]any
	Scope    string
}

// canonicalKeys are the span attributes kept, under their GenAI semantic
// convention name; aliases (OpenInference, OpenLLMetry, older semconv) map to
// the same name and only fill it when the canonical key is absent. Anything
// not listed is dropped (spec §5, §6).
var canonicalKeys = map[string]string{
	"gen_ai.operation.name":                 "gen_ai.operation.name",
	"gen_ai.provider.name":                  "gen_ai.provider.name",
	"gen_ai.request.model":                  "gen_ai.request.model",
	"gen_ai.response.model":                 "gen_ai.response.model",
	"gen_ai.usage.input_tokens":             "gen_ai.usage.input_tokens",
	"gen_ai.usage.output_tokens":            "gen_ai.usage.output_tokens",
	"gen_ai.usage.cache_read.input_tokens":  "gen_ai.usage.cache_read.input_tokens",
	"gen_ai.usage.cache_write.input_tokens": "gen_ai.usage.cache_write.input_tokens",
	"gen_ai.usage.reasoning.output_tokens":  "gen_ai.usage.reasoning.output_tokens",
	"gen_ai.response.finish_reasons":        "gen_ai.response.finish_reasons",
	"gen_ai.response.id":                    "gen_ai.response.id",
	"gen_ai.agent.id":                       "gen_ai.agent.id",
	"gen_ai.agent.name":                     "gen_ai.agent.name",
	"gen_ai.agent.version":                  "gen_ai.agent.version",
	"gen_ai.main_agent.id":                  "gen_ai.main_agent.id",
	"gen_ai.main_agent.name":                "gen_ai.main_agent.name",
	"gen_ai.conversation.id":                "gen_ai.conversation.id",
	"gen_ai.tool.name":                      "gen_ai.tool.name",
	"gen_ai.tool.type":                      "gen_ai.tool.type",
	"gen_ai.tool.call.id":                   "gen_ai.tool.call.id",
	"gen_ai.data_source.id":                 "gen_ai.data_source.id",
	"gen_ai.output.type":                    "gen_ai.output.type",
	"gen_ai.request.max_tokens":             "gen_ai.request.max_tokens",
	"gen_ai.request.temperature":            "gen_ai.request.temperature",
	"gen_ai.request.stream":                 "gen_ai.request.stream",
	"mcp.method.name":                       "mcp.method.name",
	"mcp.session.id":                        "mcp.session.id",
	"mcp.protocol.version":                  "mcp.protocol.version",
	"error.type":                            "error.type",
	"server.address":                        "server.address",
	"server.port":                           "server.port",
	"openinference.span.kind":               "openinference.span.kind",
	"traceloop.span.kind":                   "traceloop.span.kind",
	"traceloop.entity.name":                 "traceloop.entity.name",
	"llm.request.type":                      "llm.request.type",
}

// aliasKeys fill a canonical key only when the span did not set it.
var aliasKeys = map[string]string{
	"gen_ai.system":                  "gen_ai.provider.name",
	"llm.provider":                   "gen_ai.provider.name",
	"llm.system":                     "gen_ai.provider.name",
	"llm.model_name":                 "gen_ai.request.model",
	"llm.request.model":              "gen_ai.request.model",
	"llm.response.model":             "gen_ai.response.model",
	"gen_ai.usage.prompt_tokens":     "gen_ai.usage.input_tokens",
	"llm.token_count.prompt":         "gen_ai.usage.input_tokens",
	"llm.usage.prompt_tokens":        "gen_ai.usage.input_tokens",
	"gen_ai.usage.completion_tokens": "gen_ai.usage.output_tokens",
	"llm.token_count.completion":     "gen_ai.usage.output_tokens",
	"llm.usage.completion_tokens":    "gen_ai.usage.output_tokens",
	"llm.token_count.total":          "gen_ai.usage.total_tokens",
	"llm.usage.total_tokens":         "gen_ai.usage.total_tokens",
	"session.id":                     "gen_ai.conversation.id",
	"tool.name":                      "gen_ai.tool.name",
	"tool_call.id":                   "gen_ai.tool.call.id",
	"tool_call.function.name":        "gen_ai.tool.name",
}

// toolArgumentKeys carry tool call argument VALUES: only their digest is kept.
var toolArgumentKeys = []string{"gen_ai.tool.call.arguments", "tool_call.function.arguments"}

// resourceKeys are the resource attributes kept (as "resource.<key>").
var resourceKeys = []string{
	"service.name", "service.version", "cloud.provider", "cloud.platform", "cloud.account.id", "cloud.region",
	"cloud.resource_id", "faas.name", "faas.id", "aws.ecs.task.arn", "aws.ecs.task.family", "aws.ecs.task.revision",
	"aws.ecs.cluster.arn", "k8s.cluster.name", "k8s.namespace.name", "k8s.pod.name", "k8s.deployment.name",
	"authsec.workload_id", "authsec.identity_arn",
}

// onBehalfKeys name the human an agent acted for, strongest first. The GenAI
// conventions carry none; authsec.principal is ours.
var onBehalfKeys = []string{"authsec.principal", "enduser.id", "user.id"}

var modelOps = map[string]bool{"chat": true, "generate_content": true, "text_completion": true,
	"embeddings": true, "realtime_inference": true}

var deniedPattern = regexp.MustCompile(`(?i)(accessdenied|access_denied|unauthori[sz]ed|forbidden|permission|^40[13]$)`)

// runtimeARN matches an AgentCore runtime ARN and captures it without an
// endpoint or version suffix.
var runtimeARN = regexp.MustCompile(`^(arn:[a-z-]+:bedrock-agentcore:[a-z0-9-]*:[0-9]{12}:runtime/[A-Za-z0-9_-]+)`)

// AgentCoreRuntimeARN returns the runtime ARN prefix of s, or "".
func AgentCoreRuntimeARN(s string) string {
	if m := runtimeARN.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
		return m[1]
	}
	return ""
}

// Normalise turns one span into an activity row of the given source. ok is
// false when the span is not a GenAI, agent or MCP span (it is not stored) or
// has no trace or span id.
func Normalise(sp Span, source string) (Activity, bool) {
	traceID, spanID := NormaliseID(sp.TraceID), NormaliseID(sp.SpanID)
	if traceID == "" || spanID == "" {
		return Activity{}, false
	}
	kept := map[string]any{}
	for k, v := range sp.Attrs {
		if c, ok := canonicalKeys[k]; ok {
			if sv, ok := sanitiseValue(v); ok {
				kept[c] = sv
			}
		}
	}
	aliases := make([]string, 0, len(aliasKeys))
	for k := range aliasKeys {
		aliases = append(aliases, k)
	}
	sort.Strings(aliases) // deterministic when two aliases fill one key
	for _, k := range aliases {
		v, ok := sp.Attrs[k]
		if !ok {
			continue
		}
		c := aliasKeys[k]
		if _, set := kept[c]; set {
			continue
		}
		if sv, ok := sanitiseValue(v); ok {
			kept[c] = sv
		}
	}

	kind, action, ref := classify(sp, kept)
	if kind == "" {
		return Activity{}, false
	}

	attrs := map[string]any{}
	for k, v := range kept {
		attrs[k] = v
	}
	for _, k := range toolArgumentKeys {
		if v, ok := sp.Attrs[k]; ok {
			attrs["tool_arguments_sha256"] = Digest(v)
			break
		}
	}
	if sp.Name != "" {
		attrs["span.name"] = Truncate(sp.Name, MaxAttrString)
	}
	if sp.Kind != "" {
		attrs["span.kind"] = sp.Kind
	}
	if sp.Status != "" {
		attrs["span.status"] = sp.Status
	}
	if !sp.Start.IsZero() && !sp.End.IsZero() && sp.End.After(sp.Start) {
		attrs["span.duration_ms"] = sp.End.Sub(sp.Start).Milliseconds()
	}
	if sp.Scope != "" {
		attrs["scope.name"] = Truncate(sp.Scope, MaxAttrString)
	}
	for _, k := range resourceKeys {
		if v, ok := sp.Resource[k]; ok {
			if sv, ok := sanitiseValue(v); ok {
				attrs["resource."+k] = sv
			}
		}
	}
	attrs = capKeys(attrs)

	outcome := OutcomeSuccess
	errType, _ := kept["error.type"].(string)
	switch {
	case errType != "" && deniedPattern.MatchString(errType):
		outcome = OutcomeDenied
	case sp.Status == "error" || errType != "":
		outcome = OutcomeError
	}

	at := sp.Start
	if at.IsZero() {
		at = sp.End
	}
	a := Activity{
		Source: source, Kind: kind, OccurredAt: at.UTC(),
		Action: Truncate(action, MaxAction), ResourceRef: Truncate(ref, MaxResourceRef),
		Outcome: outcome, OnBehalfOf: Truncate(onBehalfOf(sp), MaxOnBehalfOf),
		TraceID: traceID, SpanID: spanID, ParentSpanID: NormaliseID(sp.ParentSpanID),
		ProviderEventID: traceID + ":" + spanID,
		Attrs:           attrs,
		Hints:           HintsFrom(sp.Resource),
	}
	if id, _ := kept["gen_ai.agent.id"].(string); id != "" {
		a.Hints.AgentID = id
	}
	return a, true
}

// classify decides kind, action and resource of a span (spec §5), or "" for
// a span that is none of GenAI, agent or MCP.
func classify(sp Span, kept map[string]any) (kind, action, ref string) {
	str := func(k string) string { s, _ := kept[k].(string); return s }
	op := strings.ToLower(str("gen_ai.operation.name"))
	mcp := str("mcp.method.name")
	model := str("gen_ai.response.model")
	if model == "" {
		model = str("gen_ai.request.model")
	}
	tool := str("gen_ai.tool.name")
	agent := str("gen_ai.agent.name")
	if agent == "" {
		agent = str("gen_ai.agent.id")
	}
	if agent == "" {
		agent = str("traceloop.entity.name")
	}
	oi := strings.ToUpper(str("openinference.span.kind"))
	tl := strings.ToLower(str("traceloop.span.kind"))
	llmType := strings.ToLower(str("llm.request.type"))

	switch {
	case modelOps[op]:
		return KindModelCall, op, model
	case op == "execute_tool":
		return KindToolCall, op, tool
	case op == "retrieval" || op == "search_memory":
		return KindDataAccess, op, firstNonEmpty(str("gen_ai.data_source.id"), tool)
	case op != "":
		return KindAgentStep, op, firstNonEmpty(agent, tool, sp.Name)
	case mcp == "tools/call":
		return KindToolCall, mcp, tool
	case mcp != "":
		return KindAgentStep, mcp, firstNonEmpty(tool, agent)
	}
	switch oi {
	case "LLM", "EMBEDDING", "RERANKER":
		return KindModelCall, strings.ToLower(oi), model
	case "TOOL":
		return KindToolCall, "execute_tool", firstNonEmpty(tool, sp.Name)
	case "RETRIEVER":
		return KindDataAccess, "retrieval", firstNonEmpty(str("gen_ai.data_source.id"), sp.Name)
	case "":
	default:
		return KindAgentStep, strings.ToLower(oi), firstNonEmpty(agent, sp.Name)
	}
	switch tl {
	case "tool":
		return KindToolCall, "execute_tool", firstNonEmpty(tool, agent, sp.Name)
	case "agent", "workflow", "task":
		return KindAgentStep, tl, firstNonEmpty(agent, sp.Name)
	}
	if llmType != "" || model != "" {
		a := llmType
		if a == "" {
			a = "chat"
		}
		return KindModelCall, a, model
	}
	return "", "", ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func onBehalfOf(sp Span) string {
	for _, m := range []map[string]any{sp.Attrs, sp.Resource} {
		for _, k := range onBehalfKeys {
			if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// HintsFrom reads attribution hints from resource attributes.
func HintsFrom(res map[string]any) Hints {
	s := func(k string) string {
		switch v := res[k].(type) {
		case string:
			return Truncate(strings.TrimSpace(v), MaxResourceRef)
		case int64:
			return fmt.Sprint(v)
		case float64:
			if v == math.Trunc(v) {
				return fmt.Sprint(int64(v))
			}
		}
		return ""
	}
	h := Hints{
		WorkloadID: s("authsec.workload_id"), IdentityARN: s("authsec.identity_arn"),
		AccountID: s("cloud.account.id"), Region: s("cloud.region"),
		FaaSName: s("faas.name"), ECSFamily: s("aws.ecs.task.family"), ECSRevision: s("aws.ecs.task.revision"),
	}
	for _, k := range []string{"cloud.resource_id", "faas.id", "aws.lambda.invoked_arn"} {
		if v := s(k); strings.HasPrefix(v, "arn:") {
			h.ResourceARN = v
			break
		}
	}
	h.RuntimeARN = AgentCoreRuntimeARN(h.ResourceARN)
	return h
}

// Digest is the sha256 hex of a value as sent: the string itself, or the JSON
// of anything else.
func Digest(v any) string {
	var b []byte
	if s, ok := v.(string); ok {
		b = []byte(s)
	} else {
		b, _ = json.Marshal(v)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sanitiseValue bounds one kept value: strings truncated, arrays of scalars
// capped, maps and bytes dropped.
func sanitiseValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		return Truncate(x, MaxAttrString), true
	case bool, int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, false
		}
		return x, true
	case []any:
		out := []any{}
		for _, e := range x {
			if len(out) == MaxArrayItems {
				break
			}
			switch e.(type) {
			case string, bool, int64, float64, int:
				sv, _ := sanitiseValue(e)
				out = append(out, sv)
			}
		}
		return out, true
	}
	return nil, false
}

// capKeys keeps at most MaxAttrKeys keys (sorted, so the choice is stable).
func capKeys(m map[string]any) map[string]any {
	if len(m) <= MaxAttrKeys {
		return m
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]any, MaxAttrKeys)
	for _, k := range keys[:MaxAttrKeys] {
		out[k] = m[k]
	}
	return out
}
