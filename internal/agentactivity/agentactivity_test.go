package agentactivity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

const (
	tTrace = "5b8efff798038103d269b633813fc60c"
	tSpan  = "eee19b7ec3c1b174"
)

// secretContent is planted in every content attribute; it must never appear
// in what is stored.
const secretContent = "PLANTED-CONTENT-sk-live-123"

func contentAttrs() map[string]any {
	return map[string]any{
		"gen_ai.input.messages":                 `[{"role":"user","parts":[{"type":"text","content":"` + secretContent + `"}]}]`,
		"gen_ai.output.messages":                secretContent,
		"gen_ai.system_instructions":            secretContent,
		"gen_ai.prompt.0.content":               secretContent,
		"gen_ai.completion.0.content":           secretContent,
		"gen_ai.prompt":                         secretContent,
		"gen_ai.tool.call.result":               secretContent,
		"gen_ai.tool.definitions":               secretContent,
		"gen_ai.retrieval.query.text":           secretContent,
		"llm.input_messages.0.message.content":  secretContent,
		"llm.output_messages.0.message.content": secretContent,
		"input.value":                           secretContent,
		"output.value":                          secretContent,
		"traceloop.entity.input":                secretContent,
		"traceloop.entity.output":               secretContent,
		"http.request.header.authorization":     secretContent,
	}
}

func mustNotLeak(t *testing.T, a Activity) {
	t.Helper()
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), secretContent) || strings.Contains(string(raw), "sk-live") {
		t.Fatalf("content leaked into the stored row: %s", raw)
	}
}

func TestNormaliseChatDropsContent(t *testing.T) {
	attrs := contentAttrs()
	attrs["gen_ai.operation.name"] = "chat"
	attrs["gen_ai.provider.name"] = "aws.bedrock"
	attrs["gen_ai.request.model"] = "anthropic.claude-3-haiku"
	attrs["gen_ai.response.model"] = "anthropic.claude-3-haiku-20240307"
	attrs["gen_ai.usage.input_tokens"] = int64(120)
	attrs["gen_ai.usage.output_tokens"] = int64(42)
	attrs["gen_ai.conversation.id"] = "conv-1"
	attrs["user.id"] = "alice@example.com"
	start := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	a, ok := Normalise(Span{TraceID: strings.ToUpper(tTrace), SpanID: tSpan, ParentSpanID: "0000000000000000",
		Name: "chat anthropic.claude-3-haiku", Kind: "client", Start: start, End: start.Add(1500 * time.Millisecond),
		Attrs: attrs, Resource: map[string]any{"service.name": "travel-agent", "cloud.account.id": "111111111111",
			"faas.name": "book-flight", "secret.resource.thing": secretContent}}, SourceOTLP)
	if !ok {
		t.Fatal("chat span not recognised")
	}
	mustNotLeak(t, a)
	if a.Kind != KindModelCall || a.Action != "chat" || a.ResourceRef != "anthropic.claude-3-haiku-20240307" || a.Outcome != OutcomeSuccess {
		t.Fatalf("row: %+v", a)
	}
	if a.TraceID != tTrace || a.SpanID != tSpan || a.ParentSpanID != "" || a.ProviderEventID != tTrace+":"+tSpan {
		t.Fatalf("ids: %+v", a)
	}
	if a.OnBehalfOf != "alice@example.com" {
		t.Errorf("on_behalf_of = %q", a.OnBehalfOf)
	}
	if a.Attrs["gen_ai.usage.input_tokens"] != int64(120) || a.Attrs["span.duration_ms"] != int64(1500) ||
		a.Attrs["resource.faas.name"] != "book-flight" {
		t.Errorf("attrs: %v", a.Attrs)
	}
	if _, ok := a.Attrs["resource.secret.resource.thing"]; ok {
		t.Error("a resource attribute outside the allowlist was kept")
	}
	if a.Hints.AccountID != "111111111111" || a.Hints.FaaSName != "book-flight" {
		t.Errorf("hints: %+v", a.Hints)
	}
}

func TestNormaliseToolCallDigestsArguments(t *testing.T) {
	args := `{"card_number":"4111111111111111","cvv":"123"}`
	attrs := contentAttrs()
	attrs["gen_ai.operation.name"] = "execute_tool"
	attrs["gen_ai.tool.name"] = "pay"
	attrs["gen_ai.tool.call.id"] = "call_1"
	attrs["gen_ai.tool.call.arguments"] = args
	attrs["error.type"] = "AccessDeniedException"
	a, ok := Normalise(Span{TraceID: tTrace, SpanID: tSpan, Name: "execute_tool pay", Attrs: attrs, Status: "error"}, SourceOTLP)
	if !ok || a.Kind != KindToolCall || a.ResourceRef != "pay" || a.Outcome != OutcomeDenied {
		t.Fatalf("tool row: %v %+v", ok, a)
	}
	mustNotLeak(t, a)
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "4111111111111111") || strings.Contains(string(raw), "cvv") {
		t.Fatalf("argument values stored: %s", raw)
	}
	if a.Attrs["tool_arguments_sha256"] != Digest(args) || len(Digest(args)) != 64 {
		t.Errorf("digest: %v", a.Attrs["tool_arguments_sha256"])
	}
	// An argument object (not a string) is digested as JSON.
	attrs["gen_ai.tool.call.arguments"] = map[string]any{"a": int64(1)}
	a, _ = Normalise(Span{TraceID: tTrace, SpanID: tSpan, Attrs: attrs}, SourceOTLP)
	if a.Attrs["tool_arguments_sha256"] != Digest(map[string]any{"a": int64(1)}) {
		t.Errorf("object digest: %v", a.Attrs["tool_arguments_sha256"])
	}
}

func TestNormaliseKindsAndAliases(t *testing.T) {
	cases := []struct {
		name   string
		attrs  map[string]any
		kind   string
		action string
		ref    string
	}{
		{"invoke_agent", map[string]any{"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "travel"}, KindAgentStep, "invoke_agent", "travel"},
		{"embeddings", map[string]any{"gen_ai.operation.name": "embeddings", "gen_ai.request.model": "titan"}, KindModelCall, "embeddings", "titan"},
		{"retrieval", map[string]any{"gen_ai.operation.name": "retrieval", "gen_ai.data_source.id": "kb-1"}, KindDataAccess, "retrieval", "kb-1"},
		{"mcp tools/call", map[string]any{"mcp.method.name": "tools/call", "gen_ai.tool.name": "search"}, KindToolCall, "tools/call", "search"},
		{"mcp list", map[string]any{"mcp.method.name": "tools/list"}, KindAgentStep, "tools/list", ""},
		{"openinference llm", map[string]any{"openinference.span.kind": "LLM", "llm.model_name": "gpt-4o", "llm.token_count.prompt": int64(5)}, KindModelCall, "llm", "gpt-4o"},
		{"openinference tool", map[string]any{"openinference.span.kind": "TOOL", "tool.name": "lookup", "tool_call.function.arguments": "{}"}, KindToolCall, "execute_tool", "lookup"},
		{"openinference chain", map[string]any{"openinference.span.kind": "CHAIN"}, KindAgentStep, "chain", "s"},
		{"openllmetry", map[string]any{"gen_ai.system": "openai", "gen_ai.request.model": "gpt-4o", "llm.request.type": "chat", "gen_ai.usage.prompt_tokens": int64(9)}, KindModelCall, "chat", "gpt-4o"},
		{"traceloop agent", map[string]any{"traceloop.span.kind": "agent", "traceloop.entity.name": "planner"}, KindAgentStep, "agent", "planner"},
	}
	for _, c := range cases {
		a, ok := Normalise(Span{TraceID: tTrace, SpanID: tSpan, Name: "s", Attrs: c.attrs}, SourceOTLP)
		if !ok || a.Kind != c.kind || a.Action != c.action || a.ResourceRef != c.ref {
			t.Errorf("%s: ok=%v kind=%q action=%q ref=%q", c.name, ok, a.Kind, a.Action, a.ResourceRef)
		}
	}
	a, _ := Normalise(Span{TraceID: tTrace, SpanID: tSpan, Attrs: map[string]any{"gen_ai.system": "openai",
		"gen_ai.request.model": "gpt-4o", "gen_ai.usage.prompt_tokens": int64(9), "llm.token_count.total": int64(12)}}, SourceOTLP)
	if a.Attrs["gen_ai.provider.name"] != "openai" || a.Attrs["gen_ai.usage.input_tokens"] != int64(9) || a.Attrs["gen_ai.usage.total_tokens"] != int64(12) {
		t.Errorf("aliases: %v", a.Attrs)
	}
	// The canonical key wins over an alias.
	a, _ = Normalise(Span{TraceID: tTrace, SpanID: tSpan, Attrs: map[string]any{"gen_ai.operation.name": "chat",
		"gen_ai.provider.name": "aws.bedrock", "gen_ai.system": "openai"}}, SourceOTLP)
	if a.Attrs["gen_ai.provider.name"] != "aws.bedrock" {
		t.Errorf("canonical lost to alias: %v", a.Attrs)
	}
	// Plain HTTP spans, and spans without ids, are not activity.
	if _, ok := Normalise(Span{TraceID: tTrace, SpanID: tSpan, Name: "GET /", Attrs: map[string]any{"http.method": "GET"}}, SourceOTLP); ok {
		t.Error("an HTTP span was kept")
	}
	if _, ok := Normalise(Span{TraceID: "", SpanID: tSpan, Attrs: map[string]any{"gen_ai.operation.name": "chat"}}, SourceOTLP); ok {
		t.Error("a span without trace id was kept")
	}
	if _, ok := Normalise(Span{TraceID: "zz", SpanID: tSpan, Attrs: map[string]any{"gen_ai.operation.name": "chat"}}, SourceOTLP); ok {
		t.Error("a span with a non-hex trace id was kept")
	}
}

func TestNormaliseBoundsValues(t *testing.T) {
	attrs := map[string]any{"gen_ai.operation.name": "chat", "gen_ai.request.model": strings.Repeat("m", 2000),
		"gen_ai.response.finish_reasons": []any{"stop", "length", map[string]any{"x": 1}}}
	a, _ := Normalise(Span{TraceID: tTrace, SpanID: tSpan, Name: strings.Repeat("n", 1000), Attrs: attrs}, SourceOTLP)
	if len(a.ResourceRef) > MaxResourceRef || len(a.Attrs["gen_ai.request.model"].(string)) > MaxAttrString ||
		len(a.Attrs["span.name"].(string)) > MaxAttrString || len(a.Action) > MaxAction {
		t.Fatalf("not bounded: %d %d", len(a.ResourceRef), len(a.Attrs["gen_ai.request.model"].(string)))
	}
	if fr := a.Attrs["gen_ai.response.finish_reasons"].([]any); len(fr) != 2 {
		t.Errorf("finish reasons: %v", fr)
	}
}

func TestHintsAttribution(t *testing.T) {
	h := HintsFrom(map[string]any{"cloud.resource_id": "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/travel-AbC_12/runtime-endpoint/DEFAULT",
		"cloud.account.id": float64(111111111111), "authsec.workload_id": "w", "aws.ecs.task.family": "f", "aws.ecs.task.revision": int64(3)})
	if h.RuntimeARN != "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/travel-AbC_12" {
		t.Errorf("runtime arn: %q", h.RuntimeARN)
	}
	if h.AccountID != "111111111111" || h.WorkloadID != "w" || h.ECSRevision != "3" {
		t.Errorf("hints: %+v", h)
	}
	if (Hints{}).Empty() != true || h.Empty() || h.Key() == (Hints{}).Key() {
		t.Error("Empty/Key")
	}
	if NormaliseID("1-5759e988-bd862e3fe1be46a994272793") != "5759e988bd862e3fe1be46a994272793" {
		t.Error("x-ray trace id")
	}
}

/* ---------------------------------- OTLP ---------------------------------- */

func kv(k string, v *commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: v}
}
func sv(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}
func iv(i int64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: i}}
}

func TestDecodeOTLPProtobuf(t *testing.T) {
	tid, _ := hex.DecodeString(tTrace)
	sid, _ := hex.DecodeString(tSpan)
	td := &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("service.name", sv("agent")), kv("faas.name", sv("fn"))}},
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{Name: "opentelemetry.instrumentation.openai"},
			Spans: []*tracepb.Span{{TraceId: tid, SpanId: sid, Name: "chat gpt-4o", Kind: tracepb.Span_SPAN_KIND_CLIENT,
				StartTimeUnixNano: 1762336800000000000, EndTimeUnixNano: 1762336801000000000,
				Attributes: []*commonpb.KeyValue{kv("gen_ai.operation.name", sv("chat")), kv("gen_ai.usage.input_tokens", iv(7)),
					kv("gen_ai.input.messages", sv(secretContent))},
				Status: &tracepb.Status{Code: tracepb.Status_STATUS_CODE_ERROR, Message: secretContent}}},
		}},
	}}}
	raw, err := proto.Marshal(td)
	if err != nil {
		t.Fatal(err)
	}
	spans, err := DecodeOTLPProtobuf(raw)
	if err != nil || len(spans) != 1 {
		t.Fatalf("decode: %v %d", err, len(spans))
	}
	s := spans[0]
	if s.TraceID != tTrace || s.SpanID != tSpan || s.Kind != "client" || s.Status != "error" || s.Resource["faas.name"] != "fn" ||
		s.Attrs["gen_ai.usage.input_tokens"] != int64(7) || s.Start.Unix() != 1762336800 {
		t.Fatalf("span: %+v", s)
	}
	a, ok := Normalise(s, SourceOTLP)
	if !ok || a.Outcome != OutcomeError {
		t.Fatalf("normalise: %v %+v", ok, a)
	}
	mustNotLeak(t, a)
	if _, err := DecodeOTLPProtobuf([]byte{0xff, 0xff, 0xff}); !errors.Is(err, ErrBadOTLP) {
		t.Errorf("garbage: %v", err)
	}
}

// OTLPJSONExample is the payload the receiver documentation shows.
const OTLPJSONExample = `{"resourceSpans":[{"resource":{"attributes":[
 {"key":"service.name","value":{"stringValue":"travel-agent"}},
 {"key":"cloud.account.id","value":{"stringValue":"111111111111"}},
 {"key":"faas.name","value":{"stringValue":"book-flight"}},
 {"key":"authsec.principal","value":{"stringValue":"alice@example.com"}}]},
 "scopeSpans":[{"scope":{"name":"my-agent"},"spans":[
  {"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","name":"invoke_agent travel",
   "kind":1,"startTimeUnixNano":"1762336800000000000","endTimeUnixNano":"1762336805000000000",
   "attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"invoke_agent"}},
                 {"key":"gen_ai.agent.name","value":{"stringValue":"travel"}}]},
  {"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b175","parentSpanId":"eee19b7ec3c1b174",
   "name":"chat claude","kind":3,"startTimeUnixNano":"1762336801000000000","endTimeUnixNano":"1762336802000000000",
   "attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"chat"}},
                 {"key":"gen_ai.request.model","value":{"stringValue":"anthropic.claude-3-haiku"}},
                 {"key":"gen_ai.usage.input_tokens","value":{"intValue":"120"}},
                 {"key":"gen_ai.input.messages","value":{"stringValue":"PLANTED-CONTENT-sk-live-123"}}]},
  {"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b176","parentSpanId":"eee19b7ec3c1b174",
   "name":"execute_tool book","kind":1,"startTimeUnixNano":"1762336803000000000",
   "attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},
                 {"key":"gen_ai.tool.name","value":{"stringValue":"book"}},
                 {"key":"gen_ai.tool.call.arguments","value":{"stringValue":"{\"flight\":\"BA117\"}"}}],
   "status":{"code":2}}]}]}]}`

func TestDecodeOTLPJSON(t *testing.T) {
	spans, err := DecodeOTLPJSON([]byte(OTLPJSONExample))
	if err != nil || len(spans) != 3 {
		t.Fatalf("decode: %v %d", err, len(spans))
	}
	var rows []Activity
	for _, s := range spans {
		a, ok := Normalise(s, SourceOTLP)
		if !ok {
			t.Fatalf("span %s not recognised", s.SpanID)
		}
		mustNotLeak(t, a)
		rows = append(rows, a)
	}
	if rows[0].Kind != KindAgentStep || rows[1].Kind != KindModelCall || rows[2].Kind != KindToolCall {
		t.Fatalf("kinds: %s %s %s", rows[0].Kind, rows[1].Kind, rows[2].Kind)
	}
	if rows[1].ParentSpanID != "eee19b7ec3c1b174" || rows[1].Attrs["gen_ai.usage.input_tokens"] != int64(120) {
		t.Errorf("chat row: %+v", rows[1])
	}
	if rows[2].Outcome != OutcomeError || rows[2].Attrs["tool_arguments_sha256"] != Digest(`{"flight":"BA117"}`) {
		t.Errorf("tool row: %+v", rows[2])
	}
	if rows[0].OnBehalfOf != "alice@example.com" || rows[0].Hints.FaaSName != "book-flight" {
		t.Errorf("principal/hints: %+v", rows[0])
	}
	for _, bad := range []string{"", "[]", "{", `{"resourceSpans":[{"scopeSpans":[{"spans":[{"attributes":7}]}]}]}`} {
		if _, err := DecodeOTLPJSON([]byte(bad)); !errors.Is(err, ErrBadOTLP) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestExportResponseProto(t *testing.T) {
	if len(ExportResponseProto(0, "")) != 0 {
		t.Error("empty response not empty")
	}
	b := ExportResponseProto(3, "3 spans rejected")
	num, typ, n := protowire.ConsumeTag(b)
	if num != 1 || typ != protowire.BytesType || n < 0 {
		t.Fatalf("tag: %d %d", num, typ)
	}
	inner, m := protowire.ConsumeBytes(b[n:])
	if m < 0 {
		t.Fatal("bytes")
	}
	num, _, n = protowire.ConsumeTag(inner)
	v, _ := protowire.ConsumeVarint(inner[n:])
	if num != 1 || v != 3 {
		t.Fatalf("rejected_spans: %d %d", num, v)
	}
}

/* ------------------------------- CloudTrail -------------------------------- */

func TestFromCloudTrail(t *testing.T) {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	ro := true
	base := agentruntime.Event{EventID: "ev-1", EventTime: at, EventSource: "bedrock.amazonaws.com", EventName: "Converse",
		EventType: "AwsApiCall", EventCategory: "Management", ReadOnly: &ro, RequestFacts: map[string]string{agentruntime.FactModelID: "anthropic.claude"},
		ErrorMessage: "secret detail " + secretContent}
	a, ok := FromCloudTrail(base)
	if !ok || a.Kind != KindModelCall || a.Source != SourceCloudTrail || a.Action != "bedrock:Converse" ||
		a.ResourceRef != "anthropic.claude" || a.Outcome != OutcomeSuccess || a.ProviderEventID != "ev-1" || !a.OccurredAt.Equal(at) {
		t.Fatalf("model call: %+v", a)
	}
	mustNotLeak(t, a)
	data := base
	data.EventSource, data.EventName, data.EventCategory = "s3.amazonaws.com", "GetObject", "Data"
	data.Resources, data.RequestFacts = []string{"arn:aws:s3:::bucket/key"}, nil
	data.AuthorizationDenied, data.ErrorCode = true, "AccessDenied"
	a, _ = FromCloudTrail(data)
	if a.Kind != KindDataAccess || a.Source != SourceCloudTrailData || a.Outcome != OutcomeDenied || a.ResourceRef != "arn:aws:s3:::bucket/key" {
		t.Fatalf("data event: %+v", a)
	}
	other := base
	other.EventSource, other.EventName, other.RequestFacts = "secretsmanager.amazonaws.com", "GetSecretValue", map[string]string{agentruntime.FactSecretID: "openai-key"}
	other.ErrorCode = "ThrottlingException"
	a, _ = FromCloudTrail(other)
	if a.Kind != KindCloudAction || a.Outcome != OutcomeError || a.ResourceRef != "openai-key" {
		t.Fatalf("cloud action: %+v", a)
	}
	login := base
	login.EventSource, login.EventName, login.RequestFacts = "signin.amazonaws.com", "ConsoleLogin", nil
	if a, _ := FromCloudTrail(login); a.Kind != KindSignIn {
		t.Errorf("sign in: %+v", a)
	}
	completion := base
	completion.EventType = "AwsServiceEvent"
	if _, ok := FromCloudTrail(completion); ok {
		t.Error("a stream-completion record became activity")
	}
}

/* ------------------------------ AgentCore spans ----------------------------- */

type fakeLogs struct {
	start    *cloudwatchlogs.StartQueryInput
	startErr error
	polls    int
	pending  int
	rows     [][]cwltypes.ResultField
	stopped  bool
}

func (f *fakeLogs) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.start = in
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q1")}, nil
}

func (f *fakeLogs) GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.polls++
	if f.polls <= f.pending {
		return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusRunning}, nil
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusComplete, Results: f.rows}, nil
}

func (f *fakeLogs) StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	f.stopped = true
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func row(ts, msg string) []cwltypes.ResultField {
	return []cwltypes.ResultField{{Field: aws.String("@timestamp"), Value: aws.String(ts)}, {Field: aws.String("@message"), Value: aws.String(msg)}}
}

// awsSpanMsg is an aws/spans record in the shape AgentCore writes (UNVERIFIED,
// spec §4.2): attributes as a flat object, kind and status as names.
const awsSpanMsg = `{"resource":{"attributes":{"cloud.resource_id":"arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/travel-AbC/runtime-endpoint/DEFAULT","service.name":"travel.DEFAULT","cloud.region":"us-east-1"}},
"scope":{"name":"strands.telemetry"},"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174","parentSpanId":"",
"name":"execute_tool search","kind":"INTERNAL","startTimeUnixNano":1762336800000000000,"endTimeUnixNano":1762336800500000000,
"attributes":{"gen_ai.operation.name":"execute_tool","gen_ai.tool.name":"search","gen_ai.tool.call.arguments":"{\"q\":\"PLANTED-CONTENT-sk-live-123\"}","session.id":"sess-9"},
"status":{"code":"UNSET"}}`

func TestReadAWSSpans(t *testing.T) {
	f := &fakeLogs{pending: 2, rows: [][]cwltypes.ResultField{
		row("2026-11-05 10:00:00.000", awsSpanMsg),
		row("2026-11-05 10:00:02.500", "not json"),
	}}
	since := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	until := since.Add(2 * time.Hour)
	noSleep := func(context.Context, time.Duration) error { return nil }
	r, err := ReadAWSSpans(context.Background(), f, SpanQuery{Since: since, Until: until, Limit: 2, Sleep: noSleep})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToInt64(f.start.StartTime) != since.Add(-SpanLateArrival).Unix() || aws.ToInt64(f.start.EndTime) != until.Unix() ||
		f.start.LogGroupNames[0] != AWSSpansLogGroup || !strings.Contains(aws.ToString(f.start.QueryString), "limit 2") {
		t.Fatalf("query: %+v", f.start)
	}
	if len(r.Spans) != 1 || r.Invalid != 1 || r.Records != 2 || !r.CapHit ||
		!r.Last.Equal(time.Date(2026, 11, 5, 10, 0, 2, 500e6, time.UTC)) {
		t.Fatalf("read: %+v", r)
	}
	a, ok := Normalise(r.Spans[0], SourceAgentCoreSpan)
	if !ok || a.Kind != KindToolCall || a.ResourceRef != "search" || a.Attrs["gen_ai.conversation.id"] != "sess-9" ||
		a.Hints.RuntimeARN != "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/travel-AbC" {
		t.Fatalf("span row: %v %+v", ok, a)
	}
	mustNotLeak(t, a)

	// Timeout stops the query.
	slow := &fakeLogs{pending: 1 << 30}
	if _, err := ReadAWSSpans(context.Background(), slow, SpanQuery{Since: since, Until: until, PollTimeout: time.Nanosecond, Sleep: noSleep}); !errors.Is(err, ErrSpanQueryTimeout) || !slow.stopped {
		t.Errorf("timeout: %v stopped=%v", err, slow.stopped)
	}
}

func TestSpanReadState(t *testing.T) {
	for code, want := range map[string]string{
		"AccessDeniedException":     SpanStatePermissionMissing,
		"ResourceNotFoundException": SpanStateNotConfigured,
		"ThrottlingException":       SpanStateError,
	} {
		_, err := ReadAWSSpans(context.Background(), &fakeLogs{startErr: &smithy.GenericAPIError{Code: code, Message: "m"}}, SpanQuery{})
		if st, c := SpanReadState(err); st != want || c != code {
			t.Errorf("%s: %s %s", code, st, c)
		}
	}
	if st, _ := SpanReadState(nil); st != SpanStateReached {
		t.Error("nil")
	}
	if st, _ := SpanReadState(errors.New("x")); st != SpanStateError {
		t.Error("plain")
	}
}
