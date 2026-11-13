package agentactivity

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// OTLP/HTTP trace decoding (spec §4.3). An ExportTraceServiceRequest is wire-
// identical to TracesData (field 1: repeated ResourceSpans), so the protobuf
// form decodes into tracepb.TracesData without the collector package.
//
// The JSON form follows the OTLP/HTTP JSON encoding: lowerCamelCase field
// names, trace and span ids as hex strings (NOT base64), enums as integers,
// 64-bit integers as strings or numbers.

// MaxSpansPerRequest bounds one request (spec §8).
const MaxSpansPerRequest = 10000

var (
	// ErrBadOTLP: the body is not an OTLP trace export.
	ErrBadOTLP = errors.New("the body is not an OTLP trace export request")
	// ErrTooManySpans: more than MaxSpansPerRequest spans.
	ErrTooManySpans = fmt.Errorf("more than %d spans in one request", MaxSpansPerRequest)
)

// DecodeOTLPProtobuf decodes an application/x-protobuf export request.
func DecodeOTLPProtobuf(body []byte) ([]Span, error) {
	if err := checkOTLPProtobufLimits(body); err != nil {
		return nil, err
	}
	var td tracepb.TracesData
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &td); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadOTLP, err)
	}
	var out []Span
	for _, rs := range td.GetResourceSpans() {
		res := kvMap(rs.GetResource().GetAttributes())
		for _, ss := range rs.GetScopeSpans() {
			scope := ss.GetScope().GetName()
			for _, s := range ss.GetSpans() {
				if len(out) == MaxSpansPerRequest {
					return nil, ErrTooManySpans
				}
				out = append(out, Span{
					TraceID: hex.EncodeToString(s.GetTraceId()), SpanID: hex.EncodeToString(s.GetSpanId()),
					ParentSpanID: hex.EncodeToString(s.GetParentSpanId()),
					Name:         s.GetName(), Kind: spanKind(int64(s.GetKind())),
					Start: nanos(s.GetStartTimeUnixNano()), End: nanos(s.GetEndTimeUnixNano()),
					Status: statusOf(int64(s.GetStatus().GetCode())),
					Attrs:  kvMap(s.GetAttributes()), Resource: res, Scope: scope,
				})
			}
		}
	}
	return out, nil
}

func kvMap(kvs []*commonpb.KeyValue) map[string]any {
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		if v, ok := anyValue(kv.GetValue()); ok {
			m[kv.GetKey()] = v
		}
	}
	return m
}

func anyValue(v *commonpb.AnyValue) (any, bool) {
	if v == nil {
		return nil, false
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue, true
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue, true
	case *commonpb.AnyValue_IntValue:
		return x.IntValue, true
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue, true
	case *commonpb.AnyValue_BytesValue:
		return x.BytesValue, true
	case *commonpb.AnyValue_ArrayValue:
		arr := []any{}
		for _, e := range x.ArrayValue.GetValues() {
			if ev, ok := anyValue(e); ok {
				arr = append(arr, ev)
			}
		}
		return arr, true
	case *commonpb.AnyValue_KvlistValue:
		return kvMap(x.KvlistValue.GetValues()), true
	}
	return nil, false
}

func nanos(n uint64) time.Time {
	if n == 0 || n > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(0, int64(n)).UTC()
}

func spanKind(k int64) string {
	switch k {
	case 1:
		return "internal"
	case 2:
		return "server"
	case 3:
		return "client"
	case 4:
		return "producer"
	case 5:
		return "consumer"
	}
	return ""
}

func statusOf(code int64) string {
	switch code {
	case 1:
		return "ok"
	case 2:
		return "error"
	}
	return ""
}

/* ---------------------------------- JSON ---------------------------------- */

type jsonTraces struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []jsonKV `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			Spans []jsonSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type jsonSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId"`
	Name              string          `json:"name"`
	Kind              json.RawMessage `json:"kind"`
	StartTimeUnixNano json.RawMessage `json:"startTimeUnixNano"`
	EndTimeUnixNano   json.RawMessage `json:"endTimeUnixNano"`
	Attributes        json.RawMessage `json:"attributes"`
	Status            struct {
		Code json.RawMessage `json:"code"`
	} `json:"status"`
}

type jsonKV struct {
	Key   string       `json:"key"`
	Value jsonAnyValue `json:"value"`
}

type jsonAnyValue struct {
	StringValue *string         `json:"stringValue"`
	BoolValue   *bool           `json:"boolValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue json.RawMessage `json:"doubleValue"`
	BytesValue  *string         `json:"bytesValue"`
	ArrayValue  *struct {
		Values []jsonAnyValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []jsonKV `json:"values"`
	} `json:"kvlistValue"`
}

// DecodeOTLPJSON decodes an application/json export request.
func DecodeOTLPJSON(body []byte) ([]Span, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ErrBadOTLP
	}
	if err := checkOTLPJSONLimits(trimmed); err != nil {
		return nil, err
	}
	var t jsonTraces
	if err := json.Unmarshal(trimmed, &t); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadOTLP, err)
	}
	var out []Span
	for _, rs := range t.ResourceSpans {
		res := jsonKVMap(rs.Resource.Attributes)
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				if len(out) == MaxSpansPerRequest {
					return nil, ErrTooManySpans
				}
				sp, err := s.span()
				if err != nil {
					return nil, err
				}
				sp.Resource, sp.Scope = res, ss.Scope.Name
				out = append(out, sp)
			}
		}
	}
	return out, nil
}

func (s jsonSpan) span() (Span, error) {
	attrs, err := attributesOf(s.Attributes)
	if err != nil {
		return Span{}, err
	}
	kind, _ := jsonInt(s.Kind)
	code, _ := jsonInt(s.Status.Code)
	start, _ := jsonUint(s.StartTimeUnixNano)
	end, _ := jsonUint(s.EndTimeUnixNano)
	return Span{
		TraceID: s.TraceID, SpanID: s.SpanID, ParentSpanID: s.ParentSpanID, Name: s.Name,
		Kind: spanKind(kind), Start: nanos(start), End: nanos(end), Status: statusOf(code), Attrs: attrs,
	}, nil
}

// attributesOf reads attributes in the OTLP list form ([{key, value}]) or,
// for AgentCore span records, as a flat object.
func attributesOf(raw json.RawMessage) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	switch raw[0] {
	case '[':
		var kvs []jsonKV
		if err := json.Unmarshal(raw, &kvs); err != nil {
			return nil, fmt.Errorf("%w: attributes: %v", ErrBadOTLP, err)
		}
		return jsonKVMap(kvs), nil
	case '{':
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("%w: attributes: %v", ErrBadOTLP, err)
		}
		for k, v := range m {
			m[k] = plainValue(v)
		}
		return m, nil
	}
	return nil, fmt.Errorf("%w: attributes must be a list or an object", ErrBadOTLP)
}

// plainValue turns json.Number into int64 or float64, recursively.
func plainValue(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case []any:
		for i := range x {
			x[i] = plainValue(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = plainValue(x[k])
		}
		return x
	}
	return v
}

func jsonKVMap(kvs []jsonKV) map[string]any {
	m := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		if v, ok := kv.Value.value(); ok {
			m[kv.Key] = v
		}
	}
	return m
}

func (v jsonAnyValue) value() (any, bool) {
	switch {
	case v.StringValue != nil:
		return *v.StringValue, true
	case v.BoolValue != nil:
		return *v.BoolValue, true
	case len(v.IntValue) > 0:
		i, ok := jsonInt(v.IntValue)
		return i, ok
	case len(v.DoubleValue) > 0:
		var f float64
		if json.Unmarshal(v.DoubleValue, &f) == nil {
			return f, true
		}
		var s string
		if json.Unmarshal(v.DoubleValue, &s) == nil {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				return f, true
			}
		}
		return nil, false
	case v.BytesValue != nil:
		b, err := base64.StdEncoding.DecodeString(*v.BytesValue)
		return b, err == nil
	case v.ArrayValue != nil:
		arr := []any{}
		for _, e := range v.ArrayValue.Values {
			if ev, ok := e.value(); ok {
				arr = append(arr, ev)
			}
		}
		return arr, true
	case v.KvlistValue != nil:
		return jsonKVMap(v.KvlistValue.Values), true
	}
	return nil, false
}

// jsonInt reads an integer sent as a number or a string; also an enum name
// some exporters write ("SPAN_KIND_CLIENT", "STATUS_CODE_ERROR", "ERROR").
func jsonInt(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0, false
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}
	switch strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(strings.ToUpper(s), "SPAN_KIND_"), "STATUS_CODE_")) {
	case "INTERNAL", "OK":
		return 1, true
	case "SERVER", "ERROR":
		return 2, true
	case "CLIENT":
		return 3, true
	case "PRODUCER":
		return 4, true
	case "CONSUMER":
		return 5, true
	}
	return 0, false
}

func jsonUint(raw json.RawMessage) (uint64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		u, err := strconv.ParseUint(s, 10, 64)
		return u, err == nil
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
			return u, true
		}
		if f, err := n.Float64(); err == nil && f >= 0 {
			return uint64(f), true
		}
	}
	return 0, false
}

/* --------------------------------- response -------------------------------- */

// ExportResponseProto encodes an ExportTraceServiceResponse: empty when
// nothing was rejected, else partial_success {rejected_spans, error_message}.
func ExportResponseProto(rejected int64, msg string) []byte {
	if rejected == 0 && msg == "" {
		return []byte{}
	}
	var ps []byte
	if rejected != 0 {
		ps = protowire.AppendTag(ps, 1, protowire.VarintType)
		ps = protowire.AppendVarint(ps, uint64(rejected))
	}
	if msg != "" {
		ps = protowire.AppendTag(ps, 2, protowire.BytesType)
		ps = protowire.AppendString(ps, msg)
	}
	var out []byte
	out = protowire.AppendTag(out, 1, protowire.BytesType)
	out = protowire.AppendBytes(out, ps)
	return out
}

// ExportResponseJSON is the JSON form of the same response.
func ExportResponseJSON(rejected int64, msg string) map[string]any {
	if rejected == 0 && msg == "" {
		return map[string]any{}
	}
	return map[string]any{"partialSuccess": map[string]any{
		"rejectedSpans": strconv.FormatInt(rejected, 10), "errorMessage": msg}}
}
