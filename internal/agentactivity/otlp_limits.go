package agentactivity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"google.golang.org/protobuf/encoding/protowire"
)

// Decoding allocates per element, and an empty element costs two or three
// bytes on the wire, so a 4 MiB body can expand to millions of structs. The
// limits are therefore checked on the raw body BEFORE it is decoded: the
// span cap (spec §8) and a cap on every nested message (resource and scope
// spans, attributes, events, links, array and kvlist values).
const (
	// MaxOTLPElements bounds every nested message in one request. 10,000
	// spans with a dozen attributes each stay well inside it.
	MaxOTLPElements = 250000
	// maxOTLPDepth bounds nesting (AnyValue arrays and kvlists recurse).
	maxOTLPDepth = 32
)

// ErrOTLPTooLarge: more nested elements, or deeper nesting, than allowed.
var ErrOTLPTooLarge = fmt.Errorf("more than %d elements in one request, or nested deeper than %d", MaxOTLPElements, maxOTLPDepth)

// otlpMsg names the trace protobuf messages the pre-scan descends into.
type otlpMsg int

const (
	msgTracesData otlpMsg = iota
	msgResourceSpans
	msgResource
	msgScopeSpans
	msgScope
	msgSpan
	msgEvent
	msgLink
	msgKeyValue
	msgAnyValue
	msgArrayValue
	msgKeyValueList
)

// otlpChildren maps each message's message-typed fields to their type
// (opentelemetry-proto trace/v1, resource/v1, common/v1). Other fields are
// scalars or strings and are skipped.
var otlpChildren = map[otlpMsg]map[protowire.Number]otlpMsg{
	msgTracesData:    {1: msgResourceSpans},
	msgResourceSpans: {1: msgResource, 2: msgScopeSpans},
	msgResource:      {1: msgKeyValue},
	msgScopeSpans:    {1: msgScope, 2: msgSpan},
	msgScope:         {3: msgKeyValue},
	msgSpan:          {9: msgKeyValue, 11: msgEvent, 13: msgLink},
	msgEvent:         {3: msgKeyValue},
	msgLink:          {4: msgKeyValue},
	msgKeyValue:      {2: msgAnyValue},
	msgAnyValue:      {5: msgArrayValue, 6: msgKeyValueList},
	msgArrayValue:    {1: msgAnyValue},
	msgKeyValueList:  {1: msgKeyValue},
}

type otlpCount struct{ spans, elements int }

func (c *otlpCount) add(span bool) error {
	c.elements++
	if span {
		c.spans++
		if c.spans > MaxSpansPerRequest {
			return ErrTooManySpans
		}
	}
	if c.elements > MaxOTLPElements {
		return ErrOTLPTooLarge
	}
	return nil
}

// checkOTLPProtobufLimits walks the wire format without allocating messages.
func checkOTLPProtobufLimits(body []byte) error {
	var c otlpCount
	return walkOTLP(body, msgTracesData, 0, &c)
}

func walkOTLP(b []byte, m otlpMsg, depth int, c *otlpCount) error {
	if depth > maxOTLPDepth {
		return ErrOTLPTooLarge
	}
	children := otlpChildren[m]
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return fmt.Errorf("%w: %v", ErrBadOTLP, protowire.ParseError(n))
		}
		b = b[n:]
		child, isMsg := children[num]
		if isMsg && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return fmt.Errorf("%w: %v", ErrBadOTLP, protowire.ParseError(n))
			}
			if err := c.add(child == msgSpan); err != nil {
				return err
			}
			if err := walkOTLP(v, child, depth+1, c); err != nil {
				return err
			}
			b = b[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return fmt.Errorf("%w: %v", ErrBadOTLP, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return nil
}

// checkOTLPJSONLimits walks the JSON tokens without building the document:
// every object counts as an element, and an object directly inside a "spans"
// array counts as a span.
func checkOTLPJSONLimits(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	type frame struct {
		array   bool
		spans   bool   // an array opened under the key "spans"
		lastKey string // object: the key whose value comes next
		wantKey bool
	}
	var stack []*frame
	var c otlpCount
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBadOTLP, err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= 2*maxOTLPDepth {
					return ErrOTLPTooLarge
				}
				key := ""
				if top != nil && !top.array {
					key, top.wantKey = top.lastKey, true
				}
				f := &frame{array: t == '[', wantKey: t == '{'}
				if t == '[' {
					f.spans = key == "spans"
				} else if err := c.add(top != nil && top.array && top.spans); err != nil {
					return err
				}
				stack = append(stack, f)
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if top != nil && !top.array && top.wantKey {
				top.lastKey, top.wantKey = t, false
				continue
			}
			if top != nil && !top.array {
				top.wantKey = true
			}
		default:
			if top != nil && !top.array {
				top.wantKey = true
			}
		}
	}
}
