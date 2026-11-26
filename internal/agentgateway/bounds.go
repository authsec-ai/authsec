package agentgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Argument bounds (SPEC-secops-backend-upgrade.md P17, W6). An allow policy
// on MCP tools may bound the tool call's arguments: numeric min/max, string
// enum / regex / max_len, array max_items. The PDP stores and validates them
// and hands the deciding policy's bounds to the gateway with the decision
// (context.arg_bounds); the GATEWAY checks them against the canonical JSON
// it already refused to forward when ambiguous (strictjson), because only the
// gateway has the argument values. A call outside its bounds is denied
// (reason argument_out_of_bounds) or held for a person (decision "ask") as
// the policy says. The decision log names the bounded fields that failed,
// never their values; a held call keeps the bounded fields' values with the
// hold, for its approver only.

// Bound types and violation handling.
const (
	BoundNumber = "number"
	BoundString = "string"
	BoundArray  = "array"

	OnViolationDeny = "deny"
	OnViolationHold = "hold"

	// ReasonArgumentOutOfBounds is the deny reason of a call outside bounds;
	// ReasonArgumentHeld the "ask" reason of a held one.
	ReasonArgumentOutOfBounds = "argument_out_of_bounds"
	ReasonArgumentHeld        = "argument_held"
	ReasonHoldDenied          = "hold_denied"
	ReasonHoldExpired         = "hold_expired"
	ReasonHoldApproved        = "hold_approved"

	// DecisionAsk is the decision word of a held call (agent_gateway_decision).
	DecisionAsk = "ask"

	MaxBoundFields     = 32
	MaxBoundPathLen    = 256
	MaxBoundEnum       = 100
	MaxBoundRegexLen   = 512
	DefaultHoldMinutes = 15
	MaxHoldMinutes     = 1440
	// MaxHeldValueBytes bounds one held value as kept for the approver.
	MaxHeldValueBytes = 4096
)

// ArgBound bounds one argument, named by a dotted path of object keys
// ("payment.amount"). An absent argument passes unless Required.
type ArgBound struct {
	Path     string   `json:"path"`
	Type     string   `json:"type"`
	Required bool     `json:"required,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Enum     []string `json:"enum,omitempty"`
	Regex    string   `json:"regex,omitempty"`
	MaxLen   *int     `json:"max_len,omitempty"`
	MaxItems *int     `json:"max_items,omitempty"`
}

// ArgBounds are a policy's argument bounds.
type ArgBounds struct {
	Fields []ArgBound `json:"fields"`
	// OnViolation is deny (default) or hold.
	OnViolation string `json:"on_violation,omitempty"`
	// HoldMinutes is how long a held call waits for its approver (default
	// 15, at most 1440).
	HoldMinutes int `json:"hold_minutes,omitempty"`
}

// Empty reports bounds that bound nothing.
func (b *ArgBounds) Empty() bool { return b == nil || len(b.Fields) == 0 }

// Hold reports whether a violation holds the call (else it is denied).
func (b *ArgBounds) Hold() bool { return b != nil && b.OnViolation == OnViolationHold }

// HoldFor is the hold's lifetime in minutes.
func (b *ArgBounds) HoldFor() int {
	if b == nil || b.HoldMinutes <= 0 {
		return DefaultHoldMinutes
	}
	if b.HoldMinutes > MaxHoldMinutes {
		return MaxHoldMinutes
	}
	return b.HoldMinutes
}

var boundPathSegment = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,64}$`)

// Validate checks bounds; field names are "conditions.arg_bounds...".
func (b *ArgBounds) Validate() []FieldError {
	var errs []FieldError
	add := func(f, m string) { errs = append(errs, FieldError{Field: "conditions.arg_bounds" + f, Message: m}) }
	if b == nil {
		return nil
	}
	switch b.OnViolation {
	case "":
		b.OnViolation = OnViolationDeny
	case OnViolationDeny, OnViolationHold:
	default:
		add(".on_violation", "on_violation must be deny or hold")
	}
	if b.HoldMinutes < 0 || b.HoldMinutes > MaxHoldMinutes {
		add(".hold_minutes", fmt.Sprintf("hold_minutes must be between 1 and %d", MaxHoldMinutes))
	}
	if len(b.Fields) == 0 {
		add(".fields", "at least one bounded field")
	}
	if len(b.Fields) > MaxBoundFields {
		add(".fields", fmt.Sprintf("at most %d bounded fields", MaxBoundFields))
	}
	seen := map[string]bool{}
	for i := range b.Fields {
		f := &b.Fields[i]
		at := fmt.Sprintf(".fields[%d]", i)
		f.Path = strings.TrimSpace(f.Path)
		if f.Path == "" || len(f.Path) > MaxBoundPathLen {
			add(at+".path", "path is required")
		} else {
			for _, seg := range strings.Split(f.Path, ".") {
				if !boundPathSegment.MatchString(seg) {
					add(at+".path", "path is object keys joined by '.' (letters, digits, _ and -)")
					break
				}
			}
		}
		if seen[f.Path] {
			add(at+".path", "a path is bounded once")
		}
		seen[f.Path] = true
		numeric := f.Min != nil || f.Max != nil
		stringy := len(f.Enum) > 0 || f.Regex != "" || f.MaxLen != nil
		switch f.Type {
		case BoundNumber:
			if stringy || f.MaxItems != nil {
				add(at, "a number bound takes min and max only")
			}
			if !numeric {
				add(at, "a number bound needs min or max")
			}
			if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
				add(at, "min must not exceed max")
			}
			for _, v := range []*float64{f.Min, f.Max} {
				if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0)) {
					add(at, "min and max must be finite")
				}
			}
		case BoundString:
			if numeric || f.MaxItems != nil {
				add(at, "a string bound takes enum, regex and max_len only")
			}
			if !stringy {
				add(at, "a string bound needs enum, regex or max_len")
			}
			if len(f.Enum) > MaxBoundEnum {
				add(at+".enum", fmt.Sprintf("at most %d values", MaxBoundEnum))
			}
			if f.Regex != "" {
				if len(f.Regex) > MaxBoundRegexLen {
					add(at+".regex", fmt.Sprintf("at most %d characters", MaxBoundRegexLen))
				} else if _, err := regexp.Compile(f.Regex); err != nil {
					add(at+".regex", "not a valid regular expression (RE2)")
				}
			}
			if f.MaxLen != nil && *f.MaxLen < 0 {
				add(at+".max_len", "max_len must be at least 0")
			}
		case BoundArray:
			if numeric || stringy {
				add(at, "an array bound takes max_items only")
			}
			if f.MaxItems == nil || *f.MaxItems < 0 {
				add(at+".max_items", "an array bound needs max_items (at least 0)")
			}
		default:
			add(at+".type", "type must be number, string or array")
		}
	}
	return errs
}

// BoundViolation is one bounded field a call breaks: the path and which
// rule, never the value.
type BoundViolation struct {
	Path string `json:"path"`
	Rule string `json:"rule"`
}

// lookupPath walks dotted object keys in v.
func lookupPath(v any, path string) (any, bool) {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// decodeArgs reads the arguments with numbers kept exact (json.Number).
func decodeArgs(raw []byte) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Check evaluates the bounds on the arguments (the call's JSON object). It
// returns the violations (sorted by path) and, for a held call, the values
// of the bounded fields present, each at most MaxHeldValueBytes of JSON.
// Arguments that are not JSON violate every bound ("unreadable").
func (b *ArgBounds) Check(args []byte) ([]BoundViolation, map[string]json.RawMessage) {
	if b.Empty() {
		return nil, nil
	}
	v, err := decodeArgs(args)
	if err != nil {
		return []BoundViolation{{Path: "", Rule: "unreadable"}}, nil
	}
	var out []BoundViolation
	held := map[string]json.RawMessage{}
	for _, f := range b.Fields {
		val, ok := lookupPath(v, f.Path)
		if ok {
			if raw, err := json.Marshal(val); err == nil {
				if len(raw) > MaxHeldValueBytes {
					raw, _ = json.Marshal(map[string]any{"truncated": true, "bytes": len(raw)})
				}
				held[f.Path] = raw
			}
		}
		if rule := f.check(val, ok); rule != "" {
			out = append(out, BoundViolation{Path: f.Path, Rule: rule})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, held
}

// check is the first rule val breaks, or "".
func (f ArgBound) check(val any, present bool) string {
	if !present || val == nil {
		if f.Required {
			return "required"
		}
		return ""
	}
	switch f.Type {
	case BoundNumber:
		n, ok := val.(json.Number)
		if !ok {
			return "type"
		}
		x, err := n.Float64()
		if err != nil {
			return "type"
		}
		if f.Min != nil && x < *f.Min {
			return "min"
		}
		if f.Max != nil && x > *f.Max {
			return "max"
		}
	case BoundString:
		s, ok := val.(string)
		if !ok {
			return "type"
		}
		if f.MaxLen != nil && len([]rune(s)) > *f.MaxLen {
			return "max_len"
		}
		if len(f.Enum) > 0 {
			in := false
			for _, e := range f.Enum {
				if e == s {
					in = true
					break
				}
			}
			if !in {
				return "enum"
			}
		}
		if f.Regex != "" {
			re, err := regexp.Compile(f.Regex)
			if err != nil || !re.MatchString(s) {
				return "regex"
			}
		}
	case BoundArray:
		a, ok := val.([]any)
		if !ok {
			return "type"
		}
		if f.MaxItems != nil && len(a) > *f.MaxItems {
			return "max_items"
		}
	default:
		return "type"
	}
	return ""
}

// BoundsFromContext reads context.arg_bounds of a PDP decision (nil when
// absent or unreadable: an unreadable bound set from AuthSec denies, see
// the gateway).
func BoundsFromContext(ctx map[string]any) (*ArgBounds, bool) {
	raw, ok := ctx["arg_bounds"]
	if !ok || raw == nil {
		return nil, true
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	var out ArgBounds
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, false
	}
	if errs := out.Validate(); len(errs) > 0 {
		return nil, false
	}
	return &out, true
}
