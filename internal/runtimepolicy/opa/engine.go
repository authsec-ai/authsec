// Package opa is the in-process decision evaluator for authsec.runtime.v1.
//
// Isolation is one prepared query and one in-memory store per workspace and
// revision. The module is the pinned typed template. Caller Rego is never
// loaded. The capabilities set removes http.send, net.* and opa.runtime, so
// a template cannot reach the network or the process. A deadline bounds
// evaluation. Undefined output, a type mismatch and any evaluation error
// become deny. Decision logs carry the decision, never the request body.
package opa

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

const (
	// Version is the OPA release in the iga-local image
	// openpolicyagent/opa@sha256:9e0010512cf405e66bfd7b89394f514e56fe0464822df0527e780344ab151450.
	Version = "1.21.0"
	// ImageDigest is that image. Central and in-process decisions use this build.
	ImageDigest = "sha256:9e0010512cf405e66bfd7b89394f514e56fe0464822df0527e780344ab151450"

	// Query is the internal data API. The HTTP form is POST /v1/data/authsec/runtime/decision.
	Query = "data.authsec.runtime.decision"

	// DefaultTimeout is the evaluation deadline when the caller does not set one.
	DefaultTimeout = 50 * time.Millisecond

	// preparedCacheLimit bounds one engine's prepared queries. Each entry is
	// one workspace and revision. The oldest entry is dropped past the limit.
	preparedCacheLimit = 64
)

//go:embed decision.rego
var templateSource string

//go:embed example_contract.rego
var exampleSource string

//go:embed VERSION
var versionFile string

// Template is the pinned authsec.runtime.v1 module. The compiler emits these
// bytes unchanged.
func Template() string { return templateSource }

// ExampleContract is the §14.2 module CI executes.
func ExampleContract() string { return exampleSource }

// VersionFile is the recorded pin: release and image digest.
func VersionFile() string { return versionFile }

// Decision is §14.2's result. Effect is allow, deny or require_approval.
// decision_id is supplied here, not by Rego.
type Decision struct {
	Effect         string           `json:"effect"`
	ReasonCodes    []string         `json:"reason_codes"`
	MatchedRuleIDs []string         `json:"matched_rule_ids"`
	PolicyRevision any              `json:"policy_revision"`
	Obligations    []map[string]any `json:"obligations"`
	DecisionID     string           `json:"decision_id"`
}

// Evaluator is the swap point for the simulator and the gateway parity tests.
// An implementation must not return effect allow when evaluation failed.
type Evaluator interface {
	Eval(ctx context.Context, workspaceID, revision string, data, input map[string]any) Decision
}

// Engine is the in-process evaluator. prepared queries are keyed by workspace
// and revision and each holds only that pair's data document.
type Engine struct {
	module  string
	timeout time.Duration
	log     io.Writer

	mu    sync.Mutex
	cache map[string]*rego.PreparedEvalQuery
	order []string
}

// NewEngine evaluates the pinned template.
func NewEngine() *Engine {
	return newEngine(templateSource)
}

func newEngine(module string) *Engine {
	return &Engine{
		module:  module,
		timeout: DefaultTimeout,
		log:     io.Discard,
		cache:   map[string]*rego.PreparedEvalQuery{},
	}
}

// SetLog receives one JSON line per decision. The line is the decision only.
func (e *Engine) SetLog(w io.Writer) {
	if w == nil {
		w = io.Discard
	}
	e.log = w
}

// RestrictedCapabilities is this OPA version's capabilities without I/O builtins.
func RestrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	out := *caps
	out.Builtins = nil
	for _, b := range caps.Builtins {
		if ioBuiltin(b.Name) {
			continue
		}
		out.Builtins = append(out.Builtins, b)
	}
	return &out
}

func ioBuiltin(name string) bool {
	switch {
	case name == "http.send" || strings.HasPrefix(name, "http."):
		return true
	case strings.HasPrefix(name, "net."):
		return true
	case name == "opa.runtime" || strings.HasPrefix(name, "opa.runtime."):
		return true
	default:
		return false
	}
}

// CompileRestricted compiles module with the sandbox. A call to a removed
// builtin is a compile error. Production code loads only the pinned template.
func CompileRestricted(module string) error {
	_, err := rego.New(
		rego.Query(Query),
		rego.Module("policy.rego", module),
		rego.Capabilities(RestrictedCapabilities()),
		rego.Strict(true),
	).PrepareForEval(context.Background())
	return err
}

// Eval decides input against one workspace's data. The result is never allow
// when the query is undefined, the value is the wrong shape, or Rego returns
// an error.
func (e *Engine) Eval(ctx context.Context, workspaceID, revision string, data, input map[string]any) Decision {
	if ctx == nil {
		ctx = context.Background()
	}
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, e.timeout)
		defer cancel()
	}
	prepared, err := e.prepare(ctx, workspaceID, revision, data)
	if err != nil {
		return e.finish(deny("evaluation_error", nil))
	}
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return e.finish(deny("evaluation_error", nil))
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil {
		return e.finish(deny("undefined_decision", nil))
	}
	d, ok := decodeDecision(rs[0].Expressions[0].Value)
	if !ok {
		return e.finish(deny("type_mismatch", nil))
	}
	return e.finish(d)
}

func (e *Engine) prepare(ctx context.Context, workspaceID, revision string, data map[string]any) (*rego.PreparedEvalQuery, error) {
	key := workspaceID + "\x00" + revision
	e.mu.Lock()
	defer e.mu.Unlock()
	if q, ok := e.cache[key]; ok {
		return q, nil
	}
	store := inmem.NewFromObject(data)
	q, err := rego.New(
		rego.Query(Query),
		rego.Module("decision.rego", e.module),
		rego.Store(store),
		rego.Capabilities(RestrictedCapabilities()),
		rego.Strict(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	if len(e.cache) >= preparedCacheLimit {
		drop := e.order[0]
		e.order = e.order[1:]
		delete(e.cache, drop)
	}
	e.cache[key] = &q
	e.order = append(e.order, key)
	return &q, nil
}

func (e *Engine) finish(d Decision) Decision {
	d.DecisionID = uuid.NewString()
	line, err := json.Marshal(d)
	if err == nil {
		_, _ = e.log.Write(append(redactLine(line), '\n'))
	}
	return d
}

func deny(reason string, revision any) Decision {
	return Decision{
		Effect:         "deny",
		ReasonCodes:    []string{reason},
		MatchedRuleIDs: []string{},
		PolicyRevision: revision,
		Obligations:    []map[string]any{},
	}
}

func decodeDecision(v any) (Decision, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return Decision{}, false
	}
	effect, _ := m["effect"].(string)
	switch effect {
	case "allow", "deny", "require_approval":
	default:
		return Decision{}, false
	}
	d := Decision{
		Effect:         effect,
		ReasonCodes:    stringList(m["reason_codes"]),
		MatchedRuleIDs: stringList(m["matched_rule_ids"]),
		PolicyRevision: m["policy_revision"],
		Obligations:    objectList(m["obligations"]),
	}
	sort.Strings(d.ReasonCodes)
	sort.Strings(d.MatchedRuleIDs)
	if d.ReasonCodes == nil {
		d.ReasonCodes = []string{}
	}
	if d.MatchedRuleIDs == nil {
		d.MatchedRuleIDs = []string{}
	}
	if d.Obligations == nil {
		d.Obligations = []map[string]any{}
	}
	return d, true
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), t...)
	default:
		return nil
	}
}

func objectList(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if ok {
			out = append(out, m)
		}
	}
	return out
}

var canary = regexp.MustCompile(`CANARY-SECRET-DO-NOT-LEAK-[A-Za-z0-9_-]*`)

func redactLine(line []byte) []byte {
	return canary.ReplaceAll(line, []byte("[redacted]"))
}

// RedactForTest reports whether b still contains a canary. Tests use it.
func RedactForTest(b []byte) bool {
	return canary.Match(b)
}

// ErrCustomRego is returned by callers that were handed caller-supplied Rego.
// The engine has no path that compiles it.
var ErrCustomRego = errors.New("custom_rego_not_supported")
