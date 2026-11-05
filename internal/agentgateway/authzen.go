// Package agentgateway is the pure part of the agent runtime gateway
// (SPEC-agent-runtime-gateway.md): the OpenID AuthZEN Authorization API 1.0
// wire types, their mapping to a gateway request, and the tool-policy
// evaluation. It has no database, no HTTP server and no clock of its own, so
// AuthSec (the PDP, services/agent_gateway*.go) and the gateway binary (the
// PEP, internal/agentgateway/gateway) share exactly the same rules.
package agentgateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// AuthZEN Authorization API 1.0 (OpenID, Final, published 11 January 2026),
// https://openid.net/specs/authorization-api-1_0.html. Section numbers below
// are that document's.

// Entity is a Subject (§5.1) or a Resource (§5.2): type and id REQUIRED,
// properties OPTIONAL.
type Entity struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is §5.3: name REQUIRED, properties OPTIONAL.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// EvaluationRequest is the Access Evaluation request (§6.1).
type EvaluationRequest struct {
	Subject  *Entity        `json:"subject,omitempty"`
	Action   *Action        `json:"action,omitempty"`
	Resource *Entity        `json:"resource,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationResponse is the Access Evaluation response (§6.2): decision
// REQUIRED, context OPTIONAL.
type EvaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationsOptions is §7.1's options object. Other keys are allowed by the
// spec (registered capabilities); this PDP ignores them.
type EvaluationsOptions struct {
	EvaluationsSemantic string `json:"evaluations_semantic,omitempty"`
}

// EvaluationsRequest is the Access Evaluations (batch) request (§7.1): the
// top-level subject/action/resource/context are defaults that an individual
// evaluation's own key replaces (no merging).
type EvaluationsRequest struct {
	Subject     *Entity             `json:"subject,omitempty"`
	Action      *Action             `json:"action,omitempty"`
	Resource    *Entity             `json:"resource,omitempty"`
	Context     map[string]any      `json:"context,omitempty"`
	Evaluations []EvaluationRequest `json:"evaluations,omitempty"`
	Options     *EvaluationsOptions `json:"options,omitempty"`
}

// EvaluationsResponse is §7.2.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// Evaluation semantics (§7.1.2.1).
const (
	SemanticExecuteAll          = "execute_all"
	SemanticDenyOnFirstDeny     = "deny_on_first_deny"
	SemanticPermitOnFirstPermit = "permit_on_first_permit"
)

// MaxBatchEvaluations bounds one Access Evaluations request.
const MaxBatchEvaluations = 100

// Expand applies the batch defaults to every evaluation (§7.1: an
// evaluation's own key replaces the default). An absent or empty
// evaluations array is a single evaluation of the defaults (backwards
// compatible with §6); single reports that case, whose response is a
// single §6.2 object.
func (r *EvaluationsRequest) Expand() (evals []EvaluationRequest, single bool, err error) {
	if r.Options != nil {
		switch r.Options.EvaluationsSemantic {
		case "", SemanticExecuteAll, SemanticDenyOnFirstDeny, SemanticPermitOnFirstPermit:
		default:
			return nil, false, fmt.Errorf("unknown evaluations_semantic %q", r.Options.EvaluationsSemantic)
		}
	}
	if len(r.Evaluations) == 0 {
		return []EvaluationRequest{{Subject: r.Subject, Action: r.Action, Resource: r.Resource, Context: r.Context}}, true, nil
	}
	if len(r.Evaluations) > MaxBatchEvaluations {
		return nil, false, fmt.Errorf("at most %d evaluations per request", MaxBatchEvaluations)
	}
	out := make([]EvaluationRequest, len(r.Evaluations))
	for i, e := range r.Evaluations {
		if e.Subject == nil {
			e.Subject = r.Subject
		}
		if e.Action == nil {
			e.Action = r.Action
		}
		if e.Resource == nil {
			e.Resource = r.Resource
		}
		if e.Context == nil {
			e.Context = r.Context
		}
		out[i] = e
	}
	return out, false, nil
}

// Semantic is the request's evaluation semantic (execute_all by default).
func (r *EvaluationsRequest) Semantic() string {
	if r.Options == nil || r.Options.EvaluationsSemantic == "" {
		return SemanticExecuteAll
	}
	return r.Options.EvaluationsSemantic
}

// Stop reports whether a batch with semantic stops after a decision
// (§7.1.2.1: the remaining evaluations are omitted from the response).
func Stop(semantic string, decision bool) bool {
	switch semantic {
	case SemanticDenyOnFirstDeny:
		return !decision
	case SemanticPermitOnFirstPermit:
		return decision
	}
	return false
}

// ErrorResponse is a per-evaluation error inside a batch (§7.2.1): decisions
// default to closed, the context carries the error.
func ErrorResponse(status int, msg string) EvaluationResponse {
	return EvaluationResponse{Decision: false, Context: map[string]any{
		"error": map[string]any{"status": status, "message": msg}}}
}

/* --------------------------- gateway vocabulary --------------------------- */

// Kinds of target.
const (
	KindMCPTool = "mcp_tool"
	KindModel   = "model"
)

// Subject type and action names.
const (
	SubjectTypeAgent  = "agent"
	ActionToolsCall   = "tools/call"
	ActionModelInvoke = "model/invoke"
)

// Model operations (action.properties.operation).
var ModelOperations = map[string]bool{
	"chat.completions": true, "responses": true, "embeddings": true, "messages": true,
}

// ContextKeys are the only request context keys AuthSec keeps; anything
// else is ignored (never stored).
var ContextKeys = map[string]bool{
	"args_digest": true, "request_id": true, "gateway_version": true, "stream": true,
}

// Field length limits.
const (
	MaxIDLen    = 512
	MaxNameLen  = 512
	MaxLabels   = 32
	MaxLabelLen = 200
)

// Request is one decision request, normalised from AuthZEN.
type Request struct {
	Kind      string
	Action    string
	Operation string
	// Subject.
	SubjectID  string
	IdentityID string
	WorkloadID string
	Labels     []string
	// GatewayID is set by the PDP from the gateway credential, never from
	// the request.
	GatewayID string
	// mcp_tool target.
	Server         string
	ServerURL      string
	Tool           string
	DefinitionHash string
	// model target.
	Provider string
	Model    string
	// Context.
	ArgsDigest     string
	RequestID      string
	GatewayVersion string
	Stream         bool
}

// ResourceID is the canonical resource id: server/tool or provider/model.
func (r Request) ResourceID() string {
	if r.Kind == KindModel {
		return r.Provider + "/" + r.Model
	}
	return r.Server + "/" + r.Tool
}

// SubjectProps is the subject's selector attributes as recorded.
func (r Request) SubjectProps() map[string]any {
	m := map[string]any{}
	if r.IdentityID != "" {
		m["identity_id"] = r.IdentityID
	}
	if r.WorkloadID != "" {
		m["workload_id"] = r.WorkloadID
	}
	if len(r.Labels) > 0 {
		m["labels"] = r.Labels
	}
	return m
}

// ResourceProps is the resource's attributes as recorded.
func (r Request) ResourceProps() map[string]any {
	if r.Kind == KindModel {
		m := map[string]any{"provider": r.Provider, "model": r.Model}
		if r.Operation != "" {
			m["operation"] = r.Operation
		}
		return m
	}
	m := map[string]any{"server": r.Server, "tool": r.Tool}
	if r.ServerURL != "" {
		m["server_url"] = r.ServerURL
	}
	if r.DefinitionHash != "" {
		m["definition_hash"] = r.DefinitionHash
	}
	return m
}

// ToAuthZEN is the request as an AuthZEN evaluation (the gateway's side).
func (r Request) ToAuthZEN() EvaluationRequest {
	subj := &Entity{Type: SubjectTypeAgent, ID: r.SubjectID}
	if p := r.SubjectProps(); len(p) > 0 {
		subj.Properties = p
	}
	act := &Action{Name: ActionToolsCall}
	if r.Kind == KindModel {
		act.Name = ActionModelInvoke
		if r.Operation != "" {
			act.Properties = map[string]any{"operation": r.Operation}
		}
	}
	props := r.ResourceProps()
	delete(props, "operation")
	res := &Entity{Type: r.Kind, ID: r.ResourceID(), Properties: props}
	ctx := map[string]any{}
	if r.ArgsDigest != "" {
		ctx["args_digest"] = r.ArgsDigest
	}
	if r.RequestID != "" {
		ctx["request_id"] = r.RequestID
	}
	if r.GatewayVersion != "" {
		ctx["gateway_version"] = r.GatewayVersion
	}
	if r.Stream {
		ctx["stream"] = true
	}
	e := EvaluationRequest{Subject: subj, Action: act, Resource: res}
	if len(ctx) > 0 {
		e.Context = ctx
	}
	return e
}

// ErrInvalid wraps every mapping error (a 400, or a per-evaluation error).
var ErrInvalid = errors.New("invalid evaluation")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func propString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

func optUUID(m map[string]any, key string) (string, error) {
	s, err := propString(m, key)
	if err != nil || s == "" {
		return "", err
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return "", invalid("subject.properties.%s must be a UUID", key)
	}
	return id.String(), nil
}

// FromAuthZEN maps one AuthZEN evaluation to a Request, or an ErrInvalid.
// Nothing in it names a workspace or a gateway: those come from the
// credential.
func FromAuthZEN(e EvaluationRequest) (Request, error) {
	var r Request
	if e.Subject == nil || e.Action == nil || e.Resource == nil {
		return r, invalid("subject, action and resource are required")
	}
	if e.Subject.Type != SubjectTypeAgent {
		return r, invalid("subject.type must be %q", SubjectTypeAgent)
	}
	r.SubjectID = strings.TrimSpace(e.Subject.ID)
	if r.SubjectID == "" || len(r.SubjectID) > MaxIDLen {
		return r, invalid("subject.id is required (at most %d characters)", MaxIDLen)
	}
	sp := e.Subject.Properties
	var err error
	if r.IdentityID, err = optUUID(sp, "identity_id"); err != nil {
		return r, err
	}
	if r.WorkloadID, err = optUUID(sp, "workload_id"); err != nil {
		return r, err
	}
	if raw, ok := sp["labels"]; ok && raw != nil {
		list, ok := raw.([]any)
		if ss, isStrings := raw.([]string); isStrings {
			list, ok = make([]any, len(ss)), true
			for i, s := range ss {
				list[i] = s
			}
		}
		if !ok || len(list) > MaxLabels {
			return r, invalid("subject.properties.labels must be an array of at most %d strings", MaxLabels)
		}
		for _, l := range list {
			s, ok := l.(string)
			if !ok || s == "" || len(s) > MaxLabelLen {
				return r, invalid("subject.properties.labels must hold non-empty strings")
			}
			r.Labels = append(r.Labels, s)
		}
	}

	switch e.Resource.Type {
	case KindMCPTool:
		r.Kind = KindMCPTool
		if e.Action.Name != ActionToolsCall {
			return r, invalid("action.name must be %q for an mcp_tool", ActionToolsCall)
		}
		rp := e.Resource.Properties
		if r.Server, err = propString(rp, "server"); err != nil {
			return r, err
		}
		if r.Tool, err = propString(rp, "tool"); err != nil {
			return r, err
		}
		if r.ServerURL, err = propString(rp, "server_url"); err != nil {
			return r, err
		}
		if r.DefinitionHash, err = propString(rp, "definition_hash"); err != nil {
			return r, err
		}
		if r.DefinitionHash != "" && !igagov.ValidArgsDigest(r.DefinitionHash) {
			return r, invalid("resource.properties.definition_hash must be sha256:<64 hex>")
		}
		srv, tool, _ := strings.Cut(e.Resource.ID, "/")
		if r.Server == "" && r.Tool == "" {
			r.Server, r.Tool = srv, tool
		} else if e.Resource.ID != "" && e.Resource.ID != r.Server+"/"+r.Tool {
			return r, invalid("resource.id must be <server>/<tool> of its properties")
		}
	case KindModel:
		r.Kind = KindModel
		if e.Action.Name != ActionModelInvoke {
			return r, invalid("action.name must be %q for a model", ActionModelInvoke)
		}
		if op, err := propString(e.Action.Properties, "operation"); err != nil {
			return r, err
		} else if op != "" {
			if !ModelOperations[op] {
				return r, invalid("action.properties.operation %q is not known", op)
			}
			r.Operation = op
		}
		rp := e.Resource.Properties
		if r.Provider, err = propString(rp, "provider"); err != nil {
			return r, err
		}
		if r.Model, err = propString(rp, "model"); err != nil {
			return r, err
		}
		prov, model, _ := strings.Cut(e.Resource.ID, "/")
		if r.Provider == "" && r.Model == "" {
			r.Provider, r.Model = prov, model
		} else if e.Resource.ID != "" && !strings.EqualFold(e.Resource.ID, r.Provider+"/"+r.Model) {
			return r, invalid("resource.id must be <provider>/<model> of its properties")
		}
		r.Provider = strings.ToLower(r.Provider)
	default:
		return r, invalid("resource.type must be %q or %q", KindMCPTool, KindModel)
	}
	if r.Kind == KindMCPTool && (r.Server == "" || r.Tool == "") {
		return r, invalid("an mcp_tool resource needs a server and a tool")
	}
	if r.Kind == KindModel && (r.Provider == "" || r.Model == "") {
		return r, invalid("a model resource needs a provider and a model")
	}
	for _, s := range []string{r.Server, r.Tool, r.ServerURL, r.Provider, r.Model} {
		if len(s) > MaxNameLen {
			return r, invalid("resource names are at most %d characters", MaxNameLen)
		}
	}

	ctx := e.Context
	if r.ArgsDigest, err = propString(ctx, "args_digest"); err != nil {
		return r, err
	}
	if r.ArgsDigest != "" && !igagov.ValidArgsDigest(r.ArgsDigest) {
		return r, invalid("context.args_digest must be sha256:<64 hex>")
	}
	if r.RequestID, err = propString(ctx, "request_id"); err != nil {
		return r, err
	}
	if len(r.RequestID) > 128 {
		r.RequestID = r.RequestID[:128]
	}
	if r.GatewayVersion, err = propString(ctx, "gateway_version"); err != nil {
		return r, err
	}
	if len(r.GatewayVersion) > 64 {
		r.GatewayVersion = r.GatewayVersion[:64]
	}
	if v, ok := ctx["stream"].(bool); ok {
		r.Stream = v
	}
	return r, nil
}

// DigestArguments is the arguments digest: sha256 of the RFC 8785 form,
// "sha256:<hex>" (as R3, DECISION R3-4). Absent arguments digest as {}.
func DigestArguments(raw json.RawMessage) (string, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		raw = json.RawMessage("{}")
	}
	return igagov.DigestArguments(raw)
}

// ValidDigest reports whether s is "sha256:<64 hex>".
func ValidDigest(s string) bool { return igagov.ValidArgsDigest(s) }
