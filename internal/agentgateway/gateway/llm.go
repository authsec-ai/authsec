package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// LLM proxy (spec §7): OpenAI-compatible /v1/chat/completions,
// /v1/responses, /v1/embeddings and Anthropic /v1/messages. The agent uses
// its gateway key as its "API key"; the gateway asks the PDP (kind model,
// provider + model) and forwards the untouched body with the provider key
// from its own environment. It reads only "model" and "stream" from the
// request and only "usage" from the response; no text is kept or sent to
// AuthSec.

// llmOperations maps a path suffix to its operation, per provider family.
var llmOperations = map[string]map[string]string{
	ProviderOpenAI: {
		"/v1/chat/completions": "chat.completions", "/v1/responses": "responses", "/v1/embeddings": "embeddings",
	},
	ProviderAnthropic: {"/v1/messages": "messages"},
}

// Forwarded agent headers (never the agent's credentials).
var llmForwardHeaders = map[string]bool{
	"Accept": true, "Content-Type": true, "User-Agent": true, "Anthropic-Version": true, "Anthropic-Beta": true,
	"Openai-Beta": true, "Idempotency-Key": true,
}

func family(provider string) string {
	if provider == ProviderAnthropic {
		return ProviderAnthropic
	}
	return ProviderOpenAI
}

// llmError writes an error in the provider's shape.
func llmError(w http.ResponseWriter, provider string, status int, code, msg string, extra map[string]any) {
	if family(provider) == ProviderAnthropic {
		typ := "invalid_request_error"
		switch status {
		case http.StatusUnauthorized:
			typ = "authentication_error"
		case http.StatusForbidden:
			typ = "permission_error"
		case http.StatusBadGateway, http.StatusServiceUnavailable:
			typ = "api_error"
		}
		e := map[string]any{"type": typ, "message": msg}
		for k, v := range extra {
			e[k] = v
		}
		writeJSON(w, status, map[string]any{"type": "error", "error": e})
		return
	}
	e := map[string]any{"message": msg, "type": "invalid_request_error", "code": code}
	if status == http.StatusForbidden {
		e["type"] = "permission_denied"
	}
	for k, v := range extra {
		e[k] = v
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func (g *Gateway) llmHandler(l *LLMUpstream) http.Handler {
	ops := llmOperations[family(l.Provider)]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, l.PathPrefix)
		subj, err := g.identify(r)
		if err != nil {
			llmError(w, l.Provider, http.StatusUnauthorized, "authsec_agent_key_required",
				"An AuthSec agent key is required (use it as the API key, or send X-AuthSec-Agent-Key).", nil)
			return
		}
		if r.Method == http.MethodGet && suffix == "/v1/models" && family(l.Provider) == ProviderOpenAI {
			// Listing models makes no model call.
			g.forwardLLM(w, r, l, suffix, nil, nil, Decision{})
			return
		}
		op, ok := ops[suffix]
		if !ok || r.Method != http.MethodPost {
			llmError(w, l.Provider, http.StatusNotFound, "not_found", "This path is not served by the AuthSec gateway.", nil)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.Limits.MaxBodyBytes))
		if err != nil {
			llmError(w, l.Provider, http.StatusRequestEntityTooLarge, "request_too_large", "The request body is too large.", nil)
			return
		}
		if err := checkUnambiguousJSON(body); err != nil {
			llmError(w, l.Provider, http.StatusBadRequest, "invalid_request", "The body must be unambiguous JSON: "+err.Error(), nil)
			return
		}
		var head struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if err := json.Unmarshal(body, &head); err != nil || strings.TrimSpace(head.Model) == "" {
			llmError(w, l.Provider, http.StatusBadRequest, "invalid_request", "The body must be JSON with a model.", nil)
			return
		}
		req := subj
		req.Kind, req.Provider, req.Model, req.Operation = agentgateway.KindModel, l.PolicyProvider, head.Model, op
		req.Stream, req.RequestID, req.GatewayVersion = head.Stream, newRequestID(), Version
		d := g.pdp.Decide(r.Context(), req)
		if !d.Allowed {
			log.Printf("[agent-gateway] llm deny agent=%s provider=%s model=%s reason=%s source=%s",
				subj.SubjectID, l.PolicyProvider, head.Model, d.Reason, d.Source)
			llmError(w, l.Provider, http.StatusForbidden, "authsec_policy_denied",
				"AuthSec policy denied this model call ("+d.Reason+").", map[string]any{"authsec": denyData(d)})
			return
		}
		g.forwardLLM(w, r, l, suffix, body, &req, d)
	})
}

// forwardLLM sends the call upstream with the provider key and streams the
// response; for a decided call (req set) it records the outcome with usage.
func (g *Gateway) forwardLLM(w http.ResponseWriter, r *http.Request, l *LLMUpstream, suffix string, body []byte, req *agentgateway.Request, d Decision) {
	target := l.BaseURL + suffix
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, target, rd)
	if err != nil {
		llmError(w, l.Provider, http.StatusBadGateway, "bad_gateway", "Bad upstream request.", nil)
		return
	}
	copyHeaders(up.Header, r.Header, llmForwardHeaders)
	if family(l.Provider) == ProviderAnthropic {
		up.Header.Set("X-Api-Key", l.apiKey)
		if up.Header.Get("Anthropic-Version") == "" {
			up.Header.Set("Anthropic-Version", "2023-06-01")
		}
	} else {
		up.Header.Set("Authorization", "Bearer "+l.apiKey)
	}
	for k, v := range l.Headers {
		up.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := g.upstream.Do(up)
	if err != nil {
		log.Printf("[agent-gateway] llm upstream provider=%s err=%v", l.Name, err)
		llmError(w, l.Provider, http.StatusBadGateway, "upstream_unreachable", "The model provider could not be reached.", nil)
		if req != nil {
			g.up.Outcome(*req, d, http.StatusBadGateway, msSince(start), nil)
		}
		return
	}
	defer resp.Body.Close()
	usage := &Usage{}
	var tee io.Writer
	var buf *boundedBuffer
	var sse *sseParser
	if req != nil {
		if isEventStream(resp.Header.Get("Content-Type")) {
			sse = newSSEParser(4<<20, func(data []byte) { mergeUsage(usage, data) })
			tee = sse
		} else {
			buf = &boundedBuffer{max: 16 << 20}
			tee = buf
		}
	}
	if err := copyResponse(w, resp, tee); err != nil {
		log.Printf("[agent-gateway] llm stream provider=%s err=%v", l.Name, err)
	}
	if req == nil {
		return
	}
	if sse != nil {
		sse.Close()
	}
	if buf != nil && !buf.overflow {
		mergeUsage(usage, buf.buf.Bytes())
	}
	if usage.TotalTokens == nil && usage.InputTokens != nil && usage.OutputTokens != nil {
		t := *usage.InputTokens + *usage.OutputTokens
		usage.TotalTokens = &t
	}
	g.up.Outcome(*req, d, resp.StatusCode, msSince(start), usage)
}

// usageFields covers OpenAI chat/embeddings (prompt/completion/total),
// the Responses API and Anthropic (input/output).
type usageFields struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	InputTokens      *int64 `json:"input_tokens"`
	OutputTokens     *int64 `json:"output_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
}

// mergeUsage reads the usage of one JSON response or one SSE event: a
// top-level usage (chat completions, embeddings, Anthropic message_delta,
// a non-streamed Anthropic or Responses body), response.usage (Responses
// API response.completed) or message.usage (Anthropic message_start).
// Later values replace earlier ones; input from message_start is kept when
// message_delta carries only output.
func mergeUsage(u *Usage, raw []byte) {
	var ev struct {
		Usage    *usageFields `json:"usage"`
		Response *struct {
			Usage *usageFields `json:"usage"`
		} `json:"response"`
		Message *struct {
			Usage *usageFields `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return
	}
	for _, f := range []*usageFields{ev.Usage, responseUsage(ev.Response), messageUsage(ev.Message)} {
		if f == nil {
			continue
		}
		if v := firstSet(f.InputTokens, f.PromptTokens); v != nil {
			u.InputTokens = v
		}
		if v := firstSet(f.OutputTokens, f.CompletionTokens); v != nil {
			u.OutputTokens = v
		}
		if f.TotalTokens != nil {
			u.TotalTokens = f.TotalTokens
		}
	}
}

func responseUsage(r *struct {
	Usage *usageFields `json:"usage"`
}) *usageFields {
	if r == nil {
		return nil
	}
	return r.Usage
}

func messageUsage(m *struct {
	Usage *usageFields `json:"usage"`
}) *usageFields {
	if m == nil {
		return nil
	}
	return m.Usage
}

func firstSet(vs ...*int64) *int64 {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}
