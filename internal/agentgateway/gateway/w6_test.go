package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// W6 in the gateway binary: AuthSec-issued agent keys need their bound
// workload identity; legacy keys only with legacy_agent_keys; provider keys
// fetched from AuthSec into memory; run id across hops; the model version
// on outcomes; argument bounds deny or hold; held values never in the
// decision log.

const (
	w6Key      = "agk_w6-authsec-issued-key-0001"
	w6SPIFFE   = "spiffe://acme.example/ns/prod/sa/billing"
	w6Workload = "5b0f6c1e-7d2a-4c1b-9d7e-3a2b1c0d9e8f"
	w6Policy   = "99999999-2222-3333-4444-555555555555"
	w6HoldID   = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

type w6PDP struct {
	mu        sync.Mutex
	srv       *httptest.Server
	bounds    *agentgateway.ArgBounds
	records   []Record
	rawUpload []string
	evals     []agentgateway.Request
	holds     []json.RawMessage
	holdState string
	consumed  int
	keyFetch  int
	hints     Hints
}

func newW6PDP(t *testing.T) *w6PDP {
	f := &w6PDP{holdState: "pending"}
	f.hints = Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p1", Version: "v1",
		AgentKeys: []AgentKeyHint{{ID: "k1", ClientID: "agk:billing", KeySHA256: HashAgentKey(w6Key), SPIFFEID: w6SPIFFE,
			WorkloadID: w6Workload, Labels: []string{"prod"}}}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/authsec/pdp/access/v1/evaluation":
			var e agentgateway.EvaluationRequest
			_ = json.Unmarshal(raw, &e)
			req, _ := agentgateway.FromAuthZEN(e)
			f.evals = append(f.evals, req)
			ctx := map[string]any{"decision_id": "11111111-2222-3333-4444-555555555555", "ttl_seconds": 0,
				"reason_admin": map[string]any{"reason": "policy_allow", "policy_id": w6Policy}}
			if f.bounds != nil {
				ctx["arg_bounds"] = f.bounds
			}
			writeJSON(w, 200, agentgateway.EvaluationResponse{Decision: true, Context: ctx})
		case r.URL.Path == "/authsec/pdp/v1/decisions":
			f.rawUpload = append(f.rawUpload, string(raw))
			var up struct {
				Records []Record `json:"records"`
			}
			_ = json.Unmarshal(raw, &up)
			f.records = append(f.records, up.Records...)
			writeJSON(w, 202, map[string]any{})
		case r.URL.Path == "/authsec/pdp/v1/policy-hints":
			writeJSON(w, 200, f.hints)
		case r.URL.Path == "/authsec/pdp/v1/provider-keys":
			f.keyFetch++
			writeJSON(w, 200, map[string]any{"ttl_seconds": 300, "keys": []map[string]any{
				{"id": "pk-1", "name": "openai-prod", "provider": "openai", "key": "sk-from-authsec-vault", "fingerprint": "...ault"}}})
		case r.URL.Path == "/authsec/pdp/v1/holds" && r.Method == http.MethodPost:
			f.holds = append(f.holds, raw)
			writeJSON(w, 201, HoldTicket{HoldID: w6HoldID, State: "pending", ExpiresAt: time.Now().Add(15 * time.Minute)})
		case r.URL.Path == "/authsec/pdp/v1/holds/"+w6HoldID && r.Method == http.MethodGet:
			writeJSON(w, 200, HoldTicket{HoldID: w6HoldID, State: f.holdState})
		case r.URL.Path == "/authsec/pdp/v1/holds/"+w6HoldID+"/consume":
			if f.holdState != "approved" {
				writeJSON(w, 409, map[string]any{})
				return
			}
			f.consumed++
			f.holdState = "consumed"
			writeJSON(w, 200, HoldTicket{HoldID: w6HoldID, State: "consumed"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func w6Config(t *testing.T, pdp *w6PDP, mcpURL, openaiURL string, mut func(*Config)) *Config {
	t.Helper()
	cfg := &Config{AuthSec: AuthSec{URL: pdp.srv.URL + "/authsec"},
		Agents: AgentsConfig{TrustSPIFFEHeader: true,
			SPIFFE: []SPIFFEAgent{{ID: w6SPIFFE, WorkloadID: w6Workload}}},
		Holds: HoldsConfig{Mode: HoldReturn}}
	if mcpURL != "" {
		cfg.MCPServers = []MCPServer{{Name: "pay", URL: mcpURL, PinTools: boolPtr(false)}}
	}
	if openaiURL != "" {
		cfg.LLM = []LLMUpstream{{Provider: ProviderOpenAI, BaseURL: openaiURL}}
	}
	if mut != nil {
		mut(cfg)
	}
	env := map[string]string{"AUTHSEC_GATEWAY_CREDENTIAL": testCred}
	if err := cfg.finish(func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func boolPtr(b bool) *bool { return &b }

func w6Gateway(t *testing.T, cfg *Config) (*Gateway, http.Handler) {
	g, h := newTestGateway(t, cfg)
	if err := g.PDP().RefreshHints(context.Background()); err != nil {
		t.Fatal(err)
	}
	return g, h
}

func w6Hdr(key, spiffe string, extra map[string]string) map[string]string {
	h := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
	if key != "" {
		h[AgentKeyHeader] = key
	}
	if spiffe != "" {
		h["X-Client-SPIFFE-ID"] = spiffe
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func TestW6AgentKeyNeedsItsWorkloadIdentity(t *testing.T) {
	pdp := newW6PDP(t)
	up := okUpstream(t)
	_, h := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", nil))
	cases := []struct {
		name, key, spiffe string
		want              int
	}{
		{"key and its workload", w6Key, w6SPIFFE, 200},
		{"key alone", w6Key, "", 401},
		{"workload alone", "", w6SPIFFE, 401},
		{"key with another workload", w6Key, "spiffe://acme.example/ns/prod/sa/other", 401},
		{"unknown key with the workload", "agk_unknown", w6SPIFFE, 401},
	}
	for _, c := range cases {
		w := do(h, "POST", "/mcp/pay", toolCallBody, w6Hdr(c.key, c.spiffe, nil))
		if w.Code != c.want {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
	}
	// The PDP saw the AuthSec client id and the key's bound workload.
	if len(pdp.evals) != 1 || pdp.evals[0].SubjectID != "agk:billing" || pdp.evals[0].WorkloadID != w6Workload {
		t.Fatalf("evals: %+v", pdp.evals)
	}
	// A key bound to a workload id needs the SPIFFE ID that maps to it.
	pdp.mu.Lock()
	pdp.hints.AgentKeys[0].SPIFFEID = ""
	pdp.hints.Version = "v2"
	pdp.mu.Unlock()
	g2, h2 := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", func(c *Config) { c.Agents.SPIFFE = nil }))
	_ = g2
	if w := do(h2, "POST", "/mcp/pay", toolCallBody, w6Hdr(w6Key, w6SPIFFE, nil)); w.Code != 401 {
		t.Fatalf("workload id unmapped accepted: %d", w.Code)
	}
}

func TestW6LegacyAgentKeysOnlyWithFlag(t *testing.T) {
	pdp := newW6PDP(t)
	up := okUpstream(t)
	legacy := []AgentKey{{ID: "old-agent", KeySHA256: HashAgentKey("agk_old-local-key")}}
	cfg := &Config{AuthSec: AuthSec{URL: pdp.srv.URL + "/authsec"}, Agents: AgentsConfig{Keys: legacy},
		MCPServers: []MCPServer{{Name: "pay", URL: up.srv.URL}}}
	if err := cfg.finish(func(k string) string { return map[string]string{"AUTHSEC_GATEWAY_CREDENTIAL": testCred}[k] }); err == nil ||
		!strings.Contains(err.Error(), "legacy_agent_keys") {
		t.Fatalf("legacy keys accepted without the flag: %v", err)
	}
	_, h := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", func(c *Config) { c.Agents.Keys, c.LegacyAgentKeys = legacy, true }))
	if w := do(h, "POST", "/mcp/pay", toolCallBody, w6Hdr("agk_old-local-key", "", nil)); w.Code != 200 {
		t.Fatalf("legacy key refused with the flag: %d %s", w.Code, w.Body.String())
	}
	// SPIFFE alone only with allow_spiffe_only.
	_, h3 := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", func(c *Config) { c.Agents.AllowSPIFFEOnly = true }))
	if w := do(h3, "POST", "/mcp/pay", toolCallBody, w6Hdr("", w6SPIFFE, nil)); w.Code != 200 {
		t.Fatalf("spiffe only refused with allow_spiffe_only: %d", w.Code)
	}
}

func TestW6ProviderKeysFromAuthSecMemoryOnly(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	pdp := newW6PDP(t)
	var gotAuth string
	oa := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		gotAuth = r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"id": "x", "model": "gpt-5.1-2026-08-01",
			"usage": map[string]any{"prompt_tokens": 3, "completion_tokens": 4}})
	})
	// api_key_env with the AuthSec default is refused (no silent fallback).
	bad := &Config{AuthSec: AuthSec{URL: pdp.srv.URL + "/authsec"}, LLM: []LLMUpstream{{Provider: ProviderOpenAI, APIKeyEnv: "K"}}}
	if err := bad.finish(func(k string) string { return map[string]string{"AUTHSEC_GATEWAY_CREDENTIAL": testCred, "K": "sk"}[k] }); err == nil {
		t.Fatal("api_key_env accepted with provider_keys: authsec")
	}
	g, h := w6Gateway(t, w6Config(t, pdp, "", oa.srv.URL, nil))
	w := do(h, "POST", "/llm/openai/v1/chat/completions", `{"model":"gpt-5.1","messages":[{"role":"user","content":"PROMPT-TEXT"}]}`,
		w6Hdr(w6Key, w6SPIFFE, map[string]string{agentgateway.RunIDHeader: "run-abc.1"}))
	if w.Code != 200 {
		t.Fatalf("llm: %d %s", w.Code, w.Body.String())
	}
	if gotAuth != "Bearer sk-from-authsec-vault" {
		t.Fatalf("upstream key: %q", gotAuth)
	}
	if w.Header().Get(agentgateway.RunIDHeader) != "run-abc.1" {
		t.Fatalf("run id not echoed: %q", w.Header().Get(agentgateway.RunIDHeader))
	}
	// A second call uses the cached key (one fetch).
	do(h, "POST", "/llm/openai/v1/chat/completions", `{"model":"gpt-5.1"}`, w6Hdr(w6Key, w6SPIFFE, nil))
	if pdp.keyFetch != 1 || g.ProviderKeys().Len() != 1 {
		t.Fatalf("fetches: %d", pdp.keyFetch)
	}
	if err := g.Uploader().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out *Record
	for i := range pdp.records {
		if pdp.records[i].RecordType == "outcome" && pdp.records[i].RunID == "run-abc.1" {
			out = &pdp.records[i]
		}
	}
	if out == nil || out.ModelVersion != "gpt-5.1-2026-08-01" || out.ProviderKeyID != "pk-1" {
		t.Fatalf("outcome: %+v (records %d)", out, len(pdp.records))
	}
	for _, raw := range pdp.rawUpload {
		if strings.Contains(raw, "sk-from-authsec-vault") || strings.Contains(raw, "PROMPT-TEXT") {
			t.Fatal("a key or prompt reached the decision upload")
		}
	}
	// Nothing written to disk.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(raw), "sk-from-authsec-vault") {
			t.Fatalf("key on disk in %s", e.Name())
		}
	}
}

func TestW6RunIDPropagatesToMCPAndDecisions(t *testing.T) {
	pdp := newW6PDP(t)
	up := okUpstream(t)
	_, h := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", nil))
	w := do(h, "POST", "/mcp/pay", toolCallBody, w6Hdr(w6Key, w6SPIFFE, map[string]string{agentgateway.RunIDHeader: "run-hop-1"}))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if got := up.calls()[0].header.Get(agentgateway.RunIDHeader); got != "run-hop-1" {
		t.Fatalf("run id not passed on: %q", got)
	}
	if pdp.evals[0].RunID != "run-hop-1" {
		t.Fatalf("pdp run id: %q", pdp.evals[0].RunID)
	}
	// Absent or unusable: a new one is made and passed on.
	w = do(h, "POST", "/mcp/pay", toolCallBody, w6Hdr(w6Key, w6SPIFFE, map[string]string{agentgateway.RunIDHeader: "bad id!"}))
	gen := w.Header().Get(agentgateway.RunIDHeader)
	if !strings.HasPrefix(gen, "run_") || up.calls()[1].header.Get(agentgateway.RunIDHeader) != gen {
		t.Fatalf("generated run id: %q", gen)
	}
}

func payBody(amount string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"pay","arguments":{"amount":` + amount +
		`,"currency":"USD","note":"SECRET-NOTE"}}}`
}

func TestW6ArgumentBoundsAllowDenyHold(t *testing.T) {
	pdp := newW6PDP(t)
	up := okUpstream(t)
	max := 100.0
	pdp.bounds = &agentgateway.ArgBounds{Fields: []agentgateway.ArgBound{{Path: "amount", Type: "number", Max: &max},
		{Path: "currency", Type: "string", Enum: []string{"USD", "EUR"}}}, OnViolation: "deny"}
	g, h := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", nil))
	if w := do(h, "POST", "/mcp/pay", payBody("50"), w6Hdr(w6Key, w6SPIFFE, nil)); w.Code != 200 || len(up.calls()) != 1 {
		t.Fatalf("in bounds: %d", w.Code)
	}
	w := do(h, "POST", "/mcp/pay", payBody("5000"), w6Hdr(w6Key, w6SPIFFE, nil))
	code, data := rpcErr(t, w)
	if code != RPCPolicyDenied || data["reason"] != agentgateway.ReasonArgumentOutOfBounds || len(up.calls()) != 1 {
		t.Fatalf("out of bounds: %d %v", code, data)
	}

	// Hold: the call is held (202), the values go to AuthSec's hold only.
	pdp.mu.Lock()
	pdp.bounds.OnViolation = "hold"
	pdp.mu.Unlock()
	w = do(h, "POST", "/mcp/pay", payBody("5000"), w6Hdr(w6Key, w6SPIFFE, nil))
	code, data = rpcErr(t, w)
	if w.Code != http.StatusAccepted || code != RPCHeld || data["hold_id"] != w6HoldID || len(up.calls()) != 1 {
		t.Fatalf("held: %d %d %v", w.Code, code, data)
	}
	if len(pdp.holds) != 1 || !strings.Contains(string(pdp.holds[0]), `"amount":5000`) || strings.Contains(string(pdp.holds[0]), "SECRET-NOTE") {
		t.Fatalf("hold body: %s", pdp.holds)
	}
	// Retried before approval: still held; after approval: forwarded once.
	w = do(h, "POST", "/mcp/pay", payBody("5000"), w6Hdr(w6Key, w6SPIFFE, map[string]string{HoldIDHeader: w6HoldID}))
	if w.Code != http.StatusAccepted {
		t.Fatalf("pending retry: %d", w.Code)
	}
	pdp.mu.Lock()
	pdp.holdState = "approved"
	pdp.mu.Unlock()
	w = do(h, "POST", "/mcp/pay", payBody("5000"), w6Hdr(w6Key, w6SPIFFE, map[string]string{HoldIDHeader: w6HoldID}))
	if w.Code != 200 || len(up.calls()) != 2 || pdp.consumed != 1 {
		t.Fatalf("approved retry: %d calls=%d consumed=%d", w.Code, len(up.calls()), pdp.consumed)
	}
	// Denied: refused.
	pdp.mu.Lock()
	pdp.holdState = "denied"
	pdp.mu.Unlock()
	w = do(h, "POST", "/mcp/pay", payBody("5000"), w6Hdr(w6Key, w6SPIFFE, map[string]string{HoldIDHeader: w6HoldID}))
	if code, data = rpcErr(t, w); code != RPCPolicyDenied || data["reason"] != agentgateway.ReasonHoldDenied {
		t.Fatalf("denied hold: %d %v", code, data)
	}
	// The decision log carries paths and rules, never the values.
	if err := g.Uploader().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	foundViolation := false
	for _, raw := range pdp.rawUpload {
		if strings.Contains(raw, "5000") || strings.Contains(raw, "SECRET-NOTE") {
			t.Fatalf("a bounded value reached the decision log: %s", raw)
		}
		if strings.Contains(raw, `"path":"amount","rule":"max"`) {
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatalf("violation not recorded: %v", pdp.rawUpload)
	}
}

func TestW6HoldWaitMode(t *testing.T) {
	pdp := newW6PDP(t)
	up := okUpstream(t)
	max := 1.0
	pdp.bounds = &agentgateway.ArgBounds{Fields: []agentgateway.ArgBound{{Path: "amount", Type: "number", Max: &max}}, OnViolation: "hold"}
	_, h := w6Gateway(t, w6Config(t, pdp, up.srv.URL, "", func(c *Config) {
		c.Holds = HoldsConfig{Mode: HoldWait, WaitTimeoutS: 5, PollIntervalMS: 20}
	}))
	go func() {
		time.Sleep(100 * time.Millisecond)
		pdp.mu.Lock()
		pdp.holdState = "approved"
		pdp.mu.Unlock()
	}()
	if w := do(h, "POST", "/mcp/pay", payBody("50"), w6Hdr(w6Key, w6SPIFFE, nil)); w.Code != 200 || len(up.calls()) != 1 {
		t.Fatalf("approved while waiting: %d %s", w.Code, w.Body.String())
	}
}

func TestW6MergeModel(t *testing.T) {
	var m string
	mergeModel(&m, []byte(`{"type":"message_start","message":{"model":"claude-opus-5-5-20260101","usage":{}}}`))
	if m != "claude-opus-5-5-20260101" {
		t.Fatal(m)
	}
	mergeModel(&m, []byte(`{"type":"response.completed","response":{"model":"gpt-5.1-2026"}}`))
	if m != "gpt-5.1-2026" {
		t.Fatal(m)
	}
	mergeModel(&m, []byte(`{"model":"bad model <script>"}`))
	if m != "gpt-5.1-2026" {
		t.Fatal("bad name kept", m)
	}
}

func TestW6ExampleConfigLoads(t *testing.T) {
	t.Setenv("AUTHSEC_GATEWAY_CREDENTIAL", "agw_example")
	t.Setenv("GITHUB_MCP_AUTHORIZATION", "Bearer x")
	cfg, err := LoadConfig(filepath.Join("..", "..", "..", "deploy", "agent-gateway", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProviderKeys != ProviderKeysAuthSec || cfg.LegacyAgentKeys || cfg.Holds.Mode != HoldWait || len(cfg.Agents.Keys) != 0 {
		t.Fatalf("%+v", cfg)
	}
}
