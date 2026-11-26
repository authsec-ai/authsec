package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// AS-174: a stopped agent is refused locally, before the cache and the PDP,
// whatever the fail mode and the workspace mode; the stop list and the fail
// mode come from AuthSec (policy hints), and local config can only tighten.

const (
	billingIdentity = "0f0e0d0c-0b0a-4908-8706-050403020100"
	otherAgentKey   = "agk_other-agent-key"
)

func stopConfig(t *testing.T, pdp *fakePDP, mcpURL, openaiURL, failMode string) *Config {
	t.Helper()
	cfg := testConfig(t, pdp, mcpURL, openaiURL, "", failMode)
	cfg.Agents.Keys[0].IdentityID = billingIdentity
	cfg.Agents.Keys = append(cfg.Agents.Keys, AgentKey{ID: "other-agent", KeySHA256: HashAgentKey(otherAgentKey)})
	return cfg
}

func okUpstream(t *testing.T) *fakeUpstream {
	return newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": 7, "result": map[string]any{}})
	})
}

func stopIdentity() []agentgateway.StoppedSubject {
	return []agentgateway.StoppedSubject{{Selector: agentgateway.Selector{IdentityID: billingIdentity}, Ref: "containment:c1"}}
}

func setHints(t *testing.T, g *Gateway, pdp *fakePDP, h *Hints) {
	t.Helper()
	pdp.mu.Lock()
	pdp.hints = h
	pdp.mu.Unlock()
	if err := g.PDP().RefreshHints(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func setFail(pdp *fakePDP, fail bool) {
	pdp.mu.Lock()
	pdp.fail = fail
	pdp.mu.Unlock()
}

func TestStoppedAgentRefusedOverCachedAllow(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.decide = func(agentgateway.Request) (bool, int) { return true, 300 }
	up := okUpstream(t)
	g, h := newTestGateway(t, stopConfig(t, pdp, up.srv.URL, "", FailAuto))
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p1", Version: "v1"})

	if w := do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil)); !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatal(w.Body.String())
	}
	if g.PDP().cache.len() != 1 || pdp.evalCount() != 1 {
		t.Fatalf("allow not cached: %d entries, %d evaluations", g.PDP().cache.len(), pdp.evalCount())
	}

	// The stop arrives WITHOUT a purge (hints swapped in directly): the cached
	// allow is still there, and the stop is checked before it.
	g.PDP().hints.Store(&Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p1", Stopped: stopIdentity()})
	if g.PDP().cache.len() != 1 {
		t.Fatal("precondition: cached allow present")
	}
	w := do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	code, data := rpcErr(t, w)
	if code != RPCPolicyDenied || data["reason"] != agentgateway.ReasonAgentStopped || data["source"] != SourceGateway {
		t.Fatalf("stopped agent served: %s", w.Body.String())
	}
	if pdp.evalCount() != 1 || len(up.calls()) != 1 {
		t.Fatalf("stopped agent reached the PDP (%d) or the upstream (%d)", pdp.evalCount(), len(up.calls()))
	}
	// Another agent is unaffected.
	if w := do(h, "POST", "/mcp/github", toolCallBody, map[string]string{AgentKeyHeader: otherAgentKey,
		"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}); !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("other agent refused: %s", w.Body.String())
	}
	// The refusal is uploaded as the gateway's own decision.
	if err := g.Uploader().Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range pdp.records {
		if r.Reason == agentgateway.ReasonAgentStopped && r.Source == SourceGateway && r.Decision == agentgateway.EffectDeny {
			found = true
		}
	}
	if !found {
		t.Fatalf("stopped refusal not uploaded: %+v", pdp.records)
	}
}

func TestStoppedAgentRefusedInObserveAndEveryFailMode(t *testing.T) {
	up := okUpstream(t)
	for _, c := range []struct{ local, server string }{
		{FailOpen, FailOpen}, {FailAuto, FailAuto}, {FailOpen, FailAuto}, {FailClosed, FailOpen},
	} {
		pdp := newFakePDP(t)
		pdp.decide = func(agentgateway.Request) (bool, int) { return true, 30 }
		g, h := newTestGateway(t, stopConfig(t, pdp, up.srv.URL, "", c.local))
		// Observe mode, no deny target: auto and open would allow on failure.
		setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, FailMode: c.server, Stopped: stopIdentity()})
		for _, fail := range []bool{false, true} {
			setFail(pdp, fail)
			w := do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
			if _, data := rpcErr(t, w); data["reason"] != agentgateway.ReasonAgentStopped {
				t.Errorf("local=%s server=%s pdp_down=%v: stopped agent not refused: %s", c.local, c.server, fail, w.Body.String())
			}
		}
		if pdp.evalCount() != 0 {
			t.Errorf("local=%s server=%s: the PDP was asked about a stopped agent", c.local, c.server)
		}
	}
}

func TestStopListChangePurgesCache(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.decide = func(agentgateway.Request) (bool, int) { return true, 300 }
	up := okUpstream(t)
	g, h := newTestGateway(t, stopConfig(t, pdp, up.srv.URL, "", FailAuto))
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p1", Version: "v1"})
	other := map[string]string{AgentKeyHeader: otherAgentKey, "Content-Type": "application/json", "Accept": "application/json"}
	do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	do(h, "POST", "/mcp/github", toolCallBody, other)
	if n := g.PDP().cache.len(); n != 2 {
		t.Fatalf("cached %d, want 2", n)
	}
	// An unchanged body is a 304 and keeps everything.
	if err := g.PDP().RefreshHints(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pdp.notModified != 1 || g.PDP().cache.len() != 2 {
		t.Fatalf("304 path: notModified=%d cache=%d", pdp.notModified, g.PDP().cache.len())
	}
	// The billing agent is stopped: only its entries go.
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p1", Version: "v2", Stopped: stopIdentity()})
	if n := g.PDP().cache.len(); n != 1 {
		t.Fatalf("after stop: %d entries, want 1 (the other agent's)", n)
	}
	// A policy change empties the cache.
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p2", Version: "v3", Stopped: stopIdentity()})
	if n := g.PDP().cache.len(); n != 0 {
		t.Fatalf("after policy change: %d entries", n)
	}
	// A lower cache lifetime from AuthSec shortens what is cached.
	do(h, "POST", "/mcp/github", toolCallBody, other)
	ttl := 10
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p2", Version: "v4", CacheTTLSeconds: &ttl, Stopped: stopIdentity()})
	g.PDP().cache.mu.Lock()
	for _, e := range g.PDP().cache.m {
		if e.expires.After(time.Now().Add(11 * time.Second)) {
			t.Errorf("entry outlives the 10 s cap: %s", time.Until(e.expires))
		}
	}
	g.PDP().cache.mu.Unlock()
	// The stop is lifted: the agent is decided by the PDP again.
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, PolicyVersion: "p2", Version: "v5"})
	if w := do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil)); !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("released agent refused: %s", w.Body.String())
	}
}

func TestServerCacheTTLAndFailModeOverrideLocal(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.decide = func(agentgateway.Request) (bool, int) { return true, 300 }
	up := okUpstream(t)
	cfg := stopConfig(t, pdp, up.srv.URL, "", FailOpen)
	g, h := newTestGateway(t, cfg)
	zero := 0
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, FailMode: FailClosed, CacheTTLSeconds: &zero})
	if g.PDP().FailMode() != FailClosed {
		t.Fatalf("fail mode %s, want closed (AuthSec's, stricter than local open)", g.PDP().FailMode())
	}
	do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	if g.PDP().cache.len() != 0 {
		t.Fatal("cached although AuthSec's cache lifetime is 0")
	}
	setFail(pdp, true)
	if w := do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil)); strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("local open loosened AuthSec's closed: %s", w.Body.String())
	}
	// Local config may be stricter: closed locally, open at AuthSec.
	pdp2 := newFakePDP(t)
	g2, _ := newTestGateway(t, stopConfig(t, pdp2, up.srv.URL, "", FailClosed))
	setHints(t, g2, pdp2, &Hints{Mode: agentgateway.ModeObserve, FailMode: FailOpen})
	if g2.PDP().FailMode() != FailClosed {
		t.Fatalf("local closed not kept: %s", g2.PDP().FailMode())
	}
	// And a local max_ttl_seconds shortens AuthSec's.
	cfg3 := stopConfig(t, pdp2, up.srv.URL, "", FailAuto)
	cfg3.Cache.MaxTTLSeconds = 5
	g3, _ := newTestGateway(t, cfg3)
	sixty := 60
	setHints(t, g3, pdp2, &Hints{Mode: agentgateway.ModeObserve, CacheTTLSeconds: &sixty})
	if g3.PDP().CacheTTLCap() != 5*time.Second {
		t.Fatalf("cap %s, want 5s", g3.PDP().CacheTTLCap())
	}
	// An unknown fail mode from AuthSec counts as closed.
	if agentgateway.StricterFailMode(FailOpen, "bogus") != FailClosed {
		t.Fatal("unknown fail mode not closed")
	}
}

func TestStaleHintsBypassCache(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.decide = func(agentgateway.Request) (bool, int) { return true, 300 }
	up := okUpstream(t)
	g, h := newTestGateway(t, stopConfig(t, pdp, up.srv.URL, "", FailAuto))
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve})
	do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	if pdp.evalCount() != 1 {
		t.Fatalf("not cached: %d", pdp.evalCount())
	}
	// Hints not confirmed for longer than the stale limit: the cache (whose
	// allows a stop list could no longer revoke) is not used.
	base := time.Now()
	g.PDP().now = func() time.Time { return base.Add(time.Minute) }
	g.PDP().cache.now = func() time.Time { return base }
	do(h, "POST", "/mcp/github", toolCallBody, agentHdr(nil))
	if pdp.evalCount() != 2 {
		t.Fatalf("stale hints still served from cache: %d evaluations", pdp.evalCount())
	}
}

func TestStoppedAgentGetsNoPassthrough(t *testing.T) {
	pdp := newFakePDP(t)
	mcpUp := okUpstream(t)
	llmUp := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		writeJSON(w, 200, map[string]any{"data": []any{}})
	})
	g, h := newTestGateway(t, stopConfig(t, pdp, mcpUp.srv.URL, llmUp.srv.URL, FailAuto))
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, Stopped: stopIdentity()})
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	if w := do(h, "POST", "/mcp/github", list, agentHdr(nil)); !strings.Contains(w.Body.String(), agentgateway.ReasonAgentStopped) {
		t.Fatalf("tools/list passed through: %s", w.Body.String())
	}
	if w := do(h, "GET", "/mcp/github", "", agentHdr(nil)); w.Code != http.StatusForbidden {
		t.Fatalf("stream passed through: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, "GET", "/llm/openai/v1/models", "", map[string]string{"Authorization": "Bearer " + testAgentKey}); w.Code != http.StatusForbidden {
		t.Fatalf("model listing passed through: %d %s", w.Code, w.Body.String())
	}
	chat := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	if w := do(h, "POST", "/llm/openai/v1/chat/completions", chat, map[string]string{"Authorization": "Bearer " + testAgentKey,
		"Content-Type": "application/json"}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), agentgateway.ReasonAgentStopped) {
		t.Fatalf("model call of a stopped agent: %d %s", w.Code, w.Body.String())
	}
	if len(mcpUp.calls()) != 0 || len(llmUp.calls()) != 0 || pdp.evalCount() != 0 {
		t.Fatalf("stopped agent reached upstream (mcp %d, llm %d) or the PDP (%d)", len(mcpUp.calls()), len(llmUp.calls()), pdp.evalCount())
	}
	// A model-level stop leaves MCP alone.
	setHints(t, g, pdp, &Hints{Mode: agentgateway.ModeObserve, Stopped: []agentgateway.StoppedSubject{
		{Selector: agentgateway.Selector{IdentityID: billingIdentity}, Kind: agentgateway.KindModel, Ref: "containment:m"}}})
	if w := do(h, "POST", "/mcp/github", list, agentHdr(nil)); strings.Contains(w.Body.String(), agentgateway.ReasonAgentStopped) {
		t.Fatalf("model-level stop refused MCP: %s", w.Body.String())
	}
}
