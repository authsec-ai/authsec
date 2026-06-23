package fakes

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// HydraFake is an in-process httptest server that mimics the Hydra Admin API.
// Tests can override per-test responses via On* helpers.
type HydraFake struct {
	mu           sync.Mutex
	server       *httptest.Server
	introspectFn func(token string) map[string]interface{}
	tokenFn      func(r *http.Request) (int, map[string]interface{})
}

func newHydraFake() *HydraFake {
	h := &HydraFake{}
	h.introspectFn = func(_ string) map[string]interface{} {
		return map[string]interface{}{"active": false}
	}
	h.tokenFn = defaultTokenFn
	return h
}

func defaultTokenFn(_ *http.Request) (int, map[string]interface{}) {
	return http.StatusNotFound, map[string]interface{}{"error": "not implemented in fake"}
}

// OnIntrospect replaces the per-test introspect handler for the duration of one test.
// The function is called with the raw token string and must return a JSON-serialisable map.
func (h *HydraFake) OnIntrospect(fn func(token string) map[string]interface{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.introspectFn = fn
}

// ResetIntrospect restores the default (all inactive) handler.
func (h *HydraFake) ResetIntrospect() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.introspectFn = func(_ string) map[string]interface{} {
		return map[string]interface{}{"active": false}
	}
}

// OnToken replaces the per-test token handler for POST /oauth2/token.
// fn receives the raw *http.Request and returns (statusCode, JSON-serialisable body).
func (h *HydraFake) OnToken(fn func(r *http.Request) (int, map[string]interface{})) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokenFn = fn
}

// ResetToken restores the default (404) token handler.
func (h *HydraFake) ResetToken() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokenFn = defaultTokenFn
}

// MakeFakeJWT builds a syntactically valid JWT whose payload contains
// {"ext":{"context_id":contextID}, "sub":sub, "scope":scope}.
// The signature is not cryptographically valid; extractContextIDFromToken
// only base64-decodes the payload, so this is sufficient for contract tests.
func MakeFakeJWT(contextID, sub, scope string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{
		"sub":   sub,
		"scope": scope,
		"ext":   map[string]interface{}{"context_id": contextID},
		"iat":   1000000,
		"exp":   9999999999,
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"
}

// URL returns the base URL of the fake Hydra server.
func (h *HydraFake) URL() string {
	if h.server != nil {
		return h.server.URL
	}
	return ""
}

func (h *HydraFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/introspect"):
		_ = r.ParseForm()
		token := r.Form.Get("token")
		h.mu.Lock()
		fn := h.introspectFn
		h.mu.Unlock()
		result := fn(token)
		_ = json.NewEncoder(w).Encode(result)

	case r.Method == http.MethodPost && r.URL.Path == "/oauth2/token":
		_ = r.ParseForm()
		h.mu.Lock()
		fn := h.tokenFn
		h.mu.Unlock()
		statusCode, result := fn(r)
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(result)

	default:
		// Return a generic 404 for routes we haven't implemented yet.
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not implemented in fake"})
	}
}
