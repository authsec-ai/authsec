package integration

// The read-API harness: the REAL §5.3 route table (RegisterIGAGraphReadRoutes)
// over the lab's database and gate, called through gin with the token's
// workspace set the way AuthMiddleware sets it. Permission middleware is a
// recorder, so tests can assert which permission each route demands without
// standing up the authz service.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
)

type readAPI struct {
	t   *testing.T
	ctl *platform.IGAGraphReadController
	eng *gin.Engine

	mu sync.Mutex
	// ws is the token's workspace for the next request; claims are extra
	// token context values (user_id, workspace_membership_id ...).
	ws     uuid.UUID
	claims map[string]string
	// lastPerm is the permission the last request's route demanded ("" when
	// its chain has no permission middleware, e.g. /capabilities).
	lastPerm string
}

// readTestCursorKey signs cursors in the suite; any fixed key works.
var readTestCursorKey = []byte("p2-read-test-cursor-key")

// api builds the route table over the lab's database and gate.
func (l *p2Lab) api() *readAPI {
	l.t.Helper()
	gin.SetMode(gin.TestMode)
	a := &readAPI{
		t:      l.t,
		ctl:    platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey),
		ws:     l.ws,
		claims: map[string]string{},
	}
	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		a.mu.Lock()
		ws, claims := a.ws, a.claims
		a.mu.Unlock()
		if ws != uuid.Nil {
			c.Set("workspace_id", ws.String())
		}
		for k, v := range claims {
			c.Set(k, v)
		}
		a.mu.Lock()
		a.lastPerm = ""
		a.mu.Unlock()
		c.Next()
	})
	platform.RegisterIGAGraphReadRoutes(g, a.ctl, func(resource, action string) gin.HandlerFunc {
		perm := resource + ":" + action
		return func(c *gin.Context) {
			a.mu.Lock()
			a.lastPerm = perm
			a.mu.Unlock()
			c.Next()
		}
	})
	a.eng = eng
	return a
}

// requiredPermission calls a route and returns the permission its middleware
// demanded (T6.7): "iga:read", "iga:review", or "" for none.
func (a *readAPI) requiredPermission(method, path string) string {
	a.t.Helper()
	a.do(method, path, nil)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastPerm
}

// asWorkspace makes the next requests carry another workspace in the token
// (E14: cross-workspace ids must be 404).
func (a *readAPI) asWorkspace(ws uuid.UUID) *readAPI {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ws = ws
	return a
}

// withClaims sets extra token context values for the next requests.
func (a *readAPI) withClaims(kv map[string]string) *readAPI {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.claims = kv
	return a
}

// get calls a GET route (path including its query string) and decodes JSON.
func (a *readAPI) get(path string) (int, map[string]any) {
	a.t.Helper()
	return a.do(http.MethodGet, path, nil)
}

// do calls any route with an optional JSON body.
func (a *readAPI) do(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			a.t.Fatalf("encode body: %v", err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: status %d, body is not JSON: %q", method, path, w.Code, w.Body.String())
		}
	}
	return w.Code, out
}

// dig walks decoded JSON by keys and slice indexes: dig(m, "data", "execution",
// 0, "identity", "ref"). Missing paths return nil.
func dig(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			s, ok := v.([]any)
			if !ok || k < 0 || k >= len(s) {
				return nil
			}
			v = s[k]
		default:
			return nil
		}
	}
	return v
}

// digs is dig for a string leaf ("" when absent or not a string).
func digs(v any, path ...any) string {
	s, _ := dig(v, path...).(string)
	return s
}

// digl is dig for an array leaf (nil when absent).
func digl(v any, path ...any) []any {
	s, _ := dig(v, path...).([]any)
	return s
}

// errCode is the §5.2 error code of a response body.
func errCode(body map[string]any) string { return digs(body, "error", "code") }

// refOf builds "<type>:<uuid>".
func refOf(typ string, id uuid.UUID) string { return typ + ":" + id.String() }

// refUUID returns the uuid of a typed reference, failing the test on garbage.
func refUUID(t *testing.T, ref string) uuid.UUID {
	t.Helper()
	_, raw, ok := strings.Cut(ref, ":")
	id, err := uuid.Parse(raw)
	if !ok || err != nil {
		t.Fatalf("not a typed reference: %q", ref)
	}
	return id
}

// qs builds a query string from alternating key, value pairs.
func qs(kv ...string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(kv[i+1]))
	}
	return b.String()
}

// num reads a JSON number leaf as int64 (-1 when absent).
func num(v any, path ...any) int64 {
	switch n := dig(v, path...).(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := strconv.ParseInt(string(n), 10, 64)
		return i
	}
	return -1
}

// mustStatus fails with the body when the status is not want.
func mustStatus(t *testing.T, what string, got int, body map[string]any, want int) {
	t.Helper()
	if got != want {
		raw, _ := json.Marshal(body)
		t.Fatalf("%s: status %d, want %d: %s", what, got, want, raw)
	}
}
