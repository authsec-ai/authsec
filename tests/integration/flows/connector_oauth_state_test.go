//go:build integration

package flows

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// AS-071: a connector OAuth callback completes only in the browser that
// started the flow (binding cookie), and a state is usable once.
func Test_ConnectorOAuthCallback_BoundToBrowser_SingleUse(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	state := "st-" + n + "-" + uuid.NewString()
	if err := config.DB.Exec(`INSERT INTO connector_oauth_states
		(state, workspace_id, connector_id, provider_key, binding_type, code_verifier, created_by, expires_at)
		VALUES (?, ?, ?, 'no-such-provider', 'workspace', 'verifier', ?, ?)`,
		state, ws.WorkspaceID, uuid.New(), ws.AdminUserID.String(), time.Now().Add(5*time.Minute)).Error; err != nil {
		t.Fatalf("seed state: %v", err)
	}
	stateRows := func() int64 {
		var c int64
		config.DB.Table("connector_oauth_states").Where("state = ?", state).Count(&c)
		return c
	}
	callback := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		q := url.Values{"code": {"code-" + n}, "state": {state}}
		req, _ := http.NewRequest(http.MethodGet, "/authsec/connector-oauth/callback?"+q.Encode(), nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)
		return w
	}

	// Another browser (no cookie, or a cookie for a different state) cannot
	// complete it, and does not burn the state.
	if w := callback(nil); w.Code != http.StatusBadRequest {
		t.Fatalf("callback without binding cookie: %d %s", w.Code, w.Body.String())
	}
	forged := &http.Cookie{Name: services.ConnectStateCookie(state), Value: services.ConnectStateBinding(state + "x")}
	if w := callback(forged); w.Code != http.StatusBadRequest {
		t.Fatalf("callback with wrong binding: %d", w.Code)
	}
	if stateRows() != 1 {
		t.Fatalf("unbound callback consumed the state")
	}

	// The initiating browser's binding consumes it (the provider lookup then
	// fails, which is fine here); a replay finds nothing. Driven through the
	// service because the test environment has no Vault for the handler.
	svc := services.NewConnectorOAuthService(config.DB, nil)
	good := services.ConnectStateBinding(state)
	if _, err := svc.HandleCallback("code-"+n, state, good); err == nil {
		t.Fatalf("callback for an unknown provider succeeded")
	}
	if stateRows() != 0 {
		t.Fatalf("bound callback did not consume the state")
	}
	if _, err := svc.HandleCallback("code-"+n, state, good); err == nil || err.Error() != "invalid or expired state" {
		t.Fatalf("replayed state: %v", err)
	}
}
