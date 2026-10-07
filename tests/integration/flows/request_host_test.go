//go:build integration

package flows

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/middlewares"
)

// AS-064: a client-chosen Host or X-Forwarded-Host decides neither the
// workspace nor which host the OAuth server answers for.
func Test_RequestHost_NotTrustedUnlessAllowListed(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws := seedWorkspace(t, n)
	mustExec(t, `UPDATE workspaces SET slug = ? WHERE id = ?`, n, ws.WorkspaceID)

	canonical, _ := url.Parse(config.AppConfig.OAuthBaseURL())

	// X-Forwarded-Host from an untrusted peer does not make an off-host
	// request look canonical.
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.Host = "evil-" + n + ".example"
	req.Header.Set("X-Forwarded-Host", canonical.Host)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code != http.StatusPermanentRedirect {
		t.Fatalf("spoofed X-Forwarded-Host: got %d, want 308 to the canonical issuer", w.Code)
	}

	// "<slug>.<foreign host>" does not select the workspace with that slug.
	email := "hostpick-" + n + "@example.test"
	body, _ := json.Marshal(map[string]string{"email": email, "password": "HostPick123!pass"})
	req = httptest.NewRequest("POST", "/authsec/uflow/user/register/initiate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = n + ".attacker-" + n + ".example"
	w = httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	if w.Code == http.StatusOK || countWhere(t, "pending_registrations", "email = ?", email) != 0 {
		t.Fatalf("a foreign host selected workspace %s: %d %s", ws.WorkspaceID, w.Code, w.Body.String())
	}

	// Allow-list checks used for redirect targets.
	for host, want := range map[string]bool{
		"evil-" + n + ".example":               false,
		strings.ToLower(ws.WorkspaceDomain):    true,
		canonical.Host:                         true,
		"localhost-" + n + ".attacker.example": false,
	} {
		if got := middlewares.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}
