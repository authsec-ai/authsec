//go:build integration

package flows

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/logintickets"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-078: the admin WebAuthn steps act on the signed-in subject's account in
// the subject's workspace, not on whichever user first matches the email.
func Test_AdminWebAuthn_UsesSubjectWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	// The same email in workspace B, with an id that sorts first, so an
	// email-only lookup (ORDER BY id LIMIT 1) finds B's account.
	twin := uuid.MustParse("00000000-0000-4000-8000-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
	mustExec(t, `INSERT INTO users (id, client_id, workspace_id, email, workspace_domain, provider, active, created_at, updated_at)
	             VALUES ($1, $1, $2, $3, $4, 'local', true, NOW(), NOW())`,
		twin, wsB.WorkspaceID, wsA.AdminEmail, wsB.WorkspaceDomain)

	ticketA := adminPasswordLogin(t, env, wsA)
	req := httptest.NewRequest("POST", "/authsec/webauthn/admin/beginRegistration",
		strings.NewReader(`{"email":"`+wsA.AdminEmail+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://app.authsec.dev")
	req.Header.Set(logintickets.HeaderName, ticketA)
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	assertStatus(t, w, http.StatusOK)
	var opts struct {
		PublicKey struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &opts); err != nil {
		t.Fatalf("decode options: %v (%s)", err, w.Body.String())
	}
	handle, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(opts.PublicKey.User.ID, "="))
	if err != nil {
		t.Fatalf("decode user handle %q: %v", opts.PublicKey.User.ID, err)
	}
	if string(handle) != wsA.AdminUserID.String() {
		t.Fatalf("registration options are for user %s, want A's admin %s (B's twin is %s)",
			handle, wsA.AdminUserID, twin)
	}
}
