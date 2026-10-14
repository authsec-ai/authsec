//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

func assertLocked(t *testing.T, label string, code int, body string) {
	t.Helper()
	if code != http.StatusTooManyRequests || !strings.Contains(body, "locked") {
		t.Fatalf("%s: got %d %s, want 429 account locked", label, code, body)
	}
}

// AS-034: repeated wrong admin passwords lock the account; while locked even
// the right password is refused. (The users.failed_login_attempts counter
// never fired because the lookup did not load it.)
func Test_AdminLogin_LocksAfterRepeatedFailures(t *testing.T) {
	env := testsupport.Get(t)
	t.Setenv("AUTH_LOCKOUT_MAX_FAILURES", "3")
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatal(err)
	}
	login := func(pw string) (int, string) {
		w := env.Do("POST", "/authsec/uflow/auth/admin/login", map[string]string{
			"email": ws.AdminEmail, "password": pw, "workspace_domain": ws.WorkspaceDomain,
		}, "")
		return w.Code, w.Body.String()
	}
	for i := 0; i < 2; i++ {
		if code, body := login("wrong-password-1"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: got %d %s", i, code, body)
		}
	}
	code, body := login("wrong-password-1")
	assertLocked(t, "third failure", code, body)
	code, body = login(ws.AdminPassword)
	assertLocked(t, "right password while locked", code, body)
}

// AS-034: the end-user password login has the same lockout, keyed by
// (workspace, email).
func Test_EndUserLogin_LocksAfterRepeatedFailures(t *testing.T) {
	env := testsupport.Get(t)
	t.Setenv("AUTH_LOCKOUT_MAX_FAILURES", "3")
	a, b := TwoTenants(t)
	login := func(tn *Tenant, pw string) (int, string) {
		w := env.Do("POST", "/authsec/uflow/user/login", map[string]string{
			"email": tn.EndUser.Email, "password": pw, "workspace_id": tn.WS.WorkspaceID.String(),
		}, "")
		return w.Code, w.Body.String()
	}
	for i := 0; i < 3; i++ {
		login(a, "nope-nope-nope")
	}
	code, body := login(a, a.EndUser.Password)
	assertLocked(t, "right password while locked", code, body)
	// Another workspace's account is unaffected.
	if code, body := login(b, b.EndUser.Password); code != http.StatusOK {
		t.Fatalf("other workspace login: %d %s", code, body)
	}
}

// AS-004/AS-034: a TOTP code is accepted once per time step, and repeated
// wrong codes lock TOTP sign-in.
func Test_TOTPLogin_ReplayAndLockout(t *testing.T) {
	env := testsupport.Get(t)
	t.Setenv("AUTH_LOCKOUT_MAX_FAILURES", "3")
	a, _ := TwoTenants(t)
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Now().Unix()
	if err := config.DB.Exec(`
		INSERT INTO totp_secrets (id, user_id, workspace_id, secret, device_name, is_active, is_primary, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'test', true, true, $5, $5)`,
		uuid.New(), a.EndUser.UserID, a.WS.WorkspaceID, secret, now).Error; err != nil {
		t.Fatal(err)
	}
	login := func(code string) (int, string) {
		w := env.Do("POST", "/authsec/uflow/auth/totp/login", map[string]string{
			"email": a.EndUser.Email, "totp_code": code, "workspace_id": a.WS.WorkspaceID.String(),
		}, "")
		return w.Code, w.Body.String()
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c, body := login(code); c != http.StatusOK {
		t.Fatalf("first use of a valid code: %d %s", c, body)
	}
	if c, body := login(code); c == http.StatusOK {
		t.Fatalf("replayed TOTP code was accepted: %s", body)
	}
	login("000000")
	c, body := login("000001")
	assertLocked(t, "after repeated failures", c, body)
	fresh, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	c, body = login(fresh)
	assertLocked(t, "valid code while locked", c, body)
}
