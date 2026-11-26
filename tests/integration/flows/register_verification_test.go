//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-018: the legacy single-step /user/register no longer creates an account
// without proof of the mailbox; it starts the OTP flow, and the account
// exists only after /user/register/complete.
func Test_LegacyRegister_RequiresEmailOTP(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatal(err)
	}
	email := "newcomer-" + n + "@example.test"
	countUsers := func() int64 {
		var c int64
		config.DB.Raw(`SELECT COUNT(*) FROM users WHERE workspace_id = $1 AND LOWER(email) = $2`, ws.WorkspaceID, email).Row().Scan(&c)
		return c
	}

	w := env.Do("POST", "/authsec/uflow/user/register", map[string]string{
		"email": email, "password": "NewcomerPass123!", "workspace_id": ws.WorkspaceID.String(),
	}, "")
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "Registration completed") || countUsers() != 0 {
		t.Fatalf("legacy register created an unverified account: %s", w.Body.String())
	}

	var otp string
	if err := config.DB.Raw(`SELECT otp FROM otp_entries WHERE email = $1 ORDER BY created_at DESC LIMIT 1`, email).Row().Scan(&otp); err != nil {
		t.Fatalf("read OTP: %v", err)
	}
	wrong := "000000"
	if otp == wrong {
		wrong = "111111"
	}
	assertStatus(t, env.Do("POST", "/authsec/uflow/user/register/complete", map[string]string{
		"email": email, "otp": wrong, "workspace_id": ws.WorkspaceID.String()}, ""), http.StatusUnauthorized)
	if countUsers() != 0 {
		t.Fatalf("a wrong OTP created the account")
	}
	assertStatus(t, env.Do("POST", "/authsec/uflow/user/register/complete", map[string]string{
		"email": email, "otp": otp, "workspace_id": ws.WorkspaceID.String()}, ""), http.StatusOK)
	if countUsers() != 1 {
		t.Fatalf("the verified registration did not create the account")
	}
}
