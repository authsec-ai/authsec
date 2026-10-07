//go:build integration

package flows

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// seedCustomUser adds a password user with this email to the workspace.
func seedCustomUser(t *testing.T, ws *WorkspaceScenario, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	hash, _ := bcrypt.GenerateFromPassword([]byte("OriginalPass123!"), bcrypt.MinCost)
	mustExec(t, `INSERT INTO users (id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'custom', true, NOW(), NOW())`, id, ws.WorkspaceID, email, string(hash), ws.WorkspaceDomain)
	return id
}

func latestOTP(t *testing.T, email string) string {
	t.Helper()
	var otp string
	if err := config.DB.Raw(`SELECT otp FROM otp_entries WHERE email = $1 ORDER BY created_at DESC LIMIT 1`, email).Row().Scan(&otp); err != nil {
		t.Fatalf("read OTP: %v", err)
	}
	return otp
}

// AS-038: a password-reset code verified for workspace A does not reset the
// same email's password in workspace B, and starting another flow (sign-up
// in B) does not delete A's code.
func Test_OTP_ScopedByWorkspaceAndPurpose(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	email := "shared-" + n + "@example.test"
	seedCustomUser(t, wsA, email)
	userB := seedCustomUser(t, wsB, email)
	hashOf := func(id uuid.UUID) string { return scalar(t, `SELECT password_hash FROM users WHERE id = ?`, id) }
	beforeB := hashOf(userB)

	env.Do("POST", "/authsec/uflow/user/forgot-password", map[string]string{
		"email": email, "workspace_id": wsA.WorkspaceID.String()}, "")
	otpA := latestOTP(t, email)

	// Another flow for the same email in another workspace leaves A's code.
	other := "Other" + n + "Pass1!"
	env.Do("POST", "/authsec/uflow/user/register/initiate", map[string]string{
		"email": email, "password": other, "workspace_id": wsB.WorkspaceID.String()}, "")

	assertStatus(t, env.Do("POST", "/authsec/uflow/user/forgot-password/verify-otp", map[string]string{
		"email": email, "otp": otpA}, ""), http.StatusOK)

	// The code was verified for A: resetting B's password with it fails.
	w := env.Do("POST", "/authsec/uflow/user/forgot-password/reset", map[string]string{
		"email": email, "new_password": "Attacker" + n + "Pass1!", "workspace_id": wsB.WorkspaceID.String()}, "")
	assertStatus(t, w, http.StatusBadRequest)
	if hashOf(userB) != beforeB {
		t.Fatalf("workspace B's password was reset with a code issued for workspace A")
	}

	// It does reset A's.
	assertStatus(t, env.Do("POST", "/authsec/uflow/user/forgot-password/reset", map[string]string{
		"email": email, "new_password": "Owner" + n + "Pass1!", "workspace_id": wsA.WorkspaceID.String()}, ""), http.StatusOK)
}

// AS-038: AuthMiddleware's email fallback resolves a user only inside the
// token's workspace; it never searches every workspace by email.
func Test_ResolveUserID_EmailFallbackIsWorkspaceScoped(t *testing.T) {
	testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	email := "only-a-" + n + "@example.test"
	userA := seedCustomUser(t, wsA, email)

	resolve := func(ws string) (string, error) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("GET", "/", nil)
		c.Set("email", email)
		if ws != "" {
			c.Set("workspace_id", ws)
		}
		return middlewares.ResolveUserID(c)
	}

	if got, err := resolve(wsA.WorkspaceID.String()); err != nil || got != userA.String() {
		t.Fatalf("own workspace: got %q, %v; want %s", got, err, userA)
	}
	if got, err := resolve(wsB.WorkspaceID.String()); err == nil {
		t.Fatalf("a workspace-B context resolved workspace A's user %s", got)
	}
	if got, err := resolve(""); err == nil {
		t.Fatalf("a context without a workspace resolved user %s by email alone", got)
	}
}
