//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// End-user sign-up keeps one pending registration per (workspace, email).
// Starting or finishing a sign-up in one workspace used to delete the
// email's pending registrations in every workspace (DELETE ... WHERE email),
// so a sign-up elsewhere silently cancelled this one.
func Test_EndUserRegister_PendingScopedToWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	email := "both-" + n + "@example.test"

	initiate := func(ws uuid.UUID) string {
		t.Helper()
		w := env.Do("POST", "/authsec/uflow/user/register/initiate", map[string]string{
			"email": email, "password": "Signup" + n + "Pass1!", "workspace_id": ws.String()}, "")
		assertStatus(t, w, http.StatusOK)
		var otp string
		if err := config.DB.Raw(`SELECT otp FROM otp_entries WHERE email = $1 AND workspace_id = $2 ORDER BY created_at DESC LIMIT 1`,
			email, ws).Row().Scan(&otp); err != nil {
			t.Fatalf("read OTP for %s: %v", ws, err)
		}
		return otp
	}
	pending := func(ws uuid.UUID) int64 {
		var c int64
		config.DB.Raw(`SELECT COUNT(*) FROM pending_registrations WHERE email = $1 AND workspace_id = $2`, email, ws).Row().Scan(&c)
		return c
	}
	complete := func(ws uuid.UUID, otp string) {
		t.Helper()
		w := env.Do("POST", "/authsec/uflow/user/register/complete", map[string]string{
			"email": email, "otp": otp, "workspace_id": ws.String()}, "")
		assertStatus(t, w, http.StatusOK)
		var users int64
		config.DB.Raw(`SELECT COUNT(*) FROM users WHERE workspace_id = $1 AND LOWER(email) = $2`, ws, email).Row().Scan(&users)
		if users != 1 {
			t.Fatalf("registration in %s did not create the user", ws)
		}
	}

	otpA := initiate(wsA.WorkspaceID)
	otpB := initiate(wsB.WorkspaceID)
	if pending(wsA.WorkspaceID) != 1 {
		t.Fatalf("starting a sign-up in workspace B deleted workspace A's pending registration")
	}
	// Re-initiating replaces only the workspace's own row.
	otpB = initiate(wsB.WorkspaceID)
	if pending(wsA.WorkspaceID) != 1 || pending(wsB.WorkspaceID) != 1 {
		t.Fatalf("re-initiating must keep one pending row per workspace: A=%d B=%d", pending(wsA.WorkspaceID), pending(wsB.WorkspaceID))
	}

	complete(wsA.WorkspaceID, otpA)
	if pending(wsA.WorkspaceID) != 0 {
		t.Fatalf("completed registration left its pending row")
	}
	if pending(wsB.WorkspaceID) != 1 {
		t.Fatalf("completing the sign-up in workspace A deleted workspace B's pending registration")
	}
	complete(wsB.WorkspaceID, otpB)
}
