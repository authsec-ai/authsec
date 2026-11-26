//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-038: an email can be a console admin in several workspaces. The admin
// password reset rewrote whichever account an email-only lookup found
// first; it must reset exactly one, named by its workspace domain.
func Test_Isolation_AdminPasswordResetNeedsTheWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	email := a.WS.AdminEmail

	twin := uuid.New()
	for _, q := range []struct {
		what string
		sql  string
		args []interface{}
	}{
		{"twin admin", `INSERT INTO users (id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
			VALUES (?, ?, ?, 'twin-hash', ?, 'local', true, NOW(), NOW())`,
			[]interface{}{twin, b.WS.WorkspaceID, email, b.WS.WorkspaceDomain}},
		{"twin binding", `INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())`,
			[]interface{}{uuid.New(), b.WS.WorkspaceID, twin, b.WS.AdminRoleID}},
		{"twin membership", `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
			VALUES (?, ?, ?, ?, 'active', 'signup', NOW(), NOW())`,
			[]interface{}{uuid.New(), b.WS.WorkspaceID, twin, b.WS.AdminRoleID}},
		{"verified otp", `INSERT INTO otp_entries (email, otp, expires_at, verified, purpose) VALUES (LOWER(?), '123456', NOW() + INTERVAL '10 minutes', true, 'admin_password_reset')`,
			[]interface{}{email}},
	} {
		if err := config.DB.Exec(q.sql, q.args...).Error; err != nil {
			t.Fatalf("seed %s: %v", q.what, err)
		}
	}
	hashA := columnValue(t, "users", "password_hash", "id = ?", a.WS.AdminUserID)

	w := env.Do("POST", "/authsec/uflow/auth/admin/forgot-password/reset",
		map[string]interface{}{"email": email, "new_password": "Brand-new-pass-1"}, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("ambiguous reset: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
	if columnValue(t, "users", "password_hash", "id = ?", a.WS.AdminUserID) != hashA ||
		columnValue(t, "users", "password_hash", "id = ?", twin) != "twin-hash" {
		t.Fatalf("an ambiguous reset changed a password")
	}

	w = env.Do("POST", "/authsec/uflow/auth/admin/forgot-password/reset",
		map[string]interface{}{"email": email, "new_password": "Brand-new-pass-1", "workspace_domain": a.WS.WorkspaceDomain}, "")
	assertStatus(t, w, http.StatusOK)
	if columnValue(t, "users", "password_hash", "id = ?", a.WS.AdminUserID) == hashA {
		t.Errorf("A's admin password was not reset")
	}
	if columnValue(t, "users", "password_hash", "id = ?", twin) != "twin-hash" {
		t.Errorf("the same email's admin in B was reset too")
	}
}
