//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-032: a session stops working as soon as its user leaves, is suspended
// in, or is deactivated or deleted from the workspace, not when it expires.
func Test_Session_RevokedWithMembership(t *testing.T) {
	env := testsupport.Get(t)
	const probe = "/authsec/uflow/admin/users/list"
	ok := func(tok string) int { return env.Do("GET", probe, nil, tok).Code }

	t.Run("deactivated user", func(t *testing.T) {
		a, _ := TwoTenants(t)
		if c := ok(a.AdminToken); c != http.StatusOK {
			t.Fatalf("baseline: got %d", c)
		}
		config.DB.Exec(`UPDATE users SET active = false WHERE id = ?`, a.WS.AdminUserID)
		if c := ok(a.AdminToken); c != http.StatusUnauthorized {
			t.Fatalf("deactivated user: got %d, want 401", c)
		}
	})

	t.Run("deleted user", func(t *testing.T) {
		a, _ := TwoTenants(t)
		config.DB.Exec(`UPDATE users SET deleted_at = now() WHERE id = ?`, a.WS.AdminUserID)
		config.DB.Exec(`DELETE FROM workspace_memberships WHERE user_id = ?`, a.WS.AdminUserID)
		if c := ok(a.AdminToken); c != http.StatusUnauthorized {
			t.Fatalf("deleted user: got %d, want 401", c)
		}
	})

	t.Run("operator from another workspace loses access when suspended", func(t *testing.T) {
		a, b := TwoTenants(t)
		// B's admin is a member of A (operator access), then suspended.
		config.DB.Exec(`INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
			VALUES (gen_random_uuid(), ?, ?, ?, 'active', 'invite', now(), now())`, a.WS.WorkspaceID, b.WS.AdminUserID, a.WS.AdminRoleID)
		tok := env.MustAsAdmin(b.WS.AdminUserID, a.WS.WorkspaceID, b.WS.AdminEmail)
		if c := ok(tok); c == http.StatusUnauthorized {
			t.Fatalf("active member was refused")
		}
		config.DB.Exec(`UPDATE workspace_memberships SET status = 'suspended' WHERE workspace_id = ? AND user_id = ?`, a.WS.WorkspaceID, b.WS.AdminUserID)
		if c := ok(tok); c != http.StatusUnauthorized {
			t.Fatalf("suspended member: got %d, want 401", c)
		}
	})

	t.Run("token for a workspace the user never belonged to", func(t *testing.T) {
		a, b := TwoTenants(t)
		tok := env.MustAsAdmin(a.WS.AdminUserID, b.WS.WorkspaceID, a.WS.AdminEmail)
		if c := ok(tok); c != http.StatusUnauthorized {
			t.Fatalf("non-member token: got %d, want 401", c)
		}
	})
}
