//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Intern report (Roles): deleting a role answered "Failed to delete role".
// An application's default role failed on the composite FK's SET NULL
// (resource_server_access_policies.workspace_id is NOT NULL), and a role
// members hold failed on workspace_memberships' RESTRICT, both as a 500
// carrying the raw Postgres error.
func Test_RoleDelete(t *testing.T) {
	a, b, da, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	ws := a.WS.WorkspaceID
	del := func(roleID uuid.UUID) *testResponse {
		w := env.Do("DELETE", "/authsec/uflow/admin/roles/"+roleID.String(), nil, tok)
		return &testResponse{code: w.Code, body: w.Body.String()}
	}
	newRole := func(name string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if err := config.DB.Exec(`INSERT INTO roles (id, workspace_id, name) VALUES (?, ?, ?)`, id, ws, name).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
		return id
	}

	t.Run("an application's default role is deleted and the policy kept", func(t *testing.T) {
		role := newRole("viewer-" + emailSafeNonce())
		if err := config.DB.Exec(`
			INSERT INTO resource_server_access_policies (workspace_id, resource_server_id, default_role_id)
			VALUES (?, ?, ?)
			ON CONFLICT (resource_server_id) DO UPDATE SET default_role_id = EXCLUDED.default_role_id`,
			ws, da.RS.RSID, role).Error; err != nil {
			t.Fatalf("seed policy: %v", err)
		}
		if r := del(role); r.code != http.StatusOK {
			t.Fatalf("delete default role: %d %s", r.code, r.body)
		}
		assertCount(t, 0, "roles", "id = ?", role)
		assertCount(t, 1, "resource_server_access_policies", "resource_server_id = ? AND workspace_id = ? AND default_role_id IS NULL", da.RS.RSID, ws)
	})

	t.Run("a role members hold is refused with a reason", func(t *testing.T) {
		role := newRole("editor-" + emailSafeNonce())
		if err := config.DB.Exec(`UPDATE workspace_memberships SET role_id = ? WHERE workspace_id = ? AND user_id = ?`,
			role, ws, da.InviteeID).Error; err != nil {
			t.Fatalf("assign role: %v", err)
		}
		r := del(role)
		if r.code != http.StatusConflict || !strings.Contains(r.body, "hold the") {
			t.Fatalf("delete held role: %d %s, want 409 naming the members", r.code, r.body)
		}
		assertCount(t, 1, "roles", "id = ?", role)
	})

	t.Run("the built-in admin role is refused", func(t *testing.T) {
		r := del(a.WS.AdminRoleID)
		if r.code != http.StatusConflict || !strings.Contains(r.body, "built in") {
			t.Fatalf("delete admin role: %d %s, want 409", r.code, r.body)
		}
	})

	t.Run("another workspace's role is 404", func(t *testing.T) {
		assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/roles/"+b.WS.AdminRoleID.String(), nil, tok)
		assertCount(t, 1, "roles", "id = ?", b.WS.AdminRoleID)
	})

	t.Run("a role nobody holds is deleted", func(t *testing.T) {
		role := newRole("test-editor-" + emailSafeNonce())
		if r := del(role); r.code != http.StatusOK {
			t.Fatalf("delete unused role: %d %s", r.code, r.body)
		}
		assertCount(t, 0, "roles", "id = ?", role)
	})
}

type testResponse struct {
	code int
	body string
}
