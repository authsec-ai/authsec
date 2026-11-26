//go:build integration

package flows

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/config"
	repositories "github.com/authsec-ai/authsec/repository"
)

// GrantUserClientsAccess runs under row-level security for the named
// workspace: it seeds the workspace's 'clients' permissions and binds one of
// its users to the admin role, and refuses a user of another workspace.
func Test_ClientsRBAC_GrantScopedToWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	repo := repositories.NewClientsRBACRepository(config.DB)
	ctx := context.Background()

	if err := repo.GrantUserClientsAccess(ctx, b.EndUser.UserID, a.WS.WorkspaceID); err == nil {
		t.Error("workspace B's user was granted clients access in workspace A")
	}
	assertCount(t, 0, "role_bindings", "workspace_id = ? AND user_id = ?", a.WS.WorkspaceID, b.EndUser.UserID)

	if err := repo.GrantUserClientsAccess(ctx, a.EndUser.UserID, a.WS.WorkspaceID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// Idempotent.
	if err := repo.GrantUserClientsAccess(ctx, a.EndUser.UserID, a.WS.WorkspaceID); err != nil {
		t.Fatalf("second grant: %v", err)
	}
	assertCount(t, 8, "permissions", "workspace_id = ? AND resource = 'clients'", a.WS.WorkspaceID)
	assertCount(t, 0, "permissions", "workspace_id = ? AND resource = 'clients'", b.WS.WorkspaceID)
	adminRole := columnValue(t, "roles", "id", "workspace_id = ? AND name = 'admin'", a.WS.WorkspaceID)
	assertCount(t, 8, "role_permissions rp JOIN permissions p ON p.id = rp.permission_id",
		"rp.role_id = ? AND p.resource = 'clients'", adminRole)
	assertCount(t, 1, "role_bindings", "workspace_id = ? AND user_id = ? AND role_id = ?", a.WS.WorkspaceID, a.EndUser.UserID, adminRole)
}
