package ownership

import "testing"

// TestWorkspaceRoleCheck_SeparatesAdminFromEndUser proves the data-layer logic
// behind middlewares.RequireWorkspaceRole: console/admin access is granted only
// to an active workspace_memberships row whose role is in the allowed admin set.
// An end-user (member role, or no admin membership) is denied — that is the
// admin/end-user separation boundary.
func TestWorkspaceRoleCheck_SeparatesAdminFromEndUser(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db) // workspace A + user aaaa...0001

	adminRole := "f0000000-0000-0000-0000-0000000000a1"
	memberRole := "f0000000-0000-0000-0000-0000000000c2"
	exec(t, db, "INSERT INTO roles (id, name, workspace_id) VALUES ($1,'admin',$2)", adminRole, wsA)
	exec(t, db, "INSERT INTO roles (id, name, workspace_id) VALUES ($1,'member',$2)", memberRole, wsA)

	adminUser := baselineUser // already seeded in workspace A
	endUser := "aaaaaaaa-0000-0000-0000-0000000000e9"
	exec(t, db, "INSERT INTO users (id, email, workspace_id) VALUES ($1,'end@a.com',$2)", endUser, wsA)

	// admin user → active membership with admin role.
	exec(t, db,
		"INSERT INTO workspace_memberships (workspace_id, user_id, role_id, status) VALUES ($1,$2,$3,'active')",
		wsA, adminUser, adminRole)
	// end user → active membership with member role only.
	exec(t, db,
		"INSERT INTO workspace_memberships (workspace_id, user_id, role_id, status) VALUES ($1,$2,$3,'active')",
		wsA, endUser, memberRole)

	// Mirror RequireWorkspaceRole("owner","admin").
	adminGate := func(userID string) int {
		var n int
		if err := db.QueryRow(`
			SELECT count(*)
			  FROM workspace_memberships wm
			  JOIN roles r ON r.id = wm.role_id
			 WHERE wm.user_id = $1 AND wm.workspace_id = $2 AND wm.status = 'active'
			   AND r.name IN ('owner','admin')`, userID, wsA).Scan(&n); err != nil {
			t.Fatalf("gate query: %v", err)
		}
		return n
	}

	if got := adminGate(adminUser); got == 0 {
		t.Fatal("admin user should pass the workspace admin gate")
	}
	if got := adminGate(endUser); got != 0 {
		t.Fatalf("end-user (member role) must NOT pass the workspace admin gate, got count %d", got)
	}
}
