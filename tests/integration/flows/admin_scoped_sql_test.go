//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// The admin controllers' raw SQL runs on the scoped layer (workspace_id = $1,
// row-level security). These tests drive the same-workspace paths end to end,
// so a statement the RLS role cannot run, or one scoped to the wrong
// workspace, fails here.

// delete_all removes the user and its related rows in one RLS transaction,
// and touches nothing in the other workspace.
func Test_AdminScoped_DeleteAllOwnUser(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)

	w := env.Do("DELETE", "/authsec/uflow/admin/users/delete_all/"+da.InviteeID.String(), nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 0, "users", "id = ?", da.InviteeID)
	assertCount(t, 0, "role_bindings", "user_id = ?", da.InviteeID)

	assertCount(t, 1, "users", "id = ?", db.InviteeID)
	assertCount(t, 1, "role_bindings", "user_id = ?", db.InviteeID)
	assertCount(t, 1, "users", "id = ?", b.WS.AdminUserID)
}

// An invite binds the new admin to the workspace's admin role and gives it
// an 'invite' membership, both in the inviter's workspace; cancelling it
// removes the user, its bindings and its membership in one RLS transaction.
func Test_AdminScoped_InviteAndCancel(t *testing.T) {
	a, b, _, db := twoTenantsWithData(t)
	env := testsupport.Get(t)

	email := "inv-" + emailSafeNonce() + "@" + a.WS.WorkspaceDomain
	w := env.Do("POST", "/authsec/uflow/admin/invite", map[string]interface{}{
		"email": email, "username": "u" + emailSafeNonce(),
	}, a.AdminToken)
	assertStatus(t, w, http.StatusCreated)
	uid := columnValue(t, "users", "id", "LOWER(email) = LOWER(?) AND workspace_id = ?", email, a.WS.WorkspaceID)
	if uid == "" {
		t.Fatalf("invited user not created: %s", w.Body.String())
	}
	assertCount(t, 1, "role_bindings", "user_id = ? AND workspace_id = ?", uid, a.WS.WorkspaceID)
	assertCount(t, 1, "workspace_memberships",
		"user_id = ? AND workspace_id = ? AND source = 'invite' AND status = 'active'", uid, a.WS.WorkspaceID)

	w = env.Do("POST", "/authsec/uflow/admin/invite/cancel", map[string]interface{}{"user_id": uid}, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 0, "users", "id = ?", uid)
	assertCount(t, 0, "role_bindings", "user_id = ?", uid)
	assertCount(t, 0, "workspace_memberships", "user_id = ?", uid)

	assertCount(t, 1, "users", "id = ?", db.InviteeID)
	assertCount(t, 1, "workspace_memberships", "user_id = ? AND workspace_id = ?", db.InviteeID, b.WS.WorkspaceID)
}
