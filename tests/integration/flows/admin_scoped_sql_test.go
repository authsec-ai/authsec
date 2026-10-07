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
