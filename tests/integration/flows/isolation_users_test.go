//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Cross-tenant isolation for admin users, end users, invites and password
// administration (ADR-0001 §4; AS-048). Every request is made with A's admin
// token against B's rows: it is answered 404 (or an empty list) and B's rows
// do not change.

func Test_Isolation_AdminUsers(t *testing.T) {
	a, b, _, db := twoTenantsWithData(t)
	tok := a.AdminToken
	bAdmin := b.WS.AdminUserID.String()

	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/users/"+bAdmin, nil, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/users/delete_all/"+bAdmin, nil, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/users/active",
		map[string]interface{}{"user_id": bAdmin, "active": false}, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/users/"+db.InviteeID.String(), nil, tok)

	assertCount(t, 1, "users", "id = ? AND active = true", b.WS.AdminUserID)
	assertCount(t, 1, "users", "id = ? AND active = true", db.InviteeID)
	assertCount(t, 1, "role_bindings", "user_id = ?", b.WS.AdminUserID)

	env := testsupport.Get(t)
	for _, method := range []string{"GET", "POST"} {
		w := env.Do(method, "/authsec/uflow/admin/users/list", nil, tok)
		assertStatus(t, w, http.StatusOK)
		if strings.Contains(w.Body.String(), b.WS.AdminEmail) || strings.Contains(w.Body.String(), db.InviteeEmail) {
			t.Errorf("%s /admin/users/list leaked B's admins", method)
		}
	}
}

// AS-048: a workspace admin can delete and deactivate the users of their own
// workspace (these handlers read user_info, which nothing set: always 403).
func Test_Isolation_AdminDeletesOwnUsers(t *testing.T) {
	a, _, da, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken

	w := env.Do("DELETE", "/authsec/uflow/admin/users/"+da.InviteeID.String(), nil, tok)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "users", "id = ? AND active = false", da.InviteeID)

	w = env.Do("POST", "/authsec/uflow/user/enduser/active",
		map[string]interface{}{"user_id": a.EndUser.UserID.String(), "active": false}, tok)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "users", "id = ? AND active = false", a.EndUser.UserID)

	w = env.Do("DELETE", "/authsec/uflow/user/enduser/"+a.WS.WorkspaceID.String()+"/"+a.EndUser.UserID.String(), nil, tok)
	assertStatus(t, w, http.StatusOK)
}

func Test_Isolation_EndUsers(t *testing.T) {
	a, b, _, _ := twoTenantsWithData(t)
	tok := a.AdminToken
	aWS := a.WS.WorkspaceID.String()
	bUser := b.EndUser.UserID.String()
	nameBefore := columnValue(t, "users", "name", "id = ?", b.EndUser.UserID)
	hashBefore := columnValue(t, "users", "password_hash", "id = ?", b.EndUser.UserID)

	assertCrossTenant404(t, "GET", "/authsec/uflow/user/enduser/"+aWS+"/"+bUser, nil, tok)
	assertCrossTenant404(t, "PUT", "/authsec/uflow/user/enduser/"+aWS+"/"+bUser,
		map[string]interface{}{"name": "renamed by A"}, tok)
	assertCrossTenant404(t, "PUT", "/authsec/uflow/user/enduser/"+aWS+"/"+bUser+"/status",
		map[string]interface{}{"active": true}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/enduser/active",
		map[string]interface{}{"workspace_id": aWS, "user_id": bUser, "active": false}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/enduser/delete",
		map[string]interface{}{"user_id": bUser}, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/user/enduser/"+aWS+"/"+bUser, nil, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/user/enduser/delete_all/"+aWS+"/"+bUser, nil, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/enduser/active",
		map[string]interface{}{"user_id": bUser, "active": false}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/admin/change-password",
		map[string]interface{}{"workspace_id": aWS, "user_id": bUser, "new_password": "Changed-by-A-123"}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/admin/reset-password",
		map[string]interface{}{"workspace_id": aWS, "user_id": bUser}, tok)
	// Naming B's workspace in the path is refused before any lookup.
	assertCrossTenant404(t, "GET", "/authsec/uflow/user/enduser/"+b.WS.WorkspaceID.String()+"/"+bUser, nil, tok)

	assertCount(t, 1, "users", "id = ? AND active = true", b.EndUser.UserID)
	if got := columnValue(t, "users", "name", "id = ?", b.EndUser.UserID); got != nameBefore {
		t.Errorf("B's user was renamed: %q", got)
	}
	if got := columnValue(t, "users", "password_hash", "id = ?", b.EndUser.UserID); got != hashBefore {
		t.Errorf("B's user password was changed")
	}
	assertCount(t, 1, "role_bindings", "user_id = ?", b.EndUser.UserID)
	assertCount(t, 1, "user_groups", "user_id = ?", b.EndUser.UserID)
}

// The admin end-user list returns the caller's workspace only. It answered
// 400 for every workspace (it opened a per-tenant database that no longer
// exists).
func Test_Isolation_AdminEndUserList(t *testing.T) {
	a, b, _, _ := twoTenantsWithData(t)
	w := testsupport.Get(t).Do("POST", "/authsec/uflow/admin/enduser/list", map[string]interface{}{"workspace_id": a.WS.WorkspaceID.String(), "page": 1, "limit": 100}, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, a.EndUser.Email) {
		t.Errorf("own end user missing from list: %s", body)
	}
	if strings.Contains(body, b.EndUser.Email) || strings.Contains(body, b.WS.AdminEmail) {
		t.Errorf("B's users leaked into A's list")
	}
}

func Test_Isolation_Invites(t *testing.T) {
	a, b, _, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken

	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/invite/cancel",
		map[string]interface{}{"user_id": db.InviteeID.String()}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/invite/resend",
		map[string]interface{}{"user_id": db.InviteeID.String()}, tok)
	assertCount(t, 1, "users", "id = ? AND password_hash = 'invite-hash'", db.InviteeID)
	assertCount(t, 1, "role_bindings", "user_id = ?", db.InviteeID)

	w := env.Do("GET", "/authsec/uflow/admin/invite/pending", nil, tok)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), db.InviteeEmail) {
		t.Errorf("B's pending invite leaked into A's list")
	}

	// An invite always lands in the inviter's workspace; without a body
	// workspace_id it used to create a user with no workspace.
	email := "new-" + emailSafeNonce() + "@" + a.WS.WorkspaceDomain
	w = env.Do("POST", "/authsec/uflow/admin/invite", map[string]interface{}{
		"email": email, "username": "u" + emailSafeNonce(),
	}, tok)
	assertStatus(t, w, http.StatusCreated)
	assertCount(t, 1, "users", "LOWER(email) = LOWER(?) AND workspace_id = ?", email, a.WS.WorkspaceID)
	assertCount(t, 0, "users", "LOWER(email) = LOWER(?) AND workspace_id IS DISTINCT FROM ?", email, a.WS.WorkspaceID)
	_ = b
}
