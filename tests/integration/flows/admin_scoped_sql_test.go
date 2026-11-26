//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Admin sign-up auto-verifies the new workspace's own subdomain. When that
// domain is already a workspace_domains row of another workspace, the
// upsert used to take over that row (mark it verified and primary for its
// owner); the registration is now refused and the row is untouched.
func Test_AdminScoped_SignupDoesNotTakeOverAnotherWorkspacesDomain(t *testing.T) {
	a, _ := TwoTenants(t)
	env := testsupport.Get(t)
	n := emailSafeNonce()
	domain := n + ".test.local"
	if err := config.DB.Exec(`
		INSERT INTO workspace_domains (workspace_id, domain, kind, is_primary, is_verified, verification_token)
		VALUES (?, ?, 'custom', false, false, 'tok')`, a.WS.WorkspaceID, domain).Error; err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	email := "owner@" + domain
	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]string{
		"email": email, "password": "Passw0rd!Passw0rd", "name": "Squatter", "workspace_domain": n,
	}, "")
	assertStatus(t, w, http.StatusCreated)
	otp := columnValue(t, "otp_entries", "otp", "email = ? ORDER BY created_at DESC LIMIT 1", email)
	w = env.Do("POST", "/authsec/uflow/auth/admin/complete-registration", map[string]string{"email": email, "otp": otp}, "")
	assertStatus(t, w, http.StatusConflict)

	assertCount(t, 1, "workspace_domains", "domain = ? AND workspace_id = ? AND is_verified = false AND is_primary = false",
		domain, a.WS.WorkspaceID)
	assertCount(t, 0, "workspaces", "workspace_domain = ?", domain)
	assertCount(t, 0, "users", "LOWER(email) = LOWER(?)", email)
}

// Admin sign-up writes the new workspace's domain, owner binding and
// membership on the scoped layer, all in the new workspace.
func Test_AdminScoped_SignupWritesInNewWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	domain := n + ".test.local"
	email := "owner@" + domain
	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]string{
		"email": email, "password": "Passw0rd!Passw0rd", "name": "Owner", "workspace_domain": n,
	}, "")
	assertStatus(t, w, http.StatusCreated)
	otp := columnValue(t, "otp_entries", "otp", "email = ? ORDER BY created_at DESC LIMIT 1", email)
	w = env.Do("POST", "/authsec/uflow/auth/admin/complete-registration", map[string]string{"email": email, "otp": otp}, "")
	assertStatus(t, w, http.StatusCreated)

	ws := uuid.MustParse(columnValue(t, "workspaces", "id", "workspace_domain = ?", domain))
	uid := columnValue(t, "users", "id", "LOWER(email) = LOWER(?) AND workspace_id = ?", email, ws)
	assertCount(t, 1, "workspaces", "id = ? AND owner_user_id = ?", ws, uid)
	assertCount(t, 1, "workspace_domains", "domain = ? AND workspace_id = ? AND is_verified AND is_primary", domain, ws)
	assertCount(t, 1, "role_bindings", "user_id = ? AND workspace_id = ? AND scope_type IS NULL", uid, ws)
	assertCount(t, 1, "workspace_memberships", "user_id = ? AND workspace_id = ? AND status = 'active'", uid, ws)
}

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

// The legacy /uflow/register/verify completion writes the new workspace's
// owner, membership and role bindings (workspace-wide, one per core service
// and a wildcard) on the scoped layer, all in the new workspace.
func Test_AdminScoped_LegacyRegisterVerifyWritesInNewWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	domain := n + ".test.local"
	email := "owner@" + domain
	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]string{
		"email": email, "password": "Passw0rd!Passw0rd", "name": "Owner", "workspace_domain": n,
	}, "")
	assertStatus(t, w, http.StatusCreated)
	otp := columnValue(t, "otp_entries", "otp", "email = ? ORDER BY created_at DESC LIMIT 1", email)
	w = env.Do("POST", "/authsec/uflow/register/verify", map[string]string{"email": email, "otp": otp}, "")
	assertStatus(t, w, http.StatusOK)

	ws := uuid.MustParse(columnValue(t, "workspaces", "id", "workspace_domain = ?", domain))
	uid := columnValue(t, "users", "id", "LOWER(email) = LOWER(?) AND workspace_id = ?", email, ws)
	assertCount(t, 1, "workspaces", "id = ? AND owner_user_id = ?", ws, uid)
	assertCount(t, 1, "workspace_memberships", "user_id = ? AND workspace_id = ? AND status = 'active'", uid, ws)
	assertCount(t, 1, "role_bindings", "user_id = ? AND workspace_id = ? AND scope_type IS NULL", uid, ws)
	assertCount(t, 7, "role_bindings", "user_id = ? AND workspace_id = ? AND scope_id = ? AND role_name = 'admin'", uid, ws, ws)
	assertCount(t, 1, "role_bindings", "user_id = ? AND workspace_id = ? AND scope_type = '*' AND scope_id IS NULL", uid, ws)
	assertCount(t, 0, "role_bindings", "user_id = ? AND workspace_id <> ?", uid, ws)
}
