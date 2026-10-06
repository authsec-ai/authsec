//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Cross-tenant isolation for workspace memberships, end-user states, role
// bindings and the effective-access view (ADR-0001 §4; AS-062).

func Test_Isolation_Memberships(t *testing.T) {
	a, b, _, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	base := "/authsec/uflow/v2/tenants/" + a.WS.WorkspaceID.String()
	bAdmin := b.WS.AdminUserID.String()
	bUser := b.EndUser.UserID.String()

	assertCrossTenant404(t, "GET", base+"/memberships/"+bAdmin, nil, tok)
	assertCrossTenant404(t, "PATCH", base+"/memberships/"+bAdmin, map[string]interface{}{"status": "suspended"}, tok)
	assertCrossTenant404(t, "DELETE", base+"/memberships/"+bAdmin, nil, tok)
	// Making B's admin a member of A used to succeed (201).
	assertCrossTenant404(t, "POST", base+"/memberships", map[string]interface{}{"user_id": bAdmin, "membership_type": "admin"}, tok)
	assertCrossTenant404(t, "GET", "/authsec/uflow/v2/tenants/"+b.WS.WorkspaceID.String()+"/memberships", nil, tok)

	assertCount(t, 1, "workspace_memberships", "workspace_id = ? AND user_id = ? AND status = 'active'", b.WS.WorkspaceID, b.WS.AdminUserID)
	assertCount(t, 0, "workspace_memberships", "workspace_id = ? AND user_id = ?", a.WS.WorkspaceID, b.WS.AdminUserID)

	assertCrossTenant404(t, "GET", base+"/end-users/"+bUser, nil, tok)
	assertCrossTenant404(t, "PATCH", base+"/end-users/"+bUser, map[string]interface{}{"status": "suspended"}, tok)
	assertCrossTenant404(t, "POST", base+"/end-users/"+bUser+"/suspend", map[string]interface{}{"reason": "x"}, tok)
	assertCrossTenant404(t, "POST", base+"/end-users/"+bUser+"/reactivate", nil, tok)
	assertCount(t, 1, "workspace_end_user_states", "workspace_id = ? AND user_id = ? AND status = 'active'", b.WS.WorkspaceID, b.EndUser.UserID)
	assertCount(t, 0, "workspace_end_user_states", "workspace_id = ? AND user_id = ?", a.WS.WorkspaceID, b.EndUser.UserID)

	for _, p := range []string{base + "/memberships", base + "/end-users"} {
		w := env.Do("GET", p, nil, tok)
		assertStatus(t, w, http.StatusOK)
		if strings.Contains(w.Body.String(), bAdmin) || strings.Contains(w.Body.String(), bUser) {
			t.Errorf("GET %s leaked B's members: %s", p, w.Body.String())
		}
	}
}

// The effective-access view answered for any user id on the platform, with
// that user's bindings, role names and scopes.
func Test_Isolation_EffectiveAccess(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)

	w := assertCrossTenant404(t, "GET", "/authsec/uflow/v2/users/"+b.EndUser.UserID.String()+"/effective-access", nil, a.AdminToken)
	if strings.Contains(w.Body.String(), db.BindingID.String()) {
		t.Fatalf("B's binding leaked: %s", w.Body.String())
	}

	w = env.Do("GET", "/authsec/uflow/v2/users/"+a.EndUser.UserID.String()+"/effective-access", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), da.BindingID.String()) {
		t.Errorf("own user's binding missing: %s", w.Body.String())
	}
}

// AS-062: a role binding's group, role, user and resource-server scope must
// all belong to the caller's workspace.
func Test_Isolation_RoleBindings(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	aRole := a.WS.AdminRoleID.String()
	aWS := a.WS.WorkspaceID.String()

	for _, body := range []map[string]interface{}{
		{"group_id": db.GroupID.String(), "role_id": aRole},
		{"user_id": b.EndUser.UserID.String(), "role_id": aRole},
		{"user_id": a.EndUser.UserID.String(), "role_id": b.WS.AdminRoleID.String()},
		{"user_id": a.EndUser.UserID.String(), "role_id": aRole,
			"scope": map[string]string{"type": "resource_server", "id": db.RS.RSID.String()}},
	} {
		assertCrossTenant404(t, "POST", "/authsec/uflow/admin/bindings", body, tok)
	}
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/bindings/"+db.BindingID.String(), nil, tok)

	// The v2 group binding endpoint, same rules.
	for _, c := range []struct {
		group string
		body  map[string]interface{}
	}{
		{db.GroupID.String(), map[string]interface{}{"workspace_id": aWS, "role_id": aRole}},
		{da.GroupID.String(), map[string]interface{}{"workspace_id": aWS, "role_id": b.WS.AdminRoleID.String()}},
		{da.GroupID.String(), map[string]interface{}{"workspace_id": aWS, "role_id": aRole, "scope_type": "resource_server", "scope_id": db.RS.RSID.String()}},
	} {
		assertCrossTenant404(t, "POST", "/authsec/uflow/v2/groups/"+c.group+"/role-bindings", c.body, tok)
	}

	assertCount(t, 0, "role_bindings", "scope_id = ? AND workspace_id = ?", db.RS.RSID, a.WS.WorkspaceID)
	assertCount(t, 0, "role_bindings", "workspace_id = ? AND group_id IS NOT NULL", a.WS.WorkspaceID)
	assertCount(t, 1, "role_bindings", "id = ?", db.BindingID)

	w := env.Do("GET", "/authsec/uflow/admin/bindings", nil, tok)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), db.BindingID.String()) {
		t.Errorf("B's binding leaked into A's list")
	}

	// Own-workspace scope and group bindings still work.
	w = env.Do("POST", "/authsec/uflow/admin/bindings", map[string]interface{}{
		"user_id": a.EndUser.UserID.String(), "role_id": aRole,
		"scope": map[string]string{"type": "resource_server", "id": da.RS.RSID.String()},
	}, tok)
	assertStatus(t, w, http.StatusOK)
	w = env.Do("POST", "/authsec/uflow/v2/groups/"+da.GroupID.String()+"/role-bindings", map[string]interface{}{"role_id": aRole}, tok)
	assertStatus(t, w, http.StatusCreated)
}
