//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Cross-tenant isolation for groups and group membership (ADR-0001 §4).

func Test_Isolation_Groups(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	aWS := a.WS.WorkspaceID.String()
	bGroup := db.GroupID.String()

	assertCrossTenant404(t, "PUT", "/authsec/uflow/admin/groups/"+bGroup,
		map[string]interface{}{"workspace_id": aWS, "name": "renamed-by-a"}, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/groups",
		map[string]interface{}{"workspace_id": aWS, "groups": []string{bGroup}}, tok)
	assertCrossTenant404(t, "GET", "/authsec/uflow/user/groups/"+aWS+"/"+bGroup+"/users", nil, tok)
	// A's group with B's user, B's group with A's user, B's group with B's user.
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/groups/"+aWS+"/users/bulk",
		map[string]interface{}{"group_id": da.GroupID.String(), "user_ids": []string{b.EndUser.UserID.String()}}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/groups/"+aWS+"/users/bulk",
		map[string]interface{}{"group_id": bGroup, "user_ids": []string{a.EndUser.UserID.String()}}, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/admin/groups/"+aWS+"/users/bulk",
		map[string]interface{}{"group_id": bGroup, "user_ids": []string{b.EndUser.UserID.String()}}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/groups/users/add",
		map[string]interface{}{"workspace_id": aWS, "user_id": b.EndUser.UserID.String(), "groups": []string{da.GroupName}}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/user/groups/users/remove",
		map[string]interface{}{"workspace_id": aWS, "user_id": b.EndUser.UserID.String(), "groups": []string{db.GroupName}}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/groups/map",
		map[string]interface{}{"workspace_id": aWS, "client_id": b.WS.ClientID.String(), "groups": []string{da.GroupName}}, tok)
	// B's workspace in the path is refused before any lookup.
	assertCrossTenant404(t, "GET", "/authsec/uflow/admin/groups/"+b.WS.WorkspaceID.String(), nil, tok)

	if got := columnValue(t, "groups", "name", "id = ?", db.GroupID); got != db.GroupName {
		t.Errorf("B's group was renamed to %q", got)
	}
	assertCount(t, 1, "user_groups", "group_id = ?", db.GroupID)
	assertCount(t, 1, "user_groups", "user_id = ?", b.EndUser.UserID)
	assertCount(t, 1, "user_groups", "user_id = ?", a.EndUser.UserID)

	for _, r := range []struct{ method, path string }{
		{"POST", "/authsec/uflow/admin/groups/list"},
		{"GET", "/authsec/uflow/admin/groups/" + aWS},
		{"GET", "/authsec/uflow/user/groups/users"},
	} {
		w := env.Do(r.method, r.path, map[string]interface{}{"workspace_id": aWS}, tok)
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		if strings.Contains(body, db.GroupName) || strings.Contains(body, bGroup) ||
			strings.Contains(body, b.EndUser.Email) || strings.Contains(body, b.WS.AdminEmail) {
			t.Errorf("%s %s leaked B's groups or users: %s", r.method, r.path, body)
		}
	}
}

// Own-workspace group membership works end to end, and the caller's admin
// role is recognised (AS-048: requestHasAdminRole read user_info).
func Test_Isolation_GroupsOwnWorkspace(t *testing.T) {
	a, _, da, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	aWS := a.WS.WorkspaceID.String()

	w := env.Do("POST", "/authsec/uflow/admin/groups/"+aWS+"/users/bulk",
		map[string]interface{}{"group_id": da.GroupID.String(), "user_ids": []string{a.WS.AdminUserID.String()}}, tok)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "user_groups", "group_id = ? AND user_id = ?", da.GroupID, a.WS.AdminUserID)

	w = env.Do("GET", "/authsec/uflow/user/groups/users", nil, tok)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), `"admins"`) || !strings.Contains(w.Body.String(), a.WS.AdminEmail) {
		t.Errorf("an admin's group view must list the workspace admins: %s", w.Body.String())
	}
}
