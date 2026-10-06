//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Regression tests for AS-007/008/009/022/023/024/039/041/075.

// AS-023/007/024: managing other users is for owners and admins; an end
// user's token gets 403 on every such route.
func Test_UserManagement_RequiresWorkspaceAdmin(t *testing.T) {
	env := testsupport.Get(t)
	ws, u := seedEndUser(t)
	_ = ws
	tok := env.MustAsUser(u.UserID, u.WorkspaceID, u.Email)
	wsid := u.WorkspaceID.String()

	for _, r := range []struct{ method, path string }{
		{"POST", "/authsec/uflow/user/admin/reset-password"},
		{"POST", "/authsec/uflow/user/admin/change-password"},
		{"GET", "/authsec/uflow/user/enduser/list"},
		{"POST", "/authsec/uflow/user/enduser/active"},
		{"PUT", "/authsec/uflow/user/enduser/" + wsid + "/" + u.UserID.String()},
		{"POST", "/authsec/uflow/user/groups/users/add"},
		{"POST", "/authsec/uflow/admin/scim/generate-token"},
	} {
		w := env.Do(r.method, r.path, map[string]interface{}{"workspace_id": wsid, "email": u.Email}, tok)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s as end user: got %d, want 403 (%s)", r.method, r.path, w.Code, w.Body.String())
		}
	}
}

// AS-008: the end-user list only returns the caller's workspace.
func Test_EndUserList_ScopedToWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	wsA, uA := seedEndUser(t)
	_, uB := seedEndUser(t)
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	w := env.Do("POST", "/authsec/uflow/user/enduser/list", map[string]interface{}{
		"workspace_id": wsA.WorkspaceID.String(), "limit": 100, "page": 1,
	}, tokA)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, uA.Email) {
		t.Fatalf("own end user missing from list: %s", body)
	}
	if strings.Contains(body, uB.Email) {
		t.Fatalf("another workspace's end user leaked into the list")
	}
	if strings.Contains(body, "password_hash") {
		t.Fatalf("user list must not serialize password hashes")
	}
}

// AS-009/041: an admin sees only their own workspace, never a password hash,
// and cannot create workspaces through the admin API.
func Test_TenantList_OwnWorkspaceOnly(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	w := env.Do("GET", "/authsec/uflow/admin/tenants", nil, tokA)
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		Tenants []map[string]interface{} `json:"tenants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Tenants) != 1 || resp.Tenants[0]["workspace_id"] != wsA.WorkspaceID.String() {
		t.Fatalf("want exactly the caller's workspace, got %v", resp.Tenants)
	}
	if strings.Contains(w.Body.String(), wsB.AdminEmail) || strings.Contains(w.Body.String(), "password_hash") {
		t.Fatalf("tenant list leaked another workspace or a password hash: %s", w.Body.String())
	}

	if w := env.Do("POST", "/authsec/uflow/admin/tenants", map[string]string{"email": "x@y.test"}, tokA); w.Code != http.StatusNotFound {
		t.Errorf("POST /admin/tenants must be gone, got %d", w.Code)
	}
}

// AS-039/022/075: platform operations are not reachable by tenant users.
func Test_PlatformOperations_Closed(t *testing.T) {
	env := testsupport.Get(t)
	ws, u := seedEndUser(t)
	tokAdmin := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	tokUser := env.MustAsUser(u.UserID, u.WorkspaceID, u.Email)

	if w := env.Do("POST", "/authsec/migration/migrations/master/run", nil, tokAdmin); w.Code != http.StatusNotFound {
		t.Errorf("master migration run must be gone, got %d", w.Code)
	}
	if w := env.Do("POST", "/authsec/oocmgr/oidc/raw-hydra-dump", map[string]string{"workspace_id": ws.WorkspaceID.String()}, tokAdmin); w.Code != http.StatusNotFound {
		t.Errorf("raw hydra dump must be gone, got %d", w.Code)
	}
	if w := env.Do("POST", "/authsec/oocmgr/hydra-clients/sync", nil, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("hydra client sync without a token: got %d, want 401", w.Code)
	}
	if w := env.Do("POST", "/authsec/oocmgr/hydra-clients/sync", nil, tokUser); w.Code != http.StatusForbidden {
		t.Errorf("hydra client sync as end user: got %d, want 403", w.Code)
	}
}
