//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Cross-tenant isolation for directory-sync configurations, directory sync
// and SCIM provisioning (ADR-0001 §4).

func Test_Isolation_SyncConfigs(t *testing.T) {
	a, b, _, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	bCfg := db.SyncConfigID.String()
	bClient := b.WS.ClientID.String()
	aWS := a.WS.WorkspaceID.String()
	nameBefore := columnValue(t, "sync_configurations", "config_name", "id = ?", db.SyncConfigID)

	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/sync-configs/update",
		map[string]interface{}{"workspace_id": aWS, "id": bCfg, "client_id": bClient, "config_name": "taken-by-a",
			"ad_config": map[string]interface{}{"server": "attacker.invalid:389"}}, tok)
	assertCrossTenant404(t, "POST", "/authsec/uflow/admin/sync-configs/delete",
		map[string]interface{}{"workspace_id": aWS, "id": bCfg, "client_id": bClient}, tok)
	assertCrossTenant404(t, "GET", "/authsec/uflow/admin/sync-configs/"+bCfg+"/runs", nil, tok)

	assertCount(t, 1, "sync_configurations", "id = ? AND ad_server = 'ldap.invalid:389'", db.SyncConfigID)
	if got := columnValue(t, "sync_configurations", "config_name", "id = ?", db.SyncConfigID); got != nameBefore {
		t.Errorf("B's sync configuration was renamed to %q", got)
	}

	w := env.Do("POST", "/authsec/uflow/admin/sync-configs/list", map[string]interface{}{"workspace_id": aWS, "client_id": bClient}, tok)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), bCfg) {
		t.Errorf("B's sync configuration leaked into A's list")
	}

	// A stored configuration of another workspace cannot drive a sync.
	before := countWhere(t, "users", "workspace_id = ?", a.WS.WorkspaceID)
	for _, p := range []string{
		"/authsec/uflow/admin/ad/sync",
		"/authsec/uflow/admin/admin-users/ad/sync",
	} {
		w := env.Do("POST", p, map[string]interface{}{
			"workspace_id": a.WS.WorkspaceID.String(), "client_id": a.WS.ClientID.String(),
			"config_id": bCfg, "sync_type": "ad",
		}, tok)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not found") {
			t.Errorf("POST %s with B's config: got %d %s, want 400 not found", p, w.Code, w.Body.String())
		}
	}
	assertCount(t, before, "users", "workspace_id = ?", a.WS.WorkspaceID)

	// A configuration is created in the caller's workspace; the body no
	// longer needs (or decides) a workspace_id.
	w = env.Do("POST", "/authsec/uflow/admin/sync-configs/create", map[string]interface{}{
		"client_id": a.WS.ClientID.String(), "project_id": a.WS.WorkspaceID.String(),
		"sync_type": "active_directory", "config_name": "own-" + emailSafeNonce(),
		"ad_config": map[string]interface{}{"server": "ldap.invalid:389", "username": "svc", "password": "p", "base_dn": "DC=x"},
	}, tok)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 2, "sync_configurations", "workspace_id = ?", a.WS.WorkspaceID)
}

func Test_Isolation_SCIMAdmin(t *testing.T) {
	a, b, _, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	tok := a.AdminToken
	bAdmin := b.WS.AdminUserID.String()

	assertCrossTenant404(t, "GET", "/authsec/uflow/scim/v2/admin/Users/"+bAdmin, nil, tok)
	assertCrossTenant404(t, "PUT", "/authsec/uflow/scim/v2/admin/Users/"+bAdmin,
		map[string]interface{}{"userName": "taken", "emails": []map[string]interface{}{{"value": "x@y.test", "primary": true}}}, tok)
	assertCrossTenant404(t, "PATCH", "/authsec/uflow/scim/v2/admin/Users/"+bAdmin, map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{"op": "replace", "path": "active", "value": false}},
	}, tok)
	assertCrossTenant404(t, "DELETE", "/authsec/uflow/scim/v2/admin/Users/"+bAdmin, nil, tok)
	assertCount(t, 1, "users", "id = ? AND active = true AND email = ?", b.WS.AdminUserID, b.WS.AdminEmail)

	w := env.Do("GET", "/authsec/uflow/scim/v2/admin/Users", nil, tok)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), bAdmin) {
		t.Errorf("SCIM admin list leaked B's users")
	}
}

// SCIM provisioning authenticates a connection; its workspace is the
// connection's own, and another workspace's users and groups do not exist.
func Test_Isolation_SCIMProvisioning(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	base := "/authsec/uflow/scim/v2/c/" + da.SCIMConnID.String()
	tok := da.SCIMToken

	assertCrossTenant404(t, "GET", base+"/Users/"+b.EndUser.UserID.String(), nil, tok)
	assertCrossTenant404(t, "PATCH", base+"/Users/"+b.EndUser.UserID.String(), map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{"op": "replace", "path": "active", "value": false}},
	}, tok)
	assertCrossTenant404(t, "DELETE", base+"/Users/"+b.EndUser.UserID.String(), nil, tok)
	assertCrossTenant404(t, "GET", base+"/Groups/"+db.GroupID.String(), nil, tok)
	assertCrossTenant404(t, "DELETE", base+"/Groups/"+db.GroupID.String(), nil, tok)
	assertCount(t, 1, "users", "id = ? AND active = true", b.EndUser.UserID)
	assertCount(t, 1, "groups", "id = ?", db.GroupID)
	assertCount(t, 1, "user_groups", "group_id = ?", db.GroupID)

	// A's connection token does not open B's connection.
	w := env.Do("GET", "/authsec/uflow/scim/v2/c/"+db.SCIMConnID.String()+"/Users", nil, tok)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("A's SCIM token on B's connection: got %d, want 401", w.Code)
	}

	w = env.Do("GET", base+"/Groups", nil, tok)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), db.GroupID.String()) || !strings.Contains(w.Body.String(), da.GroupID.String()) {
		t.Errorf("SCIM group list must hold A's groups only: %s", w.Body.String())
	}
	_ = a
}

// The SCIM writes run on the scoped layer: membership rows are created and
// kept in step in the connection's workspace, and group membership only ever
// names users of that workspace.
func Test_SCIMProvisioning_ScopedWrites(t *testing.T) {
	a, b, da, db := twoTenantsWithData(t)
	env := testsupport.Get(t)
	base := "/authsec/uflow/scim/v2/c/" + da.SCIMConnID.String()
	tok := da.SCIMToken
	ws := a.WS.WorkspaceID
	mustExec(t, `INSERT INTO roles (id, workspace_id, name, description, created_at, updated_at)
	             VALUES ($1, $2, 'member', 'member', NOW(), NOW()) ON CONFLICT DO NOTHING`, uuid.New(), ws)

	email := "scim-" + emailSafeNonce() + "@a.test"
	w := env.Do("POST", base+"/Users", map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"emails":   []map[string]interface{}{{"value": email, "primary": true}},
		"active":   true,
	}, tok)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create SCIM user: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	uid := uuid.MustParse(created.ID)
	assertCount(t, 1, "workspace_memberships", "workspace_id = ? AND user_id = ? AND status = 'active' AND source = 'scim'", ws, uid)

	// A group created with A's new user and B's user holds A's user only.
	w = env.Do("POST", base+"/Groups", map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "g-" + emailSafeNonce(),
		"members":     []map[string]string{{"value": uid.String()}, {"value": b.EndUser.UserID.String()}},
	}, tok)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create SCIM group: %d %s", w.Code, w.Body.String())
	}
	var group struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &group)
	gid := uuid.MustParse(group.ID)
	assertCount(t, 1, "user_groups", "group_id = ?", gid)
	assertCount(t, 0, "user_groups", "group_id = ? AND user_id = ?", gid, b.EndUser.UserID)

	// PATCH add of B's user changes nothing; remove of A's user empties it.
	patch := func(op, path string, value interface{}) {
		t.Helper()
		w := env.Do("PATCH", base+"/Groups/"+gid.String(), map[string]interface{}{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]interface{}{{"op": op, "path": path, "value": value}},
		}, tok)
		if w.Code >= 300 {
			t.Fatalf("PATCH %s %s: %d %s", op, path, w.Code, w.Body.String())
		}
	}
	patch("add", "members", []map[string]string{{"value": b.EndUser.UserID.String()}})
	assertCount(t, 0, "user_groups", "group_id = ? AND user_id = ?", gid, b.EndUser.UserID)
	patch("remove", "members", []map[string]string{{"value": uid.String()}})
	assertCount(t, 0, "user_groups", "group_id = ?", gid)

	// Deactivating the user suspends its membership.
	w = env.Do("PATCH", base+"/Users/"+uid.String(), map[string]interface{}{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{"op": "replace", "path": "active", "value": false}},
	}, tok)
	if w.Code >= 300 {
		t.Fatalf("deactivate SCIM user: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "workspace_memberships", "workspace_id = ? AND user_id = ? AND status = 'suspended'", ws, uid)
	_ = db
}
