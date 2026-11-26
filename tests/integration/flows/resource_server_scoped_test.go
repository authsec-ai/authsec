//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// The setup checklist's unmapped-tool count and an application's delete run
// in the caller's workspace, under RLS. Deleting an application used to
// delete every workspace's role bindings that named its id.
func Test_ResourceServer_ChecklistAndDelete_Scoped(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	n := emailSafeNonce()
	rs, err := AddResourceServer(config.DB, a.WS, "https://rsdel-"+n+".example.com", "rd"+n)
	if err != nil {
		t.Fatalf("rs: %v", err)
	}
	if len(rs.ScopeIDs) == 0 {
		t.Fatalf("resource server has no scope")
	}

	// Two manual tools; only the second is mapped to a scope by the admin.
	unmapped, mapped := uuid.New(), uuid.New()
	mustExec(t, `INSERT INTO mcp_tools (id, workspace_id, resource_server_id, name, inventory_source)
		VALUES ($1, $3, $4, $5, 'manual'), ($2, $3, $4, $6, 'manual')`,
		unmapped, mapped, a.WS.WorkspaceID, rs.RSID, "t1-"+n, "t2-"+n)
	mustExec(t, `INSERT INTO mcp_tool_scope_map (tool_id, scope_id, workspace_id, source) VALUES ($1, $2, $3, 'admin_override')`,
		mapped, rs.ScopeIDs[0], a.WS.WorkspaceID)

	w := env.Do("GET", "/authsec/applications/"+rs.RSID.String()+"/setup", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	steps, _ := decodeJSON(t, w)["steps"].([]interface{})
	var detail interface{}
	for _, s := range steps {
		if m, _ := s.(map[string]interface{}); m != nil && m["step"] == float64(4) {
			detail = m["detail"]
		}
	}
	if detail != "1 unmapped" {
		t.Fatalf("step 4 detail = %v, want \"1 unmapped\" (%s)", detail, w.Body.String())
	}

	// A's binding scoped to the application, and a row of B's that names
	// the same id.
	bindA, bindB := uuid.New(), uuid.New()
	mustExec(t, `INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id)
		VALUES ($1, $2, $3, $4, 'resource_server', $5)`, bindA, a.WS.WorkspaceID, a.WS.AdminUserID, a.WS.AdminRoleID, rs.RSID)
	mustExec(t, `INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id)
		VALUES ($1, $2, $3, $4, 'resource_server', $5)`, bindB, b.WS.WorkspaceID, b.WS.AdminUserID, b.WS.AdminRoleID, rs.RSID)

	// B's admin cannot delete A's application.
	w = env.Do("DELETE", "/authsec/applications/"+rs.RSID.String(), nil, b.AdminToken)
	assertStatus(t, w, http.StatusNotFound)
	AssertRowCount(t, "resource_servers", "id", rs.RSID, 1)

	w = env.Do("DELETE", "/authsec/applications/"+rs.RSID.String(), nil, a.AdminToken)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("delete own application: %d %s", w.Code, w.Body.String())
	}
	AssertRowCount(t, "resource_servers", "id", rs.RSID, 0)
	AssertRowCount(t, "role_bindings", "id", bindA, 0)
	AssertRowCount(t, "role_bindings", "id", bindB, 1)
}
