//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// ADR-0001 §8: a user lists only the workspaces they belong to and switching
// mints a token for exactly the chosen one, after a membership check.
func Test_WorkspaceListAndSwitch(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	_, c := TwoTenants(t) // a third workspace A's admin has nothing to do with

	list := func(tok string) []map[string]interface{} {
		w := env.Do("GET", "/authsec/workspaces", nil, tok)
		assertStatus(t, w, http.StatusOK)
		var resp struct {
			Workspaces []map[string]interface{} `json:"workspaces"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp.Workspaces
	}

	if got := list(a.AdminToken); len(got) != 1 || got[0]["workspace_id"] != a.WS.WorkspaceID.String() || got[0]["current"] != true {
		t.Fatalf("before membership: want only A (current), got %v", got)
	}

	// A's admin becomes an operator in B.
	mustExec(t, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
		VALUES (gen_random_uuid(), ?, ?, ?, 'active', 'invite', now(), now())`, b.WS.WorkspaceID, a.WS.AdminUserID, b.WS.AdminRoleID)

	got := list(a.AdminToken)
	ids := map[string]bool{}
	for _, w := range got {
		ids[w["workspace_id"].(string)] = true
	}
	if len(got) != 2 || !ids[a.WS.WorkspaceID.String()] || !ids[b.WS.WorkspaceID.String()] || ids[c.WS.WorkspaceID.String()] {
		t.Fatalf("want exactly A and B, got %v", got)
	}

	w := env.Do("POST", "/authsec/workspaces/"+b.WS.WorkspaceID.String()+"/switch", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	var sw struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &sw)
	if sw.AccessToken == "" {
		t.Fatalf("switch returned no token: %s", w.Body.String())
	}
	// The new token works in B and names B; it cannot be pointed back at A.
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/users/list", nil, sw.AccessToken), http.StatusOK)
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/groups/"+a.WS.WorkspaceID.String(), nil, sw.AccessToken), http.StatusNotFound)

	// Switching into a workspace without membership is refused.
	if w := env.Do("POST", "/authsec/workspaces/"+c.WS.WorkspaceID.String()+"/switch", nil, a.AdminToken); w.Code == http.StatusOK {
		t.Fatalf("switch into a non-member workspace must fail")
	}

	// Suspension removes B from the list and ends the B session.
	config.DB.Exec(`UPDATE workspace_memberships SET status = 'suspended' WHERE workspace_id = ? AND user_id = ?`, b.WS.WorkspaceID, a.WS.AdminUserID)
	if got := list(a.AdminToken); len(got) != 1 {
		t.Fatalf("suspended membership still listed: %v", got)
	}
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/users/list", nil, sw.AccessToken), http.StatusUnauthorized)
}
