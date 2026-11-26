//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// A user homed in B who also holds a membership in A (an operator) cannot be
// hard-deleted from B: the delete's ON DELETE CASCADE / SET NULL keys would
// change A's rows (its owners, Slack links, policy owners) and leave A's
// membership dangling. The 409 does not name A or its tables.
func Test_UserDelete_RefusedWhileAnotherWorkspaceRefersToTheUser(t *testing.T) {
	a, b, _, _ := twoTenantsWithData(t)
	env := testsupport.Get(t)
	db := config.DB

	op := uuid.New()
	n := emailSafeNonce()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO users (id, workspace_id, email, username, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'x', ?, 'local', true, NOW(), NOW())`,
		op, b.WS.WorkspaceID, "op-"+n+"@"+b.WS.WorkspaceDomain, "op-"+n, b.WS.WorkspaceDomain)
	member := func(ws, role uuid.UUID) {
		exec(`INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
			VALUES (gen_random_uuid(), ?, ?, ?, 'active', 'api', NOW(), NOW())`, ws, op, role)
	}
	member(b.WS.WorkspaceID, b.WS.AdminRoleID) // an admin of B
	exec(`INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES (gen_random_uuid(), ?, ?, ?, NOW(), NOW())`, b.WS.WorkspaceID, op, b.WS.AdminRoleID)
	member(a.WS.WorkspaceID, a.WS.AdminRoleID) // and of A

	w := env.Do("DELETE", "/authsec/uflow/admin/users/delete_all/"+op.String(), nil, b.AdminToken)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusConflict || body["code"] != database.UserInAnotherWorkspaceCode || body["detail"] != nil {
		t.Fatalf("delete B's user that A refers to: %d %s, want 409 %s without detail", w.Code, w.Body.String(), database.UserInAnotherWorkspaceCode)
	}
	assertCount(t, 1, "users", "id = ?", op)
	assertCount(t, 1, "workspace_memberships", "workspace_id = ? AND user_id = ?", a.WS.WorkspaceID, op)

	// Once A no longer refers to the user, B can delete it.
	exec(`DELETE FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, a.WS.WorkspaceID, op)
	if w := env.Do("DELETE", "/authsec/uflow/admin/users/delete_all/"+op.String(), nil, b.AdminToken); w.Code != http.StatusOK {
		t.Fatalf("delete after A let go: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 0, "users", "id = ?", op)
}
