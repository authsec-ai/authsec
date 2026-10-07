//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-061: approving a connection with a role grant only accepts one of the
// application's own roles ("rs-<id>:" prefix) and a subject that belongs to
// the workspace.
func Test_ConnectionApproval_RoleAndSubjectValidated(t *testing.T) {
	env := testsupport.Get(t)
	a, b, da, _ := twoTenantsWithData(t)
	n := emailSafeNonce()

	sa, err := AddServiceAccountWithScopes(config.DB, a.WS, da.RS, "ca-"+n)
	if err != nil {
		t.Fatalf("service account: %v", err)
	}
	config.DB.Exec(`UPDATE resource_server_client_registrations SET status = 'pending_approval'
		WHERE resource_server_id = ? AND oauth_client_id = ?`, da.RS.RSID, sa.ClientID)

	rsRole, plainRole := uuid.New(), uuid.New()
	for id, name := range map[uuid.UUID]string{
		rsRole:    "rs-" + da.RS.RSID.String() + ":viewer-" + n,
		plainRole: "workspace-wide-" + n,
	} {
		if err := config.DB.Exec(`INSERT INTO roles (id, workspace_id, name, created_at, updated_at)
			VALUES (?, ?, ?, NOW(), NOW())`, id, a.WS.WorkspaceID, name).Error; err != nil {
			t.Fatalf("role: %v", err)
		}
	}

	path := "/authsec/applications/" + da.RS.RSID.String() + "/connections/" + sa.ClientIDString + "/approve"
	approve := func(role, subject uuid.UUID) int {
		w := env.Do(http.MethodPut, path, map[string]interface{}{
			"role_id": role.String(), "subject_type": "user", "subject_id": subject.String(), "duration": "1h",
		}, a.AdminToken)
		return w.Code
	}

	if code := approve(plainRole, a.EndUser.UserID); code != http.StatusBadRequest {
		t.Errorf("role without the application's prefix: got %d, want 400", code)
	}
	if code := approve(rsRole, b.EndUser.UserID); code != http.StatusBadRequest {
		t.Errorf("subject from another workspace: got %d, want 400", code)
	}
	assertCount(t, 0, "role_bindings", "role_id IN ?", []uuid.UUID{rsRole, plainRole})
	if got := columnValue(t, "resource_server_client_registrations", "status",
		"resource_server_id = ? AND oauth_client_id = ?", da.RS.RSID, sa.ClientID); got != "pending_approval" {
		t.Errorf("a refused grant changed the registration to %q", got)
	}

	if code := approve(rsRole, a.EndUser.UserID); code != http.StatusOK {
		t.Fatalf("valid approval: got %d", code)
	}
	assertCount(t, 1, "role_bindings", "role_id = ? AND user_id = ?", rsRole, a.EndUser.UserID)
}
