//go:build integration

package flows

import (
	"testing"

	"github.com/authsec-ai/authsec/config"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// The one-transaction connector grant and revoke run on the scoped layer under
// row-level security: the client, the broker resource server and every row
// written belong to the connector's workspace, and the last revoke tears the
// registration and the role binding down again.
func Test_ConnectorGrant_ScopedToWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	n := emailSafeNonce()
	rsA, err := AddResourceServer(config.DB, a.WS, "https://broker-a-"+n+".example.com", "cga"+n)
	if err != nil {
		t.Fatalf("rs A: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, b.WS, "https://broker-b-"+n+".example.com", "cgb"+n)
	if err != nil {
		t.Fatalf("rs B: %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, a.WS, rsA, "cga"+n)
	if err != nil {
		t.Fatalf("sa A: %v", err)
	}
	saB, err := AddServiceAccountWithScopes(config.DB, b.WS, rsB, "cgb"+n)
	if err != nil {
		t.Fatalf("sa B: %v", err)
	}
	connA := uuid.New()
	mustExec(t, `INSERT INTO connectors (id, workspace_id, provider_key, name, created_by)
		VALUES (?, ?, 'github', ?, ?)`, connA, a.WS.WorkspaceID, "gh-"+n, a.WS.AdminUserID.String())
	permID, err := uuid.Parse(columnValue(t, "permissions", "id", "resource = 'connector' AND action = 'execute' AND workspace_id IS NULL"))
	if err != nil {
		t.Fatalf("connector:execute permission: %v", err)
	}
	// The scenario helpers already registered each SA on its own RS; start
	// from no registration on the broker so the grant's own row is observed.
	mustExec(t, `DELETE FROM resource_server_client_registrations WHERE resource_server_id = ?`, rsA.RSID)

	repo := repositories.NewConnectorRepository(config.DB)
	in := func(clientID string, broker uuid.UUID) repositories.GrantAssignmentInput {
		return repositories.GrantAssignmentInput{
			WorkspaceID: a.WS.WorkspaceID, ConnectorID: connA, ClientID: clientID, CreatedBy: "test",
			BrokerRSID: broker, ExecutePermID: permID, ExecuteRoleName: "connector-executor",
		}
	}

	// Another workspace's client cannot be granted, and nothing is left behind.
	if _, err := repo.GrantAssignmentTx(in(saB.ClientIDString, rsA.RSID)); err == nil {
		t.Fatal("grant to workspace B's client succeeded in workspace A")
	}
	assertCount(t, 0, "connector_assignments", "client_id = ?", saB.ClientIDString)
	assertCount(t, 0, "role_bindings", "service_account_id = ? AND scope_id = ?", saB.SAID, rsA.RSID)
	// Another workspace's resource server cannot be the broker.
	if _, err := repo.GrantAssignmentTx(in(saA.ClientIDString, rsB.RSID)); err == nil {
		t.Fatal("grant with workspace B's resource server as broker succeeded in workspace A")
	}
	assertCount(t, 0, "connector_assignments", "client_id = ?", saA.ClientIDString)
	assertCount(t, 0, "resource_server_client_registrations", "resource_server_id = ? AND oauth_client_id = ?", rsB.RSID, saA.ClientID)

	// The workspace's own client is granted: assignment, approved broker
	// registration, executor role with the execute permission, role binding.
	asg, err := repo.GrantAssignmentTx(in(saA.ClientIDString, rsA.RSID))
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	assertCount(t, 1, "connector_assignments", "id = ? AND workspace_id = ?", asg.ID, a.WS.WorkspaceID)
	assertCount(t, 1, "resource_server_client_registrations",
		"resource_server_id = ? AND oauth_client_id = ? AND status = 'approved' AND workspace_id = ?", rsA.RSID, saA.ClientID, a.WS.WorkspaceID)
	roleID := columnValue(t, "roles", "id", "workspace_id = ? AND name = 'connector-executor'", a.WS.WorkspaceID)
	if roleID == "" {
		t.Fatal("connector-executor role not created in workspace A")
	}
	assertCount(t, 1, "role_permissions", "role_id = ? AND permission_id = ?", roleID, permID)
	binding := "workspace_id = ? AND service_account_id = ? AND role_id = ? AND scope_type = 'resource_server' AND scope_id = ?"
	assertCount(t, 1, "role_bindings", binding, a.WS.WorkspaceID, saA.SAID, roleID, rsA.RSID)

	// A second (per-action) grant reuses the role and the binding.
	second := in(saA.ClientIDString, rsA.RSID)
	action := "listRepos"
	second.ActionKey = &action
	asg2, err := repo.GrantAssignmentTx(second)
	if err != nil {
		t.Fatalf("second grant: %v", err)
	}
	assertCount(t, 1, "roles", "workspace_id = ? AND name = 'connector-executor'", a.WS.WorkspaceID)
	assertCount(t, 1, "role_bindings", binding, a.WS.WorkspaceID, saA.SAID, roleID, rsA.RSID)

	// Workspace B cannot revoke A's assignment.
	if err := repo.RevokeAssignmentTx(b.WS.WorkspaceID, asg.ID, rsB.RSID); err != nil {
		t.Fatalf("revoke as B: %v", err)
	}
	assertCount(t, 1, "connector_assignments", "id = ?", asg.ID)

	// Revoking one of two keeps the wiring; revoking the last tears it down.
	if err := repo.RevokeAssignmentTx(a.WS.WorkspaceID, asg.ID, rsA.RSID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	assertCount(t, 0, "connector_assignments", "id = ?", asg.ID)
	assertCount(t, 1, "role_bindings", binding, a.WS.WorkspaceID, saA.SAID, roleID, rsA.RSID)
	if err := repo.RevokeAssignmentTx(a.WS.WorkspaceID, asg2.ID, rsA.RSID); err != nil {
		t.Fatalf("revoke last: %v", err)
	}
	assertCount(t, 0, "connector_assignments", "id = ?", asg2.ID)
	assertCount(t, 0, "resource_server_client_registrations", "resource_server_id = ? AND oauth_client_id = ?", rsA.RSID, saA.ClientID)
	assertCount(t, 0, "role_bindings", binding, a.WS.WorkspaceID, saA.SAID, roleID, rsA.RSID)
	// B's own wiring is untouched throughout.
	assertCount(t, 1, "resource_server_client_registrations", "resource_server_id = ? AND oauth_client_id = ?", rsB.RSID, saB.ClientID)
}
