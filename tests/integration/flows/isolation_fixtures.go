//go:build integration

package flows

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// TenantData is the users/identity data the isolation tests seed in a
// workspace on top of TwoTenants: a group with the end user in it, a role
// binding, a resource server, a sync configuration, an end-user state, a
// pending admin invite and a SCIM connection.
type TenantData struct {
	GroupID      uuid.UUID
	GroupName    string
	BindingID    uuid.UUID
	RS           *RSScenario
	SyncConfigID uuid.UUID
	InviteeID    uuid.UUID
	InviteeEmail string
	SCIMConnID   uuid.UUID
	SCIMToken    string
}

// seedTenantData seeds tn with the rows above and grants its admin role the
// global permission catalog, as EnsureAdminRoleAndPermissions does when a
// real workspace is created (the plain seed binds a role with no
// permissions).
func seedTenantData(t *testing.T, tn *Tenant) *TenantData {
	t.Helper()
	db := config.DB
	ws := tn.WS
	n := emailSafeNonce()
	d := &TenantData{
		GroupID:      uuid.New(),
		GroupName:    "group-" + n,
		BindingID:    uuid.New(),
		SyncConfigID: uuid.New(),
		InviteeID:    uuid.New(),
		InviteeEmail: "invitee-" + n + "@" + ws.WorkspaceDomain,
		SCIMConnID:   uuid.New(),
		SCIMToken:    "scim-" + n,
	}
	exec := func(what, q string, args ...interface{}) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("seed %s: %v", what, err)
		}
	}

	exec("admin permissions", `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id IS NULL
		ON CONFLICT DO NOTHING`, ws.AdminRoleID)

	exec("group", `INSERT INTO groups (id, name, workspace_id) VALUES (?, ?, ?)`,
		d.GroupID, d.GroupName, ws.WorkspaceID)
	exec("group member", `INSERT INTO user_groups (workspace_id, user_id, group_id) VALUES (?, ?, ?)`,
		ws.WorkspaceID, tn.EndUser.UserID, d.GroupID)
	exec("role binding", `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())`,
		d.BindingID, ws.WorkspaceID, tn.EndUser.UserID, ws.AdminRoleID)

	rs, err := AddResourceServer(db, ws, "https://rs-"+n+".test.local", n)
	if err != nil {
		t.Fatalf("seed resource server: %v", err)
	}
	d.RS = rs

	exec("sync config", `
		INSERT INTO sync_configurations (id, workspace_id, client_id, sync_type, config_name, is_active,
			ad_server, ad_username, ad_password, ad_base_dn, created_at, updated_at)
		VALUES (?, ?, ?, 'active_directory', ?, true, 'ldap.invalid:389', 'svc', 'not-a-secret', 'DC=x', NOW(), NOW())`,
		d.SyncConfigID, ws.WorkspaceID, ws.ClientID, "sync-"+n)

	exec("end-user state", `
		INSERT INTO workspace_end_user_states (workspace_id, user_id, status) VALUES (?, ?, 'active')`,
		ws.WorkspaceID, tn.EndUser.UserID)

	exec("invitee", `
		INSERT INTO users (id, workspace_id, email, username, password_hash, workspace_domain, provider, active,
			temporary_password, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'invite-hash', ?, 'local', true, true, NOW(), NOW())`,
		d.InviteeID, ws.WorkspaceID, d.InviteeEmail, "invitee-"+n, ws.WorkspaceDomain)
	exec("invitee binding", `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())`,
		uuid.New(), ws.WorkspaceID, d.InviteeID, ws.AdminRoleID)
	exec("invitee membership", `
		INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'active', 'invite', NOW(), NOW())`,
		uuid.New(), ws.WorkspaceID, d.InviteeID, ws.AdminRoleID)

	sum := sha256.Sum256([]byte(d.SCIMToken))
	exec("scim connection", `
		INSERT INTO scim_connections (id, workspace_id, token_hash, status, default_client_id, default_project_id)
		VALUES (?, ?, ?, 'active', ?, ?)`,
		d.SCIMConnID, ws.WorkspaceID, hex.EncodeToString(sum[:]), ws.ClientID, ws.WorkspaceID)
	return d
}

// twoTenantsWithData seeds A and B with TenantData.
func twoTenantsWithData(t *testing.T) (a, b *Tenant, da, db *TenantData) {
	t.Helper()
	a, b = TwoTenants(t)
	return a, b, seedTenantData(t, a), seedTenantData(t, b)
}

// assertCrossTenant404 is the strict form of AssertCrossTenantNotFound for
// handlers that look the row up: another workspace's row is answered exactly
// as a missing one, 404 (ADR-0001 §4.3).
func assertCrossTenant404(t *testing.T, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	w := testsupport.Get(t).Do(method, path, body, token)
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant %s %s: got %d, want 404 (body: %s)", method, path, w.Code, w.Body.String())
	}
	return w
}

// countWhere counts rows of table matching a condition.
func countWhere(t *testing.T, table, where string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := config.DB.Table(table).Where(where, args...).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// assertCount fails unless exactly want rows of table match where.
func assertCount(t *testing.T, want int64, table, where string, args ...interface{}) {
	t.Helper()
	if got := countWhere(t, table, where, args...); got != want {
		t.Errorf("%s where %s %v: %d rows, want %d", table, where, args, got, want)
	}
}

// columnValue reads one column of one row.
func columnValue(t *testing.T, table, column, where string, args ...interface{}) string {
	t.Helper()
	var v *string
	if err := config.DB.Table(table).Select(column+"::text").Where(where, args...).Scan(&v).Error; err != nil {
		t.Fatalf("read %s.%s: %v", table, column, err)
	}
	if v == nil {
		return ""
	}
	return *v
}
