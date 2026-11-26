//go:build integration

package flows

import (
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Cross-tenant isolation for the AWS auto-scan schedule routes
// (GET/PUT /authsec/discovery/aws/connectors/:id/schedule): workspace A's
// admin can neither read nor change workspace B's schedule, which is left as
// it was. B reading its own schedule is the positive control.
func Test_Isolation_AWSScanSchedule(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	// The AWS routes refuse to run without Vault settings; the schedule
	// routes never contact it, so an address nothing listens on is enough.
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "not-used")
	for _, tn := range []*Tenant{a, b} {
		if err := config.DB.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE workspace_id IS NULL
			ON CONFLICT DO NOTHING`, tn.WS.AdminRoleID).Error; err != nil {
			t.Fatalf("grant permissions: %v", err)
		}
	}
	conn := uuid.New()
	if err := config.DB.Exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
		VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault://aws/test')`, conn, b.WS.WorkspaceID, "123456789012").Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	if err := config.DB.Exec(`INSERT INTO cloud_scan_schedule (connector_id, workspace_id, enabled, interval_minutes, created_at, updated_at)
		VALUES (?, ?, true, 1440, now(), now())`, conn, b.WS.WorkspaceID).Error; err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	path := "/authsec/discovery/aws/connectors/" + conn.String() + "/schedule"

	if w := env.Do("GET", path, nil, b.AdminToken); w.Code != 200 {
		t.Fatalf("B reading its own schedule: %d %s", w.Code, w.Body.String())
	}
	assertCrossTenant404(t, "GET", path, nil, a.AdminToken)
	assertCrossTenant404(t, "PUT", path, map[string]any{"enabled": false, "interval_minutes": 10080}, a.AdminToken)

	var enabled bool
	var interval int
	if err := config.DB.Raw(`SELECT enabled, interval_minutes FROM cloud_scan_schedule WHERE connector_id = ?`, conn).
		Row().Scan(&enabled, &interval); err != nil || !enabled || interval != 1440 {
		t.Fatalf("B's schedule after A's PUT: enabled=%v interval=%d %v", enabled, interval, err)
	}
}
