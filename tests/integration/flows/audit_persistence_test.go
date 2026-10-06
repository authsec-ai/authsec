//go:build integration

package flows

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-049: an audited admin action lands in audit_events for its workspace,
// and audit rows cannot be rewritten.
func Test_AdminAction_PersistedToAuditLog(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	ws := a.WS.WorkspaceID.String()

	w := env.Do("POST", "/authsec/uflow/admin/groups", map[string]interface{}{
		"workspace_id": ws, "groups": []string{"audited-" + emailSafeNonce()},
	}, a.AdminToken)
	if w.Code >= 300 {
		t.Fatalf("create group: %d %s", w.Code, w.Body.String())
	}

	var n int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		config.DB.Raw(`SELECT COUNT(*) FROM audit_events WHERE workspace_id = ? AND resource = 'group' AND action = 'create'`, ws).Scan(&n)
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n == 0 {
		t.Fatalf("group creation was not recorded in audit_events for workspace %s", ws)
	}

	res := config.DB.Exec(`UPDATE audit_events SET action = 'tampered' WHERE workspace_id = ?`, ws)
	if res.Error == nil {
		t.Fatalf("updating an audit row must fail")
	}
}
