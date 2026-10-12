//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Intern report (Directory Sync): an AD configuration saved with LDAPS off
// was stored with ad_use_ssl = true (GORM omitted the false value in favour
// of the column default), and skipping certificate verification was accepted
// anywhere. A duplicate name answered 500 with the raw database error.
func Test_SyncConfig_TLSSettings(t *testing.T) {
	a, _ := TwoTenants(t)
	env := testsupport.Get(t)
	ws := a.WS
	create := func(name string, useSSL, skipVerify bool) (int, string) {
		w := env.Do("POST", "/authsec/uflow/admin/sync-configs/create", map[string]interface{}{
			"client_id":   ws.ClientID.String(),
			"project_id":  ws.WorkspaceID.String(),
			"sync_type":   "active_directory",
			"config_name": name,
			"ad_config": map[string]interface{}{
				"server": "dc.example.test:389", "username": "svc", "password": "pw",
				"base_dn": "DC=example,DC=test", "use_ssl": useSSL, "skip_verify": skipVerify,
			},
		}, a.AdminToken)
		return w.Code, w.Body.String()
	}

	name := "plain-" + emailSafeNonce()
	if code, body := create(name, false, false); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("create: %d %s", code, body)
	}
	if got := columnValue(t, "sync_configurations", "ad_use_ssl", "workspace_id = ? AND config_name = ?", ws.WorkspaceID, name); got != "false" {
		t.Errorf("use_ssl=false stored as ad_use_ssl=%s", got)
	}

	if code, body := create(name, false, false); code != http.StatusConflict {
		t.Errorf("duplicate name: %d %s, want 409", code, body)
	}

	t.Setenv("ENVIRONMENT", "production")
	if code, body := create("skip-"+emailSafeNonce(), true, true); code != http.StatusBadRequest {
		t.Errorf("skip_verify in production: %d %s, want 400", code, body)
	}
	t.Setenv("DIRECTORY_SYNC_ALLOW_SKIP_VERIFY", "true")
	if code, body := create("skip-"+emailSafeNonce(), true, true); code != http.StatusCreated && code != http.StatusOK {
		t.Errorf("skip_verify with the operator opt-out: %d %s", code, body)
	}
}
