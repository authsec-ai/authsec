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

// Editing an Entra configuration without retyping the secret keeps the stored
// secret; the update used to require it (400), and the console then sent the
// AuthSec workspace id as the directory tenant id.
func Test_SyncConfig_EntraUpdateKeepsSecret(t *testing.T) {
	a, _ := TwoTenants(t)
	env := testsupport.Get(t)
	ws := a.WS
	name := "entra-" + emailSafeNonce()
	w := env.Do("POST", "/authsec/uflow/admin/sync-configs/create", map[string]interface{}{
		"client_id": ws.ClientID.String(), "project_id": ws.WorkspaceID.String(),
		"sync_type": "entra_id", "config_name": name,
		"entra_config": map[string]interface{}{"workspace_id": "contoso.onmicrosoft.com", "client_id": "app-1", "client_secret": "s3cret"},
	}, a.AdminToken)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := columnValue(t, "sync_configurations", "id", "workspace_id = ? AND config_name = ?", ws.WorkspaceID, name)
	secret := columnValue(t, "sync_configurations", "entra_client_secret", "id = ?", id)

	w = env.Do("POST", "/authsec/uflow/admin/sync-configs/update", map[string]interface{}{
		"id": id, "client_id": ws.ClientID.String(),
		"entra_config": map[string]interface{}{"workspace_id": "fabrikam.onmicrosoft.com", "client_id": "app-1"},
	}, a.AdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("update without secret: %d %s", w.Code, w.Body.String())
	}
	if got := columnValue(t, "sync_configurations", "entra_tenant_id", "id = ?", id); got != "fabrikam.onmicrosoft.com" {
		t.Errorf("tenant id: %q", got)
	}
	if got := columnValue(t, "sync_configurations", "entra_client_secret", "id = ?", id); got != secret {
		t.Errorf("stored secret changed on an update that did not send one")
	}

	w = env.Do("POST", "/authsec/uflow/admin/sync-configs/create", map[string]interface{}{
		"client_id": ws.ClientID.String(), "project_id": ws.WorkspaceID.String(),
		"sync_type": "entra_id", "config_name": name + "-2",
		"entra_config": map[string]interface{}{"workspace_id": "contoso.onmicrosoft.com", "client_id": "app-1"},
	}, a.AdminToken)
	if w.Code != http.StatusBadRequest {
		t.Errorf("create without secret: %d %s, want 400", w.Code, w.Body.String())
	}
}
