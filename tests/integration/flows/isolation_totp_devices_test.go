//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/pquerna/otp/totp"
)

// TOTP devices and backup codes stay in the workspace of the token that
// manages them (database/totp_repository.go on internal/tenancy).
func Test_Isolation_TOTPDevices(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)

	// A registers and confirms a device through the API (insert and update
	// under row-level security).
	w := env.Do("POST", "/authsec/uflow/auth/totp/register", map[string]string{"device_name": "A phone"}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	var reg struct {
		Secret      string   `json:"secret"`
		DeviceID    string   `json:"device_id"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.DeviceID == "" || reg.Secret == "" {
		t.Fatalf("register: %s", w.Body.String())
	}
	code, err := totp.GenerateCode(reg.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	// B cannot confirm, list, delete or promote A's device.
	w = env.Do("POST", "/authsec/uflow/auth/totp/confirm", map[string]string{"device_id": reg.DeviceID, "totp_code": code}, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B confirmed A's TOTP device: %s", w.Body.String())
	}
	assertCount(t, 1, "totp_secrets", "id = ? AND NOT is_active", reg.DeviceID)

	w = env.Do("POST", "/authsec/uflow/auth/totp/confirm", map[string]string{"device_id": reg.DeviceID, "totp_code": code}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "totp_secrets", "id = ? AND is_active AND is_primary AND workspace_id = ?", reg.DeviceID, a.WS.WorkspaceID)

	w = env.Do("GET", "/authsec/uflow/auth/totp/devices", nil, b.EndUserToken)
	if strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("B's device list shows A's device: %s", w.Body.String())
	}
	w = env.Do("POST", "/authsec/uflow/auth/totp/device/delete", map[string]string{"device_id": reg.DeviceID}, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B deleted A's TOTP device: %s", w.Body.String())
	}
	w = env.Do("POST", "/authsec/uflow/auth/totp/device/primary", map[string]string{"device_id": reg.DeviceID}, b.EndUserToken)
	assertCount(t, 1, "totp_secrets", "id = ? AND is_active AND is_primary AND user_id = ?", reg.DeviceID, a.EndUser.UserID)

	// B regenerating its own backup codes leaves A's alone.
	before := countWhere(t, "totp_backup_codes", "user_id = ?", a.EndUser.UserID)
	if before == 0 {
		t.Fatalf("A has no backup codes")
	}
	_ = env.Do("POST", "/authsec/uflow/auth/totp/backup/regenerate", nil, b.EndUserToken)
	assertCount(t, before, "totp_backup_codes", "user_id = ? AND workspace_id = ?", a.EndUser.UserID, a.WS.WorkspaceID)

	w = env.Do("GET", "/authsec/uflow/auth/totp/devices", nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("A's device list misses its device: %s", w.Body.String())
	}
}
