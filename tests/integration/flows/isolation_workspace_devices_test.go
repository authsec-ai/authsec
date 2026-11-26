//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

// Workspace-plane push devices, CIBA requests and TOTP devices
// (/authsec/uflow/auth/workspace/*) stay in the token's workspace
// (database/workspace_device_repository.go on tenancy.Transaction).
func Test_Isolation_WorkspaceDevicesAndTOTP(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)

	// A registers a push device; B neither lists nor deactivates it.
	w := env.Do("POST", "/authsec/uflow/auth/workspace/ciba/register-device", map[string]interface{}{
		"device_token": "ws-push-" + uuid.NewString(), "platform": "android",
	}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &dev); err != nil || dev.DeviceID == "" {
		t.Fatalf("register-device: %s", w.Body.String())
	}
	w = env.Do("GET", "/authsec/uflow/auth/workspace/ciba/devices", nil, b.EndUserToken)
	if strings.Contains(w.Body.String(), dev.DeviceID) {
		t.Errorf("B lists A's push device: %s", w.Body.String())
	}
	_ = env.Do("DELETE", "/authsec/uflow/auth/workspace/ciba/devices/"+dev.DeviceID, nil, b.EndUserToken)
	assertCount(t, 1, "workspace_device_tokens", "id = ? AND is_active AND workspace_id = ?", dev.DeviceID, a.WS.WorkspaceID)

	// A pending CIBA request of A's is invisible to B and cannot be answered by B.
	authReqID := "ws-areq-" + uuid.NewString()
	now := time.Now().Unix()
	if err := config.DB.Exec(`
		INSERT INTO workspace_ciba_auth_requests (id, auth_req_id, user_id, workspace_id, user_email, device_token_id, binding_message,
			status, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, '', 'pending', ?, ?)`,
		uuid.New(), authReqID, a.EndUser.UserID, a.WS.WorkspaceID, a.EndUser.Email, dev.DeviceID, now+300, now).Error; err != nil {
		t.Fatalf("seed workspace ciba request: %v", err)
	}
	w = env.Do("GET", "/authsec/uflow/auth/workspace/ciba/requests", nil, b.EndUserToken)
	if strings.Contains(w.Body.String(), authReqID) {
		t.Errorf("B lists A's CIBA request: %s", w.Body.String())
	}
	w = env.Do("POST", "/authsec/uflow/auth/workspace/ciba/respond", map[string]interface{}{
		"auth_req_id": authReqID, "approved": true,
	}, b.EndUserToken)
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), `"success":true`) {
		t.Errorf("B answered A's CIBA request: %s", w.Body.String())
	}
	assertCount(t, 1, "workspace_ciba_auth_requests", "auth_req_id = ? AND status = 'pending'", authReqID)
	w = env.Do("GET", "/authsec/uflow/auth/workspace/ciba/requests", nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), authReqID) {
		t.Errorf("A's request list misses its request: %s", w.Body.String())
	}

	// A registers and confirms a TOTP device; B cannot see, delete or promote it.
	w = env.Do("POST", "/authsec/uflow/auth/workspace/totp/register", map[string]string{"device_name": "A"}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	var reg struct {
		Secret   string `json:"secret"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.DeviceID == "" || reg.Secret == "" {
		t.Fatalf("workspace totp register: %s", w.Body.String())
	}
	code, err := totp.GenerateCode(reg.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	w = env.Do("POST", "/authsec/uflow/auth/workspace/totp/confirm", map[string]string{"device_id": reg.DeviceID, "totp_code": code}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)

	w = env.Do("GET", "/authsec/uflow/auth/workspace/totp/devices", nil, b.EndUserToken)
	if strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("B lists A's TOTP device: %s", w.Body.String())
	}
	_ = env.Do("POST", "/authsec/uflow/auth/workspace/totp/devices/delete", map[string]string{"device_id": reg.DeviceID}, b.EndUserToken)
	_ = env.Do("POST", "/authsec/uflow/auth/workspace/totp/devices/primary", map[string]string{"device_id": reg.DeviceID}, b.EndUserToken)
	assertCount(t, 1, "workspace_totp_secrets", "id = ? AND is_active AND workspace_id = ?", reg.DeviceID, a.WS.WorkspaceID)

	w = env.Do("GET", "/authsec/uflow/auth/workspace/totp/devices", nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("A's TOTP list misses its device: %s", w.Body.String())
	}
}
