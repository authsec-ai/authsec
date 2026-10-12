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
)

// Cross-tenant isolation for the legacy CIBA plane (/authsec/uflow/auth/ciba):
// push devices and auth requests stay in the workspace of the token that
// created them (database/ciba_auth_repository.go on internal/tenancy).
func Test_Isolation_LegacyCIBADevices(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	pushToken := "ExponentPushToken[" + uuid.NewString() + "]"

	// A registers a push device.
	w := env.Do("POST", "/authsec/uflow/auth/ciba/register-device", map[string]interface{}{
		"device_token": pushToken, "platform": "ios", "device_name": "A phone",
	}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	var reg struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.DeviceID == "" {
		t.Fatalf("register-device: no device_id in %s", w.Body.String())
	}

	// Re-registering in the same workspace keeps the row and its id.
	w = env.Do("POST", "/authsec/uflow/auth/ciba/register-device", map[string]interface{}{
		"device_token": pushToken, "platform": "ios", "device_name": "A phone again",
	}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("re-register in the same workspace returned another id: %s", w.Body.String())
	}

	// B registering the same push token must not move A's row into B.
	w = env.Do("POST", "/authsec/uflow/auth/ciba/register-device", map[string]interface{}{
		"device_token": pushToken, "platform": "ios", "device_name": "B phone",
	}, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B re-registered A's push token: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "device_tokens", "device_token = ? AND workspace_id = ? AND user_id = ? AND is_active",
		pushToken, a.WS.WorkspaceID, a.EndUser.UserID)
	assertCount(t, 0, "device_tokens", "device_token = ? AND workspace_id = ?", pushToken, b.WS.WorkspaceID)

	// B neither lists nor deletes A's device.
	w = env.Do("GET", "/authsec/uflow/auth/ciba/devices", nil, b.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("B's device list shows A's device: %s", w.Body.String())
	}
	w = env.Do("DELETE", "/authsec/uflow/auth/ciba/devices/"+reg.DeviceID, nil, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B deleted A's device: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "device_tokens", "id = ? AND is_active", reg.DeviceID)

	// A still sees and can delete its own device.
	w = env.Do("GET", "/authsec/uflow/auth/ciba/devices", nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), reg.DeviceID) {
		t.Errorf("A's device list misses its device: %s", w.Body.String())
	}
	w = env.Do("DELETE", "/authsec/uflow/auth/ciba/devices/"+reg.DeviceID, nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "device_tokens", "id = ? AND NOT is_active", reg.DeviceID)
}

// B's user cannot answer a legacy CIBA request of A's, and the request stays
// pending.
func Test_Isolation_LegacyCIBARespond(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	deviceID := uuid.New()
	authReqID := "areq-" + uuid.NewString()
	now := time.Now().Unix()
	if err := config.DB.Exec(`
		INSERT INTO device_tokens (id, user_id, workspace_id, device_token, platform, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'ios', true, ?, ?)`,
		deviceID, a.EndUser.UserID, a.WS.WorkspaceID, "tok-"+uuid.NewString(), now, now).Error; err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := config.DB.Exec(`
		INSERT INTO ciba_auth_requests (id, auth_req_id, user_id, workspace_id, user_email, device_token_id, binding_message,
			status, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, '', 'pending', ?, ?)`,
		uuid.New(), authReqID, a.EndUser.UserID, a.WS.WorkspaceID, a.EndUser.Email, deviceID,
		now+300, now).Error; err != nil {
		t.Fatalf("seed ciba request: %v", err)
	}

	w := env.Do("POST", "/authsec/uflow/auth/ciba/respond", map[string]interface{}{
		"auth_req_id": authReqID, "approved": true,
	}, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B approved A's CIBA request: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "ciba_auth_requests", "auth_req_id = ? AND status = 'pending'", authReqID)

	w = env.Do("POST", "/authsec/uflow/auth/ciba/respond", map[string]interface{}{
		"auth_req_id": authReqID, "approved": false,
	}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	assertCount(t, 1, "ciba_auth_requests", "auth_req_id = ? AND status = 'denied'", authReqID)
}
