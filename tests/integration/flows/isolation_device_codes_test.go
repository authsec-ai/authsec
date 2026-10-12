//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// seedPendingDeviceCode stores a pending RFC 8628 code bound to ws.
func seedPendingDeviceCode(t *testing.T, ws, clientID uuid.UUID) (deviceCode, userCode string) {
	t.Helper()
	deviceCode = "dc-" + uuid.NewString()
	userCode = strings.ToUpper(uuid.NewString()[:4] + "-" + uuid.NewString()[:4])
	if err := config.DB.Exec(`
		INSERT INTO device_codes (id, workspace_id, client_id, device_code, user_code, verification_uri,
			status, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, 'https://verify.test', 'pending', '[]', ?)`,
		uuid.New(), ws, clientID, deviceCode, userCode, time.Now().Add(10*time.Minute).Unix()).Error; err != nil {
		t.Fatalf("seed device code: %v", err)
	}
	return deviceCode, userCode
}

// Pending device codes are listed only to their own workspace
// (database/device_auth_repository.go ListPendingDeviceCodes on the scoped
// layer), and a code bound to A cannot be completed by B's user.
func Test_Isolation_DeviceCodes(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	clientID := uuid.New()
	deviceCode, userCode := seedPendingDeviceCode(t, a.WS.WorkspaceID, clientID)

	path := "/authsec/uflow/auth/voice/device-pending?client_id=" + clientID.String()
	w := env.Do("GET", path, nil, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), userCode) {
		t.Errorf("A's pending list misses its code: %s", w.Body.String())
	}
	w = env.Do("GET", path, nil, b.EndUserToken)
	if strings.Contains(w.Body.String(), userCode) {
		t.Errorf("B's pending list shows A's code: %d %s", w.Code, w.Body.String())
	}

	w = env.Do("POST", "/authsec/uflow/auth/device/authorize", map[string]interface{}{
		"user_code": userCode, "approved": true,
	}, b.EndUserToken)
	if w.Code == http.StatusOK {
		t.Errorf("B authorized A's device code: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "device_codes", "device_code = ? AND status = 'pending' AND workspace_id = ? AND access_token IS NULL",
		deviceCode, a.WS.WorkspaceID)
}
