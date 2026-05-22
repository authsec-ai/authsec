package unit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/authsec-ai/authsec/config"
	adminCtrl "github.com/authsec-ai/authsec/controllers/admin"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Interface contract (no DB required) ──────────────────────────────────────

func TestMTPluginClientIface_MockIsAvailableTrue(t *testing.T) {
	assert.True(t, (&pluginMock{available: true}).IsAvailable())
}

func TestMTPluginClientIface_MockIsAvailableFalse(t *testing.T) {
	assert.False(t, (&pluginMock{available: false}).IsAvailable())
}

// ── Integration: single-tenant 409 guard (require RUN_INTEGRATION=1) ─────────
//
// These tests exercise the full AdminRegister HTTP handler and verify that
// the guard blocks or allows second-admin registration based on plugin state.

type adminRegisterPayload struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	Name         string `json:"name"`
	TenantDomain string `json:"tenant_domain"`
}

// newRegisterRouter mounts AdminRegister on a throw-away gin engine.
// Returns nil when the controller cannot be initialised (no DB/Redis in CI).
func newRegisterRouter(t *testing.T) *gin.Engine {
	t.Helper()
	ctrl, err := adminCtrl.NewAdminAuthController()
	if err != nil {
		t.Logf("AdminAuthController not available: %v", err)
		return nil
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/register", ctrl.AdminRegister)
	return r
}

func doRegister(t *testing.T, r *gin.Engine, p adminRegisterPayload) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(p)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// seedActivetenant inserts a tenant record with active=true so the guard fires.
func seedActiveGuardTenant(t *testing.T, domain string) {
	t.Helper()
	db := config.GetDatabase()
	require.NotNil(t, db, "database must be initialised")
	_, _ = db.Exec(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS active boolean DEFAULT true`)
	_, _ = db.Exec(`UPDATE tenants SET active = true`)
	_, err := db.Exec(
		`INSERT INTO tenants (tenant_id, email, tenant_domain, active)
		 VALUES (gen_random_uuid(), $1, $2, true) ON CONFLICT DO NOTHING`,
		fmt.Sprintf("guard@%s", domain), domain,
	)
	require.NoError(t, err)
}

func TestSingleTenantGuard_NilPlugin_ExistingTenant_Returns409(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION") != "1" {
		t.Skip("set RUN_INTEGRATION=1 to run integration tests")
	}

	swapPlugin(t, nil)
	r := newRegisterRouter(t)
	if r == nil {
		t.Skip("AdminAuthController unavailable")
	}

	seedActiveGuardTenant(t, "guard-blocked.local")

	w := doRegister(t, r, adminRegisterPayload{
		Email:        "second@example.com",
		Password:     "supersecret123",
		Name:         "Second Admin",
		TenantDomain: "guard-unique-domain",
	})

	assert.Equal(t, http.StatusConflict, w.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	errMsg, _ := body["error"].(string)
	assert.Contains(t, errMsg, "Single-tenant mode")
}

func TestSingleTenantGuard_PluginAvailable_ExistingTenant_GuardBypassed(t *testing.T) {
	if os.Getenv("RUN_INTEGRATION") != "1" {
		t.Skip("set RUN_INTEGRATION=1 to run integration tests")
	}

	swapPlugin(t, &pluginMock{available: true})
	r := newRegisterRouter(t)
	if r == nil {
		t.Skip("AdminAuthController unavailable")
	}

	seedActiveGuardTenant(t, "guard-plugin.local")

	w := doRegister(t, r, adminRegisterPayload{
		Email:        "third@example.com",
		Password:     "supersecret789",
		Name:         "Third Admin",
		TenantDomain: "guard-plugin-unique",
	})

	// Must NOT be a 409 from the single-tenant guard.
	if w.Code == http.StatusConflict {
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		errMsg, _ := body["error"].(string)
		assert.NotContains(t, errMsg, "Single-tenant mode",
			"guard must not fire when plugin is available; got: %s", errMsg)
	}
}
