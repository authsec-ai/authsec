//go:build integration

package flows

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Tenant is one fully seeded workspace for isolation tests: an owner/admin,
// an end user, and tokens for both.
type Tenant struct {
	WS           *WorkspaceScenario
	EndUser      *EndUserScenario
	AdminToken   string
	EndUserToken string
}

// TwoTenants seeds workspaces A and B with the same shape, so a test can act
// as A against B's data and assert that nothing crosses (ADR-0001 §4).
func TwoTenants(t *testing.T) (a, b *Tenant) {
	t.Helper()
	env := testsupport.Get(t)
	mk := func(suffix string) *Tenant {
		n := emailSafeNonce() + suffix
		ws, err := SeedWorkspaceWithAdmin(config.DB, n)
		if err != nil {
			t.Fatalf("seed workspace %s: %v", suffix, err)
		}
		u, err := AddEndUserWithRole(config.DB, ws, n)
		if err != nil {
			t.Fatalf("seed end user %s: %v", suffix, err)
		}
		return &Tenant{
			WS:           ws,
			EndUser:      u,
			AdminToken:   env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail),
			EndUserToken: env.MustAsUser(u.UserID, ws.WorkspaceID, u.Email),
		}
	}
	return mk("a"), mk("b")
}

// AssertCrossTenantNotFound asserts that a request made with one tenant's
// token against another tenant's resource is answered as if the resource did
// not exist. 403 is accepted only where a route refuses before lookup; 2xx
// and 5xx always fail.
func AssertCrossTenantNotFound(t *testing.T, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	w := testsupport.Get(t).Do(method, path, body, token)
	switch w.Code {
	case http.StatusNotFound, http.StatusForbidden:
	default:
		t.Errorf("cross-tenant %s %s: got %d, want 404 (body: %s)", method, path, w.Code, w.Body.String())
	}
	return w
}

// AssertRowCount fails unless exactly want rows of table match column=value.
// Use it after a cross-tenant write attempt to prove nothing was written.
func AssertRowCount(t *testing.T, table, column string, value interface{}, want int64) {
	t.Helper()
	var got int64
	if err := config.DB.Table(table).Where(column+" = ?", value).Count(&got).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Errorf("%s where %s=%v: %d rows, want %d", table, column, value, got, want)
	}
}
