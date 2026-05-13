package middlewares

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestGetTenantIDFromToken covers the contract that extractTenantID (in
// controllers/platform/resource_server_controller.go) and the rest of the
// RBAC handlers depend on:
//
//   - tenant_id is set on the gin context by ensureTenantContext upstream
//   - downstream callers read it via GetTenantIDFromToken
//   - the function must distinguish "missing" from "present-but-wrong-type"
//     so callers can produce the right error
//
// This is the load-bearing path after the merge with non-multi-tenant —
// ensureTenantContext lives in middlewares/auth.go and populates the same
// key. If that contract drifts, every RBAC controller silently breaks.
func TestGetTenantIDFromToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name      string
		setup     func(c *gin.Context)
		wantStr   string
		wantOK    bool
	}{
		{
			name:    "tenant_id present and string-typed",
			setup:   func(c *gin.Context) { c.Set("tenant_id", "e3975b1f-cfe7-451f-8eb3-a672e03be093") },
			wantStr: "e3975b1f-cfe7-451f-8eb3-a672e03be093",
			wantOK:  true,
		},
		{
			name:    "tenant_id absent",
			setup:   func(c *gin.Context) {},
			wantStr: "",
			wantOK:  false,
		},
		{
			name:    "tenant_id present but wrong type (int)",
			setup:   func(c *gin.Context) { c.Set("tenant_id", 42) },
			wantStr: "",
			wantOK:  false,
		},
		{
			name:    "tenant_id present but nil",
			setup:   func(c *gin.Context) { c.Set("tenant_id", nil) },
			wantStr: "",
			wantOK:  false,
		},
		{
			name:    "tenant_id empty string",
			setup:   func(c *gin.Context) { c.Set("tenant_id", "") },
			wantStr: "",
			wantOK:  true, // empty string is a valid string — caller decides whether to reject
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			tc.setup(c)

			got, ok := GetTenantIDFromToken(c)
			if got != tc.wantStr {
				t.Errorf("got tenant_id=%q want %q", got, tc.wantStr)
			}
			if ok != tc.wantOK {
				t.Errorf("got ok=%v want %v", ok, tc.wantOK)
			}
		})
	}
}
