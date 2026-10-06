package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func clientIPVia(t *testing.T, remote, xff string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ConfigureTrustedProxies(r); err != nil {
		t.Fatal(err)
	}
	r.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
	req := httptest.NewRequest("GET", "/ip", nil)
	req.RemoteAddr = remote
	req.Header.Set("X-Forwarded-For", xff)
	req.Header.Set("X-Real-IP", xff)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Body.String()
}

// AS-034: without TRUSTED_PROXIES a client cannot choose its address with
// X-Forwarded-For (gin trusts every proxy by default).
func TestTrustedProxies_DefaultIgnoresForwardedFor(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	if got := clientIPVia(t, "203.0.113.7:4000", "1.2.3.4"); got != "203.0.113.7" {
		t.Fatalf("ClientIP = %q, want the TCP peer", got)
	}
}

func TestTrustedProxies_HonouredOnlyFromConfiguredProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	if got := clientIPVia(t, "10.1.2.3:4000", "1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("from trusted proxy: ClientIP = %q, want forwarded address", got)
	}
	if got := clientIPVia(t, "203.0.113.7:4000", "1.2.3.4"); got != "203.0.113.7" {
		t.Fatalf("from untrusted peer: ClientIP = %q, want the peer", got)
	}
}

// AS-034: the strict auth budget applies to the real /authsec/... paths.
func TestSelectRateLimitConfig_AuthsecPaths(t *testing.T) {
	for _, p := range []string{
		"/authsec/uflow/auth/admin/login",
		"/authsec/uflow/user/login",
		"/authsec/uflow/auth/totp/login",
		"/authsec/uflow/auth/workspace/totp/login",
		"/authsec/uflow/auth/enduser/webauthn-callback",
	} {
		if got := selectRateLimitConfig(p); got.Endpoint != AuthRateLimit.Endpoint {
			t.Errorf("%s: limit %q, want auth", p, got.Endpoint)
		}
	}
	if got := selectRateLimitConfig("/authsec/applications"); got.Endpoint != GeneralRateLimit.Endpoint {
		t.Errorf("/authsec/applications: %q", got.Endpoint)
	}
}
