package platform

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/gin-gonic/gin"
)

// withAppConfig sets config.AppConfig for the duration of one test and
// restores whatever it was before — these tests are the only ones in this
// package that touch it, but restoring keeps this file safe if that ever
// changes.
func withAppConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	prev := config.AppConfig
	config.AppConfig = cfg
	t.Cleanup(func() { config.AppConfig = prev })
}

func ginContextForHost(host string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/.well-known/openid-configuration", nil)
	req.Host = host
	c.Request = req
	return c, w
}

/* --------------------------- issuerBaseForRequest --------------------------- */

// TestIssuerBaseForRequest_NoOverride_LocalApplicationURLsUnchanged proves
// that with GCP_WIF_ISSUER_URL unset, every request resolves to the app's
// own OAuthBaseURL() — the exact pre-existing behavior, for local dev's
// general HTTP URLs and for production alike.
func TestIssuerBaseForRequest_NoOverride_LocalApplicationURLsUnchanged(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})

	c, _ := ginContextForHost("localhost:7001")
	got := issuerBaseForRequest(c)
	if got != "http://localhost:7001" {
		t.Errorf("issuerBaseForRequest = %q, want the unchanged app base URL", got)
	}
}

// TestIssuerBaseForRequest_UsesWIFIssuerWhenHostMatches proves OIDC
// discovery uses the configured WIF issuer's own base URL — never the
// app's localhost BASE_URL — when a request genuinely arrives on that
// issuer's host (the tunnel's hostname). This is what makes the discovery
// document self-consistent: "issuer" must equal the URL GCP fetched it
// from, or GCP's own OIDC validation rejects the WIF provider.
func TestIssuerBaseForRequest_UsesWIFIssuerWhenHostMatches(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})
	t.Setenv(gcp.WIFIssuerEnv, "https://abc123.trycloudflare.com")

	c, _ := ginContextForHost("abc123.trycloudflare.com")
	got := issuerBaseForRequest(c)
	if got != "https://abc123.trycloudflare.com" {
		t.Errorf("issuerBaseForRequest = %q, want the WIF issuer", got)
	}
}

// TestIssuerBaseForRequest_UnrelatedHost_FallsBackToAppBase proves a
// request on neither the canonical app host nor the configured WIF issuer
// host still gets the app's own base URL back (never the WIF issuer, never
// something derived from the unrecognized host itself) — the safe default.
func TestIssuerBaseForRequest_UnrelatedHost_FallsBackToAppBase(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})
	t.Setenv(gcp.WIFIssuerEnv, "https://abc123.trycloudflare.com")

	c, _ := ginContextForHost("some-other-host.example")
	got := issuerBaseForRequest(c)
	if got != "http://localhost:7001" {
		t.Errorf("issuerBaseForRequest = %q, want the app base URL as the safe fallback", got)
	}
}

/* ------------------------- CanonicalIssuerOrWIFIssuer ------------------------ */

// TestCanonicalIssuerOrWIFIssuer_NoLocalhostRedirectForConfiguredWIFIssuer
// is the direct regression test for the bug this whole fix targets: a
// request on the configured WIF issuer's host must be let through — no
// redirect to localhost, no redirect at all.
func TestCanonicalIssuerOrWIFIssuer_NoLocalhostRedirectForConfiguredWIFIssuer(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})
	t.Setenv(gcp.WIFIssuerEnv, "https://abc123.trycloudflare.com")

	ctrl := &OAuthASController{}
	c, w := ginContextForHost("abc123.trycloudflare.com")

	ctrl.CanonicalIssuerOrWIFIssuer()(c)

	if w.Code != http.StatusOK && w.Code != 0 {
		// The middleware itself never writes a success status (that's the
		// real handler's job) — it only writes on redirect. 0 means
		// "nothing written yet", which is the pass-through we want.
		t.Errorf("middleware wrote status %d; want no response written (pass-through)", w.Code)
	}
	if c.IsAborted() {
		t.Error("request was aborted; want it passed through to the handler")
	}
}

// TestCanonicalIssuerOrWIFIssuer_CanonicalHostStillWorks proves the
// canonical app host still passes through unchanged — local application
// URLs are unaffected by this middleware existing.
func TestCanonicalIssuerOrWIFIssuer_CanonicalHostStillWorks(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})
	t.Setenv(gcp.WIFIssuerEnv, "https://abc123.trycloudflare.com")

	ctrl := &OAuthASController{}
	c, _ := ginContextForHost("localhost:7001")

	ctrl.CanonicalIssuerOrWIFIssuer()(c)

	if c.IsAborted() {
		t.Error("canonical host request was aborted; want it passed through")
	}
}

// TestCanonicalIssuerOrWIFIssuer_UnrelatedHostStillRedirects proves the
// relaxed check isn't wide open: a host that is neither the canonical app
// host nor the configured WIF issuer is still redirected to the canonical
// host, exactly like CanonicalIssuerOnly's existing behavior.
func TestCanonicalIssuerOrWIFIssuer_UnrelatedHostStillRedirects(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "http://localhost:7001"})
	t.Setenv(gcp.WIFIssuerEnv, "https://abc123.trycloudflare.com")

	ctrl := &OAuthASController{}
	c, w := ginContextForHost("some-random-host.example")

	ctrl.CanonicalIssuerOrWIFIssuer()(c)

	if !c.IsAborted() {
		t.Error("unrelated host request was not aborted; want it redirected")
	}
	if w.Code != http.StatusPermanentRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusPermanentRedirect)
	}
	if loc := w.Header().Get("Location"); loc != "http://localhost:7001/.well-known/openid-configuration" {
		t.Errorf("Location = %q, want the canonical app URL", loc)
	}
}

// TestCanonicalIssuerOrWIFIssuer_ProductionDefaultsRemainSafe proves that
// with GCP_WIF_ISSUER_URL unset (production's normal state), this
// middleware behaves identically to CanonicalIssuerOnly: only the
// canonical app host passes, everything else redirects to it. Production
// can never accidentally accept an arbitrary host just because this
// middleware exists.
func TestCanonicalIssuerOrWIFIssuer_ProductionDefaultsRemainSafe(t *testing.T) {
	withAppConfig(t, &config.Config{BaseURL: "https://app.authsec.dev"})
	// Deliberately no t.Setenv(gcp.WIFIssuerEnv, ...) — unset, as in production.

	ctrl := &OAuthASController{}

	c, _ := ginContextForHost("app.authsec.dev")
	ctrl.CanonicalIssuerOrWIFIssuer()(c)
	if c.IsAborted() {
		t.Error("production canonical host was aborted; want pass-through")
	}

	c2, w2 := ginContextForHost("some-attacker-controlled-host.example")
	ctrl.CanonicalIssuerOrWIFIssuer()(c2)
	if !c2.IsAborted() || w2.Code != http.StatusPermanentRedirect {
		t.Error("production must still redirect any non-canonical host away")
	}
}
