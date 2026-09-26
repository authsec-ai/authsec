package middlewares

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestLegacyIngress_DefaultAllowsBurst(t *testing.T) {
	t.Setenv("IGA_LEGACY_INGRESS_RATE_PER_MIN", "")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r); err != nil {
		t.Fatal(err)
	}
	r.POST("/authsec/discovery/sightings", LegacyDiscoveryIngressGuard(nil), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	ws := uuid.NewString()
	for i := 0; i < 500; i++ {
		body := []byte(`{"workspace_id":"` + ws + `","source":"vm_sensor"}`)
		req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/sightings", bytes.NewReader(body))
		req.RemoteAddr = "10.1.1.1:4000"
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
}

func TestLegacyIngress_RateLimitIsPerWorkspace(t *testing.T) {
	t.Setenv("IGA_LEGACY_INGRESS_RATE_PER_MIN", "2")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r); err != nil {
		t.Fatal(err)
	}
	r.POST("/authsec/discovery/sightings", LegacyDiscoveryIngressGuard(nil), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	post := func(ws string) int {
		body := []byte(`{"workspace_id":"` + ws + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/sightings", bytes.NewReader(body))
		req.RemoteAddr = "10.9.9.9:4000"
		req.Header.Set("X-Forwarded-For", "8.8.8.8")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	a := uuid.NewString()
	b := uuid.NewString()
	if post(a) != http.StatusCreated || post(a) != http.StatusCreated {
		t.Fatal("first two requests for workspace A should pass")
	}
	if post(a) != http.StatusTooManyRequests {
		t.Fatal("third request for workspace A should be limited")
	}
	if post(b) != http.StatusCreated {
		t.Fatal("workspace B must not share A's bucket")
	}
}

func TestLegacyIngress_SettingsLookupFailsOpen(t *testing.T) {
	t.Setenv("IGA_LEGACY_INGRESS_RATE_PER_MIN", "")
	gin.SetMode(gin.TestMode)
	gdb, err := gorm.Open(postgres.Open("host=127.0.0.1 port=1 user=nobody dbname=none sslmode=disable connect_timeout=1"), &gorm.Config{
		DisableAutomaticPing: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/authsec/discovery/sightings", LegacyDiscoveryIngressGuard(gdb), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	body := []byte(`{"workspace_id":"` + uuid.NewString() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/sightings", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("settings lookup failure: %d %s", w.Code, w.Body.String())
	}
}

func TestApplyTrustedProxies_DefaultIgnoresForwardedFor(t *testing.T) {
	t.Setenv("IGA_TRUSTED_PROXIES", "")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r); err != nil {
		t.Fatal(err)
	}
	r.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Body.String() != "10.1.1.1" {
		t.Fatalf("ClientIP %q, want the TCP peer", w.Body.String())
	}
}

func TestApplyTrustedProxies_HonorsConfiguredCIDR(t *testing.T) {
	t.Setenv("IGA_TRUSTED_PROXIES", "10.1.1.1/32")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := ApplyTrustedProxies(r); err != nil {
		t.Fatal(err)
	}
	r.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Body.String() != "1.2.3.4" {
		t.Fatalf("ClientIP %q, want the forwarded client", w.Body.String())
	}
}

func TestApplyTrustedProxies_RejectsGarbage(t *testing.T) {
	t.Setenv("IGA_TRUSTED_PROXIES", "not-a-cidr")
	r := gin.New()
	if err := ApplyTrustedProxies(r); err == nil {
		t.Fatal("expected an error for a proxy value that is not an IP or CIDR")
	}
}
