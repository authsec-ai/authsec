package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// A caller cannot escape the limit by sending a different X-Forwarded-For
// on each request: without a trusted proxy the header is not the key.
func TestRateLimiter_IgnoresSpoofedForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	rl := NewRateLimiter(rate.Limit(0.001), 1)
	r.GET("/x", rl.Middleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	codes := []int{}
	for _, xff := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.7:4000"
		req.Header.Set("X-Forwarded-For", xff)
		r.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	if codes[1] != http.StatusTooManyRequests || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For escaped the limit: %v", codes)
	}
}
