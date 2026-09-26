package middlewares

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Counting reader proves authentication rejects a token before the body is parsed.
type countingBody struct {
	reads int
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.reads++
	return 0, io.EOF
}

func (b *countingBody) Close() error { return nil }

func TestCollectorRateLimit_RetryAfter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/limited-collector-proof", CollectorRateLimit(1, time.Minute), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	first := httptest.NewRequest(http.MethodPost, "/limited-collector-proof", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusNoContent {
		t.Fatalf("first request: %d", w1.Code)
	}

	second := httptest.NewRequest(http.MethodPost, "/limited-collector-proof", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d body %s", w2.Code, w2.Body.String())
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
}

func TestAuthenticateCollector_RejectsActuationTokenBeforeBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// db is unused when the prefix is rejected.
	r.POST("/api/iga/v2/collectors/self", AuthenticateCollector(nil, func() time.Time { return time.Unix(0, 0) }), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	body := &countingBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v2/collectors/self", body)
	req.Header.Set("Authorization", "Bearer authsec_act_not-a-v2-credential")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if body.reads != 0 {
		t.Fatalf("body was read %d times before auth failed", body.reads)
	}
}

func TestRequireV2Ingest_OffIs404WithoutBody(t *testing.T) {
	t.Setenv("IGA_V2_INGEST", "0")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/iga/v2/collector-enrollments", RequireV2Ingest(), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})
	body := &countingBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/iga/v2/collector-enrollments", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
	if body.reads != 0 {
		t.Fatalf("flag-off route read the body %d times", body.reads)
	}
}
