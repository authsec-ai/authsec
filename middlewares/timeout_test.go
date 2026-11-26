package middlewares

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// timeoutPanicChildEnv marks the child process that actually serves the
// panicking request. Before the fix the panic escaped on the timeout
// goroutine and killed the process, so the parent runs it out of process to
// observe that as a test failure rather than a crashed test binary.
const timeoutPanicChildEnv = "AUTHSEC_TIMEOUT_PANIC_CHILD"

func newTimeoutTestRouter(timeout time.Duration) *gin.Engine {
	r := gin.New()
	r.Use(RecoveryMiddleware())
	r.Use(TimeoutMiddleware(timeout))
	r.GET("/panic", func(c *gin.Context) {
		var m map[string]string
		m["boom"] = "x" // nil map write panics
	})
	r.GET("/slow", func(c *gin.Context) {
		time.Sleep(200 * time.Millisecond)
	})
	r.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestTimeoutMiddleware_HandlerPanicBecomes500(t *testing.T) {
	if os.Getenv(timeoutPanicChildEnv) == "1" {
		r := newTimeoutTestRouter(5 * time.Second)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", w.Code)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestTimeoutMiddleware_HandlerPanicBecomes500$")
	cmd.Env = append(os.Environ(), timeoutPanicChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("handler panic was not turned into a 500 (process crashed or wrong status): %v\n%s", err, out)
	}
}

func TestTimeoutMiddleware_StillTimesOut(t *testing.T) {
	r := newTimeoutTestRouter(20 * time.Millisecond)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/slow", nil))
	if w.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want 408", w.Code)
	}
	// Let the abandoned handler goroutine finish before the test exits.
	time.Sleep(250 * time.Millisecond)
}

func TestTimeoutMiddleware_PassesThrough(t *testing.T) {
	r := newTimeoutTestRouter(5 * time.Second)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ok", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("got %d %q, want 200 ok", w.Code, w.Body.String())
	}
}
