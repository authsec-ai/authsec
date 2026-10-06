package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// AS-063: another workspace in the path is answered as "not found", never
// 403, so the response does not confirm that the workspace exists.
func TestValidateWorkspaceFromToken_MismatchIs404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws/:workspace_id", func(c *gin.Context) {
		c.Set("workspace_id", "11111111-1111-1111-1111-111111111111")
		c.Next()
	}, ValidateWorkspaceFromToken(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/ws/11111111-1111-1111-1111-111111111111", http.StatusOK},
		{"/ws/22222222-2222-2222-2222-222222222222", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("GET %s: got %d, want %d", tc.path, w.Code, tc.want)
		}
	}
}
