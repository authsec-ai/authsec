package platform

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/services"
)

// Another workspace's or user's Azure sign-in session answers 404, as one
// that does not exist (CLAUDE.md rule 6).
func TestAzureSessionMismatchIs404(t *testing.T) {
	if status, _ := mapAzureOnboardingError(services.ErrAzureSessionMismatch); status != http.StatusNotFound {
		t.Fatalf("session mismatch: %d", status)
	}
}

// A failed read inside AuthSec never returns its error text (it can name a
// database error or a Vault path).
func TestAzureInternalErrorHidesText(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/authsec/discovery/azure/identities", nil)
	azureInternalError(c, errors.New(`pq: relation "cloud_identity" does not exist`))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "cloud_identity") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
