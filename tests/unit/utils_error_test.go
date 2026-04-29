package unit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ── SanitizeError ─────────────────────────────────────────────────────────────

func TestSanitizeError_Nil(t *testing.T) {
	if utils.SanitizeError(nil) != nil {
		t.Error("SanitizeError(nil) should return nil")
	}
}

func TestSanitizeError_DatabaseConnection(t *testing.T) {
	err := utils.SanitizeError(errors.New("dial tcp: connection refused"))
	assert.EqualError(t, err, "database connection failed")
}

func TestSanitizeError_SQLSyntax(t *testing.T) {
	err := utils.SanitizeError(errors.New("syntax error near SELECT"))
	assert.EqualError(t, err, "database operation failed")
}

func TestSanitizeError_AuthError(t *testing.T) {
	err := utils.SanitizeError(errors.New("invalid credentials provided"))
	assert.EqualError(t, err, "authentication failed")
}

func TestSanitizeError_VaultError(t *testing.T) {
	err := utils.SanitizeError(errors.New("vault: token has expired"))
	assert.EqualError(t, err, "configuration service error")
}

func TestSanitizeError_NetworkError(t *testing.T) {
	err := utils.SanitizeError(errors.New("TLS handshake failed"))
	assert.EqualError(t, err, "network error occurred")
}

func TestSanitizeError_GenericError(t *testing.T) {
	err := utils.SanitizeError(errors.New("something completely unrecognized"))
	assert.EqualError(t, err, "operation failed")
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

func newGinCtx(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	return c, w
}

func TestRespondUnauthorized_Returns401(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondUnauthorized(c, errors.New("bad token"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "error")
}

func TestRespondForbidden_Returns403(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondForbidden(c)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRespondNotFound_Returns404(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondNotFound(c)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRespondBadRequest_Returns400(t *testing.T) {
	c, w := newGinCtx("POST", "/test")
	utils.RespondBadRequest(c, errors.New("missing field"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRespondInternalError_Returns500(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondInternalError(c, errors.New("panic"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRespondConflict_Returns409WithMessage(t *testing.T) {
	c, w := newGinCtx("POST", "/test")
	utils.RespondConflict(c, "resource already exists")
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "resource already exists")
}

func TestRespondRateLimited_Returns429(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondRateLimited(c)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRespondWithValidationError_Returns400WithDetails(t *testing.T) {
	c, w := newGinCtx("POST", "/test")
	utils.RespondWithValidationError(c, map[string]string{
		"email":    "invalid format",
		"password": "too short",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "email")
	assert.Contains(t, body, "password")
}

func TestRespondDatabaseError_Returns500(t *testing.T) {
	c, w := newGinCtx("GET", "/test")
	utils.RespondDatabaseError(c, errors.New("db down"), map[string]interface{}{"op": "select"})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
