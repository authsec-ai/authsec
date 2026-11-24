package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// An agent decides nothing: RespondToAction refuses an SDK token (the one an
// agent holds) and a legacy token (class unknown) before reading the body or
// the database, so the controller needs no service here.
func TestRespondToActionRefusesNonInteractiveTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctrl := &AgentActionController{} // nil service: must not be reached
	for name, claims := range map[string]jwt.MapClaims{
		"sdk":    {"typ": string(sessiontoken.SDK)},
		"legacy": {},
		"none":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/authsec/uflow/agent/actions/respond",
				strings.NewReader(`{"action_req_id":"act_x","approved":true,"biometric_verified":true}`))
			if claims != nil {
				c.Set("claims", claims)
			}
			ctrl.RespondToAction(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s token: status %d, want 403 (body %s)", name, w.Code, w.Body.String())
			}
		})
	}
}
