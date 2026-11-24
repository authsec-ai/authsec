package middlewares

import (
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestIsInteractiveUserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		claims interface{}
		want   bool
	}{
		{"admin", jwt.MapClaims{"typ": string(sessiontoken.Admin)}, true},
		{"enduser", jwt.MapClaims{"typ": string(sessiontoken.EndUser)}, true},
		{"sdk (agent)", jwt.MapClaims{"typ": string(sessiontoken.SDK)}, false},
		{"legacy (class unknown)", jwt.MapClaims{}, false},
		{"no claims", nil, false},
		{"wrong type", map[string]interface{}{"typ": "admin"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			if tc.claims != nil {
				c.Set("claims", tc.claims)
			}
			if got := IsInteractiveUserSession(c); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
