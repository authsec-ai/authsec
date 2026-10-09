package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Allows states a permission by the same test Require enforces, and fails
// closed: without claims it is false, never "probably".
func TestP2ClassAllows(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := func(claims any) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if claims != nil {
			c.Set("claims", claims)
		}
		return c
	}
	for _, tc := range []struct {
		name   string
		claims any
		want   bool
	}{
		{"scope grants it", jwt.MapClaims{"scope": "iga:read iga:review"}, true},
		{"wildcard scope", jwt.MapClaims{"scope": "iga:*"}, true},
		{"scopes array", jwt.MapClaims{"scopes": []any{"iga:review"}}, true},
		{"perms grant it", jwt.MapClaims{"perms": []any{map[string]any{"r": "iga", "a": []any{"read", "review"}}}}, true},
		{"only iga:read", jwt.MapClaims{"scope": "iga:read"}, false},
		{"another resource", jwt.MapClaims{"scope": "discovery:review"}, false},
		{"no claims", nil, false},
		{"claims of another type", "iga:review", false},
	} {
		if got := Allows(ctx(tc.claims), "iga", "review"); got != tc.want {
			t.Errorf("%s: Allows(iga:review) = %v, want %v", tc.name, got, tc.want)
		}
	}

	// It agrees with Require on the same claims: the capability never offers
	// what the route would refuse.
	for _, claims := range []jwt.MapClaims{{"scope": "iga:review"}, {"scope": "iga:read"}} {
		c := ctx(claims)
		Require("iga", "review")(c)
		required, stated := !c.IsAborted(), Allows(ctx(claims), "iga", "review")
		if required != stated {
			t.Errorf("claims %v: Require allowed=%v, Allows=%v", claims, required, stated)
		}
	}
}
