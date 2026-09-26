package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRuntimePolicyFlagOffIsNotRegistered(t *testing.T) {
	t.Setenv(services.EnvV2Policy, "")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	MountRuntimePolicy(r, policyMemDB(t), policyTestAuth(uuid.New(), uuid.New(), ""))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v2/runtime-policies", nil)
	req.Header.Set("X-Test-Scope", "runtime_policy:read")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("flag off: got %d %s", w.Code, w.Body.String())
	}
}

func TestRuntimePolicyPermissionMatrix(t *testing.T) {
	t.Setenv(services.EnvV2Policy, "1")
	gin.SetMode(gin.TestMode)
	db := policyMemDB(t)
	ws, user := uuid.New(), uuid.New()
	mount := func() *gin.Engine {
		r := gin.New()
		MountRuntimePolicy(r, db, policyTestAuth(ws, user, ""))
		return r
	}
	id := uuid.NewString()
	cases := []struct {
		method, path, scope string
		want                int
	}{
		{http.MethodGet, "/api/iga/v2/runtime-policies", "runtime_policy:read", 0},
		{http.MethodGet, "/api/iga/v2/runtime-policies", "runtime_policy:write", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies", "runtime_policy:write", 0},
		{http.MethodPost, "/api/iga/v2/runtime-policies", "runtime_policy:read", http.StatusForbidden},
		{http.MethodGet, "/api/iga/v2/runtime-policies/" + id, "runtime_policy:read", 0},
		{http.MethodGet, "/api/iga/v2/runtime-policies/" + id, "runtime_policy:approve", http.StatusForbidden},
		{http.MethodPut, "/api/iga/v2/runtime-policies/" + id + "/draft", "runtime_policy:write", 0},
		{http.MethodPut, "/api/iga/v2/runtime-policies/" + id + "/draft", "runtime_policy:read", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/validate", "runtime_policy:write", 0},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/validate", "runtime_policy:approve", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/approvals", "runtime_policy:approve", 0},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/approvals", "runtime_policy:write", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/candidates", "runtime_policy:write", http.StatusNotImplemented},
		{http.MethodPost, "/api/iga/v2/runtime-policies/candidates", "runtime_policy:read", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/publications", "runtime_policy:enforce", http.StatusNotImplemented},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/publications", "runtime_policy:approve", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/rollback", "runtime_policy:enforce", http.StatusNotImplemented},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/rollback", "runtime_policy:read", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/revoke", "runtime_policy:enforce", http.StatusNotImplemented},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/revoke", "runtime_policy:write", http.StatusForbidden},
		{http.MethodGet, "/api/iga/v2/runtime-policies/" + id + "/rollouts", "runtime_policy:read", http.StatusNotImplemented},
		{http.MethodGet, "/api/iga/v2/runtime-policies/simulations/" + id, "runtime_policy:read", http.StatusNotImplemented},
		{http.MethodGet, "/api/iga/v2/runtime-policies/simulations/" + id, "runtime_policy:enforce", http.StatusForbidden},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/simulations", "runtime_policy:write", http.StatusNotImplemented},
		{http.MethodPost, "/api/iga/v2/runtime-policies/" + id + "/simulations", "runtime_policy:read", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.scope+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-Test-Scope", tc.scope)
			req.Header.Set("Idempotency-Key", "k")
			req.Header.Set("If-Match", "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			w := httptest.NewRecorder()
			mount().ServeHTTP(w, req)
			if tc.want == 0 {
				if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
					t.Fatalf("scope %s was denied: %d %s", tc.scope, w.Code, w.Body.String())
				}
				return
			}
			if w.Code != tc.want {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCandidateSystemCannotApproveOrEnforce(t *testing.T) {
	t.Setenv(services.EnvV2Policy, "1")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	MountRuntimePolicy(r, policyMemDB(t), policyTestAuth(uuid.New(), models.RuntimePolicyCandidateSystemUserID, models.RuntimePolicyActorCandidateSystem))
	for _, path := range []string{
		"/api/iga/v2/runtime-policies/" + uuid.NewString() + "/approvals",
		"/api/iga/v2/runtime-policies/" + uuid.NewString() + "/publications",
		"/api/iga/v2/runtime-policies/" + uuid.NewString() + "/rollback",
		"/api/iga/v2/runtime-policies/" + uuid.NewString() + "/revoke",
	} {
		scope := "runtime_policy:enforce"
		if strings.Contains(path, "approvals") {
			scope = "runtime_policy:approve"
		}
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("X-Test-Scope", scope)
		req.Header.Set("Idempotency-Key", "k")
		req.Header.Set("If-Match", "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d %s", path, w.Code, w.Body.String())
		}
	}
}

func policyTestAuth(ws, user uuid.UUID, kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
		c.Set("workspace_id", ws.String())
		c.Set("user_id", user.String())
		if kind != "" {
			c.Set("actor_kind", kind)
		}
		c.Next()
	}
}

func policyMemDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return db
}
