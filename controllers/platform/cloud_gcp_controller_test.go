package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// GCP route wiring, exercised the way it actually runs in routes.go:
// middlewares.Require("discovery","admin"|"read") in front of the real
// CloudGCPController methods. A stand-in auth middleware injects claims
// exactly as the real one does post-JWT-verification (c.Set("claims", ...),
// c.Set("workspace_id", ...)) so internal/authz.Require sees the identical
// shape it does in production — this is a wiring test, not a re-test of
// authz.Require itself (that's pre-existing, shared middleware GCP-04 does
// not modify).
func gcpTestRouter(ctl *CloudGCPController) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	discovery := r.Group("/authsec/discovery")
	discovery.Use(func(c *gin.Context) {
		c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
		c.Set("workspace_id", uuid.New().String())
		c.Set("client_id", "test-actor")
		c.Next()
	})
	discovery.GET("/gcp/onboarding", middlewares.Require("discovery", "read"), ctl.GetOnboardingPackage)
	discovery.POST("/gcp/connectors", middlewares.Require("discovery", "admin"), ctl.CreateConnector)
	discovery.GET("/gcp/connectors", middlewares.Require("discovery", "read"), ctl.ListConnectors)
	discovery.DELETE("/gcp/connectors/:id", middlewares.Require("discovery", "admin"), ctl.RevokeConnector)
	return r
}

func TestCloudGcpRoutes_ReadOnlyScope_DeniedOnMutation(t *testing.T) {
	r := gcpTestRouter(NewCloudGCPController(nil))

	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/connectors",
		bytes.NewReader([]byte(`{"scope_kind":"project","scope_id":"x","reader_project_id":"y","auth":{"method":"json_key","key_json":"{}"}}`)))
	req.Header.Set("X-Test-Scope", "discovery:read")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("discovery:read-only must be denied on POST /connectors, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode denial body: %v", err)
	}
	if body["error"] != "insufficient_scope" {
		t.Fatalf("expected insufficient_scope, got %v", body)
	}
}

func TestCloudGcpRoutes_ReadOnlyScope_DeniedOnRevoke(t *testing.T) {
	r := gcpTestRouter(NewCloudGCPController(nil))

	req := httptest.NewRequest(http.MethodDelete, "/authsec/discovery/gcp/connectors/"+uuid.New().String(), nil)
	req.Header.Set("X-Test-Scope", "discovery:read")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("discovery:read-only must be denied on DELETE /connectors/:id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCloudGcpRoutes_ReadOnlyScope_AllowedOnReads(t *testing.T) {
	r := gcpTestRouter(NewCloudGCPController(nil))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/authsec/discovery/gcp/onboarding?reader_project_id=p&scope_id=s", nil),
		httptest.NewRequest(http.MethodGet, "/authsec/discovery/gcp/connectors", nil),
	} {
		req.Header.Set("X-Test-Scope", "discovery:read")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// authz must let this through (never 401/403) -- a nil DB may still
		// fail the actual handler logic for GET /connectors, and that is fine:
		// this test proves only that the AUTHZ gate itself passed a
		// discovery:read-scoped request through to the handler.
		if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
			t.Fatalf("%s %s: discovery:read should pass authz, got %d: %s",
				req.Method, req.URL.Path, w.Code, w.Body.String())
		}
	}
}

func TestCloudGcpRoutes_AdminScope_AllowedOnMutation(t *testing.T) {
	r := gcpTestRouter(NewCloudGCPController(nil))

	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/connectors",
		bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-Test-Scope", "discovery:admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// An empty body fails GCPOnboardingService.Onboard's own input validation
	// (invalid_scope_id) LONG before any nil-DB call -- a clean 400, not
	// 401/403 -- which is exactly what proves the authz gate passed a
	// discovery:admin-scoped request through.
	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("discovery:admin should pass authz on POST /connectors, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCloudGcpCreateConnector_KeyNeverAppearsInResponse proves that even an
// uploaded key that makes it all the way to a validation failure never has
// its bytes echoed back in the HTTP response body -- the response is built
// from mapGCPOnboardingError(err) and, on success, the stored connector
// (models.GCPConnectorAttrs, which structurally has no field for key
// material), never from the request struct.
func TestCloudGcpCreateConnector_KeyNeverAppearsInResponse(t *testing.T) {
	r := gcpTestRouter(NewCloudGCPController(nil))

	const secretMarker = "THIS-PRIVATE-KEY-VALUE-MUST-NEVER-BE-ECHOED"
	body := `{"scope_kind":"project","scope_id":"x","reader_project_id":"y",` +
		`"auth":{"method":"json_key","key_json":"{\"type\":\"service_account\",\"private_key\":\"` + secretMarker + `\"}"}}`

	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/connectors", bytes.NewReader([]byte(body)))
	req.Header.Set("X-Test-Scope", "discovery:admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), secretMarker) {
		t.Fatalf("the uploaded key value leaked into the HTTP response: %s", w.Body.String())
	}
}
