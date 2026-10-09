package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Google Authentication's route wiring, exercised the same way
// cloud_gcp_controller_test.go's gcpTestRouter already exercises the
// existing WIF/JSON-key routes — a stand-in auth middleware injects claims
// exactly as the real middlewares.AuthMiddleware() does post-JWT-verification,
// so middlewares.Require sees the identical shape it does in production.
//
// The callback route is registered directly on the root engine, with NO
// auth middleware and NO "/authsec" prefix, mirroring routes.go's actual
// placement (r.GET(...), not authsec.GET(...) — a RouterGroup's own path
// prefix applies regardless of middleware, and GCP_OAUTH_REDIRECT_URI is
// configured as the bare "/discovery/gcp/google-oauth/callback" with no
// "/authsec" segment, live-confirmed against a real Google consent round
// trip). This is the shape the route-placement regression test below checks
// for.
func gcpOAuthTestRouter(ctl *CloudGCPOAuthController) *gin.Engine {
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
	discovery.GET("/gcp/google-oauth/status", middlewares.Require("discovery", "read"), ctl.GoogleOAuthStatus)
	discovery.POST("/gcp/google-oauth/start", middlewares.Require("discovery", "admin"), ctl.StartGoogleOAuth)
	discovery.GET("/gcp/google-oauth/projects", middlewares.Require("discovery", "read"), ctl.ListGoogleProjects)
	discovery.POST("/gcp/google-oauth/preflight", middlewares.Require("discovery", "admin"), ctl.PreflightGoogleOAuth)
	discovery.POST("/gcp/google-oauth/connectors", middlewares.Require("discovery", "admin"), ctl.ProvisionGoogleOAuth)

	// Deliberately NOT inside the `discovery` group above, and deliberately
	// registered on `r` rather than a "/authsec"-prefixed group — no
	// AuthMiddleware, no "/authsec" segment, no claims/workspace_id in
	// context, exactly like Google's real redirect arrives. This is what
	// proves the handler itself does not implicitly depend on anything
	// AuthMiddleware would have set, AND that the path matches what
	// GCP_OAUTH_REDIRECT_URI is actually configured as.
	r.GET("/discovery/gcp/google-oauth/callback", ctl.GoogleOAuthCallback)

	return r
}

func TestGoogleOAuthCallback_ReachableWithoutAuthMiddleware(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	req := httptest.NewRequest(http.MethodGet, "/discovery/gcp/google-oauth/callback?code=abc&state=xyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// No claims, no workspace_id, no client_id were ever set on this
	// request's context -- if the handler required any of them (the way
	// middlewares.Require-gated handlers do), it would panic or 401/403
	// rather than reach its own redirect logic. A redirect (regardless of
	// whether the underlying state/service happens to be configured in this
	// test) proves the handler ran to completion without that dependency.
	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d (a redirect back into the SPA, success or error) — got body %s", w.Code, http.StatusFound, w.Body.String())
	}
}

func TestGoogleOAuthCallback_MissingCodeOrState_RedirectsWithError(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	req := httptest.NewRequest(http.MethodGet, "/discovery/gcp/google-oauth/callback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected a Location header")
	}
}

func TestGoogleOAuthCallback_GoogleDenied_RedirectsWithError(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	req := httptest.NewRequest(http.MethodGet, "/discovery/gcp/google-oauth/callback?error=access_denied", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
}

func TestGoogleOAuthRoutes_ReadOnlyScope_DeniedOnMutations(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	cases := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/google-oauth/start",
			bytes.NewReader([]byte(`{"scope_kind":"project","scope_id":"s1","reader_project_id":"p1"}`))),
		httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/google-oauth/preflight",
			bytes.NewReader([]byte(`{"session_id":"x"}`))),
		httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/google-oauth/connectors",
			bytes.NewReader([]byte(`{"session_id":"x"}`))),
	}
	for _, req := range cases {
		req.Header.Set("X-Test-Scope", "discovery:read")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: discovery:read-only must be denied, got %d: %s", req.Method, req.URL.Path, w.Code, w.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode denial body: %v", err)
		}
		if body["error"] != "insufficient_scope" {
			t.Fatalf("%s %s: expected insufficient_scope, got %v", req.Method, req.URL.Path, body)
		}
	}
}

func TestGoogleOAuthRoutes_ReadOnlyScope_AllowedOnReads(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/authsec/discovery/gcp/google-oauth/status", nil),
		httptest.NewRequest(http.MethodGet, "/authsec/discovery/gcp/google-oauth/projects?session_id=x", nil),
	} {
		req.Header.Set("X-Test-Scope", "discovery:read")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusForbidden {
			t.Fatalf("%s %s: discovery:read must be allowed, got 403: %s", req.Method, req.URL.Path, w.Body.String())
		}
	}
}

// StartGoogleOAuth takes no request body -- per the approved UX, the human
// signs in with Google BEFORE picking a project, so no scope is known yet.
// This asserts the handler never fails on the body's shape (it doesn't bind
// one at all), only ever on availability/service-layer concerns.
func TestStartGoogleOAuth_IgnoresBody(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/google-oauth/start", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Test-Scope", "discovery:admin")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusBadRequest {
		t.Fatalf("StartGoogleOAuth must not fail on request-body shape, got 400: %s", w.Body.String())
	}
}

func TestPreflightGoogleOAuth_InvalidBody_BadRequest(t *testing.T) {
	r := gcpOAuthTestRouter(NewCloudGCPOAuthController(nil))

	req := httptest.NewRequest(http.MethodPost, "/authsec/discovery/gcp/google-oauth/preflight", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Test-Scope", "discovery:admin")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
