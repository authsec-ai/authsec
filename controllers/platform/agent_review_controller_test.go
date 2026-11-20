package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

type fakeReviewIssuer struct {
	err      error
	ws, conn uuid.UUID
}

func (f *fakeReviewIssuer) Issue(_ context.Context, ws, conn uuid.UUID) (*services.AgentReviewCredentials, error) {
	f.ws, f.conn = ws, conn
	if f.err != nil {
		return nil, f.err
	}
	return &services.AgentReviewCredentials{AccessKeyID: "ASIA1", SecretAccessKey: "secret", SessionToken: "tok",
		Expiration: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), RoleARN: "arn:aws:iam::1:role/D"}, nil
}

func reviewRouter(token string, keys AgentReviewKeyIssuer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	MountAgentReviewRoutes(r, token, keys)
	return r
}

func reviewCall(r *gin.Engine, auth, ws, conn string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/authsec/internal/aws/workspaces/%s/connectors/%s/session", ws, conn), nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAgentReviewSessionIssuesKeysToTheService(t *testing.T) {
	f := &fakeReviewIssuer{}
	ws, conn := uuid.New(), uuid.New()
	w := reviewCall(reviewRouter("svc", f), "Bearer svc", ws.String(), conn.String())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("keys must not be cached")
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	for _, k := range []string{"access_key_id", "secret_access_key", "session_token", "expiration"} {
		if body[k] == nil {
			t.Errorf("response lacks %s", k)
		}
	}
	if _, leaked := body["RoleARN"]; leaked || body["role_arn"] != nil {
		t.Error("the response carries only the keys")
	}
	if f.ws != ws || f.conn != conn {
		t.Errorf("issued for %s/%s, want the path's workspace and connector", f.ws, f.conn)
	}
}

func TestAgentReviewSessionRefusesWithoutTheServiceToken(t *testing.T) {
	r := reviewRouter("svc", &fakeReviewIssuer{})
	for _, auth := range []string{"", "Bearer wrong", "svc", "Bearer svcx"} {
		if w := reviewCall(r, auth, uuid.NewString(), uuid.NewString()); w.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: status = %d, want 401", auth, w.Code)
		}
	}
}

func TestAgentReviewSessionNotMountedWithoutToken(t *testing.T) {
	if w := reviewCall(reviewRouter("", &fakeReviewIssuer{}), "Bearer ", uuid.NewString(), uuid.NewString()); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: no token, no route", w.Code)
	}
}

func TestAgentReviewSessionErrors(t *testing.T) {
	cases := map[string]struct {
		keys AgentReviewKeyIssuer
		ws   string
		want int
	}{
		"bad workspace id": {&fakeReviewIssuer{}, "not-a-uuid", http.StatusNotFound},
		"no secrets store": {nil, uuid.NewString(), http.StatusServiceUnavailable},
		"unknown connector": {&fakeReviewIssuer{err: services.ErrAgentReviewConnectorNotFound},
			uuid.NewString(), http.StatusNotFound},
		"revoked": {&fakeReviewIssuer{err: services.ErrAgentReviewConnectorRevoked}, uuid.NewString(), http.StatusConflict},
		"assume failed": {&fakeReviewIssuer{err: fmt.Errorf("%w: AccessDenied", services.ErrAgentReviewAssumeFailed)},
			uuid.NewString(), http.StatusBadGateway},
		"in error": {&fakeReviewIssuer{err: services.ErrAgentReviewUnavailable}, uuid.NewString(), http.StatusServiceUnavailable},
	}
	for name, c := range cases {
		w := reviewCall(reviewRouter("svc", c.keys), "Bearer svc", c.ws, uuid.NewString())
		if w.Code != c.want {
			t.Errorf("%s: status = %d, want %d (body %s)", name, w.Code, c.want, w.Body)
		}
	}
}
