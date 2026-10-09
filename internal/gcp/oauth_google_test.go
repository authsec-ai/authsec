package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGoogleAuthorizeURL_UsesNarrowScopes(t *testing.T) {
	raw := GoogleAuthorizeURL("client-id", "https://app.example/callback", "state-123", "challenge-abc")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	scope := u.Query().Get("scope")
	got := strings.Fields(scope)

	want := map[string]bool{
		"openid":                              true,
		"email":                               true,
		"profile":                             true,
		"https://www.googleapis.com/auth/iam": true,
		"https://www.googleapis.com/auth/cloudplatformprojects": true,
		"https://www.googleapis.com/auth/service.management":    true,
	}
	if len(got) != len(want) {
		t.Fatalf("scope list has %d entries, want %d: %v", len(got), len(want), got)
	}
	for _, s := range got {
		if !want[s] {
			t.Fatalf("unexpected scope %q was requested — this bootstrap must only request the narrow scope set, got %v", s, got)
		}
	}
	// The whole point of this test: guard against silently widening to the
	// broad cloud-platform scope.
	if strings.Contains(scope, "https://www.googleapis.com/auth/cloud-platform") {
		t.Fatalf("authorize URL must never request cloud-platform, got scope=%q", scope)
	}
}

func TestGoogleAuthorizeURL_AccessTypeOnline(t *testing.T) {
	raw := GoogleAuthorizeURL("client-id", "https://app.example/callback", "state-123", "challenge-abc")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	q := u.Query()

	if got := q.Get("access_type"); got != "online" {
		t.Fatalf("access_type = %q, want \"online\" — this bootstrap must never request offline access", got)
	}
	if q.Has("prompt") {
		t.Fatalf("prompt=%q was set — this bootstrap must never force the consent/offline prompt", q.Get("prompt"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want \"code\"", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want \"S256\"", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") != "challenge-abc" {
		t.Fatalf("code_challenge not carried through: got %q", q.Get("code_challenge"))
	}
	if q.Get("state") != "state-123" {
		t.Fatalf("state not carried through: got %q", q.Get("state"))
	}
}

func TestExchangeGoogleCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "authorization_code" {
			t.Fatalf("grant_type = %q", r.FormValue("grant_type"))
		}
		if r.FormValue("code_verifier") != "verifier-xyz" {
			t.Fatalf("code_verifier not forwarded: got %q", r.FormValue("code_verifier"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(googleTokenResponse{
			AccessToken: "access-token-abc",
			IDToken:     "id-token-abc",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			// Deliberately including a would-be refresh_token-shaped field is
			// impossible here since googleTokenResponse has no such field —
			// this is the structural guarantee itself, not something this
			// particular response needs to test further.
		})
	}))
	defer srv.Close()

	orig := googleOAuthTokenURL
	googleOAuthTokenURL = srv.URL
	defer func() { googleOAuthTokenURL = orig }()

	accessToken, idToken, err := ExchangeGoogleCode(context.Background(), "cid", "csecret", "https://app.example/callback", "auth-code", "verifier-xyz")
	if err != nil {
		t.Fatalf("ExchangeGoogleCode: %v", err)
	}
	if accessToken != "access-token-abc" {
		t.Fatalf("accessToken = %q", accessToken)
	}
	if idToken != "id-token-abc" {
		t.Fatalf("idToken = %q", idToken)
	}
}

func TestExchangeGoogleCode_ErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(googleTokenResponse{Error: "invalid_grant", ErrorDescription: "bad code"})
	}))
	defer srv.Close()
	orig := googleOAuthTokenURL
	googleOAuthTokenURL = srv.URL
	defer func() { googleOAuthTokenURL = orig }()

	_, _, err := ExchangeGoogleCode(context.Background(), "cid", "csecret", "https://app.example/callback", "bad-code", "verifier")
	if err == nil {
		t.Fatal("expected an error for a rejected code exchange")
	}
	if !strings.Contains(err.Error(), "google rejected") {
		t.Fatalf("error = %v, want a sanitized ErrGoogleOAuthExchangeFailed-shaped message", err)
	}
	// The raw provider error text must never leak into the sanitized error.
	if strings.Contains(err.Error(), "bad code") {
		t.Fatalf("error leaked the raw error_description: %v", err)
	}
}

func TestExchangeGoogleCode_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(googleTokenResponse{})
	}))
	defer srv.Close()
	orig := googleOAuthTokenURL
	googleOAuthTokenURL = srv.URL
	defer func() { googleOAuthTokenURL = orig }()

	_, _, err := ExchangeGoogleCode(context.Background(), "cid", "csecret", "https://app.example/callback", "code", "verifier")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}

func TestExchangeGoogleCode_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	orig := googleOAuthTokenURL
	googleOAuthTokenURL = srv.URL
	defer func() { googleOAuthTokenURL = orig }()

	_, _, err := ExchangeGoogleCode(context.Background(), "cid", "csecret", "https://app.example/callback", "code", "verifier")
	if err == nil {
		t.Fatal("expected an error for an unreadable response body")
	}
}

func TestDecodeGoogleIDTokenEmail(t *testing.T) {
	claims := map[string]string{"email": "user@example.com"}
	payload, _ := json.Marshal(claims)
	token := "header." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"

	if got := DecodeGoogleIDTokenEmail(token); got != "user@example.com" {
		t.Fatalf("DecodeGoogleIDTokenEmail = %q, want user@example.com", got)
	}
	if got := DecodeGoogleIDTokenEmail("not-a-jwt"); got != "" {
		t.Fatalf("DecodeGoogleIDTokenEmail(malformed) = %q, want empty string, not an error", got)
	}
	if got := DecodeGoogleIDTokenEmail(""); got != "" {
		t.Fatalf("DecodeGoogleIDTokenEmail(empty) = %q, want empty string", got)
	}
}
