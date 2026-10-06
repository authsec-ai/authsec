//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
)

// AS-031: logout ends the session server-side; the same token is refused
// afterwards even though it has not expired.
func Test_Logout_RevokesSessionToken(t *testing.T) {
	env := testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := env.Do("POST", "/authsec/uflow/auth/admin/login", map[string]string{
		"email": ws.AdminEmail, "password": ws.AdminPassword, "workspace_domain": ws.WorkspaceDomain,
	}, "")
	assertStatus(t, w, http.StatusOK)
	var login struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &login)
	if login.Token == "" {
		t.Fatalf("admin login returned no token: %s", w.Body.String())
	}
	claims := jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(login.Token, claims)
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Fatalf("session token must carry a jti")
	}

	const probe = "/authsec/uflow/admin/users/list"
	assertStatus(t, env.Do("GET", probe, nil, login.Token), http.StatusOK)
	assertStatus(t, env.Do("POST", "/authsec/auth/logout", nil, login.Token), http.StatusOK)
	assertStatus(t, env.Do("GET", probe, nil, login.Token), http.StatusUnauthorized)
}

// AS-033: a token that never expires is refused even with a valid signature.
func Test_SessionToken_WithoutExpiryRefused(t *testing.T) {
	env := testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":          "authsec-ai/auth-manager",
		"aud":          "authsec-api",
		"sub":          ws.AdminUserID.String(),
		"user_id":      ws.AdminUserID.String(),
		"workspace_id": ws.WorkspaceID.String(),
		"email_id":     ws.AdminEmail,
		"roles":        []string{"admin"},
		"iat":          time.Now().Unix(),
	}).SignedString([]byte(testsupport.HarnessJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/users/list", nil, tok), http.StatusUnauthorized)
}
