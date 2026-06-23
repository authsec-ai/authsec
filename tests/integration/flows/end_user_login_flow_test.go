//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Test_EndUserLogin_PasswordToProtectedAPI exercises the full human login →
// protected API path. It seeds a workspace with an admin, adds an end user,
// logs in via POST /authsec/uflow/user/login, and then hits a protected route
// with the returned token to confirm it is accepted.
func Test_EndUserLogin_PasswordToProtectedAPI(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	user, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	loginReq := map[string]string{
		"email":        user.Email,
		"password":     user.Password,
		"workspace_id": ws.WorkspaceID.String(),
	}

	loginResp := env.Do("POST", "/authsec/uflow/user/login", loginReq, "")
	assertStatus(t, loginResp, http.StatusOK)

	var loginPayload struct {
		Token       string `json:"token"`
		WorkspaceID string `json:"workspace_id"`
		Email       string `json:"email"`
		MFARequired bool   `json:"mfa_required"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("unmarshal login response: %v (body: %s)", err, loginResp.Body.String())
	}
	if loginPayload.Token == "" {
		t.Fatalf("expected non-empty token in login response, body: %s", loginResp.Body.String())
	}

	protectedResp := env.Do("GET", "/authsec/applications", nil, loginPayload.Token)
	if protectedResp.Code == http.StatusUnauthorized {
		t.Errorf("expected authenticated access to /authsec/applications, got 401 (body: %s)", protectedResp.Body.String())
	}
}

// Test_EndUserLogin_WrongPassword confirms that a login attempt with the wrong
// password is rejected with 401 {"error":"Invalid credentials"}.
func Test_EndUserLogin_WrongPassword(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	user, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	loginReq := map[string]string{
		"email":        user.Email,
		"password":     "WrongPass999",
		"workspace_id": ws.WorkspaceID.String(),
	}

	resp := env.Do("POST", "/authsec/uflow/user/login", loginReq, "")
	assertStatus(t, resp, http.StatusUnauthorized)
}

// Test_EndUserLogin_ExpiredToken confirms that an expired token is rejected
// on a protected route.
func Test_EndUserLogin_ExpiredToken(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	user, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	tok, err := testsupport.MintExpiredToken(testsupport.UserTokenParams{
		UserID:      user.UserID,
		WorkspaceID: ws.WorkspaceID,
		Email:       user.Email,
	})
	if err != nil {
		t.Fatalf("MintExpiredToken: %v", err)
	}

	resp := env.Do("GET", "/authsec/applications", nil, tok)
	assertExpiredRejected(t, resp)
}

// Test_EndUserLogin_ForgedToken confirms that a token signed with the wrong
// secret is rejected on a protected route.
func Test_EndUserLogin_ForgedToken(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	user, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	tok, err := testsupport.MintForgedToken(testsupport.UserTokenParams{
		UserID:      user.UserID,
		WorkspaceID: ws.WorkspaceID,
		Email:       user.Email,
	})
	if err != nil {
		t.Fatalf("MintForgedToken: %v", err)
	}

	resp := env.Do("GET", "/authsec/applications", nil, tok)
	assertForgedRejected(t, resp)
}

// Test_EndUserLogin_MissingIssuer confirms that a token without an iss claim
// is rejected on a protected route with 401.
func Test_EndUserLogin_MissingIssuer(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	user, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	tok, err := testsupport.MintNoIssuerToken(testsupport.UserTokenParams{
		UserID:      user.UserID,
		WorkspaceID: ws.WorkspaceID,
		Email:       user.Email,
	})
	if err != nil {
		t.Fatalf("MintNoIssuerToken: %v", err)
	}

	resp := env.Do("GET", "/authsec/applications", nil, tok)
	assertStatus(t, resp, http.StatusUnauthorized)
}
