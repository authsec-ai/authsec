//go:build integration

package flows

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// mintNativeToken signs a native access token using the process-global
// NativeKeyManager and inserts the authoritative native_tokens row so the
// introspect handler can verify it end-to-end. Returns the raw token string.
func mintNativeToken(
	t *testing.T,
	ws *WorkspaceScenario,
	sa *SAScenario,
	rs *RSScenario,
	scope string,
) string {
	t.Helper()

	km := tokens.NativeKeys()
	jti := uuid.New()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	claims := jwt.MapClaims{
		"iss":       "authsec-ai/auth-manager",
		"sub":       sa.SAID.String(),
		"aud":       []string{rs.ResourceURI},
		"scope":     scope,
		"client_id": sa.ClientIDString,
		"jti":       jti.String(),
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"tf":        models.TokenFamilyM2M,
	}

	tokenStr, err := km.Sign(claims)
	if err != nil {
		t.Fatalf("mintNativeToken: Sign: %v", err)
	}

	row := models.NativeToken{
		JTI:              jti,
		Iss:              "authsec-ai/auth-manager",
		WorkspaceID:      ws.WorkspaceID,
		TokenFamily:      models.TokenFamilyM2M,
		SubjectType:      "service_account",
		SubjectID:        sa.SAID,
		ClientID:         sa.ClientIDString,
		ResourceServerID: rs.RSID,
		Aud:              rs.ResourceURI,
		Scope:            scope,
		IssuedAt:         now,
		ExpiresAt:        exp,
	}
	if err := config.DB.WithContext(context.Background()).Create(&row).Error; err != nil {
		t.Fatalf("mintNativeToken: insert native_tokens row: %v", err)
	}

	return tokenStr
}

// Test_OAuth_IntrospectNativeToken_Active mints a native M2M token and
// introspects it against the resource server that issued it. Expects 200 and
// active:true (the full native path: signature OK, row present, registration
// approved, scopes live).
func Test_OAuth_IntrospectNativeToken_Active(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	tok := mintNativeToken(t, ws, sa, rs, "read:"+n)

	body := formBody("token", tok)
	w := env.DoBasicAuth("POST", "/oauth/introspect", body, rs.RSID.String(), rs.IntrospectionSecret)

	assertStatus(t, w, http.StatusOK)

	m := parseBody(t, w)
	if m == nil {
		return
	}
	if _, ok := m["active"]; !ok {
		t.Errorf("Test_OAuth_IntrospectNativeToken_Active: expected \"active\" field in body %s", readBody(w))
	}
	// The native path has a full scope-resolution pass; active:true is expected
	// when the SA is approved and all checks pass.
	assertActiveTrue(t, w)
}

// Test_OAuth_IntrospectNativeToken_BadSecret sends a correct token but an
// incorrect resource-server introspection secret. Expects 401.
func Test_OAuth_IntrospectNativeToken_BadSecret(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	tok := mintNativeToken(t, ws, sa, rs, "read:"+n)

	body := formBody("token", tok)
	w := env.DoBasicAuth("POST", "/oauth/introspect", body, rs.RSID.String(), "wrong-secret")

	assertStatus(t, w, http.StatusUnauthorized)
}

// Test_OAuth_IntrospectNativeToken_AudienceMismatch mints a token for rs1 and
// introspects it against rs2. Expects 200 and active:false (audience mismatch).
func Test_OAuth_IntrospectNativeToken_AudienceMismatch(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	// rs1 is the intended audience of the token.
	rs1, err := AddResourceServer(config.DB, ws, "https://"+n+"-rs1.example.com", n+"-rs1")
	if err != nil {
		t.Fatalf("AddResourceServer rs1: %v", err)
	}

	// rs2 is a completely separate resource server in the same workspace.
	rs2, err := AddResourceServer(config.DB, ws, "https://"+n+"-rs2.example.com", n+"-rs2")
	if err != nil {
		t.Fatalf("AddResourceServer rs2: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs1, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Token audience is rs1.ResourceURI.
	tok := mintNativeToken(t, ws, sa, rs1, "read:"+n+"-rs1")

	// Introspect against rs2 — audience mismatch must produce active:false.
	body := formBody("token", tok)
	w := env.DoBasicAuth("POST", "/oauth/introspect", body, rs2.RSID.String(), rs2.IntrospectionSecret)

	assertStatus(t, w, http.StatusOK)
	assertActiveFalse(t, w)
}

// Test_OAuth_IntrospectNativeToken_UnapprovedClient sets the client's
// resource_server_client_registrations status to "pending" and expects
// active:false on introspection (the registration gate fails closed).
func Test_OAuth_IntrospectNativeToken_UnapprovedClient(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	// Downgrade the registration to "pending" so the gate rejects it.
	if err := config.DB.Exec(
		`UPDATE resource_server_client_registrations
		    SET status = 'pending'
		  WHERE resource_server_id = $1 AND oauth_client_id = $2`,
		rs.RSID, sa.ClientID,
	).Error; err != nil {
		t.Fatalf("downgrade registration status: %v", err)
	}

	tok := mintNativeToken(t, ws, sa, rs, "read:"+n)

	body := formBody("token", tok)
	w := env.DoBasicAuth("POST", "/oauth/introspect", body, rs.RSID.String(), rs.IntrospectionSecret)

	assertStatus(t, w, http.StatusOK)
	assertRegistrationGate(t, w)
}
