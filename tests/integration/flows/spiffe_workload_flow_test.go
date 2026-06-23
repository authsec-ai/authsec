//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Test_SPIFFE_SVIDAuthentication verifies that a well-formed JWT-SVID signed
// by the workspace's registered keypair is accepted by SpiffeAuthMiddleware on
// the /authsec/exsvc/services route.
func Test_SPIFFE_SVIDAuthentication(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	privKey, err := env.Fakes.JWKS.RegisterWorkspace(ws.WorkspaceID.String())
	if err != nil {
		t.Fatalf("RegisterWorkspace: %v", err)
	}

	tok, err := testsupport.MintSVID(testsupport.SVIDParams{
		SpiffeID:    "spiffe://" + ws.WorkspaceDomain + "/service",
		WorkspaceID: ws.WorkspaceID.String(),
		Audience:    "authsec-api",
		Permissions: []string{"external-service:create"},
		PrivateKey:  privKey,
	})
	if err != nil {
		t.Fatalf("MintSVID: %v", err)
	}

	body := map[string]interface{}{
		"name":        "svc1",
		"resource_id": uuid.New().String(),
		"auth_type":   "spiffe",
	}

	w := env.Do("POST", "/authsec/exsvc/services", body, tok)

	// The endpoint requires additional setup (resource_id FK, workspace context,
	// etc.) — we verify middleware acceptance, not full business logic.
	// A 401 here means SpiffeAuthMiddleware rejected the SVID; anything else
	// (200, 201, 400, 404, 422, 500) means the token was accepted.
	if w.Code == http.StatusUnauthorized {
		t.Errorf("Test_SPIFFE_SVIDAuthentication: expected SVID to be accepted, got 401 (body: %s)", readBody(w))
	}
}

// Test_SPIFFE_WrongKid verifies that a JWT-SVID whose kid is not registered in
// the fake JWKS server is rejected with 401.
func Test_SPIFFE_WrongKid(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	// Do NOT register a keypair — MintWrongKidSVID uses a fresh unregistered key.
	tok, err := testsupport.MintWrongKidSVID(testsupport.SVIDParams{
		SpiffeID:    "spiffe://" + ws.WorkspaceDomain + "/service",
		WorkspaceID: ws.WorkspaceID.String(),
		Audience:    "authsec-api",
		Permissions: []string{"external-service:create"},
	})
	if err != nil {
		t.Fatalf("MintWrongKidSVID: %v", err)
	}

	body := map[string]interface{}{
		"name":        "svc1",
		"resource_id": uuid.New().String(),
		"auth_type":   "spiffe",
	}

	w := env.Do("POST", "/authsec/exsvc/services", body, tok)
	assertWrongKidRejected(t, w)
}

// Test_SPIFFE_ExpiredSVID verifies that a JWT-SVID with exp in the past is
// rejected with 401.
func Test_SPIFFE_ExpiredSVID(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	privKey, err := env.Fakes.JWKS.RegisterWorkspace(ws.WorkspaceID.String())
	if err != nil {
		t.Fatalf("RegisterWorkspace: %v", err)
	}

	tok, err := testsupport.MintExpiredSVID(testsupport.SVIDParams{
		SpiffeID:    "spiffe://" + ws.WorkspaceDomain + "/service",
		WorkspaceID: ws.WorkspaceID.String(),
		Audience:    "authsec-api",
		Permissions: []string{"external-service:create"},
		PrivateKey:  privKey,
	})
	if err != nil {
		t.Fatalf("MintExpiredSVID: %v", err)
	}

	body := map[string]interface{}{
		"name":        "svc1",
		"resource_id": uuid.New().String(),
		"auth_type":   "spiffe",
	}

	w := env.Do("POST", "/authsec/exsvc/services", body, tok)
	assertExpiredRejected(t, w)
}

// Test_SPIFFE_AudienceMismatch verifies that a JWT-SVID carrying the wrong aud
// claim is rejected with 401.
func Test_SPIFFE_AudienceMismatch(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	privKey, err := env.Fakes.JWKS.RegisterWorkspace(ws.WorkspaceID.String())
	if err != nil {
		t.Fatalf("RegisterWorkspace: %v", err)
	}

	tok, err := testsupport.MintSVID(testsupport.SVIDParams{
		SpiffeID:    "spiffe://" + ws.WorkspaceDomain + "/service",
		WorkspaceID: ws.WorkspaceID.String(),
		Audience:    "wrong-audience",
		Permissions: []string{"external-service:create"},
		PrivateKey:  privKey,
	})
	if err != nil {
		t.Fatalf("MintSVID (wrong audience): %v", err)
	}

	body := map[string]interface{}{
		"name":        "svc1",
		"resource_id": uuid.New().String(),
		"auth_type":   "spiffe",
	}

	w := env.Do("POST", "/authsec/exsvc/services", body, tok)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Test_SPIFFE_AudienceMismatch: expected 401 for wrong audience, got %d (body: %s)", w.Code, readBody(w))
	}
}
