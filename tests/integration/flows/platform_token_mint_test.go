//go:build integration

package flows

import (
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
)

// AS-028: /auth/token/oidc turned any active Hydra access token, issued to any
// client, into a 24h platform session. Nothing calls it, so it is gone.
func Test_AuthTokenOIDC_RouteRemoved(t *testing.T) {
	env := testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	// A Hydra token for some third-party client that happens to carry the
	// user's identity in its session ext.
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active":    true,
			"sub":       ws.AdminUserID.String(),
			"client_id": "third-party-" + emailSafeNonce(),
			"ext": map[string]interface{}{
				"provider":     "authsec",
				"provider_id":  ws.AdminUserID.String(),
				"user_id":      ws.AdminUserID.String(),
				"workspace_id": ws.WorkspaceID.String(),
				"email":        ws.AdminEmail,
			},
		}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	w := env.Do(http.MethodPost, "/authsec/auth/token/oidc",
		map[string]string{"oidc_token": "hydra-token-for-another-client"}, "")
	r := parseResp(w)
	if _, minted := r.Body["access_token"]; minted {
		t.Fatalf("a Hydra token was upgraded to a platform session: %d %v", w.Code, r.Body)
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for removed /auth/token/oidc, got %d: %v", w.Code, r.Body)
	}
}

func generatePlatformToken(t *testing.T, env *testsupport.Env, bearer string, body map[string]interface{}) (int, RespBody) {
	t.Helper()
	w := env.Do(http.MethodPost, "/authsec/auth/token/generate", body, bearer)
	return w.Code, parseResp(w)
}

func shortLivedUserToken(t *testing.T, ttl time.Duration) (string, *WorkspaceScenario) {
	t.Helper()
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	tok, err := testsupport.MintUserToken(testsupport.UserTokenParams{
		UserID:      ws.AdminUserID,
		WorkspaceID: ws.WorkspaceID,
		Email:       ws.AdminEmail,
		ExpiresIn:   ttl,
	})
	if err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	return tok, ws
}

// AS-031: re-minting must not extend a session past the presented token's expiry.
func Test_AuthTokenGenerate_DoesNotExtendLifetime(t *testing.T) {
	env := testsupport.Get(t)
	presented, ws := shortLivedUserToken(t, 10*time.Minute)
	presentedExp := time.Now().Add(10 * time.Minute)

	code, r := generatePlatformToken(t, env, presented, map[string]interface{}{
		"workspace_id": ws.WorkspaceID.String(),
		"email_id":     ws.AdminEmail,
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, r.Body)
	}
	minted, _ := r.Body["access_token"].(string)
	if minted == "" {
		t.Fatalf("no access_token in response: %v", r.Body)
	}
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(minted, claims); err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatalf("minted token has no exp: %v", claims)
	}
	if exp.Time.After(presentedExp.Add(5 * time.Second)) {
		t.Fatalf("minted token expires %s, after the presented token (%s)", exp.Time, presentedExp)
	}
	if ei, _ := r.Body["expires_in"].(float64); ei > (10 * time.Minute).Seconds() {
		t.Fatalf("expires_in %v exceeds the presented token's remaining lifetime", ei)
	}
}

// AS-031: a secret_id in the body must not upgrade the result to an
// sdk-agent token when the secret was never verified.
func Test_AuthTokenGenerate_SecretIDDoesNotUpgrade(t *testing.T) {
	env := testsupport.Get(t)
	presented, ws := shortLivedUserToken(t, time.Hour)

	code, r := generatePlatformToken(t, env, presented, map[string]interface{}{
		"workspace_id": ws.WorkspaceID.String(),
		"email_id":     ws.AdminEmail,
		"secret_id":    "anything-at-all",
	})
	if minted, _ := r.Body["access_token"].(string); minted != "" {
		claims := jwt.MapClaims{}
		if _, _, err := new(jwt.Parser).ParseUnverified(minted, claims); err == nil && claims["token_type"] == "sdk-agent" {
			t.Fatalf("unverified secret_id produced an sdk-agent token")
		}
	}
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for secret_id, got %d: %v", code, r.Body)
	}
}
