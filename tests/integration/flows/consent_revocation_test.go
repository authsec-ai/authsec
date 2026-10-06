//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// consentFixture is one workspace's user, client and resource server with a
// remembered consent grant and a live native token issued under it.
type consentFixture struct {
	rs      *RSScenario
	sa      *SAScenario
	grantID uuid.UUID
	jti     uuid.UUID
}

func seedConsentFixture(t *testing.T, tn *Tenant, n string) *consentFixture {
	t.Helper()
	rs, err := AddResourceServer(config.DB, tn.WS, "https://consent-"+n+".example.com", n)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, tn.WS, rs, n)
	if err != nil {
		t.Fatal(err)
	}
	f := &consentFixture{rs: rs, sa: sa, grantID: uuid.New(), jti: uuid.New()}
	mustExec(t, `INSERT INTO oauth_consent_grants (id, workspace_id, user_id, oauth_client_id, resource_server_id,
			granted_scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ARRAY[?]::text[], ?)`,
		f.grantID, tn.WS.WorkspaceID, tn.EndUser.UserID, sa.ClientID, rs.RSID, rs.ScopeStrings[0], time.Now().Add(24*time.Hour))
	mustExec(t, `INSERT INTO native_tokens (jti, iss, workspace_id, token_family, subject_type, subject_id,
			client_id, resource_server_id, aud, scope, issued_at, expires_at)
		VALUES (?, ?, ?, 'xaa', 'user', ?, ?, ?, ?, ?, now(), ?)`,
		f.jti, config.AppConfig.OAuthBaseURL(), tn.WS.WorkspaceID, tn.EndUser.UserID, sa.ClientIDString,
		rs.RSID, rs.ResourceURI, rs.ScopeStrings[0], time.Now().Add(time.Hour))
	return f
}

func consentRevoked(t *testing.T, id uuid.UUID) bool {
	return scalar(t, `SELECT (revoked_at IS NOT NULL)::text FROM oauth_consent_grants WHERE id = ?`, id) == "true"
}

func nativeTokenRevoked(t *testing.T, jti uuid.UUID) bool {
	var n int64
	config.DB.Raw(`SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?`, jti.String()).Scan(&n)
	return n > 0 && scalar(t, `SELECT (revoked_at IS NOT NULL)::text FROM native_tokens WHERE jti = ?`, jti) == "true"
}

// Consent grants are workspace-scoped, and revoking one revokes the tokens it
// backs (AS-068).
func Test_ConsentGrants_IsolationAndTokenRevocation(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	n := emailSafeNonce()
	fa := seedConsentFixture(t, a, n+"a")
	fb := seedConsentFixture(t, b, n+"b")

	// A's admin neither sees nor revokes B's grant.
	w := env.Do(http.MethodGet, "/authsec/consent-grants", nil, a.AdminToken)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), fb.grantID.String()) {
		t.Fatalf("A's consent list shows B's grant")
	}
	if !strings.Contains(w.Body.String(), fa.grantID.String()) {
		t.Fatalf("A's consent list misses A's grant: %s", w.Body.String())
	}
	AssertCrossTenantNotFound(t, http.MethodDelete, "/authsec/consent-grants/"+fb.grantID.String(), nil, a.AdminToken)
	AssertCrossTenantNotFound(t, http.MethodDelete, "/oauth/consent-grants/"+fb.grantID.String(), nil, a.EndUserToken)
	if consentRevoked(t, fb.grantID) || nativeTokenRevoked(t, fb.jti) {
		t.Fatalf("B's grant or token changed after A's attempts")
	}

	// A's own revocation also revokes the native token the grant backs.
	assertStatus(t, env.Do(http.MethodDelete, "/authsec/consent-grants/"+fa.grantID.String(), nil, a.AdminToken), http.StatusOK)
	if !consentRevoked(t, fa.grantID) {
		t.Fatal("grant not revoked")
	}
	if !nativeTokenRevoked(t, fa.jti) {
		t.Fatal("native token issued under the grant is still live")
	}

	// The user's self-service revoke works the same way.
	assertStatus(t, env.Do(http.MethodDelete, "/oauth/consent-grants/"+fb.grantID.String(), nil, b.EndUserToken), http.StatusOK)
	if !nativeTokenRevoked(t, fb.jti) {
		t.Fatal("self-service revoke left the native token live")
	}
}

// AS-068: a refresh of a token issued under consent that was since revoked is
// refused, even when Hydra still issues new tokens.
func Test_RefreshRefusedAfterConsentRevoked(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	f := seedConsentFixture(t, a, emailSafeNonce())
	mustExec(t, `UPDATE mcp_oauth_clients SET supports_refresh_token = true WHERE id = ?`, f.sa.ClientID)

	env.Fakes.Hydra.OnToken(func(_ *http.Request) (int, map[string]interface{}) {
		return http.StatusOK, map[string]interface{}{
			"access_token": "at-" + uuid.NewString(), "refresh_token": "rt-" + uuid.NewString(),
			"token_type": "bearer", "expires_in": 3600,
		}
	})
	defer env.Fakes.Hydra.ResetToken()
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{"active": true, "sub": a.EndUser.UserID.String(), "scope": f.rs.ScopeStrings[0]}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	refresh := func() string {
		w := env.DoBasicAuth(http.MethodPost, "/oauth/token", formBody(
			"grant_type", "refresh_token",
			"refresh_token", "rt-old",
			"resource", f.rs.ResourceURI,
		), f.sa.ClientIDString, f.sa.ClientSecret)
		return w.Body.String()
	}
	if body := refresh(); strings.Contains(body, "consent") {
		t.Fatalf("refresh refused for consent before any revocation: %s", body)
	}
	assertStatus(t, env.Do(http.MethodDelete, "/authsec/consent-grants/"+f.grantID.String(), nil, a.AdminToken), http.StatusOK)
	if body := refresh(); !strings.Contains(body, "consent for this client has been revoked") {
		t.Fatalf("refresh after consent revocation not refused: %s", body)
	}
}
