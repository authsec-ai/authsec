//go:build integration

package flows

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const spiffeSVIDAssertionType = "urn:authsec:params:oauth:client-assertion-type:spiffe-svid"

// externalIssuer is an issuer the attacker controls: its own key and JWKS.
type externalIssuer struct {
	key  *rsa.PrivateKey
	kid  string
	base string // httptest server URL; JWKS is served at base + "/jwks"
}

func startExternalIssuer(t *testing.T) *externalIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ei := &externalIssuer{key: key, kid: "kid-" + emailSafeNonce()}
	jwks, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": ei.kid,
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	ei.base = srv.URL
	return ei
}

func (ei *externalIssuer) sign(t *testing.T, typ string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = ei.kid
	if typ != "" {
		tok.Header["typ"] = typ
	}
	s, err := tok.SignedString(ei.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// AS-012: a workload identity provider registered by workspace A must not
// authenticate workspace B's service accounts. Before the fix the SPIFFE
// branch matched spiffe_id across every workspace.
func Test_SPIFFESVID_ProviderMapsOnlyItsOwnWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, wsB, "https://rs-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	saB, err := AddServiceAccountWithScopes(config.DB, wsB, rsB, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}
	spiffeID := "spiffe://victim-" + n + ".example/workload"
	if err := config.DB.Exec(`UPDATE service_accounts SET spiffe_id = ? WHERE workspace_id = ? AND id = ?`,
		spiffeID, wsB.WorkspaceID, saB.SAID).Error; err != nil {
		t.Fatalf("set spiffe_id: %v", err)
	}

	ei := startExternalIssuer(t)
	addProvider := func(ws *WorkspaceScenario, iss string) {
		if err := config.DB.Exec(`
			INSERT INTO workload_identity_providers (workspace_id, name, kind, issuer, jwks_uri)
			VALUES (?, ?, 'spiffe', ?, ?)`,
			ws.WorkspaceID, "wip-"+iss[len(iss)-1:]+n, iss, ei.base+"/jwks").Error; err != nil {
			t.Fatalf("insert provider: %v", err)
		}
	}
	tokenEndpoint := config.AppConfig.OAuthBaseURL() + "/oauth/token"
	redeem := func(iss string) (int, map[string]interface{}) {
		now := time.Now()
		svid := ei.sign(t, "", jwt.MapClaims{
			"iss": iss, "sub": spiffeID, "aud": tokenEndpoint,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		w := env.Do(http.MethodPost, "/oauth/token", formBody(
			"grant_type", "client_credentials",
			"client_id", saB.ClientIDString,
			"client_assertion_type", spiffeSVIDAssertionType,
			"client_assertion", svid,
			"resource", rsB.ResourceURI,
			"scope", rsB.ScopeStrings[0],
		), "")
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}

	// Attacker workspace A registers a provider for an issuer it controls and
	// presents an SVID naming B's workload.
	issA := ei.base + "/a"
	addProvider(wsA, issA)
	code, body := redeem(issA)
	if code != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("SVID from workspace A's provider authenticated B's workload: %d %v", code, body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("token minted across workspaces")
	}

	// Control: the same SVID via a provider registered in B authenticates.
	issB := ei.base + "/b"
	addProvider(wsB, issB)
	code, body = redeem(issB)
	if code != http.StatusOK {
		t.Fatalf("own-workspace provider: got %d %v, want 200", code, body)
	}
}

// AS-011: trusted issuers belong to the workspace that registered them.
func Test_TrustedIssuers_ScopedToTokenWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	tokB := env.MustAsAdmin(wsB.AdminUserID, wsB.WorkspaceID, wsB.AdminEmail)

	// Reserved provider names are refused.
	for _, pn := range []string{"authsec:id-jag", "AuthSec:other"} {
		w := env.Do(http.MethodPost, "/authsec/trusted-issuers", map[string]interface{}{
			"iss": "https://res-" + n + ".example.com/" + pn, "jwks_uri": "http://127.0.0.1:1/jwks", "provider_name": pn,
		}, tokA)
		assertStatus(t, w, http.StatusBadRequest)
	}

	issA := "https://idp-" + n + ".example.com"
	w := env.Do(http.MethodPost, "/authsec/trusted-issuers", map[string]interface{}{
		"iss": issA, "jwks_uri": "http://127.0.0.1:1/jwks", "provider_name": "corp-" + n,
	}, tokA)
	assertStatus(t, w, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	var owner string
	config.DB.Raw(`SELECT COALESCE(workspace_id::text, '') FROM trusted_issuers WHERE id = ?`, created.ID).Scan(&owner)
	if owner != wsA.WorkspaceID.String() {
		t.Fatalf("created issuer owner = %v, want workspace A", owner)
	}

	// A platform-owned issuer (workspace_id NULL) is read-only and invisible to tenants.
	platformID := uuid.New()
	if err := config.DB.Exec(`INSERT INTO trusted_issuers (id, iss, jwks_uri, provider_name) VALUES (?, ?, 'http://127.0.0.1:1/jwks', 'platform-idp')`,
		platformID, "https://platform-"+n+".example.com").Error; err != nil {
		t.Fatalf("insert platform issuer: %v", err)
	}

	listIDs := func(tok string) map[string]bool {
		w := env.Do(http.MethodGet, "/authsec/trusted-issuers", nil, tok)
		assertStatus(t, w, http.StatusOK)
		var resp struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		ids := map[string]bool{}
		for _, it := range resp.Items {
			ids[it.ID] = true
		}
		return ids
	}
	if ids := listIDs(tokA); !ids[created.ID] || ids[platformID.String()] {
		t.Fatalf("A's list: want own issuer only, got %v", ids)
	}
	if ids := listIDs(tokB); ids[created.ID] || ids[platformID.String()] {
		t.Fatalf("B's list shows issuers it does not own: %v", ids)
	}

	// B cannot test against A's issuer: the probe must not reach A's config.
	probe := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": issA, "sub": "x"})
	probe.Header["typ"] = "oauth-id-jag+jwt"
	probeStr, _ := probe.SignedString([]byte("k"))
	w = env.Do(http.MethodPost, "/authsec/trusted-issuers/test", map[string]interface{}{"assertion": probeStr}, tokB)
	assertStatus(t, w, http.StatusOK)
	if m := parseBody(t, w); m["pass"] != false || !strings.HasPrefix(m["reason"].(string), "untrusted_issuer") {
		t.Fatalf("B testing A's issuer: got %v, want untrusted_issuer", m)
	}

	// Live XAA tokens from A's issuer, one in each workspace (B's predates the fix).
	insertXAA := func(ws uuid.UUID) uuid.UUID {
		jti := uuid.New()
		if err := config.DB.Exec(`
			INSERT INTO native_tokens (jti, iss, workspace_id, token_family, subject_type, subject_id,
				client_id, resource_server_id, aud, scope, source_grant_iss, issued_at, expires_at)
			VALUES (?, 'https://as.test', ?, 'xaa', 'user', ?, 'c', ?, 'aud', 's', ?, NOW(), NOW() + interval '1 hour')`,
			jti, ws, uuid.New(), uuid.New(), issA).Error; err != nil {
			t.Fatalf("insert native token: %v", err)
		}
		return jti
	}
	jtiA, jtiB := insertXAA(wsA.WorkspaceID), insertXAA(wsB.WorkspaceID)

	// B cannot revoke A's issuer or the platform issuer.
	assertStatus(t, env.Do(http.MethodDelete, "/authsec/trusted-issuers/"+created.ID, nil, tokB), http.StatusNotFound)
	assertStatus(t, env.Do(http.MethodDelete, "/authsec/trusted-issuers/"+platformID.String(), nil, tokA), http.StatusNotFound)
	var active int64
	config.DB.Raw(`SELECT COUNT(*) FROM trusted_issuers WHERE id IN (?, ?) AND status = 'active'`, created.ID, platformID).Scan(&active)
	if active != 2 {
		t.Fatalf("a tenant revoked an issuer it does not own")
	}

	// A revokes its own issuer: only A's tokens are bulk-revoked.
	assertStatus(t, env.Do(http.MethodDelete, "/authsec/trusted-issuers/"+created.ID, nil, tokA), http.StatusOK)
	revoked := func(jti uuid.UUID) bool {
		var c int64
		config.DB.Raw(`SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?`, jti.String()).Scan(&c)
		return c > 0
	}
	if !revoked(jtiA) {
		t.Fatalf("A's XAA token was not revoked with A's issuer")
	}
	if revoked(jtiB) {
		t.Fatalf("revoking A's issuer revoked workspace B's token")
	}
}

// AS-011: an ID-JAG from an issuer owned by workspace A must not map a
// subject into workspace B, even when B has an identity under the same
// provider_name.
func Test_XAA_WorkspaceIssuerMapsOnlyIntoItsWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	rsA, err := AddResourceServer(config.DB, wsA, "https://rsa-"+n+".example.com", n+"a")
	if err != nil {
		t.Fatalf("AddResourceServer A: %v", err)
	}
	saA, err := AddServiceAccountWithScopes(config.DB, wsA, rsA, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, wsB, "https://rsb-"+n+".example.com", n+"b")
	if err != nil {
		t.Fatalf("AddResourceServer B: %v", err)
	}
	// B approved A's agent for its RS (a legitimate cross-app relationship).
	if err := config.DB.Exec(`
		INSERT INTO resource_server_client_registrations (id, resource_server_id, oauth_client_id, workspace_id,
			status, registration_type, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'approved', 'prereg', NOW(), NOW())`,
		uuid.New(), rsB.RSID, saA.ClientID, wsB.WorkspaceID).Error; err != nil {
		t.Fatalf("approve: %v", err)
	}

	provider := "corp-" + n
	link := func(ws *WorkspaceScenario, sub string) {
		if err := config.DB.Exec(`
			INSERT INTO oidc_user_identities (workspace_id, user_id, provider_name, provider_user_id, email)
			VALUES (?, ?, ?, ?, ?)`, ws.WorkspaceID, ws.AdminUserID, provider, sub, ws.AdminEmail).Error; err != nil {
			t.Fatalf("link identity: %v", err)
		}
	}
	link(wsB, "victim")
	link(wsA, "self")

	ei := startExternalIssuer(t)
	iss := ei.base + "/idp"
	if err := config.DB.Exec(`
		INSERT INTO trusted_issuers (iss, jwks_uri, provider_name, workspace_id) VALUES (?, ?, ?, ?)`,
		iss, ei.base+"/jwks", provider, wsA.WorkspaceID).Error; err != nil {
		t.Fatalf("insert issuer: %v", err)
	}

	selfIssuer := config.AppConfig.OAuthBaseURL()
	redeem := func(sub string, rs *RSScenario) (int, map[string]interface{}) {
		now := time.Now()
		idjag := ei.sign(t, "oauth-id-jag+jwt", jwt.MapClaims{
			"iss": iss, "sub": sub, "aud": selfIssuer, "client_id": saA.ClientIDString,
			"jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		w := env.DoBasicAuth(http.MethodPost, "/oauth/token", formBody(
			"grant_type", jwtBearerGrantType,
			"assertion", idjag,
			"resource", rs.ResourceURI,
			"scope", rs.ScopeStrings[0],
		), saA.ClientIDString, saA.ClientSecret)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}

	code, body := redeem("victim", rsB)
	desc, _ := body["error_description"].(string)
	if code != http.StatusForbidden || !strings.Contains(desc, "not trusted for this resource's workspace") {
		t.Fatalf("A's issuer redeemed into workspace B: %d %v", code, body)
	}
	var pending int64
	config.DB.Raw(`SELECT COUNT(*) FROM access_requests WHERE resource_server_id = ?`, rsB.RSID).Scan(&pending)
	if pending != 0 {
		t.Fatalf("B's user was mapped: an access request was recorded for B's resource")
	}

	// Control: the same issuer still maps subjects into its own workspace.
	code, body = redeem("self", rsA)
	desc, _ = body["error_description"].(string)
	if strings.Contains(desc, "not trusted") || code == http.StatusBadRequest || code == http.StatusUnauthorized {
		t.Fatalf("own-workspace redemption rejected: %d %v", code, body)
	}
}
