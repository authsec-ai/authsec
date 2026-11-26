//go:build integration

package flows

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/beevik/etree"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/crypto/bcrypt"
)

// Regression tests for AS-005, AS-010, AS-015, AS-016, AS-017, AS-018 and
// the /login + TOTP part of AS-038.

func mustExec(t *testing.T, q string, args ...interface{}) {
	t.Helper()
	if err := config.DB.Exec(q, args...).Error; err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return m
}

func seedTwoWorkspaces(t *testing.T) (*WorkspaceScenario, *WorkspaceScenario, string) {
	t.Helper()
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	return wsA, wsB, n
}

func insertOIDCProvider(t *testing.T, workspaceID *uuid.UUID, name, clientID, baseURL string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var ws interface{}
	if workspaceID != nil {
		ws = *workspaceID
	}
	mustExec(t, `INSERT INTO oidc_providers (id, workspace_id, provider_name, display_name, client_id, client_secret_vault_path,
			authorization_url, token_url, userinfo_url, is_active)
		VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8, true)`,
		id, ws, name, clientID, "kv/data/test/google-"+clientID, // "google": platform rows fall back to the env secret
		baseURL+"/authorize", baseURL+"/token", baseURL+"/userinfo")
	return id
}

// ── AS-010 ──────────────────────────────────────────────────────────────

func Test_AdminOIDCProviders_ScopedToTokenWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	wsA, wsB, n := seedTwoWorkspaces(t)
	name := "idp" + n
	platformOnly := "plat" + n
	insertOIDCProvider(t, &wsA.WorkspaceID, name, "cid-a-"+n, "https://a.example")
	insertOIDCProvider(t, &wsB.WorkspaceID, name, "cid-b-"+n, "https://b.example")
	insertOIDCProvider(t, nil, name, "cid-platform-"+n, "https://p.example")
	insertOIDCProvider(t, nil, platformOnly, "cid-platonly-"+n, "https://p.example")
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	w := env.Do("GET", "/authsec/uflow/admin/oidc/providers", nil, tokA)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "cid-a-"+n) {
		t.Fatalf("own provider missing: %s", body)
	}
	if strings.Contains(body, "cid-b-"+n) || strings.Contains(body, "cid-platform-"+n) || strings.Contains(body, "cid-platonly-"+n) {
		t.Fatalf("provider list leaked another workspace's or the platform's config: %s", body)
	}

	w = env.Do("PUT", "/authsec/uflow/admin/oidc/providers/"+name, map[string]interface{}{
		"client_id": "rewritten-" + n, "redirect_uri": "https://evil.example/cb",
	}, tokA)
	assertStatus(t, w, http.StatusOK)

	var owners []string
	rows, err := config.DB.Raw(`SELECT COALESCE(workspace_id::text, 'platform') FROM oidc_providers WHERE client_id = $1`, "rewritten-"+n).Rows()
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		owners = append(owners, s)
	}
	rows.Close()
	if len(owners) != 1 || owners[0] != wsA.WorkspaceID.String() {
		t.Fatalf("update must touch only the caller's row, touched %v", owners)
	}

	// Platform rows are read-only for workspace admins.
	w = env.Do("PUT", "/authsec/uflow/admin/oidc/providers/"+platformOnly, map[string]interface{}{"client_id": "x-" + n}, tokA)
	assertStatus(t, w, http.StatusNotFound)

	// The secret path cannot be pointed at another workspace's secret.
	w = env.Do("PUT", "/authsec/uflow/admin/oidc/providers/"+name, map[string]interface{}{
		"client_secret_vault_path": config.WorkspaceIDPSecretPath(wsB.WorkspaceID.String(), "oidc", name),
	}, tokA)
	assertStatus(t, w, http.StatusBadRequest)
}

// ── AS-005 ──────────────────────────────────────────────────────────────

type samlFixture struct {
	ws        *WorkspaceScenario
	ks        dsig.X509KeyStore
	provider  string
	entityID  string
	spEntity  string
	acsURL    string
	challenge string
}

func seedSAMLFixture(t *testing.T) *samlFixture {
	t.Helper()
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	ks := dsig.RandomKeyStoreForTest()
	_, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	f := &samlFixture{
		ws: ws, ks: ks, provider: "saml" + n,
		entityID: "https://idp-" + n + ".example", spEntity: "https://sp.example/" + n,
		acsURL: "https://sp.example/authsec/hmgr/saml/acs", challenge: "lc-" + n,
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	mustExec(t, `INSERT INTO saml_providers (workspace_id, provider_name, display_name, entity_id, sso_url, certificate, sp_entity_id, sp_acs_url, is_active)
		VALUES ($1, $2, $2, $3, 'https://idp.example/sso', $4, $5, $6, true)`,
		ws.WorkspaceID, f.provider, f.entityID, certPEM, f.spEntity, f.acsURL)
	return f
}

func (f *samlFixture) newRequest(t *testing.T) string {
	t.Helper()
	id := "_" + uuid.NewString()
	mustExec(t, `INSERT INTO saml_requests (id, login_challenge, workspace_id, provider_name, relay_state, created_at, expires_at)
		VALUES ($1, $2, $3, $4, '', $5, $6)`,
		id, f.challenge, f.ws.WorkspaceID, f.provider, time.Now(), time.Now().Add(10*time.Minute))
	return id
}

func (f *samlFixture) relayState() string {
	return base64.StdEncoding.EncodeToString([]byte(f.challenge + ":" + f.provider + ":" + f.ws.WorkspaceID.String()))
}

func (f *samlFixture) response(t *testing.T, requestID, email string, sign bool) string {
	t.Helper()
	now := time.Now().UTC()
	assertion := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-%s" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:Subject><saml:NameID>%s</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`+
		`<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="%s"/></saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>`+
		`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`+
		`</saml:Assertion>`,
		uuid.NewString(), now.Format(time.RFC3339), f.entityID, email,
		now.Add(5*time.Minute).Format(time.RFC3339), f.acsURL, requestID,
		now.Add(-time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339), f.spEntity, email)
	if sign {
		doc := etree.NewDocument()
		if err := doc.ReadFromString(assertion); err != nil {
			t.Fatal(err)
		}
		ctx := dsig.NewDefaultSigningContext(f.ks)
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		signed, err := ctx.SignEnveloped(doc.Root())
		if err != nil {
			t.Fatal(err)
		}
		doc.SetRoot(signed)
		assertion, err = doc.WriteToString()
		if err != nil {
			t.Fatal(err)
		}
	}
	resp := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r-` + uuid.NewString() + `" Version="2.0" InResponseTo="` + requestID +
		`" Destination="` + f.acsURL + `"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		assertion + `</samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(resp))
}

func Test_SAMLACS_FailsClosedOnSignature(t *testing.T) {
	env := testsupport.Get(t)
	f := seedSAMLFixture(t)

	// Unsigned assertion naming the workspace admin: must be rejected.
	reqID := f.newRequest(t)
	w := env.Do("POST", "/authsec/hmgr/saml/acs", map[string]string{
		"saml_response": f.response(t, reqID, f.ws.AdminEmail, false),
		"relay_state":   f.relayState(),
	}, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "signature") {
		t.Fatalf("unsigned SAML response: got %d %s, want 400 signature failure", w.Code, w.Body.String())
	}

	// A correctly signed response gets past validation once...
	signed := f.response(t, reqID, f.ws.AdminEmail, true)
	w = env.Do("POST", "/authsec/hmgr/saml/acs", map[string]string{"saml_response": signed, "relay_state": f.relayState()}, "")
	if strings.Contains(w.Body.String(), "Invalid SAML response") {
		t.Fatalf("validly signed SAML response rejected: %d %s", w.Code, w.Body.String())
	}
	// ...and cannot be replayed.
	w = env.Do("POST", "/authsec/hmgr/saml/acs", map[string]string{"saml_response": signed, "relay_state": f.relayState()}, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "pending request") {
		t.Fatalf("replayed SAML response: got %d %s, want 400", w.Code, w.Body.String())
	}
}

// ── AS-015 ──────────────────────────────────────────────────────────────

func seedCIBADevice(t *testing.T, ws *WorkspaceScenario, email, n string) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	mustExec(t, `INSERT INTO users (id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, '', $4, 'local', true, NOW(), NOW())`, userID, ws.WorkspaceID, email, ws.WorkspaceDomain)
	now := time.Now().Unix()
	mustExec(t, `INSERT INTO device_tokens (id, user_id, workspace_id, device_token, platform, device_name, device_model, app_version, os_version, is_active, last_used, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'ios', 'phone', 'model', '1.0', '17', true, $5, $5, $5)`, uuid.New(), userID, ws.WorkspaceID, "dev-"+n+"-"+userID.String(), now)
	return userID
}

func jwtExp(t *testing.T, tok string) time.Time {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	_ = json.Unmarshal(raw, &claims)
	return time.Unix(claims.Exp, 0)
}

func Test_LegacyCIBA_WorkspaceScopedAndShortLived(t *testing.T) {
	env := testsupport.Get(t)
	wsA, wsB, n := seedTwoWorkspaces(t)
	email := "ciba-" + n + "@shared.test"
	userA := seedCIBADevice(t, wsA, email, n)
	userB := seedCIBADevice(t, wsB, email, n)

	// No workspace or client: an email alone selects no user.
	w := env.Do("POST", "/authsec/uflow/auth/ciba/initiate", map[string]string{"login_hint": email}, "")
	assertStatus(t, w, http.StatusBadRequest)

	// Unknown workspace.
	w = env.Do("POST", "/authsec/uflow/auth/ciba/initiate", map[string]string{"login_hint": email, "workspace_id": uuid.NewString()}, "")
	assertStatus(t, w, http.StatusBadRequest)

	// workspace_id picks that workspace's user only.
	w = env.Do("POST", "/authsec/uflow/auth/ciba/initiate", map[string]string{"login_hint": email, "workspace_id": wsB.WorkspaceID.String()}, "")
	assertStatus(t, w, http.StatusOK)
	reqID, _ := decodeJSON(t, w)["auth_req_id"].(string)
	var gotUser uuid.UUID
	if err := config.DB.Raw(`SELECT user_id FROM ciba_auth_requests WHERE auth_req_id = $1`, reqID).Row().Scan(&gotUser); err != nil {
		t.Fatal(err)
	}
	if gotUser != userB {
		t.Fatalf("CIBA request bound to user %s, want workspace B's user %s", gotUser, userB)
	}

	// The minted token lives 24h, not a year.
	mustExec(t, `UPDATE ciba_auth_requests SET status = 'approved' WHERE auth_req_id = $1`, reqID)
	w = env.Do("POST", "/authsec/uflow/auth/ciba/token", map[string]string{"auth_req_id": reqID}, "")
	assertStatus(t, w, http.StatusOK)
	resp := decodeJSON(t, w)
	if exp, _ := resp["expires_in"].(float64); exp != 86400 {
		t.Fatalf("expires_in = %v, want 86400", resp["expires_in"])
	}
	tok, _ := resp["access_token"].(string)
	if exp := jwtExp(t, tok); exp.After(time.Now().Add(25 * time.Hour)) {
		t.Fatalf("CIBA token expires at %s, more than 24h away", exp)
	}

	// A client_id selects the workspace it is approved in, and binds the poll.
	rs, err := AddResourceServer(config.DB, wsA, "https://rs-ciba-legacy-"+n+".example.com", n)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, wsA, rs, n)
	if err != nil {
		t.Fatal(err)
	}
	w = env.Do("POST", "/authsec/uflow/auth/ciba/initiate", map[string]string{"login_hint": email, "client_id": sa.ClientIDString}, "")
	assertStatus(t, w, http.StatusOK)
	reqID, _ = decodeJSON(t, w)["auth_req_id"].(string)
	if err := config.DB.Raw(`SELECT user_id FROM ciba_auth_requests WHERE auth_req_id = $1`, reqID).Row().Scan(&gotUser); err != nil {
		t.Fatal(err)
	}
	if gotUser != userA {
		t.Fatalf("client_id request bound to user %s, want workspace A's user %s", gotUser, userA)
	}
	// client_id and workspace_id must agree.
	w = env.Do("POST", "/authsec/uflow/auth/ciba/initiate", map[string]string{
		"login_hint": email, "client_id": sa.ClientIDString, "workspace_id": wsB.WorkspaceID.String(),
	}, "")
	assertStatus(t, w, http.StatusBadRequest)

	mustExec(t, `UPDATE ciba_auth_requests SET status = 'approved' WHERE auth_req_id = $1`, reqID)
	w = env.Do("POST", "/authsec/uflow/auth/ciba/token", map[string]string{"auth_req_id": reqID}, "")
	assertStatus(t, w, http.StatusUnauthorized)
}

// ── AS-016 ──────────────────────────────────────────────────────────────

func Test_RegisterVerify_CannotTakeOverExistingWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatal(err)
	}
	attacker := "attacker-" + n + "@evil.test"

	// Anonymous end-user sign-up names the victim workspace.
	w := env.Do("POST", "/authsec/uflow/user/register/initiate", map[string]string{
		"email": attacker, "password": "AttackerPass123!", "workspace_id": ws.WorkspaceID.String(),
	}, "")
	assertStatus(t, w, http.StatusOK)
	var otp string
	if err := config.DB.Raw(`SELECT otp FROM otp_entries WHERE email = $1 ORDER BY created_at DESC LIMIT 1`, attacker).Row().Scan(&otp); err != nil {
		t.Fatalf("read OTP: %v", err)
	}

	for _, path := range []string{"/authsec/uflow/register/verify", "/authsec/uflow/auth/admin/complete-registration"} {
		w = env.Do("POST", path, map[string]string{"email": attacker, "otp": otp}, "")
		if w.Code == http.StatusOK {
			t.Errorf("%s accepted an end-user pending row for an existing workspace: %s", path, w.Body.String())
		}
	}

	var takenOver int64
	config.DB.Raw(`SELECT COUNT(*) FROM users u JOIN workspace_memberships m ON m.user_id = u.id
		WHERE u.workspace_id = $1 AND LOWER(u.email) = $2`, ws.WorkspaceID, attacker).Row().Scan(&takenOver)
	if takenOver != 0 {
		t.Fatalf("attacker became a member of the existing workspace")
	}
	var ownerIsAttacker int64
	config.DB.Raw(`SELECT COUNT(*) FROM workspaces w JOIN users u ON u.id = w.owner_user_id
		WHERE w.id = $1 AND LOWER(u.email) = $2`, ws.WorkspaceID, attacker).Row().Scan(&ownerIsAttacker)
	if ownerIsAttacker != 0 {
		t.Fatalf("attacker became the owner of the existing workspace")
	}
}

// ── AS-018 ──────────────────────────────────────────────────────────────

func Test_LegacyRegister_CannotClaimSyncedUser(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatal(err)
	}
	email := "synced-" + n + "@" + ws.WorkspaceDomain
	userID := uuid.New()
	mustExec(t, `INSERT INTO users (id, workspace_id, email, password_hash, workspace_domain, provider, active, created_at, updated_at)
		VALUES ($1, $2, $3, '', $4, 'scim', true, NOW(), NOW())`, userID, ws.WorkspaceID, email, ws.WorkspaceDomain)

	w := env.Do("POST", "/authsec/uflow/user/register", map[string]string{
		"email": email, "password": "AttackerPass123!", "workspace_id": ws.WorkspaceID.String(),
	}, "")
	// Since AS-018 the legacy route only starts the OTP flow.
	if strings.Contains(w.Body.String(), "Registration completed") {
		t.Fatalf("legacy register set a password on a synced account: %s", w.Body.String())
	}
	var hash string
	config.DB.Raw(`SELECT COALESCE(password_hash, '') FROM users WHERE id = $1`, userID).Row().Scan(&hash)
	if hash != "" {
		t.Fatalf("synced user's password was set without email proof")
	}
}

// ── AS-017 ──────────────────────────────────────────────────────────────

type fakeIdP struct {
	srv   *httptest.Server
	email string
	sub   string
}

func newFakeIdP(t *testing.T, email, sub string) *fakeIdP {
	t.Helper()
	f := &fakeIdP{email: email, sub: sub}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
		case "/userinfo":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"sub": f.sub, "email": f.email, "email_verified": true, "name": "Test User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func insertOIDCState(t *testing.T, token, provider, action string, workspaceID *uuid.UUID, workspaceDomain string) {
	t.Helper()
	var ws interface{}
	if workspaceID != nil {
		ws = *workspaceID
	}
	mustExec(t, `INSERT INTO oidc_states (state_token, workspace_id, workspace_domain, request_host, provider_name, action, code_verifier, redirect_after, expires_at, created_at)
		VALUES ($1, $2, $3, '', $4, $5, 'verifier', '', NOW() + interval '10 minutes', NOW())`,
		token, ws, workspaceDomain, provider, action)
}

func Test_OIDCCompleteRegistration_RequiresVerifiedState(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	email := "newowner-" + n + "@example.test"
	sub := "sub-" + n
	idp := newFakeIdP(t, email, sub)
	provider := "pdisc" + n
	insertOIDCProvider(t, nil, provider, "cid-"+n, idp.srv.URL)

	body := func(domain, stateToken, mail string) map[string]string {
		return map[string]string{
			"workspace_domain": domain, "provider": provider, "email": mail,
			"name": "Mallory", "provider_user_id": sub, "state_token": stateToken,
		}
	}

	// Without a state token: refused, no workspace created.
	w := env.Do("POST", "/authsec/uflow/oidc/complete-registration", body("nostate"+n, "", email), "")
	assertStatus(t, w, http.StatusBadRequest)
	w = env.Do("POST", "/authsec/uflow/oidc/complete-registration", body("bogus"+n, "not-a-state", email), "")
	assertStatus(t, w, http.StatusUnauthorized)

	// The discover flow issues a state for the identity the IdP verified.
	stateTok := "st-" + n
	insertOIDCState(t, stateTok, provider, "discover", nil, "")
	w = env.Do("POST", "/authsec/uflow/oidc/exchange-code", map[string]string{"code": "c", "state": stateTok}, "")
	assertStatus(t, w, http.StatusNotFound)
	pd, _ := decodeJSON(t, w)["provider_data"].(map[string]interface{})
	regState, _ := pd["state_token"].(string)
	if regState == "" {
		t.Fatalf("needs_domain response carries no state_token: %s", w.Body.String())
	}

	// It cannot be used for a different email.
	w = env.Do("POST", "/authsec/uflow/oidc/complete-registration", body("other"+n, regState, "victim-"+n+"@example.test"), "")
	assertStatus(t, w, http.StatusForbidden)

	var count int64
	config.DB.Raw(`SELECT COUNT(*) FROM users WHERE LOWER(email) IN ($1, $2)`, "victim-"+n+"@example.test", email).Row().Scan(&count)
	if count != 0 {
		t.Fatalf("registration created users without a matching verified state")
	}

	// The token is single use: a second attempt (even a matching one) fails.
	w = env.Do("POST", "/authsec/uflow/oidc/complete-registration", body("again"+n, regState, email), "")
	assertStatus(t, w, http.StatusUnauthorized)
}

func Test_OIDCAdminLogin_ScopedToStateWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	wsA, wsB, n := seedTwoWorkspaces(t)
	shared := "owner-" + n + "@shared.test"
	mustExec(t, `UPDATE users SET email = $1 WHERE id IN ($2, $3)`, shared, wsA.AdminUserID, wsB.AdminUserID)

	idp := newFakeIdP(t, shared, "sub-"+n)
	provider := "plogin" + n
	pid := insertOIDCProvider(t, nil, provider, "cid-"+n, idp.srv.URL)

	// Signing in to each workspace must resolve that workspace's admin. An
	// email-only admin lookup returns the same row both times, so it fails
	// one of the two.
	for i, ws := range []*WorkspaceScenario{wsA, wsB} {
		mustExec(t, `INSERT INTO identity_providers (workspace_id, provider_type, display_name, oidc_provider_id, status, created_by_user_id)
			VALUES ($1, 'oidc', $2, $3, 'configured', $4)`, ws.WorkspaceID, provider, pid, ws.AdminUserID)
		stateTok := fmt.Sprintf("st-%s-%d", n, i)
		insertOIDCState(t, stateTok, provider, "login", &ws.WorkspaceID, ws.WorkspaceDomain)
		w := env.Do("POST", "/authsec/uflow/oidc/exchange-code", map[string]string{"code": "c", "state": stateTok}, "")
		assertStatus(t, w, http.StatusOK)
		resp := decodeJSON(t, w)
		if resp["workspace_id"] != ws.WorkspaceID.String() || resp["login_ticket"] == "" || resp["login_ticket"] == nil {
			t.Fatalf("OIDC login must sign in workspace %s's admin: %s", ws.WorkspaceID, w.Body.String())
		}
		// The OIDC identity is a first factor only: no session token before MFA.
		if tok, ok := resp["token"]; ok && tok != "" {
			t.Fatalf("OIDC first factor must not return a session token: %s", w.Body.String())
		}
	}
}

// ── AS-038 ──────────────────────────────────────────────────────────────

func Test_PasswordLogin_ScopedToWorkspaceDomain(t *testing.T) {
	env := testsupport.Get(t)
	wsA, wsB, n := seedTwoWorkspaces(t)
	shared := "owner-" + n + "@shared.test"
	hashB, _ := bcrypt.GenerateFromPassword([]byte("OtherPassword123!"), bcrypt.MinCost)
	mustExec(t, `UPDATE users SET email = $1 WHERE id IN ($2, $3)`, shared, wsA.AdminUserID, wsB.AdminUserID)
	mustExec(t, `UPDATE users SET password_hash = $1 WHERE id = $2`, string(hashB), wsB.AdminUserID)
	mustExec(t, `UPDATE workspaces SET email = $1 WHERE id IN ($2, $3)`, shared, wsA.WorkspaceID, wsB.WorkspaceID)

	w := env.Do("POST", "/authsec/uflow/login", map[string]string{
		"email": shared, "password": "OtherPassword123!", "workspace_domain": wsB.WorkspaceDomain,
	}, "")
	assertStatus(t, w, http.StatusOK)
	if got := decodeJSON(t, w)["workspace_id"]; got != wsB.WorkspaceID.String() {
		t.Fatalf("login resolved workspace %v, want B %s", got, wsB.WorkspaceID)
	}

	// Workspace A's password does not open workspace B.
	w = env.Do("POST", "/authsec/uflow/login", map[string]string{
		"email": shared, "password": wsA.AdminPassword, "workspace_domain": wsB.WorkspaceDomain,
	}, "")
	assertStatus(t, w, http.StatusUnauthorized)
}

func Test_TOTPLogin_ScopedToNamedWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	wsA, wsB, _ := seedTwoWorkspaces(t)

	// A's admin does not exist in B: naming B must not resolve A's user.
	w := env.Do("POST", "/authsec/uflow/auth/totp/login", map[string]string{
		"email": wsA.AdminEmail, "totp_code": "123456", "workspace_id": wsB.WorkspaceID.String(),
	}, "")
	assertStatus(t, w, http.StatusNotFound)
}
