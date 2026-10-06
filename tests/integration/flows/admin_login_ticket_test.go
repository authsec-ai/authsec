//go:build integration

package flows

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/logintickets"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// These tests pin the admin sign-in chain: first factor -> login ticket ->
// MFA step for that subject only -> verified ticket -> one session token.
// They are the regression tests for AS-001 (anonymous admin token mint via
// webauthn-callback) and the admin half of AS-003 (anonymous WebAuthn
// enrolment for any user).

const adminCallbackPath = "/authsec/uflow/login/webauthn-callback"

func doWithTicket(env *testsupport.Env, method, path string, body interface{}, ticket string) *httptest.ResponseRecorder {
	bs, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(bs))
	req.Header.Set("Content-Type", "application/json")
	if ticket != "" {
		req.Header.Set(logintickets.HeaderName, ticket)
	}
	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)
	return w
}

func adminPasswordLogin(t *testing.T, env *testsupport.Env, ws *WorkspaceScenario) string {
	t.Helper()
	w := env.Do("POST", "/authsec/uflow/login", map[string]string{
		"email":            ws.AdminEmail,
		"password":         ws.AdminPassword,
		"workspace_domain": ws.WorkspaceDomain,
	}, "")
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		LoginTicket string `json:"login_ticket"`
		WorkspaceID string `json:"workspace_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v (%s)", err, w.Body.String())
	}
	if resp.LoginTicket == "" {
		t.Fatalf("password login must return a login_ticket; body: %s", w.Body.String())
	}
	if resp.WorkspaceID != ws.WorkspaceID.String() {
		t.Fatalf("login returned workspace %s, want %s", resp.WorkspaceID, ws.WorkspaceID)
	}
	return resp.LoginTicket
}

// AS-001: the body alone (workspace_id + mfa_verified:true) must not mint a token.
func Test_AdminWebAuthnCallback_RejectsUnticketedRequest(t *testing.T) {
	env := testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	forged := map[string]interface{}{
		"email":        "attacker@example.com",
		"mfa_verified": true,
		"workspace_id": ws.WorkspaceID.String(),
	}

	w := env.Do("POST", adminCallbackPath, forged, "")
	assertStatus(t, w, http.StatusUnauthorized)

	w = doWithTicket(env, "POST", adminCallbackPath, forged, "not-a-real-ticket")
	assertStatus(t, w, http.StatusUnauthorized)
}

// A ticket proves the first factor only; it cannot mint a token until a
// second factor has been verified.
func Test_AdminWebAuthnCallback_RequiresSecondFactor(t *testing.T) {
	env := testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	ticket := adminPasswordLogin(t, env, ws)

	w := doWithTicket(env, "POST", adminCallbackPath, map[string]interface{}{"mfa_verified": true}, ticket)
	assertStatus(t, w, http.StatusUnauthorized)
}

// A verified ticket mints exactly one token, for the ticket's subject, no
// matter which workspace or email the body names.
func Test_AdminWebAuthnCallback_MintsOnceForTicketSubject(t *testing.T) {
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
	ticket := adminPasswordLogin(t, env, wsA)
	if err := logintickets.MarkMFAVerified(config.GetDatabase().DB, ticket); err != nil {
		t.Fatalf("mark verified: %v", err)
	}

	body := map[string]interface{}{
		"email":        wsB.AdminEmail,
		"mfa_verified": true,
		"workspace_id": wsB.WorkspaceID.String(),
	}
	w := doWithTicket(env, "POST", adminCallbackPath, body, ticket)
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		AccessToken string `json:"access_token"`
		WorkspaceID string `json:"workspace_id"`
		Email       string `json:"email"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" || resp.WorkspaceID != wsA.WorkspaceID.String() || resp.Email != wsA.AdminEmail {
		t.Fatalf("token must be for the ticket's subject (workspace A), got %+v", resp)
	}

	// Single use.
	w = doWithTicket(env, "POST", adminCallbackPath, body, ticket)
	assertStatus(t, w, http.StatusUnauthorized)
}

// AS-003 (admin half): enrolment and verification steps need a ticket or a
// session, and may only act for that subject.
func Test_AdminWebAuthnSteps_RequireTicketForSameSubject(t *testing.T) {
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

	gated := []string{
		"/authsec/webauthn/admin/beginRegistration",
		"/authsec/webauthn/admin/finishRegistration",
		"/authsec/webauthn/admin/beginAuthentication",
		"/authsec/webauthn/admin/finishAuthentication",
		"/authsec/webauthn/beginRegistration",
		"/authsec/webauthn/finishRegistration",
		"/authsec/webauthn/biometric/beginSetup",
		"/authsec/webauthn/biometric/beginLoginSetup",
		"/authsec/webauthn/totp/beginLoginSetup",
		"/authsec/webauthn/totp/verifyLogin",
		"/authsec/webauthn/sms/beginSetup",
		"/authsec/webauthn/sms/verify",
	}
	victim := map[string]interface{}{"email": wsB.AdminEmail, "workspace_id": wsB.WorkspaceID.String()}
	for _, path := range gated {
		if w := env.Do("POST", path, victim, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without ticket: got %d, want 401 (body %s)", path, w.Code, w.Body.String())
		}
	}

	ticketA := adminPasswordLogin(t, env, wsA)
	for _, path := range gated {
		if w := doWithTicket(env, "POST", path, victim, ticketA); w.Code != http.StatusForbidden {
			t.Errorf("%s with A's ticket for B's account: got %d, want 403 (body %s)", path, w.Code, w.Body.String())
		}
	}

	// The ticket's own subject is admitted (the handler may still reject the
	// payload, but not as unauthenticated or forbidden).
	own := map[string]interface{}{"email": wsA.AdminEmail}
	w := doWithTicket(env, "POST", "/authsec/webauthn/admin/beginRegistration", own, ticketA)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("own beginRegistration rejected: %d %s", w.Code, w.Body.String())
	}

	// A session for A is equally scoped to A.
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	if w := env.Do("POST", "/authsec/webauthn/admin/beginRegistration", victim, tokA); w.Code != http.StatusForbidden {
		t.Errorf("A's session acting for B: got %d, want 403", w.Code)
	}

	// Status lookups stay open for the SDK.
	if w := env.Do("POST", "/authsec/webauthn/admin/mfa/loginStatus", own, ""); w.Code == http.StatusUnauthorized {
		t.Errorf("mfa/loginStatus must stay reachable without a ticket, got 401")
	}
}

// A 2xx from a verification step marks the ticket; registration-type steps
// and failed verifications do not.
func Test_LoginSubject_MarksSecondFactorOnlyOnVerifySuccess(t *testing.T) {
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	db := config.GetDatabase().DB
	issue := func() string {
		v, err := logintickets.Issue(db, logintickets.RealmAdmin, ws.WorkspaceID, ws.AdminUserID, ws.AdminEmail, "password")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return v
	}

	r := gin.New()
	r.POST("/verify-ok", middlewares.RequireLoginSubject(logintickets.RealmAdmin, true), func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/verify-bad", middlewares.RequireLoginSubject(logintickets.RealmAdmin, true), func(c *gin.Context) { c.Status(http.StatusBadRequest) })
	r.POST("/setup-ok", middlewares.RequireLoginSubject(logintickets.RealmAdmin, false), func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/enduser-only", middlewares.RequireLoginSubject(logintickets.RealmEndUser, true), func(c *gin.Context) { c.Status(http.StatusOK) })

	call := func(path, ticket string) int {
		req := httptest.NewRequest("POST", path, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(logintickets.HeaderName, ticket)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	verified := func(ticket string) bool {
		tk, err := logintickets.Lookup(db, ticket)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		return tk.MFAVerified()
	}

	for _, tc := range []struct {
		path string
		code int
		want bool
	}{
		{"/verify-ok", http.StatusOK, true},
		{"/verify-bad", http.StatusBadRequest, false},
		{"/setup-ok", http.StatusOK, false},
	} {
		tk := issue()
		if got := call(tc.path, tk); got != tc.code {
			t.Fatalf("%s: status %d, want %d", tc.path, got, tc.code)
		}
		if got := verified(tk); got != tc.want {
			t.Errorf("%s: verified=%v, want %v", tc.path, got, tc.want)
		}
	}

	if got := call("/enduser-only", issue()); got != http.StatusUnauthorized {
		t.Errorf("admin ticket on an end-user step: got %d, want 401", got)
	}
}

// emailSafeNonce is unique per call and valid inside an email domain
// (testsupport.TestNonce keeps underscores, which email validation rejects).
func emailSafeNonce() string {
	return "lt" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
}
