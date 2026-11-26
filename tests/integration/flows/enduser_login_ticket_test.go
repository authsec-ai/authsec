//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/logintickets"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Regression tests for AS-002 (anonymous end-user token mint via
// webauthn-callback), the end-user half of AS-003/AS-004 (anonymous WebAuthn
// and TOTP enrolment for any user), and AS-029 (the anonymous SAML login
// check is not a first factor).

const endUserCallbackPath = "/authsec/uflow/auth/enduser/webauthn-callback"

func endUserPasswordLogin(t *testing.T, env *testsupport.Env, u *EndUserScenario) string {
	t.Helper()
	w := env.Do("POST", "/authsec/uflow/user/login", map[string]string{
		"email":        u.Email,
		"password":     u.Password,
		"workspace_id": u.WorkspaceID.String(),
	}, "")
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		LoginTicket string `json:"login_ticket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.LoginTicket == "" {
		t.Fatalf("end-user password login must return a login_ticket; body: %s", w.Body.String())
	}
	return resp.LoginTicket
}

func seedEndUser(t *testing.T) (*WorkspaceScenario, *EndUserScenario) {
	t.Helper()
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	u, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatalf("seed end user: %v", err)
	}
	return ws, u
}

// AS-002: email + workspace_id + mfa_verified:true must not mint a token.
func Test_EndUserWebAuthnCallback_RejectsUnticketedRequest(t *testing.T) {
	env := testsupport.Get(t)
	_, u := seedEndUser(t)
	forged := map[string]interface{}{
		"email":        u.Email,
		"mfa_verified": true,
		"workspace_id": u.WorkspaceID.String(),
	}
	assertStatus(t, env.Do("POST", endUserCallbackPath, forged, ""), http.StatusUnauthorized)
	assertStatus(t, doWithTicket(env, "POST", endUserCallbackPath, forged, "bogus"), http.StatusUnauthorized)

	// A first-factor ticket without a verified second factor is not enough.
	ticket := endUserPasswordLogin(t, env, u)
	assertStatus(t, doWithTicket(env, "POST", endUserCallbackPath, forged, ticket), http.StatusUnauthorized)
}

func Test_EndUserWebAuthnCallback_MintsOnceForTicketSubject(t *testing.T) {
	env := testsupport.Get(t)
	_, u := seedEndUser(t)
	_, other := seedEndUser(t)
	ticket := endUserPasswordLogin(t, env, u)
	if err := logintickets.MarkMFAVerified(config.GetDatabase().DB, ticket); err != nil {
		t.Fatalf("mark verified: %v", err)
	}

	body := map[string]interface{}{"email": other.Email, "workspace_id": other.WorkspaceID.String(), "mfa_verified": true}
	w := doWithTicket(env, "POST", endUserCallbackPath, body, ticket)
	assertStatus(t, w, http.StatusOK)
	var resp struct {
		AccessToken string `json:"access_token"`
		WorkspaceID string `json:"workspace_id"`
		Email       string `json:"email"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" || resp.WorkspaceID != u.WorkspaceID.String() || resp.Email != u.Email {
		t.Fatalf("token must be for the ticket's subject, got %+v", resp)
	}
	assertStatus(t, doWithTicket(env, "POST", endUserCallbackPath, body, ticket), http.StatusUnauthorized)

	// An admin-realm ticket cannot be spent on the end-user callback.
	ws, _ := seedEndUser(t)
	adminTicket, err := logintickets.Issue(config.GetDatabase().DB, logintickets.RealmAdmin, ws.WorkspaceID, ws.AdminUserID, ws.AdminEmail, "password")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_ = logintickets.MarkMFAVerified(config.GetDatabase().DB, adminTicket)
	assertStatus(t, doWithTicket(env, "POST", endUserCallbackPath, map[string]interface{}{}, adminTicket), http.StatusUnauthorized)
}

// End-user half of AS-003/AS-004.
func Test_EndUserMFASteps_RequireTicketForSameSubject(t *testing.T) {
	env := testsupport.Get(t)
	_, u := seedEndUser(t)
	_, victim := seedEndUser(t)

	gated := []string{
		"/authsec/webauthn/enduser/beginRegistration",
		"/authsec/webauthn/enduser/finishRegistration",
		"/authsec/webauthn/enduser/beginAuthentication",
		"/authsec/webauthn/enduser/finishAuthentication",
		"/authsec/webauthn/totp/beginSetup",
		"/authsec/webauthn/totp/confirmSetup",
		"/authsec/webauthn/totp/verify",
	}
	target := map[string]interface{}{"email": victim.Email, "workspace_id": victim.WorkspaceID.String()}
	for _, path := range gated {
		if w := env.Do("POST", path, target, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without ticket: got %d, want 401", path, w.Code)
		}
	}
	ticket := endUserPasswordLogin(t, env, u)
	for _, path := range gated {
		if w := doWithTicket(env, "POST", path, target, ticket); w.Code != http.StatusForbidden {
			t.Errorf("%s with another user's ticket: got %d, want 403", path, w.Code)
		}
	}
	own := map[string]interface{}{"email": u.Email, "workspace_id": u.WorkspaceID.String()}
	if w := doWithTicket(env, "POST", "/authsec/webauthn/enduser/beginRegistration", own, ticket); w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("own beginRegistration rejected: %d %s", w.Code, w.Body.String())
	}
	if w := env.Do("POST", "/authsec/webauthn/enduser/mfa/loginStatus", own, ""); w.Code == http.StatusUnauthorized {
		t.Errorf("enduser mfa/loginStatus must stay reachable for the SDK")
	}
}

// AS-029: the anonymous SAML login check names a user but proves nothing, so
// it must never hand out a ticket.
func Test_SAMLLoginCheck_DoesNotIssueTicket(t *testing.T) {
	env := testsupport.Get(t)
	_, u := seedEndUser(t)
	w := env.Do("POST", "/authsec/uflow/user/saml/login", map[string]string{
		"email":        u.Email,
		"workspace_id": u.WorkspaceID.String(),
	}, "")
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp[logintickets.ResponseField]; ok {
		t.Fatalf("saml/login must not issue a login ticket; body: %s", w.Body.String())
	}
}
