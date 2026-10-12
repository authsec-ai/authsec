//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-021: the token-exchange (ID-JAG issuance) grant must authenticate the
// client. Naming a client_id is not proof of being that client, and omitting
// client_id must not reach a nil client.

func setupTokenExchangeVictim(t *testing.T) (*testsupport.Env, string, *SAScenario) {
	t.Helper()
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	rs, err := AddResourceServer(config.DB, ws, "https://rs-txauth-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	subjectToken := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active":    true,
			"sub":       ws.AdminUserID.String(),
			"client_id": sa.ClientIDString,
			"ext": map[string]interface{}{
				"workspace_id": ws.WorkspaceID.String(),
			},
		}
	})
	t.Cleanup(env.Fakes.Hydra.ResetIntrospect)
	return env, subjectToken, sa
}

func tokenExchangeForm(subjectToken string, extra ...string) []string {
	return append([]string{
		"grant_type", tokenExchangeGrantType,
		"requested_token_type", idJAGTokenType,
		"subject_token", subjectToken,
		"subject_token_type", accessTokenType,
	}, extra...)
}

func assertInvalidClient(t *testing.T, code int, body string, r RespBody) {
	t.Helper()
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 invalid_client, got %d: %s", code, body)
	}
	if r.Body["error"] != "invalid_client" {
		t.Fatalf("expected error=invalid_client, got %v", r.Body)
	}
	if _, minted := r.Body["access_token"]; minted {
		t.Fatalf("an ID-JAG was minted without client authentication: %s", body)
	}
}

func Test_TokenExchange_BodyClientIDWithoutSecretRejected(t *testing.T) {
	env, subjectToken, sa := setupTokenExchangeVictim(t)

	w := env.Do(http.MethodPost, "/oauth/token",
		formBody(tokenExchangeForm(subjectToken, "client_id", sa.ClientIDString)...), "")
	body := readBody(w)
	assertInvalidClient(t, w.Code, body, parseResp(w))
}

func Test_TokenExchange_WrongClientSecretRejected(t *testing.T) {
	env, subjectToken, sa := setupTokenExchangeVictim(t)

	w := env.DoBasicAuth(http.MethodPost, "/oauth/token",
		formBody(tokenExchangeForm(subjectToken)...), sa.ClientIDString, "not-the-secret")
	body := readBody(w)
	assertInvalidClient(t, w.Code, body, parseResp(w))
}

func Test_TokenExchange_OmittedClientIDNoPanic(t *testing.T) {
	env, subjectToken, _ := setupTokenExchangeVictim(t)

	// client_assertion_type lets the dispatcher skip the client_id check; with no
	// assertion the handler used to dereference a nil client.
	w := env.Do(http.MethodPost, "/oauth/token",
		formBody(tokenExchangeForm(subjectToken,
			"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")...), "")
	body := readBody(w)
	assertInvalidClient(t, w.Code, body, parseResp(w))
}

func Test_TokenExchange_BodyClientIDMustMatchAuthenticatedClient(t *testing.T) {
	env, subjectToken, sa := setupTokenExchangeVictim(t)
	n := emailSafeNonce()

	// A second, legitimately authenticated client may not claim the first
	// client's identity through the body client_id.
	ws2, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin(2): %v", err)
	}
	rs2, err := AddResourceServer(config.DB, ws2, "https://rs-txauth2-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer(2): %v", err)
	}
	other, err := AddServiceAccountWithScopes(config.DB, ws2, rs2, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes(2): %v", err)
	}

	w := env.DoBasicAuth(http.MethodPost, "/oauth/token",
		formBody(tokenExchangeForm(subjectToken, "client_id", sa.ClientIDString)...),
		other.ClientIDString, other.ClientSecret)
	body := readBody(w)
	if w.Code == http.StatusOK {
		t.Fatalf("expected rejection when body client_id differs from the authenticated client, got 200: %s", body)
	}
}

func Test_TokenExchange_AuthenticatedClientStillIssues(t *testing.T) {
	env, subjectToken, sa := setupTokenExchangeVictim(t)

	w := env.DoBasicAuth(http.MethodPost, "/oauth/token",
		formBody(tokenExchangeForm(subjectToken)...), sa.ClientIDString, sa.ClientSecret)
	assertStatus(t, w, http.StatusOK)
}
