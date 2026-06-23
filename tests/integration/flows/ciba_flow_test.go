//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Test_CIBA_BackchannelAuthorizePollRespond exercises the full native CIBA
// happy path: bc-authorize → end-user responds approved → SA polls token.
func Test_CIBA_BackchannelAuthorizePollRespond(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://rs-ciba-happy-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	cibaUser, err := AddCIBAUser(config.DB, ws, sa, n)
	if err != nil {
		t.Fatalf("AddCIBAUser: %v", err)
	}

	// Step 1: bc-authorize — SA authenticates via Basic auth; login_hint is the
	// CIBA user's email. Expect 200 with auth_req_id.
	bcBody := formBody(
		"login_hint", cibaUser.Email,
		"scope", "openid",
		"resource", rs.ResourceURI,
	)
	bcResp := env.DoBasicAuth("POST", "/oauth/bc-authorize", bcBody, sa.ClientIDString, sa.ClientSecret)
	if bcResp.Code != http.StatusOK {
		t.Fatalf("bc-authorize: expected 200, got %d: %s", bcResp.Code, readBody(bcResp))
	}
	authReqID := extractAuthReqID(t, bcResp)
	if authReqID == "" {
		t.Fatal("bc-authorize: auth_req_id missing from response")
	}

	// Step 2: end-user approves — POST /authsec/uflow/auth/workspace/ciba/respond
	// with a JWT for the CIBA user.
	userTok := env.MustAsUser(cibaUser.UserID, ws.WorkspaceID, cibaUser.Email)
	respondBody := map[string]interface{}{
		"auth_req_id":        authReqID,
		"approved":           true,
		"biometric_verified": false,
	}
	respondResp := env.Do("POST", "/authsec/uflow/auth/workspace/ciba/respond", respondBody, userTok)
	if respondResp.Code != http.StatusOK {
		t.Fatalf("ciba/respond: expected 200, got %d: %s", respondResp.Code, readBody(respondResp))
	}
	var respondJSON map[string]interface{}
	if err := json.NewDecoder(respondResp.Body).Decode(&respondJSON); err != nil {
		t.Fatalf("ciba/respond: decode body: %v", err)
	}
	if respondJSON["success"] != true {
		t.Errorf("ciba/respond: expected success=true, got body=%v", respondJSON)
	}

	// Step 3: SA polls /oauth/token — must get 200 with access_token now that
	// the request is approved.
	pollBody := formBody(
		"grant_type", "urn:openid:params:grant-type:ciba",
		"auth_req_id", authReqID,
		"resource", rs.ResourceURI,
	)
	pollResp := env.DoBasicAuth("POST", "/oauth/token", pollBody, sa.ClientIDString, sa.ClientSecret)
	if pollResp.Code != http.StatusOK {
		t.Fatalf("ciba token poll: expected 200, got %d: %s", pollResp.Code, readBody(pollResp))
	}
	var pollJSON map[string]interface{}
	if err := json.NewDecoder(pollResp.Body).Decode(&pollJSON); err != nil {
		t.Fatalf("ciba token poll: decode body: %v", err)
	}
	if pollJSON["access_token"] == nil || pollJSON["access_token"] == "" {
		t.Errorf("ciba token poll: expected access_token in response, got body=%v", pollJSON)
	}
}

// Test_CIBA_PollBeforeApproval verifies that polling /oauth/token with the CIBA
// grant type before the user responds returns 400 authorization_pending.
func Test_CIBA_PollBeforeApproval(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	rs, err := AddResourceServer(config.DB, ws, "https://rs-ciba-poll-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}

	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	cibaUser, err := AddCIBAUser(config.DB, ws, sa, n)
	if err != nil {
		t.Fatalf("AddCIBAUser: %v", err)
	}

	// Step 1: obtain auth_req_id — must succeed because the CIBA user has a device.
	bcBody := formBody(
		"login_hint", cibaUser.Email,
		"scope", "openid",
		"resource", rs.ResourceURI,
	)
	bcResp := env.DoBasicAuth("POST", "/oauth/bc-authorize", bcBody, sa.ClientIDString, sa.ClientSecret)
	if bcResp.Code != http.StatusOK {
		t.Fatalf("bc-authorize: expected 200, got %d: %s", bcResp.Code, readBody(bcResp))
	}
	authReqID := extractAuthReqID(t, bcResp)
	if authReqID == "" {
		t.Fatal("bc-authorize: auth_req_id missing from response")
	}

	// Step 2: poll immediately — user hasn't responded, so expect authorization_pending.
	pollBody := formBody(
		"grant_type", "urn:openid:params:grant-type:ciba",
		"auth_req_id", authReqID,
		"resource", rs.ResourceURI,
	)
	pollResp := env.DoBasicAuth("POST", "/oauth/token", pollBody, sa.ClientIDString, sa.ClientSecret)
	if pollResp.Code != http.StatusBadRequest {
		t.Errorf("ciba poll before approval: expected 400, got %d: %s", pollResp.Code, readBody(pollResp))
	}
	r := parseResp(pollResp)
	if r.Body["error"] != "authorization_pending" {
		t.Errorf("ciba poll before approval: expected error=authorization_pending, got body=%v", r.Body)
	}
}

// Test_CIBA_FlagOff_Note documents that flag-off tests live in flagsoff/.
func Test_CIBA_FlagOff_Note(t *testing.T) {
	t.Skip("flag-off test runs in flagsoff/ package")
}

// extractAuthReqID reads auth_req_id from a bc-authorize 200 response body.
func extractAuthReqID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&m); err != nil {
		t.Logf("extractAuthReqID: failed to decode response body: %v", err)
		return ""
	}
	v, ok := m["auth_req_id"]
	if !ok {
		t.Logf("extractAuthReqID: auth_req_id not found in body: %v", m)
		return ""
	}
	s, ok := v.(string)
	if !ok {
		t.Logf("extractAuthReqID: auth_req_id is not a string: %T", v)
		return ""
	}
	return s
}
