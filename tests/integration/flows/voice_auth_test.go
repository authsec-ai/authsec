//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-047: voice auth works again (its table exists and the workspace comes
// from the authenticated voice client), and a voice session cannot be used
// across clients or workspaces.
func Test_VoiceAuth_ClientAuthenticatedAndWorkspaceScoped(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)
	a, b := TwoTenants(t)
	rsA, err := AddResourceServer(config.DB, a.WS, "https://voice-a-"+n+".example.com", "va"+n)
	if err != nil {
		t.Fatalf("rs A: %v", err)
	}
	skillA, err := AddServiceAccountWithScopes(config.DB, a.WS, rsA, "va"+n)
	if err != nil {
		t.Fatalf("voice client A: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, b.WS, "https://voice-b-"+n+".example.com", "vb"+n)
	if err != nil {
		t.Fatalf("rs B: %v", err)
	}
	skillB, err := AddServiceAccountWithScopes(config.DB, b.WS, rsB, "vb"+n)
	if err != nil {
		t.Fatalf("voice client B: %v", err)
	}

	const base = "/authsec/uflow/auth/voice"
	initiate := func(body map[string]interface{}, id, secret string) (int, map[string]interface{}) {
		w := env.DoBasicAuth("POST", base+"/initiate", body, id, secret)
		var m map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}

	// Anonymous callers cannot start a voice session any more.
	if w := env.Do("POST", base+"/initiate", map[string]interface{}{"client_id": skillA.ClientID.String()}, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous initiate: got %d, want 401", w.Code)
	}

	// The workspace's voice client starts a session; it lives in that workspace.
	code, init := initiate(map[string]interface{}{"voice_platform": "web"}, skillA.ClientIDString, skillA.ClientSecret)
	if code != http.StatusOK || init["session_token"] == nil {
		t.Fatalf("initiate as A's client: %d %v", code, init)
	}
	session, _ := init["session_token"].(string)
	var ws string
	config.DB.Raw(`SELECT workspace_id::text FROM voice_sessions WHERE session_token = ?`, session).Scan(&ws)
	if ws != a.WS.WorkspaceID.String() {
		t.Fatalf("voice session stored in workspace %q, want A", ws)
	}

	// Another workspace's client cannot redeem it, even with valid user credentials.
	creds := map[string]interface{}{"session_token": session, "email": a.EndUser.Email, "password": a.EndUser.Password}
	if w := env.DoBasicAuth("POST", base+"/token", creds, skillB.ClientIDString, skillB.ClientSecret); w.Code == http.StatusOK {
		t.Fatalf("B's client redeemed A's voice session: %s", w.Body.String())
	}
	// B's user's credentials do not work in A's session either.
	wrongUser := map[string]interface{}{"session_token": session, "email": b.EndUser.Email, "password": b.EndUser.Password}
	if w := env.DoBasicAuth("POST", base+"/token", wrongUser, skillA.ClientIDString, skillA.ClientSecret); w.Code == http.StatusOK {
		t.Fatalf("a user of B signed in through A's voice session: %s", w.Body.String())
	}

	// The owning client with A's user's credentials gets a token for A.
	w := env.DoBasicAuth("POST", base+"/token", creds, skillA.ClientIDString, skillA.ClientSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("voice token as A's client: %d %s", w.Code, w.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tok)
	if tok.AccessToken == "" {
		t.Fatalf("no voice access token: %s", w.Body.String())
	}

	// A voice identity linked in A is only honoured for A's client.
	link := map[string]interface{}{"voice_platform": "alexa", "voice_user_id": "amzn-" + n}
	if w := env.Do("POST", base+"/link", link, a.EndUserToken); w.Code >= 300 {
		t.Fatalf("link voice identity in A: %d %s", w.Code, w.Body.String())
	}
	_, initB := initiate(map[string]interface{}{"voice_platform": "alexa", "voice_user_id": "amzn-" + n}, skillB.ClientIDString, skillB.ClientSecret)
	sessB, _ := initB["session_token"].(string)
	otpB, _ := initB["voice_otp"].(string)
	w = env.DoBasicAuth("POST", base+"/verify", map[string]interface{}{"session_token": sessB, "voice_otp": otpB}, skillB.ClientIDString, skillB.ClientSecret)
	var verifyB map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &verifyB)
	if at, _ := verifyB["access_token"].(string); at != "" {
		t.Fatalf("B's client obtained A's linked user's token through a voice identity: %s", w.Body.String())
	}

	// The active-session table exists (it did not before 053).
	var exists bool
	config.DB.Raw(`SELECT to_regclass('public.voice_active_sessions') IS NOT NULL`).Scan(&exists)
	if !exists {
		t.Fatalf("voice_active_sessions table missing")
	}
}
