//go:build integration

package flows

import (
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// The token endpoint's follow-up writes and the native introspection role
// lookup run in the authenticated principal's workspace, on the scoped layer.
func Test_OAuthAS_ClientCredentials_ScopedFollowUps(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("AddResourceServer: %v", err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("AddServiceAccountWithScopes: %v", err)
	}

	w := env.DoBasicAuth("POST", "/oauth/token", formBody(
		"grant_type", "client_credentials", "scope", "read:"+n, "resource", rs.ResourceURI,
	), sa.ClientIDString, sa.ClientSecret)
	assertStatus(t, w, http.StatusOK)
	m := parseBody(t, w)
	tok, _ := m["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token: %s", readBody(w))
	}

	var lastSeen *time.Time
	config.DB.Raw(`SELECT last_seen_at FROM service_accounts WHERE id = $1`, sa.SAID).Row().Scan(&lastSeen)
	if lastSeen == nil {
		t.Fatalf("service account last_seen_at not recorded after client_credentials")
	}

	w = env.DoBasicAuth("POST", "/oauth/introspect", formBody("token", tok), rs.RSID.String(), rs.IntrospectionSecret)
	assertStatus(t, w, http.StatusOK)
	resp := parseBody(t, w)
	if resp["active"] != true {
		t.Fatalf("introspection inactive: %s", readBody(w))
	}
	// The native path reports the RS-scoped role bindings of the subject.
	list, _ := resp["role_ids"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("native introspection must report the service account's RS role binding: %s", readBody(w))
	}
}
