package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMCPOAuthDiscovery_AdvertisesMCPRequiredFields verifies the discovery
// document meets the fields mcp-auth.dev (and the MCP spec) require.
//
// This is a pure unit test — no AppConfig load, no DB, no SPIRE. The
// controller only depends on a base URL string.
func TestMCPOAuthDiscovery_AdvertisesMCPRequiredFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Setenv("OAUTH_PUBLIC_BASE_URL", "https://prod.api.authsec.ai")
	ctrl := NewMCPOAuthDiscoveryController(nil)

	r := gin.New()
	r.GET("/authsec/oauth/.well-known/openid-configuration", ctrl.Discovery)
	r.GET("/authsec/oauth/.well-known/oauth-authorization-server", ctrl.Discovery)

	for _, path := range []string{
		"/authsec/oauth/.well-known/openid-configuration",
		"/authsec/oauth/.well-known/oauth-authorization-server",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d (body: %s)", path, rr.Code, rr.Body.String())
		}

		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: invalid JSON: %v", path, err)
		}

		// 1. Issuer must equal the host root + /authsec/oauth (RFC 8414 §3.3).
		wantIssuer := "https://prod.api.authsec.ai/authsec/oauth"
		if got, _ := doc["issuer"].(string); got != wantIssuer {
			t.Errorf("%s: issuer = %q, want %q", path, got, wantIssuer)
		}

		// 2. MCP required endpoints must be present and on the same host.
		for _, key := range []string{
			"authorization_endpoint",
			"token_endpoint",
			"jwks_uri",
		} {
			v, _ := doc[key].(string)
			if v == "" {
				t.Errorf("%s: missing %s", path, key)
			}
			if !strings.HasPrefix(v, "https://prod.api.authsec.ai/") {
				t.Errorf("%s: %s = %q, expected absolute URL on the configured host", path, key, v)
			}
		}

		// 3. PKCE: S256 must be supported (MCP forbids 'plain').
		if !contains(doc["code_challenge_methods_supported"], "S256") {
			t.Errorf("%s: code_challenge_methods_supported missing 'S256'", path)
		}

		// 4. Authorization-code flow only — must not advertise implicit/ROPC.
		grants := toStringSlice(doc["grant_types_supported"])
		if !sliceContains(grants, "authorization_code") {
			t.Errorf("%s: grant_types_supported missing 'authorization_code'", path)
		}
		for _, bad := range []string{"implicit", "password"} {
			if sliceContains(grants, bad) {
				t.Errorf("%s: grant_types_supported MUST NOT include %q", path, bad)
			}
		}

		// 5. response_types must include 'code' and must NOT include 'id_token' or 'token'.
		resp := toStringSlice(doc["response_types_supported"])
		if !sliceContains(resp, "code") {
			t.Errorf("%s: response_types_supported missing 'code'", path)
		}
		for _, bad := range []string{"id_token", "token", "code id_token"} {
			if sliceContains(resp, bad) {
				t.Errorf("%s: response_types_supported MUST NOT include %q (MCP forbids implicit)", path, bad)
			}
		}

		// 6. Resource indicators advertised (RFC 8707).
		if v, _ := doc["resource_indicators_supported"].(bool); !v {
			t.Errorf("%s: resource_indicators_supported should be true", path)
		}
	}
}

func contains(v any, want string) bool {
	for _, s := range toStringSlice(v) {
		if s == want {
			return true
		}
	}
	return false
}

func sliceContains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func toStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
