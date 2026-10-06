//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AS-066: an ID-JAG must carry exp, and its kid must name a key in the
// issuer's JWKS (no fallback to "any key").
func Test_IDJAG_RequiresExpAndKnownKid(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws := seedWorkspace(t, n)
	rs, err := AddResourceServer(config.DB, ws, "https://rs-"+n+".example.com", n)
	if err != nil {
		t.Fatalf("rs: %v", err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatalf("sa: %v", err)
	}
	provider := "corp-" + n
	mustExec(t, `INSERT INTO oidc_user_identities (workspace_id, user_id, provider_name, provider_user_id, email)
		VALUES (?, ?, ?, 'self', ?)`, ws.WorkspaceID, ws.AdminUserID, provider, ws.AdminEmail)
	ei := startExternalIssuer(t)
	iss := ei.base + "/idp"
	mustExec(t, `INSERT INTO trusted_issuers (iss, jwks_uri, provider_name, workspace_id) VALUES (?, ?, ?, ?)`,
		iss, ei.base+"/jwks", provider, ws.WorkspaceID)

	selfIssuer := config.AppConfig.OAuthBaseURL()
	redeem := func(kid string, withExp bool) (int, string) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": iss, "sub": "self", "aud": selfIssuer, "client_id": sa.ClientIDString,
			"jti": uuid.NewString(), "iat": now.Unix(),
		}
		if withExp {
			claims["exp"] = now.Add(5 * time.Minute).Unix()
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tok.Header["typ"] = "oauth-id-jag+jwt"
		idjag, err := tok.SignedString(ei.key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		w := env.DoBasicAuth(http.MethodPost, "/oauth/token", formBody(
			"grant_type", jwtBearerGrantType,
			"assertion", idjag,
			"resource", rs.ResourceURI,
			"scope", rs.ScopeStrings[0],
		), sa.ClientIDString, sa.ClientSecret)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		desc, _ := body["error_description"].(string)
		return w.Code, desc
	}

	if code, desc := redeem(ei.kid, false); code < 400 || !strings.Contains(desc, "signature/expiry") {
		t.Fatalf("ID-JAG without exp accepted: %d %q", code, desc)
	}
	if code, desc := redeem("not-"+ei.kid, true); code < 400 || !strings.Contains(desc, "signature/expiry") {
		t.Fatalf("ID-JAG with an unknown kid accepted: %d %q", code, desc)
	}
	// Control: the well-formed ID-JAG passes signature verification.
	if _, desc := redeem(ei.kid, true); strings.Contains(desc, "signature/expiry") {
		t.Fatalf("well-formed ID-JAG refused: %q", desc)
	}
}
