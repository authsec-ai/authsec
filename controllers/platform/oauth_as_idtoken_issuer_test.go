package platform

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
	"github.com/authsec-ai/authsec/services"
	"github.com/golang-jwt/jwt/v5"
)

// The id_token browser login returns is Hydra's: Hydra signs it with its own
// keys and stamps its own issuer (https://oauth.prod.authsec.ai), which is not
// the AS's (https://prod.api.authsec.ai). Token exchange with
// subject_token_type=id_token refused every such token with "id_token issuer
// mismatch". These tests pin the fix: Hydra's issuer is accepted with Hydra's
// keys, the AS's own issuer still is, and nothing else.

const (
	testASIssuer    = "https://api.test.example"
	testHydraIssuer = "https://oauth.test.example"
	testClientID    = "agent-client"
)

type fakeHydra struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	issuer string
	down   bool
}

func newFakeHydra(t *testing.T, issuer string) *fakeHydra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHydra{key: key, kid: "hydra-key-1", issuer: issuer}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.down {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": h.issuer})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{rsaJWK(h.kid, &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kid": kid, "kty": "RSA", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, kid, iss string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":          iss,
		"aud":          []string{testClientID},
		"sub":          "8b0c6a52-3a52-4a4c-9d0e-3f6b6b1f0c11",
		"workspace_id": "5d2f4e1a-7c3b-4f8e-9a6d-2b1c0e9f8a77",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"iat":          time.Now().Unix(),
	})
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func idTokenController(t *testing.T, h *fakeHydra) *OAuthASController {
	t.Helper()
	withAppConfig(t, &config.Config{OAuthIssuerURL: testASIssuer, HydraPublicURL: h.srv.URL})
	return &OAuthASController{service: services.NewOAuthASService(nil)}
}

func TestVerifyIDToken_AcceptsHydraIssuer(t *testing.T) {
	for _, iss := range []string{testHydraIssuer, testHydraIssuer + "/"} {
		h := newFakeHydra(t, testHydraIssuer)
		ctrl := idTokenController(t, h)
		claims, err := ctrl.verifySelfIssuedIDToken(signIDToken(t, h.key, h.kid, iss), testClientID)
		if err != nil {
			t.Fatalf("iss %q: %v, want the Hydra-issued id_token accepted", iss, err)
		}
		if claims["sub"] == "" {
			t.Fatalf("iss %q: claims %v, want sub", iss, claims)
		}
	}
}

func TestVerifyIDToken_StillAcceptsTheASIssuer(t *testing.T) {
	h := newFakeHydra(t, testHydraIssuer)
	ctrl := idTokenController(t, h)
	// With XAA_NATIVE_SEALER off the AS's key set is Hydra's, as before the fix.
	if _, err := ctrl.verifySelfIssuedIDToken(signIDToken(t, h.key, h.kid, testASIssuer), testClientID); err != nil {
		t.Fatalf("AS-issued id_token: %v, want accepted as before", err)
	}
}

func TestVerifyIDToken_RefusesAnyOtherIssuer(t *testing.T) {
	h := newFakeHydra(t, testHydraIssuer)
	ctrl := idTokenController(t, h)
	for _, iss := range []string{"https://evil.example", "", "https://oauth.test.example.evil"} {
		_, err := ctrl.verifySelfIssuedIDToken(signIDToken(t, h.key, h.kid, iss), testClientID)
		if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
			t.Errorf("iss %q: err = %v, want id_token issuer mismatch", iss, err)
		}
	}
}

func TestVerifyIDToken_HydraIssuerNeedsHydrasKey(t *testing.T) {
	h := newFakeHydra(t, testHydraIssuer)
	ctrl := idTokenController(t, h)
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{h.kid, "rogue-key"} {
		if _, err := ctrl.verifySelfIssuedIDToken(signIDToken(t, rogue, kid, testHydraIssuer), testClientID); err == nil {
			t.Errorf("kid %q: a token claiming Hydra's issuer but not signed by Hydra was accepted", kid)
		}
	}
}

func TestVerifyIDToken_HydraUnreachableFailsClosed(t *testing.T) {
	h := newFakeHydra(t, testHydraIssuer)
	h.down = true
	ctrl := idTokenController(t, h)
	_, err := ctrl.verifySelfIssuedIDToken(signIDToken(t, h.key, h.kid, testHydraIssuer), testClientID)
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("err = %v, want id_token issuer mismatch while Hydra's issuer cannot be read", err)
	}
}

// EndSession verifies id_token_hint against Hydra's keys; before the fix the
// AS issuer it expected could never match, so logout never learned the subject.
func TestVerifyIDTokenHint_AcceptsHydraIssuer(t *testing.T) {
	h := newFakeHydra(t, testHydraIssuer)
	withAppConfig(t, &config.Config{OAuthIssuerURL: testASIssuer, HydraPublicURL: h.srv.URL})
	svc := services.NewOAuthASService(nil)
	sub, err := svc.VerifyIDTokenHint(signIDToken(t, h.key, h.kid, testHydraIssuer), testASIssuer, testClientID)
	if err != nil || sub == "" {
		t.Fatalf("VerifyIDTokenHint = %q, %v; want the subject of Hydra's id_token", sub, err)
	}
	if _, err := svc.VerifyIDTokenHint(signIDToken(t, h.key, h.kid, "https://evil.example"), testASIssuer, testClientID); err == nil {
		t.Fatal("VerifyIDTokenHint accepted a third issuer")
	}
}
