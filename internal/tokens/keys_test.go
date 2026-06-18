package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNativeKeyManager_EphemeralKeyset(t *testing.T) {
	m := NewNativeKeyManager(nil) // nil Vault → ephemeral

	kids := m.NativeKeyIDs()
	if len(kids) != 2 {
		t.Fatalf("expected active+next = 2 kids, got %d", len(kids))
	}
	for kid := range kids {
		if !strings.HasPrefix(kid, NativeKIDPrefix) {
			t.Fatalf("kid %q missing %q prefix", kid, NativeKIDPrefix)
		}
		if strings.Contains(kid, "workspace") {
			t.Fatalf("kid %q must not leak workspace info", kid)
		}
	}

	jwks := m.PublicJWKS()
	if len(jwks) != 2 {
		t.Fatalf("expected 2 JWKs, got %d", len(jwks))
	}
	for _, k := range jwks {
		if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
			t.Fatalf("unexpected JWK shape: %+v", k)
		}
		if _, ok := k["kid"]; !ok {
			t.Fatalf("JWK missing kid: %+v", k)
		}
	}
}

func TestNativeKeyManager_SignAndVerify(t *testing.T) {
	m := NewNativeKeyManager(nil)

	signed, err := m.Sign(jwt.MapClaims{"sub": "svc-1", "jti": "j1"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The signed token's kid must be in the published native set.
	cls := Classify(signed, m.NativeKeyIDs())
	if cls.Family != FamilyNative {
		t.Fatalf("signed token should classify native, got %v", cls.Family)
	}

	// And it must verify against the public key for that kid.
	pub, ok := m.PublicKeyForKID(cls.Kid)
	if !ok {
		t.Fatalf("no public key for kid %q", cls.Kid)
	}
	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (interface{}, error) { return pub, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("native token should verify against its own public key: err=%v", err)
	}
}

// Core forgery guarantee: a token bearing a real native kid but signed by a
// DIFFERENT key must FAIL verification against the published public key. This is
// what introspectNative relies on to return active:false (never a Hydra retry).
func TestNativeKeyManager_ForgedSignatureRejected(t *testing.T) {
	m := NewNativeKeyManager(nil)
	var activeKid string
	for kid := range m.NativeKeyIDs() {
		activeKid = kid
		break
	}

	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "attacker"})
	tok.Header["kid"] = activeKid // claim a real native kid
	forged, err := tok.SignedString(attacker)
	if err != nil {
		t.Fatalf("sign forged: %v", err)
	}

	pub, ok := m.PublicKeyForKID(activeKid)
	if !ok {
		t.Fatalf("expected public key for active kid")
	}
	if parsed, err := jwt.Parse(forged, func(*jwt.Token) (interface{}, error) { return pub, nil }); err == nil && parsed.Valid {
		t.Fatal("forged native-kid token must NOT verify against the real native public key")
	}
}
