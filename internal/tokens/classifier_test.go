package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// signWithKid signs a minimal JWT with the given kid using a throwaway RSA key.
func signWithKid(t *testing.T, kid string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "x"})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestClassify(t *testing.T) {
	nativeKIDs := map[string]struct{}{"native:abc123": {}}

	cases := []struct {
		name  string
		token string
		want  Family
	}{
		{"native kid → native", signWithKid(t, "native:abc123"), FamilyNative},
		{"other kid → hydra", signWithKid(t, "hydra-key-1"), FamilyHydra},
		{"no kid → hydra", signWithKid(t, ""), FamilyHydra},
		{"opaque (2 parts) → hydra", "aaa.bbb", FamilyHydra},
		{"opaque single → hydra", "ory_at_opaqueblob", FamilyHydra},
		{"garbage → hydra", "....", FamilyHydra},
		{"empty → hydra", "", FamilyHydra},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.token, nativeKIDs)
			if got.Family != tc.want {
				t.Fatalf("Classify family = %v, want %v", got.Family, tc.want)
			}
		})
	}
}

// A JWT whose kid is in the native set must classify native EVEN IF its
// signature is forged — classification is by kid only; signature rejection
// happens later at introspection (never a Hydra fallback). This guards §1.
func TestClassify_ForgedNativeKidStillNative(t *testing.T) {
	nativeKIDs := map[string]struct{}{"native:deadbeef": {}}
	forged := signWithKid(t, "native:deadbeef") // signed by a random key, not the real native key
	if got := Classify(forged, nativeKIDs); got.Family != FamilyNative {
		t.Fatalf("forged native-kid token must classify native (commit, then reject at verify); got %v", got.Family)
	}
}
