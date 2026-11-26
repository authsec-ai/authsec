package sessiontoken

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Same value for every secret: the classes must still not be interchangeable.
var same = Secrets{Default: "s3cret-s3cret-s3cret-s3cret-s3cret", SDK: "s3cret-s3cret-s3cret-s3cret-s3cret", Other: "s3cret-s3cret-s3cret-s3cret-s3cret"}

func base() jwt.MapClaims {
	return jwt.MapClaims{
		"workspace_id": "11111111-1111-1111-1111-111111111111",
		"sub":          "22222222-2222-2222-2222-222222222222",
		"exp":          time.Now().Add(time.Hour).Unix(),
	}
}

func TestClassesAreNotInterchangeable(t *testing.T) {
	for _, minted := range []Class{Admin, EndUser, SDK} {
		tok, err := SignWith(same, minted, base())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []Class{Admin, EndUser, SDK} {
			_, got, err := VerifyWith(same, tok, want)
			if minted == want {
				if err != nil || got != want {
					t.Errorf("%s token on %s surface: %v", minted, want, err)
				}
			} else if err == nil {
				t.Errorf("%s token accepted where only %s is allowed", minted, want)
			}
		}
	}
}

// A typ claim does not let a raw secret verify: classed tokens verify only
// under the derived class key.
func TestRawSecretCannotMintClassedToken(t *testing.T) {
	c := base()
	c["typ"] = "admin"
	c["aud"] = "authsec-admin"
	c["jti"] = "x"
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(same.Default))
	if _, _, err := VerifyWith(same, tok, Admin); err == nil {
		t.Fatal("admin-typed token signed with the raw JWT_DEF_SECRET was accepted")
	}
}

func TestAudienceAndClaimsRequired(t *testing.T) {
	key, _ := same.key(Admin)
	for name, mutate := range map[string]func(jwt.MapClaims){
		"wrong aud":    func(c jwt.MapClaims) { c["aud"] = "authsec-enduser" },
		"no aud":       func(c jwt.MapClaims) { delete(c, "aud") },
		"no exp":       func(c jwt.MapClaims) { delete(c, "exp") },
		"no workspace": func(c jwt.MapClaims) { delete(c, "workspace_id") },
		"no jti":       func(c jwt.MapClaims) { delete(c, "jti") },
		"unknown typ":  func(c jwt.MapClaims) { c["typ"] = "platform" },
	} {
		c := base()
		c["typ"] = "admin"
		c["aud"] = "authsec-admin"
		c["jti"] = "x"
		mutate(c)
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(key)
		if _, _, err := VerifyWith(same, tok, Admin, EndUser, SDK, Legacy); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLegacyTokensUntilDeadline(t *testing.T) {
	c := base()
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(same.Other))
	if _, cl, err := VerifyWith(same, tok, Admin, Legacy); err != nil || cl != Legacy {
		t.Fatalf("live legacy token refused: %v", err)
	}
	if _, _, err := VerifyWith(same, tok, Admin); err == nil {
		t.Fatal("legacy token accepted on a surface that does not allow legacy")
	}

	far := base()
	far["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	tok, _ = jwt.NewWithClaims(jwt.SigningMethodHS256, far).SignedString([]byte(same.Default))
	if _, _, err := VerifyWith(same, tok, Legacy); err == nil {
		t.Fatal("legacy token expiring after the legacy deadline was accepted")
	}

	t.Setenv("SESSION_TOKEN_LEGACY_UNTIL", time.Now().Add(-time.Minute).Format(time.RFC3339))
	tok, _ = jwt.NewWithClaims(jwt.SigningMethodHS256, base()).SignedString([]byte(same.Default))
	if _, _, err := VerifyWith(same, tok, Legacy); err == nil {
		t.Fatal("legacy token accepted after SESSION_TOKEN_LEGACY_UNTIL")
	}
}
