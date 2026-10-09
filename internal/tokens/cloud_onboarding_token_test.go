package tokens

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newIssuerTestDB builds an in-memory sqlite DB with just the native_tokens
// table, following the hand-rolled-schema convention used elsewhere in this
// repo's unit tests (see services/resource_server_onboarding_service_test.go)
// rather than gorm.AutoMigrate, so the row-count assertion below is checking
// the same table shape production writes to.
func newIssuerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.NativeToken{}); err != nil {
		t.Fatalf("automigrate native_tokens: %v", err)
	}
	return db
}

// TestIssueCloudOnboardingToken_ShapeAndTyp proves the minted token carries
// the distinct typ header, the exact sub/aud the caller asked for, and is
// signed by the same active native key every other token on this issuer uses
// (so the provider-side STS can verify it against the same public JWKS).
func TestIssueCloudOnboardingToken_ShapeAndTyp(t *testing.T) {
	db := newIssuerTestDB(t)
	keys := NewNativeKeyManager(nil) // nil Vault -> ephemeral, same as keys_test.go
	issuer := NewNativeIssuer(db, keys, "https://app.authsec.dev")

	const sub = "authsec:deadbeefdeadbeefdeadbeefdeadbeef"
	const audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider"

	tokenStr, err := issuer.IssueCloudOnboardingToken(context.Background(), sub, audience)
	if err != nil {
		t.Fatalf("IssueCloudOnboardingToken: %v", err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}

	typ, _ := parsed.Header["typ"].(string)
	if typ != CloudOnboardingTyp {
		t.Fatalf("typ = %q, want %q", typ, CloudOnboardingTyp)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims: unexpected type %T", parsed.Claims)
	}
	if got, _ := claims["sub"].(string); got != sub {
		t.Errorf("sub = %q, want %q", got, sub)
	}
	if got, _ := claims["iss"].(string); got != "https://app.authsec.dev" {
		t.Errorf("iss = %q, want the issuer's own base URL", got)
	}
	aud, ok := claims["aud"].([]interface{})
	if !ok || len(aud) != 1 || aud[0] != audience {
		t.Errorf("aud = %v, want [%q]", claims["aud"], audience)
	}
	if _, ok := claims["jti"].(string); !ok {
		t.Error("jti missing or not a string")
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat != CloudOnboardingTTL.Seconds() {
		t.Errorf("exp-iat = %v seconds, want %v (CloudOnboardingTTL)", exp-iat, CloudOnboardingTTL.Seconds())
	}

	// The signature must verify against the SAME active key every other native
	// token on this issuer uses -- that shared trust root is the whole point of
	// reusing config.AppConfig.OAuthBaseURL()'s issuer instead of standing up a
	// second one (GCP-D9's accepted blast-radius tradeoff).
	kid, _ := parsed.Header["kid"].(string)
	pub, ok := keys.PublicKeyForKID(kid)
	if !ok {
		t.Fatalf("no public key for kid %q", kid)
	}
	if _, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) { return pub, nil }); err != nil {
		t.Fatalf("token does not verify against its own issuer's published key: %v", err)
	}
}

// TestIssueCloudOnboardingToken_NotTrackedInNativeTokens proves a
// cloud-onboarding token is a one-shot bearer, never inserted into
// native_tokens -- the same reasoning as IssueIDJAG, and load-bearing here
// too: nothing about this token kind should ever appear in a query written
// against native_tokens (introspection, revocation, audit), because AuthSec
// itself never redeems it -- the external STS does, once.
func TestIssueCloudOnboardingToken_NotTrackedInNativeTokens(t *testing.T) {
	db := newIssuerTestDB(t)
	keys := NewNativeKeyManager(nil)
	issuer := NewNativeIssuer(db, keys, "https://app.authsec.dev")

	if _, err := issuer.IssueCloudOnboardingToken(context.Background(),
		"authsec:"+uuid.New().String(), "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr"); err != nil {
		t.Fatalf("IssueCloudOnboardingToken: %v", err)
	}

	var count int64
	if err := db.Model(&models.NativeToken{}).Count(&count).Error; err != nil {
		t.Fatalf("count native_tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("native_tokens has %d row(s) after minting a cloud-onboarding token; want 0", count)
	}
}
