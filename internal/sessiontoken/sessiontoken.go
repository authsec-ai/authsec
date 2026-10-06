// Package sessiontoken mints and verifies the platform's HS256 session tokens
// and keeps the three token classes apart (AS-033, ADR-0001 §5.1).
//
// # Token classes
//
//	class    typ        aud                 signing key
//	admin    "admin"    "authsec-admin"     HMAC-SHA256(JWT_DEF_SECRET, "authsec/session-token/v1/admin")
//	enduser  "enduser"  "authsec-enduser"   HMAC-SHA256(JWT_DEF_SECRET, "authsec/session-token/v1/enduser")
//	sdk      "sdk"      "authsec-sdk"       HMAC-SHA256(JWT_SDK_SECRET, "authsec/session-token/v1/sdk")
//
// Every class has its own derived key, so a token of one class does not verify
// under another class's key even when the deployment configured the same value
// for several secrets, and no raw secret (JWT_DEF_SECRET, JWT_SDK_SECRET,
// JWT_SECRET) verifies a classed token.
//
// # Verification rule
//
// A token whose payload carries "typ" is accepted only when ALL hold:
//  1. typ is one of admin|enduser|sdk and is in the caller's allowed set
//     (the surface: see middlewares.surfaceClasses);
//  2. the signature is HS256 under that class's derived key (and only that key);
//  3. aud contains the class audience;
//  4. exp is present and in the future; workspace_id and jti are present.
//
// A token without "typ" is a legacy token, minted before classes existed. It
// is accepted, on every surface that accepted it before, only while all hold:
//  1. the signature verifies under one of the legacy raw secrets;
//  2. exp is present and in the future;
//  3. exp is no later than the legacy deadline: SESSION_TOKEN_LEGACY_UNTIL
//     (RFC 3339) when set, otherwise 25 hours after this process started. A
//     legacy session token never lived longer than 24h after 0c60925, so
//     every token from the previous release drains naturally; a forged or
//     long-lived legacy token is refused after the deadline. Set
//     SESSION_TOKEN_LEGACY_UNTIL to a past time to refuse legacy tokens at
//     once.
//
// A typ that is present but unknown is refused.
package sessiontoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Class is a session-token class.
type Class string

const (
	Admin   Class = "admin"
	EndUser Class = "enduser"
	SDK     Class = "sdk"
	// Legacy is reported for a verified token that carries no typ.
	Legacy Class = "legacy"

	// Issuer is the iss of every session token.
	Issuer = "authsec-ai/auth-manager"
)

// Audience returns the aud value of a class.
func Audience(c Class) string {
	switch c {
	case Admin:
		return "authsec-admin"
	case EndUser:
		return "authsec-enduser"
	case SDK:
		return "authsec-sdk"
	}
	return ""
}

// Errors returned by Verify. They are deliberately coarse.
var (
	ErrInvalid      = errors.New("sessiontoken: invalid token")
	ErrWrongSurface = errors.New("sessiontoken: token class not accepted here")
	ErrLegacyClosed = errors.New("sessiontoken: legacy token no longer accepted")
)

// Secrets are the configured raw HS256 secrets.
type Secrets struct {
	Default string // JWT_DEF_SECRET
	SDK     string // JWT_SDK_SECRET
	Other   string // JWT_SECRET (legacy verification only)
}

// SecretsFromEnv reads the secrets from the environment.
func SecretsFromEnv() Secrets {
	return Secrets{
		Default: os.Getenv("JWT_DEF_SECRET"),
		SDK:     os.Getenv("JWT_SDK_SECRET"),
		Other:   os.Getenv("JWT_SECRET"),
	}
}

var processStart = time.Now()

// LegacyDeadline is the last exp a legacy (typ-less) token may carry.
func LegacyDeadline() time.Time {
	if v := strings.TrimSpace(os.Getenv("SESSION_TOKEN_LEGACY_UNTIL")); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return processStart.Add(25 * time.Hour)
}

func (s Secrets) key(c Class) ([]byte, error) {
	var base string
	switch c {
	case Admin, EndUser:
		base = s.Default
	case SDK:
		base = s.SDK
	default:
		return nil, ErrInvalid
	}
	if base == "" {
		return nil, fmt.Errorf("sessiontoken: no secret configured for class %s", c)
	}
	m := hmac.New(sha256.New, []byte(base))
	m.Write([]byte("authsec/session-token/v1/" + string(c)))
	return m.Sum(nil), nil
}

// Sign mints a token of class c with the given claims, using the secrets from
// the environment. See SignWith.
func Sign(c Class, claims jwt.MapClaims) (string, error) {
	return SignWith(SecretsFromEnv(), c, claims)
}

// SignWith mints a token of class c. It sets typ and aud (overwriting any
// value in claims), and iss and jti when absent. exp and workspace_id must be
// supplied by the caller.
func SignWith(s Secrets, c Class, claims jwt.MapClaims) (string, error) {
	key, err := s.key(c)
	if err != nil {
		return "", err
	}
	if _, ok := claims["exp"]; !ok {
		return "", errors.New("sessiontoken: exp is required")
	}
	if ws, _ := claims["workspace_id"].(string); ws == "" {
		return "", errors.New("sessiontoken: workspace_id is required")
	}
	out := jwt.MapClaims{}
	for k, v := range claims {
		out[k] = v
	}
	out["typ"] = string(c)
	out["aud"] = Audience(c)
	if _, ok := out["iss"]; !ok {
		out["iss"] = Issuer
	}
	if j, _ := out["jti"].(string); j == "" {
		out["jti"] = uuid.NewString()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, out)
	tok.Header["kid"] = "session-" + string(c)
	return tok.SignedString(key)
}

// Verify checks a token against the classes allowed on the caller's surface,
// using the secrets from the environment. See VerifyWith.
func Verify(token string, allowed ...Class) (jwt.MapClaims, Class, error) {
	return VerifyWith(SecretsFromEnv(), token, allowed...)
}

// VerifyWith applies the package rule (see the package comment). Legacy in
// allowed admits legacy tokens until the legacy deadline.
func VerifyWith(s Secrets, token string, allowed ...Class) (jwt.MapClaims, Class, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, "", ErrInvalid
	}
	uc, _ := unverified.Claims.(jwt.MapClaims)
	rawTyp, hasTyp := uc["typ"]
	if !hasTyp {
		claims, err := verifyLegacy(s, token)
		if err != nil {
			return nil, "", err
		}
		if !contains(allowed, Legacy) {
			return nil, "", ErrWrongSurface
		}
		return claims, Legacy, nil
	}

	typ, _ := rawTyp.(string)
	class := Class(typ)
	key, err := s.key(class)
	if err != nil {
		return nil, "", ErrInvalid
	}
	parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(Audience(class)),
	)
	if err != nil || !parsed.Valid {
		return nil, "", ErrInvalid
	}
	claims, _ := parsed.Claims.(jwt.MapClaims)
	if claims["typ"] != typ {
		return nil, "", ErrInvalid
	}
	if ws, _ := claims["workspace_id"].(string); ws == "" {
		return nil, "", ErrInvalid
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		return nil, "", ErrInvalid
	}
	if !contains(allowed, class) {
		return nil, "", ErrWrongSurface
	}
	return claims, class, nil
}

func verifyLegacy(s Secrets, token string) (jwt.MapClaims, error) {
	seen := map[string]bool{}
	for _, secret := range []string{s.SDK, s.Default, s.Other} {
		if secret == "" || seen[secret] {
			continue
		}
		seen[secret] = true
		parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return []byte(secret), nil },
			jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !parsed.Valid {
			continue
		}
		claims, _ := parsed.Claims.(jwt.MapClaims)
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			return nil, ErrInvalid
		}
		if exp.Time.After(LegacyDeadline()) {
			return nil, ErrLegacyClosed
		}
		return claims, nil
	}
	return nil, ErrInvalid
}

// ClassOf returns the class named by claims that Verify already accepted.
func ClassOf(claims jwt.MapClaims) Class {
	if t, ok := claims["typ"].(string); ok && t != "" {
		return Class(t)
	}
	return Legacy
}

func contains(list []Class, c Class) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}
