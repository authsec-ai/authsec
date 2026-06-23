package testsupport

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// HarnessJWTSecret is the shared secret used by both the harness token minters
	// and the env-var JWT_DEF_SECRET / JWT_SDK_SECRET. AuthMiddleware validates
	// against this secret, so all must agree.
	HarnessJWTSecret = "harness-integration-jwt-secret-32chars!!"

	// HarnessIssuer must be in AuthMiddleware's allowed issuers list.
	HarnessIssuer = "authsec-ai/auth-manager"
)

// AdminTokenParams carries the fields needed to mint an admin JWT.
type AdminTokenParams struct {
	UserID      uuid.UUID
	WorkspaceID uuid.UUID
	Email       string
	Roles       []string
}

// UserTokenParams carries the fields needed to mint an end-user JWT.
type UserTokenParams struct {
	UserID      uuid.UUID
	WorkspaceID uuid.UUID
	Email       string
	ExpiresIn   time.Duration // defaults to 24h
}

// MintAdminToken returns a signed HS256 JWT for an admin user.
func MintAdminToken(p AdminTokenParams) (string, error) {
	exp := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"iss":          HarnessIssuer,
		"aud":          []string{"authsec-api"},
		"sub":          p.UserID.String(),
		"workspace_id": p.WorkspaceID.String(),
		"client_id":    p.UserID.String(),
		"email_id":     p.Email,
		"roles":        p.Roles,
		"iat":          time.Now().Unix(),
		"exp":          exp.Unix(),
		"kid":          "default",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "default"
	return tok.SignedString([]byte(HarnessJWTSecret))
}

// MintUserToken returns a signed HS256 JWT for an end user.
func MintUserToken(p UserTokenParams) (string, error) {
	exp := p.ExpiresIn
	if exp == 0 {
		exp = 24 * time.Hour
	}
	claims := jwt.MapClaims{
		"iss":          HarnessIssuer,
		"aud":          []string{"authsec-api"},
		"sub":          p.UserID.String(),
		"workspace_id": p.WorkspaceID.String(),
		"project_id":   p.WorkspaceID.String(),
		"client_id":    p.UserID.String(),
		"email_id":     p.Email,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(exp).Unix(),
		"kid":          "default",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "default"
	return tok.SignedString([]byte(HarnessJWTSecret))
}

// MintExpiredToken returns a token with exp in the past (for rejection tests).
func MintExpiredToken(p UserTokenParams) (string, error) {
	p.ExpiresIn = -time.Hour
	claims := jwt.MapClaims{
		"iss":          HarnessIssuer,
		"aud":          []string{"authsec-api"},
		"sub":          p.UserID.String(),
		"workspace_id": p.WorkspaceID.String(),
		"client_id":    p.UserID.String(),
		"email_id":     p.Email,
		"iat":          time.Now().Add(-2 * time.Hour).Unix(),
		"exp":          time.Now().Add(-time.Hour).Unix(),
		"kid":          "default",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "default"
	return tok.SignedString([]byte(HarnessJWTSecret))
}

// MintForgedToken returns a token signed with a wrong secret.
func MintForgedToken(p UserTokenParams) (string, error) {
	claims := jwt.MapClaims{
		"iss":          HarnessIssuer,
		"sub":          p.UserID.String(),
		"workspace_id": p.WorkspaceID.String(),
		"exp":          time.Now().Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte("wrong-secret-this-should-fail"))
}

// MintNoIssuerToken returns a token without an iss claim.
func MintNoIssuerToken(p UserTokenParams) (string, error) {
	claims := jwt.MapClaims{
		"sub":          p.UserID.String(),
		"workspace_id": p.WorkspaceID.String(),
		"exp":          time.Now().Add(24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(HarnessJWTSecret))
}

// SVIDParams holds params for minting a SPIFFE JWT-SVID.
type SVIDParams struct {
	SpiffeID    string
	WorkspaceID string
	Audience    string // defaults to "authsec-api"
	Permissions []string
	PrivateKey  *rsa.PrivateKey
	ExpiresIn   time.Duration // defaults to 1h
}

// MintSVID returns an RS256 JWT-SVID signed by the given private key.
// The fake JWKS server must have been registered with the matching public key.
func MintSVID(p SVIDParams) (string, error) {
	if p.Audience == "" {
		p.Audience = "authsec-api"
	}
	exp := p.ExpiresIn
	if exp == 0 {
		exp = time.Hour
	}
	kid := fmt.Sprintf("spiffe-%s", p.WorkspaceID)
	claims := jwt.MapClaims{
		"sub":          p.SpiffeID,
		"aud":          []string{p.Audience},
		"workspace_id": p.WorkspaceID,
		"client_id":    p.WorkspaceID, // required by extsvc_controller.resolveTenant
		"permissions":  p.Permissions,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(exp).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(p.PrivateKey)
}

// MintExpiredSVID returns an SVID with exp in the past.
func MintExpiredSVID(p SVIDParams) (string, error) {
	kid := fmt.Sprintf("spiffe-%s", p.WorkspaceID)
	claims := jwt.MapClaims{
		"sub":          p.SpiffeID,
		"aud":          []string{"authsec-api"},
		"workspace_id": p.WorkspaceID,
		"iat":          time.Now().Add(-2 * time.Hour).Unix(),
		"exp":          time.Now().Add(-time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(p.PrivateKey)
}

// MintWrongKidSVID returns an SVID signed by a fresh key not registered in the fake JWKS.
func MintWrongKidSVID(p SVIDParams) (string, error) {
	freshKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"sub":          p.SpiffeID,
		"aud":          []string{"authsec-api"},
		"workspace_id": p.WorkspaceID,
		"exp":          time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "wrong-kid-not-registered"
	return tok.SignedString(freshKey)
}
