package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// AuthContext is the validated identity yielded by verifying a native AuthSec
// access token against a Resource Server. It is the single shape every
// protected-resource consumer (token introspection, the connector broker) reads
// — so authorization is on Principal + Actor + resource binding, never on the
// auth method or token provenance.
type AuthContext struct {
	Principal        tokens.Principal // SubjectType, SubjectID, WorkspaceID
	ClientID         string           // authenticating OAuth client
	Actor            *tokens.Actor    // act claim (XAA/CIBA/workload); nil for plain M2M
	TokenFamily      string           // tf: m2m | xaa | ciba (provenance, for audit only)
	ResourceServerID string
	Scopes           []string // live-resolved effective scopes (RBAC-enforced)
	JTI              string
	ExpiresAt        time.Time
}

// ErrTokenInactive is returned when a token fails any verification step. The
// reason is logged, never surfaced to the caller (avoids an oracle).
var ErrTokenInactive = errors.New("token inactive")

// VerifyProtectedResourceToken is the authoritative native-token verifier. It is
// the extracted, HTTP-free core of the native-introspection path and the SINGLE
// implementation both /oauth/introspect and the connector broker call — so the
// invariants (signature → native_tokens → revocation → audience → registration →
// live RBAC) can never drift between callers.
//
// A native-kid token is validated here or rejected; it is NEVER retried on Hydra.
// rs is the Resource Server the token must be audience-bound to (RFC 8707): for
// the broker this is the workspace Connector Broker RS, so a token minted for a
// different resource is rejected — closing the confused-deputy hole.
func VerifyProtectedResourceToken(
	ctx context.Context,
	db *gorm.DB,
	oauthSvc *OAuthASService,
	scopeResolver *ScopeResolver,
	token, kid string,
	rs *models.ResourceServer,
) (*AuthContext, error) {
	reject := func(reason string) (*AuthContext, error) {
		return nil, fmt.Errorf("%w: %s", ErrTokenInactive, reason)
	}

	pub, ok := tokens.NativeKeys().PublicKeyForKID(kid)
	if !ok {
		return reject("unknown native kid")
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, isRSA := t.Method.(*jwt.SigningMethodRSA); !isRSA {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		return pub, nil
	})
	if err != nil || parsed == nil || !parsed.Valid {
		return reject("signature/claims invalid")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return reject("no jti")
	}

	row, err := tokens.LookupNativeToken(ctx, db, jti)
	if err != nil {
		return reject("native_tokens lookup error")
	}
	if row == nil {
		return reject("no native_tokens row for jti")
	}

	// Revocation source of truth.
	revoked, err := tokens.IsRevoked(ctx, db, row.Iss, models.RevokedKindAccessToken, jti)
	if err != nil || revoked {
		return reject("revoked")
	}
	if time.Now().After(row.ExpiresAt) {
		return reject("expired (row)")
	}
	// Audience binding (RFC 8707): the token must have been minted for THIS rs.
	if row.Aud != rs.ResourceURI {
		return reject("audience mismatch")
	}

	// Registration gate: revoking the client's (RS, client) approval kills
	// still-live native tokens.
	mcpClient, lookupErr := oauthSvc.GetMCPOAuthClientByClientID(row.ClientID)
	if lookupErr != nil {
		return reject("no AuthSec client for client_id")
	}
	reg, regErr := oauthSvc.GetClientRegistration(rs.ID, mcpClient.ID)
	if regErr != nil || reg.Status != "approved" {
		return reject("client registration not approved")
	}

	// Live scope re-resolution + strict-subset (revoke-on-introspect guarantee).
	storedScopes := strings.Fields(row.Scope)
	oidcScopes, rsScopes := PartitionScopes(storedScopes)
	var finalScopes []string
	if len(rsScopes) > 0 {
		principal := tokens.Principal{
			SubjectType: row.SubjectType,
			SubjectID:   row.SubjectID,
			WorkspaceID: row.WorkspaceID,
		}
		currentRS, rbacErr := scopeResolver.ResolvePrincipalEffectiveScopes(
			ctx, principal, rs.ID.String(), rsScopes, rs, nil,
		)
		if rbacErr != nil || len(currentRS) == 0 {
			return reject("RBAC revoked all RS scopes")
		}
		if lost := ScopesLost(rsScopes, currentRS); len(lost) > 0 {
			return reject("partial RS scope loss")
		}
		finalScopes = append(oidcScopes, currentRS...)
	} else {
		finalScopes = oidcScopes
	}
	if len(finalScopes) == 0 {
		return reject("no scopes after enforcement")
	}

	authCtx := &AuthContext{
		Principal: tokens.Principal{
			SubjectType: row.SubjectType,
			SubjectID:   row.SubjectID,
			WorkspaceID: row.WorkspaceID,
		},
		ClientID:         row.ClientID,
		TokenFamily:      row.TokenFamily,
		ResourceServerID: rs.ID.String(),
		Scopes:           finalScopes,
		JTI:              jti,
		ExpiresAt:        row.ExpiresAt,
	}
	if row.ActorClientID != nil {
		authCtx.Actor = &tokens.Actor{ClientID: *row.ActorClientID, SpiffeID: row.ActorSpiffeID}
	}
	return authCtx, nil
}
