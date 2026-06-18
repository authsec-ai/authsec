package tokens

import (
	"context"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// NativeClaims is the input to NativeIssuer.Issue — the resolved, post-policy,
// post-scope-resolution facts to mint a native access token from.
type NativeClaims struct {
	Family           string // models.TokenFamily{M2M,XAA,CIBA}
	WorkspaceID      uuid.UUID
	SubjectType      string // "user" | "service_account"
	SubjectID        uuid.UUID
	ClientID         string // authenticating client (the `client_id` claim)
	ActorClientID    *string
	ActorSpiffeID    *string
	ResourceServerID uuid.UUID
	Audience         string // = resource_servers.resource_uri
	Scope            string // space-delimited granted scopes
	SourceGrantJTI   *string
	RarID            *uuid.UUID
	TTL              time.Duration
}

// NativeIssuer is the narrow minting seam: it signs claims with the active
// native key and records the authoritative native_tokens row. It is the ONLY
// thing native grant handlers call to mint — orchestration (authenticate,
// validate, gate, resolve scopes) stays in the grant handlers, not here.
type NativeIssuer struct {
	db     *gorm.DB
	keys   *NativeKeyManager
	issuer string // = config.OAuthBaseURL()
}

// NewNativeIssuer wires the issuer. db is the single config.DB; issuer is the
// one canonical OAUTH_ISSUER_URL used by every token.
func NewNativeIssuer(db *gorm.DB, keys *NativeKeyManager, issuer string) *NativeIssuer {
	return &NativeIssuer{db: db, keys: keys, issuer: issuer}
}

// IDJAGClaims carries the inputs for IssueIDJAG.
type IDJAGClaims struct {
	// WorkspaceID is the minting workspace (carried as `issuance_workspace`
	// claim so the redemption path can apply §19 same-domain rejection).
	WorkspaceID uuid.UUID
	// SubjectID is the local user UUID who is being delegated (becomes `sub`).
	SubjectID uuid.UUID
	// ClientID is the authenticating agent client (becomes `client_id`).
	ClientID string
	// TargetIssuer is the AS that should accept this ID-JAG as an assertion
	// (becomes `aud`). Typically the same issuer or a trusted peer.
	TargetIssuer string
}

// IDJAGTyp is the JWT typ header for ID-JAG tokens (draft-ietf-oauth-identity-assertion-authz-grant-04).
const IDJAGTyp = "oauth-id-jag+jwt"

// IDJAGTokenType is the RFC 8693 token type URN for ID-JAG tokens.
const IDJAGTokenType = "urn:ietf:params:oauth:token-type:id-jag"

// IDJAGTLL is the lifetime of an ID-JAG token (5 minutes; non-refreshable).
const IDJAGTLL = 5 * time.Minute

// IssueIDJAG mints an ID-JAG credential (intermediary assertion, NOT an RS
// access token). It is signed with the active native key but NOT inserted into
// native_tokens — ID-JAGs are tracked only via id_jag_replay_cache on
// redemption (the redemption handler inserts the replay-guard row atomically).
func (i *NativeIssuer) IssueIDJAG(ctx context.Context, c IDJAGClaims) (string, uuid.UUID, error) {
	_ = ctx
	jti := uuid.New()
	now := time.Now().UTC()
	exp := now.Add(IDJAGTLL)

	claims := jwt.MapClaims{
		"iss":                i.issuer,
		"sub":                c.SubjectID.String(),
		"aud":                []string{c.TargetIssuer},
		"client_id":          c.ClientID,
		"jti":                jti.String(),
		"iat":                now.Unix(),
		"exp":                exp.Unix(),
		"issuance_workspace": c.WorkspaceID.String(),
	}

	tokenStr, err := i.keys.SignWithTyp(claims, IDJAGTyp)
	if err != nil {
		return "", uuid.Nil, err
	}
	return tokenStr, jti, nil
}

// Issue signs a short-lived, non-refreshable native access token and inserts its
// authoritative native_tokens row. Any inTx hooks (e.g. the ID-JAG replay-guard
// insert for XAA) run in the SAME transaction as the row insert, so issuance and
// replay-marking are atomic — a hook returning an error aborts the whole mint.
//
// Signing happens before the transaction (it has no side effects); if the
// transaction fails the token is never returned.
func (i *NativeIssuer) Issue(ctx context.Context, c NativeClaims, inTx ...func(tx *gorm.DB) error) (string, uuid.UUID, error) {
	jti := uuid.New()
	now := time.Now().UTC()
	exp := now.Add(c.TTL)

	claims := jwt.MapClaims{
		"iss":       i.issuer,
		"sub":       c.SubjectID.String(),
		"aud":       []string{c.Audience},
		"scope":     c.Scope,
		"client_id": c.ClientID,
		"jti":       jti.String(),
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"tf":        c.Family,
	}
	if c.ActorClientID != nil || c.ActorSpiffeID != nil {
		act := map[string]interface{}{}
		if c.ActorClientID != nil {
			act["client_id"] = *c.ActorClientID
		}
		if c.ActorSpiffeID != nil {
			act["spiffe_id"] = *c.ActorSpiffeID
		}
		claims["act"] = act
	}
	if c.SourceGrantJTI != nil {
		claims["source_grant_jti"] = *c.SourceGrantJTI
	}

	token, err := i.keys.Sign(claims)
	if err != nil {
		return "", uuid.Nil, err
	}

	row := models.NativeToken{
		JTI:              jti,
		Iss:              i.issuer,
		WorkspaceID:      c.WorkspaceID,
		TokenFamily:      c.Family,
		SubjectType:      c.SubjectType,
		SubjectID:        c.SubjectID,
		ActorClientID:    c.ActorClientID,
		ActorSpiffeID:    c.ActorSpiffeID,
		ClientID:         c.ClientID,
		ResourceServerID: c.ResourceServerID,
		Aud:              c.Audience,
		Scope:            c.Scope,
		SourceGrantJTI:   c.SourceGrantJTI,
		RarID:            c.RarID,
		IssuedAt:         now,
		ExpiresAt:        exp,
	}

	err = i.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, hook := range inTx {
			if hook == nil {
				continue
			}
			if herr := hook(tx); herr != nil {
				return herr
			}
		}
		return tx.Create(&row).Error
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	return token, jti, nil
}
