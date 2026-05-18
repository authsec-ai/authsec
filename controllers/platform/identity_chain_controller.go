// Package platform — IdentityChainController implements RFC 8693 OAuth 2.0
// Token Exchange with draft-ietf-oauth-identity-chaining `act` claim chaining.
//
// This controller is INTENTIONALLY separate from SpireController. The legacy
// /authsec/spire/oidc/token endpoint keeps its existing single-subject
// re-issuance behavior unchanged for backward compatibility. All new identity-
// chaining work lives under /authsec/oauth2/*.
package platform

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ===== Constants =====

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"

	defaultMaxChainDepth = 4
	jwksCacheTTL         = 10 * time.Minute
)

// ===== Controller =====

// IdentityChainController owns the v2 token-exchange surface. It depends on
// spireOIDCProvider for local signing/validation so it reuses the same key
// material and JWKS published at /authsec/.well-known/jwks.json — meaning
// tokens it issues are verifiable by every existing consumer without changes.
type IdentityChainController struct {
	db       *gorm.DB
	provider *spireOIDCProvider // local signer; shared with SpireController
	jwksMu   sync.RWMutex
	jwksHot  map[string]jwksCacheEntry // key = JWKS URI
}

type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey // kid -> parsed RSA public key
	fetchedAt time.Time
}

// NewIdentityChainController wires the controller. Reuses the shared
// SpireController's signing key + issuer so issued tokens are accepted by
// every existing consumer without changes.
//
// Returns nil if the SpireController hasn't been initialized yet — callers
// should mount routes only when this is non-nil.
func NewIdentityChainController(db *gorm.DB) *IdentityChainController {
	sc := GetSharedSpireController()
	if sc == nil || sc.oidcProviderAccessor() == nil {
		return nil
	}
	return &IdentityChainController{
		db:       db,
		provider: sc.oidcProviderAccessor(),
		jwksHot:  make(map[string]jwksCacheEntry),
	}
}

// ===== Request / response types =====

type tokenExchangeRequest struct {
	GrantType          string `form:"grant_type"           json:"grant_type"           binding:"required"`
	SubjectToken       string `form:"subject_token"        json:"subject_token"        binding:"required"`
	SubjectTokenType   string `form:"subject_token_type"   json:"subject_token_type"   binding:"required"`
	ActorToken         string `form:"actor_token"          json:"actor_token,omitempty"`
	ActorTokenType     string `form:"actor_token_type"     json:"actor_token_type,omitempty"`
	RequestedTokenType string `form:"requested_token_type" json:"requested_token_type,omitempty"`
	Resource           string `form:"resource"             json:"resource,omitempty"`
	Audience           string `form:"audience"             json:"audience,omitempty"`
	Scope              string `form:"scope"                json:"scope,omitempty"`
}

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// chainedTokenClaims is the on-the-wire claims object. The `act` field is the
// nested-actor chain defined by RFC 8693 §4.1. Each level represents one hop
// of delegation, oldest delegator at the deepest nesting.
type chainedTokenClaims struct {
	Subject   string                 `json:"sub"`
	Issuer    string                 `json:"iss"`
	Audience  []string               `json:"aud"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	NotBefore int64                  `json:"nbf"`
	JWTID     string                 `json:"jti"`
	SPIFFEID  string                 `json:"spiffe_id,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Act       *actorClaim            `json:"act,omitempty"`
	Extra     map[string]interface{} `json:"-"`
	jwt.RegisteredClaims
}

// actorClaim is a single link in the `act` chain. Per RFC 8693 §4.1, an actor
// claim contains at minimum `sub` and `iss` of the delegating party, and MAY
// nest its own `act` to record prior hops.
type actorClaim struct {
	Subject string      `json:"sub"`
	Issuer  string      `json:"iss"`
	Act     *actorClaim `json:"act,omitempty"`
}

// ===== Handlers =====

// TokenExchange is the RFC 8693 endpoint. Mount at POST /authsec/oauth2/token.
//
// Accepts either application/x-www-form-urlencoded (per RFC) or application/json.
func (c *IdentityChainController) TokenExchange(ctx *gin.Context) {
	var req tokenExchangeRequest
	if strings.Contains(ctx.ContentType(), "application/json") {
		if err := ctx.ShouldBindJSON(&req); err != nil {
			oauthError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	} else {
		if err := ctx.ShouldBind(&req); err != nil {
			oauthError(ctx, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}

	if req.GrantType != grantTypeTokenExchange {
		oauthError(ctx, http.StatusBadRequest, "unsupported_grant_type",
			"only "+grantTypeTokenExchange+" is supported")
		return
	}
	if req.SubjectTokenType != tokenTypeJWT && req.SubjectTokenType != tokenTypeAccessToken {
		oauthError(ctx, http.StatusBadRequest, "invalid_request",
			"subject_token_type must be a JWT token type")
		return
	}

	tenantID := ctx.GetString("tenant_id") // populated by upstream auth middleware

	subjectClaims, subjectIssuer, err := c.validateIncomingToken(ctx, tenantID, req.SubjectToken)
	if err != nil {
		oauthError(ctx, http.StatusBadRequest, "invalid_grant", "subject_token: "+err.Error())
		return
	}

	var (
		actorClaims  *chainedTokenClaims
		actorIssuer  string
	)
	if req.ActorToken != "" {
		if req.ActorTokenType != tokenTypeJWT && req.ActorTokenType != tokenTypeAccessToken {
			oauthError(ctx, http.StatusBadRequest, "invalid_request",
				"actor_token_type must be a JWT token type when actor_token is present")
			return
		}
		actorClaims, actorIssuer, err = c.validateIncomingToken(ctx, tenantID, req.ActorToken)
		if err != nil {
			oauthError(ctx, http.StatusBadRequest, "invalid_grant", "actor_token: "+err.Error())
			return
		}
	}

	// Build the new `act` chain. If the subject token already had an `act`
	// (it was itself a delegated token), we preserve that history and prepend
	// the new actor on top.
	newAct, depth := buildActChain(subjectClaims.Act, actorClaims, subjectClaims.Subject, subjectIssuer)
	if depth > defaultMaxChainDepth {
		oauthError(ctx, http.StatusBadRequest, "invalid_grant",
			fmt.Sprintf("chain depth %d exceeds maximum %d", depth, defaultMaxChainDepth))
		return
	}

	audience := req.Audience
	if audience == "" {
		audience = c.provider.cfg.IssuerURL
	}

	tokenStr, claims, err := c.signChainedToken(subjectClaims.Subject, subjectClaims.SPIFFEID,
		[]string{audience}, req.Resource, req.Scope, newAct)
	if err != nil {
		oauthError(ctx, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	// Audit the hop. Failure to audit is logged but does not fail the request —
	// the token is already signed and the caller needs it.
	c.recordAudit(tenantID, subjectClaims, actorClaims, actorIssuer, claims, req.Resource, audience)

	ctx.JSON(http.StatusOK, tokenExchangeResponse{
		AccessToken:     tokenStr,
		IssuedTokenType: tokenTypeJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int64(c.provider.cfg.TokenExpiry.Seconds()),
		Scope:           req.Scope,
	})
}

// Discovery serves the v2 authorization-server metadata. Mount at
// GET /authsec/oauth2/.well-known/oauth-authorization-server.
//
// Per RFC 8414, this is a *separate* document from the legacy SPIRE OIDC
// discovery doc at /authsec/spire/.well-known/openid-configuration.
func (c *IdentityChainController) Discovery(ctx *gin.Context) {
	issuer := c.provider.cfg.IssuerURL
	ctx.JSON(http.StatusOK, gin.H{
		"issuer":                                  issuer,
		"token_endpoint":                          issuer + "/authsec/oauth2/token",
		"jwks_uri":                                issuer + "/authsec/.well-known/jwks.json",
		"grant_types_supported":                   []string{grantTypeTokenExchange},
		"token_endpoint_auth_methods_supported":   []string{"client_secret_basic", "private_key_jwt", "none"},
		"subject_token_types_supported":           []string{tokenTypeJWT, tokenTypeAccessToken},
		"actor_token_types_supported":             []string{tokenTypeJWT, tokenTypeAccessToken},
		"requested_token_types_supported":         []string{tokenTypeJWT},
		"id_token_signing_alg_values_supported":   []string{"RS256"},
		"resource_parameter_supported":            true, // RFC 8707
		"identity_chaining_supported":             true,
		"max_chain_depth":                         defaultMaxChainDepth,
	})
}

// ===== Trusted-issuer admin (tenant-scoped) =====

func (c *IdentityChainController) ListTrustedIssuers(ctx *gin.Context) {
	tenantID := ctx.GetString("tenant_id")
	var rows []models.TrustedIssuer
	if err := c.db.Where("tenant_id = ?", tenantID).Find(&rows).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"issuers": rows})
}

func (c *IdentityChainController) CreateTrustedIssuer(ctx *gin.Context) {
	tenantID := ctx.GetString("tenant_id")
	var body models.TrustedIssuer
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	body.TenantID = tenantID
	if body.MaxChainHop == 0 {
		body.MaxChainHop = defaultMaxChainDepth
	}
	if err := c.db.Create(&body).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusCreated, body)
}

func (c *IdentityChainController) DeleteTrustedIssuer(ctx *gin.Context) {
	tenantID := ctx.GetString("tenant_id")
	id := ctx.Param("id")
	if err := c.db.Where("tenant_id = ? AND id = ?", tenantID, id).
		Delete(&models.TrustedIssuer{}).Error; err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.Status(http.StatusNoContent)
}

// ===== Internal helpers =====

// validateIncomingToken parses a JWT and verifies its signature using either
// the local signing key (if the token was issued by this authsec instance) or
// a trusted external issuer's JWKS.
func (c *IdentityChainController) validateIncomingToken(ctx *gin.Context, tenantID, tokenStr string) (*chainedTokenClaims, string, error) {
	// First peek the issuer without verifying.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("malformed token: %w", err)
	}
	mc, _ := unverified.Claims.(jwt.MapClaims)
	issuer, _ := mc["iss"].(string)
	if issuer == "" {
		return nil, "", errors.New("token has no iss claim")
	}

	// Local issuer → use local signer.
	if issuer == c.provider.cfg.IssuerURL {
		claims, err := c.parseLocal(tokenStr)
		return claims, issuer, err
	}

	// External issuer → must be in the trust registry for this tenant.
	var ti models.TrustedIssuer
	if err := c.db.Where("tenant_id = ? AND issuer = ? AND enabled = TRUE",
		tenantID, issuer).First(&ti).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", fmt.Errorf("issuer %q is not in the tenant trust registry", issuer)
		}
		return nil, "", err
	}

	claims, err := c.parseExternal(tokenStr, ti)
	return claims, issuer, err
}

func (c *IdentityChainController) parseLocal(tokenStr string) (*chainedTokenClaims, error) {
	var claims chainedTokenClaims
	tok, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return c.provider.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token failed validation")
	}
	return &claims, nil
}

func (c *IdentityChainController) parseExternal(tokenStr string, ti models.TrustedIssuer) (*chainedTokenClaims, error) {
	keys, err := c.loadJWKS(ti.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	var claims chainedTokenClaims
	tok, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid header")
		}
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS for issuer %s", kid, ti.Issuer)
		}
		return k, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("external token failed validation")
	}
	if ti.Audience != "" {
		matched := false
		for _, a := range claims.Audience {
			if a == ti.Audience {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("token audience does not include %q", ti.Audience)
		}
	}
	return &claims, nil
}

// loadJWKS fetches the JWKS for an external issuer and returns a kid → RSA
// public-key map, caching for jwksCacheTTL.
func (c *IdentityChainController) loadJWKS(uri string) (map[string]*rsa.PublicKey, error) {
	c.jwksMu.RLock()
	entry, ok := c.jwksHot[uri]
	c.jwksMu.RUnlock()
	if ok && time.Since(entry.fetchedAt) < jwksCacheTTL {
		return entry.keys, nil
	}

	resp, err := http.Get(uri) //nolint:gosec // URI comes from tenant-admin-configured trust registry
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []jwkRSAKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	parsed, err := parseRSAJWKS(doc.Keys)
	if err != nil {
		return nil, err
	}
	c.jwksMu.Lock()
	c.jwksHot[uri] = jwksCacheEntry{keys: parsed, fetchedAt: time.Now()}
	c.jwksMu.Unlock()
	return parsed, nil
}

// signChainedToken builds and signs the new JWT carrying the updated `act`
// chain. It deliberately uses the *same* private key + kid + issuer as
// `spireOIDCProvider.createToken`, so downstream verifiers don't need changes.
func (c *IdentityChainController) signChainedToken(
	subject, spiffeID string,
	audience []string,
	resource, scope string,
	act *actorClaim,
) (string, *chainedTokenClaims, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := chainedTokenClaims{
		Subject:   subject,
		Issuer:    c.provider.cfg.IssuerURL,
		Audience:  audience,
		ExpiresAt: now.Add(c.provider.cfg.TokenExpiry).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		JWTID:     jti,
		SPIFFEID:  spiffeID,
		Scope:     scope,
		Resource:  resource,
		Act:       act,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = c.provider.keyID
	signed, err := tok.SignedString(c.provider.privateKey)
	if err != nil {
		return "", nil, err
	}
	return signed, &claims, nil
}

func (c *IdentityChainController) recordAudit(
	tenantID string,
	subject *chainedTokenClaims,
	actor *chainedTokenClaims,
	actorIssuer string,
	issued *chainedTokenClaims,
	resource, audience string,
) {
	row := models.ActChainAudit{
		JTI:           issued.JWTID,
		TenantID:      tenantID,
		SubjectSub:    subject.Subject,
		SubjectIssuer: subject.Issuer,
		ChainDepth:    chainDepth(issued.Act),
		Resource:      resource,
		Audience:      audience,
		Scope:         issued.Scope,
		IssuedAt:      time.Unix(issued.IssuedAt, 0),
		ExpiresAt:     time.Unix(issued.ExpiresAt, 0),
	}
	if actor != nil {
		row.ActorSub = actor.Subject
		row.ActorIssuer = actorIssuer
	}
	if err := c.db.Create(&row).Error; err != nil {
		// Audit failure must not block token issuance.
		fmt.Printf("identity_chain_audit_failed jti=%s err=%v\n", issued.JWTID, err)
	}
}

// ===== Pure functions (easy to unit test) =====

// buildActChain assembles the new actor chain. The top-level `act` represents
// the most recent delegator. Returns the chain and its depth.
//
// Cases:
//   - actorClaims == nil and prevAct == nil → no chain (subject is acting on
//     its own behalf, depth 0).
//   - actorClaims != nil → the actor is the new top of the chain; the prior
//     actor (if any) becomes the actor's nested `act`.
//   - actorClaims == nil and prevAct != nil → propagate the existing chain
//     unchanged (this is the "carry-through" case where the same delegator is
//     re-issuing for a new audience).
func buildActChain(prevAct *actorClaim, actor *chainedTokenClaims, _, _ string) (*actorClaim, int) {
	if actor == nil {
		return prevAct, chainDepth(prevAct)
	}
	newTop := &actorClaim{
		Subject: actor.Subject,
		Issuer:  actor.Issuer,
		Act:     prevAct,
	}
	return newTop, chainDepth(newTop)
}

func chainDepth(a *actorClaim) int {
	n := 0
	for a != nil {
		n++
		a = a.Act
	}
	return n
}

// ===== Small utilities =====

func oauthError(ctx *gin.Context, status int, code, desc string) {
	ctx.JSON(status, gin.H{"error": code, "error_description": desc})
}

// jwkRSAKey is the subset of a JSON Web Key (RFC 7517) we support for
// external-issuer verification. RSA only — Ed25519 / EC can be added later.
type jwkRSAKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseRSAJWKS converts a decoded JWKS document into a kid → *rsa.PublicKey
// map. Non-RSA keys are skipped (not an error — issuers commonly publish
// mixed key sets).
func parseRSAJWKS(keys []jwkRSAKey) (map[string]*rsa.PublicKey, error) {
	out := make(map[string]*rsa.PublicKey, len(keys))
	for _, k := range keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Kid == "" {
			return nil, errors.New("JWKS contains an RSA key with no kid")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("kid %q: decode modulus: %w", k.Kid, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("kid %q: decode exponent: %w", k.Kid, err)
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("JWKS contains no usable RSA keys")
	}
	return out, nil
}
