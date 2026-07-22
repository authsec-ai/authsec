package services

// XAAService handles ID-JAG (Identity Assertion Authorization Grant) validation
// and subject materialization for the XAA redemption grant (jwt-bearer).
//
// Flow: authenticateClient → validateIDJAG → CheckClientApprovedForRS →
//       mapSubject → NativeIssuer.Issue(xaa). The trust boundary is the resource
//       server (audience), per ID-JAG draft §4.1/§7.3 — NOT the workspace; a
//       same-workspace agent→MCP-server delegation is conformant XAA.

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// selfIssuedProviderName is the reserved trusted-issuer provider name used for
// ID-JAGs that AuthSec issued itself (iss == this AS). Self-issued `sub` claims
// are local user UUIDs, not external federated subjects.
const selfIssuedProviderName = "authsec:id-jag"

// ErrUntrustedIssuer is returned when the ID-JAG's iss is not in trusted_issuers.
var ErrUntrustedIssuer = errors.New("untrusted_issuer: ID-JAG issuer not recognised")

// ErrIDJAGReplayed is returned when the jti has already been redeemed.
var ErrIDJAGReplayed = errors.New("id_jag_replayed: assertion already redeemed")

// IDJAGClaims are the validated claims extracted from a trusted ID-JAG JWT.
type IDJAGClaims struct {
	Issuer    string    // iss
	Subject   string    // sub (external provider subject)
	ClientID  string    // client_id claim (must match authenticated client)
	JTI       string    // jti (replay guard key)
	Resource  string    // resource claim, when the IdP scoped the ID-JAG to a resource
	Scope     string    // scope claim, when the IdP scoped the ID-JAG to scopes
	IssuedAt  time.Time // iat
	ExpiresAt time.Time // exp
	// IssuanceWorkspaceID is derived from workspace_claim_mapping if present.
	IssuanceWorkspaceID *uuid.UUID
}

// XAAService wraps the dependencies needed for ID-JAG validation and subject mapping.
type XAAService struct {
	db        *gorm.DB
	userRepo  *database.UserRepository
	identRepo *database.OIDCUserIdentityRepository
	jwksCache *trustedIssuerJWKSCache
}

// NewXAAService wires the service.
func NewXAAService(db *gorm.DB) *XAAService {
	dbConn := config.GetDatabase()
	return &XAAService{
		db:        db,
		userRepo:  database.NewUserRepository(dbConn),
		identRepo: database.NewOIDCUserIdentityRepository(dbConn),
		jwksCache: newTrustedIssuerJWKSCache(),
	}
}

func claimString(claims jwt.MapClaims, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// ValidateIDJAG validates the raw assertion JWT and returns its claims.
// It verifies: typ=oauth-id-jag+jwt, iss in trusted_issuers, sig, aud==AuthSec
// issuer, client_id==authenticatedClientID, exp/iat, and alg not in {none, HS*}.
// Replay-checking (jti) is done atomically inside the issuance transaction —
// NOT here — because validating and inserting must be one operation.
func (s *XAAService) ValidateIDJAG(ctx context.Context, assertion, authenticatedClientID, selfIssuer string) (*IDJAGClaims, *models.TrustedIssuer, error) {
	// Step 1: parse header only (no signature) to get iss + typ.
	unverified, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid_grant: malformed ID-JAG: %w", err)
	}

	// typ must be oauth-id-jag+jwt (RFC 9700 §3).
	if typ, _ := unverified.Header["typ"].(string); typ != "oauth-id-jag+jwt" {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG typ must be oauth-id-jag+jwt, got %q", typ)
	}

	uclaims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid_grant: malformed ID-JAG claims")
	}
	iss, _ := uclaims["iss"].(string)
	if iss == "" {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG missing iss")
	}

	// Step 2: resolve the issuer + a key-resolution function.
	//
	// Self-issued ID-JAGs (iss == this AS, minted by our own token-exchange) have
	// no external trusted_issuers row. Per decision #2 we trust them as a reserved
	// "authsec:id-jag" provider with JIT provisioning, verified against our OWN
	// native signing keys (no HTTP round-trip to our own JWKS). The
	// issuance_workspace claim is retained as ownership and audit provenance; it
	// does not prohibit a distinct agent and resource server in the same workspace.
	// External issuers take the trusted_issuers + JWKS path unchanged.
	var issuer models.TrustedIssuer
	var keyFunc jwt.Keyfunc
	var allowedAlgs []string

	if iss == selfIssuer {
		wsMapping := "issuance_workspace"
		issuer = models.TrustedIssuer{
			Iss:                   iss,
			ProviderName:          selfIssuedProviderName,
			JITProvisioning:       true,
			ClockSkewSecs:         30,
			WorkspaceClaimMapping: &wsMapping,
		}
		allowedAlgs = []string{"RS256"}
		keyFunc = func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unsupported signing algorithm: %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if pk, ok := tokens.NativeKeys().PublicKeyForKID(kid); ok {
				return pk, nil
			}
			return nil, fmt.Errorf("self-issued ID-JAG kid %q is not a known native signing key", kid)
		}
	} else {
		// Only ACTIVE issuers are trusted. A revoked issuer must fail closed —
		// matching by iss alone would let ID-JAGs from a revoked issuer keep
		// redeeming after the admin revoked it.
		if err := s.db.WithContext(ctx).Where("iss = ? AND status = 'active'", iss).First(&issuer).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil, ErrUntrustedIssuer
			}
			return nil, nil, fmt.Errorf("invalid_grant: issuer lookup failed: %w", err)
		}
		keyMap, kerr := s.jwksCache.get(issuer.Iss, issuer.JWKSUri)
		if kerr != nil {
			return nil, nil, fmt.Errorf("invalid_grant: could not fetch issuer JWKS: %w", kerr)
		}
		allowedAlgs = []string(issuer.AllowedAlgs)
		if len(allowedAlgs) == 0 {
			allowedAlgs = []string{"RS256"}
		}
		keyFunc = func(t *jwt.Token) (interface{}, error) {
			switch t.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			default:
				return nil, fmt.Errorf("unsupported signing algorithm: %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			if key, ok := keyMap[kid]; ok {
				return key, nil
			}
			for _, k := range keyMap {
				return k, nil
			}
			return nil, fmt.Errorf("kid not found in issuer JWKS")
		}
	}

	// Step 4: full parse + verify.
	leeway := time.Duration(issuer.ClockSkewSecs) * time.Second
	parsed, err := jwt.Parse(assertion, keyFunc, jwt.WithValidMethods(allowedAlgs), jwt.WithLeeway(leeway))
	if err != nil || !parsed.Valid {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG signature/expiry invalid: %w", err)
	}

	ac, _ := parsed.Claims.(jwt.MapClaims)

	// Step 5: aud must be the AuthSec issuer.
	if err := validateAud(ac, selfIssuer); err != nil {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG aud must be the AuthSec issuer")
	}

	// Step 6: client_id claim must equal the authenticated client.
	claimClientID, _ := ac["client_id"].(string)
	if claimClientID != authenticatedClientID {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG client_id (%q) does not match authenticated client (%q)", claimClientID, authenticatedClientID)
	}

	// Step 7: extract sub and jti.
	sub, _ := ac["sub"].(string)
	if sub == "" {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG missing sub")
	}
	jti, _ := ac["jti"].(string)
	if jti == "" {
		return nil, nil, fmt.Errorf("invalid_grant: ID-JAG missing jti")
	}

	expF, _ := ac["exp"].(float64)
	iatF, _ := ac["iat"].(float64)

	claims := &IDJAGClaims{
		Issuer:    iss,
		Subject:   sub,
		ClientID:  claimClientID,
		JTI:       jti,
		Resource:  claimString(ac, "resource"),
		Scope:     claimString(ac, "scope"),
		IssuedAt:  time.Unix(int64(iatF), 0),
		ExpiresAt: time.Unix(int64(expF), 0),
	}

	// Step 8: derive issuance workspace from workspace_claim_mapping if configured.
	if issuer.WorkspaceClaimMapping != nil && *issuer.WorkspaceClaimMapping != "" {
		if wsClaim, ok := ac[*issuer.WorkspaceClaimMapping]; ok {
			if wsStr, ok := wsClaim.(string); ok {
				if wsID, err := uuid.Parse(wsStr); err == nil {
					claims.IssuanceWorkspaceID = &wsID
				}
			}
		}
	}

	return claims, &issuer, nil
}

// MapSubject resolves (or JIT-provisions) the local user for the given
// ID-JAG subject in targetWorkspace.
//
//   - Looks up oidc_user_identities by (targetWorkspace, issuer.ProviderName, externalSub).
//   - If not found and issuer.JITProvisioning=true → materialize via CreateOIDCEndUser
//   - CreateIdentity (one tx); freshly materialized user has zero role bindings.
//   - If not found and JITProvisioning=false → returns ("", ErrNoLocalUser).
func (s *XAAService) MapSubject(ctx context.Context, externalSub string, issuer *models.TrustedIssuer, targetWorkspaceID uuid.UUID) (uuid.UUID, error) {
	// Apply subject_mapping transformation if configured (simple prefix-strip for now).
	mappedSub := externalSub
	if issuer.SubjectMapping != nil && *issuer.SubjectMapping != "" {
		// Format: "strip_prefix:<value>" strips the given prefix from sub.
		if len(*issuer.SubjectMapping) > 13 && (*issuer.SubjectMapping)[:13] == "strip_prefix:" {
			prefix := (*issuer.SubjectMapping)[13:]
			if len(mappedSub) > len(prefix) && mappedSub[:len(prefix)] == prefix {
				mappedSub = mappedSub[len(prefix):]
			}
		}
	}

	identity, err := s.identRepo.GetIdentityByTenantAndProviderUser(targetWorkspaceID, issuer.ProviderName, mappedSub)
	if err == nil && identity != nil {
		return identity.UserID, nil
	}
	if err != nil && !isNotFoundErr(err) {
		return uuid.Nil, fmt.Errorf("identity lookup: %w", err)
	}

	// Self-issued ID-JAG (AuthSec is both IdP and resource AS): the `sub` is a
	// real local user UUID we minted in tokenExchangeGrant, not an external
	// federated subject. Resolve that existing user instead of JIT-creating a
	// duplicate `<uuid>@jit.local` shadow — but only when the user actually lives
	// in the target (RS) workspace, so we never grant RS-workspace roles to a
	// user rooted elsewhere (cross-workspace stays the federated-guest path below).
	if issuer.ProviderName == selfIssuedProviderName {
		if subUUID, perr := uuid.Parse(mappedSub); perr == nil {
			if existing, uerr := s.userRepo.GetUserByID(subUUID); uerr == nil && existing != nil && existing.WorkspaceID == targetWorkspaceID {
				// Best-effort link row for audit/traceability (the real email, not a
				// placeholder). A failure here is non-fatal — the user is already real.
				now := time.Now().UTC()
				_ = s.identRepo.CreateIdentity(&models.OIDCUserIdentity{
					WorkspaceID:    targetWorkspaceID,
					UserID:         existing.ID,
					ProviderName:   issuer.ProviderName,
					ProviderUserID: mappedSub,
					Email:          existing.Email,
					ProfileData:    "{}",
					CreatedAt:      now,
					UpdatedAt:      now,
				})
				return existing.ID, nil
			}
		}
	}

	// Not found.
	if !issuer.JITProvisioning {
		return uuid.Nil, fmt.Errorf("access_denied: subject not provisioned and jit_provisioning is disabled")
	}

	// JIT provision: create a minimal end-user (no memberships, no role bindings).
	userInfo := &models.OIDCUserInfo{
		Sub:   mappedSub,
		Email: mappedSub + "@jit.local", // placeholder — real email not in ID-JAG
		Name:  mappedSub,
	}
	user, err := s.userRepo.CreateOIDCEndUser(targetWorkspaceID, issuer.ProviderName, userInfo)
	if err != nil {
		return uuid.Nil, fmt.Errorf("jit_provision: create user: %w", err)
	}

	// Link oidc_user_identities row.
	now := time.Now().UTC()
	ident := &models.OIDCUserIdentity{
		WorkspaceID:    targetWorkspaceID,
		UserID:         user.ID,
		ProviderName:   issuer.ProviderName,
		ProviderUserID: mappedSub,
		Email:          userInfo.Email,
		ProfileData:    "{}",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.identRepo.CreateIdentity(ident); err != nil {
		return uuid.Nil, fmt.Errorf("jit_provision: create identity: %w", err)
	}

	return user.ID, nil
}

// IDJAGReplayInsert returns a gorm tx hook that atomically inserts a replay
// record. If the jti is already present (RowsAffected==0) the hook returns
// ErrIDJAGReplayed, aborting the issuance transaction.
func IDJAGReplayInsert(db *gorm.DB, iss, jti string, expiresAt time.Time) func(tx *gorm.DB) error {
	return func(tx *gorm.DB) error {
		res := tx.Exec(
			`INSERT INTO id_jag_replay_cache (iss, jti, expires_at)
             VALUES (?, ?, ?)
             ON CONFLICT (iss, jti) DO NOTHING`,
			iss, jti, expiresAt,
		)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrIDJAGReplayed
		}
		return nil
	}
}

// ── Trusted-issuer JWKS cache (5-min TTL, per iss) ───────────────────────────

type trustedIssuerEntry struct {
	keys      map[string]interface{}
	fetchedAt time.Time
}

type trustedIssuerJWKSCache struct {
	mu      sync.Mutex
	entries map[string]*trustedIssuerEntry
}

func newTrustedIssuerJWKSCache() *trustedIssuerJWKSCache {
	return &trustedIssuerJWKSCache{entries: make(map[string]*trustedIssuerEntry)}
}

func (c *trustedIssuerJWKSCache) get(iss, jwksURI string) (map[string]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[iss]; ok && time.Since(e.fetchedAt) < 5*time.Minute {
		return e.keys, nil
	}

	body, err := fetchURL(jwksURI)
	if err != nil {
		return nil, err
	}
	keys, err := parseTrustedIssuerJWKS(string(body))
	if err != nil {
		return nil, err
	}
	c.entries[iss] = &trustedIssuerEntry{keys: keys, fetchedAt: time.Now()}
	return keys, nil
}

// parseTrustedIssuerJWKS parses RSA public keys only (EC support can be added later).
func parseTrustedIssuerJWKS(raw string) (map[string]interface{}, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	result := make(map[string]interface{})
	for i, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", i)
		}
		result[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no usable RSA signing keys in trusted issuer JWKS")
	}
	return result, nil
}

func isNotFoundErr(err error) bool {
	return err != nil && (errors.Is(err, gorm.ErrRecordNotFound) || err.Error() == "sql: no rows in result set")
}
