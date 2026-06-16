package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// idjagTokenType is the assertion `typ` header value per the IETF draft
// (draft-ietf-oauth-identity-assertion-authz-grant). Resource ASes check for
// this so a casual ID token can't be mistaken for an ID-JAG.
const idjagTokenType = "oauth-id-jag+jwt"

// IDJAGTokenLifetime is the lifetime of an issued ID-JAG. Kept short because
// the ID-JAG is single-use — the client should exchange it for an access
// token immediately. RFC 8693 doesn't pin a number; 5 min mirrors common
// JWT-bearer assertion lifetimes.
const IDJAGTokenLifetime = 5 * time.Minute

// ErrXAAClientNotFound is returned when the requesting client_id doesn't map
// to a known xaa_client_apps row (or the row is inactive / soft-deleted).
var ErrXAAClientNotFound = errors.New("xaa client app not found")

// ErrXAAPolicyDenied is returned when the (client, resource, issuer) tuple
// has no enabled application_xaa_policies row. Default-deny.
var ErrXAAPolicyDenied = errors.New("xaa policy denies this request")

// ErrSubjectTokenInvalid is returned when the user's subject token (ID token
// or refresh token) can't be validated.
var ErrSubjectTokenInvalid = errors.New("subject token invalid or expired")

// IDJAGService issues and inspects ID-JAGs when AuthSec acts as the IdP.
//
// "Issuance" here is the IdP side of the IETF Cross-App Access flow:
//
//	client →  POST /idjag/token (Token Exchange)
//	         {subject_token, audience, scope?, resource?}
//	idp:    validate subject_token (it's our user's id_token or refresh)
//	        look up the requesting client (Basic auth)
//	        check application_xaa_policies row exists + enabled
//	        intersect requested scopes with policy.allowed_scopes
//	        sign + return an ID-JAG JWT
type IDJAGService struct {
	rs *ResourceServerService

	keyMu     sync.Mutex
	cachedKey *idjagKey // process-local cache; refreshed if Active flag flips in DB
}

type idjagKey struct {
	row     models.IDJAGSigningKey
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func NewIDJAGService(rs *ResourceServerService) *IDJAGService {
	if rs == nil {
		rs = NewResourceServerService()
	}
	return &IDJAGService{rs: rs}
}

// IssueIDJAGInput is the validated server-side projection of the Token
// Exchange request. Empty Scopes / ResourceURI are allowed (the spec says
// they're optional); ResourceServerID is required because policy is keyed on
// the target Application.
type IssueIDJAGInput struct {
	// RequestingClient is the authenticated xaa_client_apps row. Already
	// looked up + validated by the caller — IssueIDJAG trusts this.
	RequestingClient *models.XAAClientApp

	// Audience is the Resource AS's issuer URI. For AuthSec-internal targets
	// this is `https://prod.api.authsec.ai`.
	Audience string

	// ResourceServerID is the AuthSec Application UUID the client wants to
	// reach. Used to look up application_xaa_policies. Required.
	ResourceServerID uuid.UUID

	// TenantID of the target Application. The same xaa_client_apps row can
	// have policies in multiple tenants — we look up against this one only.
	TenantID string

	// UserID is the subject the ID-JAG will identify. The Token Exchange
	// caller supplies this via subject_token; the controller validates the
	// token and extracts user_id before calling us.
	UserID uuid.UUID

	// Email + Name go into the ID-JAG as bonus claims so the Resource AS
	// doesn't have to round-trip back for them.
	Email string
	Name  string

	// RequestedScopes is the `scope` form param from the request. Empty =
	// "give me whatever the policy allows".
	RequestedScopes []string

	// ResourceURI is the optional `resource` form param (RFC 8707).
	ResourceURI string

	// Issuer is the IdP's own issuer URL — for us, `https://prod.api.authsec.ai`.
	// Goes into `iss` on the signed JWT.
	Issuer string
}

// IssuedIDJAG is what the controller returns to the client. Token is the
// signed JWT string; ScopesGranted is the intersection the IdP actually put
// into the assertion (RFC 8693 §2.1 calls this `scope` in the response too).
type IssuedIDJAG struct {
	Token         string   `json:"access_token"`
	IssuedAt      int64    `json:"-"`
	ExpiresIn     int      `json:"expires_in"`
	ScopesGranted []string `json:"scope,omitempty"`
}

// IssueIDJAG runs the policy check, intersects scopes, and signs the JWT.
//
// The expectation is that the caller (controller) has already validated the
// subject_token and extracted the user_id, email, and name; we don't redo
// that work here. We DO redo the policy check because it's cheap (one indexed
// SELECT) and because the controller's job is to parse Token Exchange, not
// to know XAA policy.
func (s *IDJAGService) IssueIDJAG(in IssueIDJAGInput) (*IssuedIDJAG, error) {
	if in.RequestingClient == nil {
		return nil, errors.New("requesting client required")
	}
	if in.ResourceServerID == uuid.Nil {
		return nil, errors.New("resource_server_id required")
	}
	if in.UserID == uuid.Nil {
		return nil, errors.New("user_id required (extracted from subject_token)")
	}
	if strings.TrimSpace(in.Audience) == "" {
		return nil, errors.New("audience required")
	}
	if strings.TrimSpace(in.Issuer) == "" {
		return nil, errors.New("issuer required")
	}

	// 1. Look up the XAA policy row. trusted_issuer='' since AuthSec is the IdP.
	tenantDB, err := config.GetTenantGORMDB(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var policy models.ApplicationXAAPolicy
	err = tenantDB.Where(
		"tenant_id = ? AND resource_server_id = ? AND requesting_client_id = ? AND trusted_issuer = ? AND enabled = TRUE",
		in.TenantID, in.ResourceServerID, in.RequestingClient.ClientID, "",
	).First(&policy).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrXAAPolicyDenied
	}
	if err != nil {
		return nil, fmt.Errorf("lookup xaa policy: %w", err)
	}

	// 2. Compute the granted scope set: requested ∩ allowed. Empty requested
	// means "give me everything the policy permits".
	granted := intersectScopes(in.RequestedScopes, []string(policy.AllowedScopes))
	if len(granted) == 0 && len(policy.AllowedScopes) > 0 {
		// Client asked for something but none of it overlaps with policy.
		// RFC 8693 says return invalid_scope; we surface a typed error.
		return nil, fmt.Errorf("requested scopes do not intersect policy.allowed_scopes")
	}

	// 3. Get / lazily create the signing key.
	key, err := s.ensureSigningKey()
	if err != nil {
		return nil, fmt.Errorf("ensure signing key: %w", err)
	}

	// 4. Build + sign the JWT.
	now := time.Now()
	jti := uuid.New().String()
	claims := jwt.MapClaims{
		"iss":       in.Issuer,
		"sub":       in.UserID.String(),
		"aud":       []string{in.Audience},
		"client_id": in.RequestingClient.ClientID,
		"jti":       jti,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(IDJAGTokenLifetime).Unix(),
	}
	if len(granted) > 0 {
		claims["scope"] = strings.Join(granted, " ")
	}
	if strings.TrimSpace(in.ResourceURI) != "" {
		claims["resource"] = in.ResourceURI
	}
	if strings.TrimSpace(in.Email) != "" {
		claims["email"] = in.Email
	}
	if strings.TrimSpace(in.Name) != "" {
		claims["name"] = in.Name
	}
	if strings.TrimSpace(in.TenantID) != "" {
		claims["tenant"] = in.TenantID
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = idjagTokenType
	tok.Header["kid"] = key.row.KID

	signed, err := tok.SignedString(key.private)
	if err != nil {
		return nil, fmt.Errorf("sign id-jag: %w", err)
	}

	return &IssuedIDJAG{
		Token:         signed,
		IssuedAt:      now.Unix(),
		ExpiresIn:     int(IDJAGTokenLifetime.Seconds()),
		ScopesGranted: granted,
	}, nil
}

// LookupXAAClient resolves a client_id + presented client_secret to an
// xaa_client_apps row. Returns ErrXAAClientNotFound if no active row matches.
// Constant-time bcrypt is the secret check.
func (s *IDJAGService) LookupXAAClient(clientID, clientSecret string) (*models.XAAClientApp, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, ErrXAAClientNotFound
	}
	var row models.XAAClientApp
	err := config.DB.
		Where("client_id = ? AND active = TRUE AND deleted_at IS NULL", clientID).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrXAAClientNotFound
	}
	if err != nil {
		return nil, err
	}
	if row.IssuanceMode == models.XAAIssuanceModeInternal {
		if row.ClientSecretHash == "" {
			return nil, ErrXAAClientNotFound
		}
		if err := bcrypt.CompareHashAndPassword(
			[]byte(row.ClientSecretHash), []byte(clientSecret),
		); err != nil {
			return nil, ErrXAAClientNotFound
		}
	}
	return &row, nil
}

// JWKSEntries returns the publishable JWK entries (one per active signing
// key) so the JWKS handler can splice them into the document Hydra serves.
// The format matches what RFC 7517 expects: kid, kty, use, alg, n, e.
func (s *IDJAGService) JWKSEntries() ([]map[string]any, error) {
	var rows []models.IDJAGSigningKey
	if err := config.DB.
		Where("active = TRUE OR (not_after IS NOT NULL AND not_after > now())").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		pubBlock, _ := pem.Decode(r.PublicKeyPEM)
		if pubBlock == nil {
			continue
		}
		pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			continue
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"kid": r.KID,
			"kty": "RSA",
			"use": "sig",
			"alg": r.Algorithm,
			"n":   base64URLUInt(pub.N),
			"e":   base64URLUInt(big.NewInt(int64(pub.E))),
		})
	}
	return out, nil
}

// ensureSigningKey returns the current active signing key, generating + persisting
// one on first call. Cached in-process; cache is invalidated whenever a key
// rotation happens (we re-query if the cached kid is no longer active).
func (s *IDJAGService) ensureSigningKey() (*idjagKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.cachedKey != nil {
		// Cheap sanity: still active?
		var stillActive bool
		if err := config.DB.Model(&models.IDJAGSigningKey{}).
			Select("active").
			Where("kid = ?", s.cachedKey.row.KID).
			Scan(&stillActive).Error; err == nil && stillActive {
			return s.cachedKey, nil
		}
		s.cachedKey = nil
	}

	// Try to load an active row.
	var row models.IDJAGSigningKey
	err := config.DB.Where("active = TRUE").Order("created_at DESC").First(&row).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row, err = generateAndPersistSigningKey()
		if err != nil {
			return nil, err
		}
	}

	priv, pub, err := parsePEM(row.PrivateKeyPEM, row.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	s.cachedKey = &idjagKey{row: row, private: priv, public: pub}
	return s.cachedKey, nil
}

// generateAndPersistSigningKey mints a fresh RSA-2048 keypair, PEM-encodes both
// halves, and writes the row to master DB. Returns the persisted row so the
// caller doesn't need a follow-up SELECT.
func generateAndPersistSigningKey() (models.IDJAGSigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return models.IDJAGSigningKey{}, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return models.IDJAGSigningKey{}, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	row := models.IDJAGSigningKey{
		KID:           "idjag-" + uuid.New().String(),
		Algorithm:     "RS256",
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		Active:        true,
		NotBefore:     time.Now(),
	}
	if err := config.DB.Create(&row).Error; err != nil {
		return models.IDJAGSigningKey{}, err
	}
	return row, nil
}

func parsePEM(privPEM, pubPEM []byte) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, nil, errors.New("decode private pem")
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pubBlock, _ := pem.Decode(pubPEM)
	if pubBlock == nil {
		return nil, nil, errors.New("decode public pem")
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("public key is not RSA")
	}
	return priv, pub, nil
}

// intersectScopes returns the elements of `requested` that also appear in
// `allowed`, preserving the order of `requested`. When `requested` is empty
// we treat that as "give me everything in `allowed`" — RFC 8693 §2.1 says an
// omitted scope is the client deferring to the AS's policy.
func intersectScopes(requested, allowed []string) []string {
	if len(allowed) == 0 {
		return nil
	}
	if len(requested) == 0 {
		out := make([]string, len(allowed))
		copy(out, allowed)
		return out
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a != "" {
			allowSet[a] = struct{}{}
		}
	}
	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := allowSet[r]; !ok {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// base64URLUInt encodes a big-endian unsigned integer in base64url-no-padding
// per RFC 7518 §6.3.1.1 (used for JWK's "n" and "e" fields).
func base64URLUInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// ── ID-JAG verification and exchange (Resource AS side, TICKET-B) ──────────
//
// When a client redeems an ID-JAG at /oauth/v2/token with
//
//	grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
//	assertion=<ID-JAG JWT>
//
// the existing Token handler routes here BEFORE forwarding to Hydra. Hydra
// can't process ID-JAGs (different semantics — see commit message on
// TICKET-B). We verify the assertion against our own JWKS, intersect scopes
// against the XAA policy, and mint a fresh access token signed by us.

// JWTBearerGrantType is the IANA-registered grant-type URN for RFC 7523
// JWT-bearer assertions. The IETF ID-JAG draft reuses this grant_type at the
// Resource AS for redeeming the assertion.
const JWTBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// AccessTokenLifetime mirrors Hydra's default (1 hour). Tunable later.
const AccessTokenLifetime = time.Hour

// ErrIDJAGVerify groups assertion-validation failures (signature, expired,
// missing claim). Returned with a typed wrapping so the controller can pick
// the right OAuth error code without string-matching.
type ErrIDJAGVerify struct{ Reason string }

func (e ErrIDJAGVerify) Error() string { return "id-jag verification failed: " + e.Reason }

// VerifiedIDJAG is the parsed-and-trusted projection of an ID-JAG. Returned
// from VerifyIDJAGAssertion so the exchange step doesn't have to re-parse.
type VerifiedIDJAG struct {
	Issuer           string
	Subject          uuid.UUID
	RequestingClient string // the `client_id` claim — matches xaa_client_apps.client_id
	Audience         string // the AS issuer this assertion was minted for
	ScopesInAssertion []string
	ResourceURI      string
	TenantID         string
	Email            string
	Name             string
	JTI              string
	ExpiresAt        time.Time
}

// VerifyIDJAGAssertion validates an ID-JAG JWT.
//
// Trust model: the assertion's `iss` claim picks the verifier. For the
// internal case (iss == AuthSec's own issuer) we use the local idjag_signing_keys
// public key. For external IdPs (Okta etc.) we'd consult a trusted_issuers
// table — deferred to TICKET-C; today an unknown iss is rejected.
func (s *IDJAGService) VerifyIDJAGAssertion(assertion, expectedAudience, ourIssuer string) (*VerifiedIDJAG, error) {
	if strings.TrimSpace(assertion) == "" {
		return nil, ErrIDJAGVerify{Reason: "empty assertion"}
	}

	// Parse twice — once unverified to read `iss` so we can pick the right
	// JWKS, then once with verification once we have the key. The first
	// parse trusts NOTHING.
	unverified, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, ErrIDJAGVerify{Reason: "malformed: " + err.Error()}
	}
	unverifiedClaims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrIDJAGVerify{Reason: "claims not a map"}
	}
	iss, _ := unverifiedClaims["iss"].(string)
	if strings.TrimSpace(iss) == "" {
		return nil, ErrIDJAGVerify{Reason: "missing iss"}
	}

	// Trust resolution: only our own issuer is allowed today. External IdPs
	// land here via TICKET-C with a trusted_issuers row + cached JWKS URL.
	if iss != strings.TrimSuffix(ourIssuer, "/") {
		return nil, ErrIDJAGVerify{Reason: "untrusted iss: " + iss}
	}

	// Verify against the signing key whose kid is in the JWT header.
	keyFunc := func(t *jwt.Token) (any, error) {
		// Reject anything that isn't an ID-JAG so a casual id_token can't
		// be misused as an assertion here.
		if typ, _ := t.Header["typ"].(string); typ != idjagTokenType {
			return nil, fmt.Errorf("typ must be %s (got %q)", idjagTokenType, typ)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		key, err := s.publicKeyForKID(kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	parsed, err := jwt.Parse(assertion, keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(iss),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, ErrIDJAGVerify{Reason: err.Error()}
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, ErrIDJAGVerify{Reason: "claims invalid"}
	}

	// Audience check is explicit (jwt's WithAudience treats a string slice
	// weirdly when the assertion has aud as a JSON array).
	audOK := false
	switch av := claims["aud"].(type) {
	case string:
		audOK = av == expectedAudience
	case []any:
		for _, a := range av {
			if s, _ := a.(string); s == expectedAudience {
				audOK = true
				break
			}
		}
	}
	if !audOK {
		return nil, ErrIDJAGVerify{Reason: "aud mismatch"}
	}

	subStr, _ := claims["sub"].(string)
	subjectID, err := uuid.Parse(subStr)
	if err != nil {
		return nil, ErrIDJAGVerify{Reason: "sub not a uuid"}
	}
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		return nil, ErrIDJAGVerify{Reason: "missing client_id"}
	}
	scope, _ := claims["scope"].(string)
	var scopes []string
	if scope != "" {
		scopes = strings.Fields(scope)
	}
	resource, _ := claims["resource"].(string)
	tenant, _ := claims["tenant"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	jti, _ := claims["jti"].(string)
	expF, _ := claims["exp"].(float64)

	return &VerifiedIDJAG{
		Issuer:            iss,
		Subject:           subjectID,
		RequestingClient:  clientID,
		Audience:          expectedAudience,
		ScopesInAssertion: scopes,
		ResourceURI:       resource,
		TenantID:          tenant,
		Email:             email,
		Name:              name,
		JTI:               jti,
		ExpiresAt:         time.Unix(int64(expF), 0),
	}, nil
}

// publicKeyForKID resolves a kid to its RSA public key by walking the active
// + grace-period signing-key rows. Mirrors the JWKSEntries() filter so the
// SDK + this verifier agree on which keys are valid.
func (s *IDJAGService) publicKeyForKID(kid string) (*rsa.PublicKey, error) {
	var row models.IDJAGSigningKey
	err := config.DB.
		Where("kid = ? AND (active = TRUE OR (not_after IS NOT NULL AND not_after > now()))", kid).
		First(&row).Error
	if err != nil {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	_, pub, err := parsePEM(row.PrivateKeyPEM, row.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse pub for kid %q: %w", kid, err)
	}
	return pub, nil
}

// ExchangeForAccessTokenInput is the validated form-level projection of the
// JWT-bearer grant. Caller (Token handler) extracts it from the POST body.
type ExchangeForAccessTokenInput struct {
	Assertion       string
	RequestedScopes []string
	OurIssuer       string // the AS's own issuer URL — goes into iss on the minted access token
}

// IssuedAccessToken is what the Token handler hands back to the client. The
// SDK validates the JWT against the published JWKS, so no introspect round
// trip is strictly required — but introspect must still work for clients
// that prefer it (see Introspect handler updates).
type IssuedAccessToken struct {
	Token     string   `json:"access_token"`
	TokenType string   `json:"token_type"`
	ExpiresIn int      `json:"expires_in"`
	Scope     string   `json:"scope,omitempty"`
	Subject   string   `json:"-"`
	Scopes    []string `json:"-"`
}

// ExchangeForAccessToken consumes a verified ID-JAG and mints an OAuth access
// token. The assertion has already been signature-verified by VerifyIDJAGAssertion;
// here we redo the policy check (defence in depth) and intersect scopes one
// more time before signing.
func (s *IDJAGService) ExchangeForAccessToken(in ExchangeForAccessTokenInput) (*IssuedAccessToken, error) {
	verified, err := s.VerifyIDJAGAssertion(in.Assertion, in.OurIssuer, in.OurIssuer)
	if err != nil {
		return nil, err
	}

	// Lookup the policy that authorised this assertion in the first place.
	// Belt-and-braces: even if the IdP shouldn't have minted the ID-JAG, we
	// re-check on the Resource AS side. Aligns with the IETF draft's
	// security guidance.
	if verified.ResourceURI == "" {
		return nil, ErrIDJAGVerify{Reason: "id-jag missing resource claim"}
	}
	rs, tenantID, err := s.rs.GetByResourceURI(verified.ResourceURI)
	if err != nil {
		return nil, ErrIDJAGVerify{Reason: "resource not found: " + verified.ResourceURI}
	}
	if verified.TenantID != "" && verified.TenantID != tenantID {
		return nil, ErrIDJAGVerify{Reason: "id-jag tenant claim mismatches resource tenant"}
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var policy models.ApplicationXAAPolicy
	err = tenantDB.Where(
		"tenant_id = ? AND resource_server_id = ? AND requesting_client_id = ? AND trusted_issuer = ? AND enabled = TRUE",
		tenantID, rs.ID, verified.RequestingClient, "", // internal IdP case; external is TICKET-C
	).First(&policy).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrXAAPolicyDenied
	}
	if err != nil {
		return nil, fmt.Errorf("lookup xaa policy: %w", err)
	}

	// Scope intersection: requested ∩ assertion ∩ policy.
	stage1 := intersectScopes(in.RequestedScopes, verified.ScopesInAssertion)
	if len(in.RequestedScopes) == 0 {
		stage1 = verified.ScopesInAssertion
	}
	final := intersectScopes(stage1, []string(policy.AllowedScopes))
	if len(final) == 0 && len(policy.AllowedScopes) > 0 {
		return nil, fmt.Errorf("requested scopes do not intersect policy.allowed_scopes")
	}

	// Mint the access token. Same signing key as the ID-JAG itself —
	// keeping it on one keypair simplifies the JWKS handler. Header carries
	// typ=at+jwt per RFC 9068 so any verifier knows what to expect.
	key, err := s.ensureSigningKey()
	if err != nil {
		return nil, fmt.Errorf("ensure signing key: %w", err)
	}
	now := time.Now()
	jti := uuid.New().String()
	claims := jwt.MapClaims{
		"iss":       in.OurIssuer,
		"sub":       verified.Subject.String(),
		"aud":       []string{verified.ResourceURI},
		"client_id": verified.RequestingClient,
		"jti":       jti,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(AccessTokenLifetime).Unix(),
		"scope":     strings.Join(final, " "),
		"resource":  verified.ResourceURI,
		"ext": map[string]any{
			"tenant_id":          tenantID,
			"resource_server_id": rs.ID.String(),
			"issued_via":         "id-jag",
			"id_jag_jti":         verified.JTI,
		},
	}
	if verified.Email != "" {
		claims["email"] = verified.Email
	}
	if verified.Name != "" {
		claims["name"] = verified.Name
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = "at+jwt" // RFC 9068
	tok.Header["kid"] = key.row.KID
	signed, err := tok.SignedString(key.private)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	return &IssuedAccessToken{
		Token:     signed,
		TokenType: "Bearer",
		ExpiresIn: int(AccessTokenLifetime.Seconds()),
		Scope:     strings.Join(final, " "),
		Subject:   verified.Subject.String(),
		Scopes:    final,
	}, nil
}

// IsAuthSecIssuedToken returns true when a token's iss matches our own. Used
// by Introspect to know whether to validate locally or proxy to Hydra.
func (s *IDJAGService) IsAuthSecIssuedToken(rawToken, ourIssuer string) bool {
	unverified, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	iss, _ := claims["iss"].(string)
	// We're loose-comparing because cfg might or might not have trailing
	// slashes depending on call site. ourIssuer here is the canonical form.
	return strings.TrimSuffix(iss, "/") == strings.TrimSuffix(ourIssuer, "/")
}

// IntrospectSelfIssued validates a locally-issued access token (one we minted
// via ExchangeForAccessToken) and returns the RFC 7662 response. Returns
// {active: false} on any validation failure — matches Hydra's introspect
// shape so the SDK's introspect parser doesn't need to branch.
func (s *IDJAGService) IntrospectSelfIssued(rawToken, ourIssuer string) (map[string]any, error) {
	inactive := map[string]any{"active": false}
	parsed, err := jwt.Parse(rawToken, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return s.publicKeyForKID(kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(strings.TrimSuffix(ourIssuer, "/")),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return inactive, nil
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return inactive, nil
	}
	// Build a Hydra-shaped response. Only the fields the SDK reads.
	resp := map[string]any{
		"active":    true,
		"iss":       claims["iss"],
		"sub":       claims["sub"],
		"aud":       claims["aud"],
		"client_id": claims["client_id"],
		"exp":       claims["exp"],
		"iat":       claims["iat"],
		"jti":       claims["jti"],
		"scope":     claims["scope"],
		"token_use": "access_token",
	}
	if ext, ok := claims["ext"].(map[string]any); ok {
		resp["ext"] = ext
	}
	return resp, nil
}

// hashAndStoreSecret bcrypts a plaintext secret. Exposed so the admin CRUD
// (TICKET-D, separate commit) doesn't duplicate the cost factor decision.
func hashAndStoreSecret(plaintext string) (string, error) {
	if len(plaintext) < 8 {
		return "", errors.New("xaa client secret must be at least 8 chars")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// safeSHA256Suffix returns the last 8 hex chars of sha256(s). Useful for
// log lines where we want to correlate without echoing secrets.
func safeSHA256Suffix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[28:32])
}
