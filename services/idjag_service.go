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
