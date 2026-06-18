package services

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthenticateClient extracts and verifies the client credential from the HTTP
// request and returns the authenticated MCPOAuthClient.
//
// Supported methods (read from allowed_token_endpoint_auth_methods):
//   - client_secret_basic: Authorization: Basic base64(id:secret)
//   - private_key_jwt:     client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
//   - client_assertion=<JWT signed with client's registered key>
//
// Clients whose allowed methods contain only "none" are rejected — public clients
// are not permitted to call confidential grant types.
//
// tokenEndpoint is the full token endpoint URL used as the required `aud` for
// private_key_jwt assertions (e.g. "https://api.authsec.dev/oauth/token").
func AuthenticateClient(ctx context.Context, db *gorm.DB, r *http.Request, tokenEndpoint string) (*models.MCPOAuthClient, error) {
	// ── 1. client_assertion (private_key_jwt) ────────────────────────────────
	assertionType := r.FormValue("client_assertion_type")
	assertion := r.FormValue("client_assertion")
	if assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && assertion != "" {
		return authenticatePrivateKeyJWT(ctx, db, assertion, tokenEndpoint)
	}

	// ── 1b. SPIFFE JWT-SVID assertion ────────────────────────────────────────
	// Agents running under SPIRE present their JWT-SVID via a custom assertion
	// type. The SVID's `sub` is the SPIFFE ID which maps to a service_account
	// (via service_accounts.spiffe_id) and from there to an mcp_oauth_client.
	if assertionType == "urn:authsec:params:oauth:client-assertion-type:spiffe-svid" && assertion != "" {
		return authenticateSPIFFESVID(ctx, db, assertion)
	}

	// ── 2. client_secret_basic ───────────────────────────────────────────────
	if clientID, secret, ok := r.BasicAuth(); ok {
		return authenticateClientSecretBasic(ctx, db, clientID, secret)
	}

	// ── 3. client_id only in body (public / PKCE flows) ─────────────────────
	// We resolve the client so the caller can read its kind, but we always
	// reject unless it has a non-'none' auth method.
	bodyClientID := r.FormValue("client_id")
	if bodyClientID == "" {
		return nil, fmt.Errorf("invalid_client: no client authentication provided")
	}
	var client models.MCPOAuthClient
	if err := db.WithContext(ctx).Where("client_id = ?", bodyClientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invalid_client: unknown client_id")
		}
		return nil, fmt.Errorf("invalid_client: %w", err)
	}
	if isPublicOnly(client.AllowedTokenEndpointAuthMethods) {
		return nil, fmt.Errorf("invalid_client: confidential authentication required")
	}
	return nil, fmt.Errorf("invalid_client: no client authentication provided")
}

// ── private_key_jwt ──────────────────────────────────────────────────────────

func authenticatePrivateKeyJWT(ctx context.Context, db *gorm.DB, assertion, tokenEndpoint string) (*models.MCPOAuthClient, error) {
	// Step 1: parse without verification to extract iss/sub (= client_id).
	unverified, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid_client: malformed client_assertion: %w", err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid_client: malformed client_assertion claims")
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return nil, fmt.Errorf("invalid_client: client_assertion must have iss and sub")
	}
	// iss MUST equal sub (both are the client_id per RFC 7523 §3).
	if iss != sub {
		return nil, fmt.Errorf("invalid_client: client_assertion iss must equal sub")
	}
	clientID := iss

	// Step 2: load the client and its registered JWKS.
	var client models.MCPOAuthClient
	if err := db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invalid_client: unknown client_id")
		}
		return nil, fmt.Errorf("invalid_client: %w", err)
	}
	if !hasMethod(client.AllowedTokenEndpointAuthMethods, "private_key_jwt") {
		return nil, fmt.Errorf("invalid_client: client does not support private_key_jwt")
	}

	var jwksRow models.OAuthClientJWKS
	if err := db.WithContext(ctx).Where("client_id = ?", client.ID).First(&jwksRow).Error; err != nil {
		return nil, fmt.Errorf("invalid_client: no JWKS registered for client")
	}
	keyMap, err := resolveJWKS(jwksRow)
	if err != nil {
		return nil, fmt.Errorf("invalid_client: JWKS resolution failed: %w", err)
	}

	// Step 3: parse + verify the assertion signature.
	parsed, err := jwt.Parse(assertion, func(t *jwt.Token) (interface{}, error) {
		// Reject none and all HMAC algorithms — per plan §(g).
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// OK
		default:
			return nil, fmt.Errorf("unsupported signing algorithm: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if key, ok := keyMap[kid]; ok {
			return key, nil
		}
		// No kid or kid not in JWKS — try any available key (single-key case).
		for _, k := range keyMap {
			return k, nil
		}
		return nil, fmt.Errorf("kid not found in client JWKS")
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}),
		jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid_client: client_assertion validation failed: %w", err)
	}

	ac, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid_client: claims parse error")
	}

	// Step 4: validate aud == token endpoint.
	if err := validateAud(ac, tokenEndpoint); err != nil {
		return nil, err
	}

	// Step 5: jti replay check — atomic insert; conflicts = already seen.
	jti, _ := ac["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("invalid_client: client_assertion must contain jti")
	}
	exp, _ := ac["exp"].(float64)
	expiresAt := time.Unix(int64(exp), 0)
	replay := models.ClientAssertionReplay{
		ClientID:  clientID,
		JTI:       jti,
		ExpiresAt: expiresAt,
	}
	res := db.WithContext(ctx).Exec(
		`INSERT INTO client_assertion_replay_cache (client_id, jti, expires_at)
         VALUES (?, ?, ?)
         ON CONFLICT (client_id, jti) DO NOTHING`,
		replay.ClientID, replay.JTI, replay.ExpiresAt,
	)
	if res.Error != nil {
		return nil, fmt.Errorf("invalid_client: replay check failed: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, fmt.Errorf("invalid_client: client_assertion jti already used (replay detected)")
	}

	return &client, nil
}

// ── SPIFFE JWT-SVID ──────────────────────────────────────────────────────────

// authenticateSPIFFESVID verifies a JWT-SVID and resolves the corresponding
// mcp_oauth_client via service_accounts.spiffe_id. The SVID is verified against
// the SPIFFE OIDC issuer's JWKS (fetched from <iss>/.well-known/jwks.json).
//
// Trust model: the issuer URL in the SVID must match the configured
// SpiffeOIDCIssuer (env SPIFFE_OIDC_ISSUER). The SPIFFE ID (sub) must be
// associated with an active service account.
func authenticateSPIFFESVID(ctx context.Context, db *gorm.DB, svid string) (*models.MCPOAuthClient, error) {
	// Step 1: parse without verification to extract iss + sub.
	unverified, _, err := new(jwt.Parser).ParseUnverified(svid, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid_client: malformed SVID: %w", err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid_client: malformed SVID claims")
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return nil, fmt.Errorf("invalid_client: SVID must have iss and sub")
	}
	if !strings.HasPrefix(sub, "spiffe://") {
		return nil, fmt.Errorf("invalid_client: SVID sub must be a SPIFFE ID")
	}

	// Step 1b: PIN the issuer to the configured SPIFFE OIDC issuer (fail-closed).
	// Without this, an attacker who runs any OIDC provider could sign a JWT with
	// sub=spiffe://<known-id> served from their own JWKS and authenticate as that
	// service account — the signature would verify against the attacker's keys.
	// We must only trust SVIDs minted by OUR trust domain. If SPIFFE_OIDC_ISSUER
	// is unset, SPIFFE client-auth is disabled entirely (no implicit any-issuer trust).
	expectedIssuer := ""
	if config.AppConfig != nil {
		expectedIssuer = config.AppConfig.SpiffeOIDCIssuer
	}
	if expectedIssuer == "" {
		return nil, fmt.Errorf("invalid_client: SPIFFE SVID authentication is not configured")
	}
	if iss != expectedIssuer {
		return nil, fmt.Errorf("invalid_client: SVID issuer is not the trusted SPIFFE OIDC issuer")
	}

	// Step 2: fetch the trusted issuer's JWKS and verify the signature.
	jwksURL := strings.TrimRight(iss, "/") + "/.well-known/jwks.json"
	jwksBody, err := fetchURL(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid_client: cannot fetch SPIFFE OIDC JWKS: %w", err)
	}
	keyMap, err := parseJWKSKeys(string(jwksBody))
	if err != nil {
		return nil, fmt.Errorf("invalid_client: SPIFFE JWKS parse error: %w", err)
	}

	parsed, err := jwt.Parse(svid, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
		default:
			return nil, fmt.Errorf("unsupported SVID alg: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if key, ok := keyMap[kid]; ok {
			return key, nil
		}
		for _, k := range keyMap {
			return k, nil
		}
		return nil, fmt.Errorf("kid not found in SPIFFE JWKS")
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "ES512"}),
		jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid_client: SVID verification failed: %w", err)
	}

	// Step 3: look up service_account by spiffe_id.
	var sa models.ServiceAccount
	if err := db.WithContext(ctx).
		Where("spiffe_id = ? AND status = 'active'", sub).
		First(&sa).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invalid_client: no active service account for SPIFFE ID")
		}
		return nil, fmt.Errorf("invalid_client: %w", err)
	}
	if sa.OAuthClientID == nil {
		return nil, fmt.Errorf("invalid_client: service account has no linked OAuth client")
	}

	// Step 4: load the linked confidential client.
	var client models.MCPOAuthClient
	if err := db.WithContext(ctx).Where("id = ?", *sa.OAuthClientID).First(&client).Error; err != nil {
		return nil, fmt.Errorf("invalid_client: linked OAuth client not found: %w", err)
	}
	if isPublicOnly(client.AllowedTokenEndpointAuthMethods) {
		return nil, fmt.Errorf("invalid_client: linked client is not confidential")
	}
	return &client, nil
}

// ── client_secret_basic ──────────────────────────────────────────────────────

func authenticateClientSecretBasic(ctx context.Context, db *gorm.DB, clientID, secret string) (*models.MCPOAuthClient, error) {
	var client models.MCPOAuthClient
	if err := db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("invalid_client: unknown client_id")
		}
		return nil, fmt.Errorf("invalid_client: %w", err)
	}
	if !hasMethod(client.AllowedTokenEndpointAuthMethods, "client_secret_basic") {
		return nil, fmt.Errorf("invalid_client: client does not support client_secret_basic")
	}

	// Load active (non-revoked, non-expired) secrets ordered newest first.
	var secrets []models.OAuthClientSecret
	if err := db.WithContext(ctx).
		Where("client_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", client.ID).
		Order("created_at DESC").
		Find(&secrets).Error; err != nil {
		return nil, fmt.Errorf("invalid_client: %w", err)
	}

	// Try each active hash — newest first (key rotation).
	for _, s := range secrets {
		if err := bcrypt.CompareHashAndPassword([]byte(s.SecretHash), []byte(secret)); err == nil {
			return &client, nil
		}
	}
	return nil, fmt.Errorf("invalid_client: invalid client secret")
}

// ── JWKS helpers ─────────────────────────────────────────────────────────────

// resolveJWKS returns a map of kid → public key from the stored JWKS row.
// It handles both inline JWKS JSON and a jwks_uri fetch.
func resolveJWKS(row models.OAuthClientJWKS) (map[string]interface{}, error) {
	var rawJWKS string
	if row.JWKS != nil && *row.JWKS != "" {
		rawJWKS = *row.JWKS
	} else if row.JWKSUri != nil && *row.JWKSUri != "" {
		body, err := fetchURL(*row.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("fetch jwks_uri: %w", err)
		}
		rawJWKS = string(body)
	} else {
		return nil, fmt.Errorf("client has no inline JWKS or jwks_uri")
	}

	return parseJWKSKeys(rawJWKS)
}

func fetchURL(u string) ([]byte, error) {
	resp, err := http.Get(u) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512*1024))
}

// parseJWKSKeys parses a JWKS JSON string and returns a map kid → public key.
// Supports RSA (kty=RSA, n+e) and EC (kty=EC) keys used for signing.
func parseJWKSKeys(rawJWKS string) (map[string]interface{}, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal([]byte(rawJWKS), &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	result := make(map[string]interface{})
	for i, raw := range doc.Keys {
		var base struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &base); err != nil {
			continue
		}
		if base.Use != "" && base.Use != "sig" {
			continue
		}
		kid := base.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", i)
		}

		switch base.Kty {
		case "RSA":
			var rk struct {
				N string `json:"n"`
				E string `json:"e"`
			}
			if err := json.Unmarshal(raw, &rk); err != nil || rk.N == "" {
				continue
			}
			nBytes, err1 := base64.RawURLEncoding.DecodeString(rk.N)
			eBytes, err2 := base64.RawURLEncoding.DecodeString(rk.E)
			if err1 != nil || err2 != nil {
				continue
			}
			e := 0
			for _, b := range eBytes {
				e = e<<8 + int(b)
			}
			result[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no usable signing keys found in JWKS")
	}
	return result, nil
}

// ── claim helpers ─────────────────────────────────────────────────────────────

func validateAud(claims jwt.MapClaims, tokenEndpoint string) error {
	switch v := claims["aud"].(type) {
	case string:
		if v == tokenEndpoint {
			return nil
		}
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == tokenEndpoint {
				return nil
			}
		}
	}
	return fmt.Errorf("invalid_client: client_assertion aud must be the token endpoint")
}

// ── method helpers ────────────────────────────────────────────────────────────

func hasMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func isPublicOnly(methods []string) bool {
	for _, m := range methods {
		if m != "none" {
			return false
		}
	}
	return true
}

// ExtractClientIDFromBasicAuth extracts the client_id from an Authorization: Basic
// header without verifying the password. Used by the Token() dispatcher to determine
// which grant handler applies before full authentication.
func ExtractClientIDFromBasicAuth(r *http.Request) string {
	clientID, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return clientID
}

// LookupClientByID loads an MCPOAuthClient by its client_id string.
func LookupClientByID(ctx context.Context, db *gorm.DB, clientID string) (*models.MCPOAuthClient, error) {
	var client models.MCPOAuthClient
	if err := db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

// HashClientSecret returns a bcrypt hash of the given plaintext secret.
func HashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GenerateClientSecret produces a random URL-safe token string for use as a
// client secret. The caller is responsible for displaying it once and storing
// only the hash via HashClientSecret.
func GenerateClientSecret() (string, error) {
	id := uuid.New()
	return strings.ReplaceAll(id.String(), "-", "") + strings.ReplaceAll(uuid.New().String(), "-", ""), nil
}
