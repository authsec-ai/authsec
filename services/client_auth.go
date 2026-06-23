package services

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
		return authenticateSPIFFESVID(ctx, db, assertion, tokenEndpoint)
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

// authenticateSPIFFESVID verifies a presented workload token (a SPIFFE JWT-SVID
// or a federated OIDC token) and resolves the corresponding mcp_oauth_client.
//
// Trust model (fail-closed): the token's issuer must be a registered, active
// workload_identity_provider OR (for back-compat) the single global
// SPIFFE_OIDC_ISSUER env. The signature is verified against that issuer's JWKS
// (via OIDC discovery or the provider's jwks_uri), the audience is checked, and
// the subject must map to an ACTIVE service account:
//   - kind 'spiffe': sub (a spiffe:// id) == service_accounts.spiffe_id
//   - kind 'oidc'  : the provider.subject_claim value == service_accounts.external_subject
//     (scoped to the provider's workspace)
//
// Only explicitly-registered (issuer, subject) pairs authenticate — an attacker
// with a token from an unregistered issuer, or a subject we never mapped, fails.
func authenticateSPIFFESVID(ctx context.Context, db *gorm.DB, svid, tokenEndpoint string) (*models.MCPOAuthClient, error) {
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
		return nil, fmt.Errorf("invalid_client: token must have iss and sub")
	}

	// Step 1b: resolve the issuer to a trusted provider (fail-closed). Prefer a
	// registered workload_identity_provider; fall back to the legacy single
	// global SPIFFE_OIDC_ISSUER env for spiffe. Anything else is rejected.
	var (
		kind         = "spiffe"
		jwksURL      string
		allowedAuds  []string
		subjectClaim = "sub"
		providerWS   *uuid.UUID
	)
	var provider models.WorkloadIdentityProvider
	perr := db.WithContext(ctx).
		Where("issuer = ? AND status = 'active'", iss).
		First(&provider).Error
	if perr == nil {
		kind = provider.Kind
		if provider.JWKSUri != nil && *provider.JWKSUri != "" {
			jwksURL = *provider.JWKSUri
		} else {
			jwksURL = jwksURLForIssuer(iss)
		}
		allowedAuds = []string(provider.AllowedAudiences)
		if provider.SubjectClaim != "" {
			subjectClaim = provider.SubjectClaim
		}
		ws := provider.WorkspaceID
		providerWS = &ws
	} else if errors.Is(perr, gorm.ErrRecordNotFound) {
		expectedIssuer := ""
		if config.AppConfig != nil {
			expectedIssuer = config.AppConfig.SpiffeOIDCIssuer
		}
		if expectedIssuer == "" {
			return nil, fmt.Errorf("invalid_client: no workload identity provider for this issuer")
		}
		if iss != expectedIssuer {
			// Unknown/untrusted caller — surface it (sub is UNVERIFIED here).
			log.Printf("auth.unverified_caller: workload auth attempt with untrusted issuer iss=%q claimed_sub=%q", iss, sub)
			return nil, fmt.Errorf("invalid_client: token issuer is not a trusted workload identity provider")
		}
		jwksURL = jwksURLForIssuer(iss)
		kind = "spiffe"
	} else {
		return nil, fmt.Errorf("invalid_client: %w", perr)
	}

	if kind == "spiffe" && !strings.HasPrefix(sub, "spiffe://") {
		return nil, fmt.Errorf("invalid_client: SVID sub must be a SPIFFE ID")
	}

	// Step 2: fetch the issuer's JWKS and verify the signature.
	jwksBody, err := fetchURL(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid_client: cannot fetch workload issuer JWKS: %w", err)
	}
	keyMap, err := parseJWKSKeys(string(jwksBody))
	if err != nil {
		return nil, fmt.Errorf("invalid_client: workload issuer JWKS parse error: %w", err)
	}

	parsed, err := jwt.Parse(svid, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
		default:
			return nil, fmt.Errorf("unsupported token alg: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if key, ok := keyMap[kid]; ok {
			return key, nil
		}
		for _, k := range keyMap {
			return k, nil
		}
		return nil, fmt.Errorf("kid not found in workload issuer JWKS")
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "ES512"}),
		jwt.WithLeeway(30*time.Second))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid_client: token verification failed: %w", err)
	}

	// Step 2b: validate audience. If the provider declares allowed audiences,
	// require one of them; otherwise require this token endpoint (the SPIFFE
	// default — `spire-agent api fetch jwt -audience <token-endpoint>`).
	if len(allowedAuds) > 0 {
		matched := false
		for _, a := range allowedAuds {
			if validateAud(claims, a) == nil {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("invalid_client: token aud must include one of the provider's allowed audiences")
		}
	} else if tokenEndpoint != "" {
		if err := validateAud(claims, tokenEndpoint); err != nil {
			return nil, fmt.Errorf("invalid_client: token aud must include this token endpoint")
		}
	}

	// Step 3: map the verified subject to an ACTIVE service account.
	var sa models.ServiceAccount
	if kind == "oidc" {
		// Extract the configured subject claim (defaults to "sub").
		subjVal := sub
		if subjectClaim != "sub" {
			subjVal, _ = claims[subjectClaim].(string)
		}
		if subjVal == "" {
			return nil, fmt.Errorf("invalid_client: token has no %q claim to map", subjectClaim)
		}
		q := db.WithContext(ctx).Where("external_subject = ? AND status = 'active'", subjVal)
		if providerWS != nil {
			q = q.Where("workspace_id = ?", *providerWS)
		}
		if err := q.First(&sa).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("auth.unknown_caller: verified federated token for unmapped subject %q (issuer %q)", subjVal, iss)
				return nil, fmt.Errorf("invalid_client: no active workload mapped to this federated subject")
			}
			return nil, fmt.Errorf("invalid_client: %w", err)
		}
	} else {
		if err := db.WithContext(ctx).
			Where("spiffe_id = ? AND status = 'active'", sub).
			First(&sa).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("auth.unknown_caller: verified SVID for unregistered SPIFFE ID sub=%q", sub)
				return nil, fmt.Errorf("invalid_client: no active service account for SPIFFE ID")
			}
			return nil, fmt.Errorf("invalid_client: %w", err)
		}
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

	// Lifecycle gate (spiffe): a revoked/disabled application_spiffe_identities
	// row must not keep minting tokens even if the SA stays active.
	if kind == "spiffe" {
		var revokedCount int64
		if err := db.WithContext(ctx).
			Table("application_spiffe_identities").
			Where("spiffe_id = ? AND (revoked_at IS NOT NULL OR status IN ('revoked','disabled'))", sub).
			Count(&revokedCount).Error; err != nil {
			return nil, fmt.Errorf("invalid_client: %w", err)
		}
		if revokedCount > 0 {
			return nil, fmt.Errorf("invalid_client: SPIFFE identity is revoked or disabled")
		}
	}

	now := time.Now().UTC()
	// Best-effort: advance attestation_pending → attested (spiffe only).
	if kind == "spiffe" {
		db.WithContext(ctx).Exec(
			`UPDATE application_spiffe_identities
			    SET status = 'attested', last_attested_at = ?, last_error = NULL, last_error_at = NULL
			  WHERE spiffe_id = ? AND status = 'attestation_pending'`,
			now, sub,
		)
	}
	// Best-effort: stamp last_seen_at so the inventory can age out stale workloads.
	db.WithContext(ctx).Exec(
		`UPDATE service_accounts SET last_seen_at = ? WHERE workspace_id = ? AND id = ?`,
		now, sa.WorkspaceID, sa.ID,
	)

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

// jwksURLForIssuer resolves an OIDC issuer's JWKS endpoint via discovery
// (OIDC Discovery / RFC 8414): GET <issuer>/.well-known/openid-configuration
// and read `jwks_uri`. This is the standards-correct way to find the keys and
// works with any compliant issuer — crucially, upstream SPIRE's
// oidc-discovery-provider serves JWKS at /keys (advertised via jwks_uri), not
// at /.well-known/jwks.json. If discovery is unavailable (or omits jwks_uri),
// we fall back to the legacy <issuer>/.well-known/jwks.json path so
// already-working issuers that publish there keep verifying.
func jwksURLForIssuer(iss string) string {
	base := strings.TrimRight(iss, "/")
	if body, err := fetchURL(base + "/.well-known/openid-configuration"); err == nil {
		var doc struct {
			JWKSUri string `json:"jwks_uri"`
		}
		if json.Unmarshal(body, &doc) == nil && doc.JWKSUri != "" {
			return doc.JWKSUri
		}
	}
	return base + "/.well-known/jwks.json"
}

// VerifySVID verifies a pasted JWT-SVID's signature against the configured
// SPIFFE OIDC issuer's JWKS and checks iss + aud — returning the SVID's `sub`
// (its SPIFFE ID). It performs NO database access and NO state changes (it does
// not advance attestation or consume replay state): it is purely for the access
// debugger's paste-SVID mode, which validates a real SVID without minting.
// The returned sub is best-effort even on error so the caller can still compare
// it to the registered SPIFFE ID.
func VerifySVID(svid, tokenEndpoint string) (string, error) {
	unverified, _, err := new(jwt.Parser).ParseUnverified(svid, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("malformed SVID: %w", err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("malformed SVID claims")
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return sub, fmt.Errorf("SVID must have iss and sub")
	}

	expectedIssuer := ""
	if config.AppConfig != nil {
		expectedIssuer = config.AppConfig.SpiffeOIDCIssuer
	}
	if expectedIssuer == "" {
		return sub, fmt.Errorf("SPIFFE_OIDC_ISSUER is not configured")
	}
	if iss != expectedIssuer {
		return sub, fmt.Errorf("SVID issuer %q is not the trusted SPIFFE OIDC issuer", iss)
	}

	body, err := fetchURL(jwksURLForIssuer(iss))
	if err != nil {
		return sub, fmt.Errorf("cannot fetch SPIFFE OIDC JWKS: %w", err)
	}
	keyMap, err := parseJWKSKeys(string(body))
	if err != nil {
		return sub, fmt.Errorf("SPIFFE JWKS parse error: %w", err)
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
		return sub, fmt.Errorf("SVID signature/expiry verification failed: %w", err)
	}

	if tokenEndpoint != "" {
		if err := validateAud(claims, tokenEndpoint); err != nil {
			return sub, fmt.Errorf("SVID aud must include the token endpoint %s", tokenEndpoint)
		}
	}
	return sub, nil
}

// ProbeSpiffeOIDC checks the two config preconditions a SPIFFE/Kubernetes
// workload needs before any SVID can verify: that SPIFFE_OIDC_ISSUER is set and
// that its JWKS is reachable + parseable from THIS backend (the same server-side
// fetch authenticateSPIFFESVID performs at auth time). The access debugger's
// config dry-run uses it. Returns the configured issuer (empty if unset) and a
// non-nil error when the issuer is unset or its keys can't be fetched/parsed.
func ProbeSpiffeOIDC() (string, error) {
	iss := ""
	if config.AppConfig != nil {
		iss = config.AppConfig.SpiffeOIDCIssuer
	}
	if iss == "" {
		return "", fmt.Errorf("SPIFFE_OIDC_ISSUER is not configured")
	}
	body, err := fetchURL(jwksURLForIssuer(iss))
	if err != nil {
		return iss, fmt.Errorf("cannot fetch SPIFFE OIDC JWKS: %w", err)
	}
	keys, err := parseJWKSKeys(string(body))
	if err != nil {
		return iss, fmt.Errorf("SPIFFE OIDC JWKS parse error: %w", err)
	}
	if len(keys) == 0 {
		return iss, fmt.Errorf("SPIFFE OIDC JWKS has no signing keys")
	}
	return iss, nil
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
