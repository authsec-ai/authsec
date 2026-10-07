package middlewares

// SpiffeAuthMiddleware validates SPIFFE JWT-SVIDs issued by authsec-spire.
// Falls back to the standard AuthMiddleware if the token is not a SPIFFE JWT-SVID.
// When a valid SPIFFE token is accepted the following context keys are set:
//
//   - "claims"      – jwt.MapClaims of the verified token
//   - "auth_method" – "spiffe-jwt-svid"
//   - "spiffe_id"   – the sub claim (e.g. "spiffe://tenant-id/agent/...")
//   - "spiffe_workspace_id" – the workspace whose JWKS verified the token
//   - the tenancy context, for that workspace
//
// Ported from external-service/middleware/spiffe_auth.go.

import (
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/delegation"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SpiffeAuthMiddleware returns a gin.HandlerFunc that accepts either a
// standard auth-manager JWT or a SPIFFE JWT-SVID.
func SpiffeAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := spiffeExtractBearer(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization token"})
			return
		}

		// Parse unverified to check whether this is a SPIFFE JWT-SVID.
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		unverified, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			return
		}

		claims, ok := unverified.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		sub, _ := claims["sub"].(string)
		if !strings.HasPrefix(sub, "spiffe://") {
			// Not a SPIFFE token — delegate to standard auth middleware.
			AuthMiddleware()(c)
			return
		}

		// The unverified claims only say which workspace's trust bundle to
		// try. The workspace is established by that bundle verifying the
		// signature; workspace_id and a spiffe:// iss, when both are present,
		// must agree (AS-065).
		workspaceID, _ := claims["workspace_id"].(string)
		iss, _ := claims["iss"].(string)
		issWS := strings.TrimPrefix(iss, "spiffe://")
		if workspaceID == "" {
			workspaceID = issWS
		}
		wsUUID, perr := uuid.Parse(workspaceID)
		if perr != nil || wsUUID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Cannot determine workspace_id from SPIFFE JWT-SVID"})
			return
		}
		if strings.HasPrefix(iss, "spiffe://") && !strings.EqualFold(issWS, workspaceID) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "SPIFFE token workspace and issuer disagree"})
			return
		}

		verified, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			kid, _ := t.Header["kid"].(string)
			return spiffeGetPublicKey(wsUUID.String(), kid)
		}, jwt.WithExpirationRequired())
		if err != nil {
			log.Printf("[SpiffeAuth] Token verification failed for workspace %s: %v", wsUUID, err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "SPIFFE token verification failed"})
			return
		}

		verifiedClaims, ok := verified.Claims.(jwt.MapClaims)
		if !ok || !verified.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid SPIFFE token"})
			return
		}
		if !spiffeAudienceAllowed(verifiedClaims["aud"]) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "SPIFFE token audience mismatch"})
			return
		}
		// A delegated JWT-SVID must still be its agent's active delegation
		// token, issued for at most delegation.MaxTTL (AS-069). Fails closed.
		if err := delegation.Verify(c.Request.Context(), spiffeDelegationDB(), verifiedClaims, token); err != nil {
			log.Printf("[SpiffeAuth] Delegated token refused: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "SPIFFE token has been revoked or is no longer valid"})
			return
		}

		// Map SPIFFE "permissions" claim to the format expected by auth-manager.
		if perms, ok := verifiedClaims["permissions"].([]interface{}); ok {
			parts := make([]string, 0, len(perms))
			for _, p := range perms {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			verifiedClaims["scope"] = strings.Join(parts, " ")
		}

		c.Set("claims", verifiedClaims)
		c.Set("auth_method", "spiffe-jwt-svid")
		c.Set("spiffe_id", sub)
		// The workspace whose trust bundle verified the signature.
		c.Set("spiffe_workspace_id", wsUUID.String())
		tenancy.Set(c, tenancy.Context{WorkspaceID: wsUUID, PrincipalKind: "workload", Realm: "spiffe"})

		c.Next()
	}
}

func spiffeDelegationDB() *sql.DB {
	if db := config.GetDatabase(); db != nil {
		return db.DB
	}
	return nil
}

func spiffeAudienceAllowed(raw interface{}) bool {
	expected := os.Getenv("AUTHSEC_SPIFFE_AUDIENCE")
	if expected == "" {
		expected = "authsec-api"
	}

	allowed := map[string]struct{}{}
	for _, aud := range strings.Split(expected, ",") {
		aud = strings.TrimSpace(aud)
		if aud != "" {
			allowed[aud] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return false
	}

	switch aud := raw.(type) {
	case string:
		_, ok := allowed[aud]
		return ok
	case []string:
		for _, item := range aud {
			if _, ok := allowed[item]; ok {
				return true
			}
		}
	case []interface{}:
		for _, item := range aud {
			if s, ok := item.(string); ok {
				if _, allowed := allowed[s]; allowed {
					return true
				}
			}
		}
	}
	return false
}

// --- JWKS caching ---

var (
	spiffeJWKSCache   = make(map[string]*spiffeJWKSCacheEntry)
	spiffeJWKSCacheMu sync.RWMutex
)

// spiffeJWKSCacheEntry holds every RSA key of one workspace's bundle by kid.
type spiffeJWKSCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

const (
	spiffeJWKSCacheTTL = 5 * time.Minute
	// An unknown kid refetches the bundle (key rotation), but at most this
	// often per workspace, so unknown kids cannot drive a fetch per request.
	spiffeJWKSRefetchAfter = 30 * time.Second
)

var spiffeBundleClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// spiffeGetPublicKey returns the key with the given kid from the workspace's
// trust bundle. A token without a kid is accepted only against a bundle with
// exactly one key.
func spiffeGetPublicKey(workspaceID, kid string) (*rsa.PublicKey, error) {
	spiffeJWKSCacheMu.RLock()
	entry := spiffeJWKSCache[workspaceID]
	spiffeJWKSCacheMu.RUnlock()

	fresh := entry != nil && time.Since(entry.fetchedAt) < spiffeJWKSCacheTTL
	if fresh {
		if k, ok := spiffePickKey(entry.keys, kid); ok {
			return k, nil
		}
		if time.Since(entry.fetchedAt) < spiffeJWKSRefetchAfter {
			return nil, fmt.Errorf("no key %q in the trust bundle of workspace %s", kid, workspaceID)
		}
	}

	keys, err := spiffeFetchBundle(workspaceID)
	if err != nil {
		return nil, err
	}
	spiffeJWKSCacheMu.Lock()
	spiffeJWKSCache[workspaceID] = &spiffeJWKSCacheEntry{keys: keys, fetchedAt: time.Now()}
	spiffeJWKSCacheMu.Unlock()

	if k, ok := spiffePickKey(keys, kid); ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key %q in the trust bundle of workspace %s", kid, workspaceID)
}

func spiffePickKey(keys map[string]*rsa.PublicKey, kid string) (*rsa.PublicKey, bool) {
	if kid != "" {
		k, ok := keys[kid]
		return k, ok
	}
	if len(keys) == 1 {
		for _, k := range keys {
			return k, true
		}
	}
	return nil, false
}

// spiffeBundleURL is the ICP trust-bundle endpoint. ICP_SERVICE_URL is
// operator configuration; the localhost default is for development only.
func spiffeBundleURL(workspaceID string) (string, error) {
	base := strings.TrimRight(os.Getenv("ICP_SERVICE_URL"), "/")
	if base == "" {
		if strings.EqualFold(os.Getenv("ENVIRONMENT"), "production") {
			return "", fmt.Errorf("ICP_SERVICE_URL is not set")
		}
		base = "http://localhost:7001"
	}
	return base + "/v1/jwt/bundle?workspace_id=" + url.QueryEscape(workspaceID), nil
}

func spiffeFetchBundle(workspaceID string) (map[string]*rsa.PublicKey, error) {
	bundleURL, err := spiffeBundleURL(workspaceID)
	if err != nil {
		return nil, err
	}
	resp, err := spiffeBundleClient.Get(bundleURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("JWKS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := spiffeParseRSAPublicKey(k.N, k.E)
		if err != nil {
			log.Printf("[SpiffeAuth] Skipping unparsable key %q for workspace %s: %v", k.Kid, workspaceID, err)
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no RSA keys in JWKS response for workspace %s", workspaceID)
	}
	return keys, nil
}

func spiffeParseRSAPublicKey(nBase64, eBase64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nBase64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eBase64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func spiffeExtractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
