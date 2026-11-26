package middlewares

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AS-065: the SVID key is chosen by kid from the workspace's bundle, a
// rotated key is picked up, and the workspace must be a UUID that a spiffe://
// issuer agrees with.

func spiffeTestBundle(t *testing.T, keys map[string]*rsa.PrivateKey, fetches *int32) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(fetches, 1)
		var out []map[string]string
		for kid, k := range keys {
			out = append(out, map[string]string{
				"kty": "RSA", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": out})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("ICP_SERVICE_URL", srv.URL)
}

func spiffeTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSpiffeGetPublicKey_SelectsByKid(t *testing.T) {
	k1, k2 := spiffeTestKey(t), spiffeTestKey(t)
	var fetches int32
	spiffeTestBundle(t, map[string]*rsa.PrivateKey{"k1": k1, "k2": k2}, &fetches)
	ws := uuid.NewString()

	got, err := spiffeGetPublicKey(ws, "k2")
	if err != nil || got.N.Cmp(k2.N) != 0 {
		t.Fatalf("kid k2: got %v, %v; want k2's key", got, err)
	}
	if _, err := spiffeGetPublicKey(ws, ""); err == nil {
		t.Fatalf("a token without kid must not pick a key from a two-key bundle")
	}
	if _, err := spiffeGetPublicKey(ws, "unknown"); err == nil {
		t.Fatalf("an unknown kid must be refused")
	}
	if n := atomic.LoadInt32(&fetches); n != 1 {
		t.Fatalf("unknown kids within %s must not refetch: %d fetches", spiffeJWKSRefetchAfter, n)
	}
}

func TestSpiffeGetPublicKey_PicksUpRotatedKey(t *testing.T) {
	k1, k2 := spiffeTestKey(t), spiffeTestKey(t)
	keys := map[string]*rsa.PrivateKey{"k1": k1}
	var fetches int32
	spiffeTestBundle(t, keys, &fetches)
	ws := uuid.NewString()

	if _, err := spiffeGetPublicKey(ws, "k1"); err != nil {
		t.Fatalf("k1: %v", err)
	}
	keys["k2"] = k2
	// Age the cache entry past the refetch floor, as after a rotation.
	spiffeJWKSCacheMu.Lock()
	spiffeJWKSCache[ws].fetchedAt = time.Now().Add(-spiffeJWKSRefetchAfter - time.Second)
	spiffeJWKSCacheMu.Unlock()
	if got, err := spiffeGetPublicKey(ws, "k2"); err != nil || got.N.Cmp(k2.N) != 0 {
		t.Fatalf("rotated key k2 not picked up: %v", err)
	}
}

func TestSpiffeAuthMiddleware_RejectsBadWorkspaceClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)
	k := spiffeTestKey(t)
	var fetches int32
	ws := uuid.NewString()
	spiffeTestBundle(t, map[string]*rsa.PrivateKey{"k": k}, &fetches)

	for name, claims := range map[string]jwt.MapClaims{
		"not a uuid":         {"workspace_id": "acme"},
		"issuer disagrees":   {"workspace_id": ws, "iss": "spiffe://" + uuid.NewString()},
		"nil workspace uuid": {"workspace_id": uuid.Nil.String()},
	} {
		claims["sub"] = "spiffe://example.org/agent"
		claims["aud"] = "authsec-api"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k"
		signed, err := tok.SignedString(k)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer "+signed)
		SpiffeAuthMiddleware()(c)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, w.Code)
		}
	}
	if n := atomic.LoadInt32(&fetches); n != 0 {
		t.Fatalf("bad workspace claims must be refused before any bundle fetch: %d fetches", n)
	}
}
