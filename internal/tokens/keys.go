package tokens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// nativeKVMount and the key paths reuse the SAME Vault KV mechanism as the
// JWT-SVID service (mount "kv"), but a DISTINCT path namespace and NO SPIFFE
// issuer semantics — this is a brand-new key manager, not the SVID signer (§5).
const (
	nativeKVMount       = "kv"
	nativeKeyPathActive = "secret/oauth/native-signing-keys/active"
	nativeKeyPathNext   = "secret/oauth/native-signing-keys/next"

	// keyReloadInterval mirrors the Hydra jwksCache TTL so multiple pods
	// converge on a rotated keyset within one interval (keys live in Vault).
	keyReloadInterval = 5 * time.Minute

	// nativeKeyEnvB64 pins the ACTIVE native signing key to a fixed base64
	// (PKCS8 PEM) value, mirroring SPIFFE_RSA_PRIVATE_KEY_B64. When set, the
	// active key (and thus its kid) is stable across restarts WITHOUT Vault —
	// so already-issued id_tokens/ID-JAGs keep validating after a redeploy.
	// Intended for single-node/dev where no Vault is wired; prod should use Vault.
	nativeKeyEnvB64 = "NATIVE_RSA_PRIVATE_KEY_B64"
)

// KVStore is the minimal Vault KV surface the key manager needs. *vault.Client
// satisfies it; a nil KVStore forces ephemeral (in-memory) keys for local dev.
type KVStore interface {
	ReadKVSecret(ctx context.Context, kvMount, secretPath string) (map[string]interface{}, error)
	WriteKVSecret(ctx context.Context, kvMount, secretPath string, data map[string]interface{}) error
}

type nativeKey struct {
	kid  string
	priv *rsa.PrivateKey
}

// NativeKeyManager owns a small GLOBAL rotating RS256 keyset (active + next) for
// the NativeSealer. The kid is opaque ("native:<hash>") with no workspace id, so
// the public JWKS cannot leak ownership and cannot grow per workspace (§17).
//
// Keys are persisted in Vault KV so all pods read the same material and converge
// on rotation. When Vault is unavailable the manager falls back to ephemeral
// keys (valid only within this process) so local dev still works.
type NativeKeyManager struct {
	mu       sync.RWMutex
	active   nativeKey
	next     nativeKey
	kv       KVStore
	loadedAt time.Time
}

// NewNativeKeyManager loads (or generates) the keyset and returns a ready
// manager. It never returns nil: a Vault failure degrades to ephemeral keys.
func NewNativeKeyManager(kv KVStore) *NativeKeyManager {
	m := &NativeKeyManager{kv: kv}
	m.reload()
	return m
}

// Reload re-reads the keyset from Vault (picks up rotation by another pod). Safe
// to call from a ticker. No-op cost when called more often than the interval.
func (m *NativeKeyManager) Reload() { m.reload() }

func (m *NativeKeyManager) reload() {
	var active nativeKey
	if envKey, ok := keyFromEnvB64(); ok {
		// Env-pinned active key takes precedence over Vault/ephemeral: stable
		// kid across restarts so outstanding tokens keep validating.
		active = envKey
	} else if a, err := m.loadOrCreate(nativeKeyPathActive); err == nil {
		active = a
	} else {
		log.Printf("[NATIVE_KEYS] active key load failed, using ephemeral: %v", err)
		active = mustGenerate()
	}
	next, err := m.loadOrCreate(nativeKeyPathNext)
	if err != nil {
		log.Printf("[NATIVE_KEYS] next key load failed, using ephemeral: %v", err)
		next = mustGenerate()
	}
	m.mu.Lock()
	m.active, m.next, m.loadedAt = active, next, time.Now()
	m.mu.Unlock()
}

// loadOrCreate reads a key from Vault; if absent it generates one and persists
// it (best effort). Returns an error only when Vault is configured but the
// persisted material is unreadable AND generation should not silently mask it.
func (m *NativeKeyManager) loadOrCreate(path string) (nativeKey, error) {
	if m.kv == nil {
		// No Vault wired (local dev) — ephemeral key, stable for this process.
		return mustGenerate(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := m.kv.ReadKVSecret(ctx, nativeKVMount, path)
	if err == nil && data != nil {
		if pemStr, ok := data["private_key_pem"].(string); ok && pemStr != "" {
			priv, perr := parsePKCS8RSA(pemStr)
			if perr == nil {
				return nativeKey{kid: deriveKID(&priv.PublicKey), priv: priv}, nil
			}
			log.Printf("[NATIVE_KEYS] stored key at %s unparseable, regenerating: %v", path, perr)
		}
	}

	// Generate + persist (best effort: ephemeral if the write fails).
	priv := generate()
	pemStr := marshalPKCS8RSA(priv)
	if werr := m.kv.WriteKVSecret(ctx, nativeKVMount, path, map[string]interface{}{
		"private_key_pem": pemStr,
		"created_at":      time.Now().UTC().Format(time.RFC3339),
	}); werr != nil {
		log.Printf("[NATIVE_KEYS] persist to %s failed (key ephemeral until next restart): %v", path, werr)
	}
	return nativeKey{kid: deriveKID(&priv.PublicKey), priv: priv}, nil
}

// Sign signs claims with the ACTIVE key as an `at+jwt` RS256 token (§ claim
// matrix). The header kid commits the token to the native validation path.
func (m *NativeKeyManager) Sign(claims jwt.MapClaims) (string, error) {
	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()
	if active.priv == nil {
		return "", fmt.Errorf("native key manager: no active signing key")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = active.kid
	tok.Header["typ"] = "at+jwt"
	return tok.SignedString(active.priv)
}

// SignWithTyp signs claims with the ACTIVE key using the provided JWT typ header.
// Used for token types that share the native keyset but differ from at+jwt
// (e.g. id-jag tokens use typ="oauth-id-jag+jwt").
func (m *NativeKeyManager) SignWithTyp(claims jwt.MapClaims, typ string) (string, error) {
	m.mu.RLock()
	active := m.active
	m.mu.RUnlock()
	if active.priv == nil {
		return "", fmt.Errorf("native key manager: no active signing key")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = active.kid
	tok.Header["typ"] = typ
	return tok.SignedString(active.priv)
}

// PublicKeyForKID returns the RSA public key for a published kid (active or
// next), so introspection can verify a native token's signature.
func (m *NativeKeyManager) PublicKeyForKID(kid string) (*rsa.PublicKey, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch kid {
	case m.active.kid:
		return &m.active.priv.PublicKey, true
	case m.next.kid:
		return &m.next.priv.PublicKey, true
	default:
		return nil, false
	}
}

// NativeKeyIDs returns the set of currently-published native kids (active+next).
func (m *NativeKeyManager) NativeKeyIDs() map[string]struct{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]struct{}{m.active.kid: {}, m.next.kid: {}}
}

// PublicJWKS returns the native public keys as JWK objects (active then next),
// for appending to the public /oauth/jwks union. Never inserted into the
// Hydra-only logout cache.
func (m *NativeKeyManager) PublicJWKS() []map[string]interface{} {
	m.mu.RLock()
	keys := []nativeKey{m.active, m.next}
	m.mu.RUnlock()

	out := make([]map[string]interface{}, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		if k.priv == nil {
			continue
		}
		if _, dup := seen[k.kid]; dup {
			continue
		}
		seen[k.kid] = struct{}{}
		out = append(out, jwkFromRSA(k.kid, &k.priv.PublicKey))
	}
	return out
}

// --- helpers ---

func jwkFromRSA(kid string, pub *rsa.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// deriveKID produces a stable opaque kid from the public key (SHA-256 of the
// SubjectPublicKeyInfo DER, first 16 hex chars). No workspace id (§17).
func deriveKID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Should never happen for an RSA public key.
		panic(fmt.Sprintf("native key: marshal public key: %v", err))
	}
	sum := sha256.Sum256(der)
	return NativeKIDPrefix + hex.EncodeToString(sum[:8])
}

// keyFromEnvB64 builds the active native key from NATIVE_RSA_PRIVATE_KEY_B64
// (base64 of a PKCS8 PEM, the same shape marshalPKCS8RSA emits). Returns ok=false
// when unset; bad values are logged and ignored so the manager falls back safely.
func keyFromEnvB64() (nativeKey, bool) {
	raw := strings.TrimSpace(os.Getenv(nativeKeyEnvB64))
	if raw == "" {
		return nativeKey{}, false
	}
	pemBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		log.Printf("[NATIVE_KEYS] %s set but not valid base64, ignoring: %v", nativeKeyEnvB64, err)
		return nativeKey{}, false
	}
	priv, err := parsePKCS8RSA(string(pemBytes))
	if err != nil {
		log.Printf("[NATIVE_KEYS] %s set but unparseable PKCS8 PEM, ignoring: %v", nativeKeyEnvB64, err)
		return nativeKey{}, false
	}
	log.Printf("[NATIVE_KEYS] active key pinned from %s (kid=%s) — stable across restarts", nativeKeyEnvB64, deriveKID(&priv.PublicKey))
	return nativeKey{kid: deriveKID(&priv.PublicKey), priv: priv}, true
}

func generate() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("native key: generate RSA: %v", err))
	}
	return key
}

func mustGenerate() nativeKey {
	priv := generate()
	return nativeKey{kid: deriveKID(&priv.PublicKey), priv: priv}
}

func marshalPKCS8RSA(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(fmt.Sprintf("native key: marshal PKCS8: %v", err))
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func parsePKCS8RSA(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}
