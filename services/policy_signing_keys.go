package services

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/sign"
	"github.com/authsec-ai/authsec/internal/vault"
)

// Signing-key configuration. A path is a filesystem path or a Vault KV v2
// path. The PEM itself is never logged and never returned by an error.
const (
	EnvPolicySigningKeyPEM         = "IGA_POLICY_SIGNING_KEY_PEM"
	EnvPolicySigningKeyID          = "IGA_POLICY_SIGNING_KEY_ID"
	EnvPolicySigningPreviousKeyPEM = "IGA_POLICY_SIGNING_PREVIOUS_KEY_PEM"
	EnvPolicySigningPreviousKeyID  = "IGA_POLICY_SIGNING_PREVIOUS_KEY_ID"
	EnvPolicySigningOverlapUntil   = "IGA_POLICY_SIGNING_OVERLAP_UNTIL"
	EnvPolicySigningVaultPath      = "IGA_POLICY_SIGNING_VAULT_PATH"
	EnvPolicyCanaryWindow          = "IGA_POLICY_CANARY_WINDOW_SECONDS"
)

// PolicyPublicKey is the verify material served to collectors.
type PolicyPublicKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Current      bool   `json:"current"`
}

// PolicyKeySet is the current key and, during overlap, the previous key.
type PolicyKeySet struct {
	Current  sign.Key
	Previous *sign.Key
	Public   []PolicyPublicKey
}

// SigningKeys returns current first, then the previous key while overlap holds.
func (s PolicyKeySet) SigningKeys() []sign.Key {
	out := []sign.Key{s.Current}
	if s.Previous != nil {
		out = append(out, *s.Previous)
	}
	return out
}

// policyKeyCacheTTL bounds how often a Vault path is read. The cache key is
// the env paths and ids, never the PEM bytes. Tests that point
// IGA_POLICY_SIGNING_KEY_PEM at a fresh directory do not share a stale miss.
const policyKeyCacheTTL = 60 * time.Second

type policyKeyCacheEntry struct {
	mu  sync.Mutex
	key string
	at  time.Time
	set PolicyKeySet
	err error
}

var loadedPolicyKeys policyKeyCacheEntry

// LoadPolicyKeys reads the current signing key. A missing key is
// "policy signing key is not configured". A present key that does not parse
// is "policy signing key could not be parsed". Neither error includes key
// bytes or the path.
//
// The previous key is file-only and must be a private PEM. During overlap the
// detached manifest is dual-signed, so a public PEM is not enough. The bundle
// itself carries one JWT, the current key, because stock OPA rejects a
// signatures file with more than one. Vault (IGA_POLICY_SIGNING_VAULT_PATH)
// supplies only the current key. Parsed keys are cached in process for
// policyKeyCacheTTL and are never logged.
func LoadPolicyKeys(now time.Time) (PolicyKeySet, error) {
	key := policyKeyCacheKey(now)
	loadedPolicyKeys.mu.Lock()
	defer loadedPolicyKeys.mu.Unlock()
	if loadedPolicyKeys.key == key && !loadedPolicyKeys.at.IsZero() && time.Since(loadedPolicyKeys.at) < policyKeyCacheTTL {
		return loadedPolicyKeys.set, loadedPolicyKeys.err
	}
	set, err := loadPolicyKeys(now)
	loadedPolicyKeys.key = key
	loadedPolicyKeys.at = time.Now()
	loadedPolicyKeys.set = set
	loadedPolicyKeys.err = err
	return set, err
}

func policyKeyCacheKey(now time.Time) string {
	open := "0"
	if overlapOpen(now) {
		open = "1"
	}
	return strings.Join([]string{
		os.Getenv(EnvPolicySigningKeyPEM),
		os.Getenv(EnvPolicySigningKeyID),
		os.Getenv(EnvPolicySigningPreviousKeyPEM),
		os.Getenv(EnvPolicySigningPreviousKeyID),
		os.Getenv(EnvPolicySigningOverlapUntil),
		os.Getenv(EnvPolicySigningVaultPath),
		os.Getenv("VAULT_ADDR"),
		open,
	}, "\x00")
}

func loadPolicyKeys(now time.Time) (PolicyKeySet, error) {
	current, err := loadOneKey(EnvPolicySigningKeyPEM, EnvPolicySigningKeyID, "current", true)
	if err != nil {
		return PolicyKeySet{}, err
	}
	set := PolicyKeySet{Current: current}
	if overlapOpen(now) {
		prev, err := loadOneKey(EnvPolicySigningPreviousKeyPEM, EnvPolicySigningPreviousKeyID, "previous", false)
		if err != nil {
			return PolicyKeySet{}, err
		}
		if prev.Private != nil {
			set.Previous = &prev
		}
	}
	set.Public = publicKeys(set)
	return set, nil
}

// PolicyPublicKeys is the enrollment and GET /policy-keys view. A missing
// key yields an empty list so enrollment still succeeds.
func PolicyPublicKeys(now time.Time) []PolicyPublicKey {
	set, err := LoadPolicyKeys(now)
	if err != nil {
		return nil
	}
	return set.Public
}

func publicKeys(set PolicyKeySet) []PolicyPublicKey {
	out := make([]PolicyPublicKey, 0, 2)
	if pem, err := sign.PublicPEM(set.Current.Public); err == nil {
		out = append(out, PolicyPublicKey{KeyID: set.Current.ID, PublicKeyPEM: pem, Current: true})
	}
	if set.Previous != nil {
		if pem, err := sign.PublicPEM(set.Previous.Public); err == nil {
			out = append(out, PolicyPublicKey{KeyID: set.Previous.ID, PublicKeyPEM: pem, Current: false})
		}
	}
	return out
}

func overlapOpen(now time.Time) bool {
	raw := strings.TrimSpace(os.Getenv(EnvPolicySigningOverlapUntil))
	if raw == "" {
		return false
	}
	until, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return until.After(now)
}

func loadOneKey(pathEnv, idEnv, defaultID string, required bool) (sign.Key, error) {
	id := strings.TrimSpace(os.Getenv(idEnv))
	if id == "" {
		id = defaultID
	}
	pemPath := strings.TrimSpace(os.Getenv(pathEnv))
	var pemBytes []byte
	var err error
	switch {
	case pemPath != "":
		pemBytes, err = os.ReadFile(pemPath)
		if err != nil {
			if os.IsNotExist(err) && !required {
				return sign.Key{}, nil
			}
			if required && os.IsNotExist(err) {
				return sign.Key{}, errNotConfigured
			}
			return sign.Key{}, errKeyParse
		}
	case required && strings.TrimSpace(os.Getenv(EnvPolicySigningVaultPath)) != "":
		pemBytes, id, err = loadVaultKey(id)
		if err != nil {
			return sign.Key{}, err
		}
	default:
		if required {
			return sign.Key{}, errNotConfigured
		}
		return sign.Key{}, nil
	}
	key, err := sign.ParseECPrivateKey(pemBytes, id)
	if err != nil {
		return sign.Key{}, errKeyParse
	}
	return key, nil
}

func loadVaultKey(fallbackID string) ([]byte, string, error) {
	addr := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	path := strings.TrimSpace(os.Getenv(EnvPolicySigningVaultPath))
	if addr == "" || token == "" || path == "" {
		return nil, "", errNotConfigured
	}
	client, err := vault.NewClient(addr, token)
	if err != nil {
		return nil, "", errKeyParse
	}
	secret, err := client.ReadSecret(path)
	if err != nil || secret == nil {
		return nil, "", errKeyParse
	}
	pem, _ := secret["private_key_pem"].(string)
	if strings.TrimSpace(pem) == "" {
		return nil, "", errKeyParse
	}
	id, _ := secret["key_id"].(string)
	if strings.TrimSpace(id) == "" {
		id = fallbackID
	}
	return []byte(pem), id, nil
}

type keyError string

func (e keyError) Error() string { return string(e) }

const (
	errNotConfigured keyError = "policy signing key is not configured"
	errKeyParse      keyError = "policy signing key could not be parsed"
)

// CanaryWindow is the default pause window. IGA_POLICY_CANARY_WINDOW_SECONDS
// overrides it. The publish request can still set its own window.
func CanaryWindow() time.Duration {
	v := strings.TrimSpace(os.Getenv(EnvPolicyCanaryWindow))
	if v == "" {
		return 10 * time.Minute
	}
	n, err := time.ParseDuration(v + "s")
	if err != nil || n < time.Second {
		return 10 * time.Minute
	}
	return n
}
