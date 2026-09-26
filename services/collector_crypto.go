package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// Token prefixes keep the three credentials from being interchangeable.
	// A v1 actuation token starts with PrefixActuation and is rejected by the
	// v2 middleware before any database lookup. A v2 credential starts with
	// PrefixCollector and is rejected by v1 actuation authentication.
	PrefixEnrollment = "authsec_enr_"
	PrefixCollector  = "authsec_col_"
	PrefixActuation  = "authsec_act_"
)

// HashCollectorSecret is SHA-256 of a high-entropy token. The plaintext is
// never stored. Same construction as the actuation token hash, different table.
func HashCollectorSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// MintPrefixedToken returns prefix plus 32 random bytes, URL-safe, no padding.
func MintPrefixedToken(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// InstallationKeyID is the stable id of an installation public key.
func InstallationKeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// RecoveryKeyHash binds a retry to one installation key and one nonce.
func RecoveryKeyHash(publicKey []byte, nonce string) string {
	h := sha256.New()
	_, _ = h.Write(publicKey)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// ParseEd25519PublicKey accepts standard or raw-URL base64 of a 32-byte key.
func ParseEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := decodeFlexible(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("installation public key must be a raw Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// ParseEd25519Signature accepts standard or raw-URL base64 of a 64-byte signature.
func ParseEd25519Signature(encoded string) ([]byte, error) {
	raw, err := decodeFlexible(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("signature must be a raw Ed25519 signature")
	}
	return raw, nil
}

func decodeFlexible(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// RotateSignedMessage is the exact byte string the installation key must sign.
// scopes is the comma-joined sorted scope list the caller is requesting, or
// empty when the caller is not changing scopes.
func RotateSignedMessage(collectorID, nonce, requestedAt, newPublicKey, scopes string) []byte {
	return []byte(strings.Join([]string{
		"authsec.collector.rotate.v1",
		collectorID,
		nonce,
		requestedAt,
		newPublicKey,
		scopes,
	}, "\n"))
}

// ResponseSealer encrypts the one-time enroll response. The key comes from
// IGA_COLLECTOR_RESPONSE_KEY or from a runtime-generated file under .secrets/,
// which is git-ignored. Nothing here is a committed secret.
type ResponseSealer struct {
	key []byte
}

// NewResponseSealer loads or creates the response-encryption key.
func NewResponseSealer() (*ResponseSealer, error) {
	key, err := loadResponseKey()
	if err != nil {
		return nil, err
	}
	return &ResponseSealer{key: key}, nil
}

func loadResponseKey() ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("IGA_COLLECTOR_RESPONSE_KEY")); v != "" {
		sum := sha256.Sum256([]byte(v))
		return sum[:], nil
	}
	path := filepath.Join(".secrets", "collector-response.key")
	if b, err := os.ReadFile(path); err == nil && len(bytesTrim(b)) >= 16 {
		sum := sha256.Sum256(b)
		return sum[:], nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate response key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		_ = os.WriteFile(path, raw, 0o600)
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// Seal encrypts plaintext. The result is nonce || ciphertext.
func (s *ResponseSealer) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal.
func (s *ResponseSealer) Open(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
