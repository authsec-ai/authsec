package policybundle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	ErrInvalidSignature  = errors.New("policybundle: invalid signature")
	ErrKeyMismatch       = errors.New("policybundle: signing key not in trusted set")
	ErrAlgorithmMismatch = errors.New("policybundle: algorithm mismatch (expected ES256)")
	ErrMalformedJWS      = errors.New("policybundle: malformed JWS compact serialization")
	ErrDuplicateJSONKeys = errors.New("policybundle: duplicate JSON keys in manifest")
)

// JWS header for ES256 signing.
type jwsHeader struct {
	Alg string `json:"alg"` // "ES256"
	Kid string `json:"kid"` // Key identifier
	Typ string `json:"typ"` // "aspol+jwt"
}

// Sign creates a JWS compact serialization of the manifest using an ES256
// private key. The key identifier is included in the JWS header for verification.
func Sign(manifest BundleManifest, privateKey *ecdsa.PrivateKey, keyID string) (string, error) {
	// Encode header.
	header := jwsHeader{Alg: "ES256", Kid: keyID, Typ: "aspol+jwt"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("policybundle: marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload.
	payloadJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("policybundle: marshal manifest: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign.
	sigInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("policybundle: ecdsa sign: %w", err)
	}

	// Encode signature as R || S (32 bytes each for P-256).
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}

// Verify checks a JWS compact serialization against a set of trusted public
// keys. It returns the decoded manifest on success. Verification rejects:
//   - Algorithm mismatch (only ES256)
//   - Key ID not in the trusted set
//   - Invalid ECDSA signature
//   - Malformed JWS structure
func Verify(jws string, trustedKeys map[string]*ecdsa.PublicKey) (BundleManifest, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return BundleManifest{}, ErrMalformedJWS
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return BundleManifest{}, fmt.Errorf("policybundle: decode header: %w", err)
	}
	var header jwsHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return BundleManifest{}, fmt.Errorf("policybundle: parse header: %w", err)
	}
	if header.Alg != "ES256" {
		return BundleManifest{}, ErrAlgorithmMismatch
	}

	// Look up key.
	pubKey, ok := trustedKeys[header.Kid]
	if !ok {
		return BundleManifest{}, ErrKeyMismatch
	}

	// Verify signature.
	sigInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(sigInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != 64 {
		return BundleManifest{}, ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return BundleManifest{}, ErrInvalidSignature
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return BundleManifest{}, fmt.Errorf("policybundle: decode payload: %w", err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(payloadJSON, &manifest); err != nil {
		return BundleManifest{}, fmt.Errorf("policybundle: parse manifest: %w", err)
	}

	return manifest, nil
}

// GenerateKeyPair creates a new ES256 key pair for testing.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of a public key.
func PublicKeyFingerprint(pub *ecdsa.PublicKey) string {
	raw := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%s", base64.RawURLEncoding.EncodeToString(sum[:]))
}

// ensure ecdsa.PrivateKey implements crypto.Signer
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
