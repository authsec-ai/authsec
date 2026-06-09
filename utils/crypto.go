// util/encryption.go
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/authsec-ai/authsec/config"
)

func EncryptString(plaintext string) (string, error) {
	key := config.TOTPEncryptionKey

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { // io.ReadFull avoids short reads
		return "", err
	}

	// Prepend nonce: output = nonce || ciphertext||tag
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptStringCompat decrypts a value that may be either encrypted (by
// EncryptString, possibly under a rotated/legacy key) OR legacy plaintext that
// predates encryption. If decryption fails it returns the input unchanged,
// treating it as legacy plaintext. Use only for fields that were historically
// stored in the clear and are being migrated to encryption (e.g.
// totp_secrets.secret) so existing rows keep working during rollout.
func DecryptStringCompat(stored string) string {
	if stored == "" {
		return ""
	}
	if plain, err := DecryptString(stored); err == nil {
		return plain
	}
	return stored
}

func DecryptString(ciphertextB64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}

	// Try the active key first, then any rotation/legacy fallback keys so that
	// secrets written under a previous key still decrypt. See
	// config.TOTPDecryptionKeys.
	keys := config.TOTPDecryptionKeys
	if len(keys) == 0 {
		keys = [][]byte{config.TOTPEncryptionKey}
	}

	var lastErr error
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			lastErr = err
			continue
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}

		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return "", fmt.Errorf("ciphertext too short")
		}

		nonce, ct := data[:nonceSize], data[nonceSize:]
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			lastErr = err
			continue
		}

		return string(plain), nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no decryption key configured")
	}
	return "", lastErr
}
