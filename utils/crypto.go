// util/encryption.go
package utils

import (
	"bytes"
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

// DecryptString decrypts with the current key and, for values written before
// the key was configured correctly, with the legacy key (AS-020).
func DecryptString(ciphertextB64 string) (string, error) {
	plain, err := decryptWithKey(ciphertextB64, config.TOTPEncryptionKey)
	if err == nil || bytes.Equal(config.TOTPEncryptionKey, config.LegacyTOTPEncryptionKey) {
		return plain, err
	}
	if legacy, legacyErr := decryptWithKey(ciphertextB64, config.LegacyTOTPEncryptionKey); legacyErr == nil {
		return legacy, nil
	}
	return "", err
}

// ReencryptLegacy returns value re-encrypted under the current key when it is a
// ciphertext that only the legacy key opens. AES-GCM authenticates, so no
// other string is mistaken for one.
func ReencryptLegacy(value string) (string, bool, error) {
	if bytes.Equal(config.TOTPEncryptionKey, config.LegacyTOTPEncryptionKey) {
		return value, false, nil
	}
	if _, err := decryptWithKey(value, config.TOTPEncryptionKey); err == nil {
		return value, false, nil
	}
	plain, err := decryptWithKey(value, config.LegacyTOTPEncryptionKey)
	if err != nil {
		return value, false, nil
	}
	fresh, err := EncryptString(plain)
	if err != nil {
		return value, false, err
	}
	return fresh, true, nil
}

func decryptWithKey(ciphertextB64 string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ct := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
