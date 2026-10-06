package utils

import (
	"bytes"
	"testing"

	"github.com/authsec-ai/authsec/config"
)

func withTOTPKey(t *testing.T, key []byte) {
	t.Helper()
	prev := config.TOTPEncryptionKey
	config.TOTPEncryptionKey = key
	t.Cleanup(func() { config.TOTPEncryptionKey = prev })
}

// AS-020: secrets written under the legacy key stay readable after the real
// key is configured, and are re-encrypted under it.
func TestLegacyCiphertexts_DecryptAndRotate(t *testing.T) {
	withTOTPKey(t, config.LegacyTOTPEncryptionKey)
	legacyCT, err := EncryptString("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}

	withTOTPKey(t, bytes.Repeat([]byte{0x24}, 32))
	if got, err := DecryptString(legacyCT); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("legacy ciphertext must still decrypt: %q %v", got, err)
	}

	fresh, changed, err := ReencryptLegacy(legacyCT)
	if err != nil || !changed {
		t.Fatalf("legacy ciphertext must be rotated: changed=%v err=%v", changed, err)
	}
	if _, err := decryptWithKey(fresh, config.LegacyTOTPEncryptionKey); err == nil {
		t.Fatalf("rotated value still opens with the legacy key")
	}
	if got, err := decryptWithKey(fresh, config.TOTPEncryptionKey); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("rotated value must open with the current key: %q %v", got, err)
	}

	// Already-current values and ordinary strings are left alone.
	if _, changed, _ := ReencryptLegacy(fresh); changed {
		t.Fatalf("a current ciphertext must not be rotated again")
	}
	for _, s := range []string{"+15551234567", "totp", "", "aGVsbG8gd29ybGQ="} {
		if out, changed, _ := ReencryptLegacy(s); changed || out != s {
			t.Fatalf("non-ciphertext %q was modified", s)
		}
	}
}
