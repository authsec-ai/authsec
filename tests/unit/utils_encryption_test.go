package unit

import (
	"os"
	"testing"

	"github.com/authsec-ai/authsec/utils"
)

// ── GetEncryptionKey ──────────────────────────────────────────────────────────

func TestGetEncryptionKey_AlwaysReturns32Bytes(t *testing.T) {
	cases := []struct {
		name string
		env  string
	}{
		{"default (no env)", ""},
		{"short key", "tooshort"},
		{"exact 32 bytes", "12345678901234567890123456789012"},
		{"longer than 32", "12345678901234567890123456789012extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, existed := os.LookupEnv("SYNC_CONFIG_ENCRYPTION_KEY")
			if tc.env == "" {
				os.Unsetenv("SYNC_CONFIG_ENCRYPTION_KEY")
			} else {
				os.Setenv("SYNC_CONFIG_ENCRYPTION_KEY", tc.env)
			}
			t.Cleanup(func() {
				if existed {
					os.Setenv("SYNC_CONFIG_ENCRYPTION_KEY", old)
				} else {
					os.Unsetenv("SYNC_CONFIG_ENCRYPTION_KEY")
				}
			})
			key := utils.GetEncryptionKey()
			if len(key) != 32 {
				t.Errorf("GetEncryptionKey len = %d, want 32", len(key))
			}
		})
	}
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	original := "secret message"
	ciphertext, err := utils.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	plaintext, err := utils.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if plaintext != original {
		t.Errorf("round-trip: got %q, want %q", plaintext, original)
	}
}

func TestEncrypt_EmptyStringReturnsEmpty(t *testing.T) {
	result, err := utils.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt(\"\") error: %v", err)
	}
	if result != "" {
		t.Errorf("Encrypt(\"\") = %q, want empty", result)
	}
}

func TestDecrypt_EmptyStringReturnsEmpty(t *testing.T) {
	result, err := utils.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt(\"\") error: %v", err)
	}
	if result != "" {
		t.Errorf("Decrypt(\"\") = %q, want empty", result)
	}
}

func TestEncrypt_DifferentCiphertextEachCall(t *testing.T) {
	// AES-GCM uses a random nonce — same input must not produce same ciphertext
	c1, _ := utils.Encrypt("hello")
	c2, _ := utils.Encrypt("hello")
	if c1 == c2 {
		t.Error("Encrypt: same input should produce different ciphertext (random nonce)")
	}
}

func TestDecrypt_InvalidBase64Fails(t *testing.T) {
	_, err := utils.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Error("Decrypt: invalid base64 should return an error")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	ciphertext, _ := utils.Encrypt("original")
	// Flip a character in the ciphertext to simulate tampering
	tampered := ciphertext[:len(ciphertext)-4] + "XXXX"
	_, err := utils.Decrypt(tampered)
	if err == nil {
		t.Error("Decrypt: tampered ciphertext should fail authentication")
	}
}

func TestEncryptDecrypt_UnicodePayload(t *testing.T) {
	original := "こんにちは 🔐 مرحبا"
	ciphertext, err := utils.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	plaintext, err := utils.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if plaintext != original {
		t.Errorf("Unicode round-trip: got %q, want %q", plaintext, original)
	}
}

func TestEncryptDecrypt_LargePayload(t *testing.T) {
	original := string(make([]byte, 100_000)) // 100 KB of null bytes
	ciphertext, err := utils.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt large payload error: %v", err)
	}
	plaintext, err := utils.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt large payload error: %v", err)
	}
	if plaintext != original {
		t.Error("Large payload round-trip failed")
	}
}
