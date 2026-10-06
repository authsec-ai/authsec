package config

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// AS-020: the key was read from the misspelled TOTP_ENCRYPTION_key, so the
// configured TOTP_ENCRYPTION_KEY was ignored and a hardcoded key used.
func TestLoadTOTPEncryptionKey_ReadsConfiguredKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 32)
	t.Setenv("TOTP_ENCRYPTION_KEY", hex.EncodeToString(want))
	if got := loadTOTPEncryptionKey(); !bytes.Equal(got, want) {
		t.Fatalf("configured key ignored: got %x", got)
	}
}

func TestLoadTOTPEncryptionKey_FallsBackOutsideProduction(t *testing.T) {
	t.Setenv("TOTP_ENCRYPTION_KEY", "")
	t.Setenv("ENVIRONMENT", "development")
	if got := loadTOTPEncryptionKey(); !bytes.Equal(got, LegacyTOTPEncryptionKey) {
		t.Fatalf("expected the legacy key in development, got %x", got)
	}
}
