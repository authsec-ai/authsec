//go:build integration

package flows

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/services"
	"github.com/authsec-ai/authsec/utils"
	"github.com/google/uuid"
)

// AS-019: admin sign-up must not return the email OTP; returning it meant
// nobody had to prove they own the address.
func Test_AdminRegister_DoesNotReturnOTP(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]string{
		"email":            "owner@" + n + ".test.local",
		"password":         "Passw0rd!Passw0rd",
		"name":             "Owner",
		"workspace_domain": n,
	}, "")
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["otp"]; ok {
		t.Fatalf("register response must not contain the OTP: %s", w.Body.String())
	}
}

// AS-020: MFA secrets encrypted with the legacy hardcoded key are moved to
// the configured key, and the pass is idempotent.
func Test_RotateLegacyMFACiphertexts(t *testing.T) {
	db := config.GetDatabase().DB

	prev := config.TOTPEncryptionKey
	t.Cleanup(func() { config.TOTPEncryptionKey = prev })

	config.TOTPEncryptionKey = config.LegacyTOTPEncryptionKey
	seedCT, _ := utils.EncryptString("JBSWY3DPEHPK3PXP")
	codeCT, _ := utils.EncryptString("ABCD-1234")
	methodData, _ := json.Marshal(map[string]string{"secret_encrypted": seedCT, "label": "phone"})
	backup, _ := json.Marshal([]string{codeCT})

	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO mfa_methods (id, client_id, method_type, method_data, backup_codes, enabled, verified)
		VALUES ($1, $2, 'totp', $3::jsonb, $4, true, true)`, id, uuid.New(), string(methodData), string(backup)); err != nil {
		t.Fatalf("seed mfa_methods: %v", err)
	}

	config.TOTPEncryptionKey = bytes.Repeat([]byte{0x5a}, 32)
	if _, err := services.RotateLegacyMFACiphertexts(db); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	var gotData, gotBackup string
	if err := db.QueryRow(`SELECT method_data::text, backup_codes FROM mfa_methods WHERE id = $1`, id).Scan(&gotData, &gotBackup); err != nil {
		t.Fatalf("read back: %v", err)
	}
	var data map[string]string
	_ = json.Unmarshal([]byte(gotData), &data)
	if data["label"] != "phone" {
		t.Fatalf("plain fields must be untouched: %v", data)
	}
	if data["secret_encrypted"] == seedCT {
		t.Fatalf("seed was not re-encrypted")
	}
	if plain, err := utils.DecryptString(data["secret_encrypted"]); err != nil || plain != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("rotated seed does not decrypt: %q %v", plain, err)
	}
	if strings.Contains(gotBackup, codeCT) {
		t.Fatalf("backup code was not re-encrypted")
	}

	// A second pass changes nothing for this row.
	before := gotData
	if _, err := services.RotateLegacyMFACiphertexts(db); err != nil {
		t.Fatalf("rotate again: %v", err)
	}
	_ = db.QueryRow(`SELECT method_data::text FROM mfa_methods WHERE id = $1`, id).Scan(&gotData)
	if gotData != before {
		t.Fatalf("rotation is not idempotent")
	}
	_ = http.StatusOK
}
