package unit

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/utils"
)

// ── ValidateEmail ─────────────────────────────────────────────────────────────

func TestValidateEmail_Valid(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name+tag@sub.domain.org",
		"user@domain.co.uk",
	}
	for _, email := range valid {
		if err := utils.ValidateEmail(email); err != nil {
			t.Errorf("ValidateEmail(%q) unexpected error: %v", email, err)
		}
	}
}

func TestValidateEmail_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"notanemail",
		"missing@",
		"@nodomain.com",
		strings.Repeat("a", 255) + "@example.com",
	}
	for _, email := range invalid {
		if err := utils.ValidateEmail(email); err == nil {
			t.Errorf("ValidateEmail(%q) should have failed", email)
		}
	}
}

// ── ValidatePassword ──────────────────────────────────────────────────────────

func TestValidatePassword_Valid(t *testing.T) {
	valid := []string{
		"Abcdefgh1!",
		"SuperSecure123@",
		"P@ssw0rd!!Longer",
	}
	for _, pw := range valid {
		if err := utils.ValidatePassword(pw); err != nil {
			t.Errorf("ValidatePassword(%q) unexpected error: %v", pw, err)
		}
	}
}

func TestValidatePassword_TooShort(t *testing.T) {
	if err := utils.ValidatePassword("Ab1!"); err == nil {
		t.Error("ValidatePassword: should reject < 10 chars")
	}
}

func TestValidatePassword_TooLong(t *testing.T) {
	if err := utils.ValidatePassword(strings.Repeat("Aa1!", 33)); err == nil {
		t.Error("ValidatePassword: should reject > 128 chars")
	}
}

func TestValidatePassword_MissingUppercase(t *testing.T) {
	if err := utils.ValidatePassword("alllower1!"); err == nil {
		t.Error("ValidatePassword: should require uppercase")
	}
}

func TestValidatePassword_MissingLowercase(t *testing.T) {
	if err := utils.ValidatePassword("ALLUPPER1!"); err == nil {
		t.Error("ValidatePassword: should require lowercase")
	}
}

func TestValidatePassword_MissingDigit(t *testing.T) {
	if err := utils.ValidatePassword("NoDigitHere!"); err == nil {
		t.Error("ValidatePassword: should require a digit")
	}
}

func TestValidatePassword_MissingSpecial(t *testing.T) {
	if err := utils.ValidatePassword("NoSpecial123"); err == nil {
		t.Error("ValidatePassword: should require a special character")
	}
}

func TestValidatePassword_Empty(t *testing.T) {
	if err := utils.ValidatePassword(""); err == nil {
		t.Error("ValidatePassword: should reject empty string")
	}
}

// ── ValidateUsername ──────────────────────────────────────────────────────────

func TestValidateUsername_Valid(t *testing.T) {
	valid := []string{"alice", "bob_123", "user.name", "user-name"}
	for _, u := range valid {
		if err := utils.ValidateUsername(u); err != nil {
			t.Errorf("ValidateUsername(%q) unexpected error: %v", u, err)
		}
	}
}

func TestValidateUsername_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"ab",
		strings.Repeat("a", 51),
		"has space",
		"has@symbol",
	}
	for _, u := range invalid {
		if err := utils.ValidateUsername(u); err == nil {
			t.Errorf("ValidateUsername(%q) should have failed", u)
		}
	}
}

// ── ValidateUUID ──────────────────────────────────────────────────────────────

func TestValidateUUID_Valid(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"00000000-0000-0000-0000-000000000001",
	}
	for _, id := range valid {
		if err := utils.ValidateUUID(id, "id"); err != nil {
			t.Errorf("ValidateUUID(%q) unexpected error: %v", id, err)
		}
	}
}

func TestValidateUUID_Invalid(t *testing.T) {
	invalid := []string{"", "not-a-uuid", "550e8400e29b41d4a716446655440000"}
	for _, id := range invalid {
		if err := utils.ValidateUUID(id, "id"); err == nil {
			t.Errorf("ValidateUUID(%q) should have failed", id)
		}
	}
}

// ── ValidateURL ───────────────────────────────────────────────────────────────

func TestValidateURL_Valid(t *testing.T) {
	valid := []string{"https://example.com", "http://localhost:8080/path"}
	for _, u := range valid {
		if err := utils.ValidateURL(u, "url", true); err != nil {
			t.Errorf("ValidateURL(%q) unexpected error: %v", u, err)
		}
	}
}

func TestValidateURL_MissingScheme(t *testing.T) {
	if err := utils.ValidateURL("example.com", "url", true); err == nil {
		t.Error("ValidateURL: should reject URL without http/https scheme")
	}
}

func TestValidateURL_JavascriptScheme(t *testing.T) {
	if err := utils.ValidateURL("javascript:alert(1)", "url", true); err == nil {
		t.Error("ValidateURL: should reject javascript: scheme")
	}
}

func TestValidateURL_EmptyOptional(t *testing.T) {
	if err := utils.ValidateURL("", "url", false); err != nil {
		t.Errorf("ValidateURL: empty optional URL should be valid, got %v", err)
	}
}

func TestValidateURL_EmptyRequired(t *testing.T) {
	if err := utils.ValidateURL("", "url", true); err == nil {
		t.Error("ValidateURL: empty required URL should fail")
	}
}

// ── ValidateDomain ────────────────────────────────────────────────────────────

func TestValidateDomain_Valid(t *testing.T) {
	valid := []string{"example.com", "sub.domain.org", "my-app.io"}
	for _, d := range valid {
		if err := utils.ValidateDomain(d, "domain"); err != nil {
			t.Errorf("ValidateDomain(%q) unexpected error: %v", d, err)
		}
	}
}

func TestValidateDomain_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"nodot",
		"-leading.com",
		"trailing-.com",
		"has space.com",
	}
	for _, d := range invalid {
		if err := utils.ValidateDomain(d, "domain"); err == nil {
			t.Errorf("ValidateDomain(%q) should have failed", d)
		}
	}
}

// ── ValidateTenantID ──────────────────────────────────────────────────────────

func TestValidateTenantID_UUID(t *testing.T) {
	if err := utils.ValidateTenantID("550e8400-e29b-41d4-a716-446655440000"); err != nil {
		t.Errorf("ValidateTenantID: valid UUID should pass, got %v", err)
	}
}

func TestValidateTenantID_Alphanumeric(t *testing.T) {
	if err := utils.ValidateTenantID("mytenantid"); err != nil {
		t.Errorf("ValidateTenantID: alphanumeric id should pass, got %v", err)
	}
}

func TestValidateTenantID_Empty(t *testing.T) {
	if err := utils.ValidateTenantID(""); err == nil {
		t.Error("ValidateTenantID: empty should fail")
	}
}

func TestValidateTenantID_TooShort(t *testing.T) {
	if err := utils.ValidateTenantID("ab"); err == nil {
		t.Error("ValidateTenantID: 2-char id should fail (min 3)")
	}
}

// ── ValidateOTPCode ───────────────────────────────────────────────────────────

func TestValidateOTPCode_Valid(t *testing.T) {
	if err := utils.ValidateOTPCode("123456"); err != nil {
		t.Errorf("ValidateOTPCode: 6-digit code should pass, got %v", err)
	}
}

func TestValidateOTPCode_Invalid(t *testing.T) {
	invalid := []string{"", "12345", "1234567", "abcdef", "12 345"}
	for _, code := range invalid {
		if err := utils.ValidateOTPCode(code); err == nil {
			t.Errorf("ValidateOTPCode(%q) should have failed", code)
		}
	}
}

// ── ValidateClientID ──────────────────────────────────────────────────────────

func TestValidateClientID_Valid(t *testing.T) {
	valid := []string{"abcdefghij", "client-id_123", strings.Repeat("a", 50)}
	for _, id := range valid {
		if err := utils.ValidateClientID(id); err != nil {
			t.Errorf("ValidateClientID(%q) unexpected error: %v", id, err)
		}
	}
}

func TestValidateClientID_TooShort(t *testing.T) {
	if err := utils.ValidateClientID("short"); err == nil {
		t.Error("ValidateClientID: < 10 chars should fail")
	}
}

func TestValidateClientID_Invalid(t *testing.T) {
	if err := utils.ValidateClientID("has spaces!!"); err == nil {
		t.Error("ValidateClientID: spaces/special chars should fail")
	}
}

// ── ValidateName ─────────────────────────────────────────────────────────────

func TestValidateName_Valid(t *testing.T) {
	if err := utils.ValidateName("Alice Smith", "name", true); err != nil {
		t.Errorf("ValidateName: valid name should pass, got %v", err)
	}
}

func TestValidateName_RequiredEmpty(t *testing.T) {
	if err := utils.ValidateName("", "name", true); err == nil {
		t.Error("ValidateName: required empty name should fail")
	}
}

func TestValidateName_OptionalEmpty(t *testing.T) {
	if err := utils.ValidateName("", "name", false); err != nil {
		t.Errorf("ValidateName: optional empty name should pass, got %v", err)
	}
}

func TestValidateName_XSSPayload(t *testing.T) {
	if err := utils.ValidateName("<script>alert(1)</script>", "name", true); err == nil {
		t.Error("ValidateName: XSS payload should fail")
	}
}

func TestValidateName_TooLong(t *testing.T) {
	if err := utils.ValidateName(strings.Repeat("a", 101), "name", true); err == nil {
		t.Error("ValidateName: > 100 chars should fail")
	}
}

// ── SanitizeInput ─────────────────────────────────────────────────────────────

func TestSanitizeInput_RemovesNullBytes(t *testing.T) {
	result := utils.SanitizeInput("hello\x00world")
	if strings.Contains(result, "\x00") {
		t.Error("SanitizeInput: null bytes should be removed")
	}
}

func TestSanitizeInput_KeepsNewlineAndTab(t *testing.T) {
	result := utils.SanitizeInput("line1\nline2\ttabbed")
	if !strings.Contains(result, "\n") || !strings.Contains(result, "\t") {
		t.Error("SanitizeInput: newlines and tabs should be preserved")
	}
}

func TestSanitizeInput_Empty(t *testing.T) {
	if got := utils.SanitizeInput(""); got != "" {
		t.Errorf("SanitizeInput(\"\") = %q, want empty", got)
	}
}
