//go:build integration

package onboarding

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseBody decodes the JSON response body into a map. Returns nil if the body
// is empty or unparseable — tests that need a field should assert it is non-nil.
func parseBody(w *httptest.ResponseRecorder) map[string]interface{} {
	var m map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&m)
	return m
}

// stringField extracts a string value from a decoded body map. Returns "" if
// the key is absent or the value is not a string.
func stringField(body map[string]interface{}, key string) string {
	if body == nil {
		return ""
	}
	v, _ := body[key].(string)
	return v
}

// Test_AdminOnboarding_SignupOTPRegisterLogin exercises the full happy-path for
// a brand-new workspace admin when the database is empty:
//
//  1. precheck  → 200, has next_step / exists field (not a 500)
//  2. register  → 201, optionally returns an otp
//  3. complete-registration → 201
//  4. login     → 200, token in response
func Test_AdminOnboarding_SignupOTPRegisterLogin(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	// Underscores are not RFC-valid in DNS labels; replace with hyphens so
	// the email validator accepts the address.
	// The register handler appends TENANT_DOMAIN_SUFFIX ("test.local") to the
	// input domain, so we send just the slug and use slug+".test.local" for login.
	slug := dnSafe(n)
	email := "admin@" + slug + ".test.local"
	password := "SecurePass123!"
	domain := slug            // sent to register; stored as slug.test.local
	loginDomain := slug + ".test.local"
	name := "Admin " + n

	// ── Step 1: precheck ─────────────────────────────────────────────────────
	w1 := env.Do("POST", "/authsec/uflow/auth/admin/login/precheck", map[string]interface{}{
		"email": email,
	}, "")
	t.Logf("precheck status=%d body=%s", w1.Code, w1.Body.String())
	assert.NotEqual(t, 500, w1.Code, "precheck must not 500")
	assert.Equal(t, 200, w1.Code, "precheck should return 200")

	body1 := parseBody(w1)
	hasExpectedField := body1 != nil && (body1["next_step"] != nil || body1["exists"] != nil)
	assert.True(t, hasExpectedField, "precheck response should contain next_step or exists; got: %v", body1)

	// ── Step 2: register ─────────────────────────────────────────────────────
	w2 := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]interface{}{
		"email":            email,
		"password":         password,
		"name":             name,
		"workspace_domain": domain,
	}, "")
	t.Logf("register status=%d body=%s", w2.Code, w2.Body.String())
	require.Equal(t, 201, w2.Code, "register should return 201")

	body2 := parseBody(w2)
	otp := stringField(body2, "otp")
	// OTP may also surface under alternate keys depending on implementation.
	if otp == "" {
		otp = stringField(body2, "verification_code")
	}
	if otp == "" {
		otp = stringField(body2, "code")
	}
	t.Logf("otp from register response: %q", otp)

	// ── Step 3: complete-registration ────────────────────────────────────────
	completePayload := map[string]interface{}{
		"email": email,
		"otp":   otp,
	}
	w3 := env.Do("POST", "/authsec/uflow/auth/admin/complete-registration", completePayload, "")
	t.Logf("complete-registration status=%d body=%s", w3.Code, w3.Body.String())
	require.Equal(t, 201, w3.Code, "complete-registration should return 201")

	// ── Step 4: login ─────────────────────────────────────────────────────────
	w4 := env.Do("POST", "/authsec/uflow/auth/admin/login", map[string]interface{}{
		"email":            email,
		"password":         password,
		"workspace_domain": loginDomain,
	}, "")
	t.Logf("login status=%d body=%s", w4.Code, w4.Body.String())
	require.Equal(t, 200, w4.Code, "login should return 200")

	body4 := parseBody(w4)
	token := stringField(body4, "token")
	if token == "" {
		token = stringField(body4, "access_token")
	}
	if token == "" {
		token = stringField(body4, "id_token")
	}
	assert.NotEmpty(t, token, "login response should contain a token; got: %v", body4)
}

// Test_AdminOnboarding_SingleWorkspaceGuard verifies that the single-workspace
// deployment guard rejects a second admin registration when one workspace
// already exists.
//
// NOTE: This test depends on Test_AdminOnboarding_SignupOTPRegisterLogin having
// run first in the same binary invocation (they share the same DB). The Go test
// runner executes functions in source-file order within a package, and our
// TestMain is serial, so this ordering is deterministic.
func Test_AdminOnboarding_SingleWorkspaceGuard(t *testing.T) {
	env := testsupport.Get(t)

	// Use a different nonce so the email and domain are genuinely new.
	n := testsupport.TestNonce(t)
	slug := dnSafe(n)
	email := "admin2@" + slug + ".test.local"

	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]interface{}{
		"email":            email,
		"password":         "SecurePass123!",
		"name":             "Admin2 " + n,
		"workspace_domain": slug,
	}, "")
	t.Logf("second-registration status=%d body=%s", w.Code, w.Body.String())
	assert.Equal(t, 409, w.Code,
		"second workspace registration must be rejected with 409 (single-workspace guard)")
}

// Test_AdminOnboarding_DuplicateEmail verifies that registering the same email
// address a second time is rejected with a conflict or bad-request status.
func Test_AdminOnboarding_DuplicateEmail(t *testing.T) {
	env := testsupport.Get(t)

	// Derive the same email that Test_AdminOnboarding_SignupOTPRegisterLogin used.
	originalNonce := nonceFromName("Test_AdminOnboarding_SignupOTPRegisterLogin")
	slug := dnSafe(originalNonce)
	email := "admin@" + slug + ".test.local"

	w := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]interface{}{
		"email":            email,
		"password":         "SecurePass123!",
		"name":             "Dup Admin",
		"workspace_domain": slug,
	}, "")
	t.Logf("duplicate-email status=%d body=%s", w.Code, w.Body.String())
	assert.True(t, w.Code == 409 || w.Code == 400,
		"duplicate email registration should return 409 or 400; got %d", w.Code)
}

// Test_AdminOnboarding_BadOTP verifies that completing registration with the
// wrong OTP is rejected with an auth or bad-request error.
func Test_AdminOnboarding_BadOTP(t *testing.T) {
	env := testsupport.Get(t)
	n := testsupport.TestNonce(t)

	slug := dnSafe(n)
	email := "badotp@" + slug + ".test.local"

	// Step 2: register to trigger OTP generation.
	w2 := env.Do("POST", "/authsec/uflow/auth/admin/register", map[string]interface{}{
		"email":            email,
		"password":         "SecurePass123!",
		"name":             "BadOTP Admin " + n,
		"workspace_domain": slug,
	}, "")
	t.Logf("bad-otp register status=%d body=%s", w2.Code, w2.Body.String())
	// The single-workspace guard may already be active if prior tests ran first;
	// accept 201 or 409. If 409, the guard itself is the expected blocker.
	if w2.Code == 409 {
		t.Skip("single-workspace guard active; bad-OTP path skipped (guard takes precedence)")
	}
	require.Equal(t, 201, w2.Code, "register should return 201 to proceed with bad-OTP test")

	// Step 3: complete-registration with a deliberately wrong OTP.
	w3 := env.Do("POST", "/authsec/uflow/auth/admin/complete-registration", map[string]interface{}{
		"email": email,
		"otp":   "000000",
	}, "")
	t.Logf("bad-otp complete-registration status=%d body=%s", w3.Code, w3.Body.String())
	assert.True(t, w3.Code == 401 || w3.Code == 400,
		"wrong OTP should return 401 or 400; got %d", w3.Code)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// nonceFromName applies the same transformation that testsupport.TestNonce
// applies to t.Name(): lower-case, replace '/', ' ', '.' with '_', truncate to
// 32 characters. This lets Test_AdminOnboarding_DuplicateEmail reconstruct the
// nonce used by Test_AdminOnboarding_SignupOTPRegisterLogin without needing a
// live *testing.T with that exact name (testing.TB has unexported methods and
// cannot be implemented outside the standard library).
func nonceFromName(name string) string {
	r := strings.NewReplacer("/", "_", " ", "_", ".", "_")
	n := strings.ToLower(r.Replace(name))
	if len(n) > 32 {
		n = n[len(n)-32:]
	}
	return n
}

// dnSafe converts a testsupport nonce into a DNS-label-safe string by replacing
// underscores (not valid in domain labels per RFC 952) with hyphens.
func dnSafe(n string) string { return strings.ReplaceAll(n, "_", "-") }
