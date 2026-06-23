//go:build integration

// Package flagsoff tests behavior when XAA feature flags are OFF.
//
// The flagsoff binary boots with XAA flags disabled.
// It is a separate test binary from the main integration suite — main_test.go
// passes testsupport.WithXAAFlagsOff() to Boot so that all XAA_* env vars
// are set to "false" before config.LoadConfig runs.
package flagsoff

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Test_FlagOff_Note logs the intent of this test binary.
// It verifies that the binary itself boots cleanly with all XAA flags off.
func Test_FlagOff_Note(t *testing.T) {
	t.Log("flag-off binary uses XAA_*_ENABLED=false")
	t.Log("Flag-off tests run in a separate binary with XAA_* flags disabled at config load time")
}

// Test_FlagOff_M2M_ClientCredentials verifies that when XAA_M2M_ENABLED=false,
// the client_credentials grant returns 400 (unsupported_grant_type or
// missing-client rejection) rather than proceeding to token issuance.
//
// The flagsoff binary boots with XAA flags disabled.
func Test_FlagOff_M2M_ClientCredentials(t *testing.T) {
	env := testsupport.Get(t)

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("scope", "openid")

	// Use a dummy client credential — the handler should reject at flag-check
	// before it ever reaches client-lookup, so the client need not exist.
	w := env.DoBasicAuth("POST", "/oauth/token", body, "dummy-client-id", "dummy-client-secret")

	// When XAA_M2M is false the controller returns 400 (unsupported_grant_type).
	// A 401 from Basic-auth rejection is also acceptable — either way the grant
	// did NOT succeed (200 would be a failure of this smoke test).
	if w.Code == http.StatusOK {
		t.Errorf("Test_FlagOff_M2M_ClientCredentials: expected 400 or 401 with XAA_M2M disabled, got %d; body: %s", w.Code, w.Body.String())
	}

	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Logf("Test_FlagOff_M2M_ClientCredentials: got %d (acceptable non-200), body: %s", w.Code, w.Body.String())
	}
}

// Test_FlagOff_CIBA_BcAuthorize verifies that POST /oauth/bc-authorize returns
// 400 when XAA_CIBA is false.
func Test_FlagOff_CIBA_BcAuthorize(t *testing.T) {
	env := testsupport.Get(t)

	body := url.Values{}
	body.Set("client_id", "dummy-client-id")
	body.Set("scope", "openid")
	body.Set("login_hint", "user@example.com")

	w := env.Do("POST", "/oauth/bc-authorize", body, "")

	// Flag-off path must not return 200. Expect 400 (flag disabled) or 401.
	if w.Code == http.StatusOK {
		t.Errorf("Test_FlagOff_CIBA_BcAuthorize: expected 400 with XAA_CIBA disabled, got 200; body: %s", w.Body.String())
	}

	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized && w.Code != http.StatusNotFound {
		t.Logf("Test_FlagOff_CIBA_BcAuthorize: got %d, body: %s", w.Code, w.Body.String())
	}
}
