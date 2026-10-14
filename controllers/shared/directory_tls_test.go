package shared

import "testing"

func TestCheckADSkipVerify(t *testing.T) {
	for _, tc := range []struct {
		env, allow        string
		useSSL, skip, bad bool
	}{
		{"production", "", true, true, true},
		{"production", "true", true, true, false},
		{"production", "", true, false, false},
		{"production", "", false, true, false}, // no TLS, nothing to verify
		{"development", "", true, true, false},
	} {
		t.Setenv("ENVIRONMENT", tc.env)
		t.Setenv("DIRECTORY_SYNC_ALLOW_SKIP_VERIFY", tc.allow)
		if err := CheckADSkipVerify(tc.useSSL, tc.skip); (err != nil) != tc.bad {
			t.Errorf("%+v: err=%v", tc, err)
		}
	}
}
