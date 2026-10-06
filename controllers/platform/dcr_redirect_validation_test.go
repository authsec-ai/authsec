package platform

import "testing"

// AS-096: DCR redirect URIs follow the exact-host rule of the PUT path.
func TestIsValidRedirectURI_ExactLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"https://app.example.com/cb":      true,
		"http://localhost:3000/cb":        true,
		"http://127.0.0.1/cb":             true,
		"http://[::1]:8080/cb":            true,
		"http://localhost.evil.com/cb":    false,
		"http://127.0.0.1.evil.com/cb":    false,
		"http://example.com/cb":           false,
		"https://app.example.com/cb#frag": false,
		"/relative/cb":                    false,
		"javascript:alert(1)":             false,
		"http://localhost@evil.com/cb":    false,
	}
	for uri, want := range cases {
		if got := isValidRedirectURI(uri); got != want {
			t.Errorf("isValidRedirectURI(%q) = %v, want %v", uri, got, want)
		}
	}
}
