package shared

import "testing"

func TestNormalizeWorkspaceDomain(t *testing.T) {
	const suffix = "app.authsec.dev"
	cases := map[string]string{
		"":                                 "",
		"  ":                               "",
		"tenanta":                          "tenanta.app.authsec.dev",
		"TenantA":                          "tenanta.app.authsec.dev",
		"tenanta.app.authsec.dev":          "tenanta.app.authsec.dev",
		"tenanta.app.authsec.dev.":         "tenanta.app.authsec.dev",
		"https://TenantA.app.authsec.dev/": "tenanta.app.authsec.dev",
		"tenanta.app.authsec.dev:443":      "tenanta.app.authsec.dev",
		"login.acme.com":                   "login.acme.com",
	}
	for in, want := range cases {
		if got := normalizeWorkspaceDomain(in, suffix); got != want {
			t.Errorf("normalizeWorkspaceDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
