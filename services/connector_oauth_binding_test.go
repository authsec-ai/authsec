package services

import "testing"

func TestConnectStateBinding(t *testing.T) {
	b := ConnectStateBinding("abc")
	if !ConnectStateBindingValid("abc", b) {
		t.Fatal("own binding rejected")
	}
	if ConnectStateBindingValid("abd", b) || ConnectStateBindingValid("abc", "") {
		t.Fatal("foreign or empty binding accepted")
	}
}

func TestSafeConnectRedirect(t *testing.T) {
	origin := "https://acme.app.authsec.dev"
	cases := map[string]bool{
		"":                                    true,
		"/connectors":                         true,
		"//evil.com/x":                        false,
		"https://acme.app.authsec.dev/c?x=1":  true,
		"https://evil.com/c":                  false,
		"javascript:alert(1)":                 false,
		"http://acme.app.authsec.dev/c":       false,
		"https://acme.app.authsec.dev.evil/c": false,
	}
	for in, want := range cases {
		if got := SafeConnectRedirect(in, origin); got != want {
			t.Errorf("SafeConnectRedirect(%q) = %v, want %v", in, got, want)
		}
	}
}
