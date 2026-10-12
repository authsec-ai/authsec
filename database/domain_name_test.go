package database

import (
	"errors"
	"strings"
	"testing"
)

// Intern report (Custom Domains): "bad domain!!" was accepted; the server
// only rejected "/", "\" and "*".
func TestValidateDomainName(t *testing.T) {
	for _, ok := range []string{"auth.example.com", "a.b.example.co.uk", "xn--bcher-kva.example", "my-app.example.io", "mylocalhost.com"} {
		if err := ValidateDomainName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "bad domain!!", "example", "-a.example.com", "a-.example.com", "a..example.com",
		"192.168.1.1", "::1", "foo.localhost", "a.123", "auth.example.com:8443", "auth_x.example.com",
		strings.Repeat("a", 64) + ".com",
	} {
		if err := ValidateDomainName(bad); err == nil || !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("%q accepted (err=%v)", bad, err)
		}
	}
}
