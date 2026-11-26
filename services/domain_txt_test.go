package services

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// Intern report (Custom Domains): a failed check said only "verification
// failed". Each outcome now says what to do.
func TestMatchTXT(t *testing.T) {
	const name, want = "_authsec-challenge.example.com", "authsec-domain-verification=abc"
	for _, tc := range []struct {
		desc    string
		records []string
		err     error
		ok      bool
		says    string
	}{
		{"match", []string{"other", want}, nil, true, ""},
		{"match with spaces", []string{" " + want + " "}, nil, true, ""},
		{"no such name", nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}, false, "No TXT record found"},
		{"no records", nil, nil, false, "No TXT record found"},
		{"wrong value", []string{"authsec-domain-verification=old"}, nil, false, "not the expected value"},
		{"resolver failure", nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}, false, "temporary DNS problem"},
		{"other error", nil, errors.New("boom"), false, "temporary DNS problem"},
	} {
		ok, reason := matchTXT(name, want, tc.records, tc.err)
		if ok != tc.ok || !strings.Contains(reason, tc.says) {
			t.Errorf("%s: ok=%v reason=%q", tc.desc, ok, reason)
		}
	}
}
