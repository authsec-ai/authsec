package services

import "testing"

// Matching our certificate against the ones uploaded to a registration is what
// makes two questions answerable: is OUR certificate there, and when does IT
// expire -- as opposed to "does this registration have some certificate", which
// is a different and much less useful thing to report.
//
// The comparison is easy to get wrong because the two sides are the same twenty
// bytes written differently, and a mismatch does not look like an encoding bug.
// It looks like "your certificate is not uploaded", on a registration where it
// plainly is, and sends an operator to upload it a second time.

// The pair below is real: taken from a live registration and the credential
// AuthSec was signing with at that moment.
const (
	liveGraphKeyID = "C2EC90B404B8213FC5B3FB2A61D2E8E2CDEE9CEB"
	liveX5T        = "wuyQtAS4IT_Fs_sqYdLo4s3unOs"
)

// Graph returns HEX for an X509 credential, whatever the documentation says.
// This is the case that shipped broken.
func TestSameThumbprint_MatchesGraphsHexAgainstOurBase64URL(t *testing.T) {
	if !sameThumbprint(liveGraphKeyID, liveX5T) {
		t.Fatalf("hex %q did not match base64url %q, so an uploaded certificate "+
			"reads as missing", liveGraphKeyID, liveX5T)
	}
	// Case should not decide it either.
	if !sameThumbprint("c2ec90b404b8213fc5b3fb2a61d2e8e2cdee9ceb", liveX5T) {
		t.Error("lowercase hex did not match")
	}
}

// The documented encoding has to keep working: other credential types do return
// base64, and this is the fallback rather than the dead branch it looks like.
func TestSameThumbprint_MatchesBase64Forms(t *testing.T) {
	// The same bytes as liveX5T, in each base64 dialect.
	for name, id := range map[string]string{
		"raw base64url": "wuyQtAS4IT_Fs_sqYdLo4s3unOs",
		"base64url":     "wuyQtAS4IT_Fs_sqYdLo4s3unOs=",
		"raw std":       "wuyQtAS4IT/Fs/sqYdLo4s3unOs",
		"std padded":    "wuyQtAS4IT/Fs/sqYdLo4s3unOs=",
	} {
		if !sameThumbprint(id, liveX5T) {
			t.Errorf("%s (%q) did not match", name, id)
		}
	}
}

// A different certificate must NOT match, or the check would report every
// registration with any certificate as correctly configured.
func TestSameThumbprint_RejectsADifferentCertificate(t *testing.T) {
	// A real thumbprint from a different certificate on a different app.
	const other = "AAFE719A9C89971D32132403859F433FB82B7897"
	if sameThumbprint(other, liveX5T) {
		t.Fatal("a different certificate matched; every uploaded certificate would " +
			"read as ours")
	}
}

func TestSameThumbprint_EmptyOrJunkNeverMatches(t *testing.T) {
	cases := [][2]string{
		{"", liveX5T},
		{liveGraphKeyID, ""},
		{"", ""},
		{"not-base64-or-hex!!", liveX5T},
		{liveGraphKeyID, "not-base64-or-hex!!"},
	}
	for _, c := range cases {
		if sameThumbprint(c[0], c[1]) {
			t.Errorf("sameThumbprint(%q, %q) matched", c[0], c[1])
		}
	}
}
