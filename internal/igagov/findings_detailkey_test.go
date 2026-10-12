package igagov

import "testing"

// p3-wire item 5: a broad_grant's detail_key never contains U+001F, so its
// fingerprint can always be computed; the escape is injective and leaves a
// key without "%" or U+001F unchanged.
func TestBroadGrantDetailKey(t *testing.T) {
	cases := map[string]string{
		"P1#0":                         "P1#0",
		"arn:aws:iam::1:policy/p\x1f0": "arn:aws:iam::1:policy/p%1F0",
		"a%1Fb":                        "a%251Fb",
		"a\x1fb":                       "a%1Fb",
		"%\x1f%":                       "%25%1F%25",
	}
	seen := map[string]string{}
	for in, want := range cases {
		got := BroadGrantDetailKey(in)
		if got != want {
			t.Fatalf("BroadGrantDetailKey(%q) = %q, want %q", in, got, want)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("%q and %q share detail_key %q", prev, in, got)
		}
		seen[got] = in
		if _, err := Fingerprint(KindBroadGrant, "AROAEXAMPLE", got); err != nil {
			t.Fatalf("fingerprint of %q: %v", got, err)
		}
		if BroadGrantDetailKey(in) != got {
			t.Fatal("not deterministic")
		}
	}
	if _, err := Fingerprint(KindBroadGrant, "AROAEXAMPLE", "a\x1fb"); err == nil {
		t.Fatal("the raw key must still be refused by Fingerprint")
	}
}
