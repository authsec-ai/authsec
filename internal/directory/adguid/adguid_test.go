package adguid

import (
	"bytes"
	"testing"
)

func TestGUIDGoldenAndRoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	const want = "03020100-0504-0706-0809-0a0b0c0d0e0f"

	got, err := Format(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Format = %s, want %s", got, want)
	}

	back, err := ToADBytes(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, raw) {
		t.Fatalf("ToADBytes = %x, want %x", back, raw)
	}

	again, err := Format(back)
	if err != nil || again != want {
		t.Fatalf("second Format = %s (%v), want %s", again, err, want)
	}

	legacy, err := LegacyString(raw)
	if err != nil {
		t.Fatal(err)
	}
	const legacyWant = "00010203-0405-0607-0809-0a0b0c0d0e0f"
	if legacy != legacyWant {
		t.Fatalf("legacy = %s, want %s", legacy, legacyWant)
	}
	if legacy == got {
		t.Fatal("legacy rendering must differ from the canonical GUID")
	}
	swapped, err := SwapString(got)
	if err != nil || swapped != legacy {
		t.Fatalf("SwapString(canonical) = %s (%v), want legacy %s", swapped, err, legacy)
	}
	backToCanon, err := SwapString(legacy)
	if err != nil || backToCanon != got {
		t.Fatalf("SwapString(legacy) = %s (%v), want %s", backToCanon, err, got)
	}
	if !MatchesEither(legacy, got) || !MatchesEither(stringsUpper(got), got) {
		t.Fatal("lookup must match the legacy form and the canonical form")
	}
	if MatchesEither("11111111-1111-1111-1111-111111111111", got) {
		t.Fatal("unrelated GUID matched")
	}
}

func stringsUpper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func TestGUIDRejectsBadLength(t *testing.T) {
	if _, err := Format([]byte{1, 2, 3}); err == nil {
		t.Fatal("short GUID must fail")
	}
	if _, err := ToADBytes("not-a-guid"); err == nil {
		t.Fatal("bad text must fail")
	}
}

func TestSIDVectors(t *testing.T) {
	cases := []struct {
		raw  []byte
		text string
	}{
		{
			// S-1-5-32-544 (Administrators)
			raw:  []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00},
			text: "S-1-5-32-544",
		},
		{
			// S-1-1-0 (Everyone)
			raw:  []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
			text: "S-1-1-0",
		},
		{
			text: "S-1-5-21-2127521184-1604012920-1887927527-72713",
		},
	}
	for _, tc := range cases {
		text := tc.text
		raw := tc.raw
		if raw == nil {
			var err error
			raw, err = SIDBytes(text)
			if err != nil {
				t.Fatalf("SIDBytes %s: %v", text, err)
			}
		}
		got, err := ParseSID(raw)
		if err != nil {
			t.Fatalf("ParseSID %s: %v", text, err)
		}
		if got != text {
			t.Fatalf("ParseSID = %s, want %s", got, text)
		}
		back, err := SIDBytes(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back, raw) {
			t.Fatalf("SIDBytes(%s) = %x, want %x", text, back, raw)
		}
	}

	if _, err := ParseSID([]byte{0x01, 0x02}); err == nil {
		t.Fatal("truncated SID must fail")
	}
	if _, err := ParseSID([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}); err == nil {
		t.Fatal("revision other than 1 must fail")
	}
	if _, err := SIDBytes("not-a-sid"); err == nil {
		t.Fatal("bad SID text must fail")
	}
}

func TestUACBitsNotDigitContains(t *testing.T) {
	cases := []struct {
		in                 string
		active             bool
		disabled           bool
		locked             bool
		expired            bool
		dontExpirePassword bool
	}{
		{in: "512", active: true},
		{in: "514", active: false, disabled: true},
		{in: "66048", active: true, dontExpirePassword: true}, // 65536|512
		{in: "12", active: true},                              // contains '2', bit 0x2 clear
		{in: "32", active: true},                              // contains '2', bit 0x2 clear
		{in: "2", active: false, disabled: true},
		{in: "528", active: true, locked: true}, // 512|16
		{in: "8388608", active: true, expired: true},
		{in: "", active: true},
	}
	for _, tc := range cases {
		f, err := ParseUAC(tc.in)
		if err != nil {
			t.Fatalf("ParseUAC %q: %v", tc.in, err)
		}
		if f.Active != tc.active || f.AccountDisabled != tc.disabled || f.LockedOut != tc.locked ||
			f.PasswordExpired != tc.expired || f.DontExpirePassword != tc.dontExpirePassword {
			t.Fatalf("ParseUAC %q = %+v, want active=%v disabled=%v locked=%v expired=%v dontExpire=%v",
				tc.in, f, tc.active, tc.disabled, tc.locked, tc.expired, tc.dontExpirePassword)
		}
	}
	if _, err := ParseUAC("12abc"); err == nil {
		t.Fatal("non-integer UAC must fail rather than search for the digit 2")
	}
}

func TestUACDelegationBits(t *testing.T) {
	unconstrained := FromUint(512 | UACTrustedForDelegation)
	if !unconstrained.TrustedForDelegation || unconstrained.NotDelegated || unconstrained.TrustedToAuthForDelegation {
		t.Fatalf("unconstrained: %+v", unconstrained)
	}
	if !unconstrained.Active {
		t.Fatal("delegation must not mark the account disabled")
	}
	sensitive := FromUint(512 | UACNotDelegated)
	if !sensitive.NotDelegated || sensitive.TrustedForDelegation {
		t.Fatalf("not delegated: %+v", sensitive)
	}
	transition := FromUint(512 | UACTrustedToAuthForDelegation)
	if !transition.TrustedToAuthForDelegation || transition.TrustedForDelegation {
		t.Fatalf("protocol transition: %+v", transition)
	}
	// 0x80000 contains the digit 2. The bit test must not treat that as disable.
	if unconstrained.AccountDisabled {
		t.Fatal("0x80000 must not be read as ACCOUNTDISABLE")
	}
}

func TestCommonNameKeepsFullDNIdentity(t *testing.T) {
	dn := `CN=Doe\, Jane,OU=People,DC=authsec,DC=test`
	if got := CommonName(dn); got != "Doe, Jane" {
		t.Fatalf("CN = %q", got)
	}
	if got := CommonName("OU=People,DC=authsec,DC=test"); got != "" {
		t.Fatalf("non-CN DN returned %q", got)
	}
}
