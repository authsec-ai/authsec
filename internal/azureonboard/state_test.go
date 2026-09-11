package azureonboard

import (
	"strings"
	"testing"
)

// The auto-setup marker rides in the state string, and a sign-in carrying it
// writes an azure_connectors row on the callback. So the marker decides whether
// an unauthenticated callback is allowed to write -- which makes its parsing
// worth pinning down.

func TestLoginState_CarriesTheAutoSetupMarkerBothWays(t *testing.T) {
	plain, err := NewLoginState(false, false)
	if err != nil {
		t.Fatalf("mint plain: %v", err)
	}
	auto, err := NewLoginState(true, false)
	if err != nil {
		t.Fatalf("mint auto: %v", err)
	}

	if LoginStateAutoSetup(plain) {
		t.Errorf("plain login state %q read as auto-setup", plain)
	}
	if !LoginStateAutoSetup(auto) {
		t.Errorf("auto login state %q not read as auto-setup", auto)
	}

	// Both must still resolve as logins, or the callback would reject them
	// before reaching either branch.
	for _, state := range []string{plain, auto} {
		purpose, tenant, ok := StatePurpose(state)
		if !ok || purpose != statePrefixLogin {
			t.Errorf("StatePurpose(%q) = (%q, %q, %v), want a login", state, purpose, tenant, ok)
		}
		if tenant != "" {
			t.Errorf("a login state named tenant %q; only consent states carry one", tenant)
		}
	}
}

// Rewriting a plain state into an auto one produces a DIFFERENT string, and the
// state row is keyed on the whole string. So the rewrite cannot be redeemed --
// which is the only thing that makes it safe to carry a privilege decision here.
func TestLoginState_RewritingItProducesAnUnredeemableString(t *testing.T) {
	plain, err := NewLoginState(false, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	nonce := strings.TrimPrefix(plain, statePrefixLogin+":")
	forged := statePrefixLogin + ":" + modeAuto + ":" + nonce

	if !LoginStateAutoSetup(forged) {
		t.Fatal("the forged shape should parse as auto -- shape is not the defence")
	}
	if forged == plain {
		t.Fatal("the forged state must differ from the minted one")
	}

	// The defence, stated: the lookup key changed, so no row matches.
	if strings.HasSuffix(plain, forged) || strings.HasSuffix(forged, plain) {
		t.Fatal("the two states must not be prefixes or suffixes of one another")
	}
}

func TestLoginState_IsUnguessableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, err := NewLoginState(i%2 == 0, false)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if seen[s] {
			t.Fatalf("duplicate state minted: %q", s)
		}
		seen[s] = true

		// 256 bits, base64url: 43 characters.
		parts := strings.Split(s, ":")
		if len(parts[len(parts)-1]) < 43 {
			t.Fatalf("nonce too short in %q", s)
		}
	}
}

// The consent state carries the second-leg marker, and it must still resolve to
// the tenant it names -- finishConsent compares that against the state row and
// against what Microsoft appends, and all three have to agree.
func TestConsentState_CarriesTheMarkerAndStillNamesTheTenant(t *testing.T) {
	for _, auto := range []bool{false, true} {
		state, err := NewConsentState(testGUID, auto, false)
		if err != nil {
			t.Fatalf("auto=%v: mint: %v", auto, err)
		}
		if got := ConsentStateAutoSetup(state); got != auto {
			t.Errorf("auto=%v: ConsentStateAutoSetup = %v in %q", auto, got, state)
		}
		purpose, tenant, ok := StatePurpose(state)
		if !ok || purpose != statePrefixConsent {
			t.Errorf("auto=%v: StatePurpose(%q) = (%q, %q, %v)", auto, state, purpose, tenant, ok)
		}
		if tenant != testGUID {
			t.Errorf("auto=%v: tenant = %q, want %q", auto, tenant, testGUID)
		}
		// A login state must never read as a consent one, in either direction.
		if LoginStateAutoSetup(state) {
			t.Errorf("auto=%v: consent state %q read as an auto LOGIN", auto, state)
		}
	}

	login, err := NewLoginState(true, false)
	if err != nil {
		t.Fatalf("mint login: %v", err)
	}
	if ConsentStateAutoSetup(login) {
		t.Errorf("auto login state %q read as an auto CONSENT", login)
	}
}

func TestConsentState_RefusesATenantThatIsNotAGUID(t *testing.T) {
	// The tenant lands in the authority URL path on the way out and is compared
	// as an identity on the way back.
	for _, bad := range []string{"", "not-a-guid", "contoso.onmicrosoft.com", "../../evil"} {
		if _, err := NewConsentState(bad, true, false); err == nil {
			t.Errorf("NewConsentState(%q) accepted a non-GUID tenant", bad)
		}
	}
}

// The tenant-wide marker decides whether a callback may briefly raise the
// operator's own account to root User Access Administrator. It must be true only
// when an operator asked for it, and asking is only possible behind
// discovery:admin -- so this is the parse that gates a privilege raise.
func TestState_TenantWideMarkerSurvivesBothLegs(t *testing.T) {
	cases := []struct {
		auto, wide bool
	}{
		{false, false},
		{true, false},
		{true, true},
	}
	for _, tc := range cases {
		login, err := NewLoginState(tc.auto, tc.wide)
		if err != nil {
			t.Fatalf("%+v: mint login: %v", tc, err)
		}
		if got := LoginStateAutoSetup(login); got != tc.auto {
			t.Errorf("%+v: LoginStateAutoSetup = %v in %q", tc, got, login)
		}
		if got := LoginStateTenantWide(login); got != tc.wide {
			t.Errorf("%+v: LoginStateTenantWide = %v in %q", tc, got, login)
		}

		consent, err := NewConsentState(testGUID, tc.auto, tc.wide)
		if err != nil {
			t.Fatalf("%+v: mint consent: %v", tc, err)
		}
		if got := ConsentStateAutoSetup(consent); got != tc.auto {
			t.Errorf("%+v: ConsentStateAutoSetup = %v in %q", tc, got, consent)
		}
		if got := ConsentStateTenantWide(consent); got != tc.wide {
			t.Errorf("%+v: ConsentStateTenantWide = %v in %q", tc, got, consent)
		}

		// Both legs must still parse, or the callback rejects them before
		// reaching the branch that reads the marker.
		if _, _, ok := StatePurpose(login); !ok {
			t.Errorf("%+v: login state %q does not parse", tc, login)
		}
		purpose, tenant, ok := StatePurpose(consent)
		if !ok || purpose != statePrefixConsent || tenant != testGUID {
			t.Errorf("%+v: StatePurpose(%q) = (%q, %q, %v)", tc, consent, purpose, tenant, ok)
		}
	}
}

// tenantWide is meaningless without autoSetup and must not leak through on its
// own -- a plain sign-in can never be read as having asked for a privilege
// raise.
func TestState_TenantWideWithoutAutoIsIgnored(t *testing.T) {
	login, err := NewLoginState(false, true)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if LoginStateAutoSetup(login) || LoginStateTenantWide(login) {
		t.Fatalf("plain sign-in %q carries an automatic-setup marker", login)
	}

	consent, err := NewConsentState(testGUID, false, true)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if ConsentStateAutoSetup(consent) || ConsentStateTenantWide(consent) {
		t.Fatalf("plain consent %q carries an automatic-setup marker", consent)
	}
}

// The two modes must not be confusable, in either direction.
func TestState_ModesAreDistinct(t *testing.T) {
	narrow, _ := NewLoginState(true, false)
	wide, _ := NewLoginState(true, true)

	if LoginStateTenantWide(narrow) {
		t.Errorf("per-subscription state %q read as tenant-wide", narrow)
	}
	if !LoginStateTenantWide(wide) {
		t.Errorf("tenant-wide state %q not read as tenant-wide", wide)
	}
	// Both are automatic setups, so both must be recognised as such.
	if !LoginStateAutoSetup(narrow) || !LoginStateAutoSetup(wide) {
		t.Error("both modes must read as automatic setup")
	}
}

func TestStatePurpose_RejectsMalformedStates(t *testing.T) {
	for _, state := range []string{
		"",
		"login",
		"login:",
		"consent:nonce",                     // consent with no tenant
		"consent:not-a-guid:nonce",          // tenant must be a GUID
		"login:bogus:nonce",                 // an unknown login mode
		"login:auto:nonce:extra",            // too many parts
		statePrefixConsent + ":" + testGUID, // consent missing its nonce
	} {
		if _, _, ok := StatePurpose(state); ok {
			t.Errorf("StatePurpose(%q) accepted a malformed state", state)
		}
	}
}

const testGUID = "11111111-1111-1111-1111-111111111111"
