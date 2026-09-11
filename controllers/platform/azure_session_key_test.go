package platform

import (
	"os"
	"testing"
)

// The Azure sign-in cookie carries a handle to a stored ARM refresh token, and
// the signature is the only thing stopping a caller writing somebody else's
// session id into the cookie and using their token.
//
// The key used to be SESSION_SECRET alone -- a variable this one feature
// introduced, that nothing else in the codebase reads, and that an operator was
// only told about at the very end of an otherwise complete setup. It is derived
// from JWT_SECRET now, which every deployment already has.

func setEnv(t *testing.T, k, v string) {
	t.Helper()
	old, had := os.LookupEnv(k)
	if v == "" {
		_ = os.Unsetenv(k)
	} else {
		_ = os.Setenv(k, v)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	})
}

const (
	testJWTSecret     = "a-deployment-jwt-secret-that-is-long-enough-32"
	testSessionSecret = "an-explicit-session-secret-of-32-plus-chars"
)

func TestAzureSessionKey_DerivesFromJWTSecret(t *testing.T) {
	setEnv(t, "SESSION_SECRET", "")
	setEnv(t, "JWT_SECRET", testJWTSecret)

	key := azureSessionKey()
	if len(key) == 0 {
		t.Fatal("no key derived, so no cookie can be issued and Azure sign-in stops " +
			"on a deployment that is correctly configured")
	}
	if len(key) != 32 {
		t.Errorf("key is %d bytes, want 32 (HMAC-SHA256)", len(key))
	}

	// Derived, not copied. Using JWT_SECRET's bytes directly would mean one key
	// doing two jobs, and a signature valid in one context valid in the other.
	if string(key) == testJWTSecret {
		t.Fatal("the cookie key IS the JWT secret")
	}

	// Same inputs, same key -- or every restart invalidates live sessions.
	if string(azureSessionKey()) != string(key) {
		t.Fatal("not deterministic; a restart would log every operator out")
	}
}

// A different JWT secret must produce a different cookie key, or rotating the
// deployment secret would leave old cookies valid.
func TestAzureSessionKey_FollowsTheRootSecret(t *testing.T) {
	setEnv(t, "SESSION_SECRET", "")

	setEnv(t, "JWT_SECRET", testJWTSecret)
	first := string(azureSessionKey())
	setEnv(t, "JWT_SECRET", testJWTSecret+"-rotated")
	second := string(azureSessionKey())

	if first == second {
		t.Fatal("rotating JWT_SECRET did not change the cookie key")
	}
}

// An explicit SESSION_SECRET still wins, so a deployment that already set one
// keeps working and anyone who wants the two blast radii separate can have it.
func TestAzureSessionKey_ExplicitSecretOverridesTheDerivation(t *testing.T) {
	setEnv(t, "JWT_SECRET", testJWTSecret)
	setEnv(t, "SESSION_SECRET", testSessionSecret)

	if got := string(azureSessionKey()); got != testSessionSecret {
		t.Fatalf("SESSION_SECRET was ignored: got %q", got)
	}
}

// Too short is not a secret. Falling back to the derivation is better than
// signing with four characters somebody typed to get past a checklist.
func TestAzureSessionKey_ShortSecretFallsBackRatherThanWeakeningTheCookie(t *testing.T) {
	setEnv(t, "JWT_SECRET", testJWTSecret)
	setEnv(t, "SESSION_SECRET", "tooshort")

	key := azureSessionKey()
	if string(key) == "tooshort" {
		t.Fatal("signed with an 8-character key")
	}
	setEnv(t, "SESSION_SECRET", "")
	if string(key) != string(azureSessionKey()) {
		t.Error("a short SESSION_SECRET did not fall back to the JWT derivation")
	}
}

// With nothing to derive from there must be NO key. The caller refuses to issue
// a cookie in that case; returning a key built from an empty secret would sign
// cookies that anyone able to read this source could forge.
func TestAzureSessionKey_NoRootSecretYieldsNoKey(t *testing.T) {
	setEnv(t, "JWT_SECRET", "")
	setEnv(t, "SESSION_SECRET", "")

	if key := azureSessionKey(); len(key) != 0 {
		t.Fatalf("produced a %d-byte key from no secret at all", len(key))
	}
}

// The signature must actually depend on the key, and a key from one deployment
// must not verify the other's cookie.
func TestAzureSession_SignatureIsBoundToTheKey(t *testing.T) {
	const sessionID = "6f1c2a90-7e3b-4a1d-9c55-0b2f8e4d1a77"

	setEnv(t, "SESSION_SECRET", "")
	setEnv(t, "JWT_SECRET", testJWTSecret)
	signed := signAzureSession(sessionID, azureSessionKey())

	if got, ok := verifyAzureSession(signed, azureSessionKey()); !ok || got != sessionID {
		t.Fatalf("a cookie this key signed did not verify: got %q ok=%v", got, ok)
	}

	setEnv(t, "JWT_SECRET", "a-completely-different-deployment-secret-32")
	if _, ok := verifyAzureSession(signed, azureSessionKey()); ok {
		t.Fatal("another deployment's key verified this cookie")
	}
}

// The attack the signature exists to stop: swapping in somebody else's session
// id to use the ARM refresh token it addresses.
func TestAzureSession_RefusesASubstitutedSessionID(t *testing.T) {
	setEnv(t, "SESSION_SECRET", "")
	setEnv(t, "JWT_SECRET", testJWTSecret)
	key := azureSessionKey()

	signed := signAzureSession("mine-6f1c2a90", key)
	_, sig, _ := cutOnce(signed)
	forged := "someone-elses-9b3d4e11." + sig

	if _, ok := verifyAzureSession(forged, key); ok {
		t.Fatal("a cookie naming a different session verified, so one operator " +
			"could use another's stored Azure token")
	}
}

func cutOnce(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
