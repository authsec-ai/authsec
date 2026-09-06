package gcp

import (
	"testing"

	"github.com/google/uuid"
)

// TestDeriveWIFParams_Deterministic proves DeriveWIFParams is a pure function:
// the SAME (workspace_id, scope_id) always produces the SAME three outputs,
// across repeated calls, with no randomness or I/O involved. This is
// load-bearing for GCP-D9's design — the console's onboarding-package
// renderer and the connector-create cross-check must independently compute
// the identical strings from the same inputs, or a customer's correctly
// pasted provider_resource fails validation for no reason support could
// explain.
func TestDeriveWIFParams_Deterministic(t *testing.T) {
	ws := uuid.New()
	const scopeID = "my-gcp-project"

	poolID1, providerID1, subject1 := DeriveWIFParams(ws, scopeID)
	poolID2, providerID2, subject2 := DeriveWIFParams(ws, scopeID)

	if poolID1 != poolID2 {
		t.Errorf("poolID not deterministic: %q vs %q", poolID1, poolID2)
	}
	if providerID1 != providerID2 {
		t.Errorf("providerID not deterministic: %q vs %q", providerID1, providerID2)
	}
	if subject1 != subject2 {
		t.Errorf("subject not deterministic: %q vs %q", subject1, subject2)
	}
}

// TestDeriveWIFParams_ProviderIDIsFixed proves provider_id is the fixed
// string GCP-D9's design specifies, not derived — there is exactly one
// provider per pool, so there is nothing to disambiguate.
func TestDeriveWIFParams_ProviderIDIsFixed(t *testing.T) {
	_, providerID, _ := DeriveWIFParams(uuid.New(), "any-scope")
	if providerID != "authsec-provider" {
		t.Errorf("providerID = %q, want the fixed \"authsec-provider\"", providerID)
	}
}

// TestDeriveWIFParams_DiffersByInput proves the derivation actually depends
// on both inputs — a pure function that ignored its arguments would also be
// "deterministic" by the test above, so this is the test that actually rules
// that out.
func TestDeriveWIFParams_DiffersByInput(t *testing.T) {
	wsA, wsB := uuid.New(), uuid.New()

	poolA, _, subjA := DeriveWIFParams(wsA, "scope-1")
	poolB, _, subjB := DeriveWIFParams(wsB, "scope-1")
	if poolA == poolB {
		t.Error("pool id must differ across workspaces for the same scope_id")
	}
	if subjA == subjB {
		t.Error("wif_subject must differ across workspaces for the same scope_id")
	}

	poolC, _, subjC := DeriveWIFParams(wsA, "scope-2")
	if poolA == poolC {
		t.Error("pool id must differ across scope_ids for the same workspace")
	}
	if subjA == subjC {
		t.Error("wif_subject must differ across scope_ids for the same workspace")
	}
}

// TestDeriveWIFParams_Shape proves the pool id and subject carry the exact
// prefixes prompt.md's GCP-D9 design specifies, since GCP-04's setup-reader.sh
// renderer and the customer-facing console both bake these directly into a
// gcloud command and an IAM principal string.
func TestDeriveWIFParams_Shape(t *testing.T) {
	poolID, _, subject := DeriveWIFParams(uuid.New(), "some-scope-id")

	const poolPrefix = "authsec-"
	if len(poolID) <= len(poolPrefix) || poolID[:len(poolPrefix)] != poolPrefix {
		t.Errorf("poolID = %q, want it to start with %q", poolID, poolPrefix)
	}
	// "authsec-" + 16 hex chars.
	if got, want := len(poolID), len(poolPrefix)+16; got != want {
		t.Errorf("len(poolID) = %d, want %d", got, want)
	}

	const subjectPrefix = "authsec:"
	if len(subject) <= len(subjectPrefix) || subject[:len(subjectPrefix)] != subjectPrefix {
		t.Errorf("subject = %q, want it to start with %q", subject, subjectPrefix)
	}
	if got, want := len(subject), len(subjectPrefix)+32; got != want {
		t.Errorf("len(subject) = %d, want %d", got, want)
	}
}

// TestDeriveWIFParams_And_ParseProviderResource_RealIncidentValues is the
// regression for a real live failure (2026-09-02, workspace
// 2ac37bca-49c9-48d3-b656-da1ef46c6f94, scope codevault-8cc83): a customer's
// Cloud Shell run printed a provider_resource that this test proves — using
// the exact real workspace_id, scope_id, and project number involved —
// passes AuthSec's own pre-flight cross-check byte-for-byte.
//
// A test-only HMAC key is used here rather than the real deployment secret
// (never duplicate that into a test file); what this test locks in is the
// SHAPE and CONSISTENCY of the real-world inputs (workspace_id, scope_id,
// project number, the "authsec-provider" fixed provider id, and the
// provider_resource string format Cloud Shell's script actually printed),
// not the specific secret-dependent hash value. The live incident's actual
// root cause — confirmed separately, live, against the real deployment
// secret — was never a mismatch here: it was GCP's STS being unable to
// reach the WIF provider's configured issuer (see
// gcp.ErrWIFIssuerUnreachable and services/gcp_auth_service_test.go's
// TestClassifyIAMError "wif issuer unreachable" case).
func TestDeriveWIFParams_And_ParseProviderResource_RealIncidentValues(t *testing.T) {
	t.Setenv("AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY", "test-only-hmac-key-for-regression")

	ws := uuid.MustParse("2ac37bca-49c9-48d3-b656-da1ef46c6f94")
	const scopeID = "codevault-8cc83"
	const projectNumber = "540895695383"

	poolID, providerID, subject := DeriveWIFParams(ws, scopeID)
	if providerID != ProviderID {
		t.Fatalf("providerID = %q, want the fixed %q", providerID, ProviderID)
	}

	// The exact provider_resource shape setup-reader.sh prints (real
	// incident values, only the pool_id below is test-key-dependent).
	providerResource := "projects/" + projectNumber + "/locations/global/workloadIdentityPools/" + poolID + "/providers/" + providerID

	pastedPool, pastedProvider, ok := ParseProviderResource(providerResource)
	if !ok {
		t.Fatalf("ParseProviderResource(%q) did not match — the real incident's script-printed shape must always parse", providerResource)
	}
	if pastedPool != poolID {
		t.Errorf("parsed pool = %q, want %q", pastedPool, poolID)
	}
	if pastedProvider != providerID {
		t.Errorf("parsed provider = %q, want %q", pastedProvider, providerID)
	}

	// Re-deriving independently (exactly what resolveOnboardingCredential's
	// cross-check does) must agree — this is the assertion that was
	// mistakenly suspected to fail during the live incident and, per the
	// live capture, never did.
	wantPool, wantProvider, wantSubject := DeriveWIFParams(ws, scopeID)
	if pastedPool != wantPool || pastedProvider != wantProvider {
		t.Fatalf("cross-check would have failed: pasted pool/provider (%q, %q) != re-derived (%q, %q)",
			pastedPool, pastedProvider, wantPool, wantProvider)
	}
	if subject != wantSubject {
		t.Fatalf("DeriveWIFParams not deterministic across calls: %q != %q", subject, wantSubject)
	}
}

/* ------------------------- provider resource parsing ----------------------- */

func TestParseProviderResource_Valid(t *testing.T) {
	poolID, providerID, ok := ParseProviderResource(
		"projects/123456789012/locations/global/workloadIdentityPools/authsec-abc123/providers/authsec-provider")
	if !ok {
		t.Fatal("expected ok=true for a well-formed provider resource")
	}
	if poolID != "authsec-abc123" {
		t.Errorf("poolID = %q, want %q", poolID, "authsec-abc123")
	}
	if providerID != "authsec-provider" {
		t.Errorf("providerID = %q, want %q", providerID, "authsec-provider")
	}
}

func TestParseProviderResource_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-resource-name",
		"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/pr", // has the scheme prefix -- must NOT be accepted here
		"projects/not-a-number/locations/global/workloadIdentityPools/p/providers/pr",
		"projects/123/locations/us-central1/workloadIdentityPools/p/providers/pr", // wrong location
		"principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/subject/x",
	}
	for _, c := range cases {
		if _, _, ok := ParseProviderResource(c); ok {
			t.Errorf("ParseProviderResource(%q) = ok, want not-ok", c)
		}
	}
}

/* ------------------------------- wif issuer -------------------------------- */

// TestResolveWIFIssuerURL_DefaultsToAppIssuer proves that with no override
// env var set, the app's own issuer is used unchanged — production, which
// sets no GCP_WIF_ISSUER_URL, needs zero new configuration and can never
// accidentally substitute anything else (in particular, never a localhost
// value that wasn't itself the passed-in default).
func TestResolveWIFIssuerURL_DefaultsToAppIssuer(t *testing.T) {
	got := ResolveWIFIssuerURL("https://app.authsec.dev")
	if got != "https://app.authsec.dev" {
		t.Fatalf("expected the app issuer unchanged, got %q", got)
	}
}

// TestResolveWIFIssuerURL_OverrideWins proves GCP_WIF_ISSUER_URL, when set,
// is used instead of the app's own issuer — the mechanism a local developer
// uses to point WIF at a public HTTPS tunnel while BASE_URL/OAUTH_ISSUER_URL
// stay at http://localhost:7001 for everything else.
func TestResolveWIFIssuerURL_OverrideWins(t *testing.T) {
	t.Setenv(WIFIssuerEnv, "https://abc123.trycloudflare.com")
	got := ResolveWIFIssuerURL("http://localhost:7001")
	if got != "https://abc123.trycloudflare.com" {
		t.Fatalf("expected the override, got %q", got)
	}
}

// TestResolveWIFIssuerURL_TrimsTrailingSlash proves both the override and
// the default path normalize a trailing slash identically, so a stray "/"
// in either BASE_URL or GCP_WIF_ISSUER_URL can't produce a script/token
// mismatch (the setup script's --issuer-uri= and the minted JWT's `iss`
// claim must be byte-identical, or GCP rejects the exchange for a reason
// that looks unrelated to the actual typo).
func TestResolveWIFIssuerURL_TrimsTrailingSlash(t *testing.T) {
	if got := ResolveWIFIssuerURL("https://app.authsec.dev/"); got != "https://app.authsec.dev" {
		t.Fatalf("default path: expected trailing slash trimmed, got %q", got)
	}
	t.Setenv(WIFIssuerEnv, "https://abc123.trycloudflare.com/")
	if got := ResolveWIFIssuerURL("http://localhost:7001"); got != "https://abc123.trycloudflare.com" {
		t.Fatalf("override path: expected trailing slash trimmed, got %q", got)
	}
}

// TestResolveWIFIssuerURL_EmptyOverrideIgnored proves an env var set to an
// empty/whitespace string is treated as unset, not as "use an empty
// issuer" — falls back to the default exactly as if GCP_WIF_ISSUER_URL had
// never been set at all.
func TestResolveWIFIssuerURL_EmptyOverrideIgnored(t *testing.T) {
	t.Setenv(WIFIssuerEnv, "   ")
	got := ResolveWIFIssuerURL("https://app.authsec.dev")
	if got != "https://app.authsec.dev" {
		t.Fatalf("expected fallback to the default, got %q", got)
	}
}

// TestIsHTTPSIssuer proves the one rule GCP actually enforces: scheme must
// be https, nothing more permissive.
func TestIsHTTPSIssuer(t *testing.T) {
	cases := map[string]bool{
		"https://app.authsec.dev":         true,
		"https://abc123.ngrok-free.app":   true,
		"http://localhost:7001":           false,
		"http://app.authsec.dev":          false,
		"":                                false,
		"ftp://app.authsec.dev":           false,
		"httpsx://not-actually-https.com": false,
	}
	for issuer, want := range cases {
		if got := IsHTTPSIssuer(issuer); got != want {
			t.Errorf("IsHTTPSIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}
