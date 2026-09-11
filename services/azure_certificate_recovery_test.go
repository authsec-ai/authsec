package services

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/google/uuid"
)

// Offering the generated certificate exactly once, in the moment it was made,
// was a trap. Close the page and the only route forward was to generate again
// -- which replaces the private key and orphans whatever was already uploaded
// to the registration. That happened: the store held one certificate, the app
// registration another, and every token request failed with AADSTS700027
// naming a thumbprint the operator had never seen.
//
// So the certificate is handed back on request. It is the public half: it
// verifies a signature and cannot make one. The private key must not come with
// it, and the thumbprint reported must be the one that actually signs -- a
// thumbprint naming some other certificate would send the operator to compare
// two strings that were never meant to match.

// bundleVault hands back a stored credential bundle.
type bundleVault struct{ data map[string]interface{} }

func (bundleVault) WriteSecret(string, map[string]interface{}) error { return nil }
func (bundleVault) DeleteSecret(string) error                        { return nil }
func (v bundleVault) ReadSecret(string) (map[string]interface{}, error) {
	return v.data, nil
}

func certService(t *testing.T, data map[string]interface{}) *AzureOnboardService {
	t.Helper()
	return &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  bundleVault{data: data},
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}
}

// The whole point of a certificate credential is that the private key never
// leaves. An accessor that returned the bundle would undo that in one line.
func TestCurrentCertificatePEM_NeverReturnsThePrivateKey(t *testing.T) {
	bundle := string(testCertPEM(t))
	if !strings.Contains(bundle, "PRIVATE KEY") {
		t.Fatal("the fixture has no private key, so this test proves nothing")
	}

	got, _ := certService(t, map[string]interface{}{
		"certificate_pem": bundle,
	}).CurrentCertificatePEM(uuid.New())

	if strings.Contains(got, "PRIVATE KEY") {
		t.Fatal("the private key was handed back")
	}
	if !strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Fatalf("no certificate came back either: %q", got)
	}
}

// The reported thumbprint has to be the one the assertion carries in x5t, or
// comparing it against the portal -- which is the entire reason it is shown --
// answers the wrong question.
func TestCurrentCertificatePEM_ThumbprintMatchesTheSigningCredential(t *testing.T) {
	bundle := testCertPEM(t)

	cred, err := azureonboard.CertificateCredential(bundle)
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cred.Thumbprint())
	if err != nil {
		t.Fatalf("decode x5t: %v", err)
	}
	want := strings.ToUpper(hex.EncodeToString(raw))

	_, got := certService(t, map[string]interface{}{
		"certificate_pem": string(bundle),
	}).CurrentCertificatePEM(uuid.New())

	if got != want {
		t.Fatalf("reported %q, but the assertion is signed with %q", got, want)
	}
	// Uppercase hex, because that is what the portal lists and what
	// AADSTS700027 quotes. Anything else has to be decoded by hand to compare.
	if got != strings.ToUpper(got) || len(got) != 40 {
		t.Errorf("not the form the portal shows: %q", got)
	}
}

// A bundle with a chain: the leaf signs, so the leaf is what gets reported.
func TestCurrentCertificatePEM_ReportsTheSigningCertificateOfAChain(t *testing.T) {
	leaf := testCertPEM(t)
	extra := testCertPEM(t)

	// An unrelated certificate FIRST, the signing one last -- the order
	// CertificateCredential resolves in.
	var chain strings.Builder
	for _, blk := range certBlocks(t, extra) {
		_ = pem.Encode(&chain, blk)
	}
	chain.Write(leaf)

	cred, err := azureonboard.CertificateCredential([]byte(chain.String()))
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(cred.Thumbprint())
	want := strings.ToUpper(hex.EncodeToString(raw))

	_, got := certService(t, map[string]interface{}{
		"certificate_pem": chain.String(),
	}).CurrentCertificatePEM(uuid.New())

	if got != want {
		t.Fatalf("reported the wrong certificate of the chain: got %q, signing key is %q",
			got, want)
	}
}

// A workspace on a client secret has no certificate, and must not be offered
// one -- an empty download box reads as a broken page.
func TestCurrentCertificatePEM_EmptyForASecret(t *testing.T) {
	for name, data := range map[string]map[string]interface{}{
		"a secret":           {"client_secret": "s3cr3t"},
		"an empty bundle":    {"certificate_pem": "   "},
		"nothing at all":     {},
		"an unparseable pem": {"certificate_pem": "not a pem"},
	} {
		pemOut, tp := certService(t, data).CurrentCertificatePEM(uuid.New())
		if pemOut != "" || tp != "" {
			t.Errorf("%s produced a certificate: pem=%q thumbprint=%q", name, pemOut, tp)
		}
	}
}

// certBlocks pulls the CERTIFICATE blocks out of a bundle.
func certBlocks(t *testing.T, bundle []byte) []*pem.Block {
	t.Helper()
	var out []*pem.Block
	rest := bundle
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b)
		}
	}
}

// A save that is not about the credential must leave the credential alone.
//
// This form gets submitted more than once -- to correct a redirect URI, to
// re-run the check after granting consent -- and every save used to demand a
// credential. The only certificate this accepts is one it generates, so each of
// those saves minted a new key pair and overwrote the stored one. The
// certificate already uploaded to the registration stopped matching, and the
// failure was AADSTS700027 naming a thumbprint the operator had never seen.
// Saving again to fix it produced a third. Three certificates were generated
// this way before the cause was found.

// recordingVault answers reads from what it holds and remembers writes.
type recordingVault struct {
	data   map[string]interface{}
	writes int
}

func (v *recordingVault) WriteSecret(_ string, d map[string]interface{}) error {
	v.writes++
	v.data = d
	return nil
}
func (v *recordingVault) DeleteSecret(string) error { return nil }
func (v *recordingVault) ReadSecret(string) (map[string]interface{}, error) {
	return v.data, nil
}

func keepInput() AzureAppConfigInput {
	return AzureAppConfigInput{
		ClientID:       "45ec9acc-c71c-4202-8203-603336648ce4",
		HomeTenant:     testTenant,
		RedirectURI:    "http://localhost:8080/api/azure/callback",
		KeepCredential: true,
	}
}

func TestSetAppConfig_KeepCredentialDoesNotTouchTheStoredKey(t *testing.T) {
	bundle := string(testCertPEM(t))
	v := &recordingVault{data: map[string]interface{}{"certificate_pem": bundle}}
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  v,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	// The check itself reaches Microsoft and will fail here. What matters is
	// what happened to the credential before that.
	res, err := svc.SetAppConfig(context.Background(), uuid.New(), "tester", keepInput())
	if err != nil {
		t.Fatalf("a save that keeps the credential was rejected: %v", err)
	}

	if v.writes != 0 {
		t.Errorf("the secrets store was written %d time(s); keeping means not writing", v.writes)
	}
	if got, _ := v.data["certificate_pem"].(string); got != bundle {
		t.Error("the stored certificate changed")
	}
	if res.CertificatePEM != "" {
		t.Error("a new certificate was generated and handed back")
	}
}

// Nothing to keep is a different problem from a store that cannot be read, and
// it must not be answered by silently storing a row with no credential behind
// it -- that reads as configured and fails at the first token request.
func TestSetAppConfig_KeepCredentialRefusesWhenThereIsNothingToKeep(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  &recordingVault{data: map[string]interface{}{}},
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	_, err := svc.SetAppConfig(context.Background(), uuid.New(), "tester", keepInput())
	if err == nil {
		t.Fatal("kept a credential that does not exist")
	}
	if !strings.Contains(err.Error(), "nothing to keep") {
		t.Errorf("does not say what is wrong: %q", err)
	}
	if !strings.Contains(err.Error(), "generateCertificate") {
		t.Errorf("does not say how to fix it: %q", err)
	}
}

// Asking to keep the stored credential and supplying a new one in the same
// request is a contradiction, and guessing which one was meant would silently
// discard a key.
func TestSetAppConfig_KeepCredentialRefusesANewCredentialAlongside(t *testing.T) {
	v := &recordingVault{data: map[string]interface{}{"certificate_pem": string(testCertPEM(t))}}
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  v,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	for name, mut := range map[string]func(*AzureAppConfigInput){
		"and a new certificate": func(in *AzureAppConfigInput) { in.GenerateCertificate = true },
		"and a client secret":   func(in *AzureAppConfigInput) { in.ClientSecret = "s3cr3t" },
	} {
		in := keepInput()
		mut(&in)
		if _, err := svc.SetAppConfig(context.Background(), uuid.New(), "tester", in); err == nil {
			t.Errorf("%s: accepted a contradictory request", name)
		}
	}
	if v.writes != 0 {
		t.Errorf("a rejected request still wrote to the secrets store %d time(s)", v.writes)
	}
}

// Without any credential field at all the request is still refused: this is the
// path that used to be the ONLY one, and it must keep saying what to send.
func TestSetAppConfig_StillRequiresACredentialWhenNotKeeping(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  &recordingVault{},
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}
	in := keepInput()
	in.KeepCredential = false

	_, err := svc.SetAppConfig(context.Background(), uuid.New(), "tester", in)
	if err == nil || !strings.Contains(err.Error(), "clientSecret or generateCertificate") {
		t.Fatalf("expected the missing-credential error, got %v", err)
	}
}

// A certificate that was just generated cannot be on the registration yet, so
// checking it can only fail -- with AADSTS700027, the exact error the upload is
// about to fix. That failure used to be reported next to the new key pair,
// which read as though generating had broken something.
func TestSetAppConfig_DoesNotCheckACertificateItJustGenerated(t *testing.T) {
	v := &recordingVault{}
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  v,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}
	in := keepInput()
	in.KeepCredential = false
	in.GenerateCertificate = true

	res, err := svc.SetAppConfig(context.Background(), uuid.New(), "tester", in)
	if err != nil {
		t.Fatalf("generate was rejected: %v", err)
	}
	if res.CertificatePEM == "" {
		t.Fatal("no certificate came back")
	}
	if res.Check != nil {
		t.Error("Microsoft was asked about a certificate that cannot be registered yet")
	}
	if res.CheckError != "" {
		t.Errorf("a doomed check ran and its failure was reported: %q", res.CheckError)
	}
	if v.writes != 1 {
		t.Errorf("the new key pair was written %d time(s), want 1", v.writes)
	}
}
