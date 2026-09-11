package azureonboard

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"
)

// AuthSec generates the key pair so the private half never travels. An operator
// who runs openssl and pastes the result sends that key through a clipboard, a
// browser and a request body -- the same path a client secret takes, which is
// the thing a certificate credential exists to avoid.
//
// So the property that matters most is not that the certificate is well formed.
// It is that the two halves stay separated: the bundle goes to the secrets
// store, and only the certificate is ever handed back.

func TestGenerateCertificate_SplitsThePublicHalfFromThePrivate(t *testing.T) {
	got, err := GenerateCertificate("authsec-test", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// The half meant for the operator must contain NO key material. This is the
	// assertion the whole feature rests on.
	certStr := string(got.CertificatePEM)
	if strings.Contains(certStr, "PRIVATE KEY") {
		t.Fatal("the certificate handed back contains a private key")
	}
	if !strings.Contains(certStr, "BEGIN CERTIFICATE") {
		t.Fatalf("certificate PEM does not contain a certificate: %q", certStr)
	}

	// And the half meant for the secrets store must contain both, or nothing
	// can sign an assertion later.
	bundle := string(got.Bundle)
	if !strings.Contains(bundle, "PRIVATE KEY") || !strings.Contains(bundle, "BEGIN CERTIFICATE") {
		t.Fatal("the stored bundle is missing a half")
	}
}

// What was generated has to be usable by the code that will use it, or the
// operator uploads a certificate and the next token request still fails.
func TestGenerateCertificate_ProducesAUsableCredential(t *testing.T) {
	got, err := GenerateCertificate("authsec-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	cred, err := CertificateCredential(got.Bundle)
	if err != nil {
		t.Fatalf("the generated bundle does not parse as a credential: %v", err)
	}
	if !cred.Configured() {
		t.Fatal("parsed but reports itself unconfigured")
	}
	// The same twenty bytes, written two ways on purpose: x5t in the JWT header
	// because the protocol says base64url, hex in the reported thumbprint
	// because that is what the portal shows a human. They must still agree.
	raw, dErr := base64.RawURLEncoding.DecodeString(cred.Thumbprint())
	if dErr != nil {
		t.Fatalf("x5t is not base64url: %v", dErr)
	}
	if want := strings.ToUpper(hex.EncodeToString(raw)); want != got.Thumbprint {
		t.Fatalf("the assertion is signed with %q but %q was reported", want, got.Thumbprint)
	}

	form := url.Values{}
	if err := cred.apply(form, "client-id", "https://login.microsoftonline.com/t/oauth2/v2.0/token"); err != nil {
		t.Fatalf("cannot sign with the generated key: %v", err)
	}
	if form.Get("client_assertion") == "" {
		t.Fatal("no assertion was produced")
	}
}

// The thumbprint AuthSec reports is what the portal will show against the
// uploaded certificate, so an operator can tell which one belongs here -- which
// means it has to be in the portal's encoding. It was base64url here and
// uppercase hex on the read-back path, under one field name, so the value the
// operator was handed at generation time matched nothing they could see.
func TestGenerateCertificate_ThumbprintMatchesTheCertificateAlone(t *testing.T) {
	got, err := GenerateCertificate("authsec-test", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	block, _ := pem.Decode(got.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("certificate PEM does not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	sum := sha1.Sum(cert.Raw)
	if want := strings.ToUpper(hex.EncodeToString(sum[:])); got.Thumbprint != want {
		t.Fatalf("thumbprint = %q, want %q", got.Thumbprint, want)
	}
	// Forty uppercase hex characters, the form AADSTS700027 quotes. Anything
	// else has to be decoded by hand before it can be compared.
	if len(got.Thumbprint) != 40 || got.Thumbprint != strings.ToUpper(got.Thumbprint) {
		t.Errorf("not the form the portal shows: %q", got.Thumbprint)
	}
}

func TestGenerateCertificate_ValidityWindow(t *testing.T) {
	const life = 365 * 24 * time.Hour
	got, err := GenerateCertificate("authsec-test", life)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	block, _ := pem.Decode(got.CertificatePEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Valid now. Backdated slightly, because a certificate rejected for being
	// "not yet valid" over a small clock difference is a confusing failure.
	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Errorf("not valid until %v, which is in the future", cert.NotBefore)
	}
	if !cert.NotAfter.After(now.Add(300 * 24 * time.Hour)) {
		t.Errorf("expires %v, sooner than the requested lifetime", cert.NotAfter)
	}
	if !got.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("reported expiry %v does not match the certificate's %v",
			got.NotAfter, cert.NotAfter)
	}

	// Entra uses this for client authentication, and says so.
	found := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("certificate is not marked for client authentication")
	}
}

// Two calls must never produce the same key.
func TestGenerateCertificate_IsUniquePerCall(t *testing.T) {
	a, err := GenerateCertificate("authsec-test", time.Hour)
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := GenerateCertificate("authsec-test", time.Hour)
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	if a.Thumbprint == b.Thumbprint {
		t.Fatal("two generated certificates share a thumbprint")
	}
	if string(a.Bundle) == string(b.Bundle) {
		t.Fatal("two generated bundles are identical")
	}
}
