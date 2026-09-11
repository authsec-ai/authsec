package azureonboard

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A certificate credential replaces the password that used to cross the network
// on every token request. What Entra actually verifies is a JWT this code signs,
// so the parts it checks are the parts asserted here: the signature, the
// certificate thumbprint that says which public key to verify against, and the
// audience that pins an assertion to one endpoint.
//
// The audience matters more than it looks. This flow talks to several tenant
// token endpoints, and an assertion built for one is rejected at another -- so a
// single assertion built once and reused would work in development against one
// tenant and fail the moment a second was onboarded.

// testCert makes a self-signed RSA certificate and returns the PEM bundle Entra
// expects: the private key and the certificate together.
func testCert(t *testing.T) (pemBundle []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()

	// 2048 rather than 4096: this runs on every test invocation.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authsec-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	var b strings.Builder
	_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return []byte(b.String()), cert, key
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return der
}

// decodeJWT splits an assertion and returns its header and claims.
func decodeJWT(t *testing.T, jwt string) (header, claims map[string]any, signing, sig string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts, want 3", len(parts))
	}
	dec := func(s string) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return m
	}
	return dec(parts[0]), dec(parts[1]), parts[0] + "." + parts[1], parts[2]
}

// The signature must verify against the certificate's public key. Everything
// else here is worthless if this does not hold.
func TestCertificateCredential_SignsAVerifiableAssertion(t *testing.T) {
	bundle, cert, _ := testCert(t)
	cred, err := CertificateCredential(bundle)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	form := url.Values{}
	const endpoint = "https://login.microsoftonline.com/tenant-a/oauth2/v2.0/token"
	if err := cred.apply(form, "client-id", endpoint); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The secret form must be gone entirely, not merely unused.
	if form.Get("client_secret") != "" {
		t.Fatal("a certificate credential sent a client_secret")
	}
	if got := form.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q", got)
	}

	_, _, signing, sig := decodeJWT(t, form.Get("client_assertion"))
	rawSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(signing))
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("certificate does not carry an RSA public key")
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], rawSig); err != nil {
		t.Fatalf("signature does not verify against the certificate: %v", err)
	}
}

// x5t tells Entra which uploaded certificate to check. Wrong, and every token
// request fails with an error about the assertion rather than the certificate.
func TestCertificateCredential_ThumbprintMatchesTheCertificate(t *testing.T) {
	bundle, cert, _ := testCert(t)
	cred, err := CertificateCredential(bundle)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	sum := sha1.Sum(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if cred.Thumbprint() != want {
		t.Fatalf("thumbprint = %q, want %q", cred.Thumbprint(), want)
	}

	form := url.Values{}
	if err := cred.apply(form, "client-id", "https://example/token"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	header, _, _, _ := decodeJWT(t, form.Get("client_assertion"))
	if header["x5t"] != want {
		t.Fatalf("x5t header = %v, want %q", header["x5t"], want)
	}
	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", header["alg"])
	}
}

// An assertion names ONE endpoint. Two tenants must get two assertions, or the
// second tenant's token request is rejected.
func TestCertificateCredential_AudienceIsPerEndpoint(t *testing.T) {
	bundle, _, _ := testCert(t)
	cred, err := CertificateCredential(bundle)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}

	const a = "https://login.microsoftonline.com/tenant-a/oauth2/v2.0/token"
	const b = "https://login.microsoftonline.com/tenant-b/oauth2/v2.0/token"

	formA, formB := url.Values{}, url.Values{}
	if err := cred.apply(formA, "client-id", a); err != nil {
		t.Fatalf("apply a: %v", err)
	}
	if err := cred.apply(formB, "client-id", b); err != nil {
		t.Fatalf("apply b: %v", err)
	}

	_, claimsA, _, _ := decodeJWT(t, formA.Get("client_assertion"))
	_, claimsB, _, _ := decodeJWT(t, formB.Get("client_assertion"))

	if claimsA["aud"] != a {
		t.Errorf("aud = %v, want %q", claimsA["aud"], a)
	}
	if claimsB["aud"] != b {
		t.Errorf("aud = %v, want %q", claimsB["aud"], b)
	}
	if claimsA["jti"] == claimsB["jti"] {
		t.Error("two assertions share a jti; each must be single-use")
	}
}

func TestCertificateCredential_ClaimsEntraRequires(t *testing.T) {
	bundle, _, _ := testCert(t)
	cred, _ := CertificateCredential(bundle)

	form := url.Values{}
	if err := cred.apply(form, "the-client-id", "https://example/token"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	_, claims, _, _ := decodeJWT(t, form.Get("client_assertion"))

	// iss and sub are both the client id -- the application asserting about
	// itself. Anything else and Entra refuses.
	if claims["iss"] != "the-client-id" || claims["sub"] != "the-client-id" {
		t.Fatalf("iss/sub = %v/%v, want the client id", claims["iss"], claims["sub"])
	}
	nbf, okN := claims["nbf"].(float64)
	exp, okE := claims["exp"].(float64)
	if !okN || !okE {
		t.Fatalf("nbf/exp missing or not numeric: %v %v", claims["nbf"], claims["exp"])
	}
	if exp <= nbf {
		t.Fatal("assertion expires before it becomes valid")
	}
	// Short-lived: minted per request, never stored.
	if d := time.Duration(exp-nbf) * time.Second; d > 11*time.Minute {
		t.Fatalf("assertion lives %v; Entra permits at most 10 minutes", d)
	}
	// A little slack before now, or a small clock difference rejects it.
	if float64(time.Now().Unix()) < nbf {
		t.Fatal("assertion is not yet valid at the moment it was created")
	}
}

// A key with no certificate cannot produce a thumbprint, so it cannot be used --
// and the reason has to say that, not fail later inside a token request.
func TestCertificateCredential_RejectsAnIncompleteBundle(t *testing.T) {
	bundle, _, key := testCert(t)

	keyOnly := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	if _, err := CertificateCredential(keyOnly); err == nil {
		t.Error("accepted a bundle with no certificate")
	} else if !strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("error does not name what is missing: %v", err)
	}

	// Certificate alone: nothing to sign with.
	certOnly := bundle[strings.Index(string(bundle), "-----BEGIN CERTIFICATE"):]
	if _, err := CertificateCredential(certOnly); err == nil {
		t.Error("accepted a bundle with no private key")
	} else if !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error does not name what is missing: %v", err)
	}

	if _, err := CertificateCredential([]byte("not pem at all")); err == nil {
		t.Error("accepted something that is not PEM")
	}
}

// PKCS#1 and PKCS#8 are both common, depending on which tool made the key.
func TestCertificateCredential_AcceptsBothKeyEncodings(t *testing.T) {
	_, _, key := testCert(t)
	der, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{SerialNumber: big.NewInt(2), NotAfter: time.Now().Add(time.Hour)},
		&x509.Certificate{SerialNumber: big.NewInt(2), NotAfter: time.Now().Add(time.Hour)},
		&key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	for name, keyPEM := range map[string][]byte{
		"PKCS#1": pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		"PKCS#8": pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)}),
	} {
		if _, err := CertificateCredential(append(keyPEM, certPEM...)); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
}

// The secret form still works, unchanged.
func TestSecretCredential_SendsTheSecretAndNoAssertion(t *testing.T) {
	form := url.Values{}
	if err := SecretCredential("s3cret").apply(form, "client-id", "https://example/token"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if form.Get("client_secret") != "s3cret" {
		t.Fatalf("client_secret = %q", form.Get("client_secret"))
	}
	if form.Get("client_assertion") != "" {
		t.Fatal("a secret credential sent an assertion")
	}
}

// Neither form supplied is a configuration fault, and it must surface as one
// rather than as a token request Microsoft rejects for an opaque reason.
func TestCredential_UnconfiguredIsRefusedBeforeAnyRequest(t *testing.T) {
	for name, cred := range map[string]Credential{
		"empty secret": SecretCredential("   "),
		"zero value":   {},
	} {
		if cred.Configured() {
			t.Errorf("%s: reported itself configured", name)
		}
		if err := cred.apply(url.Values{}, "client-id", "https://example/token"); err == nil {
			t.Errorf("%s: applied without a credential", name)
		}
	}

	bundle, _, _ := testCert(t)
	cred, _ := CertificateCredential(bundle)
	if !cred.Configured() {
		t.Error("a parsed certificate credential reports itself unconfigured")
	}
	if !SecretCredential("s3cret").Configured() {
		t.Error("a secret credential reports itself unconfigured")
	}
}
