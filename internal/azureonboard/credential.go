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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// How the application proves it is itself.
//
// Entra accepts two forms and they are not equivalent. A client secret is a
// password: it travels to Microsoft on EVERY token request, so it exists in
// transit, in whatever terminated the TLS, and in whatever the customer pasted
// it into. A certificate credential never travels at all -- the application
// signs a short-lived assertion with a private key that can live in an HSM as
// non-exportable, and Microsoft verifies it against a public key it already
// holds.
//
// Both are supported because refusing the secret would refuse the customers who
// cannot easily run a PKI, and refusing the certificate would refuse the ones
// whose compliance requires one. They are NOT offered as an even choice: the
// certificate is the recommendation and the check says so.
//
// A third form, federated credentials, removes the stored credential entirely --
// an external OIDC issuer vouches for the workload. It shares this assertion
// shape, so adding it later is a matter of where the assertion comes from
// rather than a new path through the client.

// CredentialKind names how an application authenticates.
type CredentialKind string

const (
	CredentialSecret      CredentialKind = "secret"
	CredentialCertificate CredentialKind = "certificate"
)

// Credential is the application's proof of identity.
//
// It has no String or MarshalJSON, for the same reason TokenSet does not: the
// zero-effort path for a caller must not be one that prints a private key.
type Credential struct {
	Kind CredentialKind

	// secret is the client secret value. Set only for CredentialSecret.
	secret string

	// key signs the assertion, and thumbprint identifies which uploaded
	// certificate Microsoft should verify it against. Set only for
	// CredentialCertificate.
	key        *rsa.PrivateKey
	thumbprint string
}

// SecretCredential wraps a client secret.
func SecretCredential(secret string) Credential {
	return Credential{Kind: CredentialSecret, secret: secret}
}

// ErrNoCredential means neither form was supplied.
var ErrNoCredential = errors.New("the application has no client secret and no certificate")

// CertificateCredential parses a PEM bundle holding a private key AND the
// certificate it belongs to.
//
// Both are required, and the certificate is not decoration: Microsoft matches an
// assertion to an uploaded public key by SHA-1 thumbprint, carried in the JWT's
// x5t header. With the key alone there is nothing to compute that from, and
// every token request fails with an error about the assertion rather than about
// the missing certificate.
//
// SHA-1 here is not a security choice. It is the algorithm the x5t header is
// defined with (RFC 7515), and it identifies a certificate rather than
// protecting anything -- the signature underneath is RS256.
func CertificateCredential(pemBundle []byte) (Credential, error) {
	var (
		key  *rsa.PrivateKey
		cert *x509.Certificate
	)
	rest := pemBundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			k, err := parseRSAPrivateKey(block.Bytes)
			if err != nil {
				return Credential{}, err
			}
			key = k
		case block.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return Credential{}, fmt.Errorf("parse certificate: %w", err)
			}
			cert = c
		}
	}
	if key == nil {
		return Credential{}, errors.New(
			"no RSA PRIVATE KEY block in the PEM. Include the private key and the certificate " +
				"in one file")
	}
	if cert == nil {
		return Credential{}, errors.New(
			"no CERTIFICATE block in the PEM. Microsoft identifies the uploaded public key by " +
				"its thumbprint, which can only be computed from the certificate")
	}

	sum := sha1.Sum(cert.Raw)
	return Credential{
		Kind:       CredentialCertificate,
		key:        key,
		thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// parseRSAPrivateKey accepts both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8
// ("PRIVATE KEY"), because which one a customer has depends on the tool that
// made it and neither is unusual.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	k, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T; Entra certificate credentials require RSA", any)
	}
	return k, nil
}

// Configured reports whether there is anything to authenticate with.
func (c Credential) Configured() bool {
	switch c.Kind {
	case CredentialSecret:
		return strings.TrimSpace(c.secret) != ""
	case CredentialCertificate:
		return c.key != nil && c.thumbprint != ""
	}
	return false
}

// Thumbprint is the certificate's x5t value, for reporting. Empty for a secret.
// Never the key.
func (c Credential) Thumbprint() string { return c.thumbprint }

// apply adds the credential to a token request form.
//
// tokenEndpoint is required and is not incidental: a certificate assertion names
// the endpoint it may be redeemed at in its aud claim, so an assertion built for
// one tenant is rejected at another. This flow talks to several tenant
// endpoints, which is exactly the mistake a single cached assertion would make.
func (c Credential) apply(form url.Values, clientID, tokenEndpoint string) error {
	switch c.Kind {
	case CredentialSecret:
		if strings.TrimSpace(c.secret) == "" {
			return ErrNoCredential
		}
		form.Set("client_secret", c.secret)
		return nil

	case CredentialCertificate:
		if c.key == nil {
			return ErrNoCredential
		}
		assertion, err := c.assertion(clientID, tokenEndpoint)
		if err != nil {
			return err
		}
		form.Set("client_assertion_type",
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
		return nil
	}
	return ErrNoCredential
}

// assertionLifetime is how long a client assertion is valid.
//
// Short on purpose: it is minted per request and never stored, so nothing needs
// it to outlive the call. Microsoft permits up to 10 minutes.
const assertionLifetime = 5 * time.Minute

// assertion builds and signs the JWT Entra accepts in place of a secret.
func (c Credential) assertion(clientID, tokenEndpoint string) (string, error) {
	now := time.Now()

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		// Which uploaded certificate to verify against.
		"x5t": c.thumbprint,
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate assertion id: %w", err)
	}
	claims := map[string]any{
		// The endpoint this assertion may be redeemed at, and nowhere else.
		"aud": tokenEndpoint,
		"iss": clientID,
		"sub": clientID,
		"jti": base64.RawURLEncoding.EncodeToString(nonce),
		"nbf": now.Add(-30 * time.Second).Unix(), // clock skew
		"exp": now.Add(assertionLifetime).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc(headerJSON) + "." + enc(claimsJSON)

	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return signing + "." + enc(sig), nil
}

/* ----------------------------- generating one ----------------------------- */

// GeneratedCertificate is a fresh key pair, split by who may see which half.
type GeneratedCertificate struct {
	// Bundle is the private key AND the certificate, for the secrets store.
	// It never leaves the deployment and is never returned by any endpoint.
	Bundle []byte

	// CertificatePEM is the certificate alone -- the PUBLIC half. This is what
	// the operator downloads and uploads to the app registration. It is safe to
	// email, to log and to keep: it verifies a signature and cannot make one.
	CertificatePEM []byte

	// Thumbprint identifies it in the portal, so an operator can tell which
	// uploaded certificate corresponds to this deployment.
	//
	// UPPERCASE HEX, because that is the form the portal lists under
	// Certificates and the form AADSTS700027 quotes. It was base64url x5t
	// here and hex on the read-back path, under one field name -- so an
	// operator comparing what POST /api/azure/config returned against the
	// portal was comparing a string that appears nowhere. The x5t encoding
	// belongs in the JWT header, and Credential.Thumbprint still carries it
	// there; it is not an identifier for a human to match.
	Thumbprint string

	NotAfter time.Time
}

// GenerateCertificate creates the key pair AuthSec will authenticate with.
//
// Generated HERE rather than by the operator, and that is the point of the whole
// feature rather than a convenience.
//
// A certificate credential is worth having because the private key never
// travels. An operator who runs openssl and pastes the result sends that key
// through a clipboard, a browser, a network and a request body -- the same path
// a client secret takes, once. Generating it inside the deployment means the
// only thing that ever travels is the certificate, which is public.
//
// Self-signed on purpose. Entra does not validate a chain here: it stores the
// public key from whatever is uploaded and checks assertions against it. Paying
// a CA would buy nothing.
func GenerateCertificate(commonName string, validFor time.Duration) (*GeneratedCertificate, error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "authsec"
	}
	// 2048 rather than 4096: Entra accepts both, every library verifies it
	// quickly, and the assertion is re-signed on every token request.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		// Backdated a little: a certificate that is not yet valid because the
		// two machines disagree about the time is a confusing way to fail.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Read the expiry back out of the certificate rather than reporting what was
	// asked for. X.509 stores time to the second and in UTC, so the encoded
	// value is not the template's -- and the encoded one is what Azure enforces
	// and what the portal will display.
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("read back the certificate just created: %w", err)
	}

	sum := sha1.Sum(der)
	return &GeneratedCertificate{
		// Key first, so the bundle reads the way every tool writes one.
		Bundle:         append(keyPEM, certPEM...),
		CertificatePEM: certPEM,
		Thumbprint:     strings.ToUpper(hex.EncodeToString(sum[:])),
		NotAfter:       parsed.NotAfter,
	}, nil
}
