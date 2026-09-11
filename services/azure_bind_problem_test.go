package services

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/azureonboard"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// When a workspace has submitted its own Entra application, the service binds to
// that row. Every way that binding can fail used to end in the same silent
// `return s` -- the unbound service, falling back to environment variables the
// workspace was never asked to set.
//
// The error an operator then saw was:
//
//	missing client id, redirect uri, client secret
//
// with the client id and redirect uri sitting in the row, and the actual fault
// -- an unreadable secret -- unmentioned. It sends whoever is debugging to check
// the three things that are fine. This happened for real: a development secrets
// store kept nothing across a restart, the row survived in Postgres, and the
// console reported "configured, secret set".

// failingVault reads nothing back.
type failingVault struct{ err error }

func (v failingVault) WriteSecret(string, map[string]interface{}) error { return nil }
func (v failingVault) DeleteSecret(string) error                        { return nil }
func (v failingVault) ReadSecret(string) (map[string]interface{}, error) {
	return nil, v.err
}

// emptyVault answers, but with no secret in it.
type emptyVault struct{}

func (emptyVault) WriteSecret(string, map[string]interface{}) error { return nil }
func (emptyVault) DeleteSecret(string) error                        { return nil }
func (emptyVault) ReadSecret(string) (map[string]interface{}, error) {
	return map[string]interface{}{"note": "nothing useful here"}, nil
}

// stubAppCfgRepo returns one stored application.
type stubAppCfgRepo struct{ cfg *models.AzureAppConfig }

func (r stubAppCfgRepo) Get(uuid.UUID) (*models.AzureAppConfig, error) { return r.cfg, nil }
func (r stubAppCfgRepo) Upsert(*models.AzureAppConfig) (*models.AzureAppConfig, error) {
	return r.cfg, nil
}
func (r stubAppCfgRepo) Delete(uuid.UUID) error      { return nil }
func (r stubAppCfgRepo) MarkChecked(uuid.UUID) error { return nil }

const testAuthRef = "kv/data/secret/workspaces/test/azure/app"

// testCertPEM is a private key and its certificate in one PEM, which is the
// bundle a certificate credential is submitted as. Generated rather than
// checked in: a real key in the repository is a real key in the repository,
// however small.
func testCertPEM(t *testing.T) []byte {
	t.Helper()
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var b bytes.Buffer
	_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return b.Bytes()
}

func storedApp() *models.AzureAppConfig {
	return &models.AzureAppConfig{
		ClientID:    "45ec9acc-c71c-4202-8203-603336648ce4",
		HomeTenant:  testTenant,
		RedirectURI: "http://localhost:8080/api/azure/callback",
		AuthRef:     testAuthRef,
	}
}

// An unreadable secret must be named as such, and the message must not claim the
// client id or redirect uri are missing -- they are in the row.
func TestForWorkspace_UnreadableSecretIsNamed(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  failingVault{err: errors.New("route entry not found")},
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("a service with no usable secret reported itself ready")
	}
	msg := err.Error()

	if !strings.Contains(msg, "stored application") {
		t.Errorf("does not say the workspace has its own application: %q", msg)
	}
	if !strings.Contains(msg, "route entry not found") {
		t.Errorf("does not carry the secrets-store error: %q", msg)
	}
	if !strings.Contains(msg, testAuthRef) {
		t.Errorf("does not name the path it failed to read: %q", msg)
	}
	// The old, misleading message. Both of these ARE configured.
	if strings.Contains(msg, "missing client id") || strings.Contains(msg, "redirect uri.") {
		t.Errorf("still blames values that are present in the row: %q", msg)
	}
}

// A secrets store that answers with nothing is a different fault from one that
// errors, and says so.
func TestForWorkspace_EmptySecretIsNamed(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  emptyVault{},
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("reported ready with no secret")
	}
	if !strings.Contains(err.Error(), "neither a client secret nor a certificate") {
		t.Errorf("does not distinguish an empty store from a read failure: %q", err)
	}
	if !strings.Contains(err.Error(), "POST /api/azure/config") {
		t.Errorf("does not say how to fix it: %q", err)
	}
}

// No secrets store at all, with a stored application: still the workspace's
// problem to hear about, not a list of AZURE_* variables.
func TestForWorkspace_NoVaultWithAStoredAppIsNamed(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("reported ready with no secrets store")
	}
	if !strings.Contains(err.Error(), "secrets store is not configured") {
		t.Errorf("does not name the missing secrets store: %q", err)
	}
}

// With NO stored application, the environment-variable message is the right one
// and must not be replaced by a bind explanation.
func TestForWorkspace_NoStoredAppStillPointsAtTheEnvironment(t *testing.T) {
	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  newFakeVault(),
		appCfg: stubAppCfgRepo{cfg: nil},
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("reported ready with nothing configured at all")
	}
	msg := err.Error()
	if !strings.Contains(msg, "missing client id") {
		t.Errorf("an unconfigured deployment should be told what is missing: %q", msg)
	}
	if strings.Contains(msg, "stored application") {
		t.Errorf("claims a stored application that does not exist: %q", msg)
	}
}

// A readable secret binds, and reports ready.
func TestForWorkspace_ReadableSecretBinds(t *testing.T) {
	vlt := newFakeVault()
	_ = vlt.WriteSecret(testAuthRef, map[string]interface{}{"client_secret": "s3cret"})

	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  vlt,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}
	bound := svc.ForWorkspace(uuid.New())

	if err := bound.Ready(); err != nil {
		t.Fatalf("a fully stored application is not ready: %v", err)
	}
	if bound.clientID != storedApp().ClientID {
		t.Errorf("clientID = %q, want the stored one", bound.clientID)
	}
	if bound.homeTenant != testTenant {
		t.Errorf("homeTenant = %q, want the stored one", bound.homeTenant)
	}
	// The original must be untouched: ForWorkspace returns a copy, so one
	// workspace's credentials can never leak into another's request.
	if svc.clientID != "" {
		t.Errorf("ForWorkspace mutated the shared service: clientID = %q", svc.clientID)
	}
}

// An injected test client wins over any stored row, or a test would silently
// start talking to Azure.
func TestForWorkspace_InjectedClientIsNeverReplaced(t *testing.T) {
	vlt := newFakeVault()
	_ = vlt.WriteSecret(testAuthRef, map[string]interface{}{"client_secret": "s3cret"})

	fake := &chainClient{}
	svc := (&AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  vlt,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}).WithClient(fake)

	bound := svc.ForWorkspace(uuid.New())
	if bound.azure != fake {
		t.Fatal("ForWorkspace replaced an injected client")
	}
	if bound.clientID == storedApp().ClientID {
		t.Error("ForWorkspace bound the stored application over an injected client")
	}
}

// A stored CERTIFICATE binds the same way a stored secret does, and the service
// records which form it is using -- the check reports that, and it is not the
// same question as what the registration happens to hold.
func TestForWorkspace_StoredCertificateBinds(t *testing.T) {
	vlt := newFakeVault()
	_ = vlt.WriteSecret(testAuthRef, map[string]interface{}{
		"certificate_pem": string(testCertPEM(t)),
	})

	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  vlt,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}
	bound := svc.ForWorkspace(uuid.New())

	if err := bound.Ready(); err != nil {
		t.Fatalf("a stored certificate is not ready: %v", err)
	}
	if bound.credKind != azureonboard.CredentialCertificate {
		t.Fatalf("credKind = %q, want certificate", bound.credKind)
	}
}

// A certificate that no longer parses is corruption, not operator error, and
// must not be reported as "you did not submit one".
func TestForWorkspace_CorruptStoredCertificateSaysSo(t *testing.T) {
	vlt := newFakeVault()
	_ = vlt.WriteSecret(testAuthRef, map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----",
	})

	svc := &AzureOnboardService{
		repo:   newFakeRepo(),
		vault:  vlt,
		appCfg: stubAppCfgRepo{cfg: storedApp()},
	}

	err := svc.ForWorkspace(uuid.New()).Ready()
	if err == nil {
		t.Fatal("reported ready with an unparseable certificate")
	}
	if !strings.Contains(err.Error(), "can no longer be parsed") {
		t.Errorf("does not say the stored certificate is the problem: %q", err)
	}
}
