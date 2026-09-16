package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/google/uuid"
	"google.golang.org/api/googleapi"
)

/* --------------------------------- doubles -------------------------------- */

// memVault mirrors tests/integration/cloud_aws_onboarding_test.go's own
// memVault fake exactly (in-memory secrets store, records what was written /
// deleted / read) — kept as a package-local double here rather than shared,
// matching that file's own convention of one small fake per test package
// rather than a central testsupport vault double.
type memVault struct {
	mu        sync.Mutex
	data      map[string]map[string]interface{}
	writeCall int
	deleted   []string
}

func newMemVault() *memVault {
	return &memVault{data: map[string]map[string]interface{}{}}
}

func (m *memVault) WriteSecret(path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCall++
	cp := map[string]interface{}{}
	for k, v := range data {
		cp[k] = v
	}
	m.data[path] = cp
	return nil
}

func (m *memVault) ReadSecret(path string) (map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("no secret at %s", path)
	}
	return v, nil
}

func (m *memVault) DeleteSecret(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, path)
	m.deleted = append(m.deleted, path)
	return nil
}

func (m *memVault) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCall
}

// fakeIssuer is the services-package twin of internal/gcp's fakeTokenIssuer —
// stands in for internal/tokens.NativeIssuer without a real signing keyset or
// database.
type fakeIssuer struct {
	token string
	// issuerURL, if set, is what IssuerURL() returns. Zero value defaults to
	// a valid HTTPS placeholder so every existing test in this file (none of
	// which is testing issuer validation) keeps passing unchanged.
	issuerURL string
}

func (f fakeIssuer) IssueCloudOnboardingToken(_ context.Context, _, _ string) (string, error) {
	return f.token, nil
}

// IssuerURL satisfies gcp.CloudOnboardingTokenIssuer.
func (f fakeIssuer) IssuerURL() string {
	if f.issuerURL != "" {
		return f.issuerURL
	}
	return "https://app.authsec.test"
}

/* -------------------------------- json_key --------------------------------- */

// validServiceAccountKeyJSON builds a structurally valid key with a real
// (throwaway, test-only) RSA private key. Structural validation of the shape
// is internal/gcp's job and already covered there (credentials_test.go);
// this fixture only needs to satisfy it, not re-prove it.
func validServiceAccountKeyJSON(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	b, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "test-project",
		"client_email": "authsec-reader@test-project.iam.gserviceaccount.com",
		"private_key":  pemStr,
	})
	if err != nil {
		t.Fatalf("marshal key fixture: %v", err)
	}
	return b
}

// TestGCPAuthService_LegacyKeyedConnectorStillReadsAndPurges covers what is
// left of the json_key path after onboarding stopped accepting it.
//
// There is no StoreKey any more -- nothing in the service can put key material
// into Vault. What must keep working is the other half: a connector created
// before the change still resolves its credential, so an operator can verify
// it before migrating, and still purges cleanly on revoke. Dropping these
// would strand exactly the connectors we want retired, and would leave their
// key material in Vault with no code left to delete it.
func TestGCPAuthService_LegacyKeyedConnectorStillReadsAndPurges(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "unused"})

	// Seeded directly, the way a connector onboarded before the change would
	// already have it stored.
	authRef := "kv/data/secret/workspaces/" + uuid.New().String() + "/cloud-discovery/gcp/test-project"
	if err := mv.WriteSecret(authRef, map[string]interface{}{
		"key_json": string(validServiceAccountKeyJSON(t)),
	}); err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	opt, err := svc.LoadCredential(authRef)
	if err != nil {
		t.Fatalf("LoadCredential on a legacy keyed connector: %v", err)
	}
	if opt == nil {
		t.Fatal("LoadCredential returned a nil ClientOption for a stored key")
	}

	if err := svc.DeleteCredential(authRef); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if _, err := svc.LoadCredential(authRef); err == nil {
		t.Fatal("LoadCredential succeeded after DeleteCredential; the secret should be gone")
	}
}

func TestGCPAuthService_LoadCredential_NoVaultConfigured(t *testing.T) {
	svc := NewGCPAuthService(nil, fakeIssuer{token: "unused"})
	if _, err := svc.LoadCredential("kv/data/secret/workspaces/x/cloud-discovery/gcp/y"); err == nil {
		t.Fatal("expected an error when no vault client is configured")
	}
}

/* ----------------------------------- wif ------------------------------------ */

func TestGCPAuthService_BuildWIFCredential_NoVaultCalls(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "fake.jwt.token"})

	_, err := svc.BuildWIFCredential(context.Background(), uuid.New(), "scope-1",
		"projects/1/locations/global/workloadIdentityPools/p/providers/pr",
		"reader@p.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("BuildWIFCredential: %v", err)
	}
	if got := mv.callCount(); got != 0 {
		t.Fatalf("Vault.WriteSecret was called %d time(s) building a WIF credential; want 0 -- there is nothing to store for this path", got)
	}
}

func TestGCPAuthService_RevokeCredential_WIFIsNoOp(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "unused"})

	// Seed a path that would be deleted if RevokeCredential's wif branch ever
	// (incorrectly) fell through to DeleteCredential.
	authRef := "wif:projects/1/locations/global/workloadIdentityPools/p/providers/pr"
	if err := svc.RevokeCredential(GCPAuthMethodWIF, authRef); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if len(mv.deleted) != 0 {
		t.Fatalf("Vault.DeleteSecret was called for a WIF connector's revoke; want zero Vault calls, deleted=%v", mv.deleted)
	}
}

func TestGCPAuthService_RevokeCredential_JSONKeyDeletesFromVault(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "unused"})

	// Seeded directly: onboarding can no longer write a key, so the only way
	// a connector reaches this state now is by predating that change.
	authRef := "kv/data/secret/workspaces/" + uuid.New().String() + "/cloud-discovery/gcp/test-project"
	if err := mv.WriteSecret(authRef, map[string]interface{}{
		"key_json": string(validServiceAccountKeyJSON(t)),
	}); err != nil {
		t.Fatalf("seed vault: %v", err)
	}

	if err := svc.RevokeCredential(GCPAuthMethodJSONKey, authRef); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	if _, err := svc.LoadCredential(authRef); err == nil {
		t.Fatal("key still readable from Vault after RevokeCredential on a json_key connector")
	}
}

/* -------------------------- ResolveReaderIdentity error mapping -------------- */

func TestClassifyIAMError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		authMethod string
		want       error
	}{
		{"403 forbidden", &googleapi.Error{Code: http.StatusForbidden}, GCPAuthMethodJSONKey, gcp.ErrPermissionDenied},
		{"404 not found", &googleapi.Error{Code: http.StatusNotFound}, GCPAuthMethodWIF, gcp.ErrPermissionDenied},
		{"invalid_grant on wif", errors.New("oauth2: cannot fetch token: 400 Bad Request\nResponse: {\"error\":\"invalid_grant\"}"), GCPAuthMethodWIF, gcp.ErrWIFPoolMissing},
		{"invalid_grant on json_key", errors.New("oauth2: cannot fetch token: 400 Bad Request\nResponse: {\"error\":\"invalid_grant\"}"), GCPAuthMethodJSONKey, gcp.ErrInvalidGrant},
		{"unrecognized error defaults to invalid_grant", errors.New("some other transport failure"), GCPAuthMethodJSONKey, gcp.ErrInvalidGrant},
		// Regression for a real live failure (2026-09-02): a customer's
		// provider_resource passed AuthSec's own pre-flight cross-check
		// byte-for-byte (proven separately, resolveOnboardingCredential's
		// own comparison), yet onboarding still failed, because the WIF
		// provider on GCP's side trusted an issuer hostname (a Cloudflare
		// quick tunnel) that had gone offline. This EXACT error text is what
		// google.golang.org/api's IAM client surfaced for that live failure
		// — must classify as ErrWIFIssuerUnreachable, never ErrWIFPoolMissing
		// (which would incorrectly tell the customer to re-paste an
		// already-correct value).
		{
			"wif issuer unreachable (live-captured 2026-09-02)",
			errors.New(`Get "https://iam.googleapis.com/v1/projects/-/serviceAccounts/authsec-reader@codevault-8cc83.iam.gserviceaccount.com?alt=json&prettyPrint=false": credentials: status code 400: {"error":"invalid_grant","error_description":"Error connecting to the given credential's issuer."}`),
			GCPAuthMethodWIF,
			gcp.ErrWIFIssuerUnreachable,
		},
		// The same GCP error text, but for json_key: this failure mode is
		// WIF-specific (only WIF depends on AuthSec's own OIDC issuer being
		// reachable), so json_key must fall through to the ordinary
		// invalid_grant handling, completely unaffected by this check.
		{
			"same error text on json_key falls through unaffected",
			errors.New(`Get "https://iam.googleapis.com/v1/projects/-/serviceAccounts/authsec-reader@codevault-8cc83.iam.gserviceaccount.com?alt=json&prettyPrint=false": credentials: status code 400: {"error":"invalid_grant","error_description":"Error connecting to the given credential's issuer."}`),
			GCPAuthMethodJSONKey,
			gcp.ErrInvalidGrant,
		},
		// Regression for GCP-E2E-MANUAL-TEST-GUIDE.md §12 finding #1
		// (live-confirmed 2026-09-02, §5g): a pool/provider that does not
		// exist at all makes GCP's STS reject with "invalid_target", not
		// "invalid_grant" — before this fix that fell through to the
		// unrecognized-error default (ErrInvalidGrant, fault "gcp") instead
		// of ErrWIFPoolMissing (fault "customer_account"), which is what a
		// missing pool/provider actually is.
		{
			"invalid_target on wif (missing pool/provider, live-confirmed 2026-09-02)",
			errors.New(`oauth2: cannot fetch token: 400 Bad Request` + "\n" + `Response: {"error":"invalid_target","error_description":"The workload identity pool or provider is disabled, deleted, or does not exist."}`),
			GCPAuthMethodWIF,
			gcp.ErrWIFPoolMissing,
		},
		// json_key never exchanges a token against a pool/provider, so this
		// error text (however unlikely in practice) must not be given any
		// WIF-specific meaning on that path.
		{
			"invalid_target on json_key falls through unaffected",
			errors.New(`oauth2: cannot fetch token: 400 Bad Request` + "\n" + `Response: {"error":"invalid_target","error_description":"The workload identity pool or provider is disabled, deleted, or does not exist."}`),
			GCPAuthMethodJSONKey,
			gcp.ErrInvalidGrant,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyIAMError(tc.err, tc.authMethod)
			if !errors.Is(got, tc.want) {
				t.Errorf("classifyIAMError(%v, %q) = %v, want it to wrap %v", tc.err, tc.authMethod, got, tc.want)
			}
			// The raw error's own text must never leak into the classified
			// error's message -- only the static sentinel string is allowed.
			if got.Error() != tc.want.Error() {
				t.Errorf("classified error text = %q, want exactly the sentinel's own text %q (no raw provider text leaked)", got.Error(), tc.want.Error())
			}
		})
	}
}
