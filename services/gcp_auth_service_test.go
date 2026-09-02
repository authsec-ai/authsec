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
type fakeIssuer struct{ token string }

func (f fakeIssuer) IssueCloudOnboardingToken(_ context.Context, _, _ string) (string, error) {
	return f.token, nil
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

func TestGCPAuthService_StoreKey_RoundTripsThroughVault(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "unused"})

	ws := uuid.New()
	keyJSON := validServiceAccountKeyJSON(t)

	authRef, err := svc.StoreKey(ws, "test-project", keyJSON)
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}
	wantPath := gcpKeyPath(ws, "test-project")
	if authRef != wantPath {
		t.Errorf("authRef = %q, want %q", authRef, wantPath)
	}

	opt, err := svc.LoadCredential(authRef)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if opt == nil {
		t.Fatal("LoadCredential returned a nil ClientOption for a round-tripped key")
	}

	if err := svc.DeleteCredential(authRef); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if _, err := svc.LoadCredential(authRef); err == nil {
		t.Fatal("LoadCredential succeeded after DeleteCredential; the secret should be gone")
	}
}

func TestGCPAuthService_StoreKey_MalformedRejectedBeforeVaultWrite(t *testing.T) {
	mv := newMemVault()
	svc := NewGCPAuthService(mv, fakeIssuer{token: "unused"})

	_, err := svc.StoreKey(uuid.New(), "test-project", []byte(`{"type":"service_account"}`))
	if !errors.Is(err, gcp.ErrKeyInvalid) {
		t.Fatalf("err = %v, want it to wrap gcp.ErrKeyInvalid", err)
	}
	if got := mv.callCount(); got != 0 {
		t.Fatalf("Vault.WriteSecret was called %d time(s) for a malformed key; want 0", got)
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

	ws := uuid.New()
	authRef, err := svc.StoreKey(ws, "test-project", validServiceAccountKeyJSON(t))
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
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
