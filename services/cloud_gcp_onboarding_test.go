package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GCP onboarding, exercised against a real Postgres with migrations 010-013
// applied — mirroring tests/integration/cloud_aws_onboarding_test.go's own
// approach (everything except the GCP call itself is real: the repository,
// the upsert, the constraints, the error paths). The GCP boundary is faked
// through newIAMClientFunc/newResourceManagerClientFunc (cloud_gcp_onboarding.go's
// own test seam), the reason that seam exists — a regression here must be
// catchable without a GCP project.
//
// Requires TEST_DATABASE_URL, and skips without it, matching
// tests/ownership's convention:
//
//	TEST_DATABASE_URL="postgres://postgres:test@localhost:55432/authtest?sslmode=disable" \
//	    go test ./services/... -run Gcp

/* --------------------------------- doubles -------------------------------- */

// memVault mirrors gcp_auth_service_test.go's own memVault fake exactly —
// kept as a second, package-local copy for the same reason that file's own
// comment gives (one small fake per file, matching this repo's convention),
// but with a call-count method used here to assert zero Vault interaction
// across a WIF connector's full lifecycle.
type gcpTestVault struct {
	mu      sync.Mutex
	data    map[string]map[string]interface{}
	writes  int
	reads   int
	deletes int
}

func newGCPTestVault() *gcpTestVault {
	return &gcpTestVault{data: map[string]map[string]interface{}{}}
}

func (m *gcpTestVault) WriteSecret(path string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	cp := map[string]interface{}{}
	for k, v := range data {
		cp[k] = v
	}
	m.data[path] = cp
	return nil
}

func (m *gcpTestVault) ReadSecret(path string) (map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	v, ok := m.data[path]
	if !ok {
		return nil, fmt.Errorf("no secret at %s", path)
	}
	return v, nil
}

func (m *gcpTestVault) DeleteSecret(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	delete(m.data, path)
	return nil
}

func (m *gcpTestVault) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writes + m.reads + m.deletes
}

// fakeGCPServer stands in for iam.googleapis.com and
// cloudresourcemanager.googleapis.com. Configurable per test: denyPaths
// makes any request whose path contains one of these substrings fail with
// 403, everything else succeeds with a canned response shaped for whichever
// surface the path names.
type fakeGCPServer struct {
	srv           *httptest.Server
	saEmail       string
	orgID         string
	folderID      string
	folderParent  string // "organizations/<orgID>"
	projectID     string
	projectParent string // "folders/<folderID>" or "organizations/<orgID>"
	denySubstr    string // if non-empty, any path containing this returns 403
	calls         []string
	mu            sync.Mutex
}

func newFakeGCPServer() *fakeGCPServer {
	f := &fakeGCPServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeGCPServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.Path)
	f.mu.Unlock()

	if f.denySubstr != "" && strings.Contains(r.URL.Path, f.denySubstr) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"code": 403, "message": "denied"},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.Contains(r.URL.Path, "serviceAccounts/"):
		_ = json.NewEncoder(w).Encode(iam.ServiceAccount{Email: f.saEmail, UniqueId: "111"})
	case strings.Contains(r.URL.Path, "/organizations/"):
		_ = json.NewEncoder(w).Encode(cloudresourcemanager.Organization{Name: "organizations/" + f.orgID})
	case strings.Contains(r.URL.Path, "/folders/"):
		_ = json.NewEncoder(w).Encode(cloudresourcemanager.Folder{Name: "folders/" + f.folderID, Parent: f.folderParent})
	case strings.Contains(r.URL.Path, "/projects/"):
		_ = json.NewEncoder(w).Encode(cloudresourcemanager.Project{Name: "projects/" + f.projectID, ProjectId: f.projectID, Parent: f.projectParent})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeGCPServer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeGCPServer) Close() { f.srv.Close() }

// installFakeGCPServer points newIAMClientFunc/newResourceManagerClientFunc
// at f for the duration of the test, restoring the real factories after —
// these are package vars precisely so a test in this package can do this
// (see cloud_gcp_onboarding.go's own doc comment on them). The real authOpt
// built upstream (from either auth path) is deliberately IGNORED here: since
// f.srv requires no authentication, the WIF/json_key credential object is
// never actually used to acquire a token, so this test never makes a real
// call to sts.googleapis.com or oauth2.googleapis.com regardless of which
// auth method produced it.
func installFakeGCPServer(t *testing.T, f *fakeGCPServer) {
	t.Helper()
	origIAM, origRM := newIAMClientFunc, newResourceManagerClientFunc
	newIAMClientFunc = func(ctx context.Context, _ option.ClientOption) (*iam.Service, error) {
		return iam.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	}
	newResourceManagerClientFunc = func(ctx context.Context, _ option.ClientOption) (*cloudresourcemanager.Service, error) {
		return cloudresourcemanager.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	}
	t.Cleanup(func() {
		newIAMClientFunc, newResourceManagerClientFunc = origIAM, origRM
	})
}

// fakeGCPOnboardIssuer stands in for internal/tokens.NativeIssuer.
type fakeGCPOnboardIssuer struct {
	// issuerURL, if set, is what IssuerURL() returns. Zero value defaults to
	// a valid HTTPS placeholder so every existing WIF test in this file
	// (none of which is testing issuer validation) keeps passing unchanged.
	issuerURL string
}

func (fakeGCPOnboardIssuer) IssueCloudOnboardingToken(_ context.Context, _, _ string) (string, error) {
	return "fake.jwt.token", nil
}

// IssuerURL satisfies gcp.CloudOnboardingTokenIssuer.
func (f fakeGCPOnboardIssuer) IssuerURL() string {
	if f.issuerURL != "" {
		return f.issuerURL
	}
	return "https://app.authsec.test"
}

/* ---------------------------------- DB ------------------------------------ */

func setupGCPOnboardingTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping GCP onboarding integration tests")
	}
	// Hard stop before the DROP SCHEMA below. See requireThrowawayDatabase.
	requireThrowawayDatabase(t, dsn)

	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()

	for _, stmt := range []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%q): %v", stmt, err)
		}
	}

	// Only the cloud_* migrations are needed: cloud_connector carries no FK to
	// any bootstrap table (workspace_id is a bare uuid column, not a foreign
	// key -- confirmed directly against migrations/master/010_...sql), so
	// applying 001_bootstrap.sql first would only cost time, not correctness.
	for _, name := range []string{
		"010_cloud_discovery_connector.sql",
		"011_cloud_identity_and_secret.sql",
		"012_cloud_assume_edge.sql",
		"013_cloud_permission_and_resource.sql",
	} {
		p, err := filepath.Abs(filepath.Join("..", "migrations", "master", name))
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm open: %v", err)
	}
	return db
}

/* -------------------------------- fixtures --------------------------------- */

const testSAEmail = "authsec-reader@reader-proj.iam.gserviceaccount.com"

func jsonKeyInput(scopeKind, scopeID string) GCPOnboardInput {
	key := fmt.Sprintf(`{"type":"service_account","project_id":"reader-proj","client_email":%q,"private_key":%q}`,
		testSAEmail, testRSAPrivateKeyPEM)
	return GCPOnboardInput{
		ScopeKind:       scopeKind,
		ScopeID:         scopeID,
		ReaderProjectID: "reader-proj",
		DisplayName:     "test connector",
		Auth: GCPAuthInput{
			Method:  GCPAuthMethodJSONKey,
			KeyJSON: []byte(key),
		},
	}
}

func wifInput(workspaceID uuid.UUID, scopeKind, scopeID string) GCPOnboardInput {
	poolID, providerID, _ := gcp.DeriveWIFParams(workspaceID, scopeID)
	providerResource := fmt.Sprintf("projects/123456789012/locations/global/workloadIdentityPools/%s/providers/%s", poolID, providerID)
	return GCPOnboardInput{
		ScopeKind:       scopeKind,
		ScopeID:         scopeID,
		ReaderProjectID: "reader-proj",
		DisplayName:     "test connector",
		Auth: GCPAuthInput{
			Method:           GCPAuthMethodWIF,
			ProviderResource: providerResource,
			ReaderSAEmail:    testSAEmail,
		},
	}
}

/* ---------------------------------- tests ---------------------------------- */

func TestGcpOnboardLifecycle_JSONKey(t *testing.T) {
	db := setupGCPOnboardingTestDB(t)
	mv := newGCPTestVault()
	svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{})

	fake := newFakeGCPServer()
	defer fake.Close()
	fake.saEmail = testSAEmail
	fake.projectID = "my-scope"
	fake.projectParent = "organizations/999"
	installFakeGCPServer(t, fake)

	ws := uuid.New()
	in := jsonKeyInput(models.CloudScopeProject, "my-scope")

	// --- create ---
	c, created, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if !created {
		t.Fatal("first onboard must report created")
	}
	if c.Status != models.CloudConnectorActive || c.VerifiedAt == nil {
		t.Fatalf("expected active+verified, got status=%s verified=%v", c.Status, c.VerifiedAt)
	}
	if c.ParentScopeID == nil || *c.ParentScopeID != "999" {
		t.Fatalf("parent_scope_id = %v, want \"999\" (bare id from organizations/999)", c.ParentScopeID)
	}
	if !strings.HasPrefix(c.AuthRef, "kv/data/secret/workspaces/") {
		t.Fatalf("json_key auth_ref should be a Vault path, got %q", c.AuthRef)
	}
	if mv.writes != 1 {
		t.Fatalf("expected exactly one Vault write, got %d", mv.writes)
	}

	// --- key value never appears anywhere on the row ---
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), testRSAPrivateKeyPEM) {
		t.Fatal("the private key value must never appear in the connector row's JSON encoding")
	}
	if strings.Contains(string(c.Attrs), "private_key") || strings.Contains(string(c.Attrs), testRSAPrivateKeyPEM) {
		t.Fatal("the private key value must never appear in attrs")
	}

	// --- verify ---
	verified, err := svc.VerifyConnector(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Status != models.CloudConnectorActive {
		t.Fatalf("expected active after verify, got %s", verified.Status)
	}

	// --- read ---
	got, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != c.ID {
		t.Fatalf("wrong connector returned")
	}
	list, err := svc.Connectors(ws)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected exactly one connector, got %d", len(list))
	}

	// --- revoke ---
	if err := svc.RevokeConnector(ws, c.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if mv.deletes != 1 {
		t.Fatalf("expected exactly one Vault delete on revoke, got %d", mv.deletes)
	}
	revoked, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("get after revoke: %v", err)
	}
	if revoked.Status != models.CloudConnectorRevoked {
		t.Fatalf("status after revoke = %q, want %q", revoked.Status, models.CloudConnectorRevoked)
	}
	// The row is KEPT, per plan section 9 -- this is the deliberate AWS
	// divergence (AWS hard-deletes on DELETE).
	if _, err := svc.Connector(ws, c.ID); err != nil {
		t.Fatalf("revoked connector should still be readable (row kept for audit): %v", err)
	}

	// --- verify-on-revoked must refuse, not flip the row to 'error' ---
	// Regression for GCP-E2E-MANUAL-TEST-GUIDE.md §12 finding #3
	// (live-confirmed 2026-09-02): before this guard, VerifyConnector ran
	// the normal probe against a connector whose Vault secret was already
	// purged by revoke, failed, and MarkError overwrote status='revoked'
	// with status='error' -- silently losing the fact that this connector
	// was deliberately disconnected.
	afterVerify, verr := svc.VerifyConnector(context.Background(), ws, c.ID)
	if !errors.Is(verr, ErrConnectorRevoked) {
		t.Fatalf("verify on a revoked connector: err = %v, want ErrConnectorRevoked", verr)
	}
	if afterVerify == nil || afterVerify.Status != models.CloudConnectorRevoked {
		t.Fatalf("verify on a revoked connector must not change its status; got %+v", afterVerify)
	}
	stillRevoked, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("get after verify-on-revoked: %v", err)
	}
	if stillRevoked.Status != models.CloudConnectorRevoked {
		t.Fatalf("status after verify-on-revoked = %q, want it to stay %q", stillRevoked.Status, models.CloudConnectorRevoked)
	}
}

func TestGcpOnboardLifecycle_WIF_NeverTouchesVault(t *testing.T) {
	db := setupGCPOnboardingTestDB(t)
	mv := newGCPTestVault()
	svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{})

	fake := newFakeGCPServer()
	defer fake.Close()
	fake.saEmail = testSAEmail
	fake.folderID = "my-folder"
	fake.folderParent = "organizations/999"
	installFakeGCPServer(t, fake)

	ws := uuid.New()
	in := wifInput(ws, models.CloudScopeFolder, "my-folder")

	c, created, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if !created {
		t.Fatal("first onboard must report created")
	}
	if !strings.HasPrefix(c.AuthRef, "wif:") {
		t.Fatalf("wif auth_ref should start with \"wif:\", got %q", c.AuthRef)
	}
	if c.ParentScopeID == nil || *c.ParentScopeID != "999" {
		t.Fatalf("parent_scope_id = %v, want \"999\"", c.ParentScopeID)
	}

	if _, err := svc.VerifyConnector(context.Background(), ws, c.ID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := svc.RevokeConnector(ws, c.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, err := svc.Connector(ws, c.ID)
	if err != nil {
		t.Fatalf("get after revoke: %v", err)
	}
	if revoked.Status != models.CloudConnectorRevoked {
		t.Fatalf("status after revoke = %q, want revoked", revoked.Status)
	}

	// The whole point of this test: create + verify + revoke, and Vault was
	// NEVER called, not once.
	if got := mv.callCount(); got != 0 {
		t.Fatalf("Vault was called %d time(s) across a WIF connector's full lifecycle; want 0", got)
	}
}

func TestGcpOnboard_WIFMismatchedProviderResource_RejectedBeforeAnyNetworkCall(t *testing.T) {
	db := setupGCPOnboardingTestDB(t)
	mv := newGCPTestVault()
	svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{})

	fake := newFakeGCPServer()
	defer fake.Close()
	fake.saEmail = testSAEmail
	fake.projectID = "my-scope"
	installFakeGCPServer(t, fake)

	ws := uuid.New()
	in := wifInput(ws, models.CloudScopeProject, "my-scope")
	// Corrupt the pasted provider_resource so its pool_id segment cannot match
	// what DeriveWIFParams(ws, "my-scope") derives.
	in.Auth.ProviderResource = "projects/123456789012/locations/global/workloadIdentityPools/wrong-pool/providers/authsec-provider"

	_, _, err := svc.Onboard(context.Background(), ws, in, "admin")
	if !errors.Is(err, gcp.ErrWIFPoolMissing) {
		t.Fatalf("err = %v, want it to wrap gcp.ErrWIFPoolMissing", err)
	}
	if got := fake.callCount(); got != 0 {
		t.Fatalf("fake GCP server was called %d time(s); want 0 -- the cross-check must reject this before any network call", got)
	}
	if got := mv.callCount(); got != 0 {
		t.Fatalf("Vault was called %d time(s); want 0", got)
	}

	rows, err := svc.Connectors(ws)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("a rejected onboard must leave no row, got %d", len(rows))
	}
}

// TestGcpOnboard_NonHTTPSIssuer_RejectsWIFButJSONKeyStillWorks is the
// service-layer proof that WIF and JSON-key are genuinely separate auth
// methods, not two branches of one opaque flow: a deployment whose WIF
// issuer is broken (http://localhost:7001, exactly this local dev
// backend's own configuration) must reject a WIF onboard fast, with no
// network call — and must NOT affect JSON-key onboarding against the same
// service instance at all.
func TestGcpOnboard_NonHTTPSIssuer_RejectsWIFButJSONKeyStillWorks(t *testing.T) {
	db := setupGCPOnboardingTestDB(t)
	mv := newGCPTestVault()
	svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{issuerURL: "http://localhost:7001"})

	fake := newFakeGCPServer()
	defer fake.Close()
	fake.saEmail = testSAEmail
	fake.projectID = "my-scope"
	installFakeGCPServer(t, fake)

	ws := uuid.New()

	// WIF: must fail fast, before any call to GCP.
	wifIn := wifInput(ws, models.CloudScopeProject, "my-scope")
	_, _, err := svc.Onboard(context.Background(), ws, wifIn, "admin")
	if !errors.Is(err, gcp.ErrWIFIssuerNotHTTPS) {
		t.Fatalf("wif onboard: err = %v, want it to wrap gcp.ErrWIFIssuerNotHTTPS", err)
	}
	if got := fake.callCount(); got != 0 {
		t.Fatalf("fake GCP server was called %d time(s) for the WIF attempt; want 0", got)
	}
	if rows, _ := svc.Connectors(ws); len(rows) != 0 {
		t.Fatalf("a rejected WIF onboard must leave no row, got %d", len(rows))
	}

	// JSON key, same workspace, same service instance, same (broken-for-WIF)
	// issuer: must succeed exactly as if WIF had never been attempted.
	jsonIn := jsonKeyInput(models.CloudScopeProject, "my-scope")
	c, created, err := svc.Onboard(context.Background(), ws, jsonIn, "admin")
	if err != nil {
		t.Fatalf("json_key onboard on a WIF-broken deployment must still succeed: %v", err)
	}
	if !created {
		t.Fatal("first json_key onboard must report created")
	}
	if c.AuthRef == "" || strings.HasPrefix(c.AuthRef, "wif:") {
		t.Fatalf("json_key connector should have a Vault auth_ref, got %q", c.AuthRef)
	}
}

func TestGcpOnboard_ScopeValidationFailure_LeavesNoRow(t *testing.T) {
	for _, method := range []string{GCPAuthMethodJSONKey, GCPAuthMethodWIF} {
		t.Run(method, func(t *testing.T) {
			db := setupGCPOnboardingTestDB(t)
			mv := newGCPTestVault()
			svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{})

			fake := newFakeGCPServer()
			defer fake.Close()
			fake.saEmail = testSAEmail
			fake.projectID = "denied-scope"
			fake.denySubstr = "/projects/denied-scope"
			installFakeGCPServer(t, fake)

			ws := uuid.New()
			var in GCPOnboardInput
			if method == GCPAuthMethodJSONKey {
				in = jsonKeyInput(models.CloudScopeProject, "denied-scope")
			} else {
				in = wifInput(ws, models.CloudScopeProject, "denied-scope")
			}

			_, _, err := svc.Onboard(context.Background(), ws, in, "admin")
			if !errors.Is(err, ErrScopeNotReadable) {
				t.Fatalf("err = %v, want it to wrap ErrScopeNotReadable", err)
			}

			rows, err := svc.Connectors(ws)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(rows) != 0 {
				t.Fatalf("a scope-validation failure must leave no row, got %d", len(rows))
			}
			if method == GCPAuthMethodJSONKey && mv.writes != 0 {
				t.Fatalf("json_key: Vault write count = %d, want 0 -- validation must happen before any write", mv.writes)
			}
		})
	}
}

func TestGcpOnboard_RepeatCreate_UpdatesInPlace_NeverTouchesScanGenerationOrCoverage(t *testing.T) {
	db := setupGCPOnboardingTestDB(t)
	mv := newGCPTestVault()
	svc := NewGCPOnboardingService(db, mv, fakeGCPOnboardIssuer{})

	fake := newFakeGCPServer()
	defer fake.Close()
	fake.saEmail = testSAEmail
	fake.projectID = "repeat-scope"
	installFakeGCPServer(t, fake)

	ws := uuid.New()
	in := jsonKeyInput(models.CloudScopeProject, "repeat-scope")

	first, created, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil || !created {
		t.Fatalf("first onboard: created=%v err=%v", created, err)
	}

	// Simulate a prior scan having advanced generation/coverage, exactly like
	// AWS's own re-onboard test does.
	if err := db.Model(&models.CloudConnector{}).Where("id = ?", first.ID).
		Updates(map[string]interface{}{
			"scan_generation": 7,
			"coverage":        json.RawMessage(`{"iam_roles":{"state":"reached","count":3}}`),
		}).Error; err != nil {
		t.Fatalf("simulate prior scan state: %v", err)
	}

	second, created, err := svc.Onboard(context.Background(), ws, in, "admin")
	if err != nil {
		t.Fatalf("second onboard: %v", err)
	}
	if created {
		t.Fatal("re-onboarding the same scope must report created=false")
	}
	if second.ID != first.ID {
		t.Fatalf("re-onboard must update the SAME row, got a different id (%s vs %s)", second.ID, first.ID)
	}

	rows, err := svc.Connectors(ws)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one connector after re-onboard, got %d", len(rows))
	}
	if rows[0].ScanGeneration != 7 {
		t.Fatalf("scan_generation = %d, want unchanged 7 -- re-onboard must never touch it", rows[0].ScanGeneration)
	}
	if !strings.Contains(string(rows[0].Coverage), "iam_roles") {
		t.Fatalf("coverage was reset by re-onboard; want unchanged, got %s", rows[0].Coverage)
	}
}

// testRSAPrivateKeyPEM is a throwaway, test-only PEM value. It does not need
// to be a cryptographically valid key: internal/gcp.ResolveJSONKeyCredential's
// real PEM/PKCS8 validation is already covered in internal/gcp's own test
// tier, and this file's fake IAM/ResourceManager server never actually
// authenticates with it (see installFakeGCPServer's doc comment) -- but
// gcp.ResolveJSONKeyCredential DOES still run its real structural + PEM
// checks on the way in, so this has to parse as a real PKCS8 RSA key.
const testRSAPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCxAjcEPxKXVGzH
XBnQ9xrZ/YvNlCIsBO7HS6ThAwa6drhwCZLnU6LaPvXUmv2tmMaGIaBX+4AbURwY
HBLbfCmwJyEmUUBJ6En0DCzhBRwrXFOCSZd0UNYOCC8KL8+nzdEBWHSQJJvHLduS
YrCJWCc2cCuJ/+UnXq2A+9vYl9l5nm0zpf9aXeTFbVd/Z51z3BBJ9y7Gsp2mBk2v
NM9rckPQn1n42Jw97fx4PuCAq400sU8aqyroEe5cmf9DCg1MX2l08ffT2REMLaHn
UCH2F8YkSn2YxI8N1lJRBlzIutAXxilUM8EVDuTjulAuPDMcIktkIUcZua34YWTM
W7GeWrS1AgMBAAECggEAKc+soDen1BAwq7zBKl+cO57M/a/+jGhT4Mao+S+mULhH
Y8uXJEZYwvW5StGbl3xtdHSP9Ahn38v+d2F2QNso27+6cFsj9PFGOrv/g92ZpFJo
NW/dsy9/CIx9VAosImaW9prm2b+T/m4CHidqrN6iUJUZa70C65RNJpkXeqePys6x
K5m3ysMf+52yXoihT2vCf2PQpwxV8X9oRLI39aVxavG0j79/UQgF2cw/FBCb+pVf
m+of7L+AHVfyHlv2AxYekuq6gG267SSoRsx3hkA8IP1oQsMKRKxsNOtL2tit9eNM
X3zRBM9vO4u22KisZfx2/E/k1aFr8Y4+rzNNZ6bv1wKBgQDfnzMYNGfYjnpcBzpn
7ZhkIt30SAT6n672eh4dfRebcoC/ECgoF3g6oSgfWIkvmKPIXE9ZJ9IJbd66+SNk
n8bSSC/4AaLNmk/QQ3TIz5oyeG2C8zko/aHJ50dclkHQmvVU5jN+usgcYKrtUMkU
j1TIwOXLFFWul+PuGvebt1PBCwKBgQDKoz4zlRL7uSyuDmXqs8f2BU70z3pY//w1
oJ7Kmz25qsp/iGbps9p6Mmd7SpX5giI1+w/X0ndchZ8rzxiva6UjsEVi9zne87JR
4F6lakNLXj8a6EyVKC47+UUk0vimWBdY5OHD1bFBbiqkDkQx4QkxS8/VuansOj7N
HaiST4B5PwKBgC3q0aIJuL0V3HgjH9IRTnZZVnv/gc44lcOUpbRmaD+KDnetCKHa
19wqFUQCeQDl9dOBaOWksJMxFUgNOkBCMqAhJIBnTZesNPFNuKA3SLFOWyZFbRpG
oj8EF3oifFcqSm/paO9/yPFSxCZArVlkaQNj4IuHnGRiWfIdZXR6+16rAoGANfE6
z7Rxdz0WHceLbe0p394N5LGOmj6avxPg8YJd7hz/BvAipTfRgxID5hg20FLKFKCe
2Q8X4zNW6eyZX6lCLrvv3KZ/a1BoOc+GonYlL90I43rPWC14EVMMCv92XaG5pVpY
ly89nnNbOozprnV/YvYRf42LJG1k5mlsxHYRdzUCgYAtCdOXOXPSGoQuKsHXZTUI
KBovz2ahtEB8EWqRDEYGeCpfAGH0cD4iTgljlr+ucRJ/F+pRpgCaw2Wmh4rzN9EH
u0k36Zck1UXzsm/ZiTiVMYzAo3r8ruJEBWlQTmwFjI9JUk6331Fcg9n5vCPYPsf7
phURV/5siSVQnI6k1NXjHg==
-----END PRIVATE KEY-----`
