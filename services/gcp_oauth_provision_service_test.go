package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	serviceusage "google.golang.org/api/serviceusage/v1"
	"gorm.io/gorm"
)

// This file tests services.GCPOAuthProvisionService -- the Google
// Authentication onboarding option. Redis state is faked with
// alicebob/miniredis (already a direct dependency in go.mod, used elsewhere
// in this codebase's own test harness — internal/testsupport/fakes.go — so
// this introduces no new dependency). GCP itself is faked the same way
// services/cloud_gcp_onboarding_test.go already fakes it: real generated
// clients (iam.Service/cloudresourcemanager.Service/serviceusage.Service)
// pointed at an httptest.Server via option.WithEndpoint, swapped in through
// the newIAMClientFunc/newResourceManagerClientFunc/newServiceUsageClientFunc
// package-var seams. Tests that need a real cloud_connector row (the
// equivalence/idempotency tests) require TEST_DATABASE_URL and skip without
// it, matching that same file's convention exactly.

/* ------------------------------- redis fake -------------------------------- */

func newTestRedis(t *testing.T) *redis.Client {
	rc, _ := newTestRedisWithHandle(t)
	return rc
}

// newTestRedisWithHandle also returns the underlying *miniredis.Miniredis so
// a test can deterministically expire keys via FastForward (miniredis ties
// TTL to a virtual clock it only advances on FastForward/SetTime, not real
// wall-clock sleeps -- confirmed against its own doc comment).
func newTestRedisWithHandle(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()}), mr
}

/* --------------------------- fake google token endpoint --------------------- */

// installFakeGoogleTokenEndpoint points ExchangeGoogleCode's HTTP call at a
// local server that always succeeds, returning a distinguishable access
// token per test so a test can assert on its exact value later (e.g. that it
// never turns up in a connector row).
func installFakeGoogleTokenEndpoint(t *testing.T, accessToken, idToken string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)
	// ExchangeGoogleCode always talks to the real Google endpoint in
	// production; gcp.SetGoogleOAuthTokenURLForTesting is the exported,
	// tests-only seam that redirects it to srv instead, so HandleCallback's
	// Redis/session logic can be exercised end-to-end without a real Google
	// token endpoint. ExchangeGoogleCode's own behavior (scopes, error
	// handling) is already covered directly in internal/gcp/oauth_google_test.go.
	origURL := gcp.SetGoogleOAuthTokenURLForTesting(srv.URL)
	t.Cleanup(func() { gcp.SetGoogleOAuthTokenURLForTesting(origURL) })
}

/* -------------------------- fake GCP read+write server ---------------------- */

// fakeGCPProvisionServer combines the read endpoints Onboard/ResolveReaderIdentity
// need (serviceAccounts.get, organizations/folders/projects.get) with the
// write/test endpoints EnsureReaderServiceAccount/EnsureWIFPool/
// EnsureWIFProvider/EnsureWorkloadIdentityBinding/EnsureReaderRoles/
// TestReaderProjectPermissions/TestScopePermission/EnableServices need --
// internal/gcp/provision_test.go already exercises each of those in
// isolation; this fake supports a full Start->HandleCallback->Provision
// round trip through THIS package's own orchestration.
type fakeGCPProvisionServer struct {
	srv *httptest.Server
	mu  sync.Mutex

	saEmail        string
	deniedPermSet  map[string]bool
	scopePolicy    *cloudresourcemanager.Policy
	saPolicy       *iam.Policy
	poolExists     bool
	providerExists bool
	saExists       bool

	calls []string
}

func newFakeGCPProvisionServer(saEmail string) *fakeGCPProvisionServer {
	f := &fakeGCPProvisionServer{
		saEmail:       saEmail,
		deniedPermSet: map[string]bool{},
		scopePolicy:   &cloudresourcemanager.Policy{Etag: "e1"},
		saPolicy:      &iam.Policy{Etag: "e2"},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeGCPProvisionServer) Close() { f.srv.Close() }

func (f *fakeGCPProvisionServer) recordAndCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, path)
	return len(f.calls)
}

func (f *fakeGCPProvisionServer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeGCPProvisionServer) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	f.recordAndCount(path)
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")

	notFound := func() {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]interface{}{"code": 404}})
	}
	ok := func(v interface{}) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(v)
	}

	switch {
	case r.Method == http.MethodGet && strings.Contains(path, "/serviceAccounts/") && !strings.Contains(path, ":"):
		if !f.saExists {
			notFound()
			return
		}
		ok(&iam.ServiceAccount{Email: f.saEmail})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/serviceAccounts"):
		f.mu.Lock()
		f.saExists = true
		f.mu.Unlock()
		ok(&iam.ServiceAccount{Email: f.saEmail})
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":getIamPolicy") && strings.Contains(path, "/serviceAccounts/"):
		ok(f.saPolicy)
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":setIamPolicy") && strings.Contains(path, "/serviceAccounts/"):
		var req iam.SetIamPolicyRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.saPolicy = req.Policy
		f.mu.Unlock()
		ok(req.Policy)
	case r.Method == http.MethodGet && strings.Contains(path, "/workloadIdentityPools/") && !strings.Contains(path, "/providers/"):
		if !f.poolExists {
			notFound()
			return
		}
		ok(&iam.WorkloadIdentityPool{State: "ACTIVE"})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/workloadIdentityPools"):
		f.mu.Lock()
		f.poolExists = true
		f.mu.Unlock()
		ok(&iam.Operation{Done: true})
	case r.Method == http.MethodGet && strings.Contains(path, "/providers/"):
		if !f.providerExists {
			notFound()
			return
		}
		ok(&iam.WorkloadIdentityPoolProvider{State: "ACTIVE"})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/providers"):
		f.mu.Lock()
		f.providerExists = true
		f.mu.Unlock()
		ok(&iam.Operation{Done: true})
	case r.Method == http.MethodGet && strings.Contains(path, "/organizations/"):
		ok(&cloudresourcemanager.Organization{Name: path[1:]})
	case r.Method == http.MethodGet && strings.Contains(path, "/folders/"):
		ok(&cloudresourcemanager.Folder{Name: strings.TrimPrefix(path, "/v3/")})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v3/projects/") && !strings.Contains(path, ":"):
		ok(&cloudresourcemanager.Project{Name: "projects/123456789", ProjectId: "reader-proj"})
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":getIamPolicy"):
		ok(f.scopePolicy)
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":setIamPolicy"):
		var req cloudresourcemanager.SetIamPolicyRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.scopePolicy = req.Policy
		f.mu.Unlock()
		ok(req.Policy)
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":testIamPermissions"):
		var req cloudresourcemanager.TestIamPermissionsRequest
		_ = json.Unmarshal(body, &req)
		var allowed []string
		for _, p := range req.Permissions {
			if !f.deniedPermSet[p] {
				allowed = append(allowed, p)
			}
		}
		ok(&cloudresourcemanager.TestIamPermissionsResponse{Permissions: allowed})
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":batchEnable"):
		ok(&serviceusage.Operation{Done: true})
	default:
		notFound()
	}
}

// installFakeGCPProvisionServer swaps newIAMClientFunc/newResourceManagerClientFunc
// (this package's own existing test seam, cloud_gcp_onboarding.go) and
// newServiceUsageClientFunc (this feature's own seam,
// gcp_oauth_provision_service.go) to point at f, restoring all three after.
func installFakeGCPProvisionServer(t *testing.T, f *fakeGCPProvisionServer) {
	t.Helper()
	origIAM, origRM, origSU := newIAMClientFunc, newResourceManagerClientFunc, newServiceUsageClientFunc
	newIAMClientFunc = func(ctx context.Context, _ option.ClientOption) (*iam.Service, error) {
		return iam.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	}
	newResourceManagerClientFunc = func(ctx context.Context, _ option.ClientOption) (*cloudresourcemanager.Service, error) {
		return cloudresourcemanager.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	}
	newServiceUsageClientFunc = func(ctx context.Context, _ option.ClientOption) (*serviceusage.Service, error) {
		return serviceusage.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	}
	t.Cleanup(func() {
		newIAMClientFunc, newResourceManagerClientFunc, newServiceUsageClientFunc = origIAM, origRM, origSU
	})
}

/* ---------------------------------- helpers --------------------------------- */

// newTestGCPOAuthService builds the service for tests that never reach
// stampProvenance/Onboard (db may be nil for those -- state/session/
// workspace/preflight logic never touches it). Tests that DO reach a
// successful Provision must pass the real *gorm.DB from
// setupGCPOnboardingTestDB, or stampProvenance's direct DB write panics on a
// nil *gorm.DB -- exactly as it would in production if
// CloudGCPOAuthController.service() were ever wired without one, which it
// never is (it always passes ctl.db).
func newTestGCPOAuthService(t *testing.T, db *gorm.DB, redisClient *redis.Client, onboardSvc *GCPOnboardingService) *GCPOAuthProvisionService {
	t.Helper()
	return NewGCPOAuthProvisionService(db, redisClient, onboardSvc, "test-client-id", "test-client-secret", "https://api.authsec.test/authsec/discovery/gcp/google-oauth/callback", "https://app.authsec.test")
}

// testScope is the (scope_kind, scope_id, reader_project_id) triple most
// tests below use — the human's post-sign-in project pick.
var testScope = GoogleScope{ScopeKind: "project", ScopeID: "s1", ReaderProjectID: "p1"}

// startAndCallback drives Start + a fake Google redirect + HandleCallback,
// returning the resulting opaque session id. Takes no scope -- Start itself
// no longer accepts one (the human hasn't picked a project yet at this
// point in the flow); callers pass a GoogleScope directly to
// Preflight/Provision instead.
func startAndCallback(t *testing.T, svc *GCPOAuthProvisionService, workspaceID uuid.UUID, actor, accessToken, idToken string) string {
	t.Helper()
	installFakeGoogleTokenEndpoint(t, accessToken, idToken)

	_, state, err := svc.Start(context.Background(), workspaceID, actor)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sessionID, err := svc.HandleCallback(context.Background(), "fake-auth-code", state)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	return sessionID
}

/* ------------------------------------ tests ---------------------------------- */

func TestStart_WritesStateWithTTL(t *testing.T) {
	rc := newTestRedis(t)
	svc := newTestGCPOAuthService(t, nil, rc, nil)
	_, state, err := svc.Start(context.Background(), uuid.New(), "actor")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ttl, err := rc.TTL(context.Background(), gcpOAuthStateKey(state)).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > googleOAuthStateTTL {
		t.Fatalf("state TTL = %v, want (0, %v]", ttl, googleOAuthStateTTL)
	}
}

func TestHandleCallback_UnknownState_Rejected(t *testing.T) {
	svc := newTestGCPOAuthService(t, nil, newTestRedis(t), nil)
	_, err := svc.HandleCallback(context.Background(), "code", "state-that-was-never-issued")
	if err == nil || !strings.Contains(err.Error(), "could not be verified") {
		t.Fatalf("HandleCallback with unknown state = %v, want ErrGoogleOAuthStateInvalid", err)
	}
}

func TestHandleCallback_OneShot_SecondCallFails(t *testing.T) {
	rc := newTestRedis(t)
	svc := newTestGCPOAuthService(t, nil, rc, nil)
	workspaceID := uuid.New()

	installFakeGoogleTokenEndpoint(t, "tok-1", "")
	_, state, err := svc.Start(context.Background(), workspaceID, "actor")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if _, err := svc.HandleCallback(context.Background(), "code", state); err != nil {
		t.Fatalf("first HandleCallback: %v", err)
	}
	if _, err := svc.HandleCallback(context.Background(), "code", state); err == nil {
		t.Fatal("second HandleCallback with the same state must fail -- state must be one-shot")
	}
}

func TestHandleCallback_ExpiredState_Rejected(t *testing.T) {
	rc, mr := newTestRedisWithHandle(t)
	svc := newTestGCPOAuthService(t, nil, rc, nil)
	installFakeGoogleTokenEndpoint(t, "tok-1", "")

	_, state, err := svc.Start(context.Background(), uuid.New(), "actor")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Deterministically expire the state's 10-minute TTL by advancing
	// miniredis's own virtual clock, rather than sleeping for real minutes.
	mr.FastForward(googleOAuthStateTTL + time.Minute)

	if _, err := svc.HandleCallback(context.Background(), "code", state); err == nil {
		t.Fatal("expected the expired state to be rejected")
	}
}

func TestPreflight_RejectsInvalidScope(t *testing.T) {
	rc := newTestRedis(t)
	svc := newTestGCPOAuthService(t, nil, rc, nil)
	workspaceID := uuid.New()
	sessionID := startAndCallback(t, svc, workspaceID, "actor", "tok-1", "")

	_, err := svc.Preflight(context.Background(), sessionID, workspaceID, GoogleScope{ScopeKind: "bogus", ScopeID: "s1", ReaderProjectID: "p1"})
	if err == nil {
		t.Fatal("expected an error for an unsupported scope_kind")
	}
}

func TestLoadSession_WorkspaceMismatch_DoesNotConsumeSession(t *testing.T) {
	rc := newTestRedis(t)
	svc := newTestGCPOAuthService(t, nil, rc, nil)
	ownerWorkspace := uuid.New()
	attackerWorkspace := uuid.New()

	sessionID := startAndCallback(t, svc, ownerWorkspace, "actor", "tok-1", "")

	if _, err := svc.ListProjects(context.Background(), sessionID, attackerWorkspace); err == nil || !strings.Contains(err.Error(), "does not belong to your workspace") {
		t.Fatalf("ListProjects from a different workspace = %v, want ErrGoogleOAuthWorkspaceMismatch", err)
	}
	// The legitimate owner must still be able to use the session afterward --
	// a cross-tenant probe must never be able to burn someone else's session.
	if exists, _ := rc.Exists(context.Background(), gcpOAuthSessionKey(sessionID)).Result(); exists != 1 {
		t.Fatal("session was deleted after a workspace-mismatch check -- it must be preserved for the legitimate workspace")
	}
}

func TestProvision_WorkspaceMismatch_ZeroGCPCalls(t *testing.T) {
	rc := newTestRedis(t)
	f := newFakeGCPProvisionServer("authsec-reader@p1.iam.gserviceaccount.com")
	defer f.Close()
	installFakeGCPProvisionServer(t, f)

	svc := newTestGCPOAuthService(t, nil, rc, nil)
	ownerWorkspace := uuid.New()
	attackerWorkspace := uuid.New()
	sessionID := startAndCallback(t, svc, ownerWorkspace, "actor", "tok-1", "")

	_, _, err := svc.Provision(context.Background(), sessionID, attackerWorkspace, testScope, "", nil, "attacker-actor")
	if err == nil || !strings.Contains(err.Error(), "does not belong to your workspace") {
		t.Fatalf("Provision from a different workspace = %v, want ErrGoogleOAuthWorkspaceMismatch", err)
	}
	if f.callCount() != 0 {
		t.Fatalf("GCP call count = %d, want 0 -- a workspace mismatch must be caught before any GCP call", f.callCount())
	}
}

func TestProvision_MissingPermissions_ZeroGCPWritesAndSessionPreserved(t *testing.T) {
	rc := newTestRedis(t)
	f := newFakeGCPProvisionServer("authsec-reader@p1.iam.gserviceaccount.com")
	defer f.Close()
	f.deniedPermSet["iam.serviceAccounts.create"] = true
	installFakeGCPProvisionServer(t, f)

	svc := newTestGCPOAuthService(t, nil, rc, nil)
	workspaceID := uuid.New()
	sessionID := startAndCallback(t, svc, workspaceID, "actor", "tok-1", "")

	_, _, err := svc.Provision(context.Background(), sessionID, workspaceID, testScope, "", nil, "actor")
	if err == nil || !strings.Contains(err.Error(), "does not have the permissions") {
		t.Fatalf("Provision with a missing permission = %v, want ErrGoogleOAuthPermissionsMissing", err)
	}

	// The only calls that should have happened are the two testIamPermissions
	// probes -- never EnsureReaderServiceAccount/EnsureWIFPool/etc.
	for _, c := range f.calls {
		if strings.Contains(c, "serviceAccounts") && !strings.HasSuffix(c, "s1") {
			t.Fatalf("a service-account write call happened despite missing permissions: %v", f.calls)
		}
	}
	if exists, _ := rc.Exists(context.Background(), gcpOAuthSessionKey(sessionID)).Result(); exists != 1 {
		t.Fatal("session was consumed despite a failed preflight -- it must be preserved so a retry can still use it")
	}
}

/* --------------------- full flow: DB-gated integration tests ------------------- */

func TestProvision_FullFlow_EquivalentToManualWIF_Idempotent_TokenNotPersisted(t *testing.T) {
	db := setupGCPOnboardingTestDB(t) // skips without TEST_DATABASE_URL

	f := newFakeGCPProvisionServer("authsec-reader@reader-proj.iam.gserviceaccount.com")
	defer f.Close()
	installFakeGCPProvisionServer(t, f)

	onboardSvc := NewGCPOnboardingService(db, nil, fakeGCPOnboardIssuer{})
	oauthSvc := newTestGCPOAuthService(t, db, newTestRedis(t), onboardSvc)

	workspaceID := uuid.New()
	const secretAccessToken = "super-secret-access-token-value"
	scope := GoogleScope{ScopeKind: "project", ScopeID: "oauth-scope-1", ReaderProjectID: "reader-proj"}

	sessionID := startAndCallback(t, oauthSvc, workspaceID, "human@example.com", secretAccessToken, "")

	connector, created, err := oauthSvc.Provision(context.Background(), sessionID, workspaceID, scope, "My GCP (OAuth)", nil, "human@example.com")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !created {
		t.Fatal("expected the first Provision call to create a new connector")
	}
	if connector.Provider != models.CloudProviderGCP {
		t.Fatalf("Provider = %q", connector.Provider)
	}

	attrs := connector.GCPAttrs()
	if attrs.AuthMethod != GCPAuthMethodWIF {
		t.Fatalf("AuthMethod = %q, want %q -- a connector provisioned via Google Authentication must still be an ordinary WIF connector", attrs.AuthMethod, GCPAuthMethodWIF)
	}
	if attrs.ProvisionedVia != "google_oauth" {
		t.Fatalf("ProvisionedVia = %q, want google_oauth", attrs.ProvisionedVia)
	}
	if attrs.ProvisionedBy != "human@example.com" {
		t.Fatalf("ProvisionedBy = %q, want the AuthSec actor, not a Google identity detail", attrs.ProvisionedBy)
	}

	// --- token non-persistence ---
	if strings.Contains(string(connector.Attrs), secretAccessToken) {
		t.Fatal("the OAuth access token leaked into the persisted connector Attrs")
	}
	if exists, _ := oauthSvc.redis.Exists(context.Background(), gcpOAuthSessionKey(sessionID)).Result(); exists != 0 {
		t.Fatal("the OAuth session was not consumed from Redis after a successful Provision")
	}

	// --- equivalence with a manually-onboarded WIF connector ---
	manualScopeID := "manual-scope-1"
	poolID, providerID, _ := gcp.DeriveWIFParams(workspaceID, manualScopeID)
	providerResource := "projects/123456789/locations/global/workloadIdentityPools/" + poolID + "/providers/" + providerID
	manualConnector, _, err := onboardSvc.Onboard(context.Background(), workspaceID, GCPOnboardInput{
		ScopeKind:       "project",
		ScopeID:         manualScopeID,
		ReaderProjectID: "reader-proj",
		Auth: GCPAuthInput{
			Method:           GCPAuthMethodWIF,
			ProviderResource: providerResource,
			ReaderSAEmail:    "authsec-reader@reader-proj.iam.gserviceaccount.com",
		},
	}, "human@example.com")
	if err != nil {
		t.Fatalf("manual Onboard: %v", err)
	}
	manualAttrs := manualConnector.GCPAttrs()

	if attrs.AuthMethod != manualAttrs.AuthMethod {
		t.Fatalf("AuthMethod differs: oauth=%q manual=%q", attrs.AuthMethod, manualAttrs.AuthMethod)
	}
	if attrs.ReaderSAEmail != manualAttrs.ReaderSAEmail {
		t.Fatalf("ReaderSAEmail differs: oauth=%q manual=%q", attrs.ReaderSAEmail, manualAttrs.ReaderSAEmail)
	}
	if attrs.ReaderProjectID != manualAttrs.ReaderProjectID {
		t.Fatalf("ReaderProjectID differs: oauth=%q manual=%q", attrs.ReaderProjectID, manualAttrs.ReaderProjectID)
	}
	if attrs.RoleSetStatus != manualAttrs.RoleSetStatus {
		t.Fatalf("RoleSetStatus differs: oauth=%q manual=%q", attrs.RoleSetStatus, manualAttrs.RoleSetStatus)
	}
	if !strings.HasPrefix(connector.AuthRef, "wif:") || !strings.HasPrefix(manualConnector.AuthRef, "wif:") {
		t.Fatalf("AuthRef shape differs from the manual WIF convention: oauth=%q manual=%q", connector.AuthRef, manualConnector.AuthRef)
	}

	// --- idempotency: re-provisioning the SAME scope updates, not duplicates ---
	sessionID2 := startAndCallback(t, oauthSvc, workspaceID, "human@example.com", "second-access-token", "")
	_, created2, err := oauthSvc.Provision(context.Background(), sessionID2, workspaceID, scope, "My GCP (OAuth)", nil, "human@example.com")
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	if created2 {
		t.Fatal("re-provisioning the same (workspace, scope) must update the existing connector, not create a second one")
	}
}
