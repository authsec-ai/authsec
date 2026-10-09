package gcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

// fakeProvisionServer stands in for iam.googleapis.com,
// cloudresourcemanager.googleapis.com and serviceusage.googleapis.com's
// write/test endpoints this file's Ensure*/Test* functions call. Paths are
// matched by exact suffix (ignoring query strings), determined by directly
// probing the real generated clients against a logging httptest.Server, not
// guessed from documentation.
type fakeProvisionServer struct {
	srv *httptest.Server
	mu  sync.Mutex

	calls []string // "METHOD path" (query stripped), in order

	poolState     string // "", "ACTIVE" or "DELETED" -- "" means 404 (does not exist)
	providerState string

	saExists bool

	saPolicy    *iam.Policy
	scopePolicy *cloudresourcemanager.Policy

	deniedPermissions map[string]bool
	// rejectedPermissions makes the WHOLE testIamPermissions call fail with
	// 400, the way GCP does when a permission name is not applicable to the
	// resource type being tested. Distinct from deniedPermissions, which the
	// call simply omits from its answer -- the difference between "you do not
	// have this" and "that is not a question about this resource", which the
	// probe has to keep apart.
	rejectedPermissions map[string]bool
	// failBatchEnable makes Service Usage refuse, so a test can prove that the
	// core APIs failing is fatal while an individual discovery API failing is
	// not.
	failBatchEnable bool

	createPoolCalls, undeletePoolCalls          int
	createProviderCalls                         int
	createSACalls                               int
	saSetIamPolicyCalls, scopeSetIamPolicyCalls int
	enableCalls                                 int
	lastSAPolicyPosted                          *iam.Policy
	lastScopePolicyPosted                       *cloudresourcemanager.Policy
}

func newFakeProvisionServer() *fakeProvisionServer {
	f := &fakeProvisionServer{
		saPolicy:            &iam.Policy{Etag: "etag-sa-1"},
		scopePolicy:         &cloudresourcemanager.Policy{Etag: "etag-scope-1"},
		deniedPermissions:   map[string]bool{},
		rejectedPermissions: map[string]bool{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeProvisionServer) Close() { f.srv.Close() }

func (f *fakeProvisionServer) record(method, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method+" "+path)
}

// recorded returns a copy of the calls seen so far, so a test can assert
// WHICH resource a call targeted rather than only how many there were.
func (f *fakeProvisionServer) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeProvisionServer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error": map[string]interface{}{"code": 404, "message": "not found"},
	})
}

func (f *fakeProvisionServer) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	f.record(r.Method, path)
	body, _ := io.ReadAll(r.Body)

	switch {
	// --- service account ---
	case r.Method == http.MethodGet && strings.Contains(path, "/serviceAccounts/") && !strings.HasSuffix(path, ":getIamPolicy"):
		if !f.saExists {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, &iam.ServiceAccount{Email: "authsec-reader@p1.iam.gserviceaccount.com"})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/serviceAccounts"):
		f.mu.Lock()
		f.createSACalls++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, &iam.ServiceAccount{Email: "authsec-reader@p1.iam.gserviceaccount.com"})

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":getIamPolicy") && strings.Contains(path, "/serviceAccounts/"):
		writeJSON(w, http.StatusOK, f.saPolicy)

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":setIamPolicy") && strings.Contains(path, "/serviceAccounts/"):
		var req iam.SetIamPolicyRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.saSetIamPolicyCalls++
		f.lastSAPolicyPosted = req.Policy
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, req.Policy)

	// --- WIF pool ---
	case r.Method == http.MethodGet && strings.Contains(path, "/workloadIdentityPools/") && !strings.Contains(path, "/providers/") && !strings.Contains(path, "/operations/"):
		if f.poolState == "" {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, &iam.WorkloadIdentityPool{State: f.poolState})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/workloadIdentityPools"):
		f.mu.Lock()
		f.createPoolCalls++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, &iam.Operation{Done: true})

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":undelete") && strings.Contains(path, "/workloadIdentityPools/") && !strings.Contains(path, "/providers/"):
		f.mu.Lock()
		f.undeletePoolCalls++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, &iam.Operation{Done: true})

	// --- WIF provider ---
	case r.Method == http.MethodGet && strings.Contains(path, "/providers/"):
		if f.providerState == "" {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, &iam.WorkloadIdentityPoolProvider{State: f.providerState})

	case r.Method == http.MethodPost && strings.HasSuffix(path, "/providers"):
		f.mu.Lock()
		f.createProviderCalls++
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, &iam.Operation{Done: true})

	// --- resource manager: project ---
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v3/projects/") && !strings.Contains(path, ":"):
		writeJSON(w, http.StatusOK, &cloudresourcemanager.Project{Name: "projects/123456789", ProjectId: "p1"})

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":getIamPolicy"):
		writeJSON(w, http.StatusOK, f.scopePolicy)

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":setIamPolicy"):
		var req cloudresourcemanager.SetIamPolicyRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		f.scopeSetIamPolicyCalls++
		f.lastScopePolicyPosted = req.Policy
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, req.Policy)

	case r.Method == http.MethodPost && strings.HasSuffix(path, ":testIamPermissions"):
		var req cloudresourcemanager.TestIamPermissionsRequest
		_ = json.Unmarshal(body, &req)
		for _, p := range req.Permissions {
			if f.rejectedPermissions[p] {
				http.Error(w, `{"error":{"code":400,"message":"permission not applicable"}}`, http.StatusBadRequest)
				return
			}
		}
		var allowed []string
		for _, p := range req.Permissions {
			if !f.deniedPermissions[p] {
				allowed = append(allowed, p)
			}
		}
		writeJSON(w, http.StatusOK, &cloudresourcemanager.TestIamPermissionsResponse{Permissions: allowed})

	// --- service usage ---
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":batchEnable"):
		f.mu.Lock()
		f.enableCalls++
		shouldFail := f.failBatchEnable
		f.mu.Unlock()
		if shouldFail {
			http.Error(w, `{"error":{"code":403,"message":"denied"}}`, http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, &serviceusage.Operation{Done: true})

	default:
		notFound(w)
	}
}

func (f *fakeProvisionServer) iamClient(t *testing.T) *iam.Service {
	t.Helper()
	svc, err := iam.NewService(context.Background(), option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("build fake iam client: %v", err)
	}
	return svc
}

func (f *fakeProvisionServer) rmClient(t *testing.T) *cloudresourcemanager.Service {
	t.Helper()
	svc, err := cloudresourcemanager.NewService(context.Background(), option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("build fake resourcemanager client: %v", err)
	}
	return svc
}

func (f *fakeProvisionServer) suClient(t *testing.T) *serviceusage.Service {
	t.Helper()
	svc, err := serviceusage.NewService(context.Background(), option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("build fake serviceusage client: %v", err)
	}
	return svc
}

/* ------------------------------ service account ----------------------------- */

func TestEnsureReaderServiceAccount_CreatesWhenMissing(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.saExists = false

	email, err := EnsureReaderServiceAccount(context.Background(), f.iamClient(t), "p1")
	if err != nil {
		t.Fatalf("EnsureReaderServiceAccount: %v", err)
	}
	if email != "authsec-reader@p1.iam.gserviceaccount.com" {
		t.Fatalf("email = %q", email)
	}
	if f.createSACalls != 1 {
		t.Fatalf("createSACalls = %d, want 1", f.createSACalls)
	}
}

func TestEnsureReaderServiceAccount_NoOpWhenExists(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.saExists = true

	if _, err := EnsureReaderServiceAccount(context.Background(), f.iamClient(t), "p1"); err != nil {
		t.Fatalf("EnsureReaderServiceAccount: %v", err)
	}
	if f.createSACalls != 0 {
		t.Fatalf("createSACalls = %d, want 0 (idempotent no-op)", f.createSACalls)
	}
}

/* --------------------------------- WIF pool ---------------------------------- */

func TestEnsureWIFPool_IdempotentOnAlreadyExists(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.poolState = "ACTIVE"

	if err := EnsureWIFPool(context.Background(), f.iamClient(t), "p1", "pool1"); err != nil {
		t.Fatalf("EnsureWIFPool: %v", err)
	}
	if f.createPoolCalls != 0 {
		t.Fatalf("createPoolCalls = %d, want 0 (already exists, no write)", f.createPoolCalls)
	}
}

func TestEnsureWIFPool_CreatesWhenMissing(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.poolState = ""

	if err := EnsureWIFPool(context.Background(), f.iamClient(t), "p1", "pool1"); err != nil {
		t.Fatalf("EnsureWIFPool: %v", err)
	}
	if f.createPoolCalls != 1 {
		t.Fatalf("createPoolCalls = %d, want 1", f.createPoolCalls)
	}
}

func TestEnsureWIFPool_UndeletesSoftDeletedInsteadOfCreating(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.poolState = "DELETED"

	if err := EnsureWIFPool(context.Background(), f.iamClient(t), "p1", "pool1"); err != nil {
		t.Fatalf("EnsureWIFPool: %v", err)
	}
	if f.undeletePoolCalls != 1 {
		t.Fatalf("undeletePoolCalls = %d, want 1", f.undeletePoolCalls)
	}
	if f.createPoolCalls != 0 {
		t.Fatalf("createPoolCalls = %d, want 0 -- a soft-deleted pool must be undeleted, never (re)created", f.createPoolCalls)
	}
}

/* ------------------------------- WIF provider --------------------------------- */

func TestEnsureWIFProvider_IdempotentOnAlreadyExists(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.providerState = "ACTIVE"

	if err := EnsureWIFProvider(context.Background(), f.iamClient(t), "p1", "pool1", "prov1", "https://issuer.example"); err != nil {
		t.Fatalf("EnsureWIFProvider: %v", err)
	}
	if f.createProviderCalls != 0 {
		t.Fatalf("createProviderCalls = %d, want 0", f.createProviderCalls)
	}
}

func TestEnsureWIFProvider_CreatesWhenMissing(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.providerState = ""

	if err := EnsureWIFProvider(context.Background(), f.iamClient(t), "p1", "pool1", "prov1", "https://issuer.example"); err != nil {
		t.Fatalf("EnsureWIFProvider: %v", err)
	}
	if f.createProviderCalls != 1 {
		t.Fatalf("createProviderCalls = %d, want 1", f.createProviderCalls)
	}
}

/* --------------------------- workload identity binding ------------------------- */

func TestEnsureWorkloadIdentityBinding_AdditiveMerge(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	unrelated := &iam.Binding{Role: "roles/owner", Members: []string{"user:someone@example.com"}}
	f.saPolicy = &iam.Policy{Etag: "etag-1", Bindings: []*iam.Binding{unrelated}}

	err := EnsureWorkloadIdentityBinding(context.Background(), f.iamClient(t), "p1", "authsec-reader@p1.iam.gserviceaccount.com", "123456789", "pool1", "authsec:subject1")
	if err != nil {
		t.Fatalf("EnsureWorkloadIdentityBinding: %v", err)
	}
	if f.saSetIamPolicyCalls != 1 {
		t.Fatalf("saSetIamPolicyCalls = %d, want 1", f.saSetIamPolicyCalls)
	}
	posted := f.lastSAPolicyPosted
	if posted.Etag != "etag-1" {
		t.Fatalf("posted policy etag = %q, want the etag read from GetIamPolicy (optimistic concurrency)", posted.Etag)
	}
	foundUnrelated, foundNew := false, false
	for _, b := range posted.Bindings {
		if b.Role == "roles/owner" && len(b.Members) == 1 && b.Members[0] == "user:someone@example.com" {
			foundUnrelated = true
		}
		if b.Role == WorkloadIdentityUserRole {
			for _, m := range b.Members {
				if strings.Contains(m, "authsec:subject1") {
					foundNew = true
				}
			}
		}
	}
	if !foundUnrelated {
		t.Fatalf("the pre-existing unrelated binding was lost -- policy write must be additive, got bindings=%+v", posted.Bindings)
	}
	if !foundNew {
		t.Fatalf("the new workloadIdentityUser binding was not added, got bindings=%+v", posted.Bindings)
	}
}

func TestEnsureWorkloadIdentityBinding_NoOpWhenAlreadyBound(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	member := "principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool1/subject/authsec:subject1"
	f.saPolicy = &iam.Policy{Etag: "etag-1", Bindings: []*iam.Binding{
		{Role: WorkloadIdentityUserRole, Members: []string{member}},
	}}

	if err := EnsureWorkloadIdentityBinding(context.Background(), f.iamClient(t), "p1", "authsec-reader@p1.iam.gserviceaccount.com", "123456789", "pool1", "authsec:subject1"); err != nil {
		t.Fatalf("EnsureWorkloadIdentityBinding: %v", err)
	}
	if f.saSetIamPolicyCalls != 0 {
		t.Fatalf("saSetIamPolicyCalls = %d, want 0 -- binding already present, no write should happen", f.saSetIamPolicyCalls)
	}
}

/* -------------------------------- reader roles --------------------------------- */

func TestEnsureReaderRoles_OneMergedWriteForAllRoles(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.scopePolicy = &cloudresourcemanager.Policy{Etag: "etag-scope-1"}

	roles := []string{"roles/iam.serviceAccountViewer", "roles/iam.roleViewer", "roles/cloudasset.viewer", "roles/browser"}
	if err := EnsureReaderRoles(context.Background(), f.rmClient(t), "project", "p1", "authsec-reader@p1.iam.gserviceaccount.com", roles); err != nil {
		t.Fatalf("EnsureReaderRoles: %v", err)
	}
	if f.scopeSetIamPolicyCalls != 1 {
		t.Fatalf("scopeSetIamPolicyCalls = %d, want exactly 1 (one merged write for every role)", f.scopeSetIamPolicyCalls)
	}
	if len(f.lastScopePolicyPosted.Bindings) != len(roles) {
		t.Fatalf("posted %d bindings, want %d (one per role)", len(f.lastScopePolicyPosted.Bindings), len(roles))
	}
}

func TestEnsureReaderRoles_NoOpWhenAllRolesAlreadyGranted(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	member := "serviceAccount:authsec-reader@p1.iam.gserviceaccount.com"
	f.scopePolicy = &cloudresourcemanager.Policy{
		Etag: "etag-scope-1",
		Bindings: []*cloudresourcemanager.Binding{
			{Role: "roles/browser", Members: []string{member}},
		},
	}
	if err := EnsureReaderRoles(context.Background(), f.rmClient(t), "project", "p1", "authsec-reader@p1.iam.gserviceaccount.com", []string{"roles/browser"}); err != nil {
		t.Fatalf("EnsureReaderRoles: %v", err)
	}
	if f.scopeSetIamPolicyCalls != 0 {
		t.Fatalf("scopeSetIamPolicyCalls = %d, want 0 -- role already granted, no write should happen", f.scopeSetIamPolicyCalls)
	}
}

/* -------------------------------- preflight -------------------------------- */

func TestTestReaderProjectPermissions_ReturnsMissing(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.deniedPermissions["iam.serviceAccounts.setIamPolicy"] = true

	missing, err := TestReaderProjectPermissions(context.Background(), f.rmClient(t), "p1")
	if err != nil {
		t.Fatalf("TestReaderProjectPermissions: %v", err)
	}
	if len(missing) != 1 || missing[0] != "iam.serviceAccounts.setIamPolicy" {
		t.Fatalf("missing = %v, want exactly [iam.serviceAccounts.setIamPolicy]", missing)
	}
}

func TestTestScopePermission_SelectsCorrectAPIByScopeKind(t *testing.T) {
	cases := []struct {
		scopeKind string
		scopeID   string
		wantPath  string
	}{
		{"project", "p1", "/v3/projects/p1:testIamPermissions"},
		{"folder", "f1", "/v3/folders/f1:testIamPermissions"},
		{"org", "o1", "/v3/organizations/o1:testIamPermissions"},
	}
	for _, tc := range cases {
		t.Run(tc.scopeKind, func(t *testing.T) {
			f := newFakeProvisionServer()
			defer f.Close()
			if _, err := TestScopePermission(context.Background(), f.rmClient(t), tc.scopeKind, tc.scopeID); err != nil {
				t.Fatalf("TestScopePermission: %v", err)
			}
			found := false
			for _, c := range f.calls {
				if strings.HasSuffix(c, tc.wantPath) {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a call ending in %q, got calls=%v", tc.wantPath, f.calls)
			}
		})
	}
}

/* -------------------------------- misc ------------------------------------ */

// TestEnableServices_CoreIsOneBatchAndDiscoveryIsOneAtATime pins the split
// that a live WIF setup failure forced.
//
// A single BatchEnable naming all twenty-one APIs is all-or-nothing, so one
// unavailable API (agentregistry is Beta) takes the other twenty down with it.
// In the setup script, running under `set -e`, that aborted before the pool
// and provider were created, and surfaced much later as a failed credential
// exchange pointing at a pool that had never existed. Core goes in one batch
// because nothing works without it; everything else goes one at a time so it
// can fail alone.
func TestEnableServices_CoreIsOneBatchAndDiscoveryIsOneAtATime(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	if err := EnableServices(context.Background(), f.suClient(t), "p1"); err != nil {
		t.Fatalf("EnableServices: %v", err)
	}
	want := 1 + len(DiscoveryServices)
	if f.enableCalls != want {
		t.Fatalf("enableCalls = %d, want %d (1 core batch + %d individual)",
			f.enableCalls, want, len(DiscoveryServices))
	}
}

// TestEnableServices_CoreFitsInOneBatch guards the assumption above: core is
// sent unchunked, so it must stay under BatchEnable's documented ceiling.
func TestEnableServices_CoreFitsInOneBatch(t *testing.T) {
	if len(CoreServices) > batchEnableMaxServices {
		t.Fatalf("CoreServices has %d entries, over the %d-per-call ceiling; it is sent as one batch",
			len(CoreServices), batchEnableMaxServices)
	}
}

// TestEnableServices_CoreFailureIsFatal: without these, the service account,
// the federation resources and every later read are impossible, so continuing
// would only build a connector guaranteed not to work.
func TestEnableServices_CoreFailureIsFatal(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.failBatchEnable = true

	if err := EnableServices(context.Background(), f.suClient(t), "p1"); err == nil {
		t.Fatal("expected an error when the core APIs cannot be enabled")
	}
}

// TestCoreAndDiscoveryPartitionRequiredServices stops a service being added to
// one list and quietly dropped from the other, which would leave it enabled
// but never reported, or reported but never enabled.
func TestCoreAndDiscoveryPartitionRequiredServices(t *testing.T) {
	if len(RequiredServices) != len(CoreServices)+len(DiscoveryServices) {
		t.Fatalf("RequiredServices has %d entries, want %d core + %d discovery",
			len(RequiredServices), len(CoreServices), len(DiscoveryServices))
	}
	seen := map[string]bool{}
	for _, s := range RequiredServices {
		if seen[s] {
			t.Errorf("%s appears in both lists", s)
		}
		seen[s] = true
	}
}

// TestRequiredServices_CoversEveryAPIDiscoveryReads is the E3.1 guard. The
// list is the contract with discovery; a surface whose API is missing here
// fails at scan time with "not enabled", which is a support ticket rather
// than a sentence in the setup output.
func TestRequiredServices_CoversEveryAPIDiscoveryReads(t *testing.T) {
	want := []string{
		"cloudresourcemanager.googleapis.com", "iam.googleapis.com",
		"iamcredentials.googleapis.com", "sts.googleapis.com",
		"cloudasset.googleapis.com", "serviceusage.googleapis.com",
		"logging.googleapis.com", "policyanalyzer.googleapis.com",
		"recommender.googleapis.com", "run.googleapis.com",
		"cloudfunctions.googleapis.com", "compute.googleapis.com",
		"container.googleapis.com", "aiplatform.googleapis.com",
		"agentregistry.googleapis.com", "secretmanager.googleapis.com",
		"bigquery.googleapis.com", "storage.googleapis.com",
		"pubsub.googleapis.com", "cloudkms.googleapis.com",
		"sqladmin.googleapis.com",
	}
	have := map[string]bool{}
	for _, s := range RequiredServices {
		have[s] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("RequiredServices is missing %s", w)
		}
	}
}

// TestReadAPIEnablement_UnreadableIsUnknownNotDisabled is the coverage-honesty
// rule applied to enablement. A reader that cannot list services has learned
// nothing; recording that as "not_enabled" would be indistinguishable from the
// truth while being invented.
func TestReadAPIEnablement_UnreadableIsUnknownNotDisabled(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	// The fake has no services.list handler, so the listing fails.
	state := ReadAPIEnablement(context.Background(), f.suClient(t), "p1")

	if len(state) != len(RequiredServices) {
		t.Fatalf("state has %d entries, want one per required service (%d)", len(state), len(RequiredServices))
	}
	for svc, v := range state {
		if v != APIStateUnknown {
			t.Errorf("%s = %q, want %q when enablement could not be read", svc, v, APIStateUnknown)
		}
	}
}

func TestProjectNumber_ParsesFromProjectsGet(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	num, err := ProjectNumber(context.Background(), f.rmClient(t), "p1")
	if err != nil {
		t.Fatalf("ProjectNumber: %v", err)
	}
	if num != "123456789" {
		t.Fatalf("ProjectNumber = %q, want 123456789", num)
	}
}
