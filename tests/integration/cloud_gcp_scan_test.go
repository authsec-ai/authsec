package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"gorm.io/gorm"
)

// GCP service-account discovery, against a real database.
//
// The GCP boundary is a fake IAM/Resource Manager server: it paginates, it can
// be told to deny, throttle or refuse-by-policy a specific project, and it
// serves the field shapes the real APIs do. Everything else -- the governor,
// the retry, the upserts, the coverage aggregation and above all the
// reconciliation gate -- is the shipped code.
//
// The tests that matter most here are the ones asserting that NOTHING is
// deleted. Reconciliation is a hard DELETE of a customer's discovered estate,
// and every state except a genuinely complete scan must leave it alone.

/* ------------------------------ the fake GCP ------------------------------- */

type fakeGCPAccount struct {
	uniqueID string
	email    string
	disabled bool
	keys     []fakeGCPKey
}

type fakeGCPKey struct {
	id        string
	disabled  bool
	validFrom string
	// validBefore is GCP's validBeforeTime. "9999-12-31T23:59:59Z" is the
	// provider's never-expires sentinel, observed live.
	validBefore string
	// managed is keyType: "USER_MANAGED" or "SYSTEM_MANAGED".
	managed string
	// origin is keyOrigin: "GOOGLE_PROVIDED" or "USER_PROVIDED". A separate
	// field from keyType, confirmed against the live API.
	origin string
}

type fakeGCPDiscovery struct {
	srv *httptest.Server

	// projects the Resource Manager search returns, by project id -> number.
	projects []struct{ id, number string }
	// accounts by project id.
	accounts map[string][]fakeGCPAccount

	// failProject maps a project id to the HTTP status its serviceAccounts.list
	// should return.
	failProject map[string]int
	// policyRefusedProject returns an org-policy refusal for that project.
	policyRefusedProject string
	// enumStatus, when non-zero, fails the project search itself.
	enumStatus int
	// pageProjects returns one project per page, exercising pagination.
	pageProjects bool

	mu    sync.Mutex
	calls []string
}

func newFakeGCPDiscovery() *fakeGCPDiscovery {
	f := &fakeGCPDiscovery{
		accounts:    map[string][]fakeGCPAccount{},
		failProject: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeGCPDiscovery) Close() { f.srv.Close() }

func (f *fakeGCPDiscovery) callCount(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func (f *fakeGCPDiscovery) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch {
	// Resource Manager project search.
	case strings.Contains(r.URL.Path, "/projects:search"):
		if f.enumStatus != 0 {
			writeGCPError(w, f.enumStatus, "enumeration refused")
			return
		}
		// One project per page when pageProjects is set, so the manual
		// pagination -- and its per-page limiter token and per-page retry --
		// is actually exercised rather than assumed.
		resp := cloudresourcemanager.SearchProjectsResponse{}
		start := 0
		if tok := r.URL.Query().Get("pageToken"); tok != "" {
			fmt.Sscanf(tok, "p%d", &start)
		}
		end := len(f.projects)
		if f.pageProjects && start < end {
			end = start + 1
		}
		for _, p := range f.projects[start:end] {
			resp.Projects = append(resp.Projects, &cloudresourcemanager.Project{
				Name: "projects/" + p.number, ProjectId: p.id, State: "ACTIVE",
			})
		}
		if end < len(f.projects) {
			resp.NextPageToken = fmt.Sprintf("p%d", end)
		}
		_ = json.NewEncoder(w).Encode(resp)

	// Keys must be matched before the serviceAccounts list, since the key path
	// contains the account path.
	case strings.Contains(r.URL.Path, "/keys"):
		email := gcpEmailFromKeysPath(r.URL.Path)
		resp := iam.ListServiceAccountKeysResponse{}
		wantUserManaged := r.URL.Query()["keyTypes"]
		for _, accs := range f.accounts {
			for _, a := range accs {
				if a.email != email {
					continue
				}
				for _, k := range a.keys {
					if len(wantUserManaged) > 0 && k.managed != "USER_MANAGED" {
						continue
					}
					resp.Keys = append(resp.Keys, &iam.ServiceAccountKey{
						Name:            fmt.Sprintf("projects/-/serviceAccounts/%s/keys/%s", a.email, k.id),
						KeyType:         k.managed,
						KeyOrigin:       k.origin,
						KeyAlgorithm:    "KEY_ALG_RSA_2048",
						Disabled:        k.disabled,
						ValidAfterTime:  k.validFrom,
						ValidBeforeTime: k.validBefore,
						// Present on the wire, never read by the collector.
						PrivateKeyData: "SHOULD-NEVER-BE-PERSISTED",
					})
				}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)

	case strings.Contains(r.URL.Path, "/serviceAccounts"):
		project := gcpProjectFromSAPath(r.URL.Path)
		if project == f.policyRefusedProject {
			writeGCPError(w, http.StatusForbidden,
				"Request is prohibited by organization's policy: vpcServiceControlsUniqueIdentifier")
			return
		}
		if code, ok := f.failProject[project]; ok {
			writeGCPError(w, code, "denied")
			return
		}
		resp := iam.ListServiceAccountsResponse{}
		for _, a := range f.accounts[project] {
			resp.Accounts = append(resp.Accounts, &iam.ServiceAccount{
				Name:        fmt.Sprintf("projects/%s/serviceAccounts/%s", project, a.email),
				ProjectId:   project,
				UniqueId:    a.uniqueID,
				Email:       a.email,
				DisplayName: a.email,
				Disabled:    a.disabled,
			})
		}
		_ = json.NewEncoder(w).Encode(resp)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeGCPError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{"code": code, "message": msg},
	})
}

// gcpProjectFromSAPath pulls "p1" out of "/v1/projects/p1/serviceAccounts".
func gcpProjectFromSAPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "projects" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// gcpEmailFromKeysPath pulls the email out of ".../serviceAccounts/<email>/keys".
func gcpEmailFromKeysPath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == "serviceAccounts" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

/* -------------------------------- fixtures ---------------------------------- */

func gcpScanner(t *testing.T, db *gorm.DB, f *fakeGCPDiscovery) *services.GCPScanner {
	t.Helper()
	// The auth service is constructed with no Vault and no issuer: the fake
	// server needs no authentication, so no credential is ever exchanged. The
	// connector fixture uses the wif auth method, whose BuildWIFCredential would
	// need an issuer -- so the scanner is handed client factories that ignore
	// the credential entirely, exactly as the onboarding tests do.
	scanner := services.NewGCPScanner(db, services.NewGCPAuthService(nil, nil))
	// The fake server needs no authentication, so the credential is inert. It
	// is still resolved through a seam rather than skipped, so the scan runs
	// its real ordering: credential first, then clients.
	scanner.WithCredentialFactory(
		func(context.Context, uuid.UUID, *models.CloudConnector, models.GCPConnectorAttrs) (option.ClientOption, error) {
			return option.WithoutAuthentication(), nil
		},
	)
	return scanner.WithClientFactories(
		func(ctx context.Context, _ option.ClientOption) (*iam.Service, error) {
			return iam.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
		},
		func(ctx context.Context, _ option.ClientOption) (*cloudresourcemanager.Service, error) {
			return cloudresourcemanager.NewService(ctx, option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
		},
	)
}

// gcpScanConnector seeds a project-scoped GCP connector that is ready to scan.
func gcpScanConnector(t *testing.T, db *gorm.DB, ws uuid.UUID, projectID string) uuid.UUID {
	t.Helper()
	connector := &models.CloudConnector{
		WorkspaceID: ws,
		Provider:    models.CloudProviderGCP,
		ScopeKind:   models.CloudScopeProject,
		ScopeID:     projectID,
		AuthRef:     "wif:projects/1/locations/global/workloadIdentityPools/p/providers/authsec-provider",
		Status:      models.CloudConnectorActive,
		Coverage:    json.RawMessage(`{}`),
	}
	if err := connector.SetGCPAttrs(models.GCPConnectorAttrs{
		AuthMethod:         "wif",
		ReaderSAEmail:      "authsec-reader@" + projectID + ".iam.gserviceaccount.com",
		DiscoveryReadiness: models.GCPReadinessReady,
	}); err != nil {
		t.Fatalf("set attrs: %v", err)
	}
	stored, _, err := repositories.NewCloudConnectorRepository(db).Upsert(connector)
	if err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM cloud_connector WHERE id = ?`, stored.ID) })
	return stored.ID
}

// gcpOrgScanConnector seeds an ORG-scoped connector, which must enumerate its
// projects before it can read anything.
func gcpOrgScanConnector(t *testing.T, db *gorm.DB, ws uuid.UUID, orgID string) uuid.UUID {
	t.Helper()
	connector := &models.CloudConnector{
		WorkspaceID: ws,
		Provider:    models.CloudProviderGCP,
		ScopeKind:   models.CloudScopeOrg,
		ScopeID:     orgID,
		AuthRef:     "wif:projects/1/locations/global/workloadIdentityPools/p/providers/authsec-provider",
		Status:      models.CloudConnectorActive,
		Coverage:    json.RawMessage(`{}`),
	}
	if err := connector.SetGCPAttrs(models.GCPConnectorAttrs{
		AuthMethod:         "wif",
		ReaderSAEmail:      "authsec-reader@host.iam.gserviceaccount.com",
		DiscoveryReadiness: models.GCPReadinessReady,
	}); err != nil {
		t.Fatalf("set attrs: %v", err)
	}
	stored, _, err := repositories.NewCloudConnectorRepository(db).Upsert(connector)
	if err != nil {
		t.Fatalf("seed org connector: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM cloud_connector WHERE id = ?`, stored.ID) })
	return stored.ID
}

func countIdentities(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Count(&n).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	return n
}

func countSecrets(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&models.CloudSecret{}).
		Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Count(&n).Error; err != nil {
		t.Fatalf("count secrets: %v", err)
	}
	return n
}

func account(uniqueID, email string, keys ...fakeGCPKey) fakeGCPAccount {
	return fakeGCPAccount{uniqueID: uniqueID, email: email, keys: keys}
}

/* --------------------------------- the scan --------------------------------- */

func TestGCPScan_RecordsServiceAccountsAndUserManagedKeys(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-happy")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-alpha"] = []fakeGCPAccount{
		account("100000000000000000001", "svc-one@proj-alpha.iam.gserviceaccount.com",
			fakeGCPKey{id: "key-a", managed: "USER_MANAGED", validFrom: "2026-01-02T03:04:05Z"},
			// A google-managed key must never become a row: it is rotated by
			// Google, never leaves it, and cannot be leaked by the customer.
			fakeGCPKey{id: "key-google", managed: "SYSTEM_MANAGED"},
		),
		account("100000000000000000002", "svc-two@proj-alpha.iam.gserviceaccount.com"),
	}

	connectorID := gcpScanConnector(t, db, ws, "proj-alpha")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q, want complete: %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}
	if !snapshot.Coverage.Complete() {
		t.Fatal("a scan that reached every surface it attempted must be Complete()")
	}
	if got := countIdentities(t, db, ws, connectorID); got != 2 {
		t.Fatalf("identities = %d, want 2", got)
	}
	if got := countSecrets(t, db, ws, connectorID); got != 1 {
		t.Fatalf("secrets = %d, want 1 (only the user-managed key)", got)
	}

	// Coverage describes what this scan attempted -- two surfaces -- and not
	// the thirteen the onboarding capability skeleton lists. Inheriting those
	// would hold Complete() false forever and silently disable reconciliation.
	if len(snapshot.Coverage.Surfaces) != 2 {
		t.Fatalf("coverage lists %d surfaces, want exactly the 2 this phase reads: %+v",
			len(snapshot.Coverage.Surfaces), snapshot.Coverage.Surfaces)
	}

	var secret models.CloudSecret
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).
		First(&secret).Error; err != nil {
		t.Fatalf("load secret: %v", err)
	}
	if secret.NativeID != "key-a" {
		t.Fatalf("secret native_id = %q, want the key id", secret.NativeID)
	}
	if secret.ProviderCreatedAt == nil {
		t.Fatal("validAfterTime should have become the provider creation time")
	}
	if secret.LastUsedAt != nil {
		t.Fatal("last_used_at must stay NULL: nil means UNKNOWN, and nothing here measured usage")
	}
	// The structural promise, checked rather than assumed.
	if strings.Contains(string(secret.Attrs), "SHOULD-NEVER-BE-PERSISTED") {
		t.Fatal("private key material reached the database")
	}
	t.Logf("PASS: %d identities, %d user-managed key, coverage complete", 2, 1)
}

// The recognition key. Two accounts at the same email with different unique ids
// -- a delete and recreate -- are two identities, not one silently merged row
// that would give the new account the old one's history.
func TestGCPScan_KeysOnUniqueIDNotEmail(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-recognition-key")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const email = "recycled@proj-beta.iam.gserviceaccount.com"
	f.accounts["proj-beta"] = []fakeGCPAccount{
		account("100000000000000000010", email),
		account("100000000000000000011", email),
	}

	connectorID := gcpScanConnector(t, db, ws, "proj-beta")
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if got := countIdentities(t, db, ws, connectorID); got != 2 {
		t.Fatalf("identities = %d, want 2 -- keying on the email merged two distinct principals", got)
	}

	var rows []models.CloudIdentity
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).
		Find(&rows).Error; err != nil {
		t.Fatalf("load identities: %v", err)
	}
	for _, row := range rows {
		attrs := row.GCPAttrs()
		if attrs.UniqueID == "" {
			t.Fatal("unique id was not recorded in attrs")
		}
		if !strings.Contains(row.NativeID, attrs.UniqueID) {
			t.Fatalf("native_id %q is not built on the unique id %q", row.NativeID, attrs.UniqueID)
		}
		if strings.Contains(row.NativeID, email) {
			t.Fatalf("native_id %q contains the email; it must key on the unique id", row.NativeID)
		}
		if attrs.Email != email {
			t.Fatalf("the email should still be kept as a locator, got %q", attrs.Email)
		}
	}
	t.Logf("PASS: two accounts at one address stayed two identities")
}

// Genuinely empty is not the same as unreached. A project that answers with no
// service accounts is reached with a count of zero, and that scan IS complete.
func TestGCPScan_EmptyEstateIsReachedNotUnknown(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-empty")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.accounts["proj-empty"] = nil

	connectorID := gcpScanConnector(t, db, ws, "proj-empty")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	identities := snapshot.Coverage.Surfaces["identities"]
	if identities.State != models.CloudCoverageReached {
		t.Fatalf("identities state = %q, want reached", identities.State)
	}
	if identities.Count != 0 {
		t.Fatalf("count = %d, want 0", identities.Count)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("an empty estate that was fully read is a complete scan, got %q", snapshot.Coverage.Status)
	}
	t.Logf("PASS: an empty project reads as reached/0, not unknown")
}

/* -------------------- the destructive ones: nothing is deleted -------------- */

// A complete rescan removes what genuinely disappeared. This is the ONLY state
// in which anything may be removed, and it is tested first so the negative
// cases below are proved to be withholding a deletion that would otherwise
// happen.
func TestGCPScan_CompleteRescanReconcilesDeletedAccounts(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-reconcile")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.accounts["proj-rec"] = []fakeGCPAccount{
		account("100000000000000000020", "stays@proj-rec.iam.gserviceaccount.com"),
		account("100000000000000000021", "goes@proj-rec.iam.gserviceaccount.com",
			fakeGCPKey{id: "doomed-key", managed: "USER_MANAGED"}),
	}
	connectorID := gcpScanConnector(t, db, ws, "proj-rec")
	scanner := gcpScanner(t, db, f)

	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := countIdentities(t, db, ws, connectorID); got != 2 {
		t.Fatalf("after first scan identities = %d, want 2", got)
	}

	// One account is deleted in GCP.
	f.accounts["proj-rec"] = f.accounts["proj-rec"][:1]

	snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q, want complete", snapshot.Coverage.Status)
	}
	if got := countIdentities(t, db, ws, connectorID); got != 1 {
		t.Fatalf("identities = %d, want 1 after reconciliation", got)
	}
	if got := countSecrets(t, db, ws, connectorID); got != 0 {
		t.Fatalf("secrets = %d, want 0 -- the deleted account's key should go with it", got)
	}
	t.Logf("PASS: a complete rescan removed the account that genuinely disappeared")
}

// Every not-reached state must leave the estate alone. A denied read and an
// empty project are identical in the database, so a scan that could not look
// has not earned the right to conclude anything is gone.
func TestGCPScan_NotReachedNeverDeletes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wantState string
		arrange   func(f *fakeGCPDiscovery, projectID string)
	}{
		{
			name:      "denied",
			wantState: models.CloudCoverageDenied,
			arrange: func(f *fakeGCPDiscovery, p string) {
				f.failProject[p] = http.StatusForbidden
			},
		},
		{
			name:      "throttled",
			wantState: models.CloudCoverageThrottled,
			arrange: func(f *fakeGCPDiscovery, p string) {
				f.failProject[p] = http.StatusTooManyRequests
			},
		},
		{
			name:      "constrained by org policy",
			wantState: models.CloudCoverageConstrained,
			arrange: func(f *fakeGCPDiscovery, p string) {
				f.policyRefusedProject = p
			},
		},
		{
			name:      "server error",
			wantState: models.CloudCoverageDenied,
			arrange: func(f *fakeGCPDiscovery, p string) {
				f.failProject[p] = http.StatusInternalServerError
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := igaDB(t)
			ws := newWorkspace(t, db, "gcp-scan-nodelete-"+strings.ReplaceAll(tc.name, " ", "-"))
			f := newFakeGCPDiscovery()
			defer f.Close()

			const project = "proj-guard"
			f.accounts[project] = []fakeGCPAccount{
				account("100000000000000000030", "present@proj-guard.iam.gserviceaccount.com",
					fakeGCPKey{id: "kept-key", managed: "USER_MANAGED"}),
			}
			connectorID := gcpScanConnector(t, db, ws, project)
			scanner := gcpScanner(t, db, f)

			// A good scan first, so there is something to lose.
			if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
				t.Fatalf("first scan: %v", err)
			}
			if countIdentities(t, db, ws, connectorID) != 1 || countSecrets(t, db, ws, connectorID) != 1 {
				t.Fatal("first scan did not establish the baseline")
			}

			// Now the read fails, and GCP also "loses" the account -- the exact
			// ambiguity the gate exists for.
			tc.arrange(f, project)
			f.accounts[project] = nil

			snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
			if err != nil {
				t.Fatalf("second scan: %v", err)
			}

			if got := snapshot.Coverage.Surfaces["identities"].State; got != tc.wantState {
				t.Fatalf("identities state = %q, want %q", got, tc.wantState)
			}
			if snapshot.Coverage.Complete() {
				t.Fatal("a scan that could not read a project must not be Complete()")
			}
			if snapshot.Coverage.Status != models.ScanStatusPartial {
				t.Fatalf("status = %q, want partial", snapshot.Coverage.Status)
			}
			if got := countIdentities(t, db, ws, connectorID); got != 1 {
				t.Fatalf("identities = %d, want 1 -- an unreached surface deleted data", got)
			}
			if got := countSecrets(t, db, ws, connectorID); got != 1 {
				t.Fatalf("secrets = %d, want 1 -- an unreached surface deleted data", got)
			}
			if n := snapshot.Coverage.Counters["identities_removed"]; n != 0 {
				t.Fatalf("identities_removed = %d, want 0", n)
			}
		})
	}
}

// A connector whose credential cannot be built is a failed scan: recorded as
// such rather than left showing the last report, and deleting nothing.
func TestGCPScan_FailedScanRecordsFailureAndDeletesNothing(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-failed")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const project = "proj-failcred"
	f.accounts[project] = []fakeGCPAccount{
		account("100000000000000000040", "present@proj-failcred.iam.gserviceaccount.com"),
	}
	connectorID := gcpScanConnector(t, db, ws, project)

	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	baseline := countIdentities(t, db, ws, connectorID)
	if baseline != 1 {
		t.Fatalf("baseline identities = %d, want 1", baseline)
	}

	// Break the credential: the wif path needs an issuer, and this auth service
	// has none, so BuildWIFCredential fails before any GCP call.
	breaking := services.NewGCPScanner(db, services.NewGCPAuthService(nil, nil))
	snapshot, err := breaking.Scan(context.Background(), ws, connectorID)
	if err == nil {
		t.Fatal("expected the scan to fail when no credential can be built")
	}
	if snapshot == nil {
		t.Fatal("a snapshot must be returned even on failure, so the outcome is not silently dropped")
	}
	if snapshot.Coverage.Status != models.ScanStatusFailed {
		t.Fatalf("status = %q, want failed", snapshot.Coverage.Status)
	}
	if snapshot.Coverage.Complete() {
		t.Fatal("a failed scan must never be Complete()")
	}
	if got := countIdentities(t, db, ws, connectorID); got != baseline {
		t.Fatalf("identities = %d, want %d -- a failed scan deleted data", got, baseline)
	}

	// And the failure is durable on the connector, not just returned.
	var stored models.CloudConnector
	if err := db.Where("id = ?", connectorID).First(&stored).Error; err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	if cov := models.DecodeScanCoverage(stored.Coverage); cov.Status != models.ScanStatusFailed {
		t.Fatalf("persisted status = %q, want failed", cov.Status)
	}
	t.Logf("PASS: a credential failure is a recorded failed scan that deletes nothing")
}

// A blocked readiness verdict is refused before a generation is even allocated.
// The field has been computed on every onboard and verify since onboarding
// landed, and until now nothing read it.
func TestGCPScan_RefusesBlockedConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-blocked")
	f := newFakeGCPDiscovery()
	defer f.Close()

	connectorID := gcpScanConnector(t, db, ws, "proj-blocked")
	connector := &models.CloudConnector{}
	if err := db.Where("id = ?", connectorID).First(connector).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	attrs := connector.GCPAttrs()
	attrs.DiscoveryReadiness = models.GCPReadinessBlocked
	attrs.DiscoveryReadinessReasons = []string{models.GCPLimitQuotaProjectUnusable}
	if err := connector.SetGCPAttrs(attrs); err != nil {
		t.Fatalf("set attrs: %v", err)
	}
	if err := db.Model(&models.CloudConnector{}).Where("id = ?", connectorID).
		Update("attrs", connector.Attrs).Error; err != nil {
		t.Fatalf("persist attrs: %v", err)
	}

	before := gcpGeneration(t, db, connectorID)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err == nil {
		t.Fatal("a blocked connector must not be scanned")
	}
	if after := gcpGeneration(t, db, connectorID); after != before {
		t.Fatalf("a refused scan still burned a generation: %d -> %d", before, after)
	}
	if f.callCount("/serviceAccounts") != 0 {
		t.Fatal("a blocked connector still called GCP")
	}
	t.Logf("PASS: a blocked connector is refused before any generation or GCP call")
}

// A revoked connector cannot be scanned. Revocation means "we can no longer
// read this account", and reading it anyway would be exactly the thing revoking
// was meant to stop.
func TestGCPScan_RefusesRevokedConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-revoked")
	f := newFakeGCPDiscovery()
	defer f.Close()

	connectorID := gcpScanConnector(t, db, ws, "proj-revoked")
	if err := db.Model(&models.CloudConnector{}).Where("id = ?", connectorID).
		Update("status", models.CloudConnectorRevoked).Error; err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err == nil {
		t.Fatal("a revoked connector must not be scanned")
	}
	if f.callCount("/serviceAccounts") != 0 {
		t.Fatal("a revoked connector still called GCP")
	}
}

// Phase 1 reads identities and keys. It has no standing to delete permissions,
// resources, edges, workloads or usage, because it never looked at any of them.
func TestGCPScan_NeverTouchesLaterSurfaceTables(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-scope-of-deletion")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const project = "proj-scope"
	f.accounts[project] = []fakeGCPAccount{
		account("100000000000000000050", "svc@proj-scope.iam.gserviceaccount.com"),
	}
	connectorID := gcpScanConnector(t, db, ws, project)

	// A row in a later surface's table, left by some other phase.
	resourceID := uuid.New()
	if err := db.Exec(`INSERT INTO cloud_resource
		(id, workspace_id, connector_id, kind, native_id, name, sensitivity, last_seen_generation)
		VALUES (?,?,?,?,?,?,?,?)`,
		resourceID, ws, connectorID, "bucket", "//storage.googleapis.com/b/keep-me", "keep-me", "low", 0,
	).Error; err != nil {
		t.Fatalf("seed resource: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM cloud_resource WHERE id = ?`, resourceID) })

	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var n int64
	if err := db.Model(&models.CloudResource{}).Where("id = ?", resourceID).Count(&n).Error; err != nil {
		t.Fatalf("count resources: %v", err)
	}
	if n != 1 {
		t.Fatal("the identity phase deleted a cloud_resource row it never looked at")
	}
	t.Logf("PASS: a generation-0 row in an unread surface survived a complete identity scan")
}

func gcpGeneration(t *testing.T, db *gorm.DB, connectorID uuid.UUID) int {
	t.Helper()
	var c models.CloudConnector
	if err := db.Where("id = ?", connectorID).First(&c).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	return c.ScanGeneration
}

/* --------------------- org-scoped: the enumeration path --------------------- */

// The org/folder branch: enumerate projects, then fan out across them.
//
// Exercised with pagination on, so every page takes its own limiter token and
// its own retry rather than the whole walk taking one of each.
func TestGCPScan_OrgScopedEnumeratesAndFansOut(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-org-fanout")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.pageProjects = true
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("org-proj-%d", i)
		f.projects = append(f.projects, struct{ id, number string }{id, fmt.Sprintf("10000%d", i)})
		f.accounts[id] = []fakeGCPAccount{
			account(fmt.Sprintf("2000000000000000000%d", i),
				fmt.Sprintf("svc@%s.iam.gserviceaccount.com", id),
				fakeGCPKey{id: "k" + id, managed: "USER_MANAGED"}),
		}
	}

	connectorID := gcpOrgScanConnector(t, db, ws, "123456789012")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(snapshot.Projects) != 5 {
		t.Fatalf("enumerated %d projects, want 5 -- pagination dropped some", len(snapshot.Projects))
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q, want complete: %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}
	if got := countIdentities(t, db, ws, connectorID); got != 5 {
		t.Fatalf("identities = %d, want 5", got)
	}
	if got := countSecrets(t, db, ws, connectorID); got != 5 {
		t.Fatalf("secrets = %d, want 5", got)
	}
	if got := snapshot.Coverage.Counters["projects_reached"]; got != 5 {
		t.Fatalf("projects_reached = %d, want 5", got)
	}
	// The project search must have been called more than once, or pagination
	// was never actually exercised and this test proves less than it claims.
	if n := f.callCount("projects:search"); n < 5 {
		t.Fatalf("project search called %d times; pagination was not exercised", n)
	}
	t.Logf("PASS: 5 projects enumerated across %d pages and fanned out", f.callCount("projects:search"))
}

// An org where one project denies the read: the others are still collected, but
// the scan is partial and nothing is reconciled. The per-project independence
// and the estate-wide safety rule have to hold at the same time.
func TestGCPScan_OrgScopedOneDeniedProjectBlocksReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-org-partial")
	f := newFakeGCPDiscovery()
	defer f.Close()

	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("mix-proj-%d", i)
		f.projects = append(f.projects, struct{ id, number string }{id, fmt.Sprintf("20000%d", i)})
		f.accounts[id] = []fakeGCPAccount{
			account(fmt.Sprintf("3000000000000000000%d", i),
				fmt.Sprintf("svc@%s.iam.gserviceaccount.com", id)),
		}
	}
	connectorID := gcpOrgScanConnector(t, db, ws, "223456789012")
	scanner := gcpScanner(t, db, f)

	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if got := countIdentities(t, db, ws, connectorID); got != 3 {
		t.Fatalf("baseline identities = %d, want 3", got)
	}

	// One project now denies, and its account also "disappears".
	f.failProject["mix-proj-2"] = http.StatusForbidden
	f.accounts["mix-proj-2"] = nil

	snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if snapshot.Coverage.Status != models.ScanStatusPartial {
		t.Fatalf("status = %q, want partial", snapshot.Coverage.Status)
	}
	if got := snapshot.Coverage.Surfaces["identities"].State; got != models.CloudCoverageDenied {
		t.Fatalf("identities state = %q, want denied -- worst outcome must win across projects", got)
	}
	if got := snapshot.Coverage.Counters["projects_reached"]; got != 2 {
		t.Fatalf("projects_reached = %d, want 2", got)
	}
	if got := snapshot.Coverage.Counters["projects_denied"]; got != 1 {
		t.Fatalf("projects_denied = %d, want 1", got)
	}
	// Nothing removed, including the account behind the denied project.
	if got := countIdentities(t, db, ws, connectorID); got != 3 {
		t.Fatalf("identities = %d, want 3 -- a partial org scan deleted data", got)
	}
	t.Logf("PASS: 2 of 3 projects read, worst outcome won, nothing deleted")
}

// A reader that cannot enumerate has not found an empty org. Both surfaces must
// record not-reached and nothing may be reconciled.
func TestGCPScan_OrgScopedEnumerationDenialIsNotAnEmptyEstate(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-org-enum-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()

	id := "enum-proj-1"
	f.projects = append(f.projects, struct{ id, number string }{id, "300001"})
	f.accounts[id] = []fakeGCPAccount{
		account("40000000000000000001", "svc@enum-proj-1.iam.gserviceaccount.com"),
	}
	connectorID := gcpOrgScanConnector(t, db, ws, "323456789012")
	scanner := gcpScanner(t, db, f)

	if _, err := scanner.Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if countIdentities(t, db, ws, connectorID) != 1 {
		t.Fatal("baseline not established")
	}

	f.enumStatus = http.StatusForbidden

	snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if snapshot.Coverage.Complete() {
		t.Fatal("a scan that could not enumerate must never be Complete()")
	}
	for _, surface := range []string{"identities", "keys"} {
		if got := snapshot.Coverage.Surfaces[surface].State; got == models.CloudCoverageReached {
			t.Fatalf("%s reported reached despite enumeration failing", surface)
		}
	}
	if got := countIdentities(t, db, ws, connectorID); got != 1 {
		t.Fatalf("identities = %d, want 1 -- a failed enumeration deleted data", got)
	}
	t.Logf("PASS: enumeration denial is not an empty estate")
}

// The same service account must produce the SAME native_id whether it is found
// through a project-scoped connector or an org-scoped one. Anything else forks
// the estate across two rows and lets one connector reconcile away the other's.
func TestGCPScan_NativeIDIsStableAcrossScopeKinds(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-nativeid-stable")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const projectID = "shared-proj"
	const uniqueID = "50000000000000000001"
	f.projects = append(f.projects, struct{ id, number string }{projectID, "500001"})
	f.accounts[projectID] = []fakeGCPAccount{
		account(uniqueID, "svc@shared-proj.iam.gserviceaccount.com"),
	}

	projectConnector := gcpScanConnector(t, db, ws, projectID)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, projectConnector); err != nil {
		t.Fatalf("project-scoped scan: %v", err)
	}
	orgConnector := gcpOrgScanConnector(t, db, ws, "423456789012")
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, orgConnector); err != nil {
		t.Fatalf("org-scoped scan: %v", err)
	}

	var rows []models.CloudIdentity
	if err := db.Where("workspace_id = ?", ws).Find(&rows).Error; err != nil {
		t.Fatalf("load identities: %v", err)
	}
	if len(rows) != 1 {
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.NativeID)
		}
		t.Fatalf("one service account produced %d rows across two scope kinds: %v", len(rows), ids)
	}
	if strings.Contains(rows[0].NativeID, projectID) || strings.Contains(rows[0].NativeID, "500001") {
		t.Fatalf("native_id %q embeds a project container; it must key on the unique id alone", rows[0].NativeID)
	}
	t.Logf("PASS: both scope kinds agree on native_id %q", rows[0].NativeID)
}

// Field shapes taken from a LIVE GCP response, not invented.
//
// Every value below was observed by calling the real APIs as part of reviewing
// this collector:
//
//	validBeforeTime "9999-12-31T23:59:59Z"  -- GCP's never-expires sentinel
//	keyOrigin       "GOOGLE_PROVIDED"       -- distinct from keyType
//	keyType         "USER_MANAGED"          -- distinct from keyOrigin
//
// The first two were both mishandled before that check: the sentinel was stored
// as a year-9999 date, and keyOrigin was overwritten with a keyType value.
func TestGCPScan_LiveKeyFieldShapes(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-live-key-shapes")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const project = "proj-live-shapes"
	f.accounts[project] = []fakeGCPAccount{
		account("117030850257667402454", "svc@proj-live-shapes.iam.gserviceaccount.com",
			fakeGCPKey{
				id: "4ad522d514dcd84c228b7968a1a38de5b7bd4756", managed: "USER_MANAGED",
				validFrom: "2025-10-12T20:32:46Z", validBefore: "9999-12-31T23:59:59Z",
				origin: "GOOGLE_PROVIDED",
			}),
	}

	connectorID := gcpScanConnector(t, db, ws, project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var secret models.CloudSecret
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).
		First(&secret).Error; err != nil {
		t.Fatalf("load secret: %v", err)
	}

	// The sentinel must become nil, not a year-9999 date: "this key never
	// expires" is the finding, and the schema expresses it as NULL.
	if secret.ExpiresAt != nil {
		t.Fatalf("expires_at = %v, want nil -- GCP's 9999 sentinel was stored as a real date",
			secret.ExpiresAt)
	}
	// A real expiry still has to survive.
	if secret.ProviderCreatedAt == nil || secret.ProviderCreatedAt.UTC().Year() != 2025 {
		t.Fatalf("created_at = %v, want the 2025 validAfterTime", secret.ProviderCreatedAt)
	}

	attrs := secret.GCPAttrs()
	if attrs.KeyOrigin != models.GCPKeyOriginGoogleProvided {
		t.Fatalf("key_origin = %q, want %q -- origin and type are different fields",
			attrs.KeyOrigin, models.GCPKeyOriginGoogleProvided)
	}
	if attrs.KeyType != models.GCPKeyTypeUserManaged {
		t.Fatalf("key_type = %q, want %q", attrs.KeyType, models.GCPKeyTypeUserManaged)
	}
	t.Logf("PASS: never-expires sentinel is NULL; origin=%s and type=%s kept apart",
		attrs.KeyOrigin, attrs.KeyType)
}

// A key that genuinely expires keeps its date.
func TestGCPScan_RealExpiryIsPreserved(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-real-expiry")
	f := newFakeGCPDiscovery()
	defer f.Close()

	const project = "proj-real-expiry"
	f.accounts[project] = []fakeGCPAccount{
		account("117030850257667402455", "svc@proj-real-expiry.iam.gserviceaccount.com",
			fakeGCPKey{
				id: "expiring", managed: "USER_MANAGED",
				validFrom: "2026-09-08T04:45:21Z", validBefore: "2026-09-25T04:45:21Z",
				origin: "USER_PROVIDED",
			}),
	}

	connectorID := gcpScanConnector(t, db, ws, project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var secret models.CloudSecret
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).
		First(&secret).Error; err != nil {
		t.Fatalf("load secret: %v", err)
	}
	if secret.ExpiresAt == nil {
		t.Fatal("a key with a real expiry lost it")
	}
	if secret.ExpiresAt.UTC().Year() != 2026 {
		t.Fatalf("expires_at = %v, want 2026", secret.ExpiresAt)
	}
	if got := secret.GCPAttrs().KeyOrigin; got != models.GCPKeyOriginUserProvided {
		t.Fatalf("key_origin = %q, want %q", got, models.GCPKeyOriginUserProvided)
	}
	t.Logf("PASS: a real expiry survives and USER_PROVIDED origin is recorded")
}
