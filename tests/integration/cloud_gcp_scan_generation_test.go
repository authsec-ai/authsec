package integration

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Scan-generation allocation for GCP, against a real database.
//
// There is no provider boundary to fake here: every claim this file makes is
// about Postgres semantics, so the only honest way to test it is against
// Postgres. Run with the same scratch database the rest of this package uses:
//
//	IGA_TEST_DSN="host=localhost port=5432 user=authsec password=... dbname=iga_test sslmode=disable" \
//	  go test ./tests/integration/ -run TestGCPScanGeneration -v
//
// The behaviour under test is the reason repository/cloud_gcp_scan_repository.go
// exists. AWS computes its generation in Go from a value it read earlier
// (services/cloud_aws_iam_scan.go:141) and writes it back at the end of the
// scan with no guard, so two concurrent scans of one connector compute the SAME
// number -- and since reconciliation deletes every row below the current
// generation, the first to finish can delete rows the second has not written
// yet. TestGCPScanGeneration_ConcurrentAllocationsAreUnique is what stops that
// pattern being copied into GCP by accident.

/* --------------------------------- fixtures -------------------------------- */

// gcpConnectorFixture inserts a minimal active GCP connector and returns its id.
//
// Deliberately built through the shared repository rather than a raw INSERT:
// if the onboarding upsert ever stops producing a row this scan path can use,
// that is something these tests should fail on rather than paper over.
func gcpConnectorFixture(t *testing.T, db *gorm.DB, ws uuid.UUID) uuid.UUID {
	t.Helper()
	repo := repositories.NewCloudConnectorRepository(db)
	stored, _, err := repo.Upsert(&models.CloudConnector{
		WorkspaceID: ws,
		Provider:    models.CloudProviderGCP,
		ScopeKind:   models.CloudScopeProject,
		ScopeID:     "authsec-gen-" + uuid.NewString()[:8],
		// Non-empty because cloud_connector_auth_ref_chk refuses an active
		// connector with no handle. "wif:" + provider resource is what the real
		// WIF path stores -- a resource name, never key material.
		AuthRef:  "wif:projects/1/locations/global/workloadIdentityPools/p/providers/authsec-provider",
		Status:   models.CloudConnectorActive,
		Coverage: json.RawMessage(`{}`),
		Attrs:    json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("seed gcp connector: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM cloud_connector WHERE id = ?`, stored.ID)
	})
	return stored.ID
}

// awsConnectorFixture is the negative control for the provider predicate.
func awsConnectorFixture(t *testing.T, db *gorm.DB, ws uuid.UUID) uuid.UUID {
	t.Helper()
	repo := repositories.NewCloudConnectorRepository(db)
	stored, _, err := repo.Upsert(&models.CloudConnector{
		WorkspaceID: ws,
		Provider:    models.CloudProviderAWS,
		ScopeKind:   models.CloudScopeAccount,
		ScopeID:     "42941837" + uuid.NewString()[:4],
		AuthRef:     "secret/authsec/aws/external-id",
		Status:      models.CloudConnectorActive,
		Coverage:    json.RawMessage(`{}`),
		Attrs:       json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("seed aws connector: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM cloud_connector WHERE id = ?`, stored.ID)
	})
	return stored.ID
}

func runningCoverage(generation int) json.RawMessage {
	raw, _ := json.Marshal(models.ScanCoverage{
		Generation: generation,
		Status:     models.ScanStatusRunning,
		Surfaces:   map[string]models.SurfaceCoverage{},
		Counters:   map[string]int{},
	})
	return raw
}

/* ------------------------------ the atomicity ------------------------------ */

// The claim the whole design rests on: N concurrent allocations produce N
// distinct generations, not one number handed out N times.
//
// Asserting uniqueness alone would pass for a mutex that serialises but loses
// increments, so this also asserts the set is exactly 1..N -- every allocation
// moved the column, none overwrote another.
func TestGCPScanGeneration_ConcurrentAllocationsAreUnique(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-concurrency")
	connectorID := gcpConnectorFixture(t, db, ws)

	repo := repositories.NewCloudGCPScanRepository(db)

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		got     []int
		failure error
	)

	// A start barrier, so the goroutines contend rather than politely queueing
	// behind each other's scheduling.
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			generation, err := repo.AllocateGeneration(ws, connectorID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failure = err
				return
			}
			got = append(got, generation)
		}()
	}
	close(start)
	wg.Wait()

	if failure != nil {
		t.Fatalf("allocate under contention: %v", failure)
	}
	if len(got) != racers {
		t.Fatalf("expected %d allocations, got %d", racers, len(got))
	}

	seen := map[int]bool{}
	for _, g := range got {
		if seen[g] {
			t.Fatalf("generation %d was handed out more than once: %v\n"+
				"this is the AWS read-then-increment failure mode -- two scans "+
				"sharing a generation can reconcile each other's rows away", g, got)
		}
		seen[g] = true
	}
	// The connector started at 0, so N allocations must be exactly 1..N.
	for want := 1; want <= racers; want++ {
		if !seen[want] {
			t.Fatalf("generation %d was never handed out; an increment was lost: %v", want, got)
		}
	}

	current, err := repo.CurrentGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("current generation: %v", err)
	}
	if current != racers {
		t.Fatalf("connector scan_generation = %d, want %d", current, racers)
	}
	t.Logf("PASS: %d concurrent allocations produced generations 1..%d with no duplicates", racers, racers)
}

// Allocation is monotonic across sequential scans, including after a scan that
// failed. A crashed scan burning a generation is the accepted cost of moving
// the increment to the start -- what must never happen is the number going
// backwards, because a reused generation makes a stale row look current.
func TestGCPScanGeneration_IsMonotonicAcrossScans(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-monotonic")
	connectorID := gcpConnectorFixture(t, db, ws)
	repo := repositories.NewCloudGCPScanRepository(db)

	first, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("first allocate: %v", err)
	}

	// The first scan fails outright: it writes a failed report at its own
	// generation and never commits anything else.
	failed, _ := json.Marshal(models.ScanCoverage{
		Generation: first,
		Status:     models.ScanStatusFailed,
		Error:      "gcp: permission denied",
	})
	if err := repo.CommitCoverage(ws, connectorID, first, failed); err != nil {
		t.Fatalf("commit failed coverage: %v", err)
	}

	second, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("second allocate: %v", err)
	}
	if second <= first {
		t.Fatalf("generation went backwards or stalled after a failed scan: %d then %d", first, second)
	}
	t.Logf("PASS: a failed scan at generation %d is followed by generation %d", first, second)
}

/* ------------------------------ the guard ---------------------------------- */

// A scan that ran long and was overtaken must not overwrite the newer scan's
// report with its own. This is what keeps a slow partial scan from replacing a
// fresh complete one -- and, since the runner consults the same generation
// before reconciling, what keeps it from deleting against a generation it no
// longer owns.
func TestGCPScanGeneration_StaleCommitIsRefused(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-stale-commit")
	connectorID := gcpConnectorFixture(t, db, ws)
	repo := repositories.NewCloudGCPScanRepository(db)

	stale, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("allocate stale: %v", err)
	}
	if err := repo.BeginScan(ws, connectorID, stale, runningCoverage(stale)); err != nil {
		t.Fatalf("begin stale scan: %v", err)
	}

	// A second scan starts while the first is still running.
	fresh, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("allocate fresh: %v", err)
	}
	freshCoverage, _ := json.Marshal(models.ScanCoverage{
		Generation: fresh,
		Status:     models.ScanStatusComplete,
		Surfaces:   map[string]models.SurfaceCoverage{"identities": {State: models.CloudCoverageReached, Count: 3}},
	})
	if err := repo.CommitCoverage(ws, connectorID, fresh, freshCoverage); err != nil {
		t.Fatalf("commit fresh coverage: %v", err)
	}

	// Now the overtaken scan finishes and tries to report.
	staleCoverage, _ := json.Marshal(models.ScanCoverage{
		Generation: stale,
		Status:     models.ScanStatusPartial,
		Surfaces:   map[string]models.SurfaceCoverage{"identities": {State: models.CloudCoverageDenied}},
	})
	err = repo.CommitCoverage(ws, connectorID, stale, staleCoverage)
	if !errors.Is(err, repositories.ErrScanSuperseded) {
		t.Fatalf("stale commit returned %v, want ErrScanSuperseded", err)
	}

	// And the newer report survived intact.
	var stored models.CloudConnector
	if err := db.Where("id = ?", connectorID).First(&stored).Error; err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	cov := models.DecodeScanCoverage(stored.Coverage)
	if cov.Generation != fresh || cov.Status != models.ScanStatusComplete {
		t.Fatalf("stale scan clobbered the newer report: generation=%d status=%s",
			cov.Generation, cov.Status)
	}
	t.Logf("PASS: generation %d could not overwrite the report from generation %d", stale, fresh)
}

// BeginScan carries the same guard as CommitCoverage. A scan that loses the
// race before it has read anything should find out at the first write rather
// than after spending a scan window calling GCP.
func TestGCPScanGeneration_StaleBeginIsRefused(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-stale-begin")
	connectorID := gcpConnectorFixture(t, db, ws)
	repo := repositories.NewCloudGCPScanRepository(db)

	stale, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("allocate stale: %v", err)
	}
	if _, err := repo.AllocateGeneration(ws, connectorID); err != nil {
		t.Fatalf("allocate fresh: %v", err)
	}

	err = repo.BeginScan(ws, connectorID, stale, runningCoverage(stale))
	if !errors.Is(err, repositories.ErrScanSuperseded) {
		t.Fatalf("stale begin returned %v, want ErrScanSuperseded", err)
	}
	t.Logf("PASS: an overtaken scan is refused at BeginScan, before it calls GCP")
}

/* --------------------------- the provider predicate ------------------------ */

// This repository is GCP-side by construction, not by convention. Pointing it
// at an AWS connector must do nothing at all -- the guard that survives a
// refactor of the service layer's own provider check.
func TestGCPScanGeneration_RefusesNonGCPConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-provider-guard")
	awsID := awsConnectorFixture(t, db, ws)
	repo := repositories.NewCloudGCPScanRepository(db)

	_, err := repo.AllocateGeneration(ws, awsID)
	if !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("allocating on an AWS connector returned %v, want ErrCloudConnectorNotFound", err)
	}

	// And the AWS connector's own generation is untouched.
	var stored models.CloudConnector
	if err := db.Where("id = ?", awsID).First(&stored).Error; err != nil {
		t.Fatalf("reload aws connector: %v", err)
	}
	if stored.ScanGeneration != 0 {
		t.Fatalf("AWS connector scan_generation moved to %d; the GCP scan path must never touch it",
			stored.ScanGeneration)
	}
	t.Logf("PASS: the GCP scan repository cannot allocate against an AWS connector")
}

// Tenant isolation: a connector id alone is not authority to scan it. Every
// statement in this repository carries workspace_id, and this proves the
// predicate is actually in the SQL rather than assumed by the caller.
func TestGCPScanGeneration_IsWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	owner := newWorkspace(t, db, "gcp-generation-owner")
	intruder := newWorkspace(t, db, "gcp-generation-intruder")
	connectorID := gcpConnectorFixture(t, db, owner)
	repo := repositories.NewCloudGCPScanRepository(db)

	if _, err := repo.AllocateGeneration(intruder, connectorID); !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("cross-workspace allocate returned %v, want ErrCloudConnectorNotFound", err)
	}
	if _, err := repo.CurrentGeneration(intruder, connectorID); !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("cross-workspace read returned %v, want ErrCloudConnectorNotFound", err)
	}

	var stored models.CloudConnector
	if err := db.Where("id = ?", connectorID).First(&stored).Error; err != nil {
		t.Fatalf("reload connector: %v", err)
	}
	if stored.ScanGeneration != 0 {
		t.Fatalf("another workspace moved this connector's generation to %d", stored.ScanGeneration)
	}
	t.Logf("PASS: a connector id from another workspace allocates nothing and reads nothing")
}

// An empty coverage blob is refused rather than written. The column is NOT
// NULL, and "{}" decodes to a report with no surfaces -- which reads exactly
// like a scan that looked everywhere and found nothing.
func TestGCPScanGeneration_RefusesEmptyCoverage(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-generation-empty-coverage")
	connectorID := gcpConnectorFixture(t, db, ws)
	repo := repositories.NewCloudGCPScanRepository(db)

	generation, err := repo.AllocateGeneration(ws, connectorID)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if err := repo.CommitCoverage(ws, connectorID, generation, nil); err == nil {
		t.Fatal("committing an empty coverage blob succeeded; it must be refused")
	}
	t.Logf("PASS: an empty coverage blob is refused")
}
