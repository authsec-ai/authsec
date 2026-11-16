package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GCP-1 scheduler: due-ness, skips, busy connectors, workspace isolation.

const schedInterval = 12 * time.Hour

func gcpScheduler(t *testing.T, db *gorm.DB, f *fakeGCPDiscovery, now time.Time) *services.GCPScanScheduler {
	t.Helper()
	return services.NewGCPScanScheduler(db, gcpScanner(t, db, f)).WithClock(func() time.Time { return now })
}

// setCoverage stamps a connector as if a scan of that status had last run then.
func setCoverage(t *testing.T, db *gorm.DB, ws, id uuid.UUID, status string, startedAt, finishedAt time.Time) {
	t.Helper()
	cov := models.ScanCoverage{Status: status, StartedAt: &startedAt}
	if !finishedAt.IsZero() {
		cov.FinishedAt = &finishedAt
	}
	raw, _ := json.Marshal(cov)
	if err := db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", ws, id).
		Update("coverage", raw).Error; err != nil {
		t.Fatalf("set coverage: %v", err)
	}
}

func coverageOf(t *testing.T, db *gorm.DB, ws, id uuid.UUID) models.ScanCoverage {
	t.Helper()
	var c models.CloudConnector
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).First(&c).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	return models.DecodeScanCoverage(c.Coverage)
}

// A never-scanned connector is due; the scan it causes is recorded as scheduled.
func TestGCPScheduler_ScansNeverScannedConnectorAndRecordsTrigger(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sched-first")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = append(f.projects, struct{ id, number string }{"sched-proj", "1"})
	f.accounts["sched-proj"] = []fakeGCPAccount{account("uid-s", "svc@sched-proj.iam.gserviceaccount.com")}

	id := gcpScanConnector(t, db, ws, "sched-proj")
	n := gcpScheduler(t, db, f, time.Now()).RunOnce(context.Background(), schedInterval)
	if n < 1 {
		t.Fatalf("started %d scans, want at least this connector's", n)
	}
	cov := coverageOf(t, db, ws, id)
	if cov.Trigger != models.CloudScanTriggerScheduled {
		t.Fatalf("trigger = %q, want scheduled", cov.Trigger)
	}
	if got := countIdentities(t, db, ws, id); got != 1 {
		t.Fatalf("identities = %d, want 1", got)
	}
}

// Rescans only after the interval has passed.
func TestGCPScheduler_RescansOnlyAfterTheInterval(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sched-interval")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = append(f.projects, struct{ id, number string }{"iv-proj", "1"})

	id := gcpScanConnector(t, db, ws, "iv-proj")
	now := time.Now()
	setCoverage(t, db, ws, id, models.ScanStatusComplete, now.Add(-time.Hour), now.Add(-time.Hour))

	gcpScheduler(t, db, f, now).RunOnce(context.Background(), schedInterval)
	if g := coverageOf(t, db, ws, id).Generation; g != 0 {
		t.Fatalf("scanned a connector whose last scan was 1h ago (generation %d)", g)
	}

	later := now.Add(schedInterval)
	gcpScheduler(t, db, f, later).RunOnce(context.Background(), schedInterval)
	if g := coverageOf(t, db, ws, id).Generation; g < 1 {
		t.Fatal("did not rescan after the interval elapsed")
	}
}

// A scan still marked running inside its budget is busy: never a second scan.
// One that has been running past the budget died with its process and is retaken.
func TestGCPScheduler_NeverStartsASecondScanOnABusyConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sched-busy")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = append(f.projects, struct{ id, number string }{"busy-proj", "1"})

	id := gcpScanConnector(t, db, ws, "busy-proj")
	now := time.Now()
	setCoverage(t, db, ws, id, models.ScanStatusRunning, now.Add(-time.Minute), time.Time{})

	gcpScheduler(t, db, f, now.Add(schedInterval)).RunOnce(context.Background(), schedInterval)
	if n := f.callCount("/serviceAccounts"); n != 0 {
		t.Fatalf("a scan was started on a connector already scanning (%d calls)", n)
	}

	// Dead: started long ago and never finished.
	setCoverage(t, db, ws, id, models.ScanStatusRunning, now.Add(-24*time.Hour), time.Time{})
	gcpScheduler(t, db, f, now).RunOnce(context.Background(), schedInterval)
	if f.callCount("/serviceAccounts") == 0 {
		t.Fatal("a dead running scan was never retaken")
	}
}

// Revoked and not-ready connectors are skipped.
func TestGCPScheduler_SkipsRevokedAndBlockedConnectors(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sched-skips")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = append(f.projects, struct{ id, number string }{"skip-proj", "1"})

	revoked := gcpScanConnector(t, db, ws, "skip-proj")
	if err := db.Model(&models.CloudConnector{}).Where("id = ?", revoked).
		Update("status", models.CloudConnectorRevoked).Error; err != nil {
		t.Fatal(err)
	}

	gcpScheduler(t, db, f, time.Now()).RunOnce(context.Background(), schedInterval)
	if g := coverageOf(t, db, ws, revoked).Generation; g != 0 {
		t.Fatalf("scanned a revoked connector (generation %d)", g)
	}

	// Blocked: readiness verdict says it cannot be scanned.
	blockedWs := newWorkspace(t, db, "gcp-sched-blocked")
	blocked := gcpScanConnector(t, db, blockedWs, "blocked-proj")
	var c models.CloudConnector
	if err := db.Where("id = ?", blocked).First(&c).Error; err != nil {
		t.Fatal(err)
	}
	attrs := c.GCPAttrs()
	attrs.DiscoveryReadiness = models.GCPReadinessBlocked
	_ = c.SetGCPAttrs(attrs)
	if err := db.Model(&models.CloudConnector{}).Where("id = ?", blocked).
		Update("attrs", c.Attrs).Error; err != nil {
		t.Fatal(err)
	}
	gcpScheduler(t, db, f, time.Now()).RunOnce(context.Background(), schedInterval)
	if g := coverageOf(t, db, blockedWs, blocked).Generation; g != 0 {
		t.Fatalf("scanned a blocked connector (generation %d)", g)
	}
}

// Cross-tenant: the scheduler picks connectors across workspaces but each scan
// writes only into its own connector's workspace.
func TestGCPScheduler_ScansEachWorkspaceInIsolation(t *testing.T) {
	db := igaDB(t)
	wsA := newWorkspace(t, db, "gcp-sched-iso-a")
	wsB := newWorkspace(t, db, "gcp-sched-iso-b")
	f := newFakeGCPDiscovery()
	defer f.Close()
	for _, p := range []string{"iso-a", "iso-b"} {
		f.projects = append(f.projects, struct{ id, number string }{p, "1"})
		f.accounts[p] = []fakeGCPAccount{account("uid-"+p, "svc@"+p+".iam.gserviceaccount.com")}
	}
	a := gcpScanConnector(t, db, wsA, "iso-a")
	b := gcpScanConnector(t, db, wsB, "iso-b")

	gcpScheduler(t, db, f, time.Now()).RunOnce(context.Background(), schedInterval)

	if got := countIdentities(t, db, wsA, a); got != 1 {
		t.Fatalf("workspace A identities = %d, want 1", got)
	}
	if got := countIdentities(t, db, wsB, b); got != 1 {
		t.Fatalf("workspace B identities = %d, want 1", got)
	}
	// Neither workspace sees the other's rows.
	if got := countIdentities(t, db, wsA, b); got != 0 {
		t.Fatalf("workspace A sees %d of B's identities", got)
	}
	if got := countIdentities(t, db, wsB, a); got != 0 {
		t.Fatalf("workspace B sees %d of A's identities", got)
	}
}

func TestGCPDiscoveryIntervalFromEnv(t *testing.T) {
	cases := map[string]time.Duration{
		"":       12 * time.Hour,
		"30m":    30 * time.Minute,
		"0":      0,
		"off":    0,
		"banana": 12 * time.Hour,
		"-5m":    12 * time.Hour,
	}
	for raw, want := range cases {
		t.Setenv(services.GCPDiscoveryIntervalEnv, raw)
		if got := services.GCPDiscoveryIntervalFromEnv(); got != want {
			t.Errorf("%q: interval = %v, want %v", raw, got, want)
		}
	}
}
