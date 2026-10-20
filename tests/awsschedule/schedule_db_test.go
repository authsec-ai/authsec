// Package awsschedule_test proves automatic AWS rescans against REAL POSTGRES:
// the real scheduler (services.AWSScanScheduler), the real schedule service
// (Put) and the real repositories, with a fake clock so days pass in
// milliseconds.
//
// Set TEST_DATABASE_URL to a scratch database. Its name must contain "test":
// the schema is dropped and rebuilt with the real migration runner, exactly as
// cmd/main.go builds it on boot.
//
//	TEST_DATABASE_URL="host=localhost port=5430 user=... password=... dbname=authsec_sched_test sslmode=disable" \
//	    go test -count=1 -v ./tests/awsschedule/...
//
// Unset, the suite skips.
package awsschedule_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/migration"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

var (
	buildOnce sync.Once
	buildErr  error
	rawDB     *sql.DB
	gdb       *gorm.DB
)

func dbNameOf(dsn string) string {
	if m := regexp.MustCompile(`dbname=(\S+)`).FindStringSubmatch(dsn); m != nil {
		return m[1]
	}
	if i := strings.LastIndex(dsn, "/"); i >= 0 {
		name := dsn[i+1:]
		if j := strings.IndexAny(name, "?"); j >= 0 {
			name = name[:j]
		}
		return name
	}
	return ""
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the scheduler tests")
	}
	if !strings.Contains(strings.ToLower(dbNameOf(dsn)), "test") {
		t.Fatalf("refusing to run against database %q: the schema is dropped, so its name must contain \"test\"", dbNameOf(dsn))
	}
	buildOnce.Do(func() { buildErr = rebuild(dsn) })
	if buildErr != nil {
		t.Fatalf("build schema: %v", buildErr)
	}
	return gdb
}

func rebuild(dsn string) error {
	var err error
	if rawDB, err = sql.Open("postgres", dsn); err != nil {
		return err
	}
	for _, s := range []string{"DROP SCHEMA IF EXISTS public CASCADE", "CREATE SCHEMA public"} {
		if _, err := rawDB.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	if gdb, err = gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}); err != nil {
		return err
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master"))
	if err != nil {
		return err
	}
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)
	if err := migration.AutoMigrateMigrationLogs(gdb); err != nil {
		return err
	}
	if err := migration.NewMasterMigrationRunner(dir, rawDB, gdb).RunMigrations(); err != nil {
		return err
	}
	var failed int
	if err := rawDB.QueryRow(`SELECT count(*) FROM migration_logs WHERE NOT success`).Scan(&failed); err != nil {
		return err
	}
	if failed > 0 {
		var msg string
		_ = rawDB.QueryRow(`SELECT error_msg FROM migration_logs WHERE NOT success ORDER BY executed_at DESC LIMIT 1`).Scan(&msg)
		return fmt.Errorf("%d failed migration(s): %s", failed, msg)
	}
	return nil
}

// fixture is one workspace with one active AWS connector.
type fixture struct {
	db    *gorm.DB
	ws    uuid.UUID
	id    uuid.UUID
	onb   *services.AWSOnboardingService
	sched *services.AWSScanScheduleService
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testDB(t)
	f := &fixture{db: db, ws: uuid.New(), id: uuid.New()}
	// The connector's workspace_id is a foreign key to workspaces.
	if err := db.Exec(`INSERT INTO workspaces (id, name) VALUES (?, ?)`, f.ws, "sched-test-"+f.ws.String()[:8]).Error; err != nil {
		t.Fatalf("insert workspace: %v", err)
	}
	scope := fmt.Sprintf("%012d", rand.Int63n(1_000_000_000_000))
	// An active connector must hold an auth_ref (cloud_connector_auth_ref_chk);
	// this is only a handle, and nothing here reads a secret.
	if err := db.Exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		VALUES (?, ?, 'aws', 'account', ?, 'test/handle', 'active')`, f.id, f.ws, scope).Error; err != nil {
		t.Fatalf("insert connector: %v", err)
	}
	// The scheduler claims every due schedule in the database, so switch off the
	// ones earlier tests left behind; each test then sees only its own.
	if err := db.Exec(`UPDATE cloud_scan_schedule SET enabled = false WHERE connector_id <> ?`, f.id).Error; err != nil {
		t.Fatalf("isolate fixture: %v", err)
	}
	f.onb = services.NewAWSOnboardingService(db, nil)
	f.sched = services.NewAWSScanScheduleService(db, f.onb)
	return f
}

func (f *fixture) put(t *testing.T, enabled bool, minutes int) *services.ScanScheduleView {
	t.Helper()
	after, _, err := f.sched.Put(context.Background(), f.ws, f.id, enabled, &minutes, "test")
	if err != nil {
		t.Fatalf("Put(enabled=%v, %d): %v", enabled, minutes, err)
	}
	return after
}

// runAt drives exactly one scheduler pass as if it were `at`.
func (f *fixture) runAt(t *testing.T, at time.Time) int {
	t.Helper()
	n, err := services.NewAWSScanScheduler(f.db).WithClock(func() time.Time { return at }).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return n
}

type schedRow struct {
	Enabled        bool
	NextDueAt      *time.Time
	LastEnqueuedAt *time.Time
	PausedReason   string
	StreakSince    *time.Time
}

func (f *fixture) row(t *testing.T) schedRow {
	t.Helper()
	var r schedRow
	if err := f.db.Raw(`SELECT enabled, next_due_at, last_enqueued_at, paused_reason, streak_since
		FROM cloud_scan_schedule WHERE connector_id = ?`, f.id).Scan(&r).Error; err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) runs(t *testing.T, trigger string) (total, live int) {
	t.Helper()
	if err := f.db.Raw(`SELECT count(*), count(*) FILTER (WHERE status IN ('queued','running'))
		FROM cloud_scan_run WHERE connector_id = ? AND "trigger" = ?`, f.id, trigger).Row().Scan(&total, &live); err != nil {
		t.Fatal(err)
	}
	return
}

func within(t *testing.T, what string, got *time.Time, lo, hi time.Time) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is NULL, want between %s and %s", what, lo.Format(time.RFC3339), hi.Format(time.RFC3339))
	}
	if got.Before(lo.Add(-2*time.Second)) || got.After(hi.Add(2*time.Second)) {
		t.Fatalf("%s = %s, want between %s and %s", what, got.Format(time.RFC3339), lo.Format(time.RFC3339), hi.Format(time.RFC3339))
	}
}

const jitterMax = 30 * time.Minute

// The whole life of a schedule, one step at a time.
func TestScheduleRunsOnItsOwn(t *testing.T) {
	f := newFixture(t)
	base := time.Now()
	interval := 24 * time.Hour

	// 1. Turning it on queues nothing: the first scan is one interval away.
	f.put(t, true, 1440)
	if total, _ := f.runs(t, "scheduled"); total != 0 {
		t.Fatalf("turning the schedule on queued %d scan(s); it must never scan at once", total)
	}
	r := f.row(t)
	within(t, "next_due_at after turning on", r.NextDueAt, base.Add(interval), base.Add(interval+jitterMax))
	t.Logf("on: first scan due %s (24h + jitter after now)", r.NextDueAt.Format(time.RFC3339))

	// 2. Before it is due, the scheduler does nothing.
	if n := f.runAt(t, base.Add(1*time.Hour)); n != 0 {
		t.Fatalf("scheduler served %d schedule(s) an hour in; none is due", n)
	}
	if total, _ := f.runs(t, "scheduled"); total != 0 {
		t.Fatalf("a scan was queued before it was due")
	}

	// 3. Once due, exactly one scheduled scan is queued, and the schedule moves
	//    one interval on, anchored on the slot (no drift).
	prevDue := *r.NextDueAt
	if n := f.runAt(t, base.Add(25*time.Hour)); n != 1 {
		t.Fatalf("scheduler served %d schedule(s) when one was due", n)
	}
	total, live := f.runs(t, "scheduled")
	if total != 1 || live != 1 {
		t.Fatalf("after the first slot: %d scheduled run(s), %d queued; want 1 and 1", total, live)
	}
	r = f.row(t)
	if r.LastEnqueuedAt == nil {
		t.Fatal("last_enqueued_at not set after a scan was queued")
	}
	within(t, "next_due_at after the first slot", r.NextDueAt, prevDue.Add(interval), prevDue.Add(interval))
	t.Logf("slot 1: queued 1 scheduled scan; next due %s", r.NextDueAt.Format(time.RFC3339))

	// 4. A second pass at the same moment queues nothing more.
	if n := f.runAt(t, base.Add(25*time.Hour)); n != 0 {
		t.Fatalf("a second pass at the same time served %d schedule(s)", n)
	}
	if total, _ := f.runs(t, "scheduled"); total != 1 {
		t.Fatalf("a repeated pass queued a duplicate: %d scheduled runs", total)
	}

	// 5. The next slot comes while that scan has not finished: it is skipped
	//    (never two live scans), and the schedule still moves on.
	skipAt := base.Add(49 * time.Hour)
	if n := f.runAt(t, skipAt); n != 1 {
		t.Fatalf("scheduler served %d schedule(s) at the second slot", n)
	}
	if total, live := f.runs(t, "scheduled"); total != 1 || live != 1 {
		t.Fatalf("a slot with a scan still live must be skipped: %d run(s), %d live", total, live)
	}
	if nd := f.row(t).NextDueAt; nd == nil || !nd.After(skipAt) {
		t.Fatalf("a skipped slot must still advance the schedule; next_due_at = %v", nd)
	}
	t.Logf("slot 2: previous scan still live, skipped, schedule advanced")

	// 6. When that scan finishes, the following slot queues a fresh one.
	if err := f.db.Exec(`UPDATE cloud_scan_run SET status='published', published_at=now(), generation=1
		WHERE connector_id = ? AND "trigger" = 'scheduled'`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	if n := f.runAt(t, base.Add(100*time.Hour)); n != 1 {
		t.Fatalf("scheduler served %d schedule(s) at the third slot", n)
	}
	if total, live := f.runs(t, "scheduled"); total != 2 || live != 1 {
		t.Fatalf("after the third slot: %d scheduled run(s), %d live; want 2 and 1", total, live)
	}
	t.Logf("slot 3: previous scan finished, a new scheduled scan queued (2 total)")
}

// Two backend replicas ticking at once must queue ONE scan, not two.
func TestTwoReplicasQueueOneScan(t *testing.T) {
	f := newFixture(t)
	f.put(t, true, 1440)
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET next_due_at = now() - interval '1 minute' WHERE connector_id = ?`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(time.Minute)
	var wg sync.WaitGroup
	served := make([]int, 4)
	for i := range served {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, err := services.NewAWSScanScheduler(f.db).WithClock(func() time.Time { return at }).RunOnce(context.Background())
			if err != nil {
				t.Errorf("replica %d: %v", i, err)
			}
			served[i] = n
		}(i)
	}
	wg.Wait()
	sum := 0
	for _, n := range served {
		sum += n
	}
	total, _ := f.runs(t, "scheduled")
	if sum != 1 || total != 1 {
		t.Fatalf("4 replicas ticking at once: served=%v, %d scheduled run(s); want exactly 1 of each", served, total)
	}
	t.Logf("4 replicas, one due schedule: served by exactly one, 1 scan queued")
}

// Three failed scheduled scans in a row pause the schedule; Resume restarts it
// without the old failures pausing it again.
func TestPausesAfterThreeFailuresAndResumes(t *testing.T) {
	f := newFixture(t)
	f.put(t, true, 1440)
	// The failures are stamped from the same (Go) clock that Put uses for the
	// start of the streak, so the test does not depend on the database host's
	// clock agreeing with this one: they come after the streak started, and the
	// pause below comes before the resume.
	failedAt := time.Now().Add(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		// generation > 0: a run that reached a worker has one (cloud_scan_run_generation_chk).
		if err := f.db.Exec(`INSERT INTO cloud_scan_run (workspace_id, connector_id, status, "trigger", generation, last_error, requested_at)
			VALUES (?, ?, 'failed', 'scheduled', 1, 'AccessDenied: role cannot be assumed', ?)`,
			f.ws, f.id, failedAt.Add(time.Duration(i)*time.Millisecond)).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET next_due_at = now() - interval '1 minute' WHERE connector_id = ?`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(time.Hour)
	if n := f.runAt(t, at); n != 1 {
		t.Fatalf("scheduler served %d schedule(s)", n)
	}
	r := f.row(t)
	if !strings.HasPrefix(r.PausedReason, "repeated_failures") {
		t.Fatalf("paused_reason = %q after three failed scans; want repeated_failures", r.PausedReason)
	}
	if total, _ := f.runs(t, "scheduled"); total != 3 {
		t.Fatalf("a paused schedule queued a new scan: %d scheduled runs, want the 3 failures only", total)
	}
	t.Logf("3 failures: paused with reason %q, nothing queued", r.PausedReason)

	// A paused schedule is not served again.
	if n := f.runAt(t, at.Add(48*time.Hour)); n != 0 {
		t.Fatalf("a paused schedule was served (%d)", n)
	}

	// Resume: pause cleared, streak restarted, and the old failures do not
	// pause it again when its next slot comes.
	time.Sleep(100 * time.Millisecond) // the resume must start after the failures it ignores
	after := f.put(t, true, 1440)
	if after.PausedReason != "" {
		t.Fatalf("Resume left paused_reason = %q", after.PausedReason)
	}
	if n := f.runAt(t, time.Now().Add(72*time.Hour)); n != 1 {
		t.Fatalf("resumed schedule served %d at its slot", n)
	}
	r = f.row(t)
	if r.PausedReason != "" {
		t.Fatalf("the failures that caused the pause paused the resumed schedule again: %q", r.PausedReason)
	}
	if _, live := f.runs(t, "scheduled"); live != 1 {
		t.Fatalf("resumed schedule did not queue a scan (live=%d)", live)
	}
	t.Logf("resume: pause cleared, next slot queued a scan, old failures ignored")
}

// Off means off, and a revoked connector's schedule is turned off with it.
func TestOffAndRevokedAreNeverServed(t *testing.T) {
	f := newFixture(t)
	f.put(t, true, 1440)
	f.put(t, false, 1440)
	if r := f.row(t); r.Enabled || r.NextDueAt != nil {
		t.Fatalf("off must clear the schedule: enabled=%v next_due_at=%v", r.Enabled, r.NextDueAt)
	}
	if n := f.runAt(t, time.Now().Add(100*time.Hour)); n != 0 {
		t.Fatalf("a schedule turned off was served (%d)", n)
	}

	g := newFixture(t)
	g.put(t, true, 1440)
	if err := g.onb.RevokeConnector(g.ws, g.id); err != nil {
		t.Fatalf("RevokeConnector: %v", err)
	}
	if r := g.row(t); r.Enabled {
		t.Fatal("revoking the connector left its schedule on")
	}
	if err := g.db.Exec(`UPDATE cloud_scan_schedule SET enabled = true, next_due_at = now() - interval '1 minute' WHERE connector_id = ?`, g.id).Error; err != nil {
		t.Fatal(err)
	}
	if n := g.runAt(t, time.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("a revoked connector was scanned (%d), even with its schedule forced on", n)
	}
	t.Logf("off and revoked: never served")
}

// The interval limits: only daily and weekly are offered, and the database
// refuses anything outside its own range as a second line of defence.
func TestIntervalLimits(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []int{5, 60, 359, 360, 720, 2880, 10081} {
		bad := bad
		if _, _, err := f.sched.Put(context.Background(), f.ws, f.id, true, &bad, "test"); err == nil {
			t.Fatalf("Put accepted interval %d; only daily (1440) and weekly (10080) are offered", bad)
		}
	}
	for _, good := range []int{1440, 10080} {
		good := good
		if _, _, err := f.sched.Put(context.Background(), f.ws, f.id, true, &good, "test"); err != nil {
			t.Fatalf("Put refused interval %d: %v", good, err)
		}
	}
	if err := f.db.Exec(`INSERT INTO cloud_scan_schedule (connector_id, workspace_id, interval_minutes) VALUES (?, ?, 60)`, f.id, f.ws).Error; err == nil {
		t.Fatal("the database accepted a 60-minute interval")
	}
}

// A scan already running when a slot comes due is not a reason to lose the
// slot: the schedule retries within the hour rather than a whole interval later
// (a week, on weekly).
func TestBusyConnectorRetriesSoonNotNextInterval(t *testing.T) {
	f := newFixture(t)
	f.put(t, true, 10080)
	if err := f.db.Exec(`UPDATE cloud_scan_schedule SET next_due_at = now() - interval '1 minute' WHERE connector_id = ?`, f.id).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repositories.NewCloudScanRunRepository(f.db).Enqueue(f.ws, f.id, "manual"); err != nil {
		t.Fatalf("enqueue the manual scan: %v", err)
	}
	at := time.Now().Add(time.Minute)
	if n := f.runAt(t, at); n != 1 {
		t.Fatalf("served %d schedules, want 1", n)
	}
	if total, _ := f.runs(t, "scheduled"); total != 0 {
		t.Fatalf("queued %d scheduled scan(s) beside a live one, want 0", total)
	}
	within(t, "next_due_at", f.row(t).NextDueAt, at.Add(59*time.Minute), at.Add(61*time.Minute))
	t.Logf("busy connector: slot retried in about an hour, not in a week")
}
