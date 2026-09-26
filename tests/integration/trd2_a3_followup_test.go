package integration

// TRD2 integration proofs the graph suite does not replace.
//
// The igraph tests drop public and rebuild it. These run on the migrated
// database the evidence job already applied (IGA_TEST_DSN), plus two private
// databases for the flag-off golden and the 039-shaped migration check.
// IGA_V2_PROJECTION stays off except inside a test that turns it on.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func TestTRD2ITMicrobatchKeepsEveryRun(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	epoch := uuid.New()
	var runs []uuid.UUID
	for i := 1; i <= 3; i++ {
		run := f.seedRun(integ, "runtime_batch", false)
		f.seedObject(integ, run, "Process", fmt.Sprintf("proc-%d", i))
		f.seedBatch(integ, collector, epoch, run, int64(i), uuid.Nil)
		runs = append(runs, run)
	}
	t.Setenv("IGA_V2_PROJECTION", "on")
	if _, err := f.svc().RunOnce(context.Background()); err != nil {
		t.Fatalf("project: %v", err)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, f.ws); n != 1 {
		t.Fatalf("publications = %d, want 1", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1`, f.ws); n != 3 {
		t.Fatalf("support rows = %d, want observations from all 3 runs", n)
	}
	var rev int64
	f.scan(`SELECT graph_revision FROM collector_batches WHERE workspace_id = $1 AND sequence = 1`, []any{f.ws}, &rev)
	for i, run := range runs {
		var got uuid.UUID
		var grev int64
		var state string
		f.scan(`SELECT iga_scan_run_id, graph_revision, projection_state
			FROM collector_batches WHERE workspace_id = $1 AND sequence = $2`,
			[]any{f.ws, int64(i + 1)}, &got, &grev, &state)
		if got != run || grev != rev || rev == 0 || state != "published" {
			t.Fatalf("batch %d run=%s want %s rev=%d/%d state=%s", i+1, got, run, grev, rev, state)
		}
	}
}

func TestTRD2ITSnapshotModeIsPerBatch(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("kubernetes")
	epoch := uuid.New()
	runtime := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, runtime, "Process", "live")
	f.seedBatch(integ, collector, epoch, runtime, 1, uuid.Nil)
	f.exec(`UPDATE collector_outbox SET available_at = now() - interval '1 minute'
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, runtime)

	incompleteRun := f.seedRun(integ, "configuration_snapshot", false)
	f.seedObject(integ, incompleteRun, "Pod", "waiting")
	incomplete := f.seedSnapshot(collector, epoch, "cluster-a", "Pod", false, 1)
	f.seedBatch(integ, collector, epoch, incompleteRun, 2, incomplete)
	f.exec(`UPDATE collector_outbox SET available_at = now() + interval '1 hour'
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, incompleteRun)

	otherEpoch := uuid.New()
	otherRun := f.seedRun(integ, "configuration_snapshot", true)
	f.seedObject(integ, otherRun, "Pod", "other-scope")
	other := f.seedSnapshot(collector, otherEpoch, "cluster-b", "Service", true, 1)
	f.seedBatch(integ, collector, otherEpoch, otherRun, 1, other)

	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "50ms")
	svc := f.svc()
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("runtime: %v", err)
	}
	f.wantPubs(runtime, 1)
	if n := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'ended'`, f.ws); n != 0 {
		t.Fatalf("runtime batch ended %d support rows", n)
	}
	if state := f.batchState(incompleteRun); state != "queued" {
		t.Fatalf("incomplete snapshot projection_state = %s", state)
	}
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("other scope: %v", err)
	}
	var part string
	f.scan(`SELECT partition_key FROM iga_projection_state WHERE workspace_id = $1 AND last_iga_scan_run_id = $2`,
		[]any{f.ws, otherRun}, &part)
	if part != "cluster-b/Service" {
		t.Fatalf("other snapshot partition = %q", part)
	}
	if state := f.batchState(incompleteRun); state != "queued" {
		t.Fatalf("other snapshot pulled the incomplete batch along: %s", state)
	}
	f.exec(`UPDATE collector_snapshots SET complete = true WHERE snapshot_id = $1`, incomplete)
	f.exec(`UPDATE collector_outbox SET state = 'ready', available_at = now(), lease_owner = NULL, leased_until = NULL
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, incompleteRun)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("completed snapshot: %v", err)
	}
	if state := f.batchState(incompleteRun); state != "published" {
		t.Fatalf("completed snapshot state = %s", state)
	}
	f.scan(`SELECT partition_key FROM iga_projection_state WHERE last_iga_scan_run_id = $1`, []any{incompleteRun}, &part)
	if part != "cluster-a/Pod" {
		t.Fatalf("completed snapshot took partition %q", part)
	}
}

func TestTRD2ITStaleGenerationDoesNotEndSupport(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("kubernetes")
	epoch2 := uuid.New()
	run2 := f.seedRun(integ, "configuration_snapshot", true)
	f.seedObject(integ, run2, "Pod", "pod-new")
	snap2 := f.seedSnapshot(collector, epoch2, "cluster-a", "Pod", true, 2)
	f.seedBatch(integ, collector, epoch2, run2, 1, snap2)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := f.svc()
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("G2: %v", err)
	}
	before := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'current'`, f.ws)

	epoch1 := uuid.New()
	run1 := f.seedRun(integ, "configuration_snapshot", true)
	f.seedObject(integ, run1, "Pod", "pod-old")
	snap1 := f.seedSnapshot(collector, epoch1, "cluster-a", "Pod", true, 1)
	f.seedBatch(integ, collector, epoch1, run1, 1, snap1)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("G1: %v", err)
	}
	f.wantPubs(run1, 0)
	if n := f.scalar(`SELECT count(*) FROM collector_batches WHERE iga_scan_run_id = $1 AND superseded_at IS NOT NULL AND projection_state = 'queued'`, run1); n != 1 {
		t.Fatalf("superseded batches = %d", n)
	}
	var receiptID uuid.UUID
	f.scan(`SELECT receipt_id FROM collector_batches WHERE iga_scan_run_id = $1`, []any{run1}, &receiptID)
	raw, err := services.NewCollectorSyncService(f.g, nil).Receipt(&models.CollectorPrincipal{
		WorkspaceID: f.ws, CollectorID: collector, Scopes: []string{models.CollectorScopeReceiptWrite},
	}, receiptID)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	var view struct {
		State           string `json:"state"`
		ProjectionState string `json:"projection_state"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view.State != "superseded" || view.ProjectionState != "superseded" {
		t.Fatalf("receipt = %s", raw)
	}
	after := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'current'`, f.ws)
	if after != before {
		t.Fatalf("support current %d -> %d", before, after)
	}
	var gen int64
	f.scan(`SELECT last_generation FROM iga_projection_state WHERE workspace_id = $1 AND integration_id = $2`, []any{f.ws, integ}, &gen)
	if gen != 2 {
		t.Fatalf("last_generation = %d", gen)
	}
	rt := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, rt, "Process", "still-here")
	f.seedBatch(integ, collector, uuid.New(), rt, 1, uuid.Nil)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("runtime: %v", err)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'ended'`, f.ws); n != 0 {
		t.Fatalf("runtime ended %d support rows", n)
	}
	f.scan(`SELECT last_generation FROM iga_projection_state WHERE workspace_id = $1 AND partition_key = 'cluster-a/Pod'`, []any{f.ws}, &gen)
	if gen != 2 {
		t.Fatalf("runtime moved last_generation to %d", gen)
	}
}

func TestTRD2ITCrashReclaimThenAWS(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, run, "Process", "proc-a")
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := f.svc().WithStopAfterBarrier().WithBeforeCollectorTx(func() {
		f.exec(`UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 minute' WHERE workspace_id = $1`, f.ws)
		f.exec(`UPDATE iga_pipeline_lease SET expires_at = now() - interval '1 minute' WHERE workspace_id = $1`, f.ws)
		f.exec(`UPDATE collector_outbox SET leased_until = now() - interval '1 minute' WHERE workspace_id = $1 AND job_kind = 'collector_project'`, f.ws)
	})
	if _, err := svc.RunOnce(context.Background()); !errors.Is(err, services.ErrCollectorStopped) {
		t.Fatalf("stopped worker: %v", err)
	}
	var jobStatus, barrier string
	f.scan(`SELECT status FROM iga_projection_job WHERE iga_scan_run_id = $1`, []any{run}, &jobStatus)
	f.scan(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, []any{f.ws}, &barrier)
	if jobStatus != models.ProjectionRunning || barrier != models.PipelineProjecting {
		t.Fatalf("after crash job=%s barrier=%s", jobStatus, barrier)
	}
	if err := svc.RecoverStalled(context.Background(), time.Now()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	f.scan(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, []any{f.ws}, &barrier)
	if barrier != models.PipelineProjecting {
		t.Fatalf("recovery released a claimable collector barrier: %s", barrier)
	}
	if _, err := f.svc().RunOnce(context.Background()); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	f.wantPubs(run, 1)
	f.scan(`SELECT status FROM iga_scan_runs WHERE id = $1`, []any{run}, &jobStatus)
	if jobStatus == "failed" {
		t.Fatal("reclaim marked the run failed")
	}
	f.scan(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, []any{f.ws}, &barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("barrier after reclaim = %s", barrier)
	}
	cloud := f.publishedRun(f.connector, 1)
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
		VALUES ($1, $2, $3, $4, 1, 'queued', now())`, jobID, f.ws, cloud, f.connector)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.g)
	ver, err := pipe.AcquireForCollection(f.ws, "aws-scan", cloud, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("AWS acquire after collector reclaim: %v", err)
	}
	if err := f.g.Transaction(func(tx *gorm.DB) error {
		_, err := pipe.ToProjectingTx(tx, f.ws, "aws-scan", cloud, ver, jobID, time.Minute)
		return err
	}); err != nil {
		t.Fatalf("AWS to projecting: %v", err)
	}
	if _, err := f.svc().RunOnce(context.Background()); err != nil {
		t.Fatalf("AWS project: %v", err)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE scan_run_id = $1`, cloud); n != 1 {
		t.Fatalf("AWS publications = %d", n)
	}
}

func TestTRD2ITAttemptsCeilingReleasesBarrier(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, iga_scan_run_id, generation, status, attempts, lease_owner, lease_expires_at)
		VALUES ($1, $2, $3, 1, 'running', 5, 'dead', now() - interval '1 minute')`, jobID, f.ws, run)
	f.exec(`INSERT INTO iga_pipeline_lease
		(workspace_id, state, holder, iga_scan_run_id, expires_at, version)
		VALUES ($1, 'projecting', $2, $3, now() - interval '1 minute', 4)`,
		f.ws, models.PipelineJobHolder(jobID), run)
	t.Setenv("IGA_V2_PROJECTION", "on")
	if err := f.svc().RecoverStalled(context.Background(), time.Now()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	var barrier, outbox string
	f.scan(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, []any{f.ws}, &barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("ceiling left barrier %s", barrier)
	}
	f.scan(`SELECT state FROM collector_outbox WHERE workspace_id = $1 AND job_kind = 'collector_project'`, []any{f.ws}, &outbox)
	if outbox != "failed" {
		t.Fatalf("abandoned run left outbox %s", outbox)
	}
	if _, err := f.svc().RunOnce(context.Background()); err != nil {
		t.Fatalf("run after ceiling: %v", err)
	}
	f.scan(`SELECT state FROM collector_outbox WHERE workspace_id = $1 AND job_kind = 'collector_project'`, []any{f.ws}, &outbox)
	if outbox != "failed" {
		t.Fatalf("outbox requeued after abandon: %s", outbox)
	}
	cloud := f.publishedRun(f.connector, 1)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.g)
	if _, err := pipe.AcquireForCollection(f.ws, "aws-scan", cloud, time.Minute, time.Now()); err != nil {
		t.Fatalf("AWS acquire after ceiling: %v", err)
	}
}

func TestTRD2ITSnapshotProjectsWhole(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("kubernetes")
	epochA := uuid.New()
	runA := f.seedRun(integ, "configuration_snapshot", true)
	for _, name := range []string{"ghost", "p1", "p2", "p3"} {
		f.seedObject(integ, runA, "Pod", name)
	}
	snapA := f.seedSnapshot(collector, epochA, "cluster-a", "Pod", true, 1)
	f.seedBatch(integ, collector, epochA, runA, 9, snapA)

	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "1ms")
	svc := f.svc()
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("prior snapshot: %v", err)
	}
	f.wantPubs(runA, 1)

	epochB := uuid.New()
	snapB := f.seedSnapshot(collector, epochB, "cluster-a", "Pod", true, 1)
	f.exec(`UPDATE collector_snapshots SET expected_chunks = 3 WHERE snapshot_id = $1`, snapB)
	var runs [3]uuid.UUID
	for i := 1; i <= 3; i++ {
		runs[i-1] = f.seedRun(integ, "configuration_snapshot", true)
		f.seedObject(integ, runs[i-1], "Pod", fmt.Sprintf("p%d", i))
		f.seedBatch(integ, collector, epochB, runs[i-1], int64(i), snapB)
	}
	f.exec(`UPDATE collector_outbox SET available_at = now() + interval '1 hour'
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, runs[2])

	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("three-chunk snapshot: %v", err)
	}
	for i, run := range runs {
		if state := f.batchState(run); state != "published" {
			t.Fatalf("chunk %d state = %s", i+1, state)
		}
		if n := f.scalar(`SELECT count(*) FROM collector_batches WHERE iga_scan_run_id = $1 AND superseded_at IS NOT NULL`, run); n != 0 {
			t.Fatalf("chunk %d superseded", i+1)
		}
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, f.ws); n != 2 {
		t.Fatalf("publications = %d, want the prior snapshot plus one pass", n)
	}
	var manifest []byte
	f.scan(`SELECT source_manifest_v2 FROM iga_publication WHERE iga_scan_run_id = $1`, []any{runs[0]}, &manifest)
	var refs []models.SourceManifestRef
	if err := json.Unmarshal(manifest, &refs); err != nil || len(refs) != 3 {
		t.Fatalf("source_manifest_v2 = %s (%v)", manifest, err)
	}
	if got := f.supportState(integ, "Pod", "p3"); got != "current" {
		t.Fatalf("chunk-3 object support = %s", got)
	}
	if got := f.supportState(integ, "Pod", "ghost"); got != "ended" {
		t.Fatalf("absent object support = %s", got)
	}
}

func TestTRD2ITSnapshotReplicasOnePass(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("kubernetes")
	epochA := uuid.New()
	runA := f.seedRun(integ, "configuration_snapshot", true)
	for _, name := range []string{"ghost", "p1", "p2", "p3"} {
		f.seedObject(integ, runA, "Pod", name)
	}
	snapA := f.seedSnapshot(collector, epochA, "cluster-a", "Pod", true, 1)
	f.seedBatch(integ, collector, epochA, runA, 1, snapA)
	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "200ms")
	if _, err := f.svc().RunOnce(context.Background()); err != nil {
		t.Fatalf("prior snapshot: %v", err)
	}

	epochB := uuid.New()
	snapB := f.seedSnapshot(collector, epochB, "cluster-a", "Pod", true, 1)
	f.exec(`UPDATE collector_snapshots SET expected_chunks = 3 WHERE snapshot_id = $1`, snapB)
	var runs [3]uuid.UUID
	for i := 1; i <= 3; i++ {
		runs[i-1] = f.seedRun(integ, "configuration_snapshot", true)
		f.seedObject(integ, runs[i-1], "Pod", fmt.Sprintf("p%d", i))
		f.seedBatch(integ, collector, epochB, runs[i-1], int64(i), snapB)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			svc := services.NewProjectionService(f.g,
				repositories.NewIGAProjectionJobRepository(f.g),
				repositories.NewIGAPipelineLeaseRepository(f.g),
				f.graph, fmt.Sprintf("replica-%d", n), time.Minute).
				WithCollectorWriter(services.FixtureWriter{})
			for k := 0; k < 40; k++ {
				if _, err := svc.RunOnce(context.Background()); err != nil && !errors.Is(err, repositories.ErrPipelineLost) {
					errCh <- err
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if n := f.scalar(`SELECT count(*) FROM collector_batches WHERE snapshot_id = $1 AND projection_state = 'published'`, snapB); n != 3 {
		t.Fatalf("published chunks = %d", n)
	}
	if n := f.scalar(`SELECT count(*) FROM collector_batches WHERE snapshot_id = $1 AND superseded_at IS NOT NULL`, snapB); n != 0 {
		t.Fatalf("superseded chunks = %d", n)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, f.ws); n != 2 {
		t.Fatalf("publications = %d, want one authoritative pass plus the prior snapshot", n)
	}
	for _, name := range []string{"p1", "p2", "p3"} {
		if got := f.supportState(integ, "Pod", name); got != "current" {
			t.Fatalf("%s support = %s", name, got)
		}
	}
	if got := f.supportState(integ, "Pod", "ghost"); got != "ended" {
		t.Fatalf("ghost support = %s", got)
	}
}

func TestTRD2ITConcurrentReplicasOnePublication(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, run, "Process", "once")
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	t.Setenv("IGA_V2_PROJECTION", "on")
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			svc := services.NewProjectionService(f.g,
				repositories.NewIGAProjectionJobRepository(f.g),
				repositories.NewIGAPipelineLeaseRepository(f.g),
				f.graph, fmt.Sprintf("replica-%d", n), time.Minute).
				WithCollectorWriter(services.FixtureWriter{})
			for k := 0; k < 4; k++ {
				if _, err := svc.RunOnce(context.Background()); err != nil && !errors.Is(err, repositories.ErrPipelineLost) {
					errCh <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if n := f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, f.ws); n != 1 {
		t.Fatalf("publications = %d, want 1", n)
	}
	var status string
	f.scan(`SELECT status FROM iga_scan_runs WHERE id = $1`, []any{run}, &status)
	if status == "failed" {
		t.Fatal("run marked failed")
	}
	if n := f.scalar(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = $1 AND status = 'queued'`, f.ws); n != 0 {
		t.Fatalf("orphaned queued jobs = %d", n)
	}
}

func TestTRD2ITSupportWriterLeavesNodesToA4(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, run, "Process", "proc-a")
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := services.NewProjectionService(f.g,
		repositories.NewIGAProjectionJobRepository(f.g),
		repositories.NewIGAPipelineLeaseRepository(f.g),
		f.graph, "proj", time.Minute)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("project: %v", err)
	}
	nodes := f.scalar(`SELECT (SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1) + (SELECT count(*) FROM iga_workload WHERE workspace_id = $1)`, f.ws)
	obs := f.scalar(`SELECT count(*) FROM iga_observations WHERE scan_run_id = $1`, run)
	support := f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1`, f.ws)
	if nodes != 0 || obs != 1 || support != 0 {
		t.Fatalf("nodes=%d observations=%d support=%d", nodes, obs, support)
	}
	key := "collector:" + integ.String() + ":Process:proc-a"
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, source_key, first_seen_at, last_seen_at)
		VALUES ($1, $2, 'proc-a', 'user', $3, now(), now())`, uuid.New(), f.ws, key)
	run2 := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, run2, "Process", "proc-a")
	f.seedBatch(integ, collector, uuid.New(), run2, 1, uuid.Nil)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	support = f.scalar(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND identity_account_id IS NOT NULL`, f.ws)
	nodes = f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1`, f.ws)
	if support != 1 || nodes != 1 {
		t.Fatalf("support=%d identities=%d", support, nodes)
	}
}

func TestTRD2ITSchedulerDoesNotStarveCloud(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	for i := 0; i < 6; i++ {
		run := f.seedRun(integ, "runtime_batch", false)
		f.seedObject(integ, run, "Process", fmt.Sprintf("p-%d", i))
		f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
		f.exec(`UPDATE collector_outbox SET available_at = now() - ($1 || ' seconds')::interval
			WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $2)`, fmt.Sprintf("%d", 30-i), run)
	}
	scan := uuid.New()
	conn := f.addConnector("111111111199")
	f.exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status)
		VALUES ($1, $2, $3, 1, 'queued')`, scan, f.ws, conn)
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
		VALUES ($1, $2, $3, $4, 1, 'queued', now() - interval '1 hour')`,
		uuid.New(), f.ws, scan, conn)
	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "1ms")
	start := time.Now()
	svc := f.svc().WithBeforeCollectorTx(func() { time.Sleep(30 * time.Millisecond) })
	var original time.Time
	f.scan(`SELECT requested_at FROM iga_projection_job WHERE scan_run_id = $1`, []any{scan}, &original)
	var cloudMoved bool
	var published int
	for time.Since(start) < 700*time.Millisecond {
		_, _ = svc.RunOnce(context.Background())
		var req time.Time
		f.scan(`SELECT requested_at FROM iga_projection_job WHERE scan_run_id = $1`, []any{scan}, &req)
		if !req.Equal(original) {
			cloudMoved = true
		}
		published = f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id IS NOT NULL`, f.ws)
		if cloudMoved && published > 0 && published < 6 {
			return
		}
	}
	t.Fatalf("cloudMoved=%v collector publications=%d", cloudMoved, published)
}

func TestTRD2ITSchedulerDoesNotStarveCollector(t *testing.T) {
	f := newA3(t)
	integ, collector, _ := f.seedCollector("linux")
	run := f.seedRun(integ, "runtime_batch", false)
	f.seedObject(integ, run, "Process", "proc-a")
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	for i := 0; i < 8; i++ {
		scan := uuid.New()
		conn := f.addConnector(fmt.Sprintf("2111111111%02d", i))
		f.exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status)
			VALUES ($1, $2, $3, 1, 'queued')`, scan, f.ws, conn)
		f.exec(`INSERT INTO iga_projection_job
			(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
			VALUES ($1, $2, $3, $4, 1, 'queued', now() - interval '1 hour')`,
			uuid.New(), f.ws, scan, conn)
	}
	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "200ms")
	svc := f.svc().WithCloudHold(40 * time.Millisecond)
	start := time.Now()
	for time.Since(start) < 250*time.Millisecond {
		_, _ = svc.RunOnce(context.Background())
		if f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id = $2`, f.ws, run) == 1 {
			return
		}
	}
	t.Fatalf("collector publication was not committed within the microbatch bound (%s)", time.Since(start))
}

func TestTRD2ITT06MixedSources(t *testing.T) {
	f := newA3(t)
	linuxInteg, linuxCol, _ := f.seedCollector("linux")
	k8sInteg, k8sCol, _ := f.seedCollector("kubernetes")
	linuxRun := f.seedRun(linuxInteg, "runtime_batch", false)
	f.seedObject(linuxInteg, linuxRun, "Process", "sshd")
	f.seedBatch(linuxInteg, linuxCol, uuid.New(), linuxRun, 1, uuid.Nil)
	k8sRun := f.seedRun(k8sInteg, "configuration_snapshot", true)
	f.seedObject(k8sInteg, k8sRun, "Pod", "api")
	epoch := uuid.New()
	snap := f.seedSnapshot(k8sCol, epoch, "cluster-a", "Pod", true, 1)
	f.seedBatch(k8sInteg, k8sCol, epoch, k8sRun, 1, snap)

	cloud := f.publishedRun(f.connector, 1)
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status)
		VALUES ($1, $2, $3, $4, 1, 'queued')`, jobID, f.ws, cloud, f.connector)
	t.Setenv("IGA_V2_PROJECTION", "on")
	pipe := repositories.NewIGAPipelineLeaseRepository(f.g)
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			ver, err := pipe.AcquireForCollection(f.ws, "aws-scan", cloud, time.Minute, time.Now())
			if err != nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			err = f.g.Transaction(func(tx *gorm.DB) error {
				_, err := pipe.ToProjectingTx(tx, f.ws, "aws-scan", cloud, ver, jobID, time.Minute)
				return err
			})
			if err != nil {
				errCh <- err
			}
			return
		}
		errCh <- fmt.Errorf("AWS scan never acquired the barrier")
	}()
	go func() {
		defer wg.Done()
		svc := f.svc()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := svc.RunOnce(context.Background()); err != nil && !errors.Is(err, repositories.ErrPipelineLost) {
				errCh <- err
				return
			}
			if f.scalar(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, f.ws) >= 3 {
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	linuxN := f.scalar(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, linuxRun)
	k8sN := f.scalar(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, k8sRun)
	awsN := f.scalar(`SELECT count(*) FROM iga_publication WHERE scan_run_id = $1`, cloud)
	if linuxN != 1 || k8sN != 1 || awsN != 1 {
		t.Fatalf("publications linux=%d k8s=%d aws=%d", linuxN, k8sN, awsN)
	}
	_, _ = f.svc().RunOnce(context.Background())
	var barrier string
	f.scan(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, []any{f.ws}, &barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("barrier left %s", barrier)
	}
}

// TestTRD2ITFlagOffGoldenAndMigration applies 001–039 and 001–040, projects the
// same AWS estate with the flag off, and requires the publication, edge,
// support and evidence business columns to match. It then loads AD and GitHub
// rows (GitHub connector_id null), applies 040 and the validate script, and
// requires those rows and the mode check to be unchanged. Re-applying 040 is
// a no-op. A collector batch on the 040 database stays queued.
func TestTRD2ITFlagOffGoldenAndMigration(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	t.Setenv("IGA_V2_PROJECTION", "")

	db039 := openFreshDB(t, dsn, "authsec_it_golden039")
	applyMaster(t, db039, true)
	g039 := openGorm(t, db039)
	ws, conn, runID := seedGoldenEstate(t, db039)
	projectEstate(t, g039, runID)
	golden := businessDigest(t, db039, ws)
	if !strings.Contains(golden, "pub|") || !strings.Contains(golden, "sup|") {
		t.Fatalf("039 projection wrote no publication or support:\n%s", golden)
	}
	if !strings.Contains(golden, "aee|") && !strings.Contains(golden, "ree|") {
		t.Fatalf("039 projection wrote no evidence rows:\n%s", golden)
	}
	modeBefore := constraintDef(t, db039, "iga_observations_mode_chk")
	scanModeBefore := constraintDef(t, db039, "iga_scan_runs_mode_chk")
	grandfather := grandfatherDigest(t, db039, ws)

	db040 := openFreshDB(t, dsn, "authsec_it_golden040")
	applyMaster(t, db040, false)
	if validated := constraintValidated(t, db040, "iga_object_support_arm_xor"); validated {
		t.Fatal("040 validated iga_object_support_arm_xor inside the deploy transaction")
	}
	g040 := openGorm(t, db040)
	seedGoldenEstate(t, db040)
	projectEstate(t, g040, runID)
	got := businessDigest(t, db040, ws)
	if got != golden {
		t.Fatalf("flag-off 040 business columns differ from 039\n--- 039\n%s\n--- 040\n%s", golden, got)
	}
	if n := scalarDB(t, db040, `SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND integration_id IS NOT NULL`, ws); n != 0 {
		t.Fatalf("cloud support rows set integration_id: %d", n)
	}
	if n := scalarDB(t, db040, `SELECT count(*) FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id IS NOT NULL`, ws); n != 0 {
		t.Fatalf("cloud publications set iga_scan_run_id: %d", n)
	}

	// Collector work stays queued while the flag is off.
	integ := uuid.MustParse("23232323-2323-2323-2323-232323232323")
	col := uuid.MustParse("12121212-1212-1212-1212-121212121212")
	src := uuid.MustParse("13131313-1313-1313-1313-131313131313")
	scope := uuid.MustParse("14141414-1414-1414-1414-141414141414")
	crun := uuid.MustParse("15151515-1515-1515-1515-151515151515")
	execDB(t, db040, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1,$2,'linux','local',$3,'active')`, integ, ws, integ.String())
	execDB(t, db040, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, source_key, display_name)
		VALUES ($1,$2,'host',$3,'scope')`, scope, ws, "scope-"+scope.String())
	execDB(t, db040, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1,$2,'k8s_webhook',$3)`, src, ws, "src-"+src.String())
	execDB(t, db040, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1,$2,$3,$4,$5,'linux_collector',$6,$7)`, col, ws, src, scope, integ, "key-"+col.String(), []byte("pub"))
	execDB(t, db040, `INSERT INTO iga_scan_runs (id, workspace_id, integration_id, mode, generation, status, is_authoritative, completed_at)
		VALUES ($1,$2,$3,'runtime_batch',1,'succeeded',false, now())`, crun, ws, integ)
	batch := uuid.New()
	execDB(t, db040, `INSERT INTO collector_batches
		(id, workspace_id, collector_id, epoch, sequence, batch_id, payload_hash, receipt_id, receipt_state, projection_state, iga_scan_run_id)
		VALUES ($1,$2,$3,$4,1,$5,'h',$6,'accepted','queued',$7)`,
		batch, ws, col, uuid.New(), uuid.New(), uuid.New(), crun)
	execDB(t, db040, `INSERT INTO collector_outbox
		(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key, state)
		VALUES ($1,$2,$3,$4,$5,'collector_project',$6,'ready')`, uuid.New(), ws, integ, col, batch, "batch:"+batch.String())
	svc := services.NewProjectionService(g040,
		repositories.NewIGAProjectionJobRepository(g040),
		repositories.NewIGAPipelineLeaseRepository(g040),
		repositories.NewIGAGraphRepository(), "proj", time.Minute)
	if worked, err := svc.RunOnce(context.Background()); err != nil || worked {
		t.Fatalf("flag off RunOnce = worked %v err %v", worked, err)
	}
	var outbox string
	if err := db040.QueryRow(`SELECT state FROM collector_outbox WHERE workspace_id = $1 AND job_kind = 'collector_project'`, ws).Scan(&outbox); err != nil || outbox != "ready" {
		t.Fatalf("collector outbox = %q err %v", outbox, err)
	}

	applyFile(t, db039, filepath.Join("..", "..", "migrations", "master", "040_trd2_typed_provenance.sql"))
	if businessDigest(t, db039, ws) != golden {
		t.Fatal("applying 040 changed business columns of the 039 projection")
	}
	if grandfatherDigest(t, db039, ws) != grandfather {
		t.Fatal("applying 040 changed AD or GitHub grandfather rows")
	}
	if constraintDef(t, db039, "iga_observations_mode_chk") != modeBefore {
		t.Fatal("040 changed iga_observations_mode_chk")
	}
	if constraintDef(t, db039, "iga_scan_runs_mode_chk") != scanModeBefore {
		t.Fatal("040 changed iga_scan_runs_mode_chk")
	}
	applyFile(t, db039, filepath.Join("..", "..", "scripts", "validate-040-typed-provenance.sql"))
	applyFile(t, db039, filepath.Join("..", "..", "migrations", "master", "040_trd2_typed_provenance.sql"))
	applyFile(t, db040, filepath.Join("..", "..", "scripts", "validate-040-typed-provenance.sql"))
	applyFile(t, db040, filepath.Join("..", "..", "migrations", "master", "040_trd2_typed_provenance.sql"))
	if !constraintValidated(t, db039, "iga_object_support_arm_xor") || !constraintValidated(t, db040, "iga_publication_iga_run_fkey") {
		t.Fatal("validate script left a 040 constraint NOT VALID")
	}
	for _, table := range []string{"iga_integrations", "iga_scan_runs", "iga_observations"} {
		n := scalarDB(t, db039, `SELECT count(*) FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid
			WHERE r.relname = $1 AND c.contype IN ('u','p')
			  AND (SELECT array_agg(a.attname::text ORDER BY k.ord)
			         FROM unnest(c.conkey) WITH ORDINALITY k(num, ord)
			         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num)
			      = ARRAY['workspace_id','id']::text[]`, table)
		if n != 1 {
			t.Fatalf("%s UNIQUE(workspace_id, id) count = %d", table, n)
		}
	}
	_ = conn
}

/* --------------------------------- harness -------------------------------- */

type a3 struct {
	t         *testing.T
	g         *gorm.DB
	db        *sql.DB
	ws        uuid.UUID
	connector uuid.UUID
	graph     repositories.IGAGraphRepository
}

func newA3(t *testing.T) *a3 {
	t.Helper()
	g := igaDB(t)
	db, err := g.DB()
	if err != nil {
		t.Fatal(err)
	}
	ws := newWorkspace(t, g, "trd2-it-"+uuid.NewString()[:8])
	conn := uuid.New()
	if _, err := db.Exec(`INSERT INTO cloud_connector
		(id, workspace_id, provider, scope_kind, scope_id, auth_ref)
		VALUES ($1, $2, 'aws', 'account', '111111111111', 'vault://a')`, conn, ws); err != nil {
		t.Fatal(err)
	}
	return &a3{t: t, g: g, db: db, ws: ws, connector: conn, graph: repositories.NewIGAGraphRepository()}
}

func (f *a3) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(q, args...); err != nil {
		f.t.Fatalf("exec %s: %v", q, err)
	}
}

func (f *a3) scalar(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(q, args...).Scan(&n); err != nil {
		f.t.Fatalf("query %s: %v", q, err)
	}
	return n
}

func (f *a3) scan(q string, args []any, dest ...any) {
	f.t.Helper()
	if err := f.db.QueryRow(q, args...).Scan(dest...); err != nil {
		f.t.Fatalf("scan %s: %v", q, err)
	}
}

func (f *a3) svc() *services.ProjectionService {
	return services.NewProjectionService(f.g,
		repositories.NewIGAProjectionJobRepository(f.g),
		repositories.NewIGAPipelineLeaseRepository(f.g),
		f.graph, "proj", time.Minute).
		WithCollectorWriter(services.FixtureWriter{})
}

func (f *a3) wantPubs(run uuid.UUID, n int) {
	f.t.Helper()
	if got := f.scalar(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, run); got != n {
		f.t.Fatalf("publications for %s = %d, want %d", run, got, n)
	}
}

func (f *a3) supportState(integ uuid.UUID, objectType, name string) string {
	f.t.Helper()
	key := fmt.Sprintf("collector:%s:%s:%s", integ, objectType, name)
	var state string
	f.scan(`SELECT s.state FROM iga_object_support s
		LEFT JOIN iga_workload w ON w.id = s.workload_id
		LEFT JOIN iga_identity_accounts i ON i.id = s.identity_account_id
		WHERE s.workspace_id = $1 AND (w.source_key = $2 OR i.source_key = $2)`,
		[]any{f.ws, key}, &state)
	return state
}

func (f *a3) batchState(run uuid.UUID) string {
	f.t.Helper()
	var state string
	f.scan(`SELECT projection_state FROM collector_batches WHERE iga_scan_run_id = $1`, []any{run}, &state)
	return state
}

func (f *a3) addConnector(account string) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
		VALUES ($1, $2, 'aws', 'account', $3, 'vault://b')`, id, f.ws, account)
	return id
}

func (f *a3) publishedRun(connector uuid.UUID, generation int) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO cloud_scan_run
		(id, workspace_id, connector_id, generation, status, published_at, coverage)
		VALUES ($1,$2,$3,$4,'published', now(), '{}')`, id, f.ws, connector, generation)
	return id
}

func (f *a3) seedCollector(provider string) (integ, collector, scope uuid.UUID) {
	f.t.Helper()
	integ, scope, collector = uuid.New(), uuid.New(), uuid.New()
	src := uuid.New()
	f.exec(`INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, $3, 'local', $4, 'active')`, integ, f.ws, provider, integ.String())
	f.exec(`INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, source_key, display_name)
		VALUES ($1, $2, 'host', $3, 'scope')`, scope, f.ws, "scope-"+scope.String())
	f.exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name)
		VALUES ($1, $2, 'k8s_webhook', $3)`, src, f.ws, "src-"+src.String())
	f.exec(`INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'k8s_collector', $6, $7)`,
		collector, f.ws, src, scope, integ, "key-"+collector.String(), []byte("pub"))
	return integ, collector, scope
}

func (f *a3) seedRun(integ uuid.UUID, mode string, authoritative bool) uuid.UUID {
	f.t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status, is_authoritative, completed_at)
		VALUES ($1, $2, $3, $4, 1, 'succeeded', $5, now())`, id, f.ws, integ, mode, authoritative)
	return id
}

func (f *a3) seedObject(integ, run uuid.UUID, objectType, name string) {
	f.t.Helper()
	var obj uuid.UUID
	err := f.db.QueryRow(`SELECT id FROM iga_source_objects
		WHERE workspace_id = $1 AND integration_id = $2 AND object_type = $3 AND recognition_key = $4`,
		f.ws, integ, objectType, name).Scan(&obj)
	if err != nil {
		obj = uuid.New()
		f.exec(`INSERT INTO iga_source_objects (id, workspace_id, integration_id, object_type, recognition_key)
			VALUES ($1, $2, $3, $4, $5)`, obj, f.ws, integ, objectType, name)
	}
	obs := uuid.New()
	f.exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		VALUES ($1, $2, $3, $4, 'platform_declared', now(), $5)`, obs, f.ws, obj, run, obs.String())
}

func (f *a3) seedSnapshot(collector, epoch uuid.UUID, scope, class string, complete bool, generation int64) uuid.UUID {
	f.t.Helper()
	snapID := uuid.New()
	f.exec(`INSERT INTO collector_snapshots
		(id, workspace_id, collector_id, snapshot_id, epoch, scope_key, object_class, generation, expected_chunks, complete, gap_blocked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, false)`,
		uuid.New(), f.ws, collector, snapID, epoch, scope, class, generation, complete)
	return snapID
}

func (f *a3) seedBatch(integ, collector, epoch, run uuid.UUID, sequence int64, snap uuid.UUID) {
	f.t.Helper()
	var snapArg any
	if snap != uuid.Nil {
		snapArg = snap
	}
	batch := uuid.New()
	f.exec(`INSERT INTO collector_batches
		(id, workspace_id, collector_id, epoch, sequence, batch_id, payload_hash, receipt_id,
		 receipt_state, projection_state, iga_scan_run_id, snapshot_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'h', $7, 'accepted', 'queued', $8, $9)`,
		batch, f.ws, collector, epoch, sequence, uuid.New(), uuid.New(), run, snapArg)
	f.exec(`INSERT INTO collector_outbox
		(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key, state)
		VALUES ($1, $2, $3, $4, $5, 'collector_project', $6, 'ready')`,
		uuid.New(), f.ws, integ, collector, batch, "batch:"+batch.String())
}

/* --------------------------- golden / migration --------------------------- */

const (
	goldenWS      = "11111111-1111-1111-1111-111111111111"
	goldenConn    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	goldenRun     = "44444444-4444-4444-4444-444444444444"
	goldenRole    = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	goldenLambda  = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	goldenPolicy  = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	goldenAttach  = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	goldenRoleARN = "arn:aws:iam::123456789012:role/refund"
	goldenPolARN  = "arn:aws:iam::123456789012:policy/RefundS3Access"
	goldenFnARN   = "arn:aws:lambda:eu-central-1:123456789012:function:refund-processor"
	goldenPolDoc  = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadRefunds","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::refunds-bucket/*"}]}`
)

func seedGoldenEstate(t *testing.T, db *sql.DB) (ws, conn, run uuid.UUID) {
	t.Helper()
	ws = uuid.MustParse(goldenWS)
	conn = uuid.MustParse(goldenConn)
	run = uuid.MustParse(goldenRun)
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, 'golden')`, ws)
	execDB(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		VALUES ($1,$2,'aws','account','123456789012','vault://shaped','active')`, conn, ws)
	// The projector upserts this scope. A fixed id keeps partition keys identical
	// on the 039 and 040 databases.
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, source_key, display_name, stage)
		VALUES ('10101010-1010-1010-1010-101010101010',$1,'account',$2,'123456789012','unknown')`,
		ws, igraph.ScopeKey("aws", "account", "123456789012"))
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ('33333333-3333-3333-3333-333333333333',$1,'github','github.com','gh','active')`, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ('22222222-2222-2222-2222-222222222222',$1,'ad','corp.local','ad','active')`, ws)
	execDB(t, db, `INSERT INTO iga_scan_runs (id, workspace_id, integration_id, mode, generation, status, is_authoritative, completed_at)
		VALUES ('45454545-4545-4545-4545-454545454545',$1,'22222222-2222-2222-2222-222222222222','full',1,'succeeded',false, now())`, ws)
	execDB(t, db, `INSERT INTO sync_configurations (id, workspace_id, client_id, sync_type, config_name)
		VALUES ('55555555-5555-5555-5555-555555555555',$1,'66666666-6666-6666-6666-666666666666','active_directory','corp')`, ws)
	execDB(t, db, `INSERT INTO ad_inventory_runs (id, workspace_id, sync_config_id, integration_id, scan_run_id, status, mode, objects_seen)
		VALUES ('77777777-7777-7777-7777-777777777777',$1,'55555555-5555-5555-5555-555555555555','22222222-2222-2222-2222-222222222222','45454545-4545-4545-4545-454545454545','succeeded','full',7)`, ws)
	execDB(t, db, `INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
		VALUES ('88888888-8888-8888-8888-888888888888',$1,'alice','user','github','gh:alice')`, ws)
	execDB(t, db, `INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
		VALUES ('99999999-9999-9999-9999-999999999999',$1,'eng','group','github','gh:eng')`, ws)
	execDB(t, db, `INSERT INTO iga_relationship
		(id, workspace_id, relationship_type, source_identity_account_id, target_identity_account_id, source_key, basis, state)
		VALUES ('048d1dba-ab86-44ed-ac10-a774d42d1608',$1,'member_of','88888888-8888-8888-8888-888888888888','99999999-9999-9999-9999-999999999999','gh:alice|member_of|gh:eng','declared','current')`, ws)

	cov, err := json.Marshal(models.ScanCoverage{
		Generation: 1, Status: "complete",
		Surfaces: map[string]models.SurfaceCoverage{
			models.SurfaceIAMRoles:           {State: models.CloudCoverageReached, Count: 1},
			models.SurfaceIAMUsers:           {State: models.CloudCoverageReached, Count: 0},
			models.SurfaceIAMGroups:          {State: models.CloudCoverageReached, Count: 0},
			models.SurfaceIAMPolicies:        {State: models.CloudCoverageReached, Count: 1},
			"lambda:eu-central-1":            {State: models.CloudCoverageReached, Count: 1},
			"ecs:eu-central-1":               {State: models.CloudCoverageReached, Count: 0},
			"ec2:eu-central-1":               {State: models.CloudCoverageReached, Count: 0},
			"bedrock-agents:eu-central-1":    {State: models.CloudCoverageReached, Count: 0},
			"bedrock-agentcore:eu-central-1": {State: models.CloudCoverageReached, Count: 0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	execDB(t, db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at, coverage)
		VALUES ($1,$2,$3,1,'published', now(), $4)`, run, ws, conn, cov)
	execDB(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
		VALUES ($1,$2,$3,'iam_role',$4,'refund','{"unique_id":"AROAEXAMPLE"}',1)`, uuid.MustParse(goldenRole), ws, conn, goldenRoleARN)
	execDB(t, db, `INSERT INTO cloud_workload (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, last_seen_generation)
		VALUES ($1,$2,$3,$4,'lambda_function',$5,'refund-processor','eu-central-1',1)`,
		uuid.MustParse(goldenLambda), ws, conn, uuid.MustParse(goldenRole), goldenFnARN)
	execDB(t, db, `INSERT INTO cloud_policy (id, workspace_id, connector_id, policy_kind, native_id, name, policy_id, version_id, document, document_hash, last_seen_generation)
		VALUES ($1,$2,$3,'managed',$4,'RefundS3Access','ANPA7QEXAMPLE','v2',$5::jsonb,'h1',1)`,
		uuid.MustParse(goldenPolicy), ws, conn, goldenPolARN, goldenPolDoc)
	execDB(t, db, `INSERT INTO cloud_policy_attachment (id, workspace_id, connector_id, policy_row_id, principal_identity_id, attachment_kind, last_seen_generation)
		VALUES ($1,$2,$3,$4,$5,'attached',1)`,
		uuid.MustParse(goldenAttach), ws, conn, uuid.MustParse(goldenPolicy), uuid.MustParse(goldenRole))
	for _, obs := range []struct {
		id, kind, native, col string
	}{
		{"a11aaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "identity", goldenRoleARN, "identity_id"},
		{"a22aaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "policy", goldenPolARN, "policy_id"},
		{"a33aaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "workload", goldenFnARN, "workload_id"},
	} {
		subject := uuid.MustParse(goldenRole)
		if obs.kind == "policy" {
			subject = uuid.MustParse(goldenPolicy)
		}
		if obs.kind == "workload" {
			subject = uuid.MustParse(goldenLambda)
		}
		execDB(t, db, fmt.Sprintf(`INSERT INTO cloud_observation
			(id, workspace_id, connector_id, scan_run_id, generation, source_api, observed_at, content_hash, subject_native_id, %s, last_confirmed_run_id)
			VALUES ($1,$2,$3,$4,1,'iam:GetRole', now(), $5, $6, $7, $4)`, obs.col),
			uuid.MustParse(obs.id), ws, conn, run, "h-"+obs.kind, obs.native, subject)
	}
	return ws, conn, run
}

type goldenFencer struct{}

func (goldenFencer) AssertOwnedTx(*gorm.DB, uuid.UUID, string, int64) error { return nil }
func (goldenFencer) AssertHeldTx(*gorm.DB, uuid.UUID, uuid.UUID, int64) error {
	return nil
}

func projectEstate(t *testing.T, g *gorm.DB, run uuid.UUID) {
	t.Helper()
	snap, err := igraph.Load(context.Background(), g, run)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	existing, err := igraph.LoadExisting(context.Background(), g, snap.Run.WorkspaceID)
	if err != nil {
		t.Fatalf("load existing: %v", err)
	}
	now := func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }
	p := igraph.NewProjector(repositories.NewIGAGraphRepository(), goldenFencer{}, existing,
		uuid.MustParse("16161616-1616-1616-1616-161616161616"), "golden", 1, 1, now, igraph.LastGenerationFor)
	rc := igraph.NewReconciler(now)
	err = g.Transaction(func(tx *gorm.DB) error {
		if err := p.Project(tx, snap); err != nil {
			return err
		}
		if err := rc.Reconcile(tx, snap, p.Exclusions(), p.Events()); err != nil {
			return err
		}
		return p.Events().Flush(tx, repositories.NewIGAGraphRepository())
	})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
}

func businessDigest(t *testing.T, db *sql.DB, ws uuid.UUID) string {
	t.Helper()
	const q = `
SELECT coalesce(string_agg(line, E'\n' ORDER BY line), '') FROM (
  SELECT 'pub|' || rev::text || '|' || scan_run_id::text || '|' || manifest::text AS line
    FROM iga_publication WHERE workspace_id = $1
  UNION ALL
  SELECT 'sup|' || s.state || '|' || s.partition_key || '|' || s.ended_reason || '|' ||
         coalesce(s.last_confirmed_run_id::text,'') || '|' || coalesce(s.connector_id::text,'') || '|' ||
         coalesce(i.source_key,'') || '|' || coalesce(w.source_key,'')
    FROM iga_object_support s
    LEFT JOIN iga_identity_accounts i ON i.id = s.identity_account_id
    LEFT JOIN iga_workload w ON w.id = s.workload_id
   WHERE s.workspace_id = $1
  UNION ALL
  SELECT 'edge|' || source_key || '|' || state || '|' || partition_key || '|' || direction || '|' ||
         path_kind || '|' || effective_conclusion || '|' || provider || '|' || basis || '|' || ended_reason
    FROM iga_access_edges WHERE workspace_id = $1
  UNION ALL
  SELECT 'rel|' || relationship_type || '|' || source_key || '|' || state || '|' || basis || '|' ||
         mechanism || '|' || statement_key || '|' || coalesce(connector_id::text,'null')
    FROM iga_relationship WHERE workspace_id = $1
  UNION ALL
  SELECT 'aee|' || relation || '|' || observation_id::text FROM iga_access_edge_evidence WHERE workspace_id = $1
  UNION ALL
  SELECT 'ree|' || relation || '|' || observation_id::text FROM iga_relationship_evidence WHERE workspace_id = $1
  UNION ALL
  SELECT 'ae|' || relation || '|' || observation_id::text FROM iga_assignment_evidence WHERE workspace_id = $1
  UNION ALL
  SELECT 'id|' || source_key || '|' || display_name || '|' || account_kind || '|' || provider
    FROM iga_identity_accounts WHERE workspace_id = $1
  UNION ALL
  SELECT 'wl|' || source_key || '|' || display_name || '|' || runtime_kind || '|' || provider
    FROM iga_workload WHERE workspace_id = $1
) q`
	var out string
	if err := db.QueryRow(q, ws).Scan(&out); err != nil {
		t.Fatalf("digest: %v", err)
	}
	return out
}

func grandfatherDigest(t *testing.T, db *sql.DB, ws uuid.UUID) string {
	t.Helper()
	var out string
	err := db.QueryRow(`
SELECT coalesce(string_agg(line, E'\n' ORDER BY line), '') FROM (
  SELECT 'ad|' || objects_seen::text || '|' || status || '|' || mode || '|' ||
         coalesce(integration_id::text,'') || '|' || coalesce(scan_run_id::text,'') AS line
    FROM ad_inventory_runs WHERE workspace_id = $1
  UNION ALL
  SELECT 'gh|' || relationship_type || '|' || coalesce(connector_id::text,'null') || '|' || state
    FROM iga_relationship WHERE id = '048d1dba-ab86-44ed-ac10-a774d42d1608'
) q`, ws).Scan(&out)
	if err != nil {
		t.Fatalf("grandfather: %v", err)
	}
	return out
}

func openFreshDB(t *testing.T, dsn, name string) *sql.DB {
	t.Helper()
	admin, err := gorm.Open(postgres.Open(swapDB(dsn, "postgres")), &gorm.Config{
		SkipDefaultTransaction: true,
		Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	adb, err := admin.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	if err := admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error; err != nil {
		t.Fatal(err)
	}
	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error
	})
	raw, err := sql.Open("pgx", swapDB(dsn, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func openGorm(t *testing.T, db *sql.DB) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func swapDB(dsn, name string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	u.Path = "/" + name
	return u.String()
}

func applyMaster(t *testing.T, db *sql.DB, through039 bool) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "0*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if through039 && strings.HasPrefix(base, "040") {
			continue
		}
		applyFile(t, db, f)
	}
}

func applyFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("apply %s: %v", filepath.Base(path), err)
	}
}

func execDB(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %s: %v", q, err)
	}
}

func scalarDB(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("scalar %s: %v", q, err)
	}
	return n
}

func constraintDef(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var def string
	if err := db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1`, name).Scan(&def); err != nil {
		t.Fatalf("constraint %s: %v", name, err)
	}
	return def
}

func constraintValidated(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname = $1 AND convalidated`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}
