package igagraph_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func TestTRD2MicrobatchKeepsEveryRun(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	epoch := uuid.New()
	var runs []uuid.UUID
	for i := 1; i <= 3; i++ {
		run := seedRun(t, f, ws, integ, "runtime_batch", false)
		seedObject(t, f, ws, integ, run, "Process", fmt.Sprintf("proc-%d", i))
		seedBatchSnap(t, f, ws, integ, collector, epoch, run, int64(i), uuid.Nil)
		runs = append(runs, run)
	}
	t.Setenv("IGA_V2_PROJECTION", "on")
	if _, err := collectorSvc(f).RunOnce(context.Background()); err != nil {
		t.Fatalf("project: %v", err)
	}
	var pubs int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&pubs)
	if pubs != 1 {
		t.Fatalf("publications = %d, want 1 for the group", pubs)
	}
	var support int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1`, ws).Scan(&support)
	if support != 3 {
		t.Fatalf("support rows = %d, want observations from all 3 runs", support)
	}
	var rev int64
	f.db.QueryRow(`SELECT graph_revision FROM collector_batches WHERE workspace_id = $1 AND sequence = 1`, ws).Scan(&rev)
	for i, run := range runs {
		var got uuid.UUID
		var grev int64
		var state string
		seq := int64(i + 1)
		if err := f.db.QueryRow(`SELECT iga_scan_run_id, graph_revision, projection_state
			FROM collector_batches WHERE workspace_id = $1 AND sequence = $2`, ws, seq).
			Scan(&got, &grev, &state); err != nil {
			t.Fatal(err)
		}
		if got != run || grev != rev || rev == 0 || state != "published" {
			t.Fatalf("batch %d run=%s want %s rev=%d/%d state=%s", seq, got, run, grev, rev, state)
		}
	}
}

func TestTRD2SnapshotModeIsPerBatch(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "kubernetes")
	epoch := uuid.New()
	runtime := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, runtime, "Process", "live")
	seedBatchSnap(t, f, ws, integ, collector, epoch, runtime, 1, uuid.Nil)
	f.exec(`UPDATE collector_outbox SET available_at = now() - interval '1 minute'
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, runtime)

	incompleteRun := seedRun(t, f, ws, integ, "configuration_snapshot", false)
	seedObject(t, f, ws, integ, incompleteRun, "Pod", "waiting")
	incomplete := seedSnapshotGen(t, f, ws, collector, epoch, "cluster-a", "Pod", false, 1)
	seedBatchSnap(t, f, ws, integ, collector, epoch, incompleteRun, 2, incomplete)
	f.exec(`UPDATE collector_outbox SET available_at = now() + interval '1 hour'
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, incompleteRun)

	otherEpoch := uuid.New()
	otherRun := seedRun(t, f, ws, integ, "configuration_snapshot", true)
	seedObject(t, f, ws, integ, otherRun, "Pod", "other-scope")
	other := seedSnapshotGen(t, f, ws, collector, otherEpoch, "cluster-b", "Service", true, 1)
	seedBatchSnap(t, f, ws, integ, collector, otherEpoch, otherRun, 1, other)

	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "50ms")
	svc := collectorSvc(f)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("runtime: %v", err)
	}
	assertOnePublication(t, f, runtime)
	var ended int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'ended'`, ws).Scan(&ended)
	if ended != 0 {
		t.Fatalf("runtime batch ended %d support rows", ended)
	}
	if state := batchState(t, f, incompleteRun); state != "queued" {
		t.Fatalf("incomplete snapshot projection_state = %s", state)
	}

	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("other scope: %v", err)
	}
	var part string
	f.db.QueryRow(`SELECT partition_key FROM iga_projection_state WHERE workspace_id = $1 AND last_iga_scan_run_id = $2`, ws, otherRun).Scan(&part)
	if part != "cluster-b/Service" {
		t.Fatalf("other snapshot partition = %q", part)
	}
	if state := batchState(t, f, incompleteRun); state != "queued" {
		t.Fatalf("other snapshot pulled the incomplete batch along: %s", state)
	}

	f.exec(`UPDATE collector_snapshots SET complete = true WHERE snapshot_id = $1`, incomplete)
	f.exec(`UPDATE collector_outbox SET state = 'ready', available_at = now(), lease_owner = NULL, leased_until = NULL
		WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $1)`, incompleteRun)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("completed snapshot: %v", err)
	}
	if state := batchState(t, f, incompleteRun); state != "published" {
		t.Fatalf("completed snapshot state = %s", state)
	}
	f.db.QueryRow(`SELECT partition_key FROM iga_projection_state WHERE last_iga_scan_run_id = $1`, incompleteRun).Scan(&part)
	if part != "cluster-a/Pod" {
		t.Fatalf("completed snapshot took partition %q", part)
	}
	_ = other
}

func TestTRD2StaleGenerationDoesNotEndSupport(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "kubernetes")
	epoch2 := uuid.New()
	run2 := seedRun(t, f, ws, integ, "configuration_snapshot", true)
	seedObject(t, f, ws, integ, run2, "Pod", "pod-new")
	snap2 := seedSnapshotGen(t, f, ws, collector, epoch2, "cluster-a", "Pod", true, 2)
	seedBatchSnap(t, f, ws, integ, collector, epoch2, run2, 1, snap2)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := collectorSvc(f)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("G2: %v", err)
	}
	var before int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'current'`, ws).Scan(&before)

	epoch1 := uuid.New()
	run1 := seedRun(t, f, ws, integ, "configuration_snapshot", true)
	seedObject(t, f, ws, integ, run1, "Pod", "pod-old")
	snap1 := seedSnapshotGen(t, f, ws, collector, epoch1, "cluster-a", "Pod", true, 1)
	seedBatchSnap(t, f, ws, integ, collector, epoch1, run1, 1, snap1)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("G1: %v", err)
	}
	var pubs int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, run1).Scan(&pubs)
	if pubs != 0 {
		t.Fatalf("stale snapshot published %d revisions", pubs)
	}
	var superseded int
	f.db.QueryRow(`SELECT count(*) FROM collector_batches WHERE iga_scan_run_id = $1 AND superseded_at IS NOT NULL AND projection_state = 'queued'`, run1).Scan(&superseded)
	if superseded != 1 {
		t.Fatalf("superseded batches = %d", superseded)
	}
	var after int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'current'`, ws).Scan(&after)
	if after != before {
		t.Fatalf("support current %d -> %d", before, after)
	}
	var gen int64
	f.db.QueryRow(`SELECT last_generation FROM iga_projection_state WHERE workspace_id = $1 AND integration_id = $2`, ws, integ).Scan(&gen)
	if gen != 2 {
		t.Fatalf("last_generation = %d", gen)
	}

	rt := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, rt, "Process", "still-here")
	seedBatch(t, f, ws, integ, collector, uuid.New(), rt)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("runtime: %v", err)
	}
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'ended'`, ws).Scan(&after)
	if after != 0 {
		t.Fatalf("runtime ended %d support rows", after)
	}
	f.db.QueryRow(`SELECT last_generation FROM iga_projection_state WHERE workspace_id = $1 AND partition_key = 'cluster-a/Pod'`, ws).Scan(&gen)
	if gen != 2 {
		t.Fatalf("runtime moved last_generation to %d", gen)
	}
}

func TestTRD2CrashReclaimThenAWS(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run, "Process", "proc-a")
	seedBatch(t, f, ws, integ, collector, uuid.New(), run)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := collectorSvc(f).WithStopAfterBarrier().WithBeforeCollectorTx(func() {
		f.exec(`UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 minute' WHERE workspace_id = $1`, ws)
		f.exec(`UPDATE iga_pipeline_lease SET expires_at = now() - interval '1 minute' WHERE workspace_id = $1`, ws)
		f.exec(`UPDATE collector_outbox SET leased_until = now() - interval '1 minute' WHERE workspace_id = $1 AND job_kind = 'collector_project'`, ws)
	})
	if _, err := svc.RunOnce(context.Background()); !errors.Is(err, services.ErrCollectorStopped) {
		t.Fatalf("stopped worker: %v", err)
	}
	var jobStatus, barrier string
	f.db.QueryRow(`SELECT status FROM iga_projection_job WHERE iga_scan_run_id = $1`, run).Scan(&jobStatus)
	f.db.QueryRow(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, ws).Scan(&barrier)
	if jobStatus != models.ProjectionRunning || barrier != models.PipelineProjecting {
		t.Fatalf("after crash job=%s barrier=%s", jobStatus, barrier)
	}
	if err := svc.RecoverStalled(context.Background(), time.Now()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	f.db.QueryRow(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, ws).Scan(&barrier)
	if barrier != models.PipelineProjecting {
		t.Fatalf("recovery released a claimable collector barrier: %s", barrier)
	}
	if _, err := collectorSvc(f).RunOnce(context.Background()); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	assertOnePublication(t, f, run)
	f.db.QueryRow(`SELECT status FROM iga_scan_runs WHERE id = $1`, run).Scan(&jobStatus)
	if jobStatus == "failed" {
		t.Fatal("reclaim marked the run failed")
	}
	f.db.QueryRow(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, ws).Scan(&barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("barrier after reclaim = %s", barrier)
	}

	cloud := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
		VALUES ($1, $2, $3, $4, 1, 'queued', now())`, jobID, ws, cloud.ID, f.connector)
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	ver, err := pipe.AcquireForCollection(ws, "aws-scan", cloud.ID, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("AWS acquire after collector reclaim: %v", err)
	}
	if err := f.gorm.Transaction(func(tx *gorm.DB) error {
		_, err := pipe.ToProjectingTx(tx, ws, "aws-scan", cloud.ID, ver, jobID, time.Minute)
		return err
	}); err != nil {
		t.Fatalf("AWS to projecting: %v", err)
	}
	if _, err := collectorSvc(f).RunOnce(context.Background()); err != nil {
		t.Fatalf("AWS project: %v", err)
	}
	var pubs int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE scan_run_id = $1`, cloud.ID).Scan(&pubs)
	if pubs != 1 {
		t.Fatalf("AWS publications = %d", pubs)
	}
}

func TestTRD2AttemptsCeilingReleasesBarrier(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, _, _ := seedCollector(t, f, ws, "linux")
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, iga_scan_run_id, generation, status, attempts, lease_owner, lease_expires_at)
		VALUES ($1, $2, $3, 1, 'running', 5, 'dead', now() - interval '1 minute')`,
		jobID, ws, run)
	f.exec(`INSERT INTO iga_pipeline_lease
		(workspace_id, state, holder, iga_scan_run_id, expires_at, version)
		VALUES ($1, 'projecting', $2, $3, now() - interval '1 minute', 4)`,
		ws, models.PipelineJobHolder(jobID), run)
	t.Setenv("IGA_V2_PROJECTION", "on")
	if err := collectorSvc(f).RecoverStalled(context.Background(), time.Now()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	var barrier string
	f.db.QueryRow(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, ws).Scan(&barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("ceiling left barrier %s", barrier)
	}
	cloud := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	if _, err := pipe.AcquireForCollection(ws, "aws-scan", cloud.ID, time.Minute, time.Now()); err != nil {
		t.Fatalf("AWS acquire after ceiling: %v", err)
	}
}

func TestTRD2ConcurrentReplicasOnePublication(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run, "Process", "once")
	seedBatch(t, f, ws, integ, collector, uuid.New(), run)
	t.Setenv("IGA_V2_PROJECTION", "on")
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			svc := services.NewProjectionService(f.gorm,
				repositories.NewIGAProjectionJobRepository(f.gorm),
				repositories.NewIGAPipelineLeaseRepository(f.gorm),
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
	var pubs int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&pubs)
	if pubs != 1 {
		t.Fatalf("publications = %d, want 1", pubs)
	}
	var status string
	f.db.QueryRow(`SELECT status FROM iga_scan_runs WHERE id = $1`, run).Scan(&status)
	if status == "failed" {
		t.Fatal("run marked failed")
	}
	var queued int
	f.db.QueryRow(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = $1 AND status = 'queued'`, ws).Scan(&queued)
	if queued != 0 {
		t.Fatalf("orphaned queued jobs = %d", queued)
	}
}

func TestTRD2SupportWriterLeavesNodesToA4(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run, "Process", "proc-a")
	seedBatch(t, f, ws, integ, collector, uuid.New(), run)
	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := services.NewProjectionService(f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		f.graph, "proj", time.Minute)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("project: %v", err)
	}
	var nodes, obs, support int
	f.db.QueryRow(`SELECT (SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1)
		+ (SELECT count(*) FROM iga_workload WHERE workspace_id = $1)`, ws).Scan(&nodes)
	f.db.QueryRow(`SELECT count(*) FROM iga_observations WHERE scan_run_id = $1`, run).Scan(&obs)
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1`, ws).Scan(&support)
	if nodes != 0 || obs != 1 || support != 0 {
		t.Fatalf("nodes=%d observations=%d support=%d", nodes, obs, support)
	}
	key := "collector:" + integ.String() + ":Process:proc-a"
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, source_key, first_seen_at, last_seen_at)
		VALUES ($1, $2, 'proc-a', 'user', $3, now(), now())`, uuid.New(), ws, key)
	run2 := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run2, "Process", "proc-a")
	seedBatch(t, f, ws, integ, collector, uuid.New(), run2)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND identity_account_id IS NOT NULL`, ws).Scan(&support)
	f.db.QueryRow(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1`, ws).Scan(&nodes)
	if support != 1 || nodes != 1 {
		t.Fatalf("support=%d identities=%d", support, nodes)
	}
}

func TestTRD2SchedulerDoesNotStarveCloud(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	for i := 0; i < 6; i++ {
		run := seedRun(t, f, ws, integ, "runtime_batch", false)
		seedObject(t, f, ws, integ, run, "Process", fmt.Sprintf("p-%d", i))
		seedBatch(t, f, ws, integ, collector, uuid.New(), run)
		f.exec(`UPDATE collector_outbox SET available_at = now() - ($1 || ' seconds')::interval
			WHERE batch_row_id IN (SELECT id FROM collector_batches WHERE iga_scan_run_id = $2)`, fmt.Sprintf("%d", 30-i), run)
	}
	scan := uuid.New()
	conn := f.addConnector("111111111199")
	f.exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status)
		VALUES ($1, $2, $3, 1, 'queued')`, scan, ws, conn)
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
		VALUES ($1, $2, $3, $4, 1, 'queued', now() - interval '1 hour')`,
		uuid.New(), ws, scan, conn)
	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "1ms")
	start := time.Now()
	svc := collectorSvc(f).WithBeforeCollectorTx(func() { time.Sleep(30 * time.Millisecond) })
	var original time.Time
	f.db.QueryRow(`SELECT requested_at FROM iga_projection_job WHERE scan_run_id = $1`, scan).Scan(&original)
	var cloudMoved bool
	var published int
	for time.Since(start) < 700*time.Millisecond {
		_, _ = svc.RunOnce(context.Background())
		var req time.Time
		f.db.QueryRow(`SELECT requested_at FROM iga_projection_job WHERE scan_run_id = $1`, scan).Scan(&req)
		if !req.Equal(original) {
			cloudMoved = true
		}
		f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id IS NOT NULL`, ws).Scan(&published)
		if cloudMoved && published > 0 && published < 6 {
			return
		}
	}
	t.Fatalf("cloudMoved=%v collector publications=%d", cloudMoved, published)
}

func TestTRD2T06MixedSources(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	linuxInteg, linuxCol, _ := seedCollector(t, f, ws, "linux")
	k8sInteg, k8sCol, _ := seedCollector(t, f, ws, "kubernetes")
	linuxRun := seedRun(t, f, ws, linuxInteg, "runtime_batch", false)
	seedObject(t, f, ws, linuxInteg, linuxRun, "Process", "sshd")
	seedBatch(t, f, ws, linuxInteg, linuxCol, uuid.New(), linuxRun)
	k8sRun := seedRun(t, f, ws, k8sInteg, "configuration_snapshot", true)
	seedObject(t, f, ws, k8sInteg, k8sRun, "Pod", "api")
	epoch := uuid.New()
	snap := seedSnapshotGen(t, f, ws, k8sCol, epoch, "cluster-a", "Pod", true, 1)
	seedBatchSnap(t, f, ws, k8sInteg, k8sCol, epoch, k8sRun, 1, snap)

	cloud := f.publishedRun(f.connector, 1, map[string]models.SurfaceCoverage{})
	jobID := uuid.New()
	f.exec(`INSERT INTO iga_projection_job
		(id, workspace_id, scan_run_id, connector_id, generation, status)
		VALUES ($1, $2, $3, $4, 1, 'queued')`, jobID, ws, cloud.ID, f.connector)
	t.Setenv("IGA_V2_PROJECTION", "on")
	pipe := repositories.NewIGAPipelineLeaseRepository(f.gorm)
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			ver, err := pipe.AcquireForCollection(ws, "aws-scan", cloud.ID, time.Minute, time.Now())
			if err != nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			err = f.gorm.Transaction(func(tx *gorm.DB) error {
				_, err := pipe.ToProjectingTx(tx, ws, "aws-scan", cloud.ID, ver, jobID, time.Minute)
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
		svc := collectorSvc(f)
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := svc.RunOnce(context.Background()); err != nil && !errors.Is(err, repositories.ErrPipelineLost) {
				errCh <- err
				return
			}
			var n int
			f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&n)
			if n >= 3 {
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	var linuxN, k8sN, awsN int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, linuxRun).Scan(&linuxN)
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, k8sRun).Scan(&k8sN)
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE scan_run_id = $1`, cloud.ID).Scan(&awsN)
	if linuxN != 1 || k8sN != 1 || awsN != 1 {
		t.Fatalf("publications linux=%d k8s=%d aws=%d", linuxN, k8sN, awsN)
	}
	_, _ = collectorSvc(f).RunOnce(context.Background())
	var barrier string
	f.db.QueryRow(`SELECT state FROM iga_pipeline_lease WHERE workspace_id = $1`, ws).Scan(&barrier)
	if barrier != models.PipelineIdle {
		t.Fatalf("barrier left %s", barrier)
	}
}

func TestTRD2ChecksWaitForValidateScript(t *testing.T) {
	f := newFixture(t)
	var validated int
	if err := f.db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname = 'iga_object_support_arm_xor' AND convalidated`).Scan(&validated); err != nil {
		t.Fatal(err)
	}
	if validated != 0 {
		t.Fatal("040 added iga_object_support_arm_xor already validated")
	}
	for _, stmt := range []string{
		`ALTER TABLE iga_object_support VALIDATE CONSTRAINT iga_object_support_arm_xor`,
		`ALTER TABLE iga_publication VALIDATE CONSTRAINT iga_publication_iga_run_fkey`,
		`ALTER TABLE iga_pipeline_lease VALIDATE CONSTRAINT iga_pipeline_lease_busy_chk`,
	} {
		if _, err := f.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname = 'iga_object_support_arm_xor' AND convalidated`).Scan(&validated); err != nil || validated != 1 {
		t.Fatalf("after VALIDATE, validated=%d err=%v", validated, err)
	}
}

func collectorSvc(f *fixture) *services.ProjectionService {
	return services.NewProjectionService(f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		f.graph, "proj", time.Minute).
		WithCollectorWriter(services.FixtureWriter{})
}

func assertOnePublication(t *testing.T, f *fixture, run uuid.UUID) {
	t.Helper()
	var n int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE iga_scan_run_id = $1`, run).Scan(&n)
	if n != 1 {
		t.Fatalf("publications for %s = %d", run, n)
	}
}

func batchState(t *testing.T, f *fixture, run uuid.UUID) string {
	t.Helper()
	var state string
	if err := f.db.QueryRow(`SELECT projection_state FROM collector_batches WHERE iga_scan_run_id = $1`, run).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}
