package igagraph_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// B08 and the 040 constraint shape. The catalog guard covers each new foreign
// key; this covers the exactly-one checks, the partial unique index, and a
// collector publication under the workspace fence.
func TestTRD2TypedProvenance(t *testing.T) {
	f := newFixture(t)
	assertProvenanceConstraints(t, f)

	ws := f.workspace
	other := uuid.New()
	f.exec(`INSERT INTO workspaces (id, name) VALUES ($1, 'other')`, other)
	integ := uuid.New()
	otherInteg := uuid.New()
	f.exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, 'kubernetes', 'local', 'app', 'active')`, integ, ws)
	f.exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, 'linux', 'local', 'app-b', 'active')`, otherInteg, other)
	run := uuid.New()
	f.exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status, is_authoritative)
		VALUES ($1, $2, $3, 'runtime_batch', 1, 'succeeded', false)`, run, ws, integ)
	ident := uuid.New()
	f.exec(`INSERT INTO iga_identity_accounts
		(id, workspace_id, display_name, account_kind, source_key, first_seen_at, last_seen_at)
		VALUES ($1, $2, 'n', 'user', $3, now(), now())`, ident, ws, "k-"+ident.String())

	// A collector id in the cloud column is a foreign key miss.
	_, err := f.db.Exec(`INSERT INTO iga_object_support
		(id, workspace_id, identity_account_id, connector_id, partition_key, first_seen_at, last_confirmed_run_id)
		VALUES ($1, $2, $3, $4, 'p', now(), $5)`, uuid.New(), ws, ident, integ, f.connector)
	if err == nil {
		t.Fatal("an integration id in connector_id must be rejected")
	}

	// Both arms, and neither arm.
	_, err = f.db.Exec(`INSERT INTO iga_object_support
		(id, workspace_id, identity_account_id, connector_id, integration_id, partition_key, first_seen_at)
		VALUES ($1, $2, $3, $4, $5, 'p', now())`, uuid.New(), ws, ident, f.connector, integ)
	if err == nil {
		t.Fatal("both provenance arms must be rejected")
	}
	_, err = f.db.Exec(`INSERT INTO iga_object_support
		(id, workspace_id, identity_account_id, partition_key, first_seen_at)
		VALUES ($1, $2, $3, 'p', now())`, uuid.New(), ws, ident)
	if err == nil {
		t.Fatal("neither provenance arm must be rejected")
	}

	// Cross-workspace integration.
	_, err = f.db.Exec(`INSERT INTO iga_object_support
		(id, workspace_id, identity_account_id, integration_id, confirming_iga_scan_run_id, partition_key, first_seen_at)
		VALUES ($1, $2, $3, $4, $5, 'p', now())`, uuid.New(), ws, ident, otherInteg, run)
	if err == nil {
		t.Fatal("a cross-workspace integration must be rejected")
	}

	at := f.clock
	row := models.SupportFromIntegration(ws, integ, run, "part-a", at)
	row.IdentityAccountID = &ident
	if err := f.graph.UpsertObjectSupport(f.gorm, row); err != nil {
		t.Fatalf("collector support upsert: %v", err)
	}
	again := models.SupportFromIntegration(ws, integ, run, "part-a", at.Add(time.Second))
	again.IdentityAccountID = &ident
	if err := f.graph.UpsertObjectSupport(f.gorm, again); err != nil {
		t.Fatalf("second collector support upsert: %v", err)
	}
	var n int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support
		WHERE workspace_id = $1 AND integration_id = $2 AND identity_account_id = $3`,
		ws, integ, ident).Scan(&n)
	if n != 1 {
		t.Fatalf("collector support rows = %d, want 1", n)
	}
}

func TestTRD2CollectorProjectionFence(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, scope := seedCollector(t, f, ws, "kubernetes")
	epoch := uuid.New()
	run := seedRun(t, f, ws, integ, "configuration_snapshot", true)
	pod := seedObject(t, f, ws, integ, run, "Pod", "pod-a")
	user := seedObject(t, f, ws, integ, run, "ServiceAccount", "sa-a")
	snap := seedSnapshotGen(t, f, ws, collector, epoch, "cluster-a", "Pod", true, 1)
	seedBatchSnap(t, f, ws, integ, collector, epoch, run, 1, snap)

	t.Setenv("IGA_V2_PROJECTION", "on")
	svc := services.NewProjectionService(f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		f.graph, "proj", time.Minute).
		WithCollectorWriter(services.FixtureWriter{})
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("project: %v", err)
	}

	var rev int64
	var manifest []byte
	var cloudRun *uuid.UUID
	if err := f.db.QueryRow(`SELECT rev, source_manifest_v2, scan_run_id FROM iga_publication
		WHERE workspace_id = $1 AND iga_scan_run_id = $2`, ws, run).Scan(&rev, &manifest, &cloudRun); err != nil {
		t.Fatalf("publication: %v", err)
	}
	if rev != 1 || cloudRun != nil {
		t.Fatalf("publication rev=%d cloud=%v", rev, cloudRun)
	}
	var refs []models.SourceManifestRef
	if err := json.Unmarshal(manifest, &refs); err != nil || len(refs) != 1 || refs[0].Kind != models.ManifestKindIGAScanRun || refs[0].ID != run {
		t.Fatalf("source_manifest_v2 = %s (%v)", manifest, err)
	}
	var cloudManifest []byte
	if err := f.db.QueryRow(`SELECT manifest FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id = $2`, ws, run).Scan(&cloudManifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	asMap := map[string]string{}
	if err := json.Unmarshal(cloudManifest, &asMap); err != nil {
		t.Fatalf("cloud readers decode manifest as map[string]string: %v (%s)", err, cloudManifest)
	}
	manifestKey := "collector:" + integ.String() + "/cluster-a/Pod"
	if asMap[manifestKey] != run.String() || asMap["cluster-a/Pod"] != "" {
		t.Fatalf("manifest = %s", cloudManifest)
	}
	latest, err := f.graph.LatestManifest(f.gorm, ws)
	if err != nil {
		t.Fatalf("LatestManifest: %v", err)
	}
	if err := json.Unmarshal(latest, &asMap); err != nil || asMap[manifestKey] != run.String() {
		t.Fatalf("LatestManifest = %s (%v)", latest, err)
	}
	assertArm := func(q string, args ...any) {
		t.Helper()
		var integID, cloudID *uuid.UUID
		if err := f.db.QueryRow(q, args...).Scan(&integID, &cloudID); err != nil {
			t.Fatalf("arm %s: %v", q, err)
		}
		if integID == nil || *integID != integ || cloudID != nil {
			t.Fatalf("arm integ=%v cloud=%v", integID, cloudID)
		}
	}
	assertArm(`SELECT integration_id, NULLIF(connector_id, '00000000-0000-0000-0000-000000000000')
		FROM iga_object_support WHERE workspace_id = $1 AND workload_id IS NOT NULL`, ws)
	var obs *uuid.UUID
	f.db.QueryRow(`SELECT iga_observation_id FROM iga_relationship_evidence WHERE workspace_id = $1`, ws).Scan(&obs)
	if obs == nil {
		t.Fatal("relationship evidence has no iga observation")
	}
	_ = pod
	_ = user
	_ = scope

	// Incomplete snapshot ends nothing.
	epoch2 := uuid.New()
	run2 := seedRun(t, f, ws, integ, "configuration_snapshot", false)
	seedObject(t, f, ws, integ, run2, "Pod", "pod-b")
	snap2 := seedSnapshotGen(t, f, ws, collector, epoch2, "cluster-a", "Pod", false, 1)
	seedBatchSnap(t, f, ws, integ, collector, epoch2, run2, 1, snap2)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("incomplete: %v", err)
	}
	var ended int
	f.db.QueryRow(`SELECT count(*) FROM iga_object_support WHERE workspace_id = $1 AND state = 'ended'`, ws).Scan(&ended)
	if ended != 0 {
		t.Fatalf("incomplete snapshot ended %d support rows", ended)
	}

	// Complete snapshot of the same scope and class ends only that class.
	epoch3 := uuid.New()
	run3 := seedRun(t, f, ws, integ, "configuration_snapshot", true)
	seedObject(t, f, ws, integ, run3, "Pod", "pod-b")
	snap3 := seedSnapshotGen(t, f, ws, collector, epoch3, "cluster-a", "Pod", true, 2)
	seedBatchSnap(t, f, ws, integ, collector, epoch3, run3, 1, snap3)
	if _, err := svc.RunOnce(context.Background()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	var podAState, saState string
	f.db.QueryRow(`SELECT s.state FROM iga_object_support s
		JOIN iga_workload w ON w.id = s.workload_id
		WHERE s.workspace_id = $1 AND w.display_name = 'pod-a'`, ws).Scan(&podAState)
	f.db.QueryRow(`SELECT s.state FROM iga_object_support s
		JOIN iga_identity_accounts a ON a.id = s.identity_account_id
		WHERE s.workspace_id = $1 AND a.display_name = 'sa-a'`, ws).Scan(&saState)
	if podAState != models.RelEnded || saState != models.RelCurrent {
		t.Fatalf("absence pod-a=%s sa-a=%s", podAState, saState)
	}

	// Fence steal aborts before publication.
	epoch4 := uuid.New()
	run4 := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run4, "Pod", "pod-c")
	seedBatch(t, f, ws, integ, collector, epoch4, run4)
	var pubsBefore int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&pubsBefore)
	svc.WithBeforeCollectorTx(func() {
		f.exec(`UPDATE iga_pipeline_lease SET version = version + 1 WHERE workspace_id = $1`, ws)
	})
	if _, err := svc.RunOnce(context.Background()); err == nil {
		t.Fatal("a stolen fence must fail the publication")
	}
	var pubsAfter int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&pubsAfter)
	if pubsAfter != pubsBefore {
		t.Fatalf("stolen fence published: before %d after %d", pubsBefore, pubsAfter)
	}
}

func TestTRD2SchedulerDoesNotStarveCollector(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	epoch := uuid.New()
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run, "Process", "proc-a")
	seedBatch(t, f, ws, integ, collector, epoch, run)
	for i := 0; i < 8; i++ {
		scan := uuid.New()
		// One connector may have one live scan. These rows exist so the
		// projection jobs have a cloud run to name; the jobs themselves are
		// what the scheduler must not drain ahead of the collector.
		conn := f.addConnector(fmt.Sprintf("1111111111%02d", i))
		f.exec(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status)
			VALUES ($1, $2, $3, 1, 'queued')`, scan, ws, conn)
		f.exec(`INSERT INTO iga_projection_job
			(id, workspace_id, scan_run_id, connector_id, generation, status, requested_at)
			VALUES ($1, $2, $3, $4, 1, 'queued', now() - interval '1 hour')`,
			uuid.New(), ws, scan, conn)
	}
	t.Setenv("IGA_V2_PROJECTION", "on")
	t.Setenv("IGA_V2_MICROBATCH", "200ms")
	svc := services.NewProjectionService(f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		f.graph, "proj", time.Minute).
		WithCollectorWriter(services.FixtureWriter{}).
		WithCloudHold(40 * time.Millisecond)
	start := time.Now()
	var published bool
	for time.Since(start) < 250*time.Millisecond {
		_, _ = svc.RunOnce(context.Background())
		var n int
		f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1 AND iga_scan_run_id = $2`, ws, run).Scan(&n)
		if n == 1 {
			published = true
			break
		}
	}
	if !published {
		t.Fatalf("collector publication was not committed within the microbatch bound (%s)", time.Since(start))
	}
}

func TestTRD2FlagOffLeavesCollectorQueued(t *testing.T) {
	f := newFixture(t)
	ws := f.workspace
	integ, collector, _ := seedCollector(t, f, ws, "linux")
	epoch := uuid.New()
	run := seedRun(t, f, ws, integ, "runtime_batch", false)
	seedObject(t, f, ws, integ, run, "Process", "proc-a")
	seedBatch(t, f, ws, integ, collector, epoch, run)
	os.Unsetenv("IGA_V2_PROJECTION")
	svc := services.NewProjectionService(f.gorm,
		repositories.NewIGAProjectionJobRepository(f.gorm),
		repositories.NewIGAPipelineLeaseRepository(f.gorm),
		f.graph, "proj", time.Minute).
		WithCollectorWriter(services.FixtureWriter{})
	if worked, err := svc.RunOnce(context.Background()); err != nil || worked {
		t.Fatalf("flag off RunOnce = worked %v err %v", worked, err)
	}
	var state string
	f.db.QueryRow(`SELECT state FROM collector_outbox WHERE workspace_id = $1`, ws).Scan(&state)
	if state != "ready" {
		t.Fatalf("outbox state = %s, want ready", state)
	}
	var pubs int
	f.db.QueryRow(`SELECT count(*) FROM iga_publication WHERE workspace_id = $1`, ws).Scan(&pubs)
	if pubs != 0 {
		t.Fatalf("flag off published %d revisions", pubs)
	}
}

func assertProvenanceConstraints(t *testing.T, f *fixture) {
	t.Helper()
	for _, name := range []string{
		"iga_object_support_arm_xor",
		"iga_relationship_arm_xor",
		"iga_access_edges_arm_xor",
		"iga_policy_assignment_arm_xor",
		"iga_access_edge_evidence_arm_xor",
		"iga_relationship_evidence_arm_xor",
		"iga_assignment_evidence_arm_xor",
		"iga_projection_job_arm_xor",
		"iga_projection_state_arm_xor",
		"iga_publication_arm_xor",
		"iga_pipeline_lease_arm_xor",
		"iga_object_support_integration_fkey",
		"iga_publication_iga_run_fkey",
		"iga_pipeline_lease_iga_run_fkey",
	} {
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conname = $1`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("constraint %s count=%d err=%v", name, n, err)
		}
	}
	for _, name := range []string{
		"uq_iga_os_identity_integration",
		"uq_iga_projection_job_iga_run",
		"uq_iga_projection_state_integration",
		"uq_iga_publication_iga_run",
	} {
		var n int
		if err := f.db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE indexname = $1`, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("index %s count=%d err=%v", name, n, err)
		}
	}
}

func seedCollector(t *testing.T, f *fixture, ws uuid.UUID, provider string) (integ, collector, scope uuid.UUID) {
	t.Helper()
	integ, scope, collector = uuid.New(), uuid.New(), uuid.New()
	src := uuid.New()
	f.exec(`INSERT INTO iga_integrations
		(id, workspace_id, provider, provider_host, app_registration_id, status)
		VALUES ($1, $2, $3, 'local', $4, 'active')`, integ, ws, provider, integ.String())
	f.exec(`INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind, source_key, display_name)
		VALUES ($1, $2, 'host', $3, 'scope')`, scope, ws, "scope-"+scope.String())
	f.exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name)
		VALUES ($1, $2, 'k8s_webhook', $3)`, src, ws, "src-"+src.String())
	f.exec(`INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind,
		 installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'k8s_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String(), []byte("pub"))
	return integ, collector, scope
}

func seedRun(t *testing.T, f *fixture, ws, integ uuid.UUID, mode string, authoritative bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	f.exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status, is_authoritative, completed_at)
		VALUES ($1, $2, $3, $4, 1, 'succeeded', $5, now())`, id, ws, integ, mode, authoritative)
	return id
}

func seedObject(t *testing.T, f *fixture, ws, integ, run uuid.UUID, objectType, name string) uuid.UUID {
	t.Helper()
	var obj uuid.UUID
	err := f.db.QueryRow(`SELECT id FROM iga_source_objects
		WHERE workspace_id = $1 AND integration_id = $2 AND object_type = $3 AND recognition_key = $4`,
		ws, integ, objectType, name).Scan(&obj)
	if err != nil {
		obj = uuid.New()
		f.exec(`INSERT INTO iga_source_objects
			(id, workspace_id, integration_id, object_type, recognition_key)
			VALUES ($1, $2, $3, $4, $5)`, obj, ws, integ, objectType, name)
	}
	obs := uuid.New()
	f.exec(`INSERT INTO iga_observations
		(id, workspace_id, source_object_id, scan_run_id, mode, observed_at, dedupe_key)
		VALUES ($1, $2, $3, $4, 'platform_declared', now(), $5)`,
		obs, ws, obj, run, obs.String())
	return obj
}

func seedSnapshotGen(t *testing.T, f *fixture, ws, collector, epoch uuid.UUID, scope, class string, complete bool, generation int64) uuid.UUID {
	t.Helper()
	snapID := uuid.New()
	f.exec(`INSERT INTO collector_snapshots
		(id, workspace_id, collector_id, snapshot_id, epoch, scope_key, object_class, generation, expected_chunks, complete, gap_blocked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, false)`,
		uuid.New(), ws, collector, snapID, epoch, scope, class, generation, complete)
	return snapID
}

func seedBatch(t *testing.T, f *fixture, ws, integ, collector, epoch, run uuid.UUID) {
	t.Helper()
	seedBatchSnap(t, f, ws, integ, collector, epoch, run, 1, uuid.Nil)
}

func seedBatchSnap(t *testing.T, f *fixture, ws, integ, collector, epoch, run uuid.UUID, sequence int64, snap uuid.UUID) {
	t.Helper()
	batch := uuid.New()
	var snapArg any
	if snap != uuid.Nil {
		snapArg = snap
	}
	f.exec(`INSERT INTO collector_batches
		(id, workspace_id, collector_id, epoch, sequence, batch_id, payload_hash, receipt_id,
		 receipt_state, projection_state, iga_scan_run_id, snapshot_id)
		VALUES ($1, $2, $3, $4, $5, $6, 'h', $7, 'accepted', 'queued', $8, $9)`,
		batch, ws, collector, epoch, sequence, uuid.New(), uuid.New(), run, snapArg)
	f.exec(`INSERT INTO collector_outbox
		(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key, state)
		VALUES ($1, $2, $3, $4, $5, 'collector_project', $6, 'ready')`,
		uuid.New(), ws, integ, collector, batch, "batch:"+batch.String())
}
