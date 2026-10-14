//go:build e2e

// A Kubernetes sighting reaches the shared graph when it is reported, not when
// the cluster's next RBAC snapshot arrives.
//
// Before ProjectSighting a newly sighted agent was missing from iga_workload
// -- and so from the inventory -- and a deleted one still listed, for as long
// as the agent's RBAC sweep interval. These tests pin that the sighting path
// writes the same row the sweep would, with a support row the next sweep
// confirms (one row, not two) or ends, and that it closes nothing on its own.
//
//	K8S_GRAPH_TEST_DSN="postgres://authsec:pw@localhost:55433/ud_k8s?sslmode=disable" \
//	  go test -tags e2e -run Sighting ./services/
package services_test

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func sightingMgr(db *gorm.DB, on bool) services.K8sRBACManager {
	return services.NewK8sRBACManager(db, services.NewGraphProjectionGate(on, ""))
}

// A sighting projected before any snapshot is a live workload with the sweep's
// key, kind and scope, supported by its cluster's source but by no sweep.
func TestSightingAppearsBeforeAnySnapshot(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-now", "research-agent", "Deployment", researchAnchor)

	if err := sightingMgr(db, true).ProjectSighting(ws, "fp-now"); err != nil {
		t.Fatalf("project sighting: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-now"))
	if id == uuid.Nil {
		t.Fatal("no live workload under the fingerprint key after the sighting")
	}
	if got := str(t, db, `SELECT runtime_kind FROM iga_workload WHERE id = ?`, id); got != "k8s_deployment" {
		t.Errorf("runtime_kind = %q, want k8s_deployment", got)
	}
	if got := str(t, db, `SELECT provider_attrs->>'native_id' FROM iga_workload WHERE id = ?`, id); got != "iga-demo/research-agent" {
		t.Errorf("native_id = %q, want iga-demo/research-agent", got)
	}
	if got := str(t, db, `SELECT provider_attrs->>'scope_id' FROM iga_workload WHERE id = ?`, id); got != cluster {
		t.Errorf("scope_id = %q, want the cluster", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_object_support
	    WHERE workload_id = ? AND state = 'current' AND discovery_source_id = ?
	      AND last_confirmed_sweep_id IS NULL`, id, src); n != 1 {
		t.Errorf("%d current, sweep-less support rows from the cluster's source, want 1", n)
	}
}

// The next complete sweep confirms the sighting's support in place -- one row,
// now naming the sweep -- rather than writing a second one beside it.
func TestNextSweepConfirmsTheSightingsSupport(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-c", "research-agent", "Deployment", researchAnchor)
	mgr := sightingMgr(db, true)
	if err := mgr.ProjectSighting(ws, "fp-c"); err != nil {
		t.Fatalf("project sighting: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-c"))

	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-c")); got != id {
		t.Fatalf("the sweep wrote workload %s beside the sighting's %s", got, id)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_object_support WHERE workload_id = ?`, id); n != 1 {
		t.Errorf("%d support rows after the sweep, want 1 (confirmed in place)", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_object_support
	    WHERE workload_id = ? AND state = 'current' AND last_confirmed_sweep_id = ?`,
		id, lastSweep(t, db, ws)); n != 1 {
		t.Error("the sweep did not confirm the sighting's support")
	}
}

// A sighting confirms; it never closes. A workload projected from a sighting
// that then vanishes stays until a complete sweep proves the absence.
func TestSightingNeverRetiresAWorkloadOnItsOwn(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-a", "a-agent", "Deployment", researchAnchor)
	seedSighting(t, db, ws, "fp-b", "b-agent", "Deployment", researchAnchor)
	mgr := sightingMgr(db, true)
	for _, fp := range []string{"fp-a", "fp-b"} {
		if err := mgr.ProjectSighting(ws, fp); err != nil {
			t.Fatalf("project %s: %v", fp, err)
		}
	}
	idA := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-a"))

	if err := db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-a'`,
		ws).Error; err != nil {
		t.Fatalf("delete sighting: %v", err)
	}
	// Another sighting projected now must not close fp-a.
	if err := mgr.ProjectSighting(ws, "fp-b"); err != nil {
		t.Fatalf("project fp-b again: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, idA); got != "active" {
		t.Errorf("fp-a lifecycle = %q after a sighting of another workload, want active", got)
	}

	// The complete sweep is what may end it.
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, idA); got != "retired" {
		t.Errorf("fp-a lifecycle = %q after a complete sweep without it, want retired", got)
	}
}

// Through the discovery manager, as the HTTP handlers call it: a reported
// sighting appears at once, and a deleted one is retired at once.
func TestReportedSightingAndDeletionReachTheGraphAtOnce(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))

	_, _, err := disco.ReportSighting(ws, "test", services.SightingInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, Fingerprint: "fp-r",
		DisplayName: "research-agent",
		Metadata: map[string]interface{}{
			"cluster":    map[string]interface{}{"name": cluster},
			"kubernetes": map[string]interface{}{"namespace": "iga-demo", "workload_kind": "CronJob"},
		},
	})
	if err != nil {
		t.Fatalf("report sighting: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-r"))
	if id == uuid.Nil {
		t.Fatal("a reported sighting did not reach iga_workload")
	}
	if got := str(t, db, `SELECT runtime_kind FROM iga_workload WHERE id = ?`, id); got != "k8s_cronjob" {
		t.Errorf("runtime_kind = %q, want k8s_cronjob", got)
	}

	if _, _, err := disco.RecordLifecycleEvent(ws, services.LifecycleEventInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, Fingerprint: "fp-r",
		Event: "deleted", ClusterName: cluster,
	}); err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, id); got != "retired" {
		t.Errorf("deleted workload lifecycle = %q, want retired at once", got)
	}
	if got := str(t, db, `SELECT state FROM iga_object_support WHERE workload_id = ?`, id); got != "ended" {
		t.Errorf("deleted workload support = %q, want ended", got)
	}
}

// With the projection switch off, a sighting writes nothing to the graph.
func TestSightingProjectionGateOff(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-off", "research-agent", "Deployment", researchAnchor)
	if err := sightingMgr(db, false).ProjectSighting(ws, "fp-off"); err != nil {
		t.Fatalf("project sighting: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ?`, ws); n != 0 {
		t.Errorf("%d workloads written with the switch off, want 0", n)
	}
}

// A sighting that names no cluster cannot be attributed, and is left alone.
func TestSightingWithoutAClusterIsNotProjected(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	if err := db.Exec(`INSERT INTO discovered_agents
	    (workspace_id,source,fingerprint,display_name,metadata,status,runtime_status)
	    VALUES (?,'k8s_webhook','fp-nc','orphan','{"kubernetes":{"namespace":"x"}}'::jsonb,
	            'unregistered','running')`, ws).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := sightingMgr(db, true).ProjectSighting(ws, "fp-nc"); err != nil {
		t.Fatalf("project sighting: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ?`, ws); n != 0 {
		t.Errorf("%d workloads written for a sighting with no cluster, want 0", n)
	}
}
