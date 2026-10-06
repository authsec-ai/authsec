//go:build e2e

// Kubernetes hardening, end to end against a real Postgres:
//
//   - grants are declared, not evaluated (basis declared, partial, unknown), and
//     rows written before that are corrected in place by the next sweep;
//
//   - a ServiceAccount subject with no namespace resolves in its RoleBinding's
//     namespace, and is unresolved -- never a phantom -- under a
//     ClusterRoleBinding;
//
//   - a sweep records the cluster's UID and OIDC issuer, a different cluster
//     under the same name is refused (409, nothing written), and nothing one
//     cluster's sweep does can retire another cluster's rows;
//
//   - a sighting projected while a sweep ran survives it, on the same row;
//
//   - removing a discovery source retires what only it supported;
//
//   - ServiceAccounts are members of the implicit groups a binding names.
//
//   - a workload scaled to zero is stopped -- present, never gone -- from a
//     sighting or a manifest, and running again when it scales back up.
//
//     K8S_GRAPH_TEST_DSN="postgres://authsec:pw@localhost:55433/kh_k_proj?sslmode=disable" \
//     go test -tags e2e -run 'Hardening' ./services/
package services_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func hardeningMgr(db *gorm.DB) services.K8sRBACManager {
	return services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
}

// seedSource adds a discovery source for a cluster to an existing workspace.
func seedSource(t *testing.T, db *gorm.DB, ws uuid.UUID, clusterName string) uuid.UUID {
	t.Helper()
	src := uuid.New()
	if err := db.Exec(`INSERT INTO discovery_sources (id,workspace_id,kind,display_name,cluster_name)
	    VALUES (?,?,?,?,?)`, src, ws, "k8s_webhook", "agent-"+src.String()[:8], clusterName).Error; err != nil {
		t.Fatalf("source: %v", err)
	}
	return src
}

// clusterSnapshot is the standard snapshot for another cluster name.
func clusterSnapshot(ws, src uuid.UUID, clusterName string) models.K8sRBACSnapshot {
	s := snapshot(ws, src, true, true, true)
	s.Cluster = clusterName
	return s
}

func identityState(t *testing.T, db *gorm.DB, ws uuid.UUID, key string) string {
	t.Helper()
	return str(t, db, `SELECT lifecycle FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ?
	    ORDER BY created_at DESC LIMIT 1`, ws, key)
}

/* ------------------------------ item 2 ----------------------------------- */

// Every Kubernetes grant is declared/partial/unknown, and a row written as
// observed/complete/effective is corrected in place by the next sweep.
func TestHardeningGrantsAreDeclaredNotEvaluated(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := hardeningMgr(db)

	snap := snapshot(ws, src, true, true, true)
	// One unresolved binding too: its grant is partial/unknown as well.
	snap.Bindings = append(snap.Bindings, models.K8sBinding{
		Kind: models.K8sKindClusterRoleBinding, Name: "dangling",
		RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "nope"},
		Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "research", Namespace: "iga-demo"}},
	})
	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	all := `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND provider = 'k8s' AND state = 'current'`
	honest := all + ` AND basis = 'declared' AND calculation_state = 'partial' AND effective_conclusion = 'unknown'`
	total := count(t, db, all, ws)
	if total < 2 {
		t.Fatalf("%d current grants, want the resolved and the dangling one", total)
	}
	if n := count(t, db, honest, ws); n != total {
		t.Errorf("%d of %d grants are declared/partial/unknown", n, total)
	}

	// What an earlier release wrote: observed, complete, effective.
	type row struct{ ID uuid.UUID }
	var before []row
	if err := db.Raw(`SELECT id FROM iga_access_edges WHERE workspace_id = ? AND provider = 'k8s'
	    AND entitlement_id IS NOT NULL ORDER BY id`, ws).Scan(&before).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := db.Exec(`UPDATE iga_access_edges SET basis = 'observed', calculation_state = 'complete',
	    effective_conclusion = 'effective' WHERE workspace_id = ? AND provider = 'k8s'
	    AND entitlement_id IS NOT NULL`, ws).Error; err != nil {
		t.Fatalf("simulate old rows: %v", err)
	}
	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if n := count(t, db, honest, ws); n != total {
		t.Errorf("after the next sweep %d of %d grants are declared/partial/unknown; old rows not corrected", n, total)
	}
	var after []row
	if err := db.Raw(`SELECT id FROM iga_access_edges WHERE workspace_id = ? AND provider = 'k8s'
	    AND entitlement_id IS NOT NULL AND state = 'current' ORDER BY id`, ws).Scan(&after).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(after) != len(before) || (len(after) > 0 && after[0] != before[0]) {
		t.Errorf("grant rows %v -> %v: corrected by a new row instead of in place", before, after)
	}
}

/* ------------------------------ item 3 ----------------------------------- */

// A RoleBinding subject with no namespace gets the binding's; under a
// ClusterRoleBinding it is unresolved and no phantom is written.
func TestHardeningNamespacelessServiceAccountSubject(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	snap := snapshot(ws, src, false, true, true)
	snap.Bindings = []models.K8sBinding{
		{Kind: models.K8sKindRoleBinding, Name: "rb", Namespace: "iga-demo",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "research"}}},
		{Kind: models.K8sKindClusterRoleBinding, Name: "crb",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "ghost"}}},
	}
	res, err := hardeningMgr(db).Ingest(ws, snap)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Unresolved != 1 {
		t.Errorf("unresolved = %d, want 1 (the ClusterRoleBinding subject with no namespace)", res.Unresolved)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?
	    AND (display_name LIKE '%::%' OR display_name LIKE '%ghost%')`, ws); n != 0 {
		t.Errorf("%d phantom ServiceAccounts written", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges e
	    JOIN iga_identity_accounts i ON i.id = e.subject_identity_account_id
	    WHERE e.workspace_id = ? AND e.state = 'current'
	      AND i.display_name = 'system:serviceaccount:iga-demo:research'`, ws); n == 0 {
		t.Error("the RoleBinding grant did not reach iga-demo/research")
	}
}

// A phantom written by an earlier release is retired by the next complete
// sweep -- it is this cluster's row, adopted and then not seen.
func TestHardeningExistingPhantomIsRetired(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	phantom := k8sgraph.ServiceAccountKey(cluster, "", "research")
	if err := db.Exec(`INSERT INTO iga_identity_accounts (workspace_id,display_name,account_kind,identity_backing,
	        lifecycle,provider,source_key,continuity,provider_attrs)
	      VALUES (?,?,'k8s_service_account','provider','active','k8s',?,'recognition_only',?::jsonb)`,
		ws, "system:serviceaccount::research", phantom,
		`{"cluster":"`+cluster+`","namespace":"","name":"research"}`).Error; err != nil {
		t.Fatalf("seed phantom: %v", err)
	}
	if _, err := hardeningMgr(db).Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := identityState(t, db, ws, phantom); got != "retired" {
		t.Errorf("phantom lifecycle = %q, want retired by the next complete sweep", got)
	}
}

/* ------------------------------ item 5a/5b -------------------------------- */

// The sweep records the cluster UID and issuer, the source learns its UID, and
// the IRSA role lands on the ServiceAccount.
func TestHardeningSweepRecordsClusterIdentity(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	snap := snapshot(ws, src, true, true, true)
	snap.ClusterUID = "uid-" + uuid.NewString()
	snap.OIDCIssuer = "https://oidc.eks.us-east-1.amazonaws.com/id/ABC"
	snap.ServiceAccounts[0].AWSRoleARN = "arn:aws:iam::123456789012:role/research"
	if _, err := hardeningMgr(db).Ingest(ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	sweep := lastSweep(t, db, ws)
	if got := str(t, db, `SELECT cluster_uid FROM iga_k8s_sweep WHERE id = ?`, sweep); got != snap.ClusterUID {
		t.Errorf("sweep cluster_uid = %q, want %q", got, snap.ClusterUID)
	}
	if got := str(t, db, `SELECT oidc_issuer FROM iga_k8s_sweep WHERE id = ?`, sweep); got != snap.OIDCIssuer {
		t.Errorf("sweep oidc_issuer = %q, want %q", got, snap.OIDCIssuer)
	}
	if got := str(t, db, `SELECT cluster_uid FROM discovery_sources WHERE id = ?`, src); got != snap.ClusterUID {
		t.Errorf("source cluster_uid = %q, want it recorded as %q", got, snap.ClusterUID)
	}
	if got := str(t, db, `SELECT provider_attrs->>'aws_role_arn' FROM iga_identity_accounts
	    WHERE workspace_id = ? AND source_key = ?`, ws,
		k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research")); got != snap.ServiceAccounts[0].AWSRoleARN {
		t.Errorf("aws_role_arn = %q, want %q", got, snap.ServiceAccounts[0].AWSRoleARN)
	}
}

// Two clusters installed under one name: the second UID is refused and writes
// nothing; a snapshot with no UID (an older agent) is still accepted.
func TestHardeningSameNameDifferentClusterIsRejected(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := hardeningMgr(db)
	first := snapshot(ws, src, true, true, true)
	first.ClusterUID = "uid-first"
	if _, err := mgr.Ingest(ws, first); err != nil {
		t.Fatalf("first: %v", err)
	}
	sweeps := `SELECT count(*) FROM iga_k8s_sweep WHERE workspace_id = ?`
	before := count(t, db, sweeps, ws)

	// The impostor: same cluster name, different UID, and a ServiceAccount the
	// first cluster does not have -- plus an empty sweep, which merged would end
	// everything the first cluster holds.
	second := snapshot(ws, src, false, true, true)
	second.ClusterUID = "uid-second"
	second.ServiceAccounts = []models.K8sServiceAccount{{Name: "intruder", Namespace: "iga-demo",
		Anchor: "system:serviceaccount:iga-demo:intruder"}}
	second.Roles = nil
	_, err := mgr.Ingest(ws, second)
	if !errors.Is(err, services.ErrClusterUIDMismatch) {
		t.Fatalf("second cluster: err = %v, want ErrClusterUIDMismatch", err)
	}
	if n := count(t, db, sweeps, ws); n != before {
		t.Errorf("sweeps %d -> %d: a refused snapshot recorded a sweep", before, n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?
	    AND display_name LIKE '%intruder%'`, ws); n != 0 {
		t.Error("a refused snapshot wrote an identity")
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'current'`, ws); n == 0 {
		t.Error("a refused snapshot ended the first cluster's grants")
	}
	if got := str(t, db, `SELECT cluster_uid FROM discovery_sources WHERE id = ?`, src); got != "uid-first" {
		t.Errorf("source cluster_uid = %q, want uid-first unchanged", got)
	}

	// No UID at all: accepted as before.
	legacy := snapshot(ws, src, true, true, true)
	if _, err := mgr.Ingest(ws, legacy); err != nil {
		t.Errorf("a snapshot with no cluster_uid was refused: %v", err)
	}
	// The matching UID: accepted.
	again := snapshot(ws, src, true, true, true)
	again.ClusterUID = "uid-first"
	if _, err := mgr.Ingest(ws, again); err != nil {
		t.Errorf("the recorded cluster was refused: %v", err)
	}
}

// Through the HTTP handler: the refusal is 409 cluster_uid_mismatch.
func TestHardeningClusterUIDMismatchIs409(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	if err := db.Exec(`UPDATE discovery_sources SET cluster_uid = 'uid-recorded' WHERE id = ?`, src).Error; err != nil {
		t.Fatalf("seed uid: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/rbac-snapshot", platform.NewDiscoveryController(db).ReportRBACSnapshot)

	post := func(uid string) *httptest.ResponseRecorder {
		snap := snapshot(ws, src, true, true, true)
		snap.ClusterUID = uid
		body, _ := json.Marshal(snap)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/rbac-snapshot", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}
	w := post("uid-other")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["error"] != "cluster_uid_mismatch" {
		t.Errorf("error = %v, want cluster_uid_mismatch", out["error"])
	}
	if w := post("uid-recorded"); w.Code != http.StatusOK {
		t.Errorf("matching uid: status = %d, want 200; body %s", w.Code, w.Body.String())
	}
}

/* ------------------------------ item 5c ----------------------------------- */

// Two clusters in one workspace: one's complete sweep that finds nothing
// retires its own rows and none of the other's -- including the other's rows
// that no source supports (an unattributed snapshot's).
func TestHardeningOneClusterNeverRetiresAnothers(t *testing.T) {
	db := ingestDB(t)
	ws, srcA := seedWorkspace(t, db) // cluster k3s-master
	srcB := seedSource(t, db, ws, "cluster-b")
	mgr := hardeningMgr(db)

	if _, err := mgr.Ingest(ws, snapshot(ws, srcA, true, true, true)); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := mgr.Ingest(ws, clusterSnapshot(ws, srcB, "cluster-b")); err != nil {
		t.Fatalf("B: %v", err)
	}
	// Cluster C reaches the graph through an unattributable snapshot: rows,
	// but no support and no partition.
	unattributed := clusterSnapshot(ws, uuid.New(), "cluster-c")
	res, err := mgr.Ingest(ws, unattributed)
	if err != nil {
		t.Fatalf("C: %v", err)
	}
	if res.Reason == "" {
		t.Fatal("cluster C was attributed after all; the test needs it unattributed")
	}

	// A's cluster is emptied, and A sweeps completely.
	empty := snapshot(ws, srcA, false, true, true)
	empty.ServiceAccounts, empty.Roles = nil, nil
	if _, err := mgr.Ingest(ws, empty); err != nil {
		t.Fatalf("A empty: %v", err)
	}

	if got := identityState(t, db, ws, k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research")); got != "retired" {
		t.Errorf("A's ServiceAccount = %q, want retired by A's own complete sweep", got)
	}
	for _, c := range []string{"cluster-b", "cluster-c"} {
		if got := identityState(t, db, ws, k8sgraph.ServiceAccountKey(c, "iga-demo", "research")); got != "active" {
			t.Errorf("%s ServiceAccount = %q after cluster A's sweep, want active", c, got)
		}
		if got := str(t, db, `SELECT lifecycle FROM iga_policy WHERE workspace_id = ? AND source_key = ?`,
			ws, k8sgraph.Key(c, "clusterrole", "secret-reader")); got != "active" {
			t.Errorf("%s ClusterRole = %q after cluster A's sweep, want active", c, got)
		}
		if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'current'
		    AND left(source_key, ?) = ?`, ws, len([]rune(k8sgraph.ClusterPrefix(c))), k8sgraph.ClusterPrefix(c)); n == 0 {
			t.Errorf("%s has no current grant after cluster A's sweep", c)
		}
	}
}

// Unattributed rows are adopted by THEIR OWN cluster's next attributed sweep,
// and reconciled like any other row from then on.
func TestHardeningUnattributedRowsAreAdoptedByTheirCluster(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := hardeningMgr(db)
	// The first reading cannot be attributed: an unknown source id, and a
	// cluster name no source registered (so the name fallback finds nothing).
	snapC := snapshot(ws, uuid.New(), true, true, true)
	snapC.Cluster = "adopt-me"
	if res, err := mgr.Ingest(ws, snapC); err != nil || res.Reason == "" {
		t.Fatalf("unattributed ingest: %v %+v", err, res)
	}
	edges := `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'current'
	    AND discovery_source_id IS NULL AND left(source_key, ?) = ?`
	prefix := k8sgraph.ClusterPrefix("adopt-me")
	if n := count(t, db, edges, ws, len([]rune(prefix)), prefix); n == 0 {
		t.Fatal("no unattributed grant to adopt")
	}
	// Now the cluster's own source sweeps it, completely, and the binding is gone.
	gone := snapshot(ws, src, false, true, true)
	gone.Cluster = "adopt-me"
	if _, err := mgr.Ingest(ws, gone); err != nil {
		t.Fatalf("attributed ingest: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state <> 'ended'
	    AND left(source_key, ?) = ?`, ws, len([]rune(prefix)), prefix); n != 0 {
		t.Errorf("%d unattributed grants of adopt-me still live after its complete sweep did not see them", n)
	}
}

/* ------------------------------ item 5d ----------------------------------- */

// A sighting projected while a sweep ran survives that sweep -- on the same
// row -- while a workload the sweep could have seen and did not is retired.
func TestHardeningSightingDuringASweepSurvivesIt(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := hardeningMgr(db)
	now := time.Now().UTC().Truncate(time.Second)
	at := func(s *models.K8sRBACSnapshot, started, observed time.Time) {
		s.SweepStartedAt = started.Format(time.RFC3339)
		s.ObservedAt = observed.Format(time.RFC3339)
	}

	// Sweep 1, ten minutes ago, confirms an old workload.
	seedSighting(t, db, ws, "fp-old", "old-agent", "Deployment", researchAnchor)
	s1 := snapshot(ws, src, true, true, true)
	at(&s1, now.Add(-10*time.Minute), now.Add(-10*time.Minute))
	if _, err := mgr.Ingest(ws, s1); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	oldID := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-old"))

	// Sweep 2 starts five minutes ago. While it runs, the old workload
	// vanishes and a new one is sighted and projected (now).
	if err := db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-old'`,
		ws).Error; err != nil {
		t.Fatalf("delete old: %v", err)
	}
	seedSighting(t, db, ws, "fp-mid", "mid-agent", "Deployment", researchAnchor)
	if err := mgr.ProjectSighting(ws, "fp-mid"); err != nil {
		t.Fatalf("project mid: %v", err)
	}
	midID := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-mid"))
	if midID == uuid.Nil {
		t.Fatal("the mid-sweep sighting was not projected")
	}
	midRel := str(t, db, `SELECT id FROM iga_relationship WHERE source_workload_id = ? AND state = 'current'`, midID)
	// The sweep's own read of the inventory did not include it: it read before
	// the sighting arrived.
	if err := db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-mid'`,
		ws).Error; err != nil {
		t.Fatalf("hide mid: %v", err)
	}
	s2 := snapshot(ws, src, true, true, true)
	at(&s2, now.Add(-5*time.Minute), now.Add(time.Minute))
	if _, err := mgr.Ingest(ws, s2); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, oldID); got != "retired" {
		t.Errorf("old workload = %q, want retired: it was last confirmed before sweep 2 started", got)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, midID); got != "active" {
		t.Errorf("mid-sweep workload = %q, want active: it was confirmed after sweep 2 started", got)
	}
	if got := str(t, db, `SELECT state FROM iga_object_support WHERE workload_id = ?`, midID); got != "current" {
		t.Errorf("mid-sweep workload support = %q, want current", got)
	}
	if got := str(t, db, `SELECT state FROM iga_relationship WHERE id = ?`, midRel); got != "current" {
		t.Errorf("mid-sweep executes_as = %q, want current", got)
	}

	// The next sweep sees it: same workload row, same edge row -- no history split.
	seedSighting(t, db, ws, "fp-mid", "mid-agent", "Deployment", researchAnchor)
	s3 := snapshot(ws, src, true, true, true)
	at(&s3, now.Add(2*time.Minute), now.Add(2*time.Minute))
	if _, err := mgr.Ingest(ws, s3); err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	if got := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-mid")); got != midID {
		t.Errorf("workload id %s -> %s: the sweep after split its history", midID, got)
	}
	if got := str(t, db, `SELECT id FROM iga_relationship WHERE source_workload_id = ? AND state = 'current'`,
		midID); got != midRel {
		t.Errorf("executes_as id %s -> %s: the edge history split", midRel, got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND source_key = ?`,
		ws, k8sgraph.WorkloadKey(cluster, "fp-mid")); n != 1 {
		t.Errorf("%d workload rows for fp-mid, want 1", n)
	}
}

/* ------------------------------ item 5e ----------------------------------- */

// Removing a discovery source retires what only it supported, keeps its
// claims as ended history, and leaves another source's cluster alone.
func TestHardeningRemovingASourceRetiresItsNodes(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	other := seedSource(t, db, ws, "cluster-b")
	mgr := hardeningMgr(db)
	seedSighting(t, db, ws, "fp-rm", "rm-agent", "Deployment", researchAnchor)
	if err := db.Exec(`UPDATE discovered_agents SET discovery_source_id = ? WHERE workspace_id = ?`,
		src, ws).Error; err != nil {
		t.Fatalf("attribute sighting: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := mgr.Ingest(ws, clusterSnapshot(ws, other, "cluster-b")); err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	saKey := k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research")
	saID := str(t, db, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ?`, ws, saKey)
	wlID := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-rm"))
	edges := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND discovery_source_id = ?`, ws, src)
	if edges == 0 {
		t.Fatal("no grants from the source to keep")
	}

	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	if _, err := disco.DeleteSource(ws, src); err != nil {
		t.Fatalf("delete source: %v", err)
	}

	for _, c := range []struct{ what, q string }{
		{"service account", `SELECT lifecycle || '/' || retired_reason FROM iga_identity_accounts WHERE id = '` + saID + `'`},
		{"cluster role", `SELECT lifecycle || '/' || retired_reason FROM iga_policy WHERE workspace_id = '` + ws.String() +
			`' AND source_key = '` + k8sgraph.Key(cluster, "clusterrole", "secret-reader") + `'`},
		{"workload", `SELECT lifecycle || '/' || retired_reason FROM iga_workload WHERE id = '` + wlID.String() + `'`},
	} {
		if got := str(t, db, c.q); got != "retired/connection_removed" {
			t.Errorf("%s = %q, want retired/connection_removed", c.what, got)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND provider = 'k8s'
	    AND lifecycle = 'active' AND left(source_key, ?) = ?`,
		ws, len([]rune(k8sgraph.ClusterPrefix(cluster))), k8sgraph.ClusterPrefix(cluster)); n != 0 {
		t.Errorf("%d statements of the removed cluster still active", n)
	}
	// History kept: the grants still exist, ended, detached from the source.
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?
	    AND state = 'ended' AND ended_reason = 'connection_removed' AND discovery_source_id IS NULL`, ws, saID); n == 0 {
		t.Error("the removed source's grants were deleted or left live instead of ended")
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?
	    AND state <> 'ended'`, ws, saID); n != 0 {
		t.Errorf("%d grants still live for a retired identity", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_relationship WHERE source_workload_id = ? AND state <> 'ended'`, wlID); n != 0 {
		t.Errorf("%d executes_as still live for a retired workload", n)
	}
	// The other cluster is untouched.
	if got := identityState(t, db, ws, k8sgraph.ServiceAccountKey("cluster-b", "iga-demo", "research")); got != "active" {
		t.Errorf("cluster-b ServiceAccount = %q after another source was removed, want active", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND discovery_source_id = ?
	    AND state = 'current'`, ws, other); n == 0 {
		t.Error("cluster-b lost its grants when another source was removed")
	}
}

/* ------------------------------ item 7 ------------------------------------ */

// A binding to system:serviceaccounts makes every ServiceAccount a member; a
// sweep that no longer names the group ends the memberships; a namespaced
// sweep cannot.
func TestHardeningImplicitGroupMembership(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := hardeningMgr(db)
	withGroups := func(clusterScoped bool, groups ...string) models.K8sRBACSnapshot {
		s := snapshot(ws, src, true, true, clusterScoped)
		s.ServiceAccounts = append(s.ServiceAccounts, models.K8sServiceAccount{
			Name: "other", Namespace: "iga-demo", Anchor: "system:serviceaccount:iga-demo:other"})
		for _, g := range groups {
			s.Bindings = append(s.Bindings, models.K8sBinding{
				Kind: models.K8sKindClusterRoleBinding, Name: "to-" + g,
				RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
				Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: g}},
			})
		}
		return s
	}
	members := `SELECT count(*) FROM iga_relationship r
	    JOIN iga_identity_accounts m ON m.id = r.source_identity_account_id
	    JOIN iga_identity_accounts g ON g.id = r.target_identity_account_id
	    WHERE r.workspace_id = ? AND r.relationship_type = 'member_of' AND r.state = ?
	      AND r.basis = 'declared' AND g.display_name = ?`

	res, err := mgr.Ingest(ws, withGroups(true, "system:serviceaccounts"))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Memberships != 2 {
		t.Errorf("memberships = %d, want 2 (two ServiceAccounts in system:serviceaccounts)", res.Memberships)
	}
	if n := count(t, db, members, ws, "current", "system:serviceaccounts"); n != 2 {
		t.Errorf("%d current memberships of system:serviceaccounts, want 2", n)
	}
	for _, g := range []string{"system:authenticated", "system:serviceaccounts:iga-demo"} {
		if n := count(t, db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = ?`,
			ws, g); n != 0 {
			t.Errorf("group %q written although no binding names it", g)
		}
	}
	relID := str(t, db, `SELECT r.id FROM iga_relationship r JOIN iga_identity_accounts m
	    ON m.id = r.source_identity_account_id WHERE r.workspace_id = ? AND r.relationship_type = 'member_of'
	    AND m.display_name = 'system:serviceaccount:iga-demo:research'`, ws)

	// Re-confirmed in place by the next sweep.
	if _, err := mgr.Ingest(ws, withGroups(true, "system:serviceaccounts", "system:authenticated")); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if got := str(t, db, `SELECT state FROM iga_relationship WHERE id = ?`, relID); got != "current" {
		t.Errorf("membership = %q after a sweep that still names the group, want current", got)
	}
	if n := count(t, db, members, ws, "current", "system:authenticated"); n != 2 {
		t.Errorf("%d current memberships of system:authenticated, want 2", n)
	}

	// A namespaced sweep that does not name the group cannot know it is unnamed.
	if _, err := mgr.Ingest(ws, withGroups(false)); err != nil {
		t.Fatalf("ingest 3: %v", err)
	}
	if n := count(t, db, members, ws, "ended", "system:serviceaccounts"); n != 0 {
		t.Errorf("a namespaced sweep ended %d memberships", n)
	}
	// ...but it did not reconfirm them either, and says so: stale, not current.
	if n := count(t, db, members, ws, "stale", "system:serviceaccounts"); n != 2 {
		t.Errorf("%d memberships stale after a namespaced sweep that did not name the group, want 2", n)
	}

	// A complete cluster-wide sweep that no longer names the group ends them.
	if _, err := mgr.Ingest(ws, withGroups(true, "system:authenticated")); err != nil {
		t.Fatalf("ingest 4: %v", err)
	}
	if got := str(t, db, `SELECT state FROM iga_relationship WHERE id = ?`, relID); got != "ended" {
		t.Errorf("membership = %q after the group stopped being named, want ended", got)
	}
	if n := count(t, db, members, ws, "current", "system:authenticated"); n != 2 {
		t.Errorf("%d current memberships of the still-named group, want 2", n)
	}
}

/* ---------------------------- scale to zero ------------------------------- */

func k8sSightingInput(src uuid.UUID, fp, kind, status string, at time.Time) services.SightingInput {
	return services.SightingInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, Fingerprint: fp,
		DisplayName: fp + "-agent", RuntimeStatus: status, ObservedAt: &at,
		Metadata: map[string]interface{}{
			"cluster": map[string]interface{}{"name": cluster},
			"kubernetes": map[string]interface{}{"namespace": "iga-demo", "workload_kind": kind,
				"replicas": 0},
			"provisioning_hints": map[string]interface{}{"identity_anchor": researchAnchor},
		},
	}
}

func agentRuntime(t *testing.T, db *gorm.DB, ws uuid.UUID, fp string) string {
	t.Helper()
	return str(t, db, `SELECT runtime_status FROM discovered_agents WHERE workspace_id = ? AND fingerprint = ?`, ws, fp)
}

// A sighting reporting scale-to-zero leaves the agent stopped -- not running,
// not gone -- and its workload present in the graph with runtime_status
// stopped, through a complete sweep; running again brings it back on the same
// row.
func TestHardeningStoppedSightingKeepsTheWorkload(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()

	if _, _, err := disco.ReportSighting(ws, "test", k8sSightingInput(src, "fp-zero", "Deployment", "stopped", now)); err != nil {
		t.Fatalf("stopped sighting: %v", err)
	}
	if got := agentRuntime(t, db, ws, "fp-zero"); got != "stopped" {
		t.Errorf("runtime_status = %q, want stopped", got)
	}
	if n := count(t, db, `SELECT count(*) FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-zero'
	    AND last_observed_running_at IS NOT NULL`, ws); n != 0 {
		t.Error("a stopped sighting recorded the workload as observed running")
	}
	key := k8sgraph.WorkloadKey(cluster, "fp-zero")
	id := workloadID(t, db, ws, key)
	if id == uuid.Nil {
		t.Fatal("a stopped workload did not reach the graph")
	}
	attr := func() string {
		return str(t, db, `SELECT lifecycle || '/' || (provider_attrs->>'runtime_status') FROM iga_workload WHERE id = ?`, id)
	}
	if got := attr(); got != "active/stopped" {
		t.Errorf("workload = %q, want active/stopped", got)
	}

	// A complete sweep: a stopped workload is present, so it stays supported.
	if _, err := hardeningMgr(db).Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := attr(); got != "active/stopped" {
		t.Errorf("after a complete sweep workload = %q, want active/stopped", got)
	}
	if got := str(t, db, `SELECT state FROM iga_object_support WHERE workload_id = ?`, id); got != "current" {
		t.Errorf("stopped workload support = %q, want current", got)
	}

	// Scaled back up.
	if _, _, err := disco.ReportSighting(ws, "test", k8sSightingInput(src, "fp-zero", "Deployment", "", now.Add(time.Minute))); err != nil {
		t.Fatalf("running sighting: %v", err)
	}
	if got := agentRuntime(t, db, ws, "fp-zero"); got != "running" {
		t.Errorf("runtime_status = %q after a running sighting, want running", got)
	}
	if got := workloadID(t, db, ws, key); got != id {
		t.Errorf("workload id %s -> %s after scaling back up", id, got)
	}
	if got := attr(); got != "active/running" {
		t.Errorf("workload = %q, want active/running", got)
	}
}

// "stopped" is honoured only from the Kubernetes connector, and nothing but
// running/stopped is accepted.
func TestHardeningSightingRuntimeStatusIsValidated(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	if _, _, err := disco.ReportSighting(ws, "test", services.SightingInput{
		Source: "aws", Fingerprint: "fp-aws", RuntimeStatus: "stopped"}); err != nil {
		t.Fatalf("aws sighting: %v", err)
	}
	if got := agentRuntime(t, db, ws, "fp-aws"); got != "running" {
		t.Errorf("non-Kubernetes stopped sighting runtime_status = %q, want running", got)
	}
	if _, _, err := disco.ReportSighting(ws, "test", services.SightingInput{
		Source: "k8s_webhook", Fingerprint: "fp-bad", RuntimeStatus: "gone"}); err == nil {
		t.Error("a sighting asserting gone was accepted")
	}
}

// A manifest's stopped_fingerprints are present: stopped, never gone -- even
// one the connector left out of fingerprints -- while a truly absent agent is
// still retired; a later manifest listing it running brings it back.
func TestHardeningManifestStoppedFingerprintsAreNotGone(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()
	for _, fp := range []string{"fp-run", "fp-stop", "fp-only-stopped", "fp-gone"} {
		if _, _, err := disco.ReportSighting(ws, "test", k8sSightingInput(src, fp, "Deployment", "", now)); err != nil {
			t.Fatalf("sighting %s: %v", fp, err)
		}
	}
	started, observed := now.Add(2*time.Second), now.Add(3*time.Second)
	res, err := disco.ReconcileManifest(ws, services.ManifestInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, ClusterName: cluster, Complete: true,
		Namespaces:          []string{"iga-demo"},
		Fingerprints:        []string{"fp-run", "fp-stop"},
		StoppedFingerprints: []string{"fp-stop", "fp-only-stopped"},
		SweepStartedAt:      &started, ObservedAt: &observed,
	})
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	for fp, want := range map[string]string{
		"fp-run": "running", "fp-stop": "stopped", "fp-only-stopped": "stopped", "fp-gone": "gone",
	} {
		if got := agentRuntime(t, db, ws, fp); got != want {
			t.Errorf("%s runtime_status = %q, want %q", fp, got, want)
		}
	}
	if res.MarkedGone != 1 || res.MarkedStopped != 2 {
		t.Errorf("result = %+v, want 1 gone and 2 stopped", res)
	}
	stopID := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-stop"))
	if got := str(t, db, `SELECT lifecycle || '/' || (provider_attrs->>'runtime_status') FROM iga_workload WHERE id = ?`,
		stopID); got != "active/stopped" {
		t.Errorf("stopped workload = %q, want active/stopped", got)
	}

	// Running again: listed, not stopped.
	started2, observed2 := now.Add(4*time.Second), now.Add(5*time.Second)
	res, err = disco.ReconcileManifest(ws, services.ManifestInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, ClusterName: cluster, Complete: true,
		Namespaces:     []string{"iga-demo"},
		Fingerprints:   []string{"fp-run", "fp-stop", "fp-only-stopped"},
		SweepStartedAt: &started2, ObservedAt: &observed2,
	})
	if err != nil {
		t.Fatalf("manifest 2: %v", err)
	}
	if got := agentRuntime(t, db, ws, "fp-stop"); got != "running" {
		t.Errorf("fp-stop runtime_status = %q after a manifest listing it running, want running", got)
	}
	if res.MarkedRunning != 2 || res.MarkedGone != 0 {
		t.Errorf("result = %+v, want 2 back to running and none gone", res)
	}
	if got := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-stop")); got != stopID {
		t.Errorf("workload id %s -> %s after scaling back up", stopID, got)
	}
}

// A CronJob's Job deleted arrives as pod_terminated, which asserts nothing:
// the CronJob stays as it was, in the inventory and in the graph.
func TestHardeningPodTerminatedLeavesTheCronJob(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()
	if _, _, err := disco.ReportSighting(ws, "test", k8sSightingInput(src, "fp-cron", "CronJob", "", now)); err != nil {
		t.Fatalf("sighting: %v", err)
	}
	later := now.Add(time.Minute)
	if _, _, err := disco.RecordLifecycleEvent(ws, services.LifecycleEventInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, Fingerprint: "fp-cron",
		Event: "pod_terminated", ClusterName: cluster, ObservedAt: &later,
	}); err != nil {
		t.Fatalf("pod_terminated: %v", err)
	}
	if got := agentRuntime(t, db, ws, "fp-cron"); got != "running" {
		t.Errorf("CronJob runtime_status = %q after pod_terminated, want running (unchanged)", got)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE workspace_id = ? AND source_key = ?`,
		ws, k8sgraph.WorkloadKey(cluster, "fp-cron")); got != "active" {
		t.Errorf("CronJob workload = %q after pod_terminated, want active", got)
	}
}
