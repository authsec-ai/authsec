//go:build e2e

// The full Kubernetes ingest cycle against a real Postgres.
//
// The k8sgraph tests prove the mapping and the reconciler in isolation. This
// proves they are WIRED: that a snapshot arriving at the service writes support
// rows under the partition keys the reconciler will later query, and that the
// second snapshot therefore closes what the first one opened.
//
// That wiring is exactly where this class of system fails silently. A support
// row written under a key no retirement query matches does not error -- it
// reads as "nothing supports this object", and the object is retired on the
// next complete sweep. A revocation the cluster never made, from a typo.
//
//	K8S_GRAPH_TEST_DSN="postgres://postgres:pw@localhost:55441/fresh?sslmode=disable" \
//	  go test -tags e2e -run Ingest ./services/
package services_test

import (
	"os"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ingestDB(t *testing.T) *gorm.DB {
	t.Helper()
	d := os.Getenv("K8S_GRAPH_TEST_DSN")
	if d == "" {
		t.Skip("K8S_GRAPH_TEST_DSN not set; skipping the ingest e2e")
	}
	db, err := gorm.Open(postgres.Open(d), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

const cluster = "k3s-master"

// snapshot builds a cluster with one ServiceAccount, one ClusterRole granting
// secrets:get, and optionally the ClusterRoleBinding that connects them.
func snapshot(ws uuid.UUID, src uuid.UUID, bound, complete, clusterScoped bool) models.K8sRBACSnapshot {
	s := models.K8sRBACSnapshot{
		WorkspaceID:       ws.String(),
		DiscoverySourceID: src.String(),
		Source:            "k8s_webhook",
		Cluster:           cluster,
		ScanKind:          "rbac",
		SweepStartedAt:    time.Now().UTC().Format(time.RFC3339),
		ObservedAt:        time.Now().UTC().Format(time.RFC3339),
		Complete:          complete,
		ClusterScoped:     clusterScoped,
		Namespaces:        []string{"iga-demo"},
		ServiceAccounts: []models.K8sServiceAccount{{
			Name: "research", Namespace: "iga-demo",
			Anchor: "system:serviceaccount:iga-demo:research",
		}},
		Roles: []models.K8sRole{{
			Kind: models.K8sKindClusterRole, Name: "secret-reader",
			Rules: []models.K8sPolicyRule{{
				APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
			}},
		}},
	}
	if bound {
		s.Bindings = []models.K8sBinding{{
			Kind: models.K8sKindClusterRoleBinding, Name: "research-reads-secrets",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "research", Namespace: "iga-demo"}},
		}}
	}
	return s
}

func seedWorkspace(t *testing.T, db *gorm.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ws, src := uuid.New(), uuid.New()
	if err := db.Exec(`INSERT INTO workspaces (id,name) VALUES (?,?)`, ws, "ingest-"+ws.String()[:8]).Error; err != nil {
		t.Fatalf("workspace: %v", err)
	}
	if err := db.Exec(`INSERT INTO discovery_sources (id,workspace_id,kind,display_name,cluster_name)
	    VALUES (?,?,?,?,?)`, src, ws, "k8s_webhook", "agent-"+src.String()[:8], cluster).Error; err != nil {
		t.Fatalf("source: %v", err)
	}
	return ws, src
}

func count(t *testing.T, db *gorm.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.Raw(q, args...).Scan(&n).Error; err != nil {
		t.Fatalf("count: %v\n%s", err, q)
	}
	return n
}

// The whole point, in one test: a binding that disappears from a complete sweep
// is closed, and the graph stops reporting access that no longer exists.
func TestIngestClosesABindingThatDisappeared(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))

	first, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true))
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if !first.Accepted {
		t.Fatal("first snapshot not accepted; is the projection gate off?")
	}
	if first.Generation != 1 {
		t.Errorf("first generation = %d, want 1", first.Generation)
	}
	if first.Assignments == 0 || first.Edges == 0 {
		t.Fatalf("first ingest wrote no assignment or grant: %+v", first)
	}

	// Support rows must exist, or nothing is reconcilable.
	if n := count(t, db, `SELECT count(*) FROM iga_object_support
	    WHERE workspace_id = ? AND discovery_source_id = ? AND state = 'current'`, ws, src); n == 0 {
		t.Fatal("no support rows written; every object would live forever")
	}

	live := `SELECT count(*) FROM iga_access_edges
	          WHERE workspace_id = ? AND provider = 'k8s' AND state = 'current'`
	if n := count(t, db, live, ws); n == 0 {
		t.Fatal("no current grant after the first sweep")
	}

	// The binding is deleted in the cluster. The sweep is complete and read
	// cluster-wide, so absence here is evidence.
	second, err := mgr.Ingest(ws, snapshot(ws, src, false, true, true))
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if !second.Reconciled {
		t.Fatalf("second sweep did not reconcile: %s", second.Reason)
	}
	if second.Generation != 2 {
		t.Errorf("second generation = %d, want 2", second.Generation)
	}
	if n := count(t, db, live, ws); n != 0 {
		t.Errorf("%d grants still current after the binding was deleted", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_policy_assignment
	    WHERE workspace_id = ? AND state = 'current' AND assignment_kind = 'k8s_cluster_role_binding'`, ws); n != 0 {
		t.Errorf("%d assignments still current after the binding was deleted", n)
	}
}

// The opposite failure, which is the one that would be noticed loudly and
// wrongly: an incomplete sweep must close nothing.
func TestIngestIncompleteSweepClosesNothing(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))

	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	live := `SELECT count(*) FROM iga_access_edges
	          WHERE workspace_id = ? AND provider = 'k8s' AND state = 'current'`
	before := count(t, db, live, ws)
	if before == 0 {
		t.Fatal("no current grant after the first sweep")
	}

	// A sweep where every LIST failed: no binding, no role, nothing.
	bad := snapshot(ws, src, false, false, false)
	bad.Roles, bad.ServiceAccounts, bad.Namespaces = nil, nil, nil
	res, err := mgr.Ingest(ws, bad)
	if err != nil {
		t.Fatalf("incomplete ingest: %v", err)
	}
	if res.Retired != 0 {
		t.Errorf("an incomplete sweep retired %d objects", res.Retired)
	}
	if res.Reason == "" {
		t.Error("an incomplete sweep retired nothing and said nothing about why")
	}
	if n := count(t, db, live, ws); n != before {
		t.Errorf("current grants went %d -> %d on an incomplete sweep; a permissions "+
			"outage was rendered as a revocation", before, n)
	}
}

// A re-delivered identical snapshot must be idempotent: one support row per
// object, not one per sweep. Multi-source support decides whether an object
// survives, so a count that climbs makes retirement impossible.
func TestIngestIsIdempotent(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))

	snap := snapshot(ws, src, true, true, true)
	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("first: %v", err)
	}
	after1 := count(t, db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?`, ws)

	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("second: %v", err)
	}
	after2 := count(t, db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?`, ws)

	if after1 != after2 {
		t.Errorf("support rows %d -> %d on an identical snapshot; the uniqueness "+
			"index is not catching the re-delivery", after1, after2)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges
	    WHERE workspace_id = ? AND provider = 'k8s' AND state = 'current'`, ws); n == 0 {
		t.Error("an identical re-delivery ended the grant it re-confirmed")
	}
}

// Write and read must agree. This is where a provider filter or a column that
// exists only on the write side fails silently: the ingest reports success, the
// rows are in the table, and every screen shows an empty cluster.
func TestIngestIsReadableBack(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))

	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	q := k8sread.New(db, ws)

	clusters, err := q.Clusters()
	if err != nil {
		t.Fatalf("clusters: %v", err)
	}
	if len(clusters) != 1 {
		t.Fatalf("got %d clusters, want 1", len(clusters))
	}
	cl := clusters[0]
	if cl.LastSweep == nil {
		t.Fatal("cluster has no last sweep; the reading behind the answer is missing")
	}
	if cl.LastSweep.Coverage != k8sread.CoverageComplete {
		t.Errorf("coverage = %q, want %q", cl.LastSweep.Coverage, k8sread.CoverageComplete)
	}
	if cl.ServiceAccounts == 0 || cl.Roles == 0 || cl.Grants == 0 {
		t.Errorf("cluster reads back empty: %+v", cl)
	}

	ids, err := q.Identities(50)
	if err != nil {
		t.Fatalf("identities: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("no identities read back although ingest wrote them")
	}
	var sa k8sread.Identity
	for _, i := range ids {
		if i.Grants > 0 {
			sa = i
			break
		}
	}
	if sa.ID == (uuid.UUID{}) {
		t.Fatal("no identity has a grant; the subject join is wrong")
	}

	grants, sum, err := q.AccessFor(sa.ID)
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("identity has grants in the list but none in its detail")
	}
	g := grants[0]
	if g.RoleName != "secret-reader" {
		t.Errorf("role_name = %q, want secret-reader: the chain did not resolve", g.RoleName)
	}
	if len(g.Verbs) == 0 || len(g.Resources) == 0 {
		t.Errorf("rule read back without verbs or resources: %+v", g)
	}
	if g.CalculationState != "complete" {
		t.Errorf("calculation_state = %q, want complete for a fully resolved chain", g.CalculationState)
	}
	if sum.Note == "" {
		t.Error("summary carries no note; an empty or short list would be unexplained")
	}
	if sum.Complete == 0 {
		t.Errorf("summary says nothing was fully calculated: %+v", sum)
	}
}

// A sweep that could not read cluster-wide must SAY so on the way out, not just
// behave differently inside the reconciler.
func TestReadReportsAPartialSweepHonestly(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))

	// Complete, but namespaced only.
	snap := snapshot(ws, src, true, true, false)
	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	clusters, err := k8sread.New(db, ws).Clusters()
	if err != nil {
		t.Fatalf("clusters: %v", err)
	}
	if len(clusters) != 1 || clusters[0].LastSweep == nil {
		t.Fatal("no cluster or no sweep")
	}
	sw := clusters[0].LastSweep
	if sw.Coverage != k8sread.CoverageNamespaced {
		t.Errorf("coverage = %q, want %q", sw.Coverage, k8sread.CoverageNamespaced)
	}
	if sw.Limitation == "" {
		t.Error("a namespaced-only sweep reported no limitation; the gap would be invisible")
	}
}

// seedAgent inserts a discovered agent running as the ServiceAccount the RBAC
// snapshot grants secrets to -- the join that makes "this agent can read
// secrets" answerable.
func seedAgent(t *testing.T, db *gorm.DB, ws uuid.UUID, anchor, runtime string) string {
	t.Helper()
	fp := "fp-" + uuid.New().String()[:8]
	md := `{"cluster":{"name":"` + cluster + `"},"kubernetes":{"namespace":"iga-demo"},` +
		`"provisioning_hints":{"identity_anchor":"` + anchor + `"}}`
	if err := db.Exec(`INSERT INTO discovered_agents
	    (workspace_id,source,fingerprint,display_name,metadata,status,runtime_status,
	     observed_service_account)
	    VALUES (?,?,?,?,?::jsonb,'unregistered',?,?)`,
		ws, "k8s_webhook", fp, "research-agent", md, runtime, anchor).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return fp
}

// The product question, end to end: a Pod runs as a ServiceAccount, and that
// ServiceAccount can read secrets.
func TestWorkloadsLinkToTheirIdentities(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedAgent(t, db, ws, "system:serviceaccount:iga-demo:research", "running")

	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	res, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Workloads == 0 {
		t.Fatal("no workloads projected although a discovered agent exists")
	}
	if res.ExecutesAs == 0 {
		t.Fatalf("no executes_as edge: the workload was not linked to its identity (%+v)", res)
	}

	// The edge must point at the ServiceAccount the RBAC sweep knows about.
	var n int
	if err := db.Raw(`
		SELECT count(*) FROM iga_relationship r
		  JOIN iga_workload w          ON w.id = r.source_workload_id
		  JOIN iga_identity_accounts i ON i.id = r.target_identity_account_id
		 WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as'
		   AND r.state = 'current'
		   AND i.display_name = 'system:serviceaccount:iga-demo:research'`, ws).
		Scan(&n).Error; err != nil {
		t.Fatalf("join: %v", err)
	}
	if n == 0 {
		t.Error("executes_as does not reach the ServiceAccount the sweep projected")
	}
}

// A bare ServiceAccount name cannot be resolved to a namespace. Guessing one
// would attach the workload to another namespace's identically-named account.
func TestWorkloadWithABareNameIsNotGuessed(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedAgent(t, db, ws, "research", "running") // bare, not an anchor

	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	res, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Unanchored == 0 {
		t.Error("a bare ServiceAccount name was resolved anyway; it has no namespace to resolve with")
	}
	if res.ExecutesAs != 0 {
		t.Error("an executes_as edge was invented from a bare name")
	}
}

// An agent observed gone retires its workload and ends the edge -- but the RBAC
// sweep, which never lists a Pod, must not be what decides that.
func TestGoneWorkloadIsRetired(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	fp := seedAgent(t, db, ws, "system:serviceaccount:iga-demo:research", "running")

	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	live := `SELECT count(*) FROM iga_relationship
	          WHERE workspace_id = ? AND relationship_type = 'executes_as' AND state = 'current'`
	if count(t, db, live, ws) == 0 {
		t.Fatal("no current executes_as after the first ingest")
	}

	// The resync manifest -- not this sweep -- observes the Pod gone.
	if err := db.Exec(`UPDATE discovered_agents SET runtime_status = 'gone'
	    WHERE workspace_id = ? AND fingerprint = ?`, ws, fp).Error; err != nil {
		t.Fatalf("mark gone: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if n := count(t, db, live, ws); n != 0 {
		t.Errorf("%d executes_as still current after the workload was observed gone", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload
	    WHERE workspace_id = ? AND provider = 'k8s' AND lifecycle = 'retired'`, ws); n == 0 {
		t.Error("the gone workload was not retired")
	}
}

// The whole chain, read back the way a screen will read it: agent -> identity
// -> grants. If this passes, the product can answer its own question.
func TestWorkloadReadsBackWithItsAccess(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedAgent(t, db, ws, "system:serviceaccount:iga-demo:research", "running")

	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	wls, err := k8sread.New(db, ws).Workloads(50)
	if err != nil {
		t.Fatalf("workloads: %v", err)
	}
	if len(wls) == 0 {
		t.Fatal("no workloads read back")
	}
	w := wls[0]
	if w.RunsAs != "system:serviceaccount:iga-demo:research" {
		t.Errorf("runs_as = %q; the execution identity did not resolve", w.RunsAs)
	}
	if w.Grants == 0 {
		t.Error("workload reports 0 grants although its identity can read secrets")
	}
	if w.Basis == "" {
		t.Error("no basis on the execution edge; the claim is unqualified")
	}
}

/* ------------------------- unified inventory: workloads -------------------- */

// seedSighting inserts a discovered agent in iga-demo with an explicit
// fingerprint, name and workload kind ("" leaves the kind out, as a sighting
// from before the field would).
func seedSighting(t *testing.T, db *gorm.DB, ws uuid.UUID, fp, name, kind, anchor string) {
	t.Helper()
	k8s := `"namespace":"iga-demo"`
	if kind != "" {
		k8s += `,"workload_kind":"` + kind + `"`
	}
	md := `{"cluster":{"name":"` + cluster + `"},"kubernetes":{` + k8s + `},` +
		`"provisioning_hints":{"identity_anchor":"` + anchor + `"}}`
	if err := db.Exec(`INSERT INTO discovered_agents
	    (workspace_id,source,fingerprint,display_name,metadata,status,runtime_status,
	     observed_service_account)
	    VALUES (?,?,?,?,?::jsonb,'unregistered','running',?)`,
		ws, "k8s_webhook", fp, name, md, anchor).Error; err != nil {
		t.Fatalf("seed sighting: %v", err)
	}
}

const researchAnchor = "system:serviceaccount:iga-demo:research"

func lastSweep(t *testing.T, db *gorm.DB, ws uuid.UUID) uuid.UUID {
	t.Helper()
	var row struct{ ID uuid.UUID }
	if err := db.Raw(`SELECT id FROM iga_k8s_sweep WHERE workspace_id = ?
	    ORDER BY generation DESC LIMIT 1`, ws).Scan(&row).Error; err != nil {
		t.Fatalf("last sweep: %v", err)
	}
	return row.ID
}

func workloadID(t *testing.T, db *gorm.DB, ws uuid.UUID, key string) uuid.UUID {
	t.Helper()
	var row struct{ ID uuid.UUID }
	if err := db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND source_key = ?
	    AND lifecycle <> 'retired'`, ws, key).Scan(&row).Error; err != nil {
		t.Fatalf("workload id: %v", err)
	}
	return row.ID
}

func str(t *testing.T, db *gorm.DB, q string, args ...any) string {
	t.Helper()
	var s string
	if err := db.Raw(q, args...).Scan(&s).Error; err != nil {
		t.Fatalf("query: %v\n%s", err, q)
	}
	return s
}

// Two Deployments reporting the same name in one namespace are two rows, each
// supported by the sweep under the partition the reconciler covers.
func TestSameNameWorkloadsStayTwoRows(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-one", "research-agent", "Deployment", researchAnchor)
	seedSighting(t, db, ws, "fp-two", "research-agent", "Deployment", researchAnchor)

	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload
	    WHERE workspace_id = ? AND provider = 'k8s' AND lifecycle = 'active'`, ws); n != 2 {
		t.Fatalf("%d active workloads, want 2: same-name workloads were merged", n)
	}
	sweep := lastSweep(t, db, ws)
	part := k8sgraph.PartitionForWorkload(k8sgraph.Scope{SourceID: src, Cluster: cluster}, "iga-demo").Key()
	for _, fp := range []string{"fp-one", "fp-two"} {
		id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, fp))
		if id == uuid.Nil {
			t.Fatalf("no workload keyed by fingerprint %s", fp)
		}
		if n := count(t, db, `SELECT count(*) FROM iga_object_support
		    WHERE workspace_id = ? AND workload_id = ? AND discovery_source_id = ?
		      AND last_confirmed_sweep_id = ? AND partition_key = ? AND state = 'current'`,
			ws, id, src, sweep, part); n != 1 {
			t.Errorf("workload %s has %d current support rows from this sweep, want 1", fp, n)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM iga_relationship
	    WHERE workspace_id = ? AND relationship_type = 'executes_as' AND state = 'current'`, ws); n != 2 {
		t.Errorf("%d current executes_as, want one per workload", n)
	}
}

// A row keyed the old way (cluster, namespace, display name) is moved to the
// fingerprint key IN PLACE: same id, its execution edge with it. When two
// workloads shared that old row, the one whose fingerprint it carries keeps it.
func TestLegacyKeyedWorkloadIsRekeyedInPlace(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	// A first sweep with no agents, so the ServiceAccount exists to point at.
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	saKey := k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research")
	saID := str(t, db, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ?`, ws, saKey)

	// What an earlier release wrote: one row for the shared name, carrying the
	// fingerprint that wrote last, and its edge under the never-reconciled
	// 'workload' partition.
	legacyKey := k8sgraph.LegacyWorkloadKey(cluster, "iga-demo", "research-agent")
	legacy, rel := uuid.New(), uuid.New()
	if err := db.Exec(`INSERT INTO iga_workload (id,workspace_id,provider,runtime_kind,display_name,
	        lifecycle,source_key,continuity,provider_attrs)
	      VALUES (?,?,'k8s','k8s_workload','research-agent','active',?,'recognition_only',?::jsonb)`,
		legacy, ws, legacyKey,
		`{"cluster":"`+cluster+`","namespace":"iga-demo","fingerprint":"fp-b"}`).Error; err != nil {
		t.Fatalf("legacy workload: %v", err)
	}
	oldPart := k8sgraph.Partition{SourceID: src, Cluster: cluster, Target: "workload"}.Key()
	if err := db.Exec(`INSERT INTO iga_relationship (id,workspace_id,relationship_type,source_workload_id,
	        target_identity_account_id,basis,state,source_key,partition_key)
	      VALUES (?,?,'executes_as',?,?,'observed','current',?,?)`,
		rel, ws, legacy, saID, k8sgraph.RelKey(legacyKey, saKey), oldPart).Error; err != nil {
		t.Fatalf("legacy executes_as: %v", err)
	}

	seedSighting(t, db, ws, "fp-a", "research-agent", "", researchAnchor)
	seedSighting(t, db, ws, "fp-b", "research-agent", "", researchAnchor)
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("second: %v", err)
	}

	newKey := k8sgraph.WorkloadKey(cluster, "fp-b")
	if got := workloadID(t, db, ws, newKey); got != legacy {
		t.Fatalf("fp-b workload id = %s, want the legacy row %s re-keyed in place", got, legacy)
	}
	if got := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-a")); got == uuid.Nil || got == legacy {
		t.Errorf("fp-a workload id = %s: it must get a row of its own, not the legacy one", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND source_key = ?`,
		ws, legacyKey); n != 0 {
		t.Errorf("%d rows still carry the legacy key", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ?
	    AND lifecycle = 'active'`, ws); n != 2 {
		t.Errorf("%d active workloads, want 2", n)
	}
	wantPart := k8sgraph.PartitionForEdge(k8sgraph.Scope{SourceID: src, Cluster: cluster},
		"iga-demo", k8sgraph.TargetExecutesAs).Key()
	if got := str(t, db, `SELECT source_key FROM iga_relationship WHERE id = ?`, rel); got != k8sgraph.RelKey(newKey, saKey) {
		t.Errorf("legacy executes_as key = %q, want it re-keyed with its workload", got)
	}
	if got := str(t, db, `SELECT partition_key FROM iga_relationship WHERE id = ?`, rel); got != wantPart {
		t.Errorf("legacy executes_as partition = %q, want %q", got, wantPart)
	}
	if got := str(t, db, `SELECT state FROM iga_relationship WHERE id = ?`, rel); got != "current" {
		t.Errorf("legacy executes_as state = %q, want current", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_relationship
	    WHERE workspace_id = ? AND relationship_type = 'executes_as' AND state <> 'ended'`, ws); n != 2 {
		t.Errorf("%d live executes_as, want 2: the re-keyed edge was duplicated", n)
	}
}

// A sighting that vanishes from discovered_agents retires its workload on a
// complete sweep, its support ends, and so does the edge it ran under.
func TestVanishedWorkloadRetiresOnACompleteSweep(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-v", "research-agent", "Deployment", researchAnchor)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-v"))

	if err := db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-v'`,
		ws).Error; err != nil {
		t.Fatalf("delete sighting: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, id); got != "retired" {
		t.Errorf("vanished workload lifecycle = %q, want retired", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_object_support
	    WHERE workload_id = ? AND state <> 'ended'`, id); n != 0 {
		t.Errorf("%d support rows still live for a vanished workload", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_relationship
	    WHERE source_workload_id = ? AND state <> 'ended'`, id); n != 0 {
		t.Errorf("%d executes_as still live for a vanished workload", n)
	}
}

// The same disappearance on an INCOMPLETE sweep is only stale.
func TestVanishedWorkloadIsOnlyStaleOnAnIncompleteSweep(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-v", "research-agent", "Deployment", researchAnchor)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-v"))

	if err := db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-v'`,
		ws).Error; err != nil {
		t.Fatalf("delete sighting: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, false, true)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, id); got != "active" {
		t.Errorf("workload lifecycle = %q, want active after an incomplete sweep", got)
	}
	if got := str(t, db, `SELECT state FROM iga_object_support WHERE workload_id = ?`, id); got != "stale" {
		t.Errorf("workload support = %q, want stale after an incomplete sweep", got)
	}
}

// A gone sighting's support ends with its workload.
func TestGoneWorkloadSupportEnds(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-g", "research-agent", "", researchAnchor)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	id := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-g"))
	if err := db.Exec(`UPDATE discovered_agents SET runtime_status = 'gone'
	    WHERE workspace_id = ? AND fingerprint = 'fp-g'`, ws).Error; err != nil {
		t.Fatalf("mark gone: %v", err)
	}
	// Incomplete on purpose: "gone" is an observation, not an absence, and needs
	// no complete sweep.
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, false, false)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, id); got != "retired" {
		t.Errorf("gone workload lifecycle = %q, want retired", got)
	}
	if got := str(t, db, `SELECT state FROM iga_object_support WHERE workload_id = ?`, id); got != "ended" {
		t.Errorf("gone workload support = %q, want ended", got)
	}
}

// A workload's runtime_kind comes from the sighting's workload_kind, and is
// corrected in place when a later sighting reports one.
func TestRuntimeKindComesFromTheSighting(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-s", "store", "StatefulSet", researchAnchor)
	seedSighting(t, db, ws, "fp-n", "nokind", "", researchAnchor)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("first: %v", err)
	}
	kind := func(fp string) string {
		return str(t, db, `SELECT runtime_kind FROM iga_workload WHERE workspace_id = ? AND source_key = ?`,
			ws, k8sgraph.WorkloadKey(cluster, fp))
	}
	if got := kind("fp-s"); got != "k8s_statefulset" {
		t.Errorf("runtime_kind = %q, want k8s_statefulset", got)
	}
	if got := kind("fp-n"); got != "k8s_workload" {
		t.Errorf("runtime_kind = %q, want k8s_workload for a sighting with no kind", got)
	}
	before := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-n"))
	if err := db.Exec(`UPDATE discovered_agents
	    SET metadata = jsonb_set(metadata, '{kubernetes,workload_kind}', '"CronJob"')
	    WHERE workspace_id = ? AND fingerprint = 'fp-n'`, ws).Error; err != nil {
		t.Fatalf("set kind: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := kind("fp-n"); got != "k8s_cronjob" {
		t.Errorf("runtime_kind = %q, want k8s_cronjob once the sighting reports it", got)
	}
	if after := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-n")); after != before {
		t.Error("the kind correction created a new workload row")
	}
}

// An agent that moves to another ServiceAccount: the old executes_as edge is
// no longer confirmed by any sighting and a complete sweep ends it, while the
// edge it now runs under stays current across sweeps -- with sub-second agent
// timestamps, which is where "confirmed by this sweep" could slip.
func TestExecutesAsFollowsAChangedServiceAccount(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-m", "mover", "Deployment", researchAnchor)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	snap := func() models.K8sRBACSnapshot {
		s := snapshot(ws, src, true, true, true)
		s.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.ServiceAccounts = append(s.ServiceAccounts, models.K8sServiceAccount{
			Name: "other", Namespace: "iga-demo", Anchor: "system:serviceaccount:iga-demo:other"})
		return s
	}
	if _, err := mgr.Ingest(ws, snap()); err != nil {
		t.Fatalf("first: %v", err)
	}
	wl := workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, "fp-m"))
	oldKey := k8sgraph.RelKey(k8sgraph.WorkloadKey(cluster, "fp-m"),
		k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research"))
	newKey := k8sgraph.RelKey(k8sgraph.WorkloadKey(cluster, "fp-m"),
		k8sgraph.ServiceAccountKey(cluster, "iga-demo", "other"))

	other := "system:serviceaccount:iga-demo:other"
	if err := db.Exec(`UPDATE discovered_agents
	    SET observed_service_account = ?,
	        metadata = jsonb_set(metadata, '{provisioning_hints,identity_anchor}', to_jsonb(?::text))
	    WHERE workspace_id = ? AND fingerprint = 'fp-m'`, other, other, ws).Error; err != nil {
		t.Fatalf("move agent: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := mgr.Ingest(ws, snap()); err != nil {
			t.Fatalf("ingest %d: %v", i+2, err)
		}
	}
	state := func(key string) string {
		return str(t, db, `SELECT state FROM iga_relationship WHERE workspace_id = ? AND source_key = ?
		    ORDER BY valid_from DESC LIMIT 1`, ws, key)
	}
	if got := state(oldKey); got != "ended" {
		t.Errorf("old executes_as = %q, want ended: no sighting confirms it any more", got)
	}
	if got := state(newKey); got != "current" {
		t.Errorf("new executes_as = %q, want current: every sweep confirmed it", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_relationship
	    WHERE source_workload_id = ? AND state = 'current'`, wl); n != 1 {
		t.Errorf("%d current executes_as for one workload, want 1", n)
	}
}

// Workloads written before they carried support: this cluster's sweep adopts
// its own and retires the one no sighting backs, and never touches another
// cluster's.
func TestPreSupportWorkloadsAreAdoptedByTheirOwnCluster(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mine, theirs := uuid.New(), uuid.New()
	for _, w := range []struct {
		id      uuid.UUID
		cluster string
	}{{mine, cluster}, {theirs, "another-cluster"}} {
		if err := db.Exec(`INSERT INTO iga_workload (id,workspace_id,provider,runtime_kind,display_name,
		        lifecycle,source_key,continuity,provider_attrs)
		      VALUES (?,?,'k8s','k8s_workload','old','active',?,'recognition_only',?::jsonb)`,
			w.id, ws, k8sgraph.LegacyWorkloadKey(w.cluster, "iga-demo", "old"),
			`{"cluster":"`+w.cluster+`","namespace":"iga-demo","fingerprint":"fp-old"}`).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, mine); got != "retired" {
		t.Errorf("this cluster's unbacked pre-support workload = %q, want retired", got)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE id = ?`, theirs); got != "active" {
		t.Errorf("another cluster's workload = %q, want active: this sweep has no evidence about it", got)
	}
}

// Every k8s statement names the role that declares it.
func TestStatementsLinkToTheirRole(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND provider = 'k8s'`,
		ws); n == 0 {
		t.Fatal("no statements written")
	}
	if n := count(t, db, `SELECT count(*) FROM iga_entitlements e
	    LEFT JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	    WHERE e.workspace_id = ? AND e.provider = 'k8s'
	      AND (p.id IS NULL OR p.source_key <> ?)`,
		ws, k8sgraph.Key(cluster, "clusterrole", "secret-reader")); n != 0 {
		t.Errorf("%d statements not linked to the ClusterRole that declares them", n)
	}
}

// Workloads and identities carry the unified-inventory scope keys, and keep
// the keys they already had.
func TestInventoryScopeKeysAreWritten(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	seedSighting(t, db, ws, "fp-sc", "research-agent", "Deployment", researchAnchor)
	snap := snapshot(ws, src, true, true, true)
	snap.Bindings[0].Subjects = append(snap.Bindings[0].Subjects,
		models.K8sSubject{Kind: models.K8sSubjectGroup, Name: "admins"})
	mgr := services.NewK8sRBACManager(db, services.NewGraphProjectionGate(true, ""))
	if _, err := mgr.Ingest(ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	for _, c := range []struct {
		what, table, key, sub, keep string
	}{
		{"service account", "iga_identity_accounts", k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research"), "iga-demo", "name"},
		{"group", "iga_identity_accounts", k8sgraph.Key(cluster, "group", "admins"), "", "grants_all_service_accounts"},
		{"workload", "iga_workload", k8sgraph.WorkloadKey(cluster, "fp-sc"), "iga-demo", "fingerprint"},
	} {
		want := `null`
		if c.sub != "" {
			want = `"` + c.sub + `"`
		}
		n := count(t, db, `SELECT count(*) FROM `+c.table+`
		    WHERE workspace_id = ? AND source_key = ?
		      AND provider_attrs->>'scope_kind' = 'k8s_cluster'
		      AND provider_attrs->>'scope_id' = ?
		      AND provider_attrs->>'scope_label' = ?
		      AND jsonb_exists(provider_attrs, 'sub_scope')
		      AND provider_attrs->'sub_scope' = ?::jsonb
		      AND jsonb_exists(provider_attrs, ?)`,
			ws, c.key, cluster, cluster, want, c.keep)
		if n != 1 {
			t.Errorf("%s: scope keys missing or wrong, or existing key %q lost", c.what, c.keep)
		}
	}
}
