//go:build e2e

// Reconciliation against a real Postgres.
//
// The unit tests prove the MAPPING is right. This proves the thing that
// actually decides whether the product lies: that a sweep closes what it looked
// at and did not find, and closes NOTHING it could not look at. Those two
// failures are invisible to a compiler and indistinguishable in a fixture --
// one reports access that was revoked months ago, the other reports a mass
// revocation that never happened.
//
//	docker run -d -e POSTGRES_PASSWORD=pw -p 55441:5432 postgres:16
//	# apply migrations/master/*.sql in version order, then:
//	K8S_GRAPH_TEST_DSN="postgres://postgres:pw@localhost:55441/fresh?sslmode=disable" \
//	  go test -tags e2e -run Reconcile ./internal/k8sgraph/
package k8sgraph_test

import (
	"os"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type fixture struct {
	db       *gorm.DB
	ws       uuid.UUID
	source   uuid.UUID
	identity uuid.UUID
	policy   uuid.UUID
	stmt     uuid.UUID
	assign   uuid.UUID
	cluster  string
}

func open(t *testing.T) *gorm.DB {
	t.Helper()
	d := os.Getenv("K8S_GRAPH_TEST_DSN")
	if d == "" {
		t.Skip("K8S_GRAPH_TEST_DSN not set; skipping the reconciliation e2e")
	}
	db, err := gorm.Open(postgres.Open(d), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

// seed builds one cluster's worth of graph: a ServiceAccount bound to a
// ClusterRole that grants one statement, with support rows naming the sweep
// that saw them.
func seed(t *testing.T, sweepID uuid.UUID, gen int64) *fixture {
	t.Helper()
	db := open(t)
	f := &fixture{db: db, ws: uuid.New(), source: uuid.New(), cluster: "k3s"}

	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	exec(`INSERT INTO workspaces (id,name) VALUES (?,?)`, f.ws, "k8s-recon-"+f.ws.String()[:8])
	exec(`INSERT INTO discovery_sources (id,workspace_id,kind,display_name) VALUES (?,?,?,?)`,
		f.source, f.ws, "k8s_webhook", "agent-"+f.source.String()[:8])
	exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,generation,
	        complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	      VALUES (?,?,?,?,?,true,true,'{iga-demo}',now(),now())`,
		sweepID, f.ws, f.source, f.cluster, gen)

	f.identity, f.policy, f.stmt, f.assign = uuid.New(), uuid.New(), uuid.New(), uuid.New()

	exec(`INSERT INTO iga_identity_accounts (id,workspace_id,display_name,account_kind,identity_backing,
	        lifecycle,provider,source_key,continuity,provider_attrs)
	      VALUES (?,?,?,'k8s_service_account','provider','active','k8s',?,'recognition_only','{}')`,
		f.identity, f.ws, "system:serviceaccount:iga-demo:research", "k8s|k3s|sa|iga-demo|research")
	exec(`INSERT INTO iga_policy (id,workspace_id,provider,policy_kind,display_name,native_ref,source_key,
	        continuity,lifecycle)
	      VALUES (?,?,'k8s','k8s_cluster_role',?,'ref',?,'recognition_only','active')`,
		f.policy, f.ws, "secret-reader", "k8s|k3s|clusterrole|secret-reader")
	exec(`INSERT INTO iga_entitlements (id,workspace_id,native_grant_kind,native_rights,normalized_rights,
	        lifecycle,provider,source_key,continuity,statement_key,effect,negated,conditional)
	      VALUES (?,?,'k8s_policy_rule','{"verbs":["get"]}','{"verbs":["get"]}','active','k8s',?,
	              'recognition_only',?,'allow',false,false)`,
		f.stmt, f.ws, "k8s|stmt|1", "k8s|stmt|1")

	// The partitions these rows belong to, spelled exactly as the reconciler
	// will spell them.
	sc := k8sgraph.Scope{SourceID: f.source, Cluster: f.cluster, Generation: gen,
		Complete: true, ClusterScoped: true, Namespaces: []string{"iga-demo"}}
	pIdent := k8sgraph.PartitionForIdentity(sc, "iga-demo").Key()
	pPolicy := k8sgraph.PartitionForRole(sc, "").Key()
	pStmt := k8sgraph.Partition{SourceID: f.source, Cluster: f.cluster,
		Class: k8sgraph.ClassEntitlement}.Key()
	pAssign := k8sgraph.PartitionForEdge(sc, "", k8sgraph.TargetAssignment).Key()
	pEdge := k8sgraph.PartitionForEdge(sc, "", k8sgraph.TargetAccessEdge).Key()

	exec(`INSERT INTO iga_policy_assignment (id,workspace_id,policy_id,holder_identity_account_id,
	        assignment_kind,basis,state,source_key,partition_key,discovery_source_id,last_confirmed_sweep_id)
	      VALUES (?,?,?,?,'k8s_cluster_role_binding','declared','current',?,?,?,?)`,
		f.assign, f.ws, f.policy, f.identity, "k8s|bind|1", pAssign, f.source, sweepID)
	exec(`INSERT INTO iga_access_edges (workspace_id,subject_kind,subject_id,subject_identity_account_id,
	        provider,entitlement_id,assignment_id,direction,path_kind,basis,calculation_state,
	        effective_conclusion,native_scope,state,source_key,partition_key,discovery_source_id,
	        last_confirmed_sweep_id)
	      VALUES (?,'identity_account',?,?, 'k8s',?,?,'outbound','k8s_rbac','observed','complete',
	              'effective','k3s','current',?,?,?,?)`,
		f.ws, f.identity, f.identity, f.stmt, f.assign, "k8s|edge|1", pEdge, f.source, sweepID)

	for _, s := range []struct {
		col string
		id  uuid.UUID
		p   string
	}{
		{"identity_account_id", f.identity, pIdent},
		{"policy_id", f.policy, pPolicy},
		{"entitlement_id", f.stmt, pStmt},
	} {
		exec(`INSERT INTO iga_object_support (workspace_id,`+s.col+`,discovery_source_id,partition_key,
		        state,last_confirmed_sweep_id,last_confirmed_at)
		      VALUES (?,?,?,?,'current',?,now())`, f.ws, s.id, f.source, s.p, sweepID)
	}
	return f
}

func (f *fixture) scope(gen int64, complete, clusterScoped bool, ns ...string) k8sgraph.Scope {
	return k8sgraph.Scope{SourceID: f.source, Cluster: f.cluster, Generation: gen,
		Complete: complete, ClusterScoped: clusterScoped, Namespaces: ns}
}

func (f *fixture) state(t *testing.T, table, idCol string, id uuid.UUID) string {
	t.Helper()
	var s string
	col := "state"
	if table == "iga_identity_accounts" || table == "iga_policy" || table == "iga_entitlements" {
		col = "lifecycle"
	}
	if err := f.db.Raw(`SELECT `+col+` FROM `+table+` WHERE `+idCol+` = ?`, id).Scan(&s).Error; err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	return s
}

func (f *fixture) supportState(t *testing.T, col string, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.db.Raw(`SELECT state FROM iga_object_support WHERE `+col+` = ?`, id).Scan(&s).Error; err != nil {
		t.Fatalf("read support: %v", err)
	}
	return s
}

// An INCOMPLETE sweep must retire nothing. One denied LIST would otherwise
// delete a cluster's whole authorization model.
func TestIncompleteSweepEndsNothing(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)

	second := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,2,false,false,'{}',now(),now())`, second, f.ws, f.source, f.cluster).Error; err != nil {
		t.Fatalf("second sweep: %v", err)
	}

	rc := k8sgraph.NewReconciler(func() time.Time { return time.Now() })
	res, err := rc.Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, false, false)})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.SupportEnded != 0 || res.EdgesEnded != 0 || res.ObjectsRetired != 0 {
		t.Errorf("an incomplete sweep retired things: %+v", res)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "active" {
		t.Errorf("identity lifecycle = %q, want active after an incomplete sweep", got)
	}
	if got := f.state(t, "iga_access_edges", "assignment_id", f.assign); got != "current" {
		t.Errorf("grant state = %q; an incomplete sweep must not end a grant", got)
	}
}

// A sweep that could not read cluster-wide must not retire cluster-scoped
// objects. This is the case that makes the difference between "a smaller
// answer" and "a different answer".
func TestNamespacedSweepCannotRetireClusterScoped(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)

	second := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,2,true,false,'{iga-demo}',now(),now())`, second, f.ws, f.source, f.cluster).Error; err != nil {
		t.Fatalf("second sweep: %v", err)
	}

	rc := k8sgraph.NewReconciler(nil)
	if _, err := rc.Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, false, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The ClusterRole lives in the cluster partition, which this sweep never read.
	if got := f.state(t, "iga_policy", "id", f.policy); got != "active" {
		t.Errorf("ClusterRole lifecycle = %q; a namespaced sweep must not retire it", got)
	}
	if got := f.supportState(t, "policy_id", f.policy); got == "ended" {
		t.Error("a namespaced sweep ended the support for a cluster-scoped policy")
	}
}

// The case the whole mechanism exists for: a complete sweep that looked
// everywhere and did not see the binding must close it, and the grant with it.
func TestCompleteSweepEndsWhatItDidNotSee(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)

	second := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,2,true,true,'{iga-demo}',now(),now())`, second, f.ws, f.source, f.cluster).Error; err != nil {
		t.Fatalf("second sweep: %v", err)
	}

	rc := k8sgraph.NewReconciler(nil)
	res, err := rc.Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.state(t, "iga_policy_assignment", "id", f.assign); got != "ended" {
		t.Errorf("assignment state = %q, want ended: sweep 2 looked and did not find it", got)
	}
	if got := f.state(t, "iga_access_edges", "assignment_id", f.assign); got != "ended" {
		t.Errorf("grant state = %q, want ended: a grant must not outlive its assignment", got)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "retired" {
		t.Errorf("identity lifecycle = %q, want retired: its only support ended", got)
	}
	if res.ObjectsRetired == 0 {
		t.Error("ObjectsRetired = 0 although objects were retired")
	}
}

// Multi-source support (§2.10B): a second source still seeing the object keeps
// it alive. One agent going blind must not retire what another can see.
func TestASecondSourceKeepsTheObjectAlive(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)

	// A second agent, with its own support row for the same identity.
	other := uuid.New()
	otherSweep := uuid.New()
	if err := f.db.Exec(`INSERT INTO discovery_sources (id,workspace_id,kind,display_name)
	    VALUES (?,?,?,?)`, other, f.ws, "k8s_webhook", "agent-b-"+other.String()[:8]).Error; err != nil {
		t.Fatalf("second source: %v", err)
	}
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,1,true,true,'{iga-demo}',now(),now())`,
		otherSweep, f.ws, other, f.cluster).Error; err != nil {
		t.Fatalf("other sweep: %v", err)
	}
	sc := k8sgraph.Scope{SourceID: other, Cluster: f.cluster, Generation: 1,
		Complete: true, ClusterScoped: true, Namespaces: []string{"iga-demo"}}
	if err := f.db.Exec(`INSERT INTO iga_object_support (workspace_id,identity_account_id,
	    discovery_source_id,partition_key,state,last_confirmed_sweep_id,last_confirmed_at)
	    VALUES (?,?,?,?,'current',?,now())`,
		f.ws, f.identity, other, k8sgraph.PartitionForIdentity(sc, "iga-demo").Key(),
		otherSweep).Error; err != nil {
		t.Fatalf("other support: %v", err)
	}

	// The FIRST agent now sweeps and does not see the identity.
	second := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,2,true,true,'{iga-demo}',now(),now())`,
		second, f.ws, f.source, f.cluster).Error; err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	rc := k8sgraph.NewReconciler(nil)
	if _, err := rc.Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "active" {
		t.Errorf("identity lifecycle = %q, want active: a second source still supports it", got)
	}
}

/* -------------------------------- workloads ------------------------------- */

// seedWorkload adds one workload in iga-demo running as the fixture's
// ServiceAccount: the workload, its support row confirmed by sweepID, and its
// executes_as edge confirmed at confirmedAt -- all under the partitions the
// reconciler spells for them.
func (f *fixture) seedWorkload(t *testing.T, sweepID uuid.UUID, confirmedAt time.Time) (uuid.UUID, uuid.UUID) {
	t.Helper()
	sc := f.scope(1, true, true, "iga-demo")
	wl, rel := uuid.New(), uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_workload (id,workspace_id,provider,runtime_kind,display_name,
	        lifecycle,source_key,continuity,provider_attrs)
	      VALUES (?,?,'k8s','k8s_deployment','research-agent','active',?,'recognition_only',
	              '{"cluster":"k3s","namespace":"iga-demo"}')`,
		wl, f.ws, k8sgraph.WorkloadKey(f.cluster, "fp-"+wl.String()[:8])).Error; err != nil {
		t.Fatalf("seed workload: %v", err)
	}
	if err := f.db.Exec(`INSERT INTO iga_object_support (workspace_id,workload_id,discovery_source_id,
	        partition_key,state,last_confirmed_sweep_id,last_confirmed_at)
	      VALUES (?,?,?,?,'current',?,now())`,
		f.ws, wl, f.source, k8sgraph.PartitionForWorkload(sc, "iga-demo").Key(), sweepID).Error; err != nil {
		t.Fatalf("seed workload support: %v", err)
	}
	if err := f.db.Exec(`INSERT INTO iga_relationship (id,workspace_id,relationship_type,source_workload_id,
	        target_identity_account_id,basis,state,valid_from,last_confirmed_at,source_key,partition_key)
	      VALUES (?,?,'executes_as',?,?,'observed','current',?,?,?,?)`,
		rel, f.ws, wl, f.identity, confirmedAt, confirmedAt, "k8s|rel|"+rel.String(),
		k8sgraph.PartitionForEdge(sc, "iga-demo", k8sgraph.TargetExecutesAs).Key()).Error; err != nil {
		t.Fatalf("seed executes_as: %v", err)
	}
	return wl, rel
}

func (f *fixture) sweep(t *testing.T, gen int64, complete, clusterScoped bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,?,?,?,'{iga-demo}',now(),now())`,
		id, f.ws, f.source, f.cluster, gen, complete, clusterScoped).Error; err != nil {
		t.Fatalf("sweep %d: %v", gen, err)
	}
	return id
}

func (f *fixture) lifecycle(t *testing.T, table string, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.db.Raw(`SELECT lifecycle FROM `+table+` WHERE id = ?`, id).Scan(&s).Error; err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	return s
}

// A workload no sighting confirmed is retired by a complete sweep exactly as
// an identity is: its support ends, it retires, and the edge it ran under goes
// with it -- by cascade, so the edge here is one this sweep DID confirm, and
// only its workload's retirement can end it.
func TestCompleteSweepRetiresAnUnconfirmedWorkload(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	at := time.Now().UTC().Truncate(time.Microsecond)
	wl, rel := f.seedWorkload(t, first, at)

	second := f.sweep(t, 2, true, true)
	res, err := k8sgraph.NewReconciler(func() time.Time { return at }).Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.supportState(t, "workload_id", wl); got != "ended" {
		t.Errorf("workload support = %q, want ended: a complete sweep did not confirm it", got)
	}
	if got := f.lifecycle(t, "iga_workload", wl); got != "retired" {
		t.Errorf("workload lifecycle = %q, want retired: its only support ended", got)
	}
	if got := f.state(t, "iga_relationship", "id", rel); got != "ended" {
		t.Errorf("executes_as state = %q, want ended: its workload is gone", got)
	}
	var reason string
	if err := f.db.Raw(`SELECT ended_reason FROM iga_relationship WHERE id = ?`, rel).
		Scan(&reason).Error; err != nil {
		t.Fatalf("read reason: %v", err)
	}
	if reason != "subject_retired" {
		t.Errorf("executes_as ended_reason = %q, want subject_retired", reason)
	}
	if res.ObjectsRetired == 0 || res.SupportEnded == 0 {
		t.Errorf("retirement not counted: %+v", res)
	}
}

// A complete sweep ends an executes_as edge it did not reconfirm, through the
// workload's namespace partition, even while the workload itself stays.
func TestCompleteSweepEndsAnUnconfirmedExecutesAs(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	second := f.sweep(t, 2, true, true)
	// The workload is confirmed by this sweep; its edge is an hour old.
	wl, rel := f.seedWorkload(t, second, time.Now().Add(-time.Hour))

	res, err := k8sgraph.NewReconciler(nil).Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.state(t, "iga_relationship", "id", rel); got != "ended" {
		t.Errorf("executes_as state = %q, want ended: no sighting reconfirmed it", got)
	}
	if got := f.lifecycle(t, "iga_workload", wl); got != "active" {
		t.Errorf("workload lifecycle = %q, want active: this sweep confirmed it", got)
	}
	if res.EdgesEnded == 0 {
		t.Errorf("no edge counted as ended: %+v", res)
	}
}

// An incomplete sweep only marks the workload's support and edge stale.
func TestIncompleteSweepOnlyStalesAWorkload(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	wl, rel := f.seedWorkload(t, first, time.Now().Add(-time.Hour))

	second := f.sweep(t, 2, false, true)
	if _, err := k8sgraph.NewReconciler(nil).Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, false, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.supportState(t, "workload_id", wl); got != "stale" {
		t.Errorf("workload support = %q, want stale after an incomplete sweep", got)
	}
	if got := f.lifecycle(t, "iga_workload", wl); got != "active" {
		t.Errorf("workload lifecycle = %q, want active after an incomplete sweep", got)
	}
	if got := f.state(t, "iga_relationship", "id", rel); got != "stale" {
		t.Errorf("executes_as state = %q, want stale after an incomplete sweep", got)
	}
}

// An edge confirmed at the sweep's own instant was seen by this sweep, and a
// complete sweep must leave it current. iga_relationship has no sweep id, so
// this is the whole of what "confirmed" means for it.
func TestExecutesAsConfirmedByThisSweepSurvives(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	at := time.Now().UTC().Truncate(time.Microsecond)

	second := f.sweep(t, 2, true, true)
	wl, rel := f.seedWorkload(t, second, at)
	if _, err := k8sgraph.NewReconciler(func() time.Time { return at }).Reconcile(f.db,
		k8sgraph.ReconcileInput{WorkspaceID: f.ws, SweepID: second,
			Scope: f.scope(2, true, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.state(t, "iga_relationship", "id", rel); got != "current" {
		t.Errorf("executes_as state = %q, want current: this sweep confirmed it", got)
	}
	if got := f.lifecycle(t, "iga_workload", wl); got != "active" {
		t.Errorf("workload lifecycle = %q, want active: this sweep confirmed it", got)
	}
}

// A workload that has never had support -- written before workloads carried
// any, or by another cluster's projection not yet adopted -- is not evidence
// of anything, and no sweep may retire it for lacking support it never had.
func TestNeverSupportedWorkloadIsNotRetired(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	wl := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_workload (id,workspace_id,provider,runtime_kind,display_name,
	        lifecycle,source_key,continuity,provider_attrs)
	      VALUES (?,?,'k8s','k8s_workload','other-cluster-agent','active',?,'recognition_only','{}')`,
		wl, f.ws, k8sgraph.WorkloadKey("other", "fp-x")).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	second := f.sweep(t, 2, true, true)
	if _, err := k8sgraph.NewReconciler(nil).Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.lifecycle(t, "iga_workload", wl); got != "active" {
		t.Errorf("never-supported workload lifecycle = %q, want active", got)
	}
}

/* --------------------------- kubernetes hardening -------------------------- */

// sweepStartedAt inserts a complete, cluster-wide sweep that started at a given
// instant.
func (f *fixture) sweepStartedAt(t *testing.T, gen int64, started time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_k8s_sweep (id,workspace_id,discovery_source_id,cluster,
	    generation,complete,cluster_scoped,namespaces,sweep_started_at,observed_at)
	    VALUES (?,?,?,?,?,true,true,'{iga-demo}',?,now())`,
		id, f.ws, f.source, f.cluster, gen, started).Error; err != nil {
		t.Fatalf("sweep %d: %v", gen, err)
	}
	return id
}

// Support confirmed AFTER the sweep started (a sighting projected while it
// ran) is newer evidence than the sweep holds: the sweep may not end it, and
// the object it supports stays.
func TestFenceKeepsSupportConfirmedAfterTheSweepStarted(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	// The seed confirmed everything at now(); this sweep started an hour ago.
	second := f.sweepStartedAt(t, 2, time.Now().Add(-time.Hour))
	res, err := NewReconcilerForTest().Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.supportState(t, "identity_account_id", f.identity); got != "current" {
		t.Errorf("identity support = %q, want current: it was confirmed after the sweep started", got)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "active" {
		t.Errorf("identity lifecycle = %q, want active", got)
	}
	if res.SupportEnded != 0 || res.ObjectsRetired != 0 {
		t.Errorf("the fence let the sweep end newer evidence: %+v", res)
	}

	// The same rows, swept by a sweep that started after they were confirmed,
	// are ended as before -- the fence holds back only newer evidence.
	third := f.sweepStartedAt(t, 3, time.Now().Add(time.Hour))
	if _, err := NewReconcilerForTest().Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: third, Scope: f.scope(3, true, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile 3: %v", err)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "retired" {
		t.Errorf("identity lifecycle = %q, want retired by a sweep that started after its confirmation", got)
	}
}

// NewReconcilerForTest is a reconciler on the wall clock.
func NewReconcilerForTest() *k8sgraph.Reconciler { return k8sgraph.NewReconciler(nil) }

// Another cluster's identity that no source supports -- an unattributed
// snapshot's -- is not this sweep's to retire.
func TestSweepNeverRetiresAnotherClustersUnsupportedRows(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	theirs := uuid.New()
	if err := f.db.Exec(`INSERT INTO iga_identity_accounts (id,workspace_id,display_name,account_kind,
	        identity_backing,lifecycle,provider,source_key,continuity,provider_attrs)
	      VALUES (?,?,?,'k8s_service_account','provider','active','k8s',?,'recognition_only','{}')`,
		theirs, f.ws, "system:serviceaccount:iga-demo:research",
		k8sgraph.ServiceAccountKey("other-cluster", "iga-demo", "research")).Error; err != nil {
		t.Fatalf("seed other cluster: %v", err)
	}
	second := f.sweep(t, 2, true, true)
	if _, err := NewReconcilerForTest().Reconcile(f.db, k8sgraph.ReconcileInput{
		WorkspaceID: f.ws, SweepID: second, Scope: f.scope(2, true, true, "iga-demo")}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "retired" {
		t.Errorf("own identity = %q, want retired (the sweep did not see it)", got)
	}
	if got := f.state(t, "iga_identity_accounts", "id", theirs); got != "active" {
		t.Errorf("other cluster's unsupported identity = %q, want active: this sweep has no evidence about it", got)
	}
}

// RetireSource retires what only the removed source supported, keeps what
// another source still supports, and ends the source's own claims in place.
func TestRetireSourceRetiresOnlyWhatItAloneSupported(t *testing.T) {
	first := uuid.New()
	f := seed(t, first, 1)
	// A second source supports the policy, so it must survive the removal.
	other := uuid.New()
	if err := f.db.Exec(`INSERT INTO discovery_sources (id,workspace_id,kind,display_name) VALUES (?,?,?,?)`,
		other, f.ws, "k8s_webhook", "agent-b-"+other.String()[:8]).Error; err != nil {
		t.Fatalf("second source: %v", err)
	}
	sc := k8sgraph.Scope{SourceID: other, Cluster: f.cluster}
	if err := f.db.Exec(`INSERT INTO iga_object_support (workspace_id,policy_id,discovery_source_id,partition_key,state)
	    VALUES (?,?,?,?,'current')`, f.ws, f.policy, other, k8sgraph.PartitionForRole(sc, "").Key()).Error; err != nil {
		t.Fatalf("other support: %v", err)
	}

	n, err := k8sgraph.RetireSource(f.db, f.ws, f.source, time.Now())
	if err != nil {
		t.Fatalf("retire source: %v", err)
	}
	if n != 2 {
		t.Errorf("retired %d objects, want 2 (identity and statement)", n)
	}
	var reason string
	if err := f.db.Raw(`SELECT retired_reason FROM iga_identity_accounts WHERE id = ?`, f.identity).
		Scan(&reason).Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := f.state(t, "iga_identity_accounts", "id", f.identity); got != "retired" || reason != "connection_removed" {
		t.Errorf("identity = %s/%s, want retired/connection_removed", got, reason)
	}
	if got := f.state(t, "iga_policy", "id", f.policy); got != "active" {
		t.Errorf("policy = %q, want active: another source still supports it", got)
	}
	if got := f.state(t, "iga_policy_assignment", "id", f.assign); got != "ended" {
		t.Errorf("assignment = %q, want ended", got)
	}
	var detached int
	if err := f.db.Raw(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND discovery_source_id IS NULL
	    AND state = 'ended' AND ended_reason = 'connection_removed'`, f.ws).Scan(&detached).Error; err != nil {
		t.Fatalf("read edges: %v", err)
	}
	if detached != 1 {
		t.Errorf("%d grants ended and detached, want 1 kept as history", detached)
	}
	// The delete the caller then runs must not take the history with it.
	if err := f.db.Exec(`DELETE FROM discovery_sources WHERE id = ?`, f.source).Error; err != nil {
		t.Fatalf("delete source: %v", err)
	}
	if got := f.state(t, "iga_policy_assignment", "id", f.assign); got != "ended" {
		t.Errorf("assignment after the delete = %q, want the ended row kept", got)
	}
}
