//go:build e2e

// Kubernetes cluster identity, concurrent sweeps and the cost of the
// projection, end to end against a real Postgres:
//
//   - the first cluster UID a connection records is kept: a heartbeat
//     reporting another is accepted but never re-binds the connection, and is
//     recorded as cluster_uid_conflict; RBAC snapshots from the other UID stay
//     409;
//
//   - sightings an agent attributed to a discovery source are projected only by
//     that source's sweep, never by another same-name cluster's; a sighting
//     or resync manifest stating a different cluster UID is not projected /
//     is refused (409 cluster_uid_mismatch), and the conflict is recorded;
//
//   - two sweeps of one cluster racing for a generation: one 200, one 409
//     sweep_conflict, nothing of the loser written;
//
//   - ProjectSighting reads only the identities and workloads its sighting can
//     reference;
//
//   - sweep history is pruned to the newest N projected sweeps plus every sweep
//     a row still names, and reconciliation is unaffected.
//
//     K8S_GRAPH_TEST_DSN="postgres://authsec:pw@localhost:55433/kf_k_ident?sslmode=disable" \
//     go test -tags e2e -run 'Ident' ./services/
package services_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

/* --------------------------- 1. cluster identity -------------------------- */

func heartbeat(t *testing.T, db *gorm.DB, ws uuid.UUID, clusterName, uid string) *models.DiscoverySource {
	t.Helper()
	src, _, err := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db)).
		RegisterAgent(ws, services.AgentRegistrationInput{
			Kind: models.DiscoverySourceK8sWebhook, InstanceID: "k8s:" + clusterName,
			ClusterName: clusterName, ClusterUID: uid, AgentVersion: "0.4.0",
			Runtime: map[string]interface{}{"pod": "iga-agent-0"},
		})
	if err != nil {
		t.Fatalf("heartbeat %q: %v", uid, err)
	}
	return src
}

type sourceRow struct {
	ClusterUID      string
	LastStatus      string
	LastError       string
	Conflict        string
	AgentVersion    string
	LastHeartbeatAt time.Time
}

func readSource(t *testing.T, db *gorm.DB, id uuid.UUID) sourceRow {
	t.Helper()
	var r sourceRow
	if err := db.Raw(`SELECT cluster_uid, last_status, last_error, agent_version, last_heartbeat_at,
	        COALESCE(runtime->>'cluster_uid_conflict', '') AS conflict
	      FROM discovery_sources WHERE id = ?`, id).Scan(&r).Error; err != nil {
		t.Fatalf("read source: %v", err)
	}
	return r
}

// A heartbeat from a different cluster under the same instance never moves the
// recorded UID; it is accepted, and recorded as a conflict the console can see.
func TestIdentHeartbeatKeepsTheFirstClusterUID(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	const name = "prod-east"

	// An empty UID is no claim: the first non-empty one is recorded.
	src := heartbeat(t, db, ws, name, "")
	if got := readSource(t, db, src.ID).ClusterUID; got != "" {
		t.Fatalf("cluster_uid = %q after a heartbeat with none", got)
	}
	heartbeat(t, db, ws, name, "uid-a")
	if got := readSource(t, db, src.ID); got.ClusterUID != "uid-a" || got.LastStatus != "healthy" {
		t.Fatalf("after uid-a: %+v, want uid-a recorded and healthy", got)
	}
	before := readSource(t, db, src.ID).LastHeartbeatAt

	// The impostor heartbeats: accepted, UID kept, conflict recorded.
	time.Sleep(10 * time.Millisecond)
	out := heartbeat(t, db, ws, name, "uid-b")
	if out.ID != src.ID {
		t.Fatalf("a conflicting heartbeat minted connector %s; want the existing %s", out.ID, src.ID)
	}
	got := readSource(t, db, src.ID)
	if got.ClusterUID != "uid-a" {
		t.Errorf("cluster_uid = %q after a heartbeat from uid-b, want uid-a kept", got.ClusterUID)
	}
	if out.ClusterUID != "uid-a" {
		t.Errorf("returned connector says cluster_uid %q, want uid-a", out.ClusterUID)
	}
	if got.LastStatus != repositories.ClusterUIDConflictStatus {
		t.Errorf("last_status = %q, want %q", got.LastStatus, repositories.ClusterUIDConflictStatus)
	}
	if !strings.Contains(got.LastError, "uid-a") || !strings.Contains(got.LastError, "uid-b") {
		t.Errorf("last_error %q does not name both UIDs", got.LastError)
	}
	if !strings.Contains(got.Conflict, `"reported_uid": "uid-b"`) ||
		!strings.Contains(got.Conflict, `"recorded_uid": "uid-a"`) {
		t.Errorf("runtime.cluster_uid_conflict = %s, want both UIDs", got.Conflict)
	}
	if !got.LastHeartbeatAt.After(before) {
		t.Error("the conflicting heartbeat was not accepted as liveness")
	}

	// The real cluster's next heartbeat does not clear it while it is recent:
	// both agents heartbeat under one instance, and the console must not see
	// the conflict only half of the time.
	heartbeat(t, db, ws, name, "uid-a")
	if got := readSource(t, db, src.ID); got.LastStatus != repositories.ClusterUIDConflictStatus ||
		got.ClusterUID != "uid-a" || got.Conflict == "" {
		t.Errorf("a matching heartbeat right after the conflict cleared it: %+v", got)
	}
	// Nor does a heartbeat with no UID erase the recorded one.
	heartbeat(t, db, ws, name, "")
	if got := readSource(t, db, src.ID).ClusterUID; got != "uid-a" {
		t.Errorf("cluster_uid = %q after a heartbeat with none, want uid-a", got)
	}

	// Snapshots: the other UID is still refused, the recorded one accepted.
	mgr := hardeningMgr(db)
	other := clusterSnapshot(ws, src.ID, name)
	other.ClusterUID = "uid-b"
	if _, err := mgr.Ingest(ws, other); !errors.Is(err, services.ErrClusterUIDMismatch) {
		t.Errorf("snapshot from uid-b: err = %v, want ErrClusterUIDMismatch", err)
	}
	mine := clusterSnapshot(ws, src.ID, name)
	mine.ClusterUID = "uid-a"
	if _, err := mgr.Ingest(ws, mine); err != nil {
		t.Errorf("snapshot from the recorded uid-a refused: %v", err)
	}

	// Once the conflicting cluster has been quiet past the hold, the matching
	// cluster's heartbeat restores its own status.
	if err := db.Exec(`UPDATE discovery_sources
	    SET runtime = jsonb_set(runtime, '{cluster_uid_conflict,last_seen_at}',
	                            to_jsonb(now() - interval '1 hour'))
	    WHERE id = ?`, src.ID).Error; err != nil {
		t.Fatalf("age the conflict: %v", err)
	}
	heartbeat(t, db, ws, name, "uid-a")
	if got := readSource(t, db, src.ID); got.LastStatus != "healthy" || got.LastError != "" ||
		got.Conflict != "" || got.ClusterUID != "uid-a" {
		t.Errorf("after the hold expired: %+v, want healthy, no conflict, uid-a", got)
	}
}

// The same through the snapshot handler: a connector whose UID a heartbeat
// recorded refuses the other cluster's snapshot with 409.
func TestIdentHeartbeatUIDGovernsSnapshots(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	src := heartbeat(t, db, ws, "prod-west", "uid-first")
	heartbeat(t, db, ws, "prod-west", "uid-second") // must not re-bind

	r := snapshotRouter(db)
	post := func(uid string) *httptest.ResponseRecorder {
		s := clusterSnapshot(ws, src.ID, "prod-west")
		s.ClusterUID = uid
		return postSnapshot(r, s)
	}
	if w := post("uid-second"); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "cluster_uid_mismatch") {
		t.Errorf("uid-second: %d %s, want 409 cluster_uid_mismatch", w.Code, w.Body.String())
	}
	if w := post("uid-first"); w.Code != http.StatusOK {
		t.Errorf("uid-first: %d %s, want 200", w.Code, w.Body.String())
	}
}

func snapshotRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/rbac-snapshot", platform.NewDiscoveryController(db).ReportRBACSnapshot)
	return r
}

func postSnapshot(r *gin.Engine, s models.K8sRBACSnapshot) *httptest.ResponseRecorder {
	body, _ := json.Marshal(s)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rbac-snapshot", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// attributeSighting stamps a seeded sighting with the source its agent
// registered as.
func attributeSighting(t *testing.T, db *gorm.DB, ws uuid.UUID, fp string, src uuid.UUID) {
	t.Helper()
	if err := db.Exec(`UPDATE discovered_agents SET discovery_source_id = ?
	    WHERE workspace_id = ? AND fingerprint = ?`, src, ws, fp).Error; err != nil {
		t.Fatalf("attribute sighting: %v", err)
	}
}

func workloadSupport(t *testing.T, db *gorm.DB, ws uuid.UUID, fp string, src uuid.UUID) int {
	t.Helper()
	return count(t, db, `SELECT count(*) FROM iga_object_support s
	    JOIN iga_workload w ON w.id = s.workload_id
	    WHERE s.workspace_id = ? AND w.source_key = ? AND s.discovery_source_id = ?
	      AND s.state <> 'ended'`, ws, k8sgraph.WorkloadKey(cluster, fp), src)
}

// Two connections reporting one cluster name: each sweep projects only the
// sightings its own agent reported (plus the unattributed ones), so neither
// confirms -- nor, by missing it, ends -- the other's workloads.
func TestIdentSightingsAreScopedByTheirSource(t *testing.T) {
	db := ingestDB(t)
	ws, s1 := seedWorkspace(t, db)
	s2 := seedSource(t, db, ws, cluster) // a second cluster under the same name
	mgr := hardeningMgr(db)

	seedSighting(t, db, ws, "fp-mine", "mine", "Deployment", researchAnchor)
	attributeSighting(t, db, ws, "fp-mine", s1)
	seedSighting(t, db, ws, "fp-theirs", "theirs", "Deployment", researchAnchor)
	attributeSighting(t, db, ws, "fp-theirs", s2)
	seedSighting(t, db, ws, "fp-legacy", "legacy", "Deployment", researchAnchor) // no source

	// The other cluster's sighting reaches the graph through its own source.
	if err := mgr.ProjectSighting(ws, "fp-theirs"); err != nil {
		t.Fatalf("project theirs: %v", err)
	}

	for i := 0; i < 2; i++ { // twice: the second sweep reconciles the first
		if _, err := mgr.Ingest(ws, snapshot(ws, s1, true, true, true)); err != nil {
			t.Fatalf("sweep %d from s1: %v", i+1, err)
		}
	}
	if n := workloadSupport(t, db, ws, "fp-mine", s1); n != 1 {
		t.Errorf("s1's own sighting: %d live s1 support rows, want 1", n)
	}
	if n := workloadSupport(t, db, ws, "fp-legacy", s1); n != 1 {
		t.Errorf("unattributed sighting: %d live s1 support rows, want 1 (still matched by name)", n)
	}
	if n := workloadSupport(t, db, ws, "fp-theirs", s1); n != 0 {
		t.Errorf("s2's sighting: %d live s1 support rows, want 0 -- s1's sweep projected another cluster's workload", n)
	}
	if n := workloadSupport(t, db, ws, "fp-theirs", s2); n != 1 {
		t.Errorf("s2's sighting: %d live s2 support rows, want 1", n)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE workspace_id = ? AND source_key = ?
	    ORDER BY created_at DESC LIMIT 1`, ws, k8sgraph.WorkloadKey(cluster, "fp-theirs")); got != "active" {
		t.Errorf("s2's workload is %q after s1's complete sweeps, want active", got)
	}
}

// A pre-support workload whose sighting another source reported is not
// adopted by this source's sweep: adopting it would let this sweep end the
// only support it would ever get, and retire a live workload.
func TestIdentAnotherSourcesWorkloadIsNotAdopted(t *testing.T) {
	db := ingestDB(t)
	ws, s1 := seedWorkspace(t, db)
	s2 := seedSource(t, db, ws, cluster)
	mgr := hardeningMgr(db)

	seedSighting(t, db, ws, "fp-theirs", "theirs", "Deployment", researchAnchor)
	attributeSighting(t, db, ws, "fp-theirs", s2)
	if err := mgr.ProjectSighting(ws, "fp-theirs"); err != nil {
		t.Fatalf("project: %v", err)
	}
	// As a workload written before support existed: no support row at all.
	if err := db.Exec(`DELETE FROM iga_object_support WHERE workspace_id = ? AND workload_id IS NOT NULL`,
		ws).Error; err != nil {
		t.Fatalf("drop support: %v", err)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, s1, true, true, true)); err != nil {
		t.Fatalf("s1 sweep: %v", err)
	}
	if got := str(t, db, `SELECT lifecycle FROM iga_workload WHERE workspace_id = ? AND source_key = ?
	    ORDER BY created_at DESC LIMIT 1`, ws, k8sgraph.WorkloadKey(cluster, "fp-theirs")); got != "active" {
		t.Errorf("s2's pre-support workload is %q after s1's complete sweep, want active", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?
	    AND workload_id IS NOT NULL AND discovery_source_id = ?`, ws, s1); n != 0 {
		t.Errorf("s1 adopted %d support rows for s2's workload", n)
	}
}

/* ---------------------------- 2. concurrent sweeps ------------------------ */

// Two snapshots of one cluster projected at the same moment: one is applied
// (200), the other is refused 409 sweep_conflict, retryable, and NOTHING of it
// is written. The race is forced, not hoped for: a blocker transaction holds
// generation 1 uncommitted, both ingests read MAX(generation) = 0 and queue on
// it; the blocker then rolls back and they race for generation 1 with no one
// in the way.
func TestIdentConcurrentSweepsOneWinsOneConflicts(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	r := snapshotRouter(db)

	blocker := db.Begin()
	defer blocker.Rollback()
	if err := blocker.Exec(`INSERT INTO iga_k8s_sweep (workspace_id,discovery_source_id,cluster,generation,
	        sweep_started_at,observed_at) VALUES (?,?,?,1,now(),now())`, ws, src, cluster).Error; err != nil {
		t.Fatalf("blocker: %v", err)
	}
	var xid string
	if err := blocker.Raw(`SELECT backend_xid::text FROM pg_stat_activity WHERE pid = pg_backend_pid()`).
		Scan(&xid).Error; err != nil || xid == "" {
		t.Fatalf("blocker xid: %q %v", xid, err)
	}

	snaps := []models.K8sRBACSnapshot{snapshot(ws, src, true, true, true), snapshot(ws, src, true, true, true)}
	results := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range snaps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = postSnapshot(r, snaps[i])
		}(i)
	}

	// Both ingests must be queued on the blocker before it lets go.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var waiting int
		if err := db.Raw(`SELECT count(*) FROM pg_locks WHERE NOT granted
		    AND locktype = 'transactionid' AND transactionid::text = ?`, xid).Scan(&waiting).Error; err != nil {
			t.Fatalf("pg_locks: %v", err)
		}
		if waiting == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d ingests queued on the blocker", waiting)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := blocker.Rollback().Error; err != nil {
		t.Fatalf("release blocker: %v", err)
	}
	wg.Wait()

	codes := map[int]int{}
	var conflict *httptest.ResponseRecorder
	for _, w := range results {
		codes[w.Code]++
		if w.Code == http.StatusConflict {
			conflict = w
		}
	}
	if codes[http.StatusOK] != 1 || codes[http.StatusConflict] != 1 {
		t.Fatalf("status codes %v, want one 200 and one 409; bodies %s | %s",
			codes, results[0].Body.String(), results[1].Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(conflict.Body.Bytes(), &body)
	if body["error"] != "sweep_conflict" || body["retryable"] != true {
		t.Errorf("409 body = %s, want error sweep_conflict, retryable true", conflict.Body.String())
	}

	// Exactly the winner's state: one projected sweep, no 'received' leftover,
	// one row per object -- nothing of the loser.
	if n := count(t, db, `SELECT count(*) FROM iga_k8s_sweep WHERE workspace_id = ?`, ws); n != 1 {
		t.Errorf("%d sweep rows, want 1 (the winner's)", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_k8s_sweep WHERE workspace_id = ?
	    AND status = 'projected' AND generation = 1`, ws); n != 1 {
		t.Errorf("the winner's sweep is not projected as generation 1")
	}
	for q, want := range map[string]int{
		`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?`:                                  1,
		`SELECT count(*) FROM iga_policy WHERE workspace_id = ?`:                                             1,
		`SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ?`:                                  1,
		`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ?`:                                       1,
		`SELECT count(*) FROM iga_object_support WHERE workspace_id = ? AND identity_account_id IS NOT NULL`: 1,
		`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND last_confirmed_sweep_id IS NULL`:   0,
	} {
		if n := count(t, db, q, ws); n != want {
			t.Errorf("%s = %d, want %d", q, n, want)
		}
	}

	// The loser retries on its next cycle and is applied on top.
	if w := postSnapshot(r, snapshot(ws, src, true, true, true)); w.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", w.Code, w.Body.String())
	}
	if n := count(t, db, `SELECT max(generation) FROM iga_k8s_sweep WHERE workspace_id = ?
	    AND status = 'projected'`, ws); n != 2 {
		t.Errorf("after the retry the newest projected generation is %d, want 2", n)
	}
}

/* --------------------------- 3a. ProjectSighting cost --------------------- */

// statementLog records every statement gorm runs, with the rows it returned
// or touched.
type statementLog struct {
	mu   sync.Mutex
	stmt []loggedStatement
}

type loggedStatement struct {
	SQL  string
	Rows int64
}

func (l *statementLog) LogMode(logger.LogLevel) logger.Interface      { return l }
func (l *statementLog) Info(context.Context, string, ...interface{})  {}
func (l *statementLog) Warn(context.Context, string, ...interface{})  {}
func (l *statementLog) Error(context.Context, string, ...interface{}) {}
func (l *statementLog) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	sql, rows := fc()
	l.mu.Lock()
	l.stmt = append(l.stmt, loggedStatement{sql, rows})
	l.mu.Unlock()
}

// reads are the SELECTs that read FROM the table.
func (l *statementLog) reads(table string) []loggedStatement {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []loggedStatement
	for _, s := range l.stmt {
		q := strings.ToUpper(strings.TrimSpace(s.SQL))
		if strings.HasPrefix(q, "SELECT") &&
			(strings.Contains(s.SQL, `FROM "`+table+`"`) || strings.Contains(s.SQL, "FROM "+table+" ")) {
			out = append(out, s)
		}
	}
	return out
}

// A sighting resolves the one ServiceAccount it runs as and its own workload --
// never every identity and workload of the workspace.
func TestIdentProjectSightingReadsOnlyWhatItReferences(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)

	// A workspace with many identities and workloads: 40 ServiceAccounts, and
	// 30 sightings already projected.
	snap := snapshot(ws, src, true, true, true)
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("sa-%02d", i)
		snap.ServiceAccounts = append(snap.ServiceAccounts, models.K8sServiceAccount{Name: name,
			Namespace: "iga-demo", Anchor: "system:serviceaccount:iga-demo:" + name})
	}
	for i := 0; i < 30; i++ {
		seedSighting(t, db, ws, fmt.Sprintf("fp-bulk-%02d", i), fmt.Sprintf("bulk-%02d", i), "Deployment",
			fmt.Sprintf("system:serviceaccount:iga-demo:sa-%02d", i))
	}
	if _, err := hardeningMgr(db).Ingest(ws, snap); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	idents := count(t, db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?`, ws)
	wls := count(t, db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ?`, ws)
	if idents < 41 || wls < 30 {
		t.Fatalf("fixture: %d identities, %d workloads", idents, wls)
	}

	seedSighting(t, db, ws, "fp-one", "one", "Deployment", researchAnchor)
	rec := &statementLog{}
	capDB, err := gorm.Open(postgres.Open(os.Getenv("K8S_GRAPH_TEST_DSN")), &gorm.Config{Logger: rec})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := hardeningMgr(capDB).ProjectSighting(ws, "fp-one"); err != nil {
		t.Fatalf("project: %v", err)
	}

	// It worked: the workload runs as research.
	if n := count(t, db, `SELECT count(*) FROM iga_relationship r
	    JOIN iga_workload w ON w.id = r.source_workload_id
	    JOIN iga_identity_accounts i ON i.id = r.target_identity_account_id
	    WHERE r.workspace_id = ? AND w.source_key = ? AND r.state = 'current'
	      AND i.display_name = ?`, ws, k8sgraph.WorkloadKey(cluster, "fp-one"), researchAnchor); n != 1 {
		t.Fatalf("executes_as research: %d rows, want 1", n)
	}

	for _, c := range []struct {
		table string
		total int
	}{{"iga_identity_accounts", idents}, {"iga_workload", wls}} {
		reads := c.table
		got := rec.reads(reads)
		if len(got) == 0 {
			t.Errorf("no SELECT from %s captured; the statement log is not seeing the projection", c.table)
		}
		for _, s := range got {
			if s.Rows > 1 {
				t.Errorf("a SELECT from %s returned %d rows (of %d in the workspace), want <= 1:\n%s",
					c.table, s.Rows, c.total, s.SQL)
			}
			if !strings.Contains(s.SQL, "source_key IN") {
				t.Errorf("a SELECT from %s is not narrowed by key:\n%s", c.table, s.SQL)
			}
		}
	}
}

/* ----------------------------- 3b. sweep history -------------------------- */

func generations(t *testing.T, db *gorm.DB, ws uuid.UUID) []int64 {
	t.Helper()
	var gens []int64
	if err := db.Raw(`SELECT generation FROM iga_k8s_sweep WHERE workspace_id = ? ORDER BY generation`,
		ws).Scan(&gens).Error; err != nil {
		t.Fatalf("generations: %v", err)
	}
	return gens
}

// History is pruned to the newest N projected sweeps plus every sweep a row
// still names, without nulling a single reference, and reconciliation goes on
// exactly as before.
func TestIdentSweepHistoryIsPruned(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.SweepHistoryEnv, "3")
	mgr := hardeningMgr(db)

	// Sweep 1 also sees a second binding, which every later sweep does not:
	// sweep 2 ends it, and the ended rows keep naming sweep 1 forever.
	first := snapshot(ws, src, true, true, true)
	first.ServiceAccounts = append(first.ServiceAccounts, models.K8sServiceAccount{Name: "ops",
		Namespace: "iga-demo", Anchor: "system:serviceaccount:iga-demo:ops"})
	first.Bindings = append(first.Bindings, models.K8sBinding{
		Kind: models.K8sKindClusterRoleBinding, Name: "ops-reads-secrets",
		RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
		Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "ops", Namespace: "iga-demo"}},
	})
	if _, err := mgr.Ingest(ws, first); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	sweep1 := lastSweep(t, db, ws)
	nulls := func() int {
		return count(t, db, `SELECT
		    (SELECT count(*) FROM iga_object_support WHERE workspace_id = ? AND last_confirmed_sweep_id IS NULL)
		  + (SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ? AND last_confirmed_sweep_id IS NULL)
		  + (SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND last_confirmed_sweep_id IS NULL)`,
			ws, ws, ws)
	}
	for i := 2; i <= 6; i++ {
		res, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true))
		if err != nil {
			t.Fatalf("sweep %d: %v", i, err)
		}
		if i == 2 {
			if n := count(t, db, `SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ?
			    AND state = 'ended' AND last_confirmed_sweep_id = ?`, ws, sweep1); n != 1 {
				t.Fatalf("sweep 2 did not end the ops binding as last confirmed by sweep 1 (%d)", n)
			}
		}
		if i == 6 && res.SweepsPruned == 0 {
			t.Errorf("sweep 6 reports no sweeps pruned")
		}
	}
	nullsBefore := nulls()

	// Kept: the newest three (4, 5, 6) and sweep 1, which the ended rows name.
	if got := fmt.Sprint(generations(t, db, ws)); got != "[1 4 5 6]" {
		t.Errorf("sweeps kept = %s, want [1 4 5 6]", got)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ?
	    AND last_confirmed_sweep_id = ?`, ws, sweep1); n != 1 {
		t.Errorf("the ended binding no longer names sweep 1 (%d rows)", n)
	}
	if n := nulls(); n != nullsBefore {
		t.Errorf("pruning nulled references: %d -> %d", nullsBefore, n)
	}

	// Reconciliation is unaffected: the next generation follows the newest,
	// an incomplete sweep only stales, and a complete one without the binding
	// ends it.
	inc := snapshot(ws, src, false, false, true)
	res, err := mgr.Ingest(ws, inc)
	if err != nil {
		t.Fatalf("incomplete sweep: %v", err)
	}
	if res.Generation != 7 {
		t.Errorf("generation after pruning = %d, want 7", res.Generation)
	}
	live := `SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ? AND state = ?`
	if n := count(t, db, live, ws, "stale"); n != 1 {
		t.Errorf("incomplete sweep: %d stale assignments, want 1", n)
	}
	if _, err := mgr.Ingest(ws, snapshot(ws, src, false, true, true)); err != nil {
		t.Fatalf("complete sweep without the binding: %v", err)
	}
	if n := count(t, db, live, ws, "ended"); n != 2 {
		t.Errorf("complete sweep: %d ended assignments, want 2 (ops and research)", n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state <> 'ended'`,
		ws); n != 0 {
		t.Errorf("%d grants still live after the binding disappeared", n)
	}
	if got := identityState(t, db, ws, k8sgraph.ServiceAccountKey(cluster, "iga-demo", "research")); got != "active" {
		t.Errorf("research = %q, want active (the ServiceAccount is still there)", got)
	}
	gens := generations(t, db, ws)
	if len(gens) == 0 || gens[len(gens)-1] != 8 {
		t.Errorf("sweeps = %v, want the newest to be 8", gens)
	}
	// The newest three projected, plus every one still named.
	for _, g := range []int64{6, 7, 8} {
		found := false
		for _, h := range gens {
			found = found || h == g
		}
		if !found {
			t.Errorf("sweep %d pruned; the newest three must stay (%v)", g, gens)
		}
	}
}

// The setting falls back to the default for nonsense, and never below 1.
func TestIdentSweepHistoryNeverDropsTheNewest(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.SweepHistoryEnv, "0") // invalid: the default applies
	mgr := hardeningMgr(db)
	for i := 0; i < 3; i++ {
		if _, err := mgr.Ingest(ws, snapshot(ws, src, true, true, true)); err != nil {
			t.Fatalf("sweep %d: %v", i+1, err)
		}
	}
	if got := fmt.Sprint(generations(t, db, ws)); got != "[1 2 3]" {
		t.Errorf("sweeps = %s with history 0 (invalid, default %d), want all three kept",
			got, services.DefaultSweepHistory)
	}
}

/* ------------------- 1b. sightings and manifests carry the UID ------------ */

// uidSighting is a Kubernetes sighting whose metadata states the cluster UID
// ("" leaves it out, as an agent before chart 0.4.1 would).
func uidSighting(src uuid.UUID, fp, uid string, at time.Time) services.SightingInput {
	in := k8sSightingInput(src, fp, "Deployment", "", at)
	if uid != "" {
		in.Metadata["cluster"] = map[string]interface{}{"name": cluster, "uid": uid}
	}
	return in
}

func setRecordedUID(t *testing.T, db *gorm.DB, src uuid.UUID, uid string) {
	t.Helper()
	if err := db.Exec(`UPDATE discovery_sources SET cluster_uid = ? WHERE id = ?`, uid, src).Error; err != nil {
		t.Fatalf("record uid: %v", err)
	}
}

// A sighting from another cluster UID is kept in the inventory but never
// projected into its source's graph -- not when it is reported, not by the
// source's sweep -- and the conflict is recorded on the connection. Run with
// IGA_K8S_REQUIRE_CLUSTER_UID=false, where a sighting stating no UID is still
// projected; with it on (the default) see TestUIDRequiredSightingWithoutUID.
func TestIdentSightingFromAnotherClusterUIDIsNotProjected(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	t.Setenv(services.GraphProjectionEnv, "on")
	t.Setenv(services.RequireClusterUIDEnv, "false")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()

	// An ordered slice, conflicting sighting FIRST: the matching cluster's
	// sightings after it must not clear the conflict it recorded. (A map here
	// made the order -- and the test -- random.)
	for _, c := range []struct{ fp, uid string }{{"fp-other", "uid-b"}, {"fp-same", "uid-a"}, {"fp-none", ""}} {
		if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, c.fp, c.uid, now)); err != nil {
			t.Fatalf("sighting %s: %v", c.fp, err)
		}
	}
	// All three are in the inventory.
	if n := count(t, db, `SELECT count(*) FROM discovered_agents WHERE workspace_id = ?`, ws); n != 3 {
		t.Fatalf("%d sightings stored, want 3 (a conflicting one is still kept)", n)
	}
	live := func(fp string) bool { return workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, fp)) != uuid.Nil }
	if !live("fp-same") || !live("fp-none") {
		t.Error("a sighting from the recorded cluster, or with no UID, was not projected")
	}
	if live("fp-other") {
		t.Error("a sighting from uid-b was projected into uid-a's connection")
	}
	got := readSource(t, db, src)
	if got.LastStatus != repositories.ClusterUIDConflictStatus || !strings.Contains(got.Conflict, "uid-b") ||
		!strings.Contains(got.Conflict, "sighting") || got.ClusterUID != "uid-a" {
		t.Errorf("connection after the conflicting sighting: %+v, want cluster_uid_conflict via sighting, uid-a kept", got)
	}

	// Directly, too: the projection refuses it with ErrClusterUIDMismatch.
	if err := hardeningMgr(db).ProjectSighting(ws, "fp-other"); !errors.Is(err, services.ErrClusterUIDMismatch) {
		t.Errorf("ProjectSighting(fp-other) = %v, want ErrClusterUIDMismatch", err)
	}

	// The source's own sweep does not load it either.
	snap := snapshot(ws, src, true, true, true)
	snap.ClusterUID = "uid-a"
	if _, err := hardeningMgr(db).Ingest(ws, snap); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if live("fp-other") {
		t.Error("uid-a's sweep projected a sighting from uid-b")
	}
	if n := workloadSupport(t, db, ws, "fp-same", src); n != 1 {
		t.Errorf("fp-same: %d live support rows after the sweep, want 1", n)
	}
	if n := workloadSupport(t, db, ws, "fp-none", src); n != 1 {
		t.Errorf("fp-none: %d live support rows after the sweep, want 1", n)
	}
}

// A refused RBAC snapshot records the conflict on the connection too.
func TestIdentRefusedSnapshotRecordsTheConflict(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	snap := snapshot(ws, src, true, true, true)
	snap.ClusterUID = "uid-b"
	if _, err := hardeningMgr(db).Ingest(ws, snap); !errors.Is(err, services.ErrClusterUIDMismatch) {
		t.Fatalf("err = %v, want ErrClusterUIDMismatch", err)
	}
	got := readSource(t, db, src)
	if got.LastStatus != repositories.ClusterUIDConflictStatus || !strings.Contains(got.LastError, "uid-b") ||
		!strings.Contains(got.Conflict, "RBAC snapshot") || got.ClusterUID != "uid-a" {
		t.Errorf("connection after the refused snapshot: %+v", got)
	}
}

// A resync manifest from another cluster UID is refused -- 409
// cluster_uid_mismatch through the handler -- before it marks anything gone;
// the recorded UID and a manifest with none are handled as before.
func TestIdentManifestFromAnotherClusterUIDIsRefused(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()
	if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, "fp-1", "uid-a", now)); err != nil {
		t.Fatalf("sighting: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/resync-manifest", platform.NewDiscoveryController(db).ReportResyncManifest)
	post := func(uid string, bySource bool) *httptest.ResponseRecorder {
		started, observed := now.Add(2*time.Second), now.Add(3*time.Second)
		body := map[string]any{
			"workspace_id": ws.String(), "source": "k8s_webhook", "cluster": cluster,
			"complete": true, "namespaces": []string{"iga-demo"}, "fingerprints": []string{},
			"sweep_started_at": started, "observed_at": observed,
		}
		if bySource {
			body["discovery_source_id"] = src.String()
		}
		if uid != "" {
			body["cluster_uid"] = uid
		}
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/resync-manifest", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	// By source id, and by cluster name alone: both refused, nothing gone.
	for _, bySource := range []bool{true, false} {
		w := post("uid-b", bySource)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"cluster_uid_mismatch"`) {
			t.Errorf("bySource=%v: %d %s, want 409 cluster_uid_mismatch", bySource, w.Code, w.Body.String())
		}
		if got := agentRuntime(t, db, ws, "fp-1"); got == "gone" {
			t.Fatalf("bySource=%v: a refused manifest marked fp-1 gone", bySource)
		}
	}
	if got := readSource(t, db, src); got.LastStatus != repositories.ClusterUIDConflictStatus ||
		!strings.Contains(got.Conflict, "resync manifest") {
		t.Errorf("connection after the refused manifest: %+v", got)
	}

	// The recorded cluster's manifest is applied (fp-1 absent -> gone).
	if w := post("uid-a", true); w.Code != http.StatusOK {
		t.Fatalf("uid-a: %d %s", w.Code, w.Body.String())
	}
	if got := agentRuntime(t, db, ws, "fp-1"); got != "gone" {
		t.Errorf("fp-1 = %q after the recorded cluster's complete manifest, want gone", got)
	}
}

// With IGA_K8S_REQUIRE_CLUSTER_UID=false, a manifest with no UID behaves
// exactly as before. With it on (the default) see
// TestUIDRequiredManifestWithoutUID.
func TestIdentManifestWithoutUIDIsUnchanged(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	t.Setenv(services.RequireClusterUIDEnv, "false")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()
	if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, "fp-1", "", now)); err != nil {
		t.Fatalf("sighting: %v", err)
	}
	started, observed := now.Add(2*time.Second), now.Add(3*time.Second)
	res, err := disco.ReconcileManifest(ws, services.ManifestInput{
		Source: "k8s_webhook", DiscoverySourceID: &src, ClusterName: cluster, Complete: true,
		Namespaces: []string{"iga-demo"}, SweepStartedAt: &started, ObservedAt: &observed,
	})
	if err != nil || res.MarkedGone != 1 {
		t.Errorf("manifest without a UID: %+v %v, want fp-1 marked gone", res, err)
	}
}

// A sweep of a cluster with more workloads than one key batch resolves every
// one of them: the narrowed id lookup batches its keys, and none is dropped at
// a batch boundary.
func TestIdentLargeSweepResolvesEveryWorkload(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	const n = 1105 // two batches of 1000
	if err := db.Exec(`INSERT INTO discovered_agents
	    (workspace_id,source,fingerprint,display_name,metadata,status,runtime_status,observed_service_account)
	    SELECT ?, 'k8s_webhook', 'fp-many-' || g, 'many-' || g,
	           jsonb_build_object('cluster', jsonb_build_object('name', ?::text),
	                              'kubernetes', jsonb_build_object('namespace', 'iga-demo'),
	                              'provisioning_hints', jsonb_build_object('identity_anchor', ?::text)),
	           'unregistered', 'running', ?
	      FROM generate_series(1, ?) g`, ws, cluster, researchAnchor, researchAnchor, n).Error; err != nil {
		t.Fatalf("seed sightings: %v", err)
	}
	res, err := hardeningMgr(db).Ingest(ws, snapshot(ws, src, true, true, true))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Workloads != n || res.ExecutesAs != n {
		t.Errorf("result: %d workloads, %d executes_as, want %d each", res.Workloads, res.ExecutesAs, n)
	}
	if got := count(t, db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?
	    AND workload_id IS NOT NULL AND discovery_source_id = ? AND state = 'current'
	    AND last_confirmed_sweep_id IS NOT NULL`, ws, src); got != n {
		t.Errorf("%d workloads confirmed by the sweep, want %d", got, n)
	}
}
