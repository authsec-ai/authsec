//go:build e2e

// A missing cluster UID is not a way round the cluster UID check
// (IGA_K8S_REQUIRE_CLUSTER_UID, default on), end to end against a real
// Postgres. Once a discovery source has recorded a cluster UID:
//
//   - an RBAC snapshot or resync manifest stating none is refused, 409
//     cluster_uid_required, nothing written, and the connection is flagged
//     cluster_uid_conflict (reason "missing") like a mismatch;
//
//   - a sighting stating none is kept in the inventory, never projected into
//     the graph (not when reported, not by the source's sweep), and the
//     connection is flagged;
//
//   - a heartbeat stating none is still accepted as liveness and never clears
//     the recorded UID.
//
// A source with no recorded UID behaves as before, and
// IGA_K8S_REQUIRE_CLUSTER_UID=false restores the lenient behaviour.
//
//	K8S_GRAPH_TEST_DSN="postgres://authsec:pw@localhost:55433/ku_k8s?sslmode=disable" \
//	go test -tags e2e -run 'IdentUIDRequired' ./services/
package services_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// flaggedMissing reports whether the connection carries the missing-UID flag
// for `via`, with its recorded UID kept.
func flaggedMissing(t *testing.T, db *gorm.DB, src uuid.UUID, recorded, via string) bool {
	t.Helper()
	got := readSource(t, db, src)
	return got.ClusterUID == recorded &&
		got.LastStatus == repositories.ClusterUIDConflictStatus &&
		strings.Contains(got.LastError, "cluster_uid_required") &&
		strings.Contains(got.Conflict, `"reason": "missing"`) &&
		strings.Contains(got.Conflict, `"reported_uid": ""`) &&
		strings.Contains(got.Conflict, `"via": "`+via+`"`)
}

func errorCode(w *httptest.ResponseRecorder) (string, string) {
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	code, _ := out["error"].(string)
	detail, _ := out["detail"].(string)
	return code, detail
}

// RBAC snapshot: refused without a UID once the source has one; accepted
// while it has none; accepted with the requirement off.
func TestIdentUIDRequiredSnapshot(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	t.Setenv(services.GraphProjectionEnv, "on")
	t.Setenv(services.RequireClusterUIDEnv, "") // the default: required
	r := snapshotRouter(db)

	// No recorded UID: a snapshot stating none is accepted as before, and
	// records nothing.
	if w := postSnapshot(r, snapshot(ws, src, true, true, true)); w.Code != http.StatusOK {
		t.Fatalf("no recorded uid, none stated: %d %s, want 200", w.Code, w.Body.String())
	}
	if got := readSource(t, db, src).ClusterUID; got != "" {
		t.Fatalf("cluster_uid = %q after a snapshot stating none", got)
	}

	setRecordedUID(t, db, src, "uid-a")
	sweeps := `SELECT count(*) FROM iga_k8s_sweep WHERE workspace_id = ?`
	edges := `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'current'`
	sweepsBefore, edgesBefore := count(t, db, sweeps, ws), count(t, db, edges, ws)
	if edgesBefore == 0 {
		t.Fatal("setup: no current grants to protect")
	}

	// The forged / old agent: no UID, a ServiceAccount this cluster does not
	// have, and an empty complete sweep that, merged, would end every grant.
	forged := snapshot(ws, src, false, true, true)
	forged.ServiceAccounts = []models.K8sServiceAccount{{Name: "intruder", Namespace: "iga-demo",
		Anchor: "system:serviceaccount:iga-demo:intruder"}}
	forged.Roles = nil
	w := postSnapshot(r, forged)
	if code, detail := errorCode(w); w.Code != http.StatusConflict || code != "cluster_uid_required" || detail == "" {
		t.Fatalf("no uid stated for a source with one: %d %s, want 409 cluster_uid_required with a detail",
			w.Code, w.Body.String())
	}
	if n := count(t, db, sweeps, ws); n != sweepsBefore {
		t.Errorf("sweeps %d -> %d: the refused snapshot recorded a sweep", sweepsBefore, n)
	}
	if n := count(t, db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?
	    AND display_name LIKE '%intruder%'`, ws); n != 0 {
		t.Error("the refused snapshot wrote an identity")
	}
	if n := count(t, db, edges, ws); n != edgesBefore {
		t.Errorf("current grants %d -> %d: the refused snapshot changed them", edgesBefore, n)
	}
	if !flaggedMissing(t, db, src, "uid-a", "RBAC snapshot") {
		t.Errorf("connection after the refused snapshot: %+v, want cluster_uid_conflict (missing, via RBAC snapshot), uid-a kept",
			readSource(t, db, src))
	}

	// The recorded UID is still accepted.
	ok := snapshot(ws, src, true, true, true)
	ok.ClusterUID = "uid-a"
	if w := postSnapshot(r, ok); w.Code != http.StatusOK {
		t.Errorf("the recorded uid: %d %s, want 200", w.Code, w.Body.String())
	}

	// Requirement off: a snapshot stating no UID is accepted as before ...
	t.Setenv(services.RequireClusterUIDEnv, "false")
	if w := postSnapshot(r, snapshot(ws, src, true, true, true)); w.Code != http.StatusOK {
		t.Errorf("requirement off, no uid: %d %s, want 200", w.Code, w.Body.String())
	}
	// ... and a different UID is refused regardless.
	other := snapshot(ws, src, true, true, true)
	other.ClusterUID = "uid-b"
	if w := postSnapshot(r, other); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "cluster_uid_mismatch") {
		t.Errorf("requirement off, uid-b: %d %s, want 409 cluster_uid_mismatch", w.Code, w.Body.String())
	}
	if got := readSource(t, db, src).ClusterUID; got != "uid-a" {
		t.Errorf("cluster_uid = %q at the end, want uid-a", got)
	}
}

func manifestRouter(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/resync-manifest", platform.NewDiscoveryController(db).ReportResyncManifest)
	return r
}

// postManifest posts a complete manifest of `cluster` that observed nothing:
// every sighting in iga-demo it covers is marked gone if it is applied.
func postManifest(r *gin.Engine, ws, src uuid.UUID, uid string, bySource bool,
	after time.Time) *httptest.ResponseRecorder {

	body := map[string]any{
		"workspace_id": ws.String(), "source": "k8s_webhook", "cluster": cluster,
		"complete": true, "namespaces": []string{"iga-demo"}, "fingerprints": []string{},
		"sweep_started_at": after.Add(2 * time.Second), "observed_at": after.Add(3 * time.Second),
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

// Resync manifest: refused without a UID once the connection has one --
// before it marks anything gone -- whether it names the connection or only
// the cluster; applied while the connection has none; applied with the
// requirement off.
func TestIdentUIDRequiredManifest(t *testing.T) {
	db := ingestDB(t)
	t.Setenv(services.RequireClusterUIDEnv, "")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	r := manifestRouter(db)
	now := time.Now().UTC()

	// A connection with no recorded UID: unchanged.
	wsOld, srcOld := seedWorkspace(t, db)
	if _, _, err := disco.ReportSighting(wsOld, "test", uidSighting(srcOld, "fp-old", "", now)); err != nil {
		t.Fatalf("sighting: %v", err)
	}
	if w := postManifest(r, wsOld, srcOld, "", true, now); w.Code != http.StatusOK {
		t.Fatalf("no recorded uid, none stated: %d %s, want 200", w.Code, w.Body.String())
	}
	if got := agentRuntime(t, db, wsOld, "fp-old"); got != "gone" {
		t.Errorf("fp-old = %q after an applied complete manifest, want gone", got)
	}

	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, "fp-1", "uid-a", now)); err != nil {
		t.Fatalf("sighting: %v", err)
	}
	for _, bySource := range []bool{true, false} {
		w := postManifest(r, ws, src, "", bySource, now)
		if code, detail := errorCode(w); w.Code != http.StatusConflict || code != "cluster_uid_required" || detail == "" {
			t.Errorf("bySource=%v, no uid: %d %s, want 409 cluster_uid_required", bySource, w.Code, w.Body.String())
		}
		if got := agentRuntime(t, db, ws, "fp-1"); got == "gone" {
			t.Fatalf("bySource=%v: a refused manifest marked fp-1 gone", bySource)
		}
	}
	if !flaggedMissing(t, db, src, "uid-a", "resync manifest") {
		t.Errorf("connection after the refused manifest: %+v, want cluster_uid_conflict (missing, via resync manifest)",
			readSource(t, db, src))
	}

	// Requirement off: applied as before (fp-1 absent -> gone).
	t.Setenv(services.RequireClusterUIDEnv, "false")
	if w := postManifest(r, ws, src, "", true, now); w.Code != http.StatusOK {
		t.Fatalf("requirement off, no uid: %d %s, want 200", w.Code, w.Body.String())
	}
	if got := agentRuntime(t, db, ws, "fp-1"); got != "gone" {
		t.Errorf("fp-1 = %q after the manifest applied with the requirement off, want gone", got)
	}
}

// Sighting: stored in the inventory, never projected (when reported, directly,
// or by the source's own sweep), connection flagged; projected for a source
// with no UID, and with the requirement off.
func TestIdentUIDRequiredSighting(t *testing.T) {
	db := ingestDB(t)
	ws, src := seedWorkspace(t, db)
	setRecordedUID(t, db, src, "uid-a")
	t.Setenv(services.GraphProjectionEnv, "on")
	t.Setenv(services.RequireClusterUIDEnv, "")
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	now := time.Now().UTC()

	// In this order: the matching cluster's sighting after the refused one
	// must not clear the flag the refused one set.
	for _, c := range []struct{ fp, uid string }{{"fp-none", ""}, {"fp-same", "uid-a"}} {
		if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, c.fp, c.uid, now)); err != nil {
			t.Fatalf("sighting %s: %v (a sighting is never refused from the inventory)", c.fp, err)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM discovered_agents WHERE workspace_id = ? AND fingerprint = 'fp-none'`,
		ws); n != 1 {
		t.Fatalf("fp-none: %d inventory rows, want 1 -- a sighting without a uid is still stored", n)
	}
	live := func(ws uuid.UUID, fp string) bool {
		return workloadID(t, db, ws, k8sgraph.WorkloadKey(cluster, fp)) != uuid.Nil
	}
	if !live(ws, "fp-same") {
		t.Error("the sighting stating the recorded uid was not projected")
	}
	if live(ws, "fp-none") {
		t.Error("a sighting stating no uid was projected into a source that recorded one")
	}
	if !flaggedMissing(t, db, src, "uid-a", "sighting") {
		t.Errorf("connection after the sighting without a uid: %+v, want cluster_uid_conflict (missing, via sighting)",
			readSource(t, db, src))
	}
	// Even past the hold, a later good sighting does not clear it.
	if err := db.Exec(`UPDATE discovery_sources
	    SET runtime = jsonb_set(runtime, '{cluster_uid_conflict,last_seen_at}',
	                            to_jsonb(now() - interval '1 hour'))
	    WHERE id = ?`, src).Error; err != nil {
		t.Fatalf("age the conflict: %v", err)
	}
	if _, _, err := disco.ReportSighting(ws, "test", uidSighting(src, "fp-same", "uid-a", now)); err != nil {
		t.Fatalf("re-sighting: %v", err)
	}
	if got := readSource(t, db, src); got.LastStatus != repositories.ClusterUIDConflictStatus {
		t.Errorf("a good sighting after the hold cleared the conflict: %+v", got)
	}
	if err := hardeningMgr(db).ProjectSighting(ws, "fp-none"); !errors.Is(err, services.ErrClusterUIDRequired) {
		t.Errorf("ProjectSighting(fp-none) = %v, want ErrClusterUIDRequired", err)
	}

	// The source's own sweep does not project it either.
	snap := snapshot(ws, src, true, true, true)
	snap.ClusterUID = "uid-a"
	if _, err := hardeningMgr(db).Ingest(ws, snap); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if live(ws, "fp-none") {
		t.Error("the recorded cluster's sweep projected a sighting stating no uid")
	}
	if n := workloadSupport(t, db, ws, "fp-same", src); n != 1 {
		t.Errorf("fp-same: %d live support rows after the sweep, want 1", n)
	}

	// A source with no recorded UID: projected as before.
	wsOld, srcOld := seedWorkspace(t, db)
	if _, _, err := disco.ReportSighting(wsOld, "test", uidSighting(srcOld, "fp-legacy", "", now)); err != nil {
		t.Fatalf("legacy sighting: %v", err)
	}
	if !live(wsOld, "fp-legacy") {
		t.Error("a sighting stating no uid, for a source with none, was not projected")
	}

	// Requirement off: projected as before.
	t.Setenv(services.RequireClusterUIDEnv, "false")
	if err := hardeningMgr(db).ProjectSighting(ws, "fp-none"); err != nil {
		t.Fatalf("requirement off: ProjectSighting(fp-none) = %v", err)
	}
	if !live(ws, "fp-none") {
		t.Error("requirement off: a sighting stating no uid was not projected")
	}
}

// Heartbeat: a heartbeat stating no UID is accepted (liveness) and never
// clears or flags the recorded one, and the recorded UID keeps governing
// snapshots.
func TestIdentUIDRequiredHeartbeatWithoutUID(t *testing.T) {
	db := ingestDB(t)
	ws, _ := seedWorkspace(t, db)
	t.Setenv(services.RequireClusterUIDEnv, "")
	const name = "hb-cluster"

	src := heartbeat(t, db, ws, name, "uid-a")
	before := readSource(t, db, src.ID).LastHeartbeatAt
	time.Sleep(10 * time.Millisecond)
	out := heartbeat(t, db, ws, name, "") // fails the test on any error
	if out.ID != src.ID {
		t.Fatalf("a heartbeat without a uid minted connector %s; want the existing %s", out.ID, src.ID)
	}
	got := readSource(t, db, src.ID)
	if got.ClusterUID != "uid-a" || out.ClusterUID != "uid-a" {
		t.Errorf("cluster_uid = %q (returned %q) after a heartbeat with none, want uid-a kept",
			got.ClusterUID, out.ClusterUID)
	}
	if got.LastStatus != "healthy" || got.Conflict != "" {
		t.Errorf("a heartbeat without a uid flagged the connection: %+v", got)
	}
	if !got.LastHeartbeatAt.After(before) {
		t.Error("the heartbeat without a uid was not accepted as liveness")
	}

	// The recorded UID still governs: a snapshot stating none is refused.
	mgr := hardeningMgr(db)
	if _, err := mgr.Ingest(ws, clusterSnapshot(ws, src.ID, name)); !errors.Is(err, services.ErrClusterUIDRequired) {
		t.Errorf("snapshot without a uid: err = %v, want ErrClusterUIDRequired", err)
	}
	// Heartbeats after that refusal keep working and keep the UID.
	heartbeat(t, db, ws, name, "")
	if got := readSource(t, db, src.ID); got.ClusterUID != "uid-a" ||
		got.LastStatus != repositories.ClusterUIDConflictStatus {
		t.Errorf("heartbeat after a refused snapshot: %+v, want uid-a kept and the conflict held", got)
	}
	mine := clusterSnapshot(ws, src.ID, name)
	mine.ClusterUID = "uid-a"
	if _, err := mgr.Ingest(ws, mine); err != nil {
		t.Errorf("snapshot from the recorded uid-a refused: %v", err)
	}

	// Past the hold, a heartbeat stating no UID still does not clear the
	// conflict -- it is not the recorded cluster vouching for itself -- and one
	// from the recorded UID does.
	if err := db.Exec(`UPDATE discovery_sources
	    SET runtime = jsonb_set(runtime, '{cluster_uid_conflict,last_seen_at}',
	                            to_jsonb(now() - interval '1 hour'))
	    WHERE id = ?`, src.ID).Error; err != nil {
		t.Fatalf("age the conflict: %v", err)
	}
	heartbeat(t, db, ws, name, "")
	if got := readSource(t, db, src.ID); got.LastStatus != repositories.ClusterUIDConflictStatus || got.Conflict == "" {
		t.Errorf("a heartbeat without a uid cleared the conflict: %+v", got)
	}
	heartbeat(t, db, ws, name, "uid-a")
	if got := readSource(t, db, src.ID); got.LastStatus != "healthy" || got.Conflict != "" || got.ClusterUID != "uid-a" {
		t.Errorf("a heartbeat from the recorded uid after the hold: %+v, want healthy, no conflict", got)
	}
}
