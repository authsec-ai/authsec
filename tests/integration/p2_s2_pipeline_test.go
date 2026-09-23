package integration

// T2.3 (SPEC-iga-phase2-graph.md §5.3, §2.14.7; D-55, D-56, D-59): GET
// /api/iga/v1/pipeline, driven through the REAL worker and projector. Gate:
// the pipeline reports queued-behind, collecting and projecting.

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func TestP2S2PipelineQueuedBehindCollectingProjecting(t *testing.T) {
	l := newP2Lab(t, "p2-s2-pipeline", true)
	a := oneLambda(l)
	b := l.account(accountB)
	b.role("sandbox-role", "AROAS2PIPELINEBBBBBB")
	api := l.api()

	// Connected, never scanned; no barrier row yet.
	view := s2Pipeline(t, api)
	if digs(view, "barrier", "state") != models.PipelineIdle || dig(view, "barrier", "since") != nil ||
		dig(view, "current_rev") != nil {
		t.Fatalf("fresh workspace pipeline = %v", view)
	}
	for _, acct := range []*p2Account{a, b} {
		if st := digs(s2PipelineAccount(t, view, acct), "state"); st != "never_scanned" {
			t.Fatalf("account %s before any scan = %q, want never_scanned", acct.id, st)
		}
	}

	// A is queued: shown at once (§2.15 step 1), waiting on nothing.
	runA, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	accA := s2PipelineAccount(t, s2Pipeline(t, api), a)
	if digs(accA, "state") != "queued" || digs(accA, "latest_run", "status") != models.CloudScanRunQueued ||
		digs(accA, "latest_run", "queued_at") == "" || dig(accA, "latest_run", "waiting_on") != nil {
		t.Fatalf("A queued on an idle barrier = %v", accA)
	}

	// B is queued too, and A starts collecting. Observed from INSIDE A's scan.
	time.Sleep(5 * time.Millisecond)
	runB, err := l.runs.Enqueue(l.ws, b.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	var during map[string]any
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("s2-pipeline-worker-a").
		WithGraphProjection(l.gate).WithScannerHook(func(i *services.AWSIAMScanner, p *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		a.hook()(i, p, wl)
		p.WithEKSAPI(&s2DuringEKS{fakeEKS: newFakeEKS(), during: func() {
			// A heartbeat moves the lease's updated_at on every renewal; since
			// must not follow it (D-92).
			l.db.Exec(`UPDATE iga_pipeline_lease SET updated_at = updated_at + interval '2 hours' WHERE workspace_id = ?`, l.ws)
			during = s2Pipeline(t, api)
		}})
	})
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("scan A: worked=%v err=%v", worked, err)
	}
	if during == nil {
		t.Fatal("setup: /pipeline was never read during the scan")
	}
	var started models.CloudScanRun
	l.db.First(&started, "id = ?", runA.ID)
	if digs(during, "barrier", "state") != models.PipelineCollecting ||
		digs(during, "barrier", "scan_run") != refOf("cloud_scan_run", runA.ID) ||
		digs(during, "barrier", "integration") != refOf("cloud_connector", a.conn) ||
		digs(during, "barrier", "account_id") != a.id || digs(during, "barrier", "label") != "acct-"+a.id ||
		digs(during, "barrier", "since") == "" || digs(during, "barrier", "since") != digs(during, "barrier", "started_at") {
		t.Fatalf("barrier while A collects = %v", dig(during, "barrier"))
	}
	if acc := s2PipelineAccount(t, during, a); digs(acc, "state") != "collecting" ||
		digs(acc, "latest_run", "status") != models.CloudScanRunRunning || digs(acc, "latest_run", "started_at") == "" {
		t.Fatalf("A while collecting = %v", acc)
	}
	// QUEUED BEHIND: B waits on the run the barrier holds.
	if acc := s2PipelineAccount(t, during, b); digs(acc, "state") != "queued" ||
		digs(acc, "latest_run", "waiting_on") != refOf("cloud_scan_run", runA.ID) {
		t.Fatalf("B while A collects = %v, want queued, waiting_on A's run", acc)
	}

	// A published, not yet projected: projecting, and B still waits on A.
	// since is when the barrier passed to the projection (A's publication),
	// however often the lease has been renewed since.
	l.db.Exec(`UPDATE iga_pipeline_lease SET updated_at = updated_at + interval '2 hours' WHERE workspace_id = ?`, l.ws)
	view = s2Pipeline(t, api)
	l.db.First(&started, "id = ?", runA.ID)
	if digs(view, "barrier", "state") != models.PipelineProjecting ||
		digs(view, "barrier", "since") != s2TS(started.PublishedAt) {
		t.Fatalf("barrier after A published = %v, want projecting since A's publication %s", dig(view, "barrier"), s2TS(started.PublishedAt))
	}
	accA = s2PipelineAccount(t, view, a)
	if digs(accA, "state") != "projecting" || digs(accA, "projection", "status") != models.ProjectionQueued ||
		dig(accA, "projection", "rev") != nil || dig(accA, "last_published_rev") != nil {
		t.Fatalf("A published, unprojected = %v", accA)
	}
	if acc := s2PipelineAccount(t, view, b); digs(acc, "latest_run", "waiting_on") != refOf("cloud_scan_run", runA.ID) {
		t.Fatalf("B while A projects = %v, want waiting_on A's run", acc)
	}

	// A worker claims B and is REFUSED by the barrier: B stays queued, and a
	// refusal leaves no start time behind (D-55).
	refused := services.NewAWSScanWorker(l.db, b.svc).WithOwner("s2-pipeline-worker-b").
		WithGraphProjection(l.gate).WithScannerHook(b.hook())
	if worked, err := refused.RunOnce(context.Background()); worked || err != nil {
		t.Fatalf("claim of B behind a busy barrier: worked=%v err=%v, want refused", worked, err)
	}
	var bRun models.CloudScanRun
	l.db.First(&bRun, "id = ?", runB.ID)
	if bRun.Status != models.CloudScanRunQueued || bRun.StartedAt != nil {
		t.Fatalf("B after a refused claim: status %s, started_at %v; want queued with no start", bRun.Status, bRun.StartedAt)
	}
	if acc := s2PipelineAccount(t, s2Pipeline(t, api), b); dig(acc, "latest_run", "started_at") != nil ||
		digs(acc, "latest_run", "queued_at") != s2TS(&bRun.RequestedAt) {
		t.Fatalf("B after refusal = %v, want queued_at = requested_at (D-55) and no started_at", acc)
	}

	// Projected: published at rev 1, the barrier idle, B no longer waiting.
	l.project("s2-pipeline-projector-a")
	view = s2Pipeline(t, api)
	accA = s2PipelineAccount(t, view, a)
	if digs(accA, "state") != "published" || digs(accA, "projection", "status") != models.ProjectionComplete ||
		num(accA, "projection", "rev") != 1 || num(accA, "last_published_rev") != 1 {
		t.Fatalf("A projected = %v", accA)
	}
	if digs(view, "barrier", "state") != models.PipelineIdle || num(view, "current_rev") != 1 ||
		digs(view, "current_published_at") == "" {
		t.Fatalf("pipeline after projection = %v", view)
	}
	if acc := s2PipelineAccount(t, view, b); digs(acc, "state") != "queued" || dig(acc, "latest_run", "waiting_on") != nil {
		t.Fatalf("B on an idle barrier = %v, want queued, waiting_on null", acc)
	}

	// B scans; its projection FAILS below the attempts ceiling: still
	// projecting, retrying (D-59). At the ceiling it is failed.
	wb := services.NewAWSScanWorker(l.db, b.svc).WithOwner("s2-pipeline-worker-b2").
		WithGraphProjection(l.gate).WithScannerHook(b.hook())
	if worked, err := wb.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("scan B: worked=%v err=%v", worked, err)
	}
	l.db.Exec(`UPDATE iga_projection_job SET status = 'failed', attempts = 1, last_error = 'deadlock detected',
	             lease_expires_at = now() + interval '30 seconds' WHERE scan_run_id = ?`, runB.ID)
	accB := s2PipelineAccount(t, s2Pipeline(t, api), b)
	if digs(accB, "state") != "projecting" || dig(accB, "projection", "retrying") != true ||
		num(accB, "projection", "attempts") != 1 || digs(accB, "projection", "last_error") != "deadlock detected" ||
		digs(accB, "projection", "status") != models.ProjectionFailed {
		t.Fatalf("B's projection failing below the ceiling = %v, want projecting, retrying", accB)
	}
	l.db.Exec(`UPDATE iga_projection_job SET attempts = ? WHERE scan_run_id = ?`, repositories.MaxProjectionAttempts, runB.ID)
	accB = s2PipelineAccount(t, s2Pipeline(t, api), b)
	if digs(accB, "state") != "failed" || dig(accB, "projection", "retrying") != false {
		t.Fatalf("B's projection at the ceiling = %v, want failed, not retrying", accB)
	}
	// B's own last_published_rev is still none; A's is 1 (D-56).
	if dig(accB, "last_published_rev") != nil {
		t.Fatalf("B last_published_rev = %v, want null (never projected)", dig(accB, "last_published_rev"))
	}
	// Leave the workspace clean for the lab's cleanup.
	l.db.Exec(`UPDATE iga_projection_job SET status = 'abandoned' WHERE scan_run_id = ?`, runB.ID)
	l.db.Exec(`UPDATE iga_pipeline_lease SET state = 'idle', holder = '', scan_run_id = NULL, expires_at = NULL WHERE workspace_id = ?`, l.ws)
}

// D-55: a refused claim clears started_at only when THIS claim set it. A run
// reclaimed after its worker died really did start collecting, and a refused
// reclaim must not erase that.
func TestP2S2RefusedReclaimKeepsItsStart(t *testing.T) {
	l := newP2Lab(t, "p2-s2-reclaim-start", true)
	a := oneLambda(l)
	b := l.account(accountB)
	run, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	first, err := l.runs.ClaimForPipeline("s2-dead-collector", time.Minute, time.Now())
	if err != nil || first == nil || first.ID != run.ID || first.StartedAt == nil {
		t.Fatalf("first claim: %v %v", first, err)
	}
	began := *first.StartedAt
	// The collector died; its lease lapsed. Meanwhile ANOTHER run holds the
	// barrier, so the reclaim is refused.
	l.db.Exec(`UPDATE cloud_scan_run SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, run.ID)
	otherRun, err := l.runs.Enqueue(l.ws, b.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	pipe := repositories.NewIGAPipelineLeaseRepository(l.db)
	if _, err := pipe.AcquireForCollection(l.ws, "s2-other-holder", otherRun.ID, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("s2-reclaimer").
		WithGraphProjection(l.gate).WithScannerHook(a.hook())
	if worked, err := w.RunOnce(context.Background()); worked || err != nil {
		t.Fatalf("reclaim behind a busy barrier: worked=%v err=%v, want refused", worked, err)
	}
	var after models.CloudScanRun
	l.db.First(&after, "id = ?", run.ID)
	if after.Status != models.CloudScanRunQueued {
		t.Fatalf("refused reclaim left the run %s", after.Status)
	}
	if after.StartedAt == nil || !after.StartedAt.Equal(began) {
		t.Fatalf("refused reclaim started_at = %v, want the original start %v kept", after.StartedAt, began)
	}
	l.db.Exec(`UPDATE iga_pipeline_lease SET state = 'idle', holder = '', scan_run_id = NULL, expires_at = NULL WHERE workspace_id = ?`, l.ws)
}

// /pipeline and /coverage are graph routes: 503 while the switch is off
// (D-10, D-11), and /capabilities says coverage only while it is on.
func TestP2S2PipelineAndCoverageUnavailableWhenOff(t *testing.T) {
	off := newP2Lab(t, "p2-s2-off", false)
	api := off.api()
	for _, path := range []string{"/pipeline", "/coverage"} {
		code, body := api.get(path)
		if code != http.StatusServiceUnavailable || errCode(body) != "graph_unavailable" {
			t.Fatalf("GET %s with the switch off = %d %v, want 503 graph_unavailable", path, code, body)
		}
		if perm := api.requiredPermission(http.MethodGet, path); perm != "iga:read" {
			t.Fatalf("GET %s demands %q, want iga:read", path, perm)
		}
	}
	if code, body := api.get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "coverage") != false {
		t.Fatalf("/capabilities off = %d %v, want features.coverage false", code, body)
	}

	on := newP2Lab(t, "p2-s2-on", true)
	if code, body := on.api().get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "coverage") != true ||
		dig(body, "data", "features", "workloads") != true {
		// workloads: T6.2's list and T6.3's detail and tabs are all served (D-11).
		t.Fatalf("/capabilities on = %d %v, want coverage and workloads true", code, body)
	}
}

// D-56, D-89, D-92, D-82: with two accounts projected, BOTH are at the
// revision the graph is at (the §5.3 example's "41" twice), while each run
// carries the revision that published it; a failed run is shown with its
// error and does not take the account out of the graph; a revoked connector is
// listed as revoked; accounts come in label order; and the route takes no
// parameters -- a rev in particular is refused, since it reports live state.
func TestP2S2PipelineAccountsAtTheCurrentRevision(t *testing.T) {
	l := newP2Lab(t, "p2-s2-pipeline-revs", true)
	a := oneLambda(l)
	b := l.account(accountB)
	b.role("sandbox-role", "AROAS2PIPELINEREVSBB")
	c := l.account("111122223333")
	api := l.api()

	runA := l.scanAndProject(a) // rev 1
	time.Sleep(5 * time.Millisecond)
	runB := l.scanAndProject(b) // rev 2
	if _, err := repositories.NewCloudConnectorRepository(l.db).Revoke(l.ws, c.conn); err != nil {
		t.Fatal(err)
	}

	view := s2Pipeline(t, api)
	if num(view, "current_rev") != 2 {
		t.Fatalf("current_rev = %v, want 2", dig(view, "current_rev"))
	}
	for _, x := range []struct {
		acct *p2Account
		run  models.CloudScanRun
		rev  int64
	}{{a, runA, 1}, {b, runB, 2}} {
		acc := s2PipelineAccount(t, view, x.acct)
		if digs(acc, "state") != "published" || num(acc, "last_published_rev") != 2 ||
			digs(acc, "latest_run", "ref") != refOf("cloud_scan_run", x.run.ID) ||
			num(acc, "projection", "rev") != x.rev || digs(acc, "connector_status") != models.CloudConnectorActive {
			t.Fatalf("account %s = %v, want published, last_published_rev 2 (the graph's), projection.rev %d (its run's)",
				x.acct.id, acc, x.rev)
		}
	}
	accC := s2PipelineAccount(t, view, c)
	if digs(accC, "state") != "revoked" || digs(accC, "connector_status") != models.CloudConnectorRevoked ||
		dig(accC, "latest_run") != nil || dig(accC, "last_published_rev") != nil {
		t.Fatalf("revoked, never-scanned connector = %v, want listed as revoked with nothing published", accC)
	}
	// Label order (D-92): acct-111122223333, acct-429418377036, acct-905418271234.
	var order []string
	for _, acc := range digl(view, "accounts") {
		order = append(order, digs(acc, "account_id"))
	}
	if !reflect.DeepEqual(order, []string{c.id, a.id, b.id}) {
		t.Fatalf("accounts in order %v, want by label", order)
	}

	// A's next run FAILS: it is A's latest run, shown failed with its error;
	// the graph still holds A's earlier publication.
	time.Sleep(5 * time.Millisecond)
	failed, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := l.runs.ClaimForPipeline("s2-failing-worker", time.Minute, time.Now())
	if err != nil || claimed == nil || claimed.ID != failed.ID {
		t.Fatalf("claim the run to fail: %v %v", claimed, err)
	}
	if err := l.runs.Fail(failed.ID, "s2-failing-worker", claimed.LeaseVersion, "iam scan: connection reset"); err != nil {
		t.Fatal(err)
	}
	accA := s2PipelineAccount(t, s2Pipeline(t, api), a)
	if digs(accA, "state") != "failed" || digs(accA, "latest_run", "ref") != refOf("cloud_scan_run", failed.ID) ||
		digs(accA, "latest_run", "error") != "iam scan: connection reset" || digs(accA, "latest_run", "finished_at") == "" ||
		dig(accA, "projection") != nil || num(accA, "last_published_rev") != 2 {
		t.Fatalf("A after a failed run = %v, want failed with its error, still at the graph's rev", accA)
	}

	// A's next run is queued. It is A's latest run even if the failed run's
	// requested_at sorts after it (clock skew between hosts, or a refused
	// claim's requeue): the live run is what the account is doing now (D-92).
	next, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	l.db.Exec(`UPDATE cloud_scan_run SET requested_at = now() + interval '1 hour' WHERE id = ?`, failed.ID)
	accA = s2PipelineAccount(t, s2Pipeline(t, api), a)
	if digs(accA, "state") != "queued" || digs(accA, "latest_run", "ref") != refOf("cloud_scan_run", next.ID) {
		t.Fatalf("A with a queued run = %v, want the queued run as latest_run", accA)
	}

	// No parameters: rev is refused rather than honoured as a pin it is not.
	for _, q := range []string{qs("rev", "2"), qs("account", a.id)} {
		code, body := api.get("/pipeline" + q)
		if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Fatalf("/pipeline%s = %d %v, want 400 invalid_parameter", q, code, body)
		}
	}
	if _, body := api.get("/pipeline" + qs("rev", "2")); digs(body, "error", "parameter") != "rev" {
		t.Fatalf("/pipeline?rev must name rev: %v", body)
	}
}

/* --------------------------------- helpers -------------------------------- */

func s2Pipeline(t *testing.T, api *readAPI) map[string]any {
	t.Helper()
	code, body := api.get("/pipeline")
	mustStatus(t, "GET /pipeline", code, body, http.StatusOK)
	data, _ := body["data"].(map[string]any)
	if data == nil {
		t.Fatalf("/pipeline has no data: %v", body)
	}
	return data
}

func s2PipelineAccount(t *testing.T, view map[string]any, a *p2Account) map[string]any {
	t.Helper()
	for _, acc := range digl(view, "accounts") {
		if digs(acc, "integration") == refOf("cloud_connector", a.conn) {
			if digs(acc, "account_id") != a.id {
				t.Fatalf("account line %v names the wrong account", acc)
			}
			m, _ := acc.(map[string]any)
			return m
		}
	}
	t.Fatalf("no /pipeline line for account %s: %v", a.id, view)
	return nil
}

// s2TS renders a time the way the read API does.
func s2TS(at *time.Time) string {
	if at == nil {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}
