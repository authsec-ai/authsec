package integration

// §7.1 E1 (connect and publish the first graph) and E13 (interruption, lease
// loss and replay): the backend halves, through the real /pipeline, list and
// discovery routes. The console half -- first-run states drawn in order, the
// list appearing without a reload, the *as of* label -- is M3's Playwright run
// (T8.2) against real AWS; here the API those states are drawn from is
// asserted at each step.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// egatesNotPublished asserts §5.1's first-run list answer: 200, no rows, no
// revision, graph_state not_published -- never an empty "published" list.
func egatesNotPublished(t *testing.T, api *readAPI, path string) {
	t.Helper()
	body := egatesGet(t, api, path)
	if len(digl(body, "data")) != 0 || digs(body, "meta", "graph_state") != "not_published" ||
		dig(body, "meta", "rev") != nil || dig(body, "meta", "published_at") != nil {
		t.Errorf("%s before the first publication = %s, want 200, no rows, rev null, graph_state not_published",
			path, egatesJSON(body))
	}
}

// egatesPublication is the workspace's publication of one run.
type egatesPublication struct {
	Rev         int64
	PublishedAt time.Time
}

func egatesPublicationOf(t *testing.T, l *p2Lab, run uuid.UUID) egatesPublication {
	t.Helper()
	var p egatesPublication
	if err := l.db.Raw(`SELECT rev, published_at FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`,
		l.ws, run).Row().Scan(&p.Rev, &p.PublishedAt); err != nil {
		t.Fatalf("no publication of run %s: %v", run, err)
	}
	return p
}

// egatesPubTime renders a publication time as the envelope does: meta.
// published_at is RFC 3339 UTC to the second, the one rendering of a
// publication's time on every route (D-96, igaread.PublicationTime).
func egatesPubTime(at time.Time) string { return igaread.PublicationTime(at).Format(time.RFC3339) }

// E1. Connect A with regions eu-central-1 and us-east-1; queue a scan through
// the discovery route; the real worker collects and publishes; the real
// projector projects. /pipeline moves queued -> collecting -> projecting ->
// published (an account state, with the barrier idle), nothing is listed until
// the publication, and then /workloads lists A's workloads at rev 1 as of the
// publication time. The second scan starts, and a pinned rev 1 is then stale.
//
// Database: one published run, one job complete, the barrier idle, one
// iga_publication at rev 1, no AWS rows in iga_agents or iga_agent_instances.
//
// Safeguards (mutation-checked): the list is empty until the projection
// commits (lists read the publication, not the collected inventory), and the
// pipeline reports collecting from inside the run.
func TestP2EgatesE1ConnectAndPublishFirstGraph(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e1", true)
	a := egatesProduction(t, l)
	api := l.api()
	disc := egatesDiscoveryAPI(t, l, a)

	// Connected with both regions, never scanned: no revision anywhere.
	if got := egatesSorted(s2ConnectorRegions(t, l, a.conn)); len(got) != 2 || got[0] != egatesPrimary || got[1] != egatesSecondary {
		t.Fatalf("connector regions = %v, want [%s %s]", got, egatesPrimary, egatesSecondary)
	}
	view := s2Pipeline(t, api)
	acc := s2PipelineAccount(t, view, a.p2Account)
	if digs(view, "barrier", "state") != models.PipelineIdle || dig(view, "current_rev") != nil ||
		dig(view, "current_published_at") != nil || digs(acc, "state") != "never_scanned" ||
		dig(acc, "last_published_rev") != nil || digs(acc, "label") != "acct-"+a.id {
		t.Fatalf("pipeline of a connected, never-scanned account = %s", egatesJSON(view))
	}
	for _, p := range []string{"/workloads", "/identities", "/resources", "/coverage"} {
		egatesNotPublished(t, api, p)
	}
	// What the console asks first (§5.3 /capabilities): the switch on at 036,
	// every feature served -- before anything is published, so "nothing
	// published yet" is never drawn as "unavailable" (§2.14.7).
	caps := egatesGet(t, api, "/capabilities")
	if digs(caps, "data", "graph_projection") != "on" || dig(caps, "data", "reason") != nil ||
		digs(caps, "data", "schema_head") != "036" {
		t.Errorf("/capabilities = %s, want on at 036 with no reason", egatesJSON(dig(caps, "data")))
	}
	for _, f := range []string{"workloads", "identities", "resources", "graph", "evidence", "changes", "classification", "coverage"} {
		if dig(caps, "data", "features", f) != true {
			t.Errorf("/capabilities features.%s = %v, want true", f, dig(caps, "data", "features", f))
		}
	}

	// Queued at once (§2.15 step 1), waiting on nothing.
	runID := disc.queueScan(a)
	view = s2Pipeline(t, api)
	acc = s2PipelineAccount(t, view, a.p2Account)
	if digs(acc, "state") != "queued" || digs(acc, "latest_run", "status") != models.CloudScanRunQueued ||
		digs(acc, "latest_run", "ref") != refOf("cloud_scan_run", runID) ||
		dig(acc, "latest_run", "waiting_on") != nil || digs(acc, "latest_run", "queued_at") == "" ||
		digs(view, "barrier", "state") != models.PipelineIdle {
		t.Fatalf("pipeline right after POST scan = %s, want A queued on an idle barrier", egatesJSON(view))
	}

	// Collecting, observed from INSIDE the worker's run -- and nothing listed
	// yet: a collection in progress is never shown as a graph.
	var during, duringList map[string]any
	a.extra = func(_ *services.AWSIAMScanner, p *services.AWSPermissionScanner, _ *services.AWSWorkloadScanner) {
		p.WithEKSAPI(&s2DuringEKS{fakeEKS: newFakeEKS(), during: func() {
			during = s2Pipeline(t, api)
			duringList = egatesGet(t, api, "/workloads")
		}})
	}
	if !egatesWork(l, a, "egates-e1-worker") {
		t.Fatal("the worker claimed nothing, want the queued run")
	}
	a.extra = nil
	if during == nil {
		t.Fatal("setup: /pipeline was never read during the scan")
	}
	acc = s2PipelineAccount(t, during, a.p2Account)
	if digs(during, "barrier", "state") != models.PipelineCollecting ||
		digs(during, "barrier", "scan_run") != refOf("cloud_scan_run", runID) ||
		digs(acc, "state") != "collecting" || digs(acc, "latest_run", "status") != models.CloudScanRunRunning ||
		digs(acc, "latest_run", "started_at") == "" {
		t.Errorf("pipeline while collecting = %s", egatesJSON(during))
	}
	if len(digl(duringList, "data")) != 0 || digs(duringList, "meta", "graph_state") != "not_published" {
		t.Errorf("/workloads while collecting = %s, want nothing listed before the publication", egatesJSON(duringList))
	}

	// Published by the worker, not yet projected: projecting, still unlisted.
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", runID).Error; err != nil || run.Status != models.CloudScanRunPublished {
		t.Fatalf("run after the worker = %+v (%v), want published", run.Status, err)
	}
	view = s2Pipeline(t, api)
	acc = s2PipelineAccount(t, view, a.p2Account)
	if digs(view, "barrier", "state") != models.PipelineProjecting || digs(view, "barrier", "since") != s2TS(run.PublishedAt) ||
		digs(acc, "state") != "projecting" || digs(acc, "projection", "status") != models.ProjectionQueued ||
		dig(acc, "projection", "rev") != nil || dig(view, "current_rev") != nil {
		t.Errorf("pipeline after collection = %s, want projecting since the run's publication", egatesJSON(view))
	}
	egatesNotPublished(t, api, "/workloads")

	// Projected: published at rev 1.
	l.project("egates-e1-projector")
	pub := egatesPublicationOf(t, l, runID)
	if pub.Rev != 1 {
		t.Fatalf("first publication is rev %d, want 1", pub.Rev)
	}
	view = s2Pipeline(t, api)
	acc = s2PipelineAccount(t, view, a.p2Account)
	if digs(view, "barrier", "state") != models.PipelineIdle || dig(view, "barrier", "since") != nil ||
		num(view, "current_rev") != 1 || digs(view, "current_published_at") != s2TS(&pub.PublishedAt) ||
		digs(acc, "state") != "published" || digs(acc, "projection", "status") != models.ProjectionComplete ||
		num(acc, "projection", "rev") != 1 || num(acc, "last_published_rev") != 1 ||
		digs(acc, "latest_run", "status") != models.CloudScanRunPublished {
		t.Errorf("pipeline after projection = %s, want A published at rev 1 on an idle barrier", egatesJSON(view))
	}

	// /workloads lists A's workloads at rev 1, as of the publication.
	list := egatesGet(t, api, "/workloads")
	egatesMeta(t, "/workloads", list, 1, egatesPubTime(pub.PublishedAt))
	if digs(list, "meta", "graph_state") != "published" || dig(list, "meta", "total_known") != true ||
		num(list, "meta", "total") != 7 || dig(list, "meta", "next_cursor") != nil {
		t.Errorf("/workloads meta = %s", egatesJSON(dig(list, "meta")))
	}
	type wantRow struct{ kind, region, role string }
	want := map[string]wantRow{
		"ticket-tools":   {"lambda_function", egatesPrimary, egatesSharedRole},
		"refund-tools":   {"lambda_function", egatesPrimary, egatesSharedRole},
		"ticket-worker":  {"ecs_task_definition", egatesSecondary, "TicketTaskRole"},
		"reports-host":   {"ec2_instance", egatesSecondary, "ReportsRole"},
		"support-agent":  {"bedrock_agent", egatesSecondary, "BedrockAgentRole"},
		"triage-runtime": {"bedrock_agentcore_runtime", egatesSecondary, "AgentCoreRole"},
		"tools-gateway":  {"bedrock_agentcore_gateway", egatesSecondary, "AgentCoreRole"},
	}
	rows := egatesRows(t, digl(list, "data"), "name")
	if len(rows) != len(want) {
		t.Errorf("/workloads names = %v, want %d workloads of A", listsField(digl(list, "data"), "name"), len(want))
	}
	published := s2TS(&pub.PublishedAt)
	for name, w := range want {
		r := rows[name]
		if r == nil {
			t.Errorf("/workloads has no %s", name)
			continue
		}
		if digs(r, "runtime_kind") != w.kind || digs(r, "region") != w.region ||
			digs(r, "account", "id") != a.id || digs(r, "account", "label") != "acct-"+a.id ||
			dig(r, "account", "connected") != true || digs(r, "lifecycle") != "active" ||
			digs(r, "state") != models.RelCurrent || digs(r, "first_seen_at") != published ||
			digs(r, "last_confirmed_at") != published || digs(r, "execution_role", "state") != "resolved" ||
			digs(r, "execution_role", "name") != w.role || digs(r, "instances", "state") != "not_collected" {
			t.Errorf("/workloads row %s = %s, want %s in %s, account %s, current, confirmed at %s, running as %s",
				name, egatesJSON(r), w.kind, w.region, a.id, published, w.role)
		}
	}
	if code, body := api.get("/workloads" + qs("rev", "1")); code != http.StatusOK || num(body, "meta", "rev") != 1 {
		t.Errorf("/workloads?rev=1 at rev 1 = %d %s", code, egatesJSON(body))
	}

	// The database side of E1.
	if n := l.count(`SELECT count(*) FROM cloud_scan_run WHERE workspace_id = ? AND status = 'published'`, l.ws); n != 1 {
		t.Errorf("published runs = %d, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ? AND status = 'complete'`, l.ws); n != 1 {
		t.Errorf("complete projection jobs = %d, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != 1 {
		t.Errorf("publications = %d, want 1", n)
	}
	if st := l.barrier(); st != models.PipelineIdle {
		t.Errorf("barrier = %s, want idle", st)
	}
	for _, table := range []string{"iga_agents", "iga_agent_instances"} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, l.ws); n != 0 {
			t.Errorf("%s has %d rows after an AWS scan, want 0 (AWS workloads are never GitHub agents)", table, n)
		}
	}
	// The run itself says what became of its projection (§5.3, T2.2).
	code, rb := disc.do(http.MethodGet, "/aws/scan-runs/"+runID.String())
	mustStatus(t, "GET scan-run", code, rb, http.StatusOK)
	if digs(rb, "data", "projection", "status") != models.ProjectionComplete || num(rb, "data", "projection", "rev") != 1 {
		t.Errorf("GET scan-run projection = %s, want complete at rev 1", egatesJSON(dig(rb, "data", "projection")))
	}

	// The second scan starts, publishes rev 2, and a pinned rev 1 is stale.
	second := disc.queueScan(a)
	if !egatesWork(l, a, "egates-e1-worker-2") {
		t.Fatal("the second scan was not claimed")
	}
	l.project("egates-e1-projector-2")
	pub2 := egatesPublicationOf(t, l, second)
	if pub2.Rev != 2 {
		t.Fatalf("second publication rev %d, want 2", pub2.Rev)
	}
	if acc := s2PipelineAccount(t, s2Pipeline(t, api), a.p2Account); digs(acc, "state") != "published" ||
		num(acc, "projection", "rev") != 2 || digs(acc, "latest_run", "ref") != refOf("cloud_scan_run", second) {
		t.Errorf("pipeline after the second scan = %s", egatesJSON(acc))
	}
	code, stale := api.get("/workloads" + qs("rev", "1"))
	if code != http.StatusConflict || errCode(stale) != "revision_stale" || num(stale, "error", "requested_rev") != 1 ||
		num(stale, "error", "current_rev") != 2 || digs(stale, "error", "current_published_at") == "" {
		t.Errorf("/workloads?rev=1 at rev 2 = %d %s, want 409 revision_stale naming rev 2", code, egatesJSON(stale))
	}
}

// E13. Interruption, lease loss and replay, each followed through /pipeline,
// every scan by the REAL AWSScanWorker and every projection pass by the REAL
// ProjectionService:
//
//  1. a scan worker dies mid-collection: it claimed the run and the barrier
//     and stalls inside its first IAM listing (egatesSupersedeMidScan). A
//     second worker started while it is merely paused claims nothing; once
//     its leases run out the next worker reclaims the run without
//     intervention and publishes it; the stalled worker then wakes, and its
//     own fence refuses its first write -- nothing it does afterwards changes
//     a row (TestP2EgatesE13SupersededScannersWriteNothing: the other two
//     scanners);
//  2. a projector dies mid-projection: the service pauses after reading its
//     inputs, before its graph transaction (WithBeforeGraphTx). A second
//     projector started while it is merely paused claims nothing; the job is
//     reclaimed, and when the first pass wakes on the lease it claimed, the
//     service's own fencer refuses it inside its graph transaction and it
//     writes nothing; the job then completes;
//  3. a projector dies after its commit and before completing the job: the
//     replay completes, publishing nothing twice.
//
// Exactly one publication per run; job complete; barrier idle; the next scan
// starts; nothing but the pipeline view ever shows the in-flight state.
//
// Safeguards (mutation-checked): the IAM scanner is built with the run's
// fence; the projection service's fencer asserts the job lease.
func TestP2EgatesE13InterruptionLeaseLossReplay(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e13", true)
	a := egatesProduction(t, l)
	api := l.api()

	// (1) A worker claims the run and the barrier and stalls mid-collection.
	// While it is paused: the pipeline shows the collection in flight, nothing
	// is listed, and a second worker claims nothing (the lease is live).
	run, stale := egatesSupersedeMidScan(t, l, a, egatesPauseIAM, func(owner string) {
		view := s2Pipeline(t, api)
		if digs(view, "barrier", "state") != models.PipelineCollecting ||
			digs(s2PipelineAccount(t, view, a.p2Account), "state") != "collecting" {
			t.Errorf("pipeline while the first worker is paused mid-scan = %s", egatesJSON(view))
		}
		egatesNotPublished(t, api, "/workloads")
		if egatesWork(l, a, "egates-second-worker") {
			t.Fatal("a second worker claimed a run whose lease is live")
		}
		var holder string
		l.db.Raw(`SELECT lease_owner FROM cloud_scan_run WHERE workspace_id = ? AND status = 'running'`, l.ws).Scan(&holder)
		if holder != owner {
			t.Fatalf("run owner after the second worker = %q, want the paused worker's %q", holder, owner)
		}
		if digs(view, "barrier", "scan_run") == "" {
			t.Errorf("pipeline while collecting names no run: %s", egatesJSON(view))
		}
	})
	queued := run
	if st := digs(s2PipelineAccount(t, s2Pipeline(t, api), a.p2Account), "state"); st != "projecting" {
		t.Errorf("after the reclaimed run published: %q, want projecting", st)
	}
	// A supplement at the repository level, under the stalled worker's OWN
	// fence: the generation-reconcile deletes a scan ends with, which the
	// real worker never reaches here (its first write is refused). Aimed at
	// a generation past the reclaimed run's (which keeps its own, T1.5), each
	// WOULD remove every row of its table were it accepted.
	inventory := func() map[string]int64 {
		out := map[string]int64{}
		for _, table := range []string{"cloud_identity", "cloud_workload", "cloud_permission", "cloud_group_membership"} {
			out[table] = l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, l.ws)
		}
		return out
	}
	kept := inventory()
	for table, n := range kept {
		if n == 0 {
			t.Fatalf("setup: %s is empty after the reclaimed scan; a refused delete from it would prove nothing", table)
		}
	}
	next := run.Generation + 1
	for what, del := range map[string]func() error{
		"identity reconcile": func() error {
			_, _, err := repositories.NewCloudIdentityRepository(l.db).Fenced(stale).ReconcileGeneration(l.ws, a.conn, next)
			return err
		},
		"workload reconcile": func() error {
			_, _, err := repositories.NewCloudWorkloadRepository(l.db).Fenced(stale).ReconcileGeneration(l.ws, a.conn, next)
			return err
		},
		"permission reconcile": func() error {
			_, _, _, err := repositories.NewCloudPermissionRepository(l.db).Fenced(stale).ReconcileGeneration(l.ws, a.conn, next)
			return err
		},
		"membership reconcile": func() error {
			_, err := repositories.NewCloudPolicyRepository(l.db).Fenced(stale).ReconcileMemberships(l.ws, a.conn, next)
			return err
		},
	} {
		if err := del(); !errors.Is(err, repositories.ErrScanFenceLost) {
			t.Errorf("the stalled scan worker's %s = %v, want %v", what, err, repositories.ErrScanFenceLost)
		}
	}
	if now := inventory(); egatesJSON(now) != egatesJSON(kept) {
		t.Errorf("a superseded worker's deletes landed: inventory %v -> %v", kept, now)
	}

	// (2) A projector dies mid-projection. The REAL ProjectionService claims
	// the job, holds the barrier, reads the run's snapshot and the existing
	// graph -- and pauses there, before its graph transaction opens
	// (WithBeforeGraphTx), as a worker stalls. While it is paused: the
	// pipeline shows the projection in flight and nothing is listed; a second
	// projector finds nothing to claim (the lease is live). Then its lease
	// runs out and a reclaiming projector takes the job -- a new lease
	// version on the same job, so the barrier (held by the JOB, §2.10A) still
	// admits it. The paused pass then wakes and carries on with the lease it
	// claimed: only the service's own fencer, inside the graph transaction,
	// stands between it and the graph.
	jobs := repositories.NewIGAProjectionJobRepository(l.db)
	leases := repositories.NewIGAPipelineLeaseRepository(l.db)
	graphWrites := func() int64 {
		return l.count(`SELECT (SELECT count(*) FROM iga_publication WHERE workspace_id = ?)
		                     + (SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?)
		                     + (SELECT count(*) FROM iga_object_support WHERE workspace_id = ?)`, l.ws, l.ws, l.ws)
	}
	var paused, reclaimed *models.IGAProjectionJob
	var shapeAtWake int
	var writesAtWake int64
	dying := services.NewProjectionService(l.db, jobs, leases, repositories.NewIGAGraphRepository(),
		"egates-dying-projector", time.Minute).
		WithBeforeGraphTx(func(job models.IGAProjectionJob) {
			paused = &job
			if job.ScanRunID != queued.ID {
				t.Fatalf("the dying projector claimed job %s of run %s, want the reclaimed run %s", job.ID, job.ScanRunID, queued.ID)
			}
			acc := s2PipelineAccount(t, s2Pipeline(t, api), a.p2Account)
			if digs(acc, "state") != "projecting" || digs(acc, "projection", "status") != models.ProjectionRunning {
				t.Errorf("pipeline while the projector is paused mid-pass = %s", egatesJSON(acc))
			}
			egatesNotPublished(t, api, "/workloads")
			pubs := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws)
			second := services.NewProjectionService(l.db, jobs, leases, repositories.NewIGAGraphRepository(),
				"egates-second-projector", time.Minute)
			if worked, err := second.RunOnce(context.Background()); err != nil || worked {
				t.Errorf("a second projector while the first holds a live lease: worked=%v err=%v, want nothing claimed", worked, err)
			}
			if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != pubs {
				t.Errorf("a second projector published while the first held the job: %d -> %d", pubs, n)
			}
			egatesExec(t, l, `UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, job.ID)
			r, err := jobs.Claim("egates-reclaiming-projector", time.Minute, time.Now())
			if err != nil || r == nil || r.ID != job.ID || r.LeaseVersion == job.LeaseVersion {
				t.Fatalf("reclaim of job %s: %+v %v, want the same job under a new lease", job.ID, r, err)
			}
			reclaimed = r
			shapeAtWake, writesAtWake = len(l.shape()), graphWrites()
		})
	worked, err := dying.RunOnce(context.Background())
	if paused == nil {
		t.Fatalf("the projection service never reached its graph transaction: worked=%v err=%v", worked, err)
	}
	// Refused inside its graph transaction, with the projection lease lost,
	// and nothing it would have written landed: no graph row, publication,
	// lifecycle event or support row.
	if !worked || !errors.Is(err, repositories.ErrProjectionLeaseLost) {
		t.Errorf("the superseded projection pass: worked=%v err=%v, want %v", worked, err, repositories.ErrProjectionLeaseLost)
	}
	if n, w := len(l.shape()), graphWrites(); n != shapeAtWake || w != writesAtWake {
		t.Errorf("a superseded projector wrote: graph rows %d -> %d, publications+events+support %d -> %d",
			shapeAtWake, n, writesAtWake, w)
	}
	// ... and changed nothing of the job it lost: still the reclaimer's.
	var held models.IGAProjectionJob
	if err := l.db.First(&held, "id = ?", paused.ID).Error; err != nil || held.Status != models.ProjectionRunning ||
		held.LeaseOwner != "egates-reclaiming-projector" || held.LeaseVersion != reclaimed.LeaseVersion {
		t.Errorf("job after the superseded pass = %s owned by %q at v%d (%v), want running, the reclaimer's at v%d",
			held.Status, held.LeaseOwner, held.LeaseVersion, err, reclaimed.LeaseVersion)
	}
	job := paused
	// The reclaiming projector dies too; the next one completes, first pass.
	egatesExec(t, l, `UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, job.ID)
	l.project("egates-final-projector")
	pub := egatesPublicationOf(t, l, queued.ID)
	acc := s2PipelineAccount(t, s2Pipeline(t, api), a.p2Account)
	if pub.Rev != 1 || digs(acc, "state") != "published" || num(acc, "projection", "rev") != 1 ||
		num(acc, "projection", "attempts") != 3 {
		t.Errorf("after the reclaimed projection: rev %d, pipeline %s; want published at rev 1 on attempt 3",
			pub.Rev, egatesJSON(acc))
	}
	if body := egatesGet(t, api, "/workloads"); num(body, "meta", "rev") != 1 || len(digl(body, "data")) != 7 {
		t.Errorf("/workloads after recovery = rev %d, %d rows; want rev 1, A's 7 workloads",
			num(body, "meta", "rev"), len(digl(body, "data")))
	}

	// (3) The next scan's projector dies after its commit, before completing.
	// The projection service completes its job in the same call right after
	// the graph transaction commits, so that crash cannot be staged
	// in-process: the pass runs whole, and its job and the barrier are then
	// put back exactly as the crash leaves them -- graph and publication
	// committed, the job running under a lease that has run out, the barrier
	// still projecting for it.
	run2 := egatesScan(l, a)
	l.project("egates-projector-dies-after-commit")
	before := len(l.shape())
	var job2 uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_projection_job WHERE workspace_id = ? AND scan_run_id = ?`,
		l.ws, run2.ID).Row().Scan(&job2); err != nil {
		t.Fatalf("read the second run's job: %v", err)
	}
	if n := egatesExec(t, l, `UPDATE iga_projection_job SET status = 'running', lease_owner = 'egates-projector-dies-after-commit',
	          lease_expires_at = now() - interval '1 minute', completed_at = NULL WHERE id = ?`, job2); n != 1 {
		t.Fatalf("restore the dead projector's job: %d rows", n)
	}
	if n := egatesExec(t, l, `UPDATE iga_pipeline_lease SET state = 'projecting', holder = ?, scan_run_id = ?,
	          expires_at = now() + interval '15 minutes' WHERE workspace_id = ?`, models.PipelineJobHolder(job2), run2.ID, l.ws); n != 1 {
		t.Fatalf("restore the barrier the dead projector held: %d rows", n)
	}
	view := s2Pipeline(t, api)
	if digs(view, "barrier", "state") != models.PipelineProjecting || num(view, "current_rev") != 2 {
		t.Errorf("pipeline after a commit whose job never completed = %s, want projecting with the committed rev 2 current",
			egatesJSON(view))
	}
	// Reads are unaffected: the committed publication is simply current.
	if body := egatesGet(t, api, "/workloads"); num(body, "meta", "rev") != 2 {
		t.Errorf("/workloads between the commit and the replay = rev %d, want 2", num(body, "meta", "rev"))
	}
	l.project("egates-replaying-projector")
	if after := len(l.shape()); after != before {
		t.Errorf("the replay changed the graph: %d -> %d rows", before, after)
	}
	view = s2Pipeline(t, api)
	acc = s2PipelineAccount(t, view, a.p2Account)
	if digs(view, "barrier", "state") != models.PipelineIdle || num(view, "current_rev") != 2 ||
		digs(acc, "state") != "published" || num(acc, "projection", "rev") != 2 {
		t.Errorf("pipeline after the replay = %s, want published at rev 2 on an idle barrier", egatesJSON(view))
	}

	// The next scan starts; one publication per run, every job complete.
	run3 := egatesCycle(l, a)
	if p := egatesPublicationOf(t, l, run3.ID); p.Rev != 3 {
		t.Errorf("the next scan published rev %d, want 3", p.Rev)
	}
	var perRun []int64
	l.db.Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ? GROUP BY scan_run_id`, l.ws).Scan(&perRun)
	if len(perRun) != 3 {
		t.Errorf("publications cover %d runs, want 3", len(perRun))
	}
	for _, n := range perRun {
		if n != 1 {
			t.Errorf("a run has %d publications, want exactly 1: %v", n, perRun)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_projection_job WHERE workspace_id = ? AND status <> 'complete'`, l.ws); n != 0 {
		t.Errorf("%d projection jobs are not complete", n)
	}
	if st := l.barrier(); st != models.PipelineIdle {
		t.Errorf("barrier = %s, want idle", st)
	}
}

// egatesExec runs one statement that stages a state the fakes cannot reach
// (a lease run out, a crash between two writes), failing the test when it
// errors, and returns the rows it touched.
func egatesExec(t *testing.T, l *p2Lab, q string, args ...any) int64 {
	t.Helper()
	res := l.db.Exec(q, args...)
	if res.Error != nil {
		t.Fatalf("%s: %v", q, res.Error)
	}
	return res.RowsAffected
}
