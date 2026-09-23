package integration

// T2.2 (SPEC-iga-phase2-graph.md §5.3): GET .../connectors/:id/scan-runs and
// the projection on GET .../scan-runs/:id. Gate: history shows published,
// failed and abandoned runs with rev.

import (
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

func TestP2S2ScanRunHistoryShowsEveryEnding(t *testing.T) {
	l := newP2Lab(t, "p2-s2-history", true)
	a := oneLambda(l)
	b := l.account(accountB)
	api := s2DiscoveryAPI(t, l, a.svc)

	// Run 1: published and projected (rev 1).
	published := l.scanAndProject(a)

	// Run 2: failed -- claimed, then failed under its own fence.
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

	// Run 3: abandoned -- collecting, then given up on by the barrier's
	// abandon exit (§2.10A), which terminalizes the run before idling.
	time.Sleep(5 * time.Millisecond)
	abandoned, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	held, err := l.runs.ClaimForPipeline("s2-dead-worker", time.Minute, time.Now())
	if err != nil || held == nil || held.ID != abandoned.ID {
		t.Fatalf("claim the run to abandon: %v %v", held, err)
	}
	pipe := repositories.NewIGAPipelineLeaseRepository(l.db)
	version, err := pipe.AcquireForCollection(l.ws, "s2-dead-worker", held.ID, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.db.Transaction(func(tx *gorm.DB) error {
		return pipe.AbandonTx(tx, repositories.PipelineFence{WorkspaceID: l.ws,
			Phase: models.PipelineCollecting, RunID: held.ID, Version: version}, "collector gone")
	}); err != nil {
		t.Fatal(err)
	}

	path := "/aws/connectors/" + a.conn.String() + "/scan-runs"
	code, body := api.do(http.MethodGet, path, nil)
	mustStatus(t, "history", code, body, http.StatusOK)
	rows := digl(body, "data")
	if len(rows) != 3 {
		t.Fatalf("history rows = %d, want 3 (published, failed, abandoned): %v", len(rows), body)
	}
	// Newest first.
	wantOrder := []struct {
		ref, status string
	}{
		{refOf("cloud_scan_run", abandoned.ID), models.CloudScanRunAbandoned},
		{refOf("cloud_scan_run", failed.ID), models.CloudScanRunFailed},
		{refOf("cloud_scan_run", published.ID), models.CloudScanRunPublished},
	}
	for i, w := range wantOrder {
		if digs(rows[i], "ref") != w.ref || digs(rows[i], "status") != w.status {
			t.Fatalf("row %d = %s %s, want %s %s", i, digs(rows[i], "ref"), digs(rows[i], "status"), w.ref, w.status)
		}
		if digs(rows[i], "integration") != refOf("cloud_connector", a.conn) {
			t.Fatalf("row %d integration = %q", i, digs(rows[i], "integration"))
		}
	}

	// The published run: projection complete at rev 1, coverage summarized,
	// finished when it published.
	pub := rows[2]
	if digs(pub, "projection", "status") != models.ProjectionComplete || num(pub, "projection", "rev") != 1 {
		t.Fatalf("published run projection = %v, want complete at rev 1", dig(pub, "projection"))
	}
	// Coverage summary (D-91): counts per state, and every surface NOT
	// reached with its state -- exactly the run's own coverage, summarized.
	stored := s2Coverage(published)
	if digs(pub, "coverage", "status") != stored.Status {
		t.Fatalf("published run coverage status = %v, want %q", dig(pub, "coverage"), stored.Status)
	}
	wantCounts := map[string]int64{}
	var wantNotReached []string
	for name, s := range stored.Surfaces {
		wantCounts[s.State]++
		if s.State != models.CloudCoverageReached {
			wantNotReached = append(wantNotReached, name+"="+s.State)
		}
	}
	sort.Strings(wantNotReached)
	for state, n := range wantCounts {
		if num(pub, "coverage", "counts", state) != n {
			t.Fatalf("coverage counts[%s] = %d, want %d: %v", state, num(pub, "coverage", "counts", state), n, dig(pub, "coverage"))
		}
	}
	var gotNotReached []string
	for _, s := range digl(pub, "coverage", "not_reached") {
		gotNotReached = append(gotNotReached, digs(s, "surface")+"="+digs(s, "state"))
	}
	if len(wantNotReached) == 0 || !reflect.DeepEqual(gotNotReached, wantNotReached) {
		t.Fatalf("coverage not_reached = %v, want %v", gotNotReached, wantNotReached)
	}
	if dig(body, "success") != true || num(body, "meta", "limit") != 20 {
		t.Fatalf("history envelope = success %v, limit %v; want the discovery envelope, 20 per page by default", dig(body, "success"), dig(body, "meta", "limit"))
	}
	if digs(pub, "finished_at") == "" || digs(pub, "finished_at") != digs(pub, "published_at") {
		t.Fatalf("published run finished_at = %q, published_at = %q", digs(pub, "finished_at"), digs(pub, "published_at"))
	}
	if digs(pub, "started_at") == "" || digs(pub, "queued_at") == "" {
		t.Fatalf("published run times = %v", pub)
	}
	// The failed and abandoned runs: no projection, no coverage, finished,
	// with their error.
	for _, i := range []int{0, 1} {
		r := rows[i]
		if dig(r, "projection") != nil || dig(r, "coverage") != nil {
			t.Fatalf("%s run carries projection %v / coverage %v, want null", digs(r, "status"), dig(r, "projection"), dig(r, "coverage"))
		}
		if digs(r, "finished_at") == "" || digs(r, "last_error") == "" {
			t.Fatalf("%s run finished_at/last_error = %q / %q", digs(r, "status"), digs(r, "finished_at"), digs(r, "last_error"))
		}
	}

	// Cursor paging: two pages, no overlap, no gap.
	code, body = api.do(http.MethodGet, path+qs("limit", "2"), nil)
	mustStatus(t, "page 1", code, body, http.StatusOK)
	page1 := digl(body, "data")
	cursor := digs(body, "meta", "next_cursor")
	if len(page1) != 2 || cursor == "" {
		t.Fatalf("page 1 = %d rows, next_cursor %q; want 2 and a cursor", len(page1), cursor)
	}
	code, body = api.do(http.MethodGet, path+qs("limit", "2", "cursor", cursor), nil)
	mustStatus(t, "page 2", code, body, http.StatusOK)
	page2 := digl(body, "data")
	if len(page2) != 1 || digs(page2[0], "ref") != refOf("cloud_scan_run", published.ID) || dig(body, "meta", "next_cursor") != nil {
		t.Fatalf("page 2 = %v, want only the published run and no further cursor", body)
	}

	// A cursor is bound to its connector: presented on another's history it
	// is cursor_invalid, as is a tampered one.
	code, body = api.do(http.MethodGet, "/aws/connectors/"+b.conn.String()+"/scan-runs"+qs("cursor", cursor), nil)
	if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
		t.Fatalf("another connector's cursor = %d %v, want 400 cursor_invalid", code, body)
	}
	code, body = api.do(http.MethodGet, path+qs("cursor", cursor+"x"), nil)
	if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
		t.Fatalf("tampered cursor = %d %v, want 400 cursor_invalid", code, body)
	}
	// limit is 1-100 (D-91); any parameter but cursor and limit is refused,
	// naming it, rather than ignored.
	for _, q := range []string{qs("limit", "0"), qs("limit", "101"), qs("limit", "x"), qs("status", "failed")} {
		if code, body := api.do(http.MethodGet, path+q, nil); code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Fatalf("history%s = %d %v, want 400 invalid_parameter", q, code, body)
		}
	}
	if code, body := api.do(http.MethodGet, path+qs("limit", "100"), nil); code != http.StatusOK || len(digl(body, "data")) != 3 {
		t.Fatalf("limit=100 = %d %v", code, body)
	}
	other := newWorkspace(t, l.db, "p2-s2-history-foreign")
	if code, body := api.asWorkspace(other).do(http.MethodGet, path, nil); code != http.StatusNotFound || errCode(body) != "not_found" {
		t.Fatalf("another workspace's history = %d %v, want 404", code, body)
	}
	api.asWorkspace(l.ws)

	// GET .../scan-runs/:id gains projection {status, rev}.
	code, body = api.do(http.MethodGet, "/aws/scan-runs/"+published.ID.String(), nil)
	mustStatus(t, "GET scan run", code, body, http.StatusOK)
	if digs(body, "data", "id") != published.ID.String() || digs(body, "data", "status") != models.CloudScanRunPublished {
		t.Fatalf("GET scan run lost the run's own fields: %v", body)
	}
	if digs(body, "data", "projection", "status") != models.ProjectionComplete || num(body, "data", "projection", "rev") != 1 {
		t.Fatalf("GET scan run projection = %v, want {complete, 1}", dig(body, "data", "projection"))
	}
	code, body = api.do(http.MethodGet, "/aws/scan-runs/"+failed.ID.String(), nil)
	mustStatus(t, "GET failed scan run", code, body, http.StatusOK)
	if p, ok := body["data"].(map[string]any)["projection"]; !ok || p != nil {
		t.Fatalf("a run with no job must carry projection: null, got %v (present=%v)", p, ok)
	}
}
