package integration

// /pipeline over a LONG run history (SPEC-iga-phase2-graph.md §5.1: every
// request under the 3 s budget; §2.14.7 the console polls it). cloud_scan_run
// has no retention, so the latest-run read must cost a fixed amount per
// connector -- two index probes of LIMIT 1 -- and never read, sort or join the
// workspace's whole history (with its coverage jsonb) on every poll.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

func TestP2S2PipelineReadsAFixedAmountPerConnector(t *testing.T) {
	l := newP2Lab(t, "p2-s2-pipeline-bounded", true)
	a := oneLambda(l)
	b := l.account(accountB) // connected, never scanned
	api := l.api()

	first := l.scanAndProject(a)
	// 400 earlier runs of A, every way a run ends -- history a poll must not
	// walk. Written AFTER the first run and BEFORE the newest, so the newest
	// is neither the first row stored nor the last.
	const history = 400
	if err := l.db.Exec(`
		INSERT INTO cloud_scan_run (workspace_id, connector_id, generation, status, trigger,
		                            requested_at, started_at, published_at, updated_at, last_error, coverage)
		SELECT r.workspace_id, r.connector_id, 1,
		       CASE WHEN g % 2 = 0 THEN 'failed' ELSE 'published' END, 'manual',
		       r.requested_at - make_interval(mins => g), r.requested_at - make_interval(mins => g),
		       CASE WHEN g % 2 = 0 THEN NULL ELSE r.requested_at - make_interval(mins => g) END,
		       r.requested_at - make_interval(mins => g),
		       CASE WHEN g % 2 = 0 THEN 'iam scan: connection reset' ELSE '' END, r.coverage
		  FROM cloud_scan_run r, generate_series(1, ?::int) g
		 WHERE r.id = ?`, history, first.ID).Error; err != nil {
		t.Fatalf("insert history: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	newest := l.scanAndProject(a)
	if err := l.db.Exec(`ANALYZE cloud_scan_run`).Error; err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// The answer is the newest run, however much history lies behind it.
	view := s2Pipeline(t, api)
	accA := s2PipelineAccount(t, view, a)
	if digs(accA, "state") != "published" || digs(accA, "latest_run", "ref") != refOf("cloud_scan_run", newest.ID) ||
		num(accA, "projection", "rev") != 2 || num(accA, "last_published_rev") != 2 {
		t.Fatalf("A over %d runs of history = %v, want its newest run, published at rev 2", history, accA)
	}
	if accB := s2PipelineAccount(t, view, b); digs(accB, "state") != "never_scanned" || dig(accB, "latest_run") != nil ||
		dig(accB, "last_published_rev") != nil {
		t.Fatalf("B = %v, want never_scanned, nothing published", accB)
	}

	// A live run wins over the newest terminal one, still in two probes.
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	l.db.Exec(`UPDATE cloud_scan_run SET requested_at = requested_at - interval '1 day' WHERE id = ?`, queued.ID)
	if accA := s2PipelineAccount(t, s2Pipeline(t, api), a); digs(accA, "state") != "queued" ||
		digs(accA, "latest_run", "ref") != refOf("cloud_scan_run", queued.ID) {
		t.Fatalf("A with a live run older than its newest terminal one = %v, want the live run", accA)
	}

	// THE COST: rows read from cloud_scan_run by the query /pipeline runs,
	// as PostgreSQL executed it -- a handful per connector, not the history.
	var raw string
	if err := l.db.Raw("EXPLAIN (ANALYZE, FORMAT JSON) "+igaread.PipelineLatestRunsSQL,
		models.CloudScanRunQueued, models.CloudScanRunRunning, l.ws, models.CloudProviderAWS).
		Row().Scan(&raw); err != nil {
		t.Fatalf("explain: %v", err)
	}
	var plan []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &plan); err != nil || len(plan) != 1 {
		t.Fatalf("plan %q: %v", raw, err)
	}
	read := s2RowsReadFrom(plan[0].Plan, "cloud_scan_run")
	if read > 6 {
		t.Fatalf("/pipeline read %v rows of cloud_scan_run for 1 connector with %d runs, want a fixed handful:\n%s",
			read, history+3, raw)
	}
	// Cleanup: the queued run would otherwise be claimable by the next test.
	l.db.Exec(`DELETE FROM cloud_scan_run WHERE id = ?`, queued.ID)
}

// s2RowsReadFrom sums, over an EXPLAIN ANALYZE plan, the rows every scan node
// of the relation returned (Actual Rows x Actual Loops).
func s2RowsReadFrom(node map[string]any, relation string) float64 {
	var total float64
	if node["Relation Name"] == relation {
		rows, _ := node["Actual Rows"].(float64)
		loops, _ := node["Actual Loops"].(float64)
		total += rows * loops
	}
	if kids, ok := node["Plans"].([]any); ok {
		for _, k := range kids {
			if m, ok := k.(map[string]any); ok {
				total += s2RowsReadFrom(m, relation)
			}
		}
	}
	return total
}
