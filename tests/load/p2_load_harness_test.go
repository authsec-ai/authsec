package load

// The measurement's own safeguards, tested without a database: a timing is
// only worth recording if a dishonest answer cannot pass for a fast one, a
// failed request cannot pass for a quick one, and a miss cannot pass for a
// hit. These run in every `go test ./tests/load/`, IGA_LOAD_DSN or not.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// loadJSONBody decodes a literal response body for loadHonest.
func loadJSONBody(t *testing.T, s string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("bad literal %s: %v", s, err)
	}
	return out
}

// TestP2LoadHonest: every kind of timed-out or partial answer (§5.1, §5.2,
// D-14, D-15, D-17, B23) is named, wherever it sits in the body, and the
// honest forms beside each (a capped total, a capped count, a node-bound
// traversal) are not.
func TestP2LoadHonest(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		want string // a substring of the one finding; "" for none
	}{
		{"clean list", `{"data":[],"meta":{"graph_state":"published","total_known":true,"total":3,"facets":{"kind":[]}}}`, ""},
		{"capped total", `{"data":[],"meta":{"total_known":false,"total_at_least":10000}}`, ""},
		{"timed-out total", `{"data":[],"meta":{"total_known":false}}`, "timed-out total"},
		{"timed-out section total", `{"data":{"workloads":{"items":[],"total_known":false}},"meta":{}}`, "data.workloads"},
		{"capped count", `{"data":{"named_by_count":{"value":1000,"exact":false}},"meta":{}}`, ""},
		{"timed-out count", `{"data":{"named_by_count":{"value":null,"exact":false}},"meta":{}}`, "timed-out count"},
		{"timed-out facet", `{"data":[],"meta":{"facets":{"account":null,"kind":[]}}}`, "facet account is null"},
		{"node-bound graph", `{"data":{"truncated":{"bound_by":"nodes"}},"meta":{}}`, ""},
		{"time-bound graph", `{"data":{"truncated":{"bound_by":"time"}},"meta":{}}`, "bound_by time"},
		{"time-bound path", `{"data":{"outcome":"not_found_within_budget","bound_by":"time"},"meta":{}}`, "bound_by time"},
		{"not published", `{"data":[],"meta":{"graph_state":"not_published"}}`, "graph_state not_published"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := loadHonest(loadJSONBody(t, c.body))
			switch {
			case c.want == "" && len(got) > 0:
				t.Errorf("an honest answer is flagged: %v", got)
			case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
				t.Errorf("findings %v, want one naming %q", got, c.want)
			}
		})
	}
}

// TestP2LoadRank: p50 / p95 are nearest-rank -- the smallest value with at
// least p of the samples at or below it -- never an interpolation below a
// measured value.
func TestP2LoadRank(t *testing.T) {
	ms := func(n int) []time.Duration {
		out := make([]time.Duration, n)
		for i := range out {
			out[i] = time.Duration(i+1) * time.Millisecond
		}
		return out
	}
	for _, c := range []struct {
		n    int
		p    float64
		want time.Duration
	}{
		{100, 0.95, 95 * time.Millisecond},
		{50, 0.95, 48 * time.Millisecond}, // ceil(47.5) = 48th of 50
		{50, 0.50, 25 * time.Millisecond},
		{1, 0.95, time.Millisecond},
	} {
		if got := loadRank(ms(c.n), c.p); got != c.want {
			t.Errorf("rank %.2f of 1..%d ms = %s, want %s", c.p, c.n, got, c.want)
		}
	}
}

// TestP2LoadIsCount: the report's COUNT column finds every kind of optional
// count the routes run -- a list total, a facet, a tab total over its CTEs --
// and no page statement.
func TestP2LoadIsCount(t *testing.T) {
	for sql, want := range map[string]bool{
		`SELECT count(*) FROM (SELECT 1 FROM "iga_workload" w WHERE x LIMIT 10001) t`:                             true,
		`SELECT (w.region)::text AS v, count(*) AS n FROM iga_workload w WHERE x GROUP BY 1`:                      true,
		`WITH grants AS (SELECT 1) SELECT count(*) FROM ( SELECT ia.id FROM iga_identity_accounts ia) x`:          true,
		`WITH changes_naming AS MATERIALIZED (SELECT 1) SELECT count(*) FROM (SELECT 1 FROM (x) c LIMIT 10001) t`: true,
		`SELECT w.id, w.display_name FROM iga_workload w ORDER BY 1 LIMIT 101`:                                    false,
		`WITH holders AS (SELECT 1) SELECT h.k0 FROM holders h`:                                                   false,
	} {
		if got := loadIsCount(sql); got != want {
			t.Errorf("loadIsCount(%q) = %v, want %v", sql, got, want)
		}
	}
}

// loadFakeAPI serves one canned response on every path, after a delay.
func loadFakeAPI(code int, body string, delay time.Duration) *loadAPI {
	gin.SetMode(gin.ReleaseMode)
	eng := gin.New()
	eng.NoRoute(func(c *gin.Context) {
		time.Sleep(delay)
		c.Data(code, "application/json", []byte(body))
	})
	return &loadAPI{eng: eng}
}

// TestP2LoadMeasureFailsWhatIsNotAnAnswer: loadMeasure records every
// non-200 and every dishonest 200 as a failure, whatever its time, and
// loadVerdict fails the read on it -- a 504 is quick precisely because it
// gave up.
func TestP2LoadMeasureFailsWhatIsNotAnAnswer(t *testing.T) {
	c := loadCase{rows: []string{loadRowDetail}, name: "fake", path: func(int) string { return "/x" }}
	for _, f := range []struct {
		name string
		api  *loadAPI
		want string
	}{
		{"timeout", loadFakeAPI(http.StatusGatewayTimeout, `{"error":{"code":"query_timeout"}}`, 0), "status 504"},
		{"not found", loadFakeAPI(http.StatusNotFound, `{"error":{"code":"not_found"}}`, 0), "status 404"},
		{"timed-out total", loadFakeAPI(http.StatusOK, `{"data":[],"meta":{"total_known":false}}`, 0), "timed-out total"},
		{"not JSON", loadFakeAPI(http.StatusOK, `<html>`, 0), "not JSON"},
	} {
		t.Run(f.name, func(t *testing.T) {
			r := loadMeasure(f.api, c, loadMinIterations)
			v := loadVerdict(r)
			if len(v) == 0 || !strings.Contains(strings.Join(v, "\n"), f.want) {
				t.Errorf("verdict %v, want a failure naming %q", v, f.want)
			}
		})
	}
	r := loadMeasure(loadFakeAPI(http.StatusOK, `{"data":{},"meta":{"graph_state":"published"}}`, 0), c, loadMinIterations)
	if v := loadVerdict(r); len(v) != 0 {
		t.Errorf("a fast honest read fails: %v", v)
	}
}

// TestP2LoadVerdictJudgesEveryRow: a read over its target fails on that row;
// a read judged on two rows fails on each it misses; at the target is met.
func TestP2LoadVerdictJudgesEveryRow(t *testing.T) {
	res := func(p95 time.Duration, rows ...string) *loadResult {
		return &loadResult{c: loadCase{rows: rows, name: "r"}, p95: p95}
	}
	if v := loadVerdict(res(300*time.Millisecond, loadRowDetail)); len(v) != 0 {
		t.Errorf("p95 at the 300 ms target fails: %v", v)
	}
	if v := loadVerdict(res(301*time.Millisecond, loadRowDetail)); len(v) != 1 || !strings.Contains(v[0], "Detail tabs target missed") {
		t.Errorf("p95 301 ms on Detail tabs: %v, want one miss", v)
	}
	// A facets-on list page: both the page target and the totals budget.
	if v := loadVerdict(res(450*time.Millisecond, loadRowLists, loadRowTotals)); len(v) != 1 || !strings.Contains(v[0], "Lists target missed") {
		t.Errorf("p95 450 ms on Lists + Totals: %v, want the Lists miss only", v)
	}
	if v := loadVerdict(res(3100*time.Millisecond, loadRowLists, loadRowTotals)); len(v) != 2 {
		t.Errorf("p95 3.1 s on Lists + Totals: %v, want both misses", v)
	}
	if v := loadVerdict(res(time.Millisecond, "no such row")); len(v) != 1 {
		t.Errorf("a row with no target passes: %v", v)
	}
	// A real measurement over the target, end to end.
	slow := loadMeasure(loadFakeAPI(http.StatusOK, `{"data":{},"meta":{}}`, 5*time.Millisecond),
		loadCase{rows: []string{loadRowDetail}, name: "slow", path: func(int) string { return "/x" }}, loadMinIterations)
	saved := loadTargets[loadRowDetail]
	loadTargets[loadRowDetail] = time.Millisecond
	defer func() { loadTargets[loadRowDetail] = saved }()
	if v := loadVerdict(slow); len(v) != 1 {
		t.Errorf("a 5 ms read against a 1 ms target: %v, want one miss", v)
	}
}
