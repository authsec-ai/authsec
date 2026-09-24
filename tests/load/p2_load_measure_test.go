package load

// The §5.6 measurement (T6.10): every read class against its p95 target on
// the 10 000-workload fixture, through the real route table.
//
// Methodology (RESULTS.md repeats it):
//   - sequential: one request at a time, one process, the machine otherwise idle;
//   - warm cache: every read makes one full unrecorded pass over its requests
//     before the measured pass, so the pages it touches are in PostgreSQL's
//     buffers or the OS page cache -- §5.6 states steady-state targets, and a
//     cold first touch measures the disk, not the query;
//   - at least 50 measured iterations per read (IGA_LOAD_ITERATIONS may raise
//     it), rotating over typical objects where the read takes an object, plus
//     separate reads pinned to the heaviest object of each kind (the hub
//     execution role, the "*" selector, the most-granted holder), because a
//     p95 over typical objects says nothing about the one object every
//     workload shares;
//   - the time is the whole request as the server sees it: routing, handler,
//     every query of the §5.1 snapshot, and JSON rendering (httptest, no
//     network);
//   - p50 / p95 / max by nearest rank over the measured iterations.
//
// A fast answer counts only if it is an honest one: every measured response
// must be 200 with the graph published, and nothing in it may be a timed-out
// optional piece (loadHonest) -- a total, a facet or a count that gave up is
// quick precisely because it gave up, and a traversal bound by time returned
// less than it should. Any such response fails the read whatever its time.
//
// A target missed is a defect (§5.6): the test fails, naming the read, its
// p95 and its slowest statement.

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// loadMinIterations is the fewest measured iterations a p95 is taken over.
const loadMinIterations = 50

// The §5.6 rows and their p95 targets.
const (
	loadRowLists   = "Lists"
	loadRowTotals  = "Totals and facets"
	loadRowDetail  = "Detail tabs"
	loadRowGraph   = "Graph"
	loadRowEvid    = "Evidence"
	loadRowChanges = "Changes"
)

var loadTargets = map[string]time.Duration{
	loadRowLists:   400 * time.Millisecond,
	loadRowTotals:  3 * time.Second, // "within the 3 s timeout, counted in the page budget"
	loadRowDetail:  300 * time.Millisecond,
	loadRowGraph:   1500 * time.Millisecond,
	loadRowEvid:    300 * time.Millisecond,
	loadRowChanges: 500 * time.Millisecond,
}

// loadCase is one measured read.
type loadCase struct {
	// rows are the §5.6 rows the read is judged against (a facets-on list page
	// is both a list page and the totals-and-facets work).
	rows []string
	name string
	// path is the i-th iteration's request (path and query).
	path func(i int) string
}

// loadResult is one read's measurement.
type loadResult struct {
	c             loadCase
	n             int
	p50, p95, max time.Duration
	// counts is the p95 of the time the traced pass spent in COUNT statements
	// (totals and facets); 0 when the read runs none.
	counts  time.Duration
	slowest []loadStatement
	fails   []string
}

// TestP2LoadTargets measures every §5.6 read and fails on any target missed.
func TestP2LoadTargets(t *testing.T) {
	env := loadEnvFor(t)
	n := loadMinIterations
	if s := os.Getenv(loadIterEnv); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < loadMinIterations {
			t.Fatalf("%s=%q: must be a number of at least %d", loadIterEnv, s, loadMinIterations)
		}
		n = v
	}
	cases := loadCases(t, env)
	var results []*loadResult
	for _, c := range cases {
		r := loadMeasure(env.api, c, n)
		results = append(results, r)
		t.Logf("%-18s %-55s p50 %7.1f  p95 %7.1f  max %7.1f ms", c.rows[0], c.name,
			loadMS(r.p50), loadMS(r.p95), loadMS(r.max))
	}
	report := loadReport(env, results, n)
	t.Log("\n" + report)
	if path := os.Getenv(loadReportEnv); path != "" {
		if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
			t.Errorf("write %s: %v", path, err)
		}
	}
	for _, r := range results {
		for _, f := range r.fails {
			t.Errorf("%s: %s", r.c.name, f)
		}
		for _, row := range r.c.rows {
			if target := loadTargets[row]; r.p95 > target {
				slow := ""
				if len(r.slowest) > 0 {
					slow = fmt.Sprintf("; slowest statement %.1f ms: %s", loadMS(r.slowest[0].elapsed), loadClipSQL(r.slowest[0].sql))
				}
				t.Errorf("§5.6 %s target missed: %s p95 %.1f ms > %s%s", row, r.c.name, loadMS(r.p95), target, slow)
			}
		}
	}
}

// loadMeasure runs one read: a warm pass, the measured pass, then one traced
// pass for the statement breakdown.
func loadMeasure(api *loadAPI, c loadCase, n int) *loadResult {
	r := &loadResult{c: c, n: n}
	fail := func(i int, path, msg string) {
		if len(r.fails) < 5 {
			r.fails = append(r.fails, fmt.Sprintf("iteration %d, GET %s: %s", i, path, msg))
		}
	}
	check := func(i int, path string, code int, raw []byte) {
		if code != 200 {
			fail(i, path, fmt.Sprintf("status %d: %s", code, loadClip(raw)))
			return
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			fail(i, path, "body is not JSON")
			return
		}
		for _, p := range loadHonest(body) {
			fail(i, path, p)
		}
	}
	for i := 0; i < n; i++ { // warm
		path := c.path(i)
		code, raw, _ := api.get(path)
		check(i, path, code, raw)
	}
	times := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		path := c.path(i)
		code, raw, d := api.get(path)
		times[i] = d
		check(i, path, code, raw)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	r.p50, r.p95, r.max = loadRank(times, 0.50), loadRank(times, 0.95), times[n-1]

	// The traced pass: which statements the time goes to, and how much of it
	// is the optional COUNT work (totals and facets).
	var counted []time.Duration
	byText := map[string]time.Duration{}
	for i := 0; i < n; i++ {
		loadTracer.start()
		api.get(c.path(i))
		stmts := loadTracer.stop()
		var sum time.Duration
		for _, s := range stmts {
			if loadIsCount(s.sql) {
				sum += s.elapsed
			}
			if s.elapsed > byText[s.sql] {
				byText[s.sql] = s.elapsed
			}
		}
		counted = append(counted, sum)
	}
	sort.Slice(counted, func(i, j int) bool { return counted[i] < counted[j] })
	r.counts = loadRank(counted, 0.95)
	for text, d := range byText {
		r.slowest = append(r.slowest, loadStatement{sql: text, elapsed: d})
	}
	sort.Slice(r.slowest, func(i, j int) bool { return r.slowest[i].elapsed > r.slowest[j].elapsed })
	if len(r.slowest) > 3 {
		r.slowest = r.slowest[:3]
	}
	return r
}

// loadRank is the nearest-rank percentile of sorted durations.
func loadRank(sorted []time.Duration, p float64) time.Duration {
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	return sorted[i]
}

// loadIsCount reports whether a statement is optional COUNT work: a total or
// a facet (§5.2), which the lists run as separate COUNT queries.
func loadIsCount(sql string) bool {
	s := strings.ToLower(sql)
	return strings.HasPrefix(s, "select count(") || strings.Contains(s, "count(*) from (select")
}

// loadHonest lists what in a response is a timed-out optional piece, or
// otherwise not a full answer: a total that is unknown without being over the
// cap (§5.2, D-15), a null facet (D-14), a {value: null, exact: false} count
// (D-17), a traversal bound by time (§5.1, B23), a graph not published.
func loadHonest(body map[string]any) []string {
	var out []string
	if s, _ := loadDig(body, "meta", "graph_state").(string); s != "" && s != "published" {
		out = append(out, "graph_state "+s)
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if known, ok := x["total_known"].(bool); ok && !known {
				if _, capped := x["total_at_least"]; !capped {
					out = append(out, path+": total_known false without total_at_least (a timed-out total)")
				}
			}
			if exact, ok := x["exact"].(bool); ok && !exact {
				if val, has := x["value"]; has && val == nil {
					out = append(out, path+": {value: null, exact: false} (a timed-out count)")
				}
			}
			if b, _ := x["bound_by"].(string); b == "time" {
				out = append(out, path+": bound_by time (the traversal ran out of time)")
			}
			if f, ok := x["facets"].(map[string]any); ok {
				for name, vals := range f {
					if vals == nil {
						out = append(out, path+": facet "+name+" is null (a timed-out facet)")
					}
				}
			}
			for k, e := range x {
				walk(path+"."+k, e)
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		}
	}
	walk("", body)
	return out
}

/* ---------------------------------- cases ---------------------------------- */

// loadRot rotates over ids: the i-th iteration's object.
func loadRot(ids []uuid.UUID) func(i int) uuid.UUID {
	return func(i int) uuid.UUID { return ids[i%len(ids)] }
}

// loadFixed is one object every iteration.
func loadFixed(id uuid.UUID) func(int) uuid.UUID { return func(int) uuid.UUID { return id } }

// loadPath builds "<prefix><id><suffix>".
func loadPath(prefix string, pick func(int) uuid.UUID, suffix string) func(int) string {
	return func(i int) string { return prefix + pick(i).String() + suffix }
}

// loadCases is every measured read.
func loadCases(t *testing.T, env *loadEnv) []loadCase {
	t.Helper()
	g, api := env.main, env.api
	h := g.h
	lists, both := []string{loadRowLists}, []string{loadRowLists, loadRowTotals}
	detail, graph, evid, changes := []string{loadRowDetail}, []string{loadRowGraph}, []string{loadRowEvid}, []string{loadRowChanges}

	teams := loadTeams
	accounts := []string{g.accts[0].id, g.accts[1].id, g.accts[2].id}
	resAccounts := append(append([]string{}, accounts...), "unknown")
	q := func(route string, kv ...string) func(int) string {
		return func(int) string { return route + "?" + loadQS(kv...) }
	}
	rot := func(route, key string, values []string, kv ...string) func(int) string {
		return func(i int) string {
			return route + "?" + loadQS(append([]string{key, values[i%len(values)]}, kv...)...)
		}
	}

	heavyWL, heavyHolder := loadHeaviest(g)

	var cs []loadCase
	add := func(rows []string, name string, path func(int) string) {
		cs = append(cs, loadCase{rows: rows, name: name, path: path})
	}

	// Lists: first page (with its total), a deep cursor page, q search, the
	// account filter, and every facet on.
	for _, l := range []struct {
		route, facets string
		deep          int // page number of the deep cursor page
		accts         []string
	}{
		{"/workloads", "account,runtime_kind,classification,region", 50, accounts},
		{"/identities", "account,kind", 30, accounts},
		{"/resources", "kind,service,account", 50, resAccounts},
	} {
		add(lists, "GET "+l.route+" first page", q(l.route))
		cursor := loadDeepCursor(t, api, l.route, l.deep)
		add(lists, fmt.Sprintf("GET %s deep page (page %d, cursor)", l.route, l.deep), q(l.route, "cursor", cursor))
		add(lists, "GET "+l.route+" q=<team> search", rot(l.route, "q", teams))
		add(lists, "GET "+l.route+" account=<account>", rot(l.route, "account", l.accts))
		add(both, "GET "+l.route+" facets="+l.facets, q(l.route, "facets", l.facets))
		add(both, "GET "+l.route+" q + account + facets", func(i int) string {
			return l.route + "?" + loadQS("q", teams[i%len(teams)], "account", l.accts[i%len(l.accts)], "facets", l.facets)
		})
	}
	add(lists, "GET /workloads classification=agent sort=classification", q("/workloads", "classification", "agent", "sort", "classification"))
	add(lists, "GET /identities used_by=workloads", q("/identities", "used_by", "workloads"))

	// Detail tabs: typical objects rotated, then the heaviest of each kind.
	wl := loadRot(h.workloads)
	add(detail, "GET /workloads/:id", loadPath("/workloads/", wl, ""))
	add(detail, "GET /workloads/:id/identities", loadPath("/workloads/", wl, "/identities"))
	add(detail, "GET /workloads/:id/resources", loadPath("/workloads/", wl, "/resources"))
	add(detail, "GET /workloads/:id/classification", loadPath("/workloads/", wl, "/classification"))
	add(detail, "GET /workloads/:id/resources (most-granted role)", loadPath("/workloads/", loadFixed(heavyWL), "/resources"))
	add(detail, "GET /workloads/:id (most-granted role)", loadPath("/workloads/", loadFixed(heavyWL), ""))
	roles := loadRot(h.roles)
	add(detail, "GET /identities/:id (roles)", loadPath("/identities/", roles, ""))
	add(detail, "GET /identities/:id/used-by (roles)", loadPath("/identities/", roles, "/used-by"))
	add(detail, "GET /identities/:id/permissions (roles)", loadPath("/identities/", roles, "/permissions"))
	users := loadRot(h.users)
	add(detail, "GET /identities/:id (users)", loadPath("/identities/", users, ""))
	add(detail, "GET /identities/:id/permissions (users)", loadPath("/identities/", users, "/permissions"))
	add(detail, fmt.Sprintf("GET /identities/:id (hub role, %d workloads)", h.hubRoleUsers), loadPath("/identities/", loadFixed(h.hubRole), ""))
	add(detail, fmt.Sprintf("GET /identities/:id/used-by (hub role, %d workloads)", h.hubRoleUsers), loadPath("/identities/", loadFixed(h.hubRole), "/used-by"))
	add(detail, fmt.Sprintf("GET /identities/:id/used-by (ecsTaskExecutionRole, %d)", h.ecsExecUsers), loadPath("/identities/", loadFixed(h.ecsExecRole), "/used-by"))
	add(detail, "GET /identities/:id/used-by (largest group)", loadPath("/identities/", loadFixed(h.hubGroup), "/used-by"))
	add(detail, "GET /identities/:id/permissions (most grants)", loadPath("/identities/", loadFixed(heavyHolder), "/permissions"))
	ext := loadRot(h.externals)
	add(detail, "GET /external-principals/:id", loadPath("/external-principals/", ext, ""))
	add(detail, "GET /external-principals/:id/referenced-by", loadPath("/external-principals/", ext, "/referenced-by"))
	add(detail, "GET /external-principals/:id (lambda.amazonaws.com)", loadPath("/external-principals/", loadFixed(h.lambdaService), ""))
	add(detail, "GET /external-principals/:id/referenced-by (lambda.amazonaws.com)", loadPath("/external-principals/", loadFixed(h.lambdaService), "/referenced-by"))
	res := loadRot(h.resources)
	add(detail, "GET /resources/:id", loadPath("/resources/", res, ""))
	add(detail, "GET /resources/:id/access", loadPath("/resources/", res, "/access"))
	add(detail, `GET /resources/:id ("*")`, loadPath("/resources/", loadFixed(h.starResource), ""))
	add(detail, `GET /resources/:id/access ("*")`, loadPath("/resources/", loadFixed(h.starResource), "/access"))
	add(detail, "GET /resources/:id (most-named bucket)", loadPath("/resources/", loadFixed(h.hotBucket), ""))
	add(detail, "GET /resources/:id/access (most-named bucket)", loadPath("/resources/", loadFixed(h.hotBucket), "/access"))

	// Graph at the display defaults (assume_hops 2, 150 nodes, 300 edges).
	gq := func(root func(int) string, dir string) func(int) string {
		return func(i int) string { return "/graph?" + loadQS("root", root(i), "direction", dir) }
	}
	ref := func(typ string, pick func(int) uuid.UUID) func(int) string {
		return func(i int) string { return typ + ":" + pick(i).String() }
	}
	add(graph, "GET /graph workload forward", gq(ref("workload", wl), "forward"))
	add(graph, "GET /graph workload forward (most-granted role)", gq(ref("workload", loadFixed(heavyWL)), "forward"))
	add(graph, "GET /graph identity forward (roles)", gq(ref("identity", roles), "forward"))
	add(graph, "GET /graph identity reverse (hub role)", gq(ref("identity", loadFixed(h.hubRole)), "reverse"))
	add(graph, "GET /graph resource reverse", gq(ref("resource", res), "reverse"))
	add(graph, "GET /graph resource reverse (most-named bucket)", gq(ref("resource", loadFixed(h.hotBucket)), "reverse"))
	add(graph, "GET /graph external principal forward (lambda.amazonaws.com)", gq(ref("external_principal", loadFixed(h.lambdaService)), "forward"))

	// Evidence: one query per edge type; a grouped edge of 50 claims (D-79).
	ev := func(typ string, ids []uuid.UUID) func(int) string {
		return func(i int) string { return "/evidence?" + loadQS("claim", typ+":"+ids[i%len(ids)].String()) }
	}
	add(evid, "GET /evidence grant", ev("grant", h.grants))
	add(evid, "GET /evidence assignment", ev("assignment", h.assignments))
	add(evid, "GET /evidence relationship (executes_as)", ev("relationship", h.executes))
	add(evid, "GET /evidence relationship (cross-account can_assume)", ev("relationship", h.canAssume))
	add(evid, "GET /evidence workload presence", ev("workload", h.workloads))
	add(evid, "GET /evidence coverage", func(i int) string {
		return "/evidence?" + loadQS("claim", h.coverageClaims[i%len(h.coverageClaims)])
	})
	add(evid, fmt.Sprintf("GET /evidence grouped edge (%d grants)", len(h.groupedGrants)), func(int) string {
		v := url.Values{}
		for _, id := range h.groupedGrants {
			v.Add("claim", "grant:"+id.String())
		}
		return "/evidence?" + v.Encode()
	})

	// Changes: typical objects, the objects with the most history, a second
	// page, and the coverage lane.
	add(changes, "GET /workloads/:id/changes", loadPath("/workloads/", wl, "/changes"))
	add(changes, "GET /workloads/:id/changes (role switched)", loadPath("/workloads/", loadRot(h.switchedWL), "/changes"))
	add(changes, "GET /workloads/:id/changes (most-granted role)", loadPath("/workloads/", loadFixed(heavyWL), "/changes"))
	add(changes, "GET /workloads/:id/changes kind=coverage", loadPath("/workloads/", wl, "/changes?kind=coverage"))
	add(changes, "GET /identities/:id/changes (roles)", loadPath("/identities/", roles, "/changes"))
	add(changes, "GET /identities/:id/changes (most grants)", loadPath("/identities/", loadFixed(heavyHolder), "/changes"))
	second := loadNextCursor(t, api, "/identities/"+heavyHolder.String()+"/changes")
	add(changes, "GET /identities/:id/changes page 2 (most grants)", func(int) string {
		return "/identities/" + heavyHolder.String() + "/changes?" + loadQS("cursor", second)
	})
	add(changes, "GET /resources/:id/changes", loadPath("/resources/", res, "/changes"))
	add(changes, `GET /resources/:id/changes ("*")`, loadPath("/resources/", loadFixed(h.starResource), "/changes"))
	add(changes, "GET /resources/:id/changes (most-named bucket)", loadPath("/resources/", loadFixed(h.hotBucket), "/changes"))
	return cs
}

// loadHeaviest picks the live workload whose execution role holds the most
// current grants, and the identity holding the most current grants.
func loadHeaviest(g *loadGen) (uuid.UUID, uuid.UUID) {
	var wl uuid.UUID
	best := -1
	for _, w := range g.workloads {
		if w.life.live() && w.role != nil && len(g.grantsByHolder[w.role]) > best {
			wl, best = w.id, len(g.grantsByHolder[w.role])
		}
	}
	var holder uuid.UUID
	best = -1
	for _, i := range g.idents {
		if i.life.live() && len(g.grantsByHolder[i]) > best {
			holder, best = i.id, len(g.grantsByHolder[i])
		}
	}
	return wl, holder
}

// loadDeepCursor pages a list to page n and returns the cursor for it.
func loadDeepCursor(t *testing.T, api *loadAPI, route string, n int) string {
	t.Helper()
	cursor := ""
	for page := 1; page < n; page++ {
		path := route
		if cursor != "" {
			path += "?" + loadQS("cursor", cursor)
		}
		body := loadMustGet(t, api, path)
		next, _ := loadDig(body, "meta", "next_cursor").(string)
		if next == "" {
			t.Fatalf("%s ends at page %d, before the deep page %d", route, page, n)
		}
		cursor = next
	}
	return cursor
}

// loadNextCursor is the cursor of a list's second page.
func loadNextCursor(t *testing.T, api *loadAPI, path string) string {
	t.Helper()
	body := loadMustGet(t, api, path)
	next, _ := loadDig(body, "meta", "next_cursor").(string)
	if next == "" {
		t.Fatalf("%s has no second page", path)
	}
	return next
}

// loadQS builds a query string from alternating keys and values.
func loadQS(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

func loadMS(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func loadClipSQL(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

/* --------------------------------- report ---------------------------------- */

// loadReport renders the measurement as the Markdown table RESULTS.md
// carries: one line per read, grouped by §5.6 row.
func loadReport(env *loadEnv, results []*loadResult, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fixture: %d rows (main workspace %d workloads), %d measured iterations per read, sequential, warm.\n\n",
		env.rows, env.main.h.activeWL, n)
	for _, row := range []string{loadRowLists, loadRowTotals, loadRowDetail, loadRowGraph, loadRowEvid, loadRowChanges} {
		target := loadTargets[row]
		fmt.Fprintf(&b, "\n#### %s (p95 target %s)\n\n", row, target)
		fmt.Fprintf(&b, "| Read | p50 ms | p95 ms | max ms | COUNT p95 ms | Slowest statement ms | Verdict |\n|---|---:|---:|---:|---:|---:|---|\n")
		for _, r := range results {
			if !loadHasRow(r.c.rows, row) {
				continue
			}
			verdict := "met"
			if r.p95 > target {
				verdict = "**MISSED**"
			}
			if len(r.fails) > 0 {
				verdict = "**FAILED** (" + r.fails[0] + ")"
			}
			slow := 0.0
			if len(r.slowest) > 0 {
				slow = loadMS(r.slowest[0].elapsed)
			}
			fmt.Fprintf(&b, "| %s | %.1f | %.1f | %.1f | %.1f | %.1f | %s |\n", strings.ReplaceAll(r.c.name, "|", "\\|"),
				loadMS(r.p50), loadMS(r.p95), loadMS(r.max), loadMS(r.counts), slow, verdict)
		}
	}
	return b.String()
}

func loadHasRow(rows []string, row string) bool {
	for _, r := range rows {
		if r == row {
			return true
		}
	}
	return false
}
