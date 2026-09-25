package integration

// T6.4, B17 and B23: every budget that binds gives the non-complete form --
// truncated / a frontier / not_found_within_budget / more_paths -- and never a
// completeness claim; a control where nothing binds gives exact counts and
// none_exists. Time: a graph at the deadline is 200 truncated time, never
// 504; only a root that cannot be read is 504.
//
// Budgets bind on small fixtures through the reader's test seam
// (Reader.TraversalWith); time binds on a real statement timeout, with no
// hook in production code: another session holds a lock on a table only the
// level under test reads.

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igaread"
)

func graphBudgets(mod func(*igaread.GraphBudgets)) igaread.GraphBudgets {
	b := igaread.DefaultGraphBudgets
	mod(&b)
	return b
}

func TestP2GraphNodeAndEdgeBudgets(t *testing.T) {
	l := newP2Lab(t, "p2-graph-budgets", true)
	l.scanAndProject(graphTeaching(t, l))
	r := igaread.NewReader(l.db, readTestCursorKey)
	ticket, role := graphWorkload(t, l, "ticket-tools"), graphIdentity(t, l, "SharedToolRole")

	for _, tc := range []struct {
		name  string
		b     igaread.GraphBudgets
		bound string
		nodes int
		edges int
	}{
		// Level 2 reads the role's two grants; the node budget stops after
		// the first statement, the edge budget after the first grant.
		{"nodes", graphBudgets(func(b *igaread.GraphBudgets) { b.Nodes = 3 }), "nodes", 3, 2},
		{"edges", graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 2 }), "edges", 3, 2},
	} {
		code, body := graphDirect(t, r, tc.b, l.ws, "/graph", "root", ticket, "direction", "forward")
		mustStatus(t, tc.name, code, body, 200)
		if got := digs(body, "data", "truncated", "bound_by"); got != tc.bound {
			t.Errorf("%s: truncated = %v, want bound_by %s", tc.name, dig(body, "data", "truncated"), tc.bound)
		}
		nodes := digl(body, "data", "nodes")
		edges := graphEdges(t, digl(body, "data", "edges"))
		if len(nodes) != tc.nodes || len(edges) != tc.edges {
			t.Errorf("%s: %d nodes %d edges, want %d and %d -- exactly where the budget binds", tc.name, len(nodes), len(edges), tc.nodes, tc.edges)
		}
		// The frontier says what was not returned, counted exactly inside
		// the budget: the role's other grant, the reached statement's target.
		if f := graphFrontier(body, role, "grant"); f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true {
			t.Errorf("%s: role grant frontier = %v, want {count 1, exact}", tc.name, f)
		}
		stmts := graphRefsOfKind(nodes, "statement")
		if len(stmts) != 1 {
			t.Fatalf("%s: statements %v, want the one reached", tc.name, stmts)
		}
		if f := graphFrontier(body, stmts[0], "target"); f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true {
			t.Errorf("%s: statement target frontier = %v, want {count 1, exact}", tc.name, f)
		}
		// A frontier entry is never a (node, kind) with nothing more: the
		// role has no member_of or can_assume neighbours.
		if graphFrontier(body, role, "member_of") != nil || graphFrontier(body, role, "can_assume") != nil {
			t.Errorf("%s: frontier = %v names kinds counted at zero", tc.name, dig(body, "data", "frontier"))
		}
	}

	// Control: nothing binds -- no truncation, and nothing left over.
	code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph", "root", ticket, "direction", "forward")
	mustStatus(t, "control", code, body, 200)
	if dig(body, "data", "truncated") != nil || len(digl(body, "data", "frontier")) != 0 || len(digl(body, "data", "nodes")) != 5 {
		t.Errorf("control = %v, want the whole path, not truncated, no frontier", body["data"])
	}
}

// The path budget: two declared paths (TicketRead's and ToolboxRead's), a
// budget of one -> found, one path, more_paths, bound_by paths. Control: both,
// complete.
func TestP2GraphPathBudget(t *testing.T) {
	l := newP2Lab(t, "p2-graph-pathbudget", true)
	l.scanAndProject(graphTeaching(t, l))
	r := igaread.NewReader(l.db, readTestCursorKey)
	ticket, res := graphWorkload(t, l, "ticket-tools"), graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	code, body := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Paths = 1 }), l.ws,
		"/graph/path", "from", ticket, "to", res)
	mustStatus(t, "paths=1", code, body, 200)
	if digs(body, "data", "outcome") != "found" || len(digl(body, "data", "paths")) != 1 ||
		dig(body, "data", "more_paths") != true || digs(body, "data", "bound_by") != "paths" {
		t.Errorf("paths=1 = %v, want found, one path, more_paths, bound_by paths", body["data"])
	}
	code, body = graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph/path", "from", ticket, "to", res)
	mustStatus(t, "control", code, body, 200)
	paths := digl(body, "data", "paths")
	if digs(body, "data", "outcome") != "found" || len(paths) != 2 || dig(body, "data", "more_paths") != false ||
		dig(body, "data", "bound_by") != nil {
		t.Fatalf("control = %v, want both paths, complete", body["data"])
	}
	// Each path is whole and ordered: from, ..., to; edges between them.
	for i, p := range paths {
		ns, es := digl(p, "nodes"), digl(p, "edges")
		if len(ns) != 4 || len(es) != 3 || digs(ns[0], "ref") != ticket || digs(ns[3], "ref") != res {
			t.Errorf("path %d = %v, want ticket-tools -> role -> statement -> selector", i, p)
			continue
		}
		for j, e := range es {
			if digs(e, "from") != digs(ns[j], "ref") || digs(e, "to") != digs(ns[j+1], "ref") {
				t.Errorf("path %d step %d: edge %v does not join %v and %v", i, j, e, ns[j], ns[j+1])
			}
		}
	}
	if digs(paths[0], "nodes", 2, "ref") == digs(paths[1], "nodes", 2, "ref") {
		t.Errorf("both paths run through one statement: the two grants must be two paths")
	}
}

// D-38 and its mutation check: none_exists ONLY when both frontiers were
// exhausted before any budget bound. The fixture makes the node budget bind
// on the forward side's LAST level, after the reverse side is exhausted -- so
// a search that ignored the bound would see two empty frontiers and claim
// none_exists.
func TestP2GraphPathNoneExistsOnlyWhenExhausted(t *testing.T) {
	l := newP2Lab(t, "p2-graph-exhausted", true)
	a := l.account(accountA)
	role := a.role("ArchiveRole", "AROAARCHIVEROLE00001")
	a.attach("ArchiveRole", a.managed("AllButFinance", graphDocAllButFinance))
	a.attach("ArchiveRole", a.managed("TicketRead", docTicketRead))
	a.attach("ArchiveRole", a.managed("ToolboxRead", docToolboxRead))
	listsFunctions(a, "us-east-1", "archiver", role)
	l.scanAndProject(a)
	r := igaread.NewReader(l.db, readTestCursorKey)
	from, finance := graphIdentity(t, l, "ArchiveRole"), graphResource(t, l, "arn:aws:s3:::finance/*")

	// Control: nothing binds, no path (finance is only excluded): none_exists.
	code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph/path", "from", from, "to", finance)
	mustStatus(t, "control", code, body, 200)
	if digs(body, "data", "outcome") != "none_exists" || dig(body, "data", "bound_by") != nil || dig(body, "data", "more_paths") != false {
		t.Fatalf("control = %v, want none_exists", body["data"])
	}
	// Nodes: the role, finance, three statements = 5; the forward side's
	// next level (the statements' targets) binds on its first new node.
	code, body = graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Nodes = 5 }), l.ws,
		"/graph/path", "from", from, "to", finance)
	mustStatus(t, "nodes=5", code, body, 200)
	if digs(body, "data", "outcome") != "not_found_within_budget" || digs(body, "data", "bound_by") != "nodes" ||
		len(digl(body, "data", "paths")) != 0 {
		t.Errorf("nodes=5 = %v, want not_found_within_budget, bound_by nodes -- never none_exists when a budget bound", body["data"])
	}
	// The edge budget, likewise.
	code, body = graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 3 }), l.ws,
		"/graph/path", "from", from, "to", finance)
	mustStatus(t, "edges=3", code, body, 200)
	if digs(body, "data", "outcome") != "not_found_within_budget" || digs(body, "data", "bound_by") != "edges" {
		t.Errorf("edges=3 = %v, want not_found_within_budget, bound_by edges", body["data"])
	}
}

// The hop limit on paths: a path needing more can_assume steps than the
// budget is not "none": not_found_within_budget, bound_by assume_hops.
func TestP2GraphPathHopLimit(t *testing.T) {
	l := newP2Lab(t, "p2-graph-pathhops", true)
	loopA, loopB := graphLoop(t, l)
	r := igaread.NewReader(l.db, readTestCursorKey)
	code, body := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.AssumeHops = 0 }), l.ws,
		"/graph/path", "from", loopA, "to", loopB)
	mustStatus(t, "hops=0", code, body, 200)
	if digs(body, "data", "outcome") != "not_found_within_budget" || digs(body, "data", "bound_by") != "assume_hops" {
		t.Errorf("hops=0 = %v, want not_found_within_budget, bound_by assume_hops", body["data"])
	}
}

// B23: a level that runs out of time is rolled back to its savepoint and the
// earlier levels are returned: 200, truncated time -- through the real route,
// under the production budget. The lock is on iga_entitlement_target, which
// only the level that reaches the statements reads (their group keys and
// exclusions). After a time bind the frontier counts are not attempted:
// {count: null, exact: false}, never a number.
func TestP2GraphTimeBudgetTruncates(t *testing.T) {
	l := newP2Lab(t, "p2-graph-time", true)
	l.scanAndProject(graphTeaching(t, l))
	api := l.api()
	ticket, role := graphWorkload(t, l, "ticket-tools"), graphIdentity(t, l, "SharedToolRole")

	listsWithTableLocked(t, l.db, "iga_entitlement_target", func() {
		start := time.Now()
		code, body := api.get("/graph" + qs("root", ticket, "direction", "forward"))
		mustStatus(t, "graph at the deadline", code, body, 200)
		if digs(body, "data", "truncated", "bound_by") != "time" {
			t.Fatalf("truncated = %v, want bound_by time", dig(body, "data", "truncated"))
		}
		nodes := graphNodes(t, digl(body, "data", "nodes"))
		if len(nodes) != 2 || nodes[ticket] == nil || nodes[role] == nil {
			t.Errorf("nodes = %v, want exactly the levels before the one that timed out", nodes)
		}
		if es := graphEdges(t, digl(body, "data", "edges")); len(es) != 1 || es[0].Kind != "executes_as" {
			t.Errorf("edges = %+v, want the executes_as edge only: the timed-out level is rolled back whole", es)
		}
		f := graphFrontier(body, role, "grant")
		if f == nil || dig(f, "more", "count") != nil || dig(f, "more", "exact") != false {
			t.Errorf("role grant frontier = %v, want {count: null, exact: false}", f)
		}
		for _, e := range digl(body, "data", "frontier") {
			if dig(e, "more", "exact") != false {
				t.Errorf("frontier entry %v claims an exact count after the time budget bound", e)
			}
		}
		if el := time.Since(start); el > igaread.RequestBudget {
			t.Errorf("request took %s, past the %s budget", el, igaread.RequestBudget)
		}
		// The path search, likewise: not_found_within_budget, bound_by time.
		code, body = api.get("/graph/path" + qs("from", ticket, "to", graphResource(t, l, "arn:aws:s3:::support-tickets/*")))
		mustStatus(t, "path at the deadline", code, body, 200)
		if digs(body, "data", "outcome") != "not_found_within_budget" || digs(body, "data", "bound_by") != "time" {
			t.Errorf("path at the deadline = %v, want not_found_within_budget, bound_by time", body["data"])
		}
	})
}

// D-40: with less than the reserve left, no level STARTS -- the root is
// returned, truncated by time, rather than a level begun that cannot finish.
// A 240 ms budget is below the 250 ms floor of the reserve from the start.
// The root read is mandatory and must fit the budget; a machine too loaded
// for it answers 504, which is the contract too, so that outcome is retried.
func TestP2GraphTimeReserve(t *testing.T) {
	l := newP2Lab(t, "p2-graph-reserve", true)
	l.scanAndProject(graphTeaching(t, l))
	ticket := graphWorkload(t, l, "ticket-tools")
	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(240 * time.Millisecond)
	var code int
	var body map[string]any
	for attempt := 0; attempt < 20; attempt++ {
		code, body = graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph", "root", ticket, "direction", "forward")
		if code != 504 {
			break
		}
	}
	mustStatus(t, "graph under the reserve", code, body, 200)
	if digs(body, "data", "truncated", "bound_by") != "time" || len(digl(body, "data", "nodes")) != 1 {
		t.Errorf("under the reserve = %v, want the root alone, truncated time", body["data"])
	}
	if f := graphFrontier(body, ticket, "executes_as"); f == nil || dig(f, "more", "exact") != false {
		t.Errorf("frontier = %v, want the root's executes_as, count not known", dig(body, "data", "frontier"))
	}
}

// D-40 on /graph/expand: its page is a level, and it is not STARTED under the
// reserve either. The page is not begun: nothing partial, truncated time, and
// the same call is the continuation. As above, a machine too loaded to read
// the root in 240 ms answers 504, which is retried.
func TestP2GraphExpandTimeReserve(t *testing.T) {
	l := newP2Lab(t, "p2-graph-expand-reserve", true)
	l.scanAndProject(graphTeaching(t, l))
	role := graphIdentity(t, l, "SharedToolRole")
	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(240 * time.Millisecond)
	var code int
	var body map[string]any
	for attempt := 0; attempt < 20; attempt++ {
		code, body = graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph/expand", "node", role, "edge", "grant", "direction", "forward")
		if code != 504 {
			break
		}
	}
	mustStatus(t, "expand under the reserve", code, body, 200)
	if digs(body, "data", "truncated", "bound_by") != "time" || len(digl(body, "data", "edges")) != 0 ||
		len(digl(body, "data", "nodes")) != 0 || dig(body, "data", "next_cursor") != nil {
		t.Errorf("expand under the reserve = %v, want no page begun: truncated time, nothing partial", body["data"])
	}
	f := graphFrontier(body, role, "grant")
	if f == nil || dig(f, "more", "exact") != false ||
		digs(f, "expand") != "/api/iga/v1/graph/expand?node="+role+"&edge=grant&direction=forward" {
		t.Errorf("frontier = %v, want the same call as the continuation", dig(body, "data", "frontier"))
	}
	// Control: the full budget pages normally.
	code, body = graphDirect(t, igaread.NewReader(l.db, readTestCursorKey), igaread.DefaultGraphBudgets, l.ws,
		"/graph/expand", "node", role, "edge", "grant", "direction", "forward")
	mustStatus(t, "control", code, body, 200)
	if dig(body, "data", "truncated") != nil || len(digl(body, "data", "edges")) != 2 {
		t.Errorf("control expand = %v, want both grants, not truncated", body["data"])
	}
}

// §5.1: 504 query_timeout ONLY when even the root cannot be read.
func TestP2GraphRootTimeoutIs504(t *testing.T) {
	l := newP2Lab(t, "p2-graph-root504", true)
	l.scanAndProject(graphTeaching(t, l))
	ticket := graphWorkload(t, l, "ticket-tools")
	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(800 * time.Millisecond)
	listsWithTableLocked(t, l.db, "iga_workload", func() {
		code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph", "root", ticket, "direction", "forward")
		if code != 504 || errCode(body) != "query_timeout" || body["data"] != nil {
			t.Errorf("root unreadable = %d %v, want 504 query_timeout, nothing partial", code, body)
		}
	})
	// And the snapshot is not poisoned for the next request.
	code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph", "root", ticket, "direction", "forward")
	mustStatus(t, "after the lock", code, body, 200)
}

// Re-discovered edges cost no budget -- and must not cost rows either. The
// reverse side's grant query from the three statements naming the resource
// returns alpha's two grants (the forward side already holds them) BEFORE
// bravo's (holders are ordered by source key). With the edge budget one short
// of the whole graph, a query limited to "remaining + 1" rows would read only
// the two re-discoveries, leave bravo's grant unread, let the reverse side
// look exhausted, and list two paths as complete. Three exist.
func TestP2GraphPathRediscoveredEdgesCostNoRows(t *testing.T) {
	l := newP2Lab(t, "p2-graph-rediscover", true)
	a := l.account(accountA)
	denyAll := trustDoc(`{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`)
	alpha := trustRole(a, "alpha-role", "AROAALPHAROLEALPHARO", denyAll)
	trustRole(a, "bravo-role", "AROABRAVOROLEBRAVORO", trustDoc(trustAllow(`{"AWS":"`+alpha+`"}`, "sts:AssumeRole")))
	a.attach("alpha-role", a.managed("TicketRead", docTicketRead))
	a.attach("alpha-role", a.managed("TicketWrite", s3aDoc("WriteTickets", "s3:PutObject", "arn:aws:s3:::support-tickets/*")))
	a.attach("alpha-role", a.managed("Elsewhere", s3aDoc("Other", "s3:GetObject", "arn:aws:s3:::elsewhere/*")))
	a.attach("bravo-role", a.managed("ToolboxRead", docToolboxRead))
	trustCycle(l, a, nil)
	r := igaread.NewReader(l.db, readTestCursorKey)
	from, to := graphIdentity(t, l, "alpha-role"), graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	// Forward level 1: alpha's can_assume and 3 grants (4 edges); reverse
	// level 1: the resource's 3 targets (7); reverse level 2 reads the three
	// statements' holders. Eight edges is the whole graph the search needs.
	code, body := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 8 }), l.ws,
		"/graph/path", "from", from, "to", to)
	mustStatus(t, "edges=8", code, body, 200)
	paths := digl(body, "data", "paths")
	viaBravo := false
	for _, p := range paths {
		for _, n := range digl(p, "nodes") {
			if digs(n, "label") == "bravo-role" {
				viaBravo = true
			}
		}
	}
	if digs(body, "data", "outcome") != "found" || len(paths) != 3 || !viaBravo {
		t.Errorf("edges=8 = %d paths (via bravo: %v), outcome %v, more_paths %v: want all three, including alpha -> bravo -> ToolboxRead",
			len(paths), viaBravo, dig(body, "data", "outcome"), dig(body, "data", "more_paths"))
	}
	// Control: the default budgets give the same three, complete.
	code, body = graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, "/graph/path", "from", from, "to", to)
	mustStatus(t, "control", code, body, 200)
	if len(digl(body, "data", "paths")) != 3 || dig(body, "data", "more_paths") != false {
		t.Errorf("control = %v, want three paths, complete", body["data"])
	}
}
