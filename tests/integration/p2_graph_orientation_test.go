package integration

// T6.4, /graph/path in both orientations (§5.4 l.6091-6092: reverse answers
// "what reaches this" -- Resource › Access, *View in graph* from a resource;
// §2.14.11 "View in graph must find the thing it was asked for"). The route
// has no direction, so a path asked for from a resource to the workload that
// reaches it is the forward path read backwards: found, direction reverse --
// never none_exists for an orientation that was not searched (D-38).

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/igaread"
)

func TestP2GraphPathEitherOrientation(t *testing.T) {
	l := newP2Lab(t, "p2-graph-orientation", true)
	l.scanAndProject(graphTeaching(t, l))
	api := l.api()
	ticket, refund := graphWorkload(t, l, "ticket-tools"), graphWorkload(t, l, "refund-tools")
	role := graphIdentity(t, l, "SharedToolRole")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	// Control: the edges' own orientation.
	body := graphGet(t, api, "/graph/path"+qs("from", ticket, "to", res))
	if digs(body, "data", "outcome") != "found" || digs(body, "data", "direction") != "forward" || len(digl(body, "data", "paths")) != 2 {
		t.Fatalf("ticket-tools -> selector = %v, want found forward, two paths", body["data"])
	}

	// The teaching case asked from its other end: the same two paths, from
	// the selector back to the workload, complete.
	body = graphGet(t, api, "/graph/path"+qs("from", res, "to", ticket))
	paths := digl(body, "data", "paths")
	if digs(body, "data", "outcome") != "found" || digs(body, "data", "direction") != "reverse" || len(paths) != 2 ||
		dig(body, "data", "more_paths") != false || dig(body, "data", "bound_by") != nil ||
		digs(body, "data", "from") != res || digs(body, "data", "to") != ticket {
		t.Fatalf("selector -> ticket-tools = %v, want found, direction reverse, both paths, complete", body["data"])
	}
	for i, p := range paths {
		ns, es := digl(p, "nodes"), digl(p, "edges")
		if len(ns) != 4 || len(es) != 3 || digs(ns[0], "ref") != res || digs(ns[2], "ref") != role || digs(ns[3], "ref") != ticket {
			t.Errorf("path %d = %v, want selector, statement, role, ticket-tools", i, p)
			continue
		}
		// Each edge keeps its own from and to, and runs TOWARD `from`.
		for j, e := range es {
			if digs(e, "to") != digs(ns[j], "ref") || digs(e, "from") != digs(ns[j+1], "ref") {
				t.Errorf("path %d step %d: edge %v does not run from %v to %v", i, j, e, ns[j+1], ns[j])
			}
		}
		if k := []string{digs(es[0], "kind"), digs(es[1], "kind"), digs(es[2], "kind")}; k[0] != "target" || k[1] != "grant" || k[2] != "executes_as" {
			t.Errorf("path %d steps = %v, want target, grant, executes_as", i, k)
		}
	}
	if digs(paths[0], "nodes", 1, "ref") == digs(paths[1], "nodes", 1, "ref") {
		t.Errorf("both reverse paths run through one statement: the two grants are two paths")
	}
	// The role asked from the selector, likewise.
	body = graphGet(t, api, "/graph/path"+qs("from", res, "to", role))
	if digs(body, "data", "outcome") != "found" || digs(body, "data", "direction") != "reverse" || len(digl(body, "data", "paths")) != 2 {
		t.Errorf("selector -> role = %v, want found reverse, two paths", body["data"])
	}

	// No path in EITHER orientation -- two workloads sharing a role are not a
	// path (workload -> role <- workload): none_exists, and no direction.
	body = graphGet(t, api, "/graph/path"+qs("from", ticket, "to", refund))
	if digs(body, "data", "outcome") != "none_exists" || dig(body, "data", "direction") != nil || dig(body, "data", "bound_by") != nil {
		t.Errorf("ticket-tools -> refund-tools = %v, want none_exists with no direction", body["data"])
	}

	// The forward orientation is exhausted at once (nothing leaves a
	// resource), but the reverse one binds: that is NOT none_exists. Two
	// edges do not hold the three-edge path.
	r := igaread.NewReader(l.db, readTestCursorKey)
	code, b := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 2 }), l.ws,
		"/graph/path", "from", res, "to", ticket)
	mustStatus(t, "edges=2", code, b, 200)
	if digs(b, "data", "outcome") != "not_found_within_budget" || digs(b, "data", "bound_by") != "edges" {
		t.Errorf("selector -> ticket-tools under edges=2 = %v, want not_found_within_budget, bound_by edges", b["data"])
	}
}
