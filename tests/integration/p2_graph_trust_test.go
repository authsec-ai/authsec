package integration

// T6.4 and E11 over trust the REAL pipeline projected (T3.4, T4.7): cycles
// (loop-a / loop-b), account boundaries, external principals, the hop limit.
//
//   - A cycle: the edge back to a node on the path that reached it is
//     returned, closes_cycle: true, and the node is never expanded again.
//   - crosses_account (D-36) when both ends name accounts and they differ,
//     with the far account's coverage as limitations on the edge.
//   - An external principal is terminal; its resolution is shown, never
//     walked.
//   - assume_hops limits can_assume only; at the limit the frontier says what
//     was not walked, with an exact count when it was counted.

import (
	"testing"
)

// graphLoop is E11's loop: loop-a and loop-b in B trust each other.
func graphLoop(t *testing.T, l *p2Lab) (a, b string) {
	t.Helper()
	acct := l.account(accountB)
	loopA, loopB := "arn:aws:iam::"+accountB+":role/loop-a", "arn:aws:iam::"+accountB+":role/loop-b"
	trustRole(acct, "loop-a", "AROALOOPALOOPALOOPA1", trustDoc(trustAllow(`{"AWS":"`+loopB+`"}`, "sts:AssumeRole")))
	trustRole(acct, "loop-b", "AROALOOPBLOOPBLOOPB1", trustDoc(trustAllow(`{"AWS":"`+loopA+`"}`, "sts:AssumeRole")))
	trustCycle(l, acct, nil)
	return graphIdentity(t, l, "loop-a"), graphIdentity(t, l, "loop-b")
}

func TestP2GraphCycleClosesAndIsNotReexpanded(t *testing.T) {
	l := newP2Lab(t, "p2-graph-loop", true)
	loopA, loopB := graphLoop(t, l)
	api := l.api()

	for _, dir := range []string{"forward", "reverse"} {
		body := graphGet(t, api, "/graph"+qs("root", loopA, "direction", dir, "assume_hops", "4"))
		nodes := graphNodes(t, digl(body, "data", "nodes")) // fails on a node returned twice
		edges := graphEdges(t, digl(body, "data", "edges"))
		if len(nodes) != 2 || nodes[loopA] == nil || nodes[loopB] == nil {
			t.Fatalf("%s: nodes = %v, want loop-a and loop-b, each once", dir, nodes)
		}
		// Exactly the two trust edges: loop-a is not expanded a second time
		// when the walk comes back to it, so no edge is repeated and nothing
		// is walked to the hop budget.
		if len(edges) != 2 {
			t.Fatalf("%s: edges = %+v, want the two can_assume edges once each", dir, edges)
		}
		var closing, opening []graphEdge
		for _, e := range edges {
			if e.Kind != "can_assume" {
				t.Errorf("%s: edge %+v, want only can_assume", dir, e)
			}
			if e.ClosesCycle {
				closing = append(closing, e)
			} else {
				opening = append(opening, e)
			}
		}
		// Forward from loop-a: loop-a -> loop-b opens, loop-b -> loop-a closes.
		// Reverse: loop-b -> loop-a is walked first (from loop-a to its
		// principal loop-b), then loop-a -> loop-b closes back onto loop-a.
		wantOpenFrom, wantCloseFrom := loopA, loopB
		if dir == "reverse" {
			wantOpenFrom, wantCloseFrom = loopB, loopA
		}
		if len(opening) != 1 || opening[0].From != wantOpenFrom || len(closing) != 1 || closing[0].From != wantCloseFrom {
			t.Errorf("%s: opening %+v closing %+v, want the edge back onto loop-a marked closes_cycle", dir, opening, closing)
		}
		if dig(body, "data", "truncated") != nil || len(digl(body, "data", "frontier")) != 0 {
			t.Errorf("%s: truncated = %v frontier = %v, want a complete walk", dir, dig(body, "data", "truncated"), dig(body, "data", "frontier"))
		}
	}

	// A path through the cycle is simple: loop-a -> loop-b, one step, once.
	p := graphGet(t, api, "/graph/path"+qs("from", loopA, "to", loopB))
	if digs(p, "data", "outcome") != "found" || len(digl(p, "data", "paths")) != 1 ||
		len(digl(p, "data", "paths", 0, "edges")) != 1 || dig(p, "data", "more_paths") != false {
		t.Errorf("path loop-a -> loop-b = %v, want exactly one one-step path, complete", p["data"])
	}
}

// assume_hops (D-34): 0 walks no can_assume; 1 walks one. At the limit the
// frontier names the role with an EXACT count (it was counted in the budget),
// and the response is truncated by assume_hops -- never shown as complete.
func TestP2GraphAssumeHopsFrontier(t *testing.T) {
	l := newP2Lab(t, "p2-graph-hops", true)
	loopA, loopB := graphLoop(t, l)
	api := l.api()

	body := graphGet(t, api, "/graph"+qs("root", loopA, "direction", "forward", "assume_hops", "0"))
	if n := len(digl(body, "data", "nodes")); n != 1 || len(digl(body, "data", "edges")) != 0 {
		t.Errorf("assume_hops=0: %d nodes, edges %v, want the root alone", n, dig(body, "data", "edges"))
	}
	f := graphFrontier(body, loopA, "can_assume")
	if f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true || digs(f, "direction") != "forward" ||
		digs(f, "expand") != "/api/iga/v1/graph/expand?node="+loopA+"&edge=can_assume&direction=forward" {
		t.Errorf("assume_hops=0 frontier = %v, want loop-a can_assume {count 1, exact} with its expand call", dig(body, "data", "frontier"))
	}
	if digs(body, "data", "truncated", "bound_by") != "assume_hops" {
		t.Errorf("assume_hops=0 truncated = %v, want bound_by assume_hops", dig(body, "data", "truncated"))
	}

	body = graphGet(t, api, "/graph"+qs("root", loopA, "direction", "forward", "assume_hops", "1"))
	if n := len(digl(body, "data", "nodes")); n != 2 || len(digl(body, "data", "edges")) != 1 {
		t.Errorf("assume_hops=1: %d nodes, edges %v, want loop-a -> loop-b only", n, dig(body, "data", "edges"))
	}
	if f := graphFrontier(body, loopB, "can_assume"); f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true {
		t.Errorf("assume_hops=1 frontier = %v, want loop-b can_assume {count 1, exact}", dig(body, "data", "frontier"))
	}
	if digs(body, "data", "truncated", "bound_by") != "assume_hops" {
		t.Errorf("assume_hops=1 truncated = %v, want assume_hops", dig(body, "data", "truncated"))
	}
	// The default is 2 (the display default), and 2 is enough here.
	body = graphGet(t, api, "/graph"+qs("root", loopA, "direction", "forward"))
	if len(digl(body, "data", "edges")) != 2 || dig(body, "data", "truncated") != nil {
		t.Errorf("default assume_hops: %v, want both edges and nothing truncated", body["data"])
	}
	// Past the hard budget is 400, not a silent clamp.
	if code, b := api.get("/graph" + qs("root", loopA, "direction", "forward", "assume_hops", "5")); code != 400 || errCode(b) != "invalid_parameter" {
		t.Errorf("assume_hops=5 = %d %v, want 400 invalid_parameter", code, b)
	}
	// Expanding from the frontier goes past the default: a hop is a request.
	exp := graphGet(t, api, "/graph/expand"+qs("node", loopB, "edge", "can_assume", "direction", "forward"))
	if es := graphEdges(t, digl(exp, "data", "edges")); len(es) != 1 || es[0].From != loopB || es[0].To != loopA {
		t.Errorf("expand loop-b can_assume = %v, want loop-b -> loop-a", exp["data"])
	}
}

// crosses_account (D-36) with the far account's coverage on the edge: B's
// data-reader may assume A's reader-access; A's trust is the claim's own
// source, so B's coverage is the far segment's -- and B could not read its
// users.
func TestP2GraphCrossAccountEdge(t *testing.T) {
	l := newP2Lab(t, "p2-graph-cross", true)
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERCONNEC")
	b.iam.fail["GetAccountAuthorizationDetails:User"] = denied("iam:GetAccountAuthorizationDetails")
	trustCycle(l, b, nil)
	a := l.account(accountA)
	readerARN := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "reader-access", "AROAREADERACCESSCONN", trustDoc(trustAllow(`{"AWS":"`+readerARN+`"}`, "sts:AssumeRole")))
	// A same-account edge beside the crossing one: A's reader-fn runs as A's
	// reader-access. Both ends name account A, so it must NOT cross.
	listsFunctions(a, "us-east-1", "reader-fn", a.roleARN("reader-access"))
	trustCycle(l, a, nil)
	api := l.api()
	reader, access := graphIdentity(t, l, "data-reader"), graphIdentity(t, l, "reader-access")
	readerFn := graphWorkload(t, l, "reader-fn")

	for _, tc := range []struct{ root, dir string }{{reader, "forward"}, {access, "reverse"}} {
		body := graphGet(t, api, "/graph"+qs("root", tc.root, "direction", tc.dir))
		var cross *graphEdge
		for _, e := range graphEdges(t, digl(body, "data", "edges")) {
			if e.Kind == "can_assume" && e.From == reader && e.To == access {
				e := e
				cross = &e
			} else if e.CrossesAccount {
				t.Errorf("%s: edge %+v crosses_account, but both ends are in one account", tc.dir, e)
			}
		}
		if cross == nil || !cross.CrossesAccount {
			t.Fatalf("%s from %s: the data-reader -> reader-access edge = %+v, want crosses_account true", tc.dir, tc.root, cross)
		}
		// The far account (B) could not read its users: surface_denied on
		// the edge, naming B and the surface -- in either direction.
		lim := graphLim(cross.Limitations, "surface_denied")
		if lim == nil || digs(lim, "account_id") != accountB || digs(lim, "surface") != "iam_users" || digs(lim, "state") != "denied" {
			t.Errorf("%s: crossing edge limitations = %v, want B's iam_users surface_denied", tc.dir, cross.Limitations)
		}
		if graphHasCode(cross.Limitations, "account_not_connected") {
			t.Errorf("%s: both accounts are connected, got %v", tc.dir, cross.Limitations)
		}
		if tc.dir == "reverse" {
			x := graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "executes_as")
			if len(x) != 1 || x[0].From != readerFn || x[0].CrossesAccount {
				t.Errorf("reverse: executes_as = %+v, want reader-fn -> reader-access, both in A, not crossing", x)
			}
		}
		nodes := graphNodes(t, digl(body, "data", "nodes"))
		if digs(nodes[reader], "account", "id") != accountB || digs(nodes[access], "account", "id") != accountA {
			t.Errorf("%s: the far node must name its account: %v / %v", tc.dir, nodes[reader]["account"], nodes[access]["account"])
		}
	}

	// An account filter applies to STARTING objects, never to traversal
	// (§2.14.10): filtering to A still shows the path into B.
	body := graphGet(t, api, "/graph"+qs("root", access, "direction", "reverse", "account", accountA))
	if graphNodes(t, digl(body, "data", "nodes"))[reader] == nil {
		t.Errorf("account=%s hid the far node %s: %v", accountA, reader, body["data"])
	}
	if code, b := api.get("/graph" + qs("root", access, "direction", "reverse", "account", "production")); code != 400 {
		t.Errorf("a malformed account = %d %v, want 400", code, b)
	}
}

// External principals: an unconnected account's principals are nodes naming
// their account (account_not_connected), the edge crosses accounts, and the
// principal is terminal -- nothing is expanded from it, and a resolution it
// carries is shown, never walked.
func TestP2GraphExternalPrincipalIsTerminal(t *testing.T) {
	l := newP2Lab(t, "p2-graph-external", true)
	a := l.account(accountA)
	readerARN := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "partner-access", "AROAPARTNERACCESS001", trustDoc(
		trustAllow(`{"AWS":["arn:aws:iam::`+trustAccountC+`:role/partner-role","arn:aws:iam::`+trustAccountC+`:root"]}`, "sts:AssumeRole")))
	trustRole(a, "reader-access", "AROAREADERACCESS0001", trustDoc(trustAllow(`{"AWS":"`+readerARN+`"}`, "sts:AssumeRole")))
	trustRole(a, "open-role", "AROAOPENROLEOPENROLE", trustDoc(trustAllow(`"*"`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	api := l.api()
	partner := graphIdentity(t, l, "partner-access")

	body := graphGet(t, api, "/graph"+qs("root", partner, "direction", "reverse"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))
	if len(edges) != 2 || len(nodes) != 3 {
		t.Fatalf("reverse from partner-access = %v, want the role and C's two principals", body["data"])
	}
	for _, e := range edges {
		ext := nodes[e.From]
		if digs(ext, "kind") != "external_principal" || digs(ext, "account", "id") != trustAccountC ||
			dig(ext, "account", "connected") != false {
			t.Errorf("principal %v, want an external principal naming unconnected account %s", ext, trustAccountC)
		}
		// D-96: /evidence's field for the code -- the accounts it names.
		if l := graphLim(digl(ext, "limitations"), "account_not_connected"); l == nil || digs(l, "accounts", 0) != trustAccountC {
			t.Errorf("principal limitations = %v, want account_not_connected %s", digl(ext, "limitations"), trustAccountC)
		}
		if !e.CrossesAccount || graphLim(e.Limitations, "account_not_connected") == nil {
			t.Errorf("edge %+v, want crosses_account with account_not_connected", e)
		}
		if graphFrontier(body, e.From, "can_assume") != nil {
			t.Errorf("an external principal is terminal; frontier = %v", dig(body, "data", "frontier"))
		}
	}
	// Unresolved principals are the end of what can be read: nothing was
	// left unfollowed, so the walk is complete.
	if dig(body, "data", "truncated") != nil {
		t.Errorf("reverse from partner-access: truncated = %v, want null (no resolution in force)", dig(body, "data", "truncated"))
	}
	labels := []string{digs(nodes[edges[0].From], "label"), digs(nodes[edges[1].From], "label")}
	if !(labels[0] == trustAccountC || labels[1] == trustAccountC) {
		t.Errorf("principal labels = %v, want the account id for the :root principal (D-87)", labels)
	}
	// Expanding an external principal in reverse is not an edge the
	// traversal has: 400, not an empty answer that looks like "nobody".
	if code, b := api.get("/graph/expand" + qs("node", edges[0].From, "edge", "can_assume", "direction", "reverse")); code != 400 {
		t.Errorf("reverse expand of an external principal = %d %v, want 400", code, b)
	}
	// "*" names no account: the edge does not cross (unknown is not a
	// different account) and the label says what it is.
	open := graphGet(t, api, "/graph"+qs("root", graphIdentity(t, l, "open-role"), "direction", "reverse"))
	oe := graphEdges(t, digl(open, "data", "edges"))
	on := graphNodes(t, digl(open, "data", "nodes"))
	if len(oe) != 1 || oe[0].CrossesAccount || digs(on[oe[0].From], "label") != "any AWS principal" || on[oe[0].From]["account"] != nil {
		t.Errorf("open-role reverse = %v, want one non-crossing edge from 'any AWS principal' with Unknown account", open["data"])
	}

	// B connects: the principal for B's data-reader gains a DERIVED
	// resolution (D-41). It is displayed on the node and never walked.
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERDATARE")
	b.attach("data-reader", b.managed("ReaderTickets", docTicketRead))
	trustCycle(l, b, nil)
	reader, access := graphIdentity(t, l, "data-reader"), graphIdentity(t, l, "reader-access")
	rev := graphGet(t, api, "/graph"+qs("root", access, "direction", "reverse"))
	rn := graphNodes(t, digl(rev, "data", "nodes"))
	var ext map[string]any
	for ref, n := range rn {
		if digs(n, "kind") == "external_principal" {
			ext = rn[ref]
		}
	}
	if ext == nil || digs(ext, "resolution", "basis") != "derived" || digs(ext, "resolution", "resolved_to") != reader {
		t.Fatalf("reader-access's principal = %v, want a derived resolution to %s", ext, reader)
	}
	if rn[reader] != nil {
		t.Errorf("the resolution was walked: data-reader %s is a node of reader-access's reverse graph", reader)
	}
	// ...so what reaches data-reader was not walked, and the answer to "what
	// reaches reader-access" is not complete: it must not read as complete.
	if digs(rev, "data", "truncated", "bound_by") != "resolution_not_followed" {
		t.Errorf("reverse from reader-access: truncated = %v, want bound_by resolution_not_followed", dig(rev, "data", "truncated"))
	}
	fwd := graphGet(t, api, "/graph"+qs("root", reader, "direction", "forward"))
	if graphNodes(t, digl(fwd, "data", "nodes"))[access] != nil {
		t.Errorf("forward from data-reader reaches reader-access through the principal's resolution: %v", fwd["data"])
	}
	// Forward from data-reader nothing bound -- but the principal that IS
	// data-reader may assume reader-access, and the walk (which can never
	// reach a principal) did not look: not complete, as /graph/path says.
	if digs(fwd, "data", "truncated", "bound_by") != "resolution_not_followed" {
		t.Errorf("forward from data-reader: truncated = %v, want bound_by resolution_not_followed", dig(fwd, "data", "truncated"))
	}
	// The path search did not look through the resolution, so it must not
	// say none_exists: the trust names data-reader's exact ARN.
	p := graphGet(t, api, "/graph/path"+qs("from", reader, "to", access))
	if digs(p, "data", "outcome") != "not_found_within_budget" || digs(p, "data", "bound_by") != "resolution_not_followed" {
		t.Errorf("path data-reader -> reader-access = %v, want not_found_within_budget, bound_by resolution_not_followed", p["data"])
	}

	// From the principal itself: its own edges are walked, data-reader's
	// (its resolved self) are not -- on /graph and on /graph/path alike.
	extRef := digs(ext, "ref")
	fromExt := graphGet(t, api, "/graph"+qs("root", extRef, "direction", "forward"))
	if graphNodes(t, digl(fromExt, "data", "nodes"))[access] == nil ||
		digs(fromExt, "data", "truncated", "bound_by") != "resolution_not_followed" {
		t.Errorf("forward from the principal = %v, want reader-access, truncated resolution_not_followed", fromExt["data"])
	}
	tickets := graphResource(t, l, "arn:aws:s3:::support-tickets/*")
	p = graphGet(t, api, "/graph/path"+qs("from", extRef, "to", tickets))
	if digs(p, "data", "outcome") != "not_found_within_budget" || digs(p, "data", "bound_by") != "resolution_not_followed" {
		t.Errorf("path principal -> data-reader's resource = %v, want not_found_within_budget, bound_by resolution_not_followed", p["data"])
	}
	// Control: data-reader's own path to it is declared and found.
	if p = graphGet(t, api, "/graph/path"+qs("from", reader, "to", tickets)); digs(p, "data", "outcome") != "found" {
		t.Errorf("path data-reader -> its resource = %v, want found", p["data"])
	}
}
