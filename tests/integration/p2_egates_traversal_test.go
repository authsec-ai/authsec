package integration

// §7.1 E11 (external accounts, cycles and limits): the backend half, through
// the real identity, external-principal and traversal routes over the §7.1
// lab, with A scanned before B. What the console draws -- "Account not
// connected", each loop node once, the truncation chip, the two not-found
// messages kept apart -- is M3's Playwright run; here the API those are drawn
// from is asserted.
//
// §7.1's lab holds nothing deeper than the display default of can_assume hops
// (assume_hops 2, §5.4), so this scenario adds what "expand past the display
// default" and a path past the hard hop budget need, in A: chain-1 may assume
// chain-2, chain-2 chain-3, and so on to chain-6 (each trusts the one before)
// -- five can_assume hops end to end, one more than §5.4's per-request 4.

import (
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// egatesChainLength is how many roles egatesChain adds: chain-1 to chain-6,
// five hops, so the whole chain is one hop past the hard budget.
const egatesChainLength = 6

// egatesChain adds E11's chain of six roles to A.
func egatesChain(a *egatesAcct) {
	a.role("chain-1", "AROAEGATESCHAIN00001")
	for i, id := range []string{"AROAEGATESCHAIN00002", "AROAEGATESCHAIN00003", "AROAEGATESCHAIN00004",
		"AROAEGATESCHAIN00005", "AROAEGATESCHAIN00006"} {
		prev := a.roleARN("chain-" + string(rune('1'+i)))
		trustRole(a.p2Account, "chain-"+string(rune('2'+i)), id, trustDoc(trustAllow(`{"AWS":"`+prev+`"}`, "sts:AssumeRole")))
	}
}

// egatesUsedByPrincipal is the one principal of an identity's Used-by whose
// principal kind is kind.
func egatesUsedByPrincipal(t *testing.T, api *readAPI, identity, kind string) map[string]any {
	t.Helper()
	body := egatesGet(t, api, egatesRoute(t, identity, "/used-by"))
	var out map[string]any
	for _, it := range digl(body, "data", "principals", "items") {
		if digs(it, "principal", "kind") == kind {
			if out != nil {
				t.Fatalf("%s used-by has two %s principals: %s", identity, kind, egatesJSON(dig(body, "data", "principals")))
			}
			out = it.(map[string]any)
		}
	}
	if out == nil {
		t.Fatalf("%s used-by has no %s principal: %s", identity, kind, egatesJSON(dig(body, "data", "principals")))
	}
	return out
}

// E11. Open A's role trusting C (never connected): an external principal for
// C, unresolved, account not connected, and the edge crosses accounts. Open
// loop-a's graph: can_assume both ways, each node once, the edge back
// closes_cycle. Expand past the display default: the frontier counts what was
// not walked (exact), and /graph/expand walks it. Search a path to an
// unreachable resource: none_exists when nothing bound, and
// not_found_within_budget -- never none_exists -- when a budget did, through
// the route under its own hard budgets (chain-1 to chain-6 is one can_assume
// hop past them); none claims a distance. A walk past a resolution in force
// it does not follow says so in resolution_not_followed, and is not
// truncated: no budget bound (§5.4, D-egates). The field is true, false or
// -- when the time budget stopped the walk first -- null, whether or not a
// budget bound.
//
// Safeguards (mutation-checked): a node already on the walk is not expanded
// again (a cycle never duplicates nodes); none_exists only when both
// frontiers were exhausted before any budget bound (D-38); /graph's
// truncated names only a budget that bound (D-egates).
func TestP2EgatesE11ExternalAccountsCyclesAndLimits(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e11", true)
	a := egatesProduction(t, l)
	egatesChain(a)
	b := egatesSandbox(t, l)
	egatesCycle(l, a)
	egatesCycle(l, b)
	api := l.api()

	// --- A's role trusting C, an account no one connected.
	partner := egatesIdentity(t, l, "partner-access")
	var cNodes int64 = l.count(`SELECT count(*) FROM iga_external_principal WHERE workspace_id = ? AND issuer = 'aws'
	                             AND subject_claim = ? AND mechanism = ? AND resolution_basis = ''`,
		l.ws, egatesAccountC, models.ExternalPrincipalAWSAccount)
	if cNodes != 1 {
		t.Errorf("external principals for C = %d, want one, unresolved", cNodes)
	}
	pc := egatesUsedByPrincipal(t, api, partner, models.ExternalPrincipalAWSAccount)
	cRef := digs(pc, "principal", "ref")
	if digs(pc, "type") != "can_assume" || digs(pc, "mechanism") != "sts_assume_role" || digs(pc, "state") != models.RelCurrent ||
		digs(pc, "principal", "account", "id") != egatesAccountC || dig(pc, "principal", "account", "connected") != false ||
		digs(pc, "basis") != "declared" || !strings.HasPrefix(cRef, "external_principal:") {
		t.Errorf("partner-access used-by C = %s, want a declared can_assume from C's principal, account not connected", egatesJSON(pc))
	}
	ep := egatesGet(t, api, "/external-principals/"+strings.TrimPrefix(cRef, "external_principal:"))
	if digs(ep, "data", "ref") != cRef || digs(ep, "data", "account", "id") != egatesAccountC ||
		dig(ep, "data", "account", "connected") != false || dig(ep, "data", "account_connected") != false ||
		dig(ep, "data", "resolution") != nil || digs(ep, "data", "unresolved_reason") != igaread.UnresolvedAccountNotConnected ||
		digs(ep, "data", "state") != models.RelCurrent || digs(ep, "data", "lifecycle") != models.IGALifecycleActive ||
		digs(ep, "data", "name") != egatesAccountC {
		t.Errorf("C's principal = %s, want unresolved, account %s not connected", egatesJSON(dig(ep, "data")), egatesAccountC)
	}
	refBy := egatesGet(t, api, "/external-principals/"+strings.TrimPrefix(cRef, "external_principal:")+"/referenced-by")
	if rows := digl(refBy, "data"); len(rows) != 1 || digs(rows[0], "target", "ref") != partner {
		t.Errorf("C's principal referenced-by = %s, want partner-access", egatesJSON(rows))
	}
	rev := egatesGet(t, api, "/graph"+qs("root", partner, "direction", "reverse"))
	nodes := graphNodes(t, digl(rev, "data", "nodes"))
	var cEdge *graphEdge
	for _, e := range graphEdges(t, digl(rev, "data", "edges")) {
		if e.From == cRef {
			e := e
			cEdge = &e
		}
	}
	if cEdge == nil || !cEdge.CrossesAccount || graphLim(cEdge.Limitations, "account_not_connected") == nil ||
		graphLim(digl(nodes[cRef], "limitations"), "account_not_connected") == nil ||
		dig(nodes[cRef], "account", "connected") != false {
		t.Errorf("partner-access reverse graph = %s, want C's principal (account_not_connected) on a crosses_account edge",
			egatesJSON(dig(rev, "data")))
	}
	if graphFrontier(rev, cRef, "can_assume") != nil {
		t.Errorf("an external principal is terminal; frontier %s", egatesJSON(dig(rev, "data", "frontier")))
	}
	// C's principal is unresolved: nothing was left unfollowed, and the walk
	// is complete -- the control for reader-access's below.
	if dig(rev, "data", "truncated") != nil || dig(rev, "data", "resolution_not_followed") != false {
		t.Errorf("partner-access reverse graph: truncated %s, resolution_not_followed %v, want null and false",
			egatesJSON(dig(rev, "data", "truncated")), dig(rev, "data", "resolution_not_followed"))
	}
	// The GitHub OIDC trust: an oidc principal with the wildcard subject,
	// unresolved as a wildcard, federated.
	gha := egatesUsedByPrincipal(t, api, egatesIdentity(t, l, "gha-deploy"), models.ExternalPrincipalOIDC)
	gRef := strings.TrimPrefix(digs(gha, "principal", "ref"), "external_principal:")
	gp := egatesGet(t, api, "/external-principals/"+gRef)
	if digs(gha, "mechanism") != "oidc_federation" || digs(gp, "data", "issuer") != "token.actions.githubusercontent.com" ||
		digs(gp, "data", "subject") != "repo:authsec-ai/authsec:*" || digs(gp, "data", "unresolved_reason") != igaread.UnresolvedWildcard ||
		dig(gp, "data", "resolution") != nil || dig(gp, "data", "account") != nil {
		t.Errorf("gha-deploy's principal = %s (edge %s), want oidc for repo:authsec-ai/authsec:*, unresolved wildcard",
			egatesJSON(dig(gp, "data")), egatesJSON(gha))
	}
	if !strings.Contains(egatesJSON(dig(gha, "conditions")), "repo:authsec-ai/authsec:*") {
		t.Errorf("gha-deploy's conditions = %s, want the StringLike sub condition verbatim", egatesJSON(dig(gha, "conditions")))
	}
	// A's role trusting B's data-reader: A was projected first, so the trust
	// names a principal; B's pass then RESOLVED it (derived, D-41) -- shown,
	// never walked, and the edge crosses from B into A. What reaches
	// data-reader was therefore not read: resolution_not_followed says so,
	// and truncated stays null -- no budget bound (§5.4 "Continuation", the
	// §5.3 Graph example; D-egates).
	access := egatesIdentity(t, l, "reader-access")
	reader := egatesIdentity(t, l, "data-reader")
	rg := egatesGet(t, api, "/graph"+qs("root", access, "direction", "reverse"))
	var crossing *graphEdge
	for _, e := range graphEdges(t, digl(rg, "data", "edges")) {
		if e.Kind == "can_assume" && e.To == access {
			e := e
			crossing = &e
		}
	}
	rn := graphNodes(t, digl(rg, "data", "nodes"))
	if crossing == nil || !crossing.CrossesAccount || digs(rn[crossing.From], "account", "id") != accountB ||
		digs(rn[crossing.From], "resolution", "resolved_to") != reader || rn[reader] != nil ||
		dig(rg, "data", "truncated") != nil || dig(rg, "data", "resolution_not_followed") != true {
		t.Errorf("reader-access reverse graph = %s, want B's resolved principal on a crossing edge, the resolution not walked",
			egatesJSON(dig(rg, "data")))
	}

	// --- loop-a / loop-b: both ways, each node once, the way back marked.
	loopA, loopB := egatesIdentity(t, l, "loop-a"), egatesIdentity(t, l, "loop-b")
	if n := l.count(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND relationship_type = 'can_assume'
	                  AND state = 'current' AND ((source_identity_account_id = ? AND target_identity_account_id = ?)
	                    OR (source_identity_account_id = ? AND target_identity_account_id = ?))`,
		l.ws, refUUID(t, loopA), refUUID(t, loopB), refUUID(t, loopB), refUUID(t, loopA)); n != 2 {
		t.Errorf("can_assume between loop-a and loop-b = %d, want one each way", n)
	}
	for _, dir := range []string{"forward", "reverse"} {
		g := egatesGet(t, api, "/graph"+qs("root", loopA, "direction", dir, "assume_hops", "4"))
		ln := graphNodes(t, digl(g, "data", "nodes")) // fails on a node drawn twice
		le := graphEdges(t, digl(g, "data", "edges"))
		var closing []graphEdge
		for _, e := range le {
			if e.ClosesCycle {
				closing = append(closing, e)
			}
			if e.CrossesAccount {
				t.Errorf("%s: the loop edge %+v crosses accounts; both are B's", dir, e)
			}
		}
		if len(ln) != 2 || len(le) != 2 || len(closing) != 1 || (closing[0].To != loopA && closing[0].From != loopA) ||
			dig(g, "data", "truncated") != nil || dig(g, "data", "resolution_not_followed") != false {
			t.Errorf("loop-a %s graph = %s, want 2 nodes, 2 edges, one closes_cycle back at loop-a, complete",
				dir, egatesJSON(dig(g, "data")))
		}
	}

	// --- Past the display default: chain-1 -> chain-2 -> chain-3 at two hops,
	// then the frontier; /graph/expand takes the next step.
	chain := map[int]string{}
	for i := 1; i <= egatesChainLength; i++ {
		chain[i] = egatesIdentity(t, l, "chain-"+string(rune('0'+i)))
	}
	cg := egatesGet(t, api, "/graph"+qs("root", chain[1], "direction", "forward"))
	cn := graphNodes(t, digl(cg, "data", "nodes"))
	if cn[chain[2]] == nil || cn[chain[3]] == nil || cn[chain[4]] != nil {
		t.Errorf("chain-1 at the display default = %v nodes, want chain-1..3 and not chain-4", egatesSorted(egatesMapKeys(cn)))
	}
	f := graphFrontier(cg, chain[3], "can_assume")
	if f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true || digs(f, "direction") != "forward" ||
		digs(cg, "data", "truncated", "bound_by") != "assume_hops" {
		t.Errorf("chain-1 frontier %s truncated %s, want chain-3 can_assume {count 1, exact}, bound by assume_hops",
			egatesJSON(dig(cg, "data", "frontier")), egatesJSON(dig(cg, "data", "truncated")))
	}
	// A budget that binds and a resolution left unfollowed are two facts, each
	// in its own field (D-egates): this walk was bound by the hops, and the
	// check still ran -- it passed no resolution in force, so false, not null.
	if dig(cg, "data", "resolution_not_followed") != false {
		t.Errorf("chain-1 (bound by assume_hops) resolution_not_followed = %v, want false: established, none passed",
			dig(cg, "data", "resolution_not_followed"))
	}
	// ... and a walk the time budget stopped did not establish it: null, never
	// false (a false would claim a completeness nothing checked). A 240 ms
	// budget is below the D-40 reserve, so no level starts; a machine too
	// loaded to read the root in it answers 504, which is the contract too,
	// and is retried (TestP2GraphTimeReserve). Reader-level: the route's own
	// 3 s budget cannot be made to bind on this fixture.
	short := igaread.NewReader(l.db, readTestCursorKey).WithBudget(240 * time.Millisecond)
	var tcode int
	var timed map[string]any
	for attempt := 0; attempt < 20; attempt++ {
		if tcode, timed = graphDirect(t, short, igaread.DefaultGraphBudgets, l.ws, "/graph", "root", access, "direction", "reverse"); tcode != 504 {
			break
		}
	}
	mustStatus(t, "graph under the time reserve", tcode, timed, 200)
	if digs(timed, "data", "truncated", "bound_by") != "time" || dig(timed, "data", "resolution_not_followed") != nil {
		t.Errorf("reader-access under the time reserve: truncated %s, resolution_not_followed %v, want time and null (not established)",
			egatesJSON(dig(timed, "data", "truncated")), dig(timed, "data", "resolution_not_followed"))
	}
	if _, present := timed["data"].(map[string]any)["resolution_not_followed"]; !present {
		t.Errorf("reader-access under the time reserve omits resolution_not_followed; want it present, null: %s", egatesJSON(dig(timed, "data")))
	}
	exp := egatesGet(t, api, "/graph/expand"+qs("node", chain[3], "edge", "can_assume", "direction", "forward"))
	if es := graphEdges(t, digl(exp, "data", "edges")); len(es) != 1 || es[0].From != chain[3] || es[0].To != chain[4] ||
		dig(exp, "data", "next_cursor") != nil {
		t.Errorf("expand chain-3 = %s, want chain-3 -> chain-4, complete", egatesJSON(dig(exp, "data")))
	}

	// --- Paths. Unreachable with nothing bound: none_exists, no distance.
	refund := egatesWorkload(t, l, "refund-tools", accountA)
	ops := egatesResource(t, l, "arn:aws:s3:::ops-bucket/*")
	none := egatesGet(t, api, "/graph/path"+qs("from", refund, "to", ops))
	if digs(none, "data", "outcome") != "none_exists" || len(digl(none, "data", "paths")) != 0 ||
		dig(none, "data", "bound_by") != nil || dig(none, "data", "more_paths") != false || dig(none, "data", "direction") != nil {
		t.Errorf("refund-tools -> ops-bucket/* = %s, want none_exists, no paths, nothing bound", egatesJSON(dig(none, "data")))
	}
	// The same search with a budget that binds is never "none". A node budget
	// small enough to bind on this fixture is below the route's own (500), so
	// this one case is injected at the Reader; the hop budget below binds
	// through the route.
	r := igaread.NewReader(l.db, readTestCursorKey)
	code, bound := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Nodes = 3 }), l.ws, "/graph/path", "from", refund, "to", ops)
	mustStatus(t, "bounded path", code, bound, 200)
	if digs(bound, "data", "outcome") != "not_found_within_budget" || digs(bound, "data", "bound_by") != "nodes" ||
		len(digl(bound, "data", "paths")) != 0 {
		t.Errorf("refund-tools -> ops-bucket/* under a 3-node budget = %s, want not_found_within_budget, bound_by nodes",
			egatesJSON(dig(bound, "data")))
	}
	// A path that exists but needs more can_assume hops than the route's hard
	// budget (4, §5.4): not found within it, bound by the hops -- never
	// none_exists, and no distance. Through the ROUTE, under its own budgets:
	// chain-1 -> chain-4 (three hops) is found, chain-1 -> chain-6 (five) is
	// not. The control first: the budget, not the chain, is what stops it.
	if p := egatesGet(t, api, "/graph/path"+qs("from", chain[1], "to", chain[4])); digs(p, "data", "outcome") != "found" ||
		len(digl(p, "data", "paths", 0, "edges")) != 3 {
		t.Errorf("chain-1 -> chain-4 = %s, want found, three hops", egatesJSON(dig(p, "data")))
	}
	if n := l.count(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND relationship_type = 'can_assume'
	                  AND state = 'current' AND source_identity_account_id = ANY(?::uuid[]) AND target_identity_account_id = ANY(?::uuid[])`,
		l.ws, egatesRefArray(t, chain), egatesRefArray(t, chain)); n != egatesChainLength-1 {
		t.Fatalf("setup: %d current can_assume edges along the chain, want %d: the path exists", n, egatesChainLength-1)
	}
	code, hops := api.get("/graph/path" + qs("from", chain[1], "to", chain[egatesChainLength]))
	mustStatus(t, "hop-bound path", code, hops, 200)
	if digs(hops, "data", "outcome") != "not_found_within_budget" || digs(hops, "data", "bound_by") != "assume_hops" ||
		len(digl(hops, "data", "paths")) != 0 || dig(hops, "data", "direction") != nil {
		t.Errorf("chain-1 -> chain-%d (%d hops, the route's budget %d) = %s, want not_found_within_budget, bound_by assume_hops, no path",
			egatesChainLength, egatesChainLength-1, igaread.DefaultGraphBudgets.AssumeHops, egatesJSON(dig(hops, "data")))
	}
	for what, body := range map[string]map[string]any{"none": none, "bounded": bound, "hops": hops} {
		if strings.Contains(egatesJSON(body), `"distance`) || strings.Contains(egatesJSON(body), `"length`) {
			t.Errorf("%s path response claims a distance: %s", what, egatesJSON(body))
		}
	}
}

// E11, the hard budgets as the ROUTES apply them (§5.4 "Budgets"): the
// scenario's "expand past the display default" on a neighbourhood larger than
// one request may return. 510 Lambdas in A run as fleet-role. Its reverse
// /graph stops at the 500-node hard budget -- bound_by nodes, every node once,
// meta.budgets the production ones -- and its frontier's more count is exact
// (counted within the budget), never a guess; /graph/expand pages the
// executes_as neighbours 100 at a time with a cursor for the rest, until all
// 510 are walked once; assume_hops beyond the hard 4 is refused, not clamped.
//
// Nothing is injected here: the route runs Reader.Traversal's own budgets.
// The cases that need a budget below the route's -- edges, paths, the time
// budget and a more count that cannot be made exact ({count: null}) -- are
// the Reader-level suites' (p2_graph_budgets_test.go, and the path cases of
// TestP2EgatesE11ExternalAccountsCyclesAndLimits above).
//
// Safeguards (mutation-checked): the routes run under the §5.4 hard node and
// neighbour budgets.
func TestP2EgatesE11HardBudgetsThroughTheRoutes(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e11-budgets", true)
	a := egatesProduction(t, l)
	const fleetSize = 510
	egatesFillersAs(a, egatesPrimary, "fleet-fn", fleetSize, a.role("fleet-role", "AROAEGATESFLEETROLE1"))
	egatesCycle(l, a)
	api := l.api()
	fleet := egatesIdentity(t, l, "fleet-role")

	g := egatesGet(t, api, "/graph"+qs("root", fleet, "direction", "reverse"))
	b := igaread.DefaultGraphBudgets
	if num(g, "meta", "budgets", "nodes") != int64(b.Nodes) || num(g, "meta", "budgets", "edges") != int64(b.Edges) ||
		num(g, "meta", "budgets", "assume_hops") != int64(b.AssumeHops) || num(g, "meta", "budgets", "timeout_ms") != 3000 ||
		b.Nodes != 500 || b.Edges != 2000 || b.AssumeHops != 4 || b.Neighbours != 100 {
		t.Errorf("meta.budgets = %s, want §5.4's hard budgets (nodes 500, edges 2000, assume_hops 4, 3 s)",
			egatesJSON(dig(g, "meta", "budgets")))
	}
	nodes := graphNodes(t, digl(g, "data", "nodes")) // fails on a node drawn twice
	edges := graphEdges(t, digl(g, "data", "edges"))
	if len(nodes) != b.Nodes || digs(g, "data", "truncated", "bound_by") != "nodes" {
		t.Fatalf("fleet-role's reverse graph = %d nodes, truncated %s; want the %d-node hard budget to bind",
			len(nodes), egatesJSON(dig(g, "data", "truncated")), b.Nodes)
	}
	var drawn int64
	for _, e := range edges {
		if e.Kind != "executes_as" {
			continue
		}
		if e.To != fleet || nodes[e.From] == nil {
			t.Errorf("executes_as %+v does not join a drawn workload to fleet-role", e)
		}
		drawn++
	}
	if len(graphRefsOfKind(digl(g, "data", "nodes"), "workload")) != int(drawn) {
		t.Errorf("%d workloads drawn for %d executes_as edges: every drawn workload has its edge", len(graphRefsOfKind(digl(g, "data", "nodes"), "workload")), drawn)
	}
	// What was not returned, counted exactly within the budget -- and the
	// call that returns it.
	f := graphFrontier(g, fleet, "executes_as")
	if f == nil || num(f, "more", "count") != fleetSize-drawn || dig(f, "more", "exact") != true ||
		digs(f, "direction") != "reverse" ||
		digs(f, "expand") != "/api/iga/v1/graph/expand?node="+fleet+"&edge=executes_as&direction=reverse" {
		t.Errorf("fleet-role executes_as frontier = %s, want {count %d, exact} and its expand call", egatesJSON(f), fleetSize-drawn)
	}

	// /graph/expand: 100 per page, a cursor for the rest, every workload once.
	seen := map[string]bool{}
	cursor, pages := "", 0
	for {
		args := []string{"node", fleet, "edge", "executes_as", "direction", "reverse"}
		if cursor != "" {
			args = append(args, "cursor", cursor)
		}
		page := egatesGet(t, api, "/graph/expand"+qs(args...))
		es := graphEdges(t, digl(page, "data", "edges"))
		if len(es) > b.Neighbours || (digs(page, "data", "next_cursor") != "" && len(es) != b.Neighbours) {
			t.Fatalf("expand page %d = %d edges (cursor %v), want pages of %d", pages, len(es), dig(page, "data", "next_cursor"), b.Neighbours)
		}
		for _, e := range es {
			if e.To != fleet || seen[e.From] {
				t.Fatalf("expand page %d: edge %+v repeats a workload or leaves fleet-role", pages, e)
			}
			seen[e.From] = true
		}
		pages++
		if cursor = digs(page, "data", "next_cursor"); cursor == "" {
			break
		}
		if pages > fleetSize/b.Neighbours+1 {
			t.Fatalf("expand did not end after %d pages", pages)
		}
	}
	if len(seen) != fleetSize || pages != fleetSize/b.Neighbours+1 {
		t.Errorf("expand walked %d workloads in %d pages, want all %d in %d", len(seen), pages, fleetSize, fleetSize/b.Neighbours+1)
	}

	// assume_hops: 4 is the per-request ceiling; beyond it is a new expand
	// from the frontier, so 5 is refused rather than quietly clamped.
	if code, body := api.get("/graph" + qs("root", fleet, "direction", "forward", "assume_hops", "4")); code != 200 {
		t.Errorf("assume_hops=4 = %d %s, want 200", code, egatesJSON(body))
	}
	if code, body := api.get("/graph" + qs("root", fleet, "direction", "forward", "assume_hops", "5")); code != 400 ||
		errCode(body) != "invalid_parameter" {
		t.Errorf("assume_hops=5 = %d %s, want 400 invalid_parameter", code, egatesJSON(body))
	}
}

// egatesMapKeys lists a node map's refs.
func egatesMapKeys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// egatesRefArray renders refs' UUIDs as a PostgreSQL uuid[] literal.
func egatesRefArray(t *testing.T, refs map[int]string) string {
	t.Helper()
	ids := make([]string, 0, len(refs))
	for _, ref := range refs {
		ids = append(ids, refUUID(t, ref).String())
	}
	return "{" + strings.Join(ids, ",") + "}"
}
