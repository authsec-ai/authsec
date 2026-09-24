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
// default" needs, in A: chain-1 may assume chain-2, chain-2 chain-3, chain-3
// chain-4 (each trusts the one before).

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// egatesChain adds E11's chain of four roles to A.
func egatesChain(a *egatesAcct) {
	a.role("chain-1", "AROAEGATESCHAIN00001")
	for i, id := range []string{"AROAEGATESCHAIN00002", "AROAEGATESCHAIN00003", "AROAEGATESCHAIN00004"} {
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
// not_found_within_budget -- never none_exists -- when a budget did; neither
// claims a distance.
//
// Safeguards (mutation-checked): a node already on the walk is not expanded
// again (a cycle never duplicates nodes); none_exists only when both
// frontiers were exhausted before any budget bound (D-38).
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
	// never walked, and the edge crosses from B into A.
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
		digs(rg, "data", "truncated", "bound_by") != "resolution_not_followed" {
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
			dig(g, "data", "truncated") != nil {
			t.Errorf("loop-a %s graph = %s, want 2 nodes, 2 edges, one closes_cycle back at loop-a, complete",
				dir, egatesJSON(dig(g, "data")))
		}
	}

	// --- Past the display default: chain-1 -> chain-2 -> chain-3 at two hops,
	// then the frontier; /graph/expand takes the next step.
	chain := map[int]string{}
	for i := 1; i <= 4; i++ {
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
	// The same search with a budget that binds is never "none".
	r := igaread.NewReader(l.db, readTestCursorKey)
	code, bound := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Nodes = 3 }), l.ws, "/graph/path", "from", refund, "to", ops)
	mustStatus(t, "bounded path", code, bound, 200)
	if digs(bound, "data", "outcome") != "not_found_within_budget" || digs(bound, "data", "bound_by") != "nodes" ||
		len(digl(bound, "data", "paths")) != 0 {
		t.Errorf("refund-tools -> ops-bucket/* under a 3-node budget = %s, want not_found_within_budget, bound_by nodes",
			egatesJSON(dig(bound, "data")))
	}
	// A path that exists but needs more can_assume hops than the budget: not
	// found within it, bound by the hops -- never none_exists.
	if p := egatesGet(t, api, "/graph/path"+qs("from", chain[1], "to", chain[4])); digs(p, "data", "outcome") != "found" ||
		len(digl(p, "data", "paths", 0, "edges")) != 3 {
		t.Errorf("chain-1 -> chain-4 = %s, want found, three hops", egatesJSON(dig(p, "data")))
	}
	code, hops := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.AssumeHops = 2 }), l.ws, "/graph/path", "from", chain[1], "to", chain[4])
	mustStatus(t, "hop-bound path", code, hops, 200)
	if digs(hops, "data", "outcome") != "not_found_within_budget" || digs(hops, "data", "bound_by") != "assume_hops" {
		t.Errorf("chain-1 -> chain-4 within 2 hops = %s, want not_found_within_budget, bound_by assume_hops", egatesJSON(dig(hops, "data")))
	}
	for what, body := range map[string]map[string]any{"none": none, "bounded": bound, "hops": hops} {
		if strings.Contains(egatesJSON(body), `"distance`) || strings.Contains(egatesJSON(body), `"length`) {
			t.Errorf("%s path response claims a distance: %s", what, egatesJSON(body))
		}
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
