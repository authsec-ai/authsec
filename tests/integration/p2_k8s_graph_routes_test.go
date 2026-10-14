package integration

// The traversal routes over a Kubernetes cluster (traverse_k8s.go): /graph
// from a workload, a ServiceAccount and a rule; /graph/expand on Kubernetes
// nodes; /graph/path; the budgets; and the workspace boundary. The fixture
// (p2_k8s_graph_fixture_test.go) is written by the real projection, in a
// workspace with NO AWS publication -- Kubernetes rows belong to none.

import (
	"net/http"
	"net/url"
	"sort"
	"testing"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// k8sQS builds a query string, refs unescaped as the frontier writes them.
func k8sQS(kv ...string) string {
	vals := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Add(kv[i], kv[i+1])
	}
	s, _ := url.QueryUnescape(vals.Encode())
	return "?" + s
}

// k8sGrantVia is the binding name of every grant edge from -> to, sorted.
func k8sGrantVia(es []graphEdge, from, to string) []string {
	var out []string
	for _, e := range graphEdgesOfKind(es, "grant") {
		if e.From == from && e.To == to {
			out = append(out, digs(e.Raw, "assignment", "name"))
		}
	}
	sort.Strings(out)
	return out
}

func TestP2K8sGraphWorkloadRoot(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-workload")
	api := f.api()
	body := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward"))
	contractCheck(t, "GET /graph (k8s workload)", body, contractK8sGraph)

	nodes := graphNodes(t, digl(body, "data", "nodes"))
	for _, ref := range []string{f.workload, f.research, f.secretRule, f.podRule, f.cmRule} {
		if nodes[ref] == nil {
			t.Errorf("node %s missing; got %v", ref, nodes)
		}
	}
	if len(nodes) != 5 || nodes[f.idle] != nil {
		t.Errorf("nodes = %d, want the workload, its SA and the SA's three rules only", len(nodes))
	}
	es := graphEdges(t, digl(body, "data", "edges"))
	if ex := graphEdgesOfKind(es, "executes_as"); len(ex) != 1 || ex[0].From != f.workload || ex[0].To != f.research ||
		digs(ex[0].Raw, "basis") != "observed" {
		t.Errorf("executes_as = %+v, want workload -> research, observed", ex)
	}
	// Two grants reach secret-reader's rule: one through the
	// ClusterRoleBinding (cluster-wide), one through a RoleBinding that
	// narrows it to iga-demo -- the binding is on the edge, the role on both.
	if got := k8sGrantVia(es, f.research, f.secretRule); len(got) != 2 || got[0] != "research-reads-secrets" || got[1] != "research-secrets-ns" {
		t.Errorf("grants to the secrets rule via %v, want the CRB and the namespaced RB", got)
	}
	for _, e := range graphEdgesOfKind(es, "grant") {
		a, _ := dig(e.Raw, "assignment").(map[string]any)
		if a == nil {
			t.Errorf("grant %s names no binding: %v", e.Claim, e.Raw)
			continue
		}
		switch a["name"] {
		case "research-reads-secrets":
			if a["kind"] != "k8s_cluster_role_binding" || a["namespace"] != nil || digs(e.Raw, "policy_kind") != "k8s_cluster_role" {
				t.Errorf("CRB grant = %v, want a cluster-wide binding of a ClusterRole", e.Raw)
			}
		case "research-secrets-ns":
			if a["kind"] != "k8s_role_binding" || a["namespace"] != k8sGraphNS || digs(e.Raw, "policy_ref") != f.secretReader {
				t.Errorf("RB grant = %v, want an iga-demo binding of secret-reader", e.Raw)
			}
		case "research-pods":
			if digs(e.Raw, "policy") != "iga-demo/pod-reader" || digs(e.Raw, "policy_ref") != f.podReader {
				t.Errorf("pod grant = %v, want Role iga-demo/pod-reader", e.Raw)
			}
		default:
			t.Errorf("grant through %v, which is not in the fixture", a)
		}
	}
	if n := len(graphEdgesOfKind(es, "grant")); n != 4 {
		t.Errorf("%d grants, want 4 (the dangling binding reaches no rule)", n)
	}

	// The nodes say what they are without an AWS account.
	wl, sa, rule := nodes[f.workload], nodes[f.research], nodes[f.secretRule]
	if wl["runtime_kind"] != "k8s_deployment" || wl["native_id"] != "iga-demo/research-agent" || digs(wl, "scope", "id") != k8sGraphCluster ||
		wl["sub_scope"] != k8sGraphNS {
		t.Errorf("workload node = %v", wl)
	}
	for _, n := range []map[string]any{wl, sa, rule} {
		if _, has := n["account"]; has {
			t.Errorf("%s carries an account: %v", n["ref"], n["account"])
		}
		if _, has := n["arn"]; has {
			t.Errorf("%s carries an arn: %v", n["ref"], n["arn"])
		}
	}
	if sa["kind"] != "k8s_service_account" || sa["native_id"] != "iga-demo/research" || dig(sa, "used_by_count", "value") != float64(1) {
		t.Errorf("SA node = %v", sa)
	}
	if rule["label"] != "get, list on secrets" || rule["sub_scope"] != nil || rule["policy"] != "secret-reader" {
		t.Errorf("rule node = %v", rule)
	}
	if vs := digl(rule, "k8s_rule", "verbs"); len(vs) != 2 || vs[0] != "get" || vs[1] != "list" {
		t.Errorf("k8s_rule.verbs = %v", vs)
	}
	if nodes[f.podRule]["sub_scope"] != k8sGraphNS {
		t.Errorf("a Role's rule is its namespace's: %v", nodes[f.podRule])
	}
	// Unresolved is not none: the dangling binding is stated on the SA.
	if l := graphLim(digl(sa, "limitations"), "k8s_unresolved_bindings"); l == nil || l["count"] != float64(1) ||
		len(digl(l, "bindings")) != 1 || digl(l, "bindings")[0] != "iga-demo/dangling" {
		t.Errorf("SA limitations = %v, want k8s_unresolved_bindings naming iga-demo/dangling", digl(sa, "limitations"))
	}
	// A complete, cluster-wide sweep that read iga-demo leaves no gap.
	for _, n := range digl(body, "data", "nodes") {
		if graphHasCode(digl(n, "limitations"), "k8s_coverage_gap") {
			t.Errorf("%s has a coverage gap after a complete sweep: %v", digs(n, "ref"), digl(n, "limitations"))
		}
	}

	// Nothing more to load, nothing bound, and no publication behind it.
	if fr := digl(body, "data", "frontier"); len(fr) != 0 || dig(body, "data", "truncated") != nil {
		t.Errorf("frontier %v truncated %v, want a complete answer", fr, dig(body, "data", "truncated"))
	}
	if dig(body, "meta", "rev") != nil || digs(body, "meta", "graph_state") != "unrevisioned" {
		t.Errorf("meta = %v, want rev null and graph_state unrevisioned", body["meta"])
	}
}

func TestP2K8sGraphIdentityAndStatementRoots(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-roots")
	api := f.api()

	// From the SA, forward: its four grants to three rules, nothing else.
	fwd := graphGet(t, api, "/graph"+k8sQS("root", f.research, "direction", "forward"))
	contractCheck(t, "GET /graph (k8s SA forward)", fwd, contractK8sGraph)
	if n := graphNodes(t, digl(fwd, "data", "nodes")); len(n) != 4 || n[f.workload] != nil {
		t.Errorf("SA forward nodes = %v, want the SA and its three rules", n)
	}
	if es := graphEdges(t, digl(fwd, "data", "edges")); len(es) != 4 || len(graphEdgesOfKind(es, "grant")) != 4 {
		t.Errorf("SA forward edges = %+v, want four grants", es)
	}

	// From the SA, reverse: the workload that runs as it.
	rev := graphGet(t, api, "/graph"+k8sQS("root", f.research, "direction", "reverse"))
	contractCheck(t, "GET /graph (k8s SA reverse)", rev, contractK8sGraph)
	es := graphEdges(t, digl(rev, "data", "edges"))
	if len(es) != 1 || es[0].Kind != "executes_as" || es[0].From != f.workload {
		t.Errorf("SA reverse edges = %+v, want workload -executes_as-> SA", es)
	}

	// From a rule, reverse: who holds it, through which binding, and what
	// runs as them.
	st := graphGet(t, api, "/graph"+k8sQS("root", f.secretRule, "direction", "reverse"))
	contractCheck(t, "GET /graph (k8s rule reverse)", st, contractK8sGraph)
	nodes := graphNodes(t, digl(st, "data", "nodes"))
	if len(nodes) != 3 || nodes[f.research] == nil || nodes[f.workload] == nil {
		t.Errorf("rule reverse nodes = %v, want the rule, the SA and the workload", nodes)
	}
	es = graphEdges(t, digl(st, "data", "edges"))
	if got := k8sGrantVia(es, f.research, f.secretRule); len(got) != 2 {
		t.Errorf("rule reverse grants via %v, want both bindings", got)
	}
	if len(graphEdgesOfKind(es, "executes_as")) != 1 {
		t.Errorf("rule reverse edges = %+v, want the workload's executes_as", es)
	}

	// A rule forward has nowhere to go: Kubernetes rules name resource
	// types, never resource rows, so there is no target edge and no frontier
	// offering one.
	sf := graphGet(t, api, "/graph"+k8sQS("root", f.secretRule, "direction", "forward"))
	if len(digl(sf, "data", "edges")) != 0 || len(digl(sf, "data", "frontier")) != 0 || dig(sf, "data", "truncated") != nil {
		t.Errorf("rule forward = %v, want the rule alone, complete", sf["data"])
	}

	// An idle SA: itself, complete.
	idle := graphGet(t, api, "/graph"+k8sQS("root", f.idle, "direction", "reverse"))
	if len(digl(idle, "data", "nodes")) != 1 || len(digl(idle, "data", "edges")) != 0 {
		t.Errorf("idle SA = %v, want itself only", idle["data"])
	}
}

func TestP2K8sGraphExpand(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-expand")
	api := f.api()

	// One step: the SA's grants, each with its binding.
	body := graphGet(t, api, "/graph/expand"+k8sQS("node", f.research, "edge", "grant", "direction", "forward"))
	contractCheck(t, "GET /graph/expand (k8s grant)", body, contractK8sGraphExpand)
	if es := graphEdges(t, digl(body, "data", "edges")); len(es) != 4 || dig(body, "data", "next_cursor") != nil {
		t.Errorf("expand grants = %+v, want four grants on one page", es)
	}
	if n := digl(body, "data", "nodes"); len(n) != 3 {
		t.Errorf("expand nodes = %v, want the three rules", n)
	}
	// And back from the SA to what runs as it.
	back := graphGet(t, api, "/graph/expand"+k8sQS("node", f.research, "edge", "executes_as", "direction", "reverse"))
	contractCheck(t, "GET /graph/expand (k8s executes_as)", back, contractK8sGraphExpand)
	if es := graphEdges(t, digl(back, "data", "edges")); len(es) != 1 || es[0].From != f.workload {
		t.Errorf("expand executes_as = %+v", es)
	}
	// The new neighbour's own continuation is named: the workload has none in
	// reverse, so nothing.
	if fr := digl(back, "data", "frontier"); len(fr) != 0 {
		t.Errorf("expand frontier = %v", fr)
	}

	// Paged, one neighbour at a time, with an unrevisioned cursor bound to
	// the node: four pages, each grant once, in the response's order.
	r := igaread.NewReader(f.db, readTestCursorKey)
	one := graphBudgets(func(b *igaread.GraphBudgets) { b.Neighbours = 1 })
	args := []string{"node", f.research, "edge", "grant", "direction", "forward"}
	seen := map[string]bool{}
	cursor := ""
	for page := 1; ; page++ {
		kv := args
		if cursor != "" {
			kv = append(append([]string{}, args...), "cursor", cursor)
		}
		code, p := graphDirect(t, r, one, f.ws, "/graph/expand", kv...)
		mustStatus(t, "expand page", code, p, 200)
		es := graphEdges(t, digl(p, "data", "edges"))
		if len(es) != 1 {
			t.Fatalf("page %d = %v, want one grant", page, p["data"])
		}
		if seen[es[0].Claim] {
			t.Fatalf("page %d repeats %s", page, es[0].Claim)
		}
		seen[es[0].Claim] = true
		cursor = digs(p, "data", "next_cursor")
		if cursor == "" {
			break
		}
		if page > 4 {
			t.Fatal("more than four pages")
		}
	}
	if len(seen) != 4 {
		t.Errorf("paged %d grants, want 4", len(seen))
	}
	// A kind the Kubernetes projection never writes is an empty page, not an
	// error and not a frontier.
	none := graphGet(t, api, "/graph/expand"+k8sQS("node", f.research, "edge", "member_of", "direction", "forward"))
	if len(digl(none, "data", "edges")) != 0 || len(digl(none, "data", "frontier")) != 0 {
		t.Errorf("member_of expand = %v, want nothing", none["data"])
	}
}

func TestP2K8sGraphPath(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-path")
	api := f.api()

	// workload -> rule: two declared paths, one per binding.
	body := graphGet(t, api, "/graph/path"+k8sQS("from", f.workload, "to", f.secretRule))
	contractCheck(t, "GET /graph/path (k8s)", body, contractK8sGraphPath)
	if digs(body, "data", "outcome") != "found" || digs(body, "data", "direction") != "forward" ||
		dig(body, "data", "more_paths") != false || dig(body, "data", "bound_by") != nil {
		t.Fatalf("path = %v, want found, forward, complete", body["data"])
	}
	paths := digl(body, "data", "paths")
	if len(paths) != 2 {
		t.Fatalf("%d paths, want 2 (one per binding)", len(paths))
	}
	var via []string
	for _, p := range paths {
		ns := digl(p, "nodes")
		if len(ns) != 3 || digs(ns[0], "ref") != f.workload || digs(ns[1], "ref") != f.research || digs(ns[2], "ref") != f.secretRule {
			t.Errorf("path nodes = %v, want workload, SA, rule", ns)
		}
		es := digl(p, "edges")
		if len(es) != 2 || digs(es[0], "kind") != "executes_as" || digs(es[1], "kind") != "grant" {
			t.Errorf("path edges = %v", es)
			continue
		}
		via = append(via, digs(es[1], "assignment", "name"))
		// The SA's unresolved binding is on the path: it runs through the SA.
		if !graphHasCode(digl(p, "limitations"), "k8s_unresolved_bindings") {
			t.Errorf("path limitations = %v, want the SA's", digl(p, "limitations"))
		}
	}
	sort.Strings(via)
	if len(via) != 2 || via[0] != "research-reads-secrets" || via[1] != "research-secrets-ns" {
		t.Errorf("paths via %v", via)
	}

	// The other way round: the same paths, against the edges.
	back := graphGet(t, api, "/graph/path"+k8sQS("from", f.secretRule, "to", f.workload))
	if digs(back, "data", "outcome") != "found" || digs(back, "data", "direction") != "reverse" || len(digl(back, "data", "paths")) != 2 {
		t.Errorf("reverse path = %v", back["data"])
	}

	// No path, searched to exhaustion in both orientations: none_exists.
	none := graphGet(t, api, "/graph/path"+k8sQS("from", f.workload, "to", f.idle))
	contractCheck(t, "GET /graph/path (k8s none)", none, contractK8sGraphPath)
	if digs(none, "data", "outcome") != "none_exists" || dig(none, "data", "bound_by") != nil {
		t.Errorf("workload -> idle SA = %v, want none_exists", none["data"])
	}

	// A budget that binds is never none_exists.
	r := igaread.NewReader(f.db, readTestCursorKey)
	code, tight := graphDirect(t, r, graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 1 }), f.ws, "/graph/path",
		"from", f.workload, "to", f.idle)
	mustStatus(t, "tight path", code, tight, 200)
	if digs(tight, "data", "outcome") != "not_found_within_budget" || digs(tight, "data", "bound_by") != "edges" {
		t.Errorf("bound path = %v, want not_found_within_budget by edges", tight["data"])
	}
}

func TestP2K8sGraphBudgets(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-budgets")
	r := igaread.NewReader(f.db, readTestCursorKey)
	for _, tc := range []struct {
		name         string
		b            igaread.GraphBudgets
		bound        string
		nodes, edges int
	}{
		// Level 1 reaches the SA; level 2's first new rule would be a third
		// node.
		{"nodes", graphBudgets(func(b *igaread.GraphBudgets) { b.Nodes = 2 }), "nodes", 2, 1},
		// Level 2's first grant would be a second edge.
		{"edges", graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 1 }), "edges", 2, 1},
	} {
		code, body := graphDirect(t, r, tc.b, f.ws, "/graph", "root", f.workload, "direction", "forward")
		mustStatus(t, tc.name, code, body, 200)
		if digs(body, "data", "truncated", "bound_by") != tc.bound {
			t.Errorf("%s: truncated = %v, want %s", tc.name, dig(body, "data", "truncated"), tc.bound)
		}
		if n, e := len(digl(body, "data", "nodes")), len(digl(body, "data", "edges")); n != tc.nodes || e != tc.edges {
			t.Errorf("%s: %d nodes %d edges, want %d/%d", tc.name, n, e, tc.nodes, tc.edges)
		}
		// The SA's grants are the frontier, counted exactly: four.
		fr := graphFrontier(body, f.research, "grant")
		if fr == nil || dig(fr, "more", "count") != float64(4) || dig(fr, "more", "exact") != true ||
			digs(fr, "expand") != "/api/iga/v1/graph/expand?node="+f.research+"&edge=grant&direction=forward" {
			t.Errorf("%s: frontier = %v, want the SA's four grants", tc.name, digl(body, "data", "frontier"))
		}
	}
}

func TestP2K8sGraphStaysInItsWorkspace(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-ws")
	other := newP2Lab(t, "p2-k8s-graph-ws-other", true)
	api := f.api().asWorkspace(other.ws)
	for _, p := range []string{
		"/graph" + k8sQS("root", f.workload, "direction", "forward"),
		"/graph" + k8sQS("root", f.secretRule, "direction", "reverse"),
		"/graph/expand" + k8sQS("node", f.research, "edge", "grant", "direction", "forward"),
		"/graph/path" + k8sQS("from", f.workload, "to", f.secretRule),
	} {
		code, body := api.get(p)
		if code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("another workspace's token: GET %s = %d %v, want 404", p, code, body)
		}
	}
	// The same calls from the owning workspace are 200 (the 404 is the
	// workspace's, not the ref's).
	code, body := f.api().get("/graph" + k8sQS("root", f.workload, "direction", "forward"))
	mustStatus(t, "own workspace", code, body, 200)
}
