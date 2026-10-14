package integration

// Kubernetes lifecycle, coverage and provider separation on the traversal
// routes: an ended binding is hidden by default and shown with include_ended;
// a binding an incomplete sweep could not re-read is stale, not ended, and
// says why; a sweep that did not read the cluster-scoped part, or a
// namespace, leaves exactly those elements with a k8s_coverage_gap; and in a
// workspace holding both providers, every AWS response is byte-for-byte what
// it was before the Kubernetes rows arrived, and neither provider's graph
// reaches the other's nodes.

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// k8sEdgeVia finds the grant from -> to through a binding, or nil.
func k8sEdgeVia(es []graphEdge, from, to, binding string) *graphEdge {
	for i, e := range graphEdgesOfKind(es, "grant") {
		_ = i
		if e.From == from && e.To == to && digs(e.Raw, "assignment", "name") == binding {
			e := e
			return &e
		}
	}
	return nil
}

func TestP2K8sGraphEndedAndStale(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-lifecycle")
	api := f.api()

	// research-pods is deleted in the cluster; the sweep is complete and
	// cluster-wide, so its absence is evidence: its grants END.
	gone := k8sFullWorld()
	gone.drop = map[string]bool{"research-pods": true}
	f.sweep(gone)

	def := graphGet(t, api, "/graph"+k8sQS("root", f.research, "direction", "forward"))
	es := graphEdges(t, digl(def, "data", "edges"))
	if k8sEdgeVia(es, f.research, f.podRule, "research-pods") != nil || len(es) != 2 {
		t.Errorf("default edges = %+v, want the two secrets grants only: ended is hidden", es)
	}
	if fr := digl(def, "data", "frontier"); len(fr) != 0 {
		t.Errorf("default frontier = %v: ended grants are not 'more'", fr)
	}

	all := graphGet(t, api, "/graph"+k8sQS("root", f.research, "direction", "forward", "include_ended", "true"))
	contractCheck(t, "GET /graph include_ended (k8s)", all, contractK8sGraph)
	es = graphEdges(t, digl(all, "data", "edges"))
	for _, rule := range []string{f.podRule, f.cmRule} {
		e := k8sEdgeVia(es, f.research, rule, "research-pods")
		if e == nil || e.State != "ended" || digs(e.Raw, "assignment", "kind") != "k8s_role_binding" ||
			digs(e.Raw, "assignment", "namespace") != k8sGraphNS {
			t.Errorf("include_ended: grant to %s via research-pods = %+v, want it, ended, with its binding", rule, e)
		}
	}
	// The ended binding's expansion carries the filter.
	ex := graphGet(t, api, "/graph/expand"+k8sQS("node", f.research, "edge", "grant", "direction", "forward", "include_ended", "true"))
	if n := len(digl(ex, "data", "edges")); n != 4 {
		t.Errorf("expand include_ended = %d grants, want 4", n)
	}

	// The next sweep fails a LIST (incomplete) and does not mention the
	// ClusterRoleBinding. That proves nothing: the binding is STALE, still
	// drawn by default, and says which reading left it unconfirmed.
	broken := k8sFullWorld()
	broken.complete = false
	broken.drop = map[string]bool{"research-pods": true, "research-reads-secrets": true}
	f.sweep(broken)

	body := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward"))
	contractCheck(t, "GET /graph stale (k8s)", body, contractK8sGraph)
	es = graphEdges(t, digl(body, "data", "edges"))
	crb := k8sEdgeVia(es, f.research, f.secretRule, "research-reads-secrets")
	if crb == nil || crb.State != "stale" {
		t.Fatalf("CRB grant = %+v, want it drawn, stale -- stale is not ended", crb)
	}
	rs := digl(crb.Raw, "stale_reason")
	if len(rs) != 1 || digs(rs[0], "account_id") != k8sGraphCluster || digs(rs[0], "surface") != "k8s_sweep" ||
		digs(rs[0], "state") != "incomplete" {
		t.Errorf("stale_reason = %v, want the cluster's incomplete sweep", rs)
	}
	gap := graphLim(crb.Limitations, "k8s_coverage_gap")
	if gap == nil || gap["cluster"] != k8sGraphCluster || gap["namespace"] != nil || gap["state"] != "incomplete" || gap["observed_at"] == nil {
		t.Errorf("CRB limitations = %v, want k8s_coverage_gap incomplete on the cluster-scoped part", crb.Limitations)
	}
	if ns := k8sEdgeVia(es, f.research, f.secretRule, "research-secrets-ns"); ns == nil || ns.State != "current" {
		t.Errorf("the re-read RoleBinding grant = %+v, want current", ns)
	}
	// Every element of this cluster now stands on an incomplete sweep, and
	// says so -- current ones included: absence near them proves nothing.
	for _, n := range digl(body, "data", "nodes") {
		if l := graphLim(digl(n, "limitations"), "k8s_coverage_gap"); l == nil || l["state"] != "incomplete" {
			t.Errorf("%s limitations = %v, want the incomplete sweep", digs(n, "ref"), digl(n, "limitations"))
		}
	}
	// No AWS vocabulary on a Kubernetes element.
	for _, code := range []string{"surface_stale", "surface_partial", "surface_denied", "account_not_connected", "organizations_not_collected"} {
		if graphMentions(t, body, code) || graphHasCode(digl(body, "meta", "limitations"), code) {
			t.Errorf("a Kubernetes graph mentions %s", code)
		}
	}
}

func TestP2K8sGraphCoverageGaps(t *testing.T) {
	k := newK8sGraphLab(t, "p2-k8s-graph-coverage")
	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")
	// Complete, but the agent could not read cluster-scoped objects, and it
	// read only iga-demo -- while a binding there names a ServiceAccount of
	// "other".
	w := k8sFullWorld()
	w.clusterScoped = false
	w.crossNamespace = true
	k.sweep(w)
	f := k.fixture()
	helper := refOf("identity", k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:other:helper"))
	api := f.api()

	body := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward"))
	contractCheck(t, "GET /graph coverage (k8s)", body, contractK8sGraph)
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	gapOf := func(ls []any) map[string]any { return graphLim(ls, "k8s_coverage_gap") }

	// The ClusterRole's rule and the ClusterRoleBinding are the
	// cluster-scoped part, which was not read.
	if g := gapOf(digl(nodes[f.secretRule], "limitations")); g == nil || g["state"] != "namespaced_only" || g["namespace"] != nil {
		t.Errorf("ClusterRole rule limitations = %v, want namespaced_only", digl(nodes[f.secretRule], "limitations"))
	}
	es := graphEdges(t, digl(body, "data", "edges"))
	if e := k8sEdgeVia(es, f.research, f.secretRule, "research-reads-secrets"); e == nil || gapOf(e.Limitations) == nil ||
		gapOf(e.Limitations)["state"] != "namespaced_only" {
		t.Errorf("CRB grant = %+v, want namespaced_only", e)
	}
	// What lives in iga-demo was read: no gap.
	for _, ref := range []string{f.workload, f.research, f.podRule, f.cmRule} {
		if g := gapOf(digl(nodes[ref], "limitations")); g != nil {
			t.Errorf("%s has %v, but iga-demo was read", ref, g)
		}
	}
	if e := k8sEdgeVia(es, f.research, f.secretRule, "research-secrets-ns"); e == nil || gapOf(e.Limitations) != nil {
		t.Errorf("iga-demo RoleBinding grant = %+v, want no gap: the binding's namespace was read", e)
	}
	// A ServiceAccount of a namespace the sweep never read.
	hb := graphGet(t, api, "/graph"+k8sQS("root", helper, "direction", "forward"))
	contractCheck(t, "GET /graph helper (k8s)", hb, contractK8sGraph)
	hn := graphNodes(t, digl(hb, "data", "nodes"))[helper]
	if g := gapOf(digl(hn, "limitations")); g == nil || g["state"] != "namespace_not_swept" || g["namespace"] != "other" ||
		g["cluster"] != k8sGraphCluster {
		t.Errorf("helper SA limitations = %v, want namespace_not_swept in other", digl(hn, "limitations"))
	}
}

// TestP2K8sGraphLeavesAWSUnchanged: one workspace with an AWS publication and
// a Kubernetes cluster. Every AWS traversal answer is identical, byte for
// byte, before and after the cluster's rows arrive; neither provider's walk
// reaches the other's nodes; and a Kubernetes expansion cursor survives a
// new AWS publication.
func TestP2K8sGraphLeavesAWSUnchanged(t *testing.T) {
	k := newK8sGraphLab(t, "p2-k8s-graph-mixed")
	a := graphTeaching(t, k.p2Lab)
	k.scanAndProject(a)
	api := k.api()
	ticket, role := graphWorkload(t, k.p2Lab, "ticket-tools"), graphIdentity(t, k.p2Lab, "SharedToolRole")
	res := graphResource(t, k.p2Lab, "arn:aws:s3:::support-tickets/*")
	awsCalls := []string{
		"/graph" + k8sQS("root", ticket, "direction", "forward"),
		"/graph" + k8sQS("root", role, "direction", "reverse"),
		"/graph" + k8sQS("root", res, "direction", "reverse", "include_ended", "true"),
		"/graph/expand" + k8sQS("node", role, "edge", "grant", "direction", "forward"),
		"/graph/expand" + k8sQS("node", role, "edge", "executes_as", "direction", "reverse"),
		"/graph/path" + k8sQS("from", ticket, "to", res),
	}
	before := map[string]string{}
	for _, p := range awsCalls {
		before[p] = graphRaw(t, graphGet(t, api, p))
	}

	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")
	k.sweep(k8sFullWorld())
	f := k.fixture()

	for _, p := range awsCalls {
		body := graphGet(t, api, p)
		if got := graphRaw(t, body); got != before[p] {
			t.Errorf("GET %s changed after the Kubernetes rows arrived:\nbefore %s\nafter  %s", p, before[p], got)
		}
		for _, ref := range []string{f.workload, f.research, f.secretRule} {
			if graphMentions(t, body, ref) {
				t.Errorf("GET %s reaches the Kubernetes node %s", p, ref)
			}
		}
		if digs(body, "meta", "graph_state") != "published" {
			t.Errorf("GET %s meta = %v", p, body["meta"])
		}
	}

	// The Kubernetes root reads the same snapshot, but neither pins nor
	// reports the AWS publication (D-111): rev and published_at null,
	// graph_state says its rows have none -- and a rev= on it, current or
	// not, is ignored rather than 409.
	kb := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward"))
	contractCheck(t, "GET /graph (k8s beside AWS)", kb, contractK8sGraph)
	awsBody := graphGet(t, api, awsCalls[0])
	if dig(kb, "meta", "rev") != nil || dig(kb, "meta", "published_at") != nil || dig(awsBody, "meta", "rev") == nil ||
		digs(kb, "meta", "graph_state") != "unrevisioned" {
		t.Errorf("k8s meta = %v, want rev and published_at null and graph_state unrevisioned", kb["meta"])
	}
	if graphMentions(t, kb, ticket) || graphMentions(t, kb, role) {
		t.Error("the Kubernetes walk reaches an AWS node")
	}

	// A path between the two providers' nodes runs only through a crossing
	// (D-108), and there is none here: both ends are read, both frontiers
	// are exhausted, none_exists -- a mixed response with the AWS rev.
	for _, p := range []string{
		"/graph/path" + k8sQS("from", ticket, "to", f.secretRule),
		"/graph/path" + k8sQS("from", f.workload, "to", role),
	} {
		code, body := api.get(p)
		mustStatus(t, p, code, body, http.StatusOK)
		if digs(body, "data", "outcome") != "none_exists" || digs(body, "meta", "graph_state") != "mixed" ||
			dig(body, "meta", "rev") != dig(awsBody, "meta", "rev") {
			t.Errorf("GET %s = %v, want none_exists in a mixed response at the AWS rev", p, body)
		}
	}

	// A Kubernetes expansion cursor is unrevisioned: a new AWS publication
	// between its pages does not make it stale (an AWS cursor's does, as
	// p2_graph_expand_test.go proves).
	r := igaread.NewReader(k.db, readTestCursorKey)
	one := graphBudgets(func(b *igaread.GraphBudgets) { b.Neighbours = 1 })
	args := []string{"node", f.research, "edge", "grant", "direction", "forward"}
	code, p1 := graphDirect(t, r, one, k.ws, "/graph/expand", args...)
	mustStatus(t, "k8s page 1", code, p1, 200)
	cursor := digs(p1, "data", "next_cursor")
	if cursor == "" {
		t.Fatalf("page 1 = %v, want a cursor", p1["data"])
	}
	k.scanAndProject(a)
	code, p2 := graphDirect(t, r, one, k.ws, "/graph/expand", append(args, "cursor", cursor)...)
	mustStatus(t, "k8s page 2 after a publication", code, p2, 200)
	if len(digl(p2, "data", "edges")) != 1 {
		t.Errorf("page 2 = %v", p2["data"])
	}

	// A projector defect that wrote an edge ACROSS the providers -- an AWS
	// workload "executing as" the Kubernetes SA, and the Kubernetes workload
	// as the AWS role -- is never walked: every predicate names the
	// traversal's one provider, so neither walk reads the other's node.
	for i, pair := range [][2]string{{ticket, f.research}, {f.workload, role}} {
		if err := k.db.Exec(`INSERT INTO iga_relationship (workspace_id, relationship_type, source_workload_id,
		                         target_identity_account_id, basis, state, source_key)
		                     VALUES (?, 'executes_as', ?, ?, 'declared', 'current', ?)`,
			k.ws, refUUID(t, pair[0]), refUUID(t, pair[1]), "defect-cross-provider-"+graphItoa(int64(i))).Error; err != nil {
			t.Fatalf("plant cross-provider row: %v", err)
		}
	}
	for _, tc := range []struct{ path, foreign string }{
		{"/graph" + k8sQS("root", ticket, "direction", "forward"), f.research},
		{"/graph" + k8sQS("root", role, "direction", "reverse"), f.workload},
		{"/graph" + k8sQS("root", f.research, "direction", "reverse"), ticket},
		{"/graph" + k8sQS("root", f.workload, "direction", "forward"), role},
		{"/graph/expand" + k8sQS("node", f.research, "edge", "executes_as", "direction", "reverse"), ticket},
		{"/graph/expand" + k8sQS("node", role, "edge", "executes_as", "direction", "reverse"), f.workload},
	} {
		body := graphGet(t, api, tc.path)
		if graphMentions(t, body, tc.foreign) {
			t.Errorf("GET %s walks a cross-provider row to %s", tc.path, tc.foreign)
		}
	}

	// D-4 stays AWS's: with no publication (removed here, as no pipeline
	// path does) an AWS root is 404 though its rows remain, and a Kubernetes
	// root -- whose rows were never a publication's -- still answers, rev null.
	for _, table := range []string{"iga_lifecycle_event", "iga_publication"} {
		if err := k.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, k.ws).Error; err != nil {
			t.Fatalf("remove %s: %v", table, err)
		}
	}
	for _, p := range []string{
		"/graph" + k8sQS("root", ticket, "direction", "forward"),
		"/graph/expand" + k8sQS("node", role, "edge", "grant", "direction", "forward"),
		"/graph/path" + k8sQS("from", ticket, "to", res),
	} {
		if code, body := api.get(p); code != http.StatusNotFound {
			t.Errorf("GET %s with no publication = %d %v, want 404 (D-4)", p, code, body)
		}
	}
	nb := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward"))
	if dig(nb, "meta", "rev") != nil || len(digl(nb, "data", "nodes")) != 5 {
		t.Errorf("k8s root with no publication = %v", nb)
	}
}
