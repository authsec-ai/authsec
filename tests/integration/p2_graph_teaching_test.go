package integration

// T6.4, §5.3 Graph and §5.4 over the teaching case (§2.14.11 "The worked
// example"), built end to end by the REAL scan worker and projector:
//
//	ticket-tools ──executes_as──▶ SharedToolRole ══grant══▶ s3:GetObject (TicketRead)  ──target──▶ support-tickets/*
//	refund-tools ──executes_as──┘                 ══grant══▶ s3:GetObject (ToolboxRead) ──target──┘
//
// Forward from the workload and reverse from the resource; two policies
// declaring the same action are two grants and two statement nodes sharing a
// group_key; the same request twice is the same response.

import (
	"sort"
	"testing"
)

func TestP2GraphTeachingPathForward(t *testing.T) {
	l := newP2Lab(t, "p2-graph-teaching-fwd", true)
	l.scanAndProject(graphTeaching(t, l))
	api := l.api()
	ticket := graphWorkload(t, l, "ticket-tools")
	role := graphIdentity(t, l, "SharedToolRole")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward"))
	if digs(body, "data", "root") != ticket {
		t.Fatalf("root = %v, want %s", dig(body, "data", "root"), ticket)
	}
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))

	// The path, and nothing else: refund-tools is NOT reached forward from
	// ticket-tools (it is a second source into the role, found in reverse).
	if len(nodes) != 5 {
		t.Fatalf("nodes = %v, want ticket-tools, SharedToolRole, two statements, the selector", nodes)
	}
	if n := nodes[ticket]; digs(n, "kind") != "workload" || digs(n, "label") != "ticket-tools" ||
		digs(n, "state") != "current" || digs(n, "account", "id") != accountA {
		t.Errorf("workload node = %v", n)
	}
	rn := nodes[role]
	if digs(rn, "kind") != "iam_role" || digs(rn, "label") != "SharedToolRole" ||
		num(rn, "restrictions", "deny_statements") != 0 || dig(rn, "restrictions", "permissions_boundary") != false {
		t.Errorf("role node = %v, want an iam_role with restrictions {deny_statements: 0, permissions_boundary: false}", rn)
	}
	if num(rn, "used_by_count", "value") != 2 || dig(rn, "used_by_count", "exact") != true {
		t.Errorf("role used_by_count = %v, want the list's exact 2 (ticket-tools and refund-tools)", dig(rn, "used_by_count"))
	}
	if n := nodes[res]; digs(n, "kind") != "selector" || digs(n, "label") != "support-tickets/*" ||
		digs(n, "text") != "arn:aws:s3:::support-tickets/*" || dig(n, "account") != nil {
		t.Errorf("resource node = %v, want the selector support-tickets/* with Unknown account (S3 ARNs name none)", n)
	}

	// Two policies, one action: two statement nodes, two grants, ONE
	// group_key (§5.4 "Independent grants").
	stmts := graphRefsOfKind(digl(body, "data", "nodes"), "statement")
	if len(stmts) != 2 {
		t.Fatalf("statement nodes = %v, want two (TicketRead's and ToolboxRead's)", stmts)
	}
	policies := []string{digs(nodes[stmts[0]], "policy"), digs(nodes[stmts[1]], "policy")}
	sort.Strings(policies)
	if policies[0] != "TicketRead" || policies[1] != "ToolboxRead" {
		t.Errorf("statement policies = %v, want TicketRead and ToolboxRead", policies)
	}
	k0, k1 := digs(nodes[stmts[0]], "group_key"), digs(nodes[stmts[1]], "group_key")
	if k0 == "" || k0 != k1 || k0 != "s3:GetObject→"+res {
		t.Errorf("group_keys = %q, %q, want both s3:GetObject→%s", k0, k1, res)
	}
	for _, s := range stmts {
		n := nodes[s]
		if digs(n, "label") != "s3:GetObject" || dig(n, "account") != nil || len(digl(n, "exclusions")) != 0 ||
			dig(n, "exclusions") == nil {
			t.Errorf("statement node = %v, want label s3:GetObject, no account, exclusions []", n)
		}
	}

	byKind := map[string][]graphEdge{}
	for _, e := range edges {
		byKind[e.Kind] = append(byKind[e.Kind], e)
		if e.State != "current" || e.ClosesCycle || e.CrossesAccount {
			t.Errorf("edge %+v: want current, no cycle, no account crossing", e)
		}
	}
	if x := byKind["executes_as"]; len(x) != 1 || x[0].From != ticket || x[0].To != role {
		t.Errorf("executes_as = %+v, want ticket-tools -> SharedToolRole", x)
	}
	if g := byKind["grant"]; len(g) != 2 || g[0].From != role || g[1].From != role || g[0].To == g[1].To {
		t.Errorf("grants = %+v, want two grants from the role, one to each statement", g)
	}
	for _, g := range byKind["grant"] {
		if digs(g.Raw, "policy") == "" || digs(g.Raw, "claim")[:6] != "grant:" {
			t.Errorf("grant %v names no policy", g.Raw)
		}
	}
	if tg := byKind["target"]; len(tg) != 2 || tg[0].To != res || tg[1].To != res || tg[0].Mode != "resource" {
		t.Errorf("targets = %+v, want two mode=resource targets to the selector", tg)
	}
	if len(edges) != 5 {
		t.Errorf("%d edges, want 5 (executes_as, 2 grants, 2 targets)", len(edges))
	}
	// Complete: nothing bound, so nothing is left for a frontier.
	if dig(body, "data", "truncated") != nil || len(digl(body, "data", "frontier")) != 0 {
		t.Errorf("truncated = %v frontier = %v, want null and []", dig(body, "data", "truncated"), dig(body, "data", "frontier"))
	}
	meta := body["meta"].(map[string]any)
	if num(meta, "budgets", "nodes") != 500 || num(meta, "budgets", "edges") != 2000 ||
		num(meta, "budgets", "assume_hops") != 4 || num(meta, "budgets", "timeout_ms") != 3000 || num(meta, "rev") < 1 {
		t.Errorf("meta = %v, want the §5.4 budgets and the revision", meta)
	}
	if !graphHasCode(digl(meta, "limitations"), "effective_access_not_evaluated") ||
		!graphHasCode(digl(meta, "limitations"), "organizations_not_collected") {
		t.Errorf("meta.limitations = %v, want effective_access_not_evaluated and organizations_not_collected once", meta["limitations"])
	}

	// Determinism: the same request is the same response, byte for byte.
	again := graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward"))
	if graphRaw(t, again) != graphRaw(t, body) {
		t.Errorf("two identical requests differ:\n%s\n%s", graphRaw(t, body), graphRaw(t, again))
	}
}

func TestP2GraphTeachingPathReverse(t *testing.T) {
	l := newP2Lab(t, "p2-graph-teaching-rev", true)
	l.scanAndProject(graphTeaching(t, l))
	api := l.api()
	ticket, refund := graphWorkload(t, l, "ticket-tools"), graphWorkload(t, l, "refund-tools")
	role := graphIdentity(t, l, "SharedToolRole")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))
	for _, want := range []string{res, role, ticket, refund} {
		if nodes[want] == nil {
			t.Errorf("reverse from the selector does not reach %s: %v", want, nodes)
		}
	}
	if s := graphRefsOfKind(digl(body, "data", "nodes"), "statement"); len(s) != 2 {
		t.Errorf("statements = %v, want both declaring statements", s)
	}
	// Every edge keeps its OWN direction (from -> to), whichever way it was
	// walked: targets still run statement -> resource.
	for _, e := range graphEdgesOfKind(edges, "target") {
		if e.To != res || nodes[e.From]["kind"] != "statement" {
			t.Errorf("target %+v, want statement -> resource", e)
		}
	}
	if x := graphEdgesOfKind(edges, "executes_as"); len(x) != 2 || x[0].To != role || x[1].To != role {
		t.Errorf("executes_as = %+v, want both workloads -> the role", x)
	}
	// The role's Lambda trust: lambda.amazonaws.com may assume it -- an
	// external principal, reached in reverse, terminal.
	ca := graphEdgesOfKind(edges, "can_assume")
	if len(ca) != 1 || ca[0].To != role || digs(nodes[ca[0].From], "kind") != "external_principal" ||
		digs(nodes[ca[0].From], "label") != "lambda.amazonaws.com" {
		t.Fatalf("can_assume = %+v, want lambda.amazonaws.com -> the role", ca)
	}
	if !graphHasCode(ca[0].Limitations, "caller_permission_not_evaluated") {
		t.Errorf("can_assume limitations = %v, want caller_permission_not_evaluated", ca[0].Limitations)
	}
	if graphFrontier(body, ca[0].From, "can_assume") != nil {
		t.Errorf("an external principal is terminal: no frontier entry, got %v", dig(body, "data", "frontier"))
	}
	if dig(body, "data", "truncated") != nil {
		t.Errorf("truncated = %v, want null", dig(body, "data", "truncated"))
	}

	// §5.4's order: within a level, by (edge kind, target source_key, id).
	// Level 3 reads the role's reverse neighbours: can_assume before
	// executes_as, the workloads by their source key.
	var level3 []graphEdge
	for _, e := range edges {
		if e.Kind == "can_assume" || e.Kind == "executes_as" {
			level3 = append(level3, e)
		}
	}
	keys := map[string]string{}
	for _, w := range []string{ticket, refund} {
		var k string
		l.db.Raw(`SELECT source_key FROM iga_workload WHERE id = ?`, refUUID(t, w)).Row().Scan(&k)
		keys[w] = k
	}
	if len(level3) != 3 || level3[0].Kind != "can_assume" || keys[level3[1].From] > keys[level3[2].From] {
		t.Errorf("level order = %+v, want can_assume then executes_as by workload source_key", level3)
	}
}
