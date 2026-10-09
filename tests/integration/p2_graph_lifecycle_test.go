package integration

// T6.4 lifecycle and restrictions through membership, over the REAL pipeline:
//
//   - Default current and stale; ended only with include_ended=true (§5.4,
//     D-12), on /graph and /graph/expand alike.
//   - A stale edge is traversed and MARKED (§5.4 "still believed"): its
//     stale_reason names the surface its partition's run did not reach (D-74)
//     and its limitations carry the matching surface_* (D-35).
//   - user -> member_of -> group -> grant: the group's Deny statements count
//     against its members, a member's boundary is on the member, and a path
//     through them carries both (§5.4, D-22).

import (
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/authsec-ai/authsec/internal/igaread"
)

func TestP2GraphEndedEdgesOnlyWhenAsked(t *testing.T) {
	l := newP2Lab(t, "p2-graph-ended", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	a.detach("SharedToolRole", a.policyARN("ToolboxRead"))
	l.scanAndProject(a)
	if g := grantsOf(l.grants(), "ToolboxRead"); len(g) != 1 || g[0].State != "ended" {
		t.Fatalf("setup: ToolboxRead grants = %+v, want one, ended", g)
	}
	api := l.api()
	role := graphIdentity(t, l, "SharedToolRole")

	body := graphGet(t, api, "/graph"+qs("root", role, "direction", "forward"))
	grants := graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant")
	if len(grants) != 1 || grants[0].State != "current" || digs(grants[0].Raw, "policy") != "TicketRead" {
		t.Errorf("default grants = %+v, want only TicketRead's, current", grants)
	}
	if n := len(graphRefsOfKind(digl(body, "data", "nodes"), "statement")); n != 1 {
		t.Errorf("default statements = %d, want 1: the ended grant is not walked", n)
	}
	if len(digl(body, "data", "frontier")) != 0 {
		t.Errorf("default frontier = %v: an ended grant is not a hidden neighbour", dig(body, "data", "frontier"))
	}

	body = graphGet(t, api, "/graph"+qs("root", role, "direction", "forward", "include_ended", "true"))
	states := map[string]string{}
	for _, g := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant") {
		states[digs(g.Raw, "policy")] = g.State
	}
	if states["TicketRead"] != "current" || states["ToolboxRead"] != "ended" || len(states) != 2 {
		t.Errorf("include_ended grants = %v, want TicketRead current and ToolboxRead ended", states)
	}

	// /graph/expand agrees, both ways.
	if n := len(digl(graphGet(t, api, "/graph/expand"+qs("node", role, "edge", "grant", "direction", "forward")), "data", "edges")); n != 1 {
		t.Errorf("expand grants = %d, want 1", n)
	}
	exp := graphGet(t, api, "/graph/expand"+qs("node", role, "edge", "grant", "direction", "forward", "include_ended", "true"))
	if n := len(digl(exp, "data", "edges")); n != 2 {
		t.Errorf("expand grants with include_ended = %d, want 2", n)
	}
	// A frontier built under include_ended expands under it too.
	for _, f := range digl(exp, "data", "frontier") {
		if s := digs(f, "expand"); s[len(s)-len("&include_ended=true"):] != "&include_ended=true" {
			t.Errorf("frontier expand %q drops include_ended", s)
		}
	}

	// Reverse -- "what reaches this" -- applies the same filter to the same
	// claim read from its other end. ToolboxRead's statement is still active
	// (a detached customer-managed policy keeps its statements, §2.15), so
	// reverse from the selector reaches it; its only grant is ended, so by
	// default the walk stops there.
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")
	toolbox := graphStatementOf(t, l, "ToolboxRead")
	body = graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse"))
	if graphNodes(t, digl(body, "data", "nodes"))[toolbox] == nil {
		t.Fatalf("setup: reverse from the selector does not reach ToolboxRead's active statement: %v", body["data"])
	}
	for _, g := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant") {
		if g.To == toolbox || g.State == "ended" {
			t.Errorf("reverse default: grant %+v -- the ended grant is walked back to its holder", g)
		}
	}
	body = graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse", "include_ended", "true"))
	var ended []graphEdge
	for _, g := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant") {
		if g.To == toolbox {
			ended = append(ended, g)
		}
	}
	if len(ended) != 1 || ended[0].State != "ended" || ended[0].From != role {
		t.Errorf("reverse include_ended: ToolboxRead grants = %+v, want the role's, ended", ended)
	}
	if n := len(digl(graphGet(t, api, "/graph/expand"+qs("node", toolbox, "edge", "grant", "direction", "reverse")), "data", "edges")); n != 0 {
		t.Errorf("reverse expand of ToolboxRead's holders = %d edges, want 0 (its grant is ended)", n)
	}
	exp = graphGet(t, api, "/graph/expand"+qs("node", toolbox, "edge", "grant", "direction", "reverse", "include_ended", "true"))
	if es := graphEdges(t, digl(exp, "data", "edges")); len(es) != 1 || es[0].State != "ended" || es[0].From != role {
		t.Errorf("reverse expand include_ended = %+v, want the role's ended grant", es)
	}

	// The frontier's count is taken under the SAME filter as the walk, so an
	// ended edge is never a hidden neighbour: make the edge budget bind next
	// to it, so the count is taken. Forward from ticket-tools the one edge is
	// executes_as and the role's grants are cut: one is hidden, not two.
	r := igaread.NewReader(l.db, readTestCursorKey)
	ticket := graphWorkload(t, l, "ticket-tools")
	one := graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 1 })
	for _, tc := range []struct {
		ended string
		want  int64
	}{{"false", 1}, {"true", 2}} {
		code, fb := graphDirect(t, r, one, l.ws, "/graph", "root", ticket, "direction", "forward", "include_ended", tc.ended)
		mustStatus(t, "edges=1", code, fb, 200)
		if f := graphFrontier(fb, role, "grant"); f == nil || num(f, "more", "count") != tc.want || dig(f, "more", "exact") != true {
			t.Errorf("include_ended=%s: role grant frontier = %v, want {count %d, exact}", tc.ended, f, tc.want)
		}
	}
	// And in reverse: from the selector, the two targets fill a budget of
	// two, and both statements' holders are cut. TicketRead's has one
	// hidden grant; ToolboxRead's has none by default -- no frontier entry --
	// and one, ended, with include_ended.
	two := graphBudgets(func(b *igaread.GraphBudgets) { b.Edges = 2 })
	ticketStmt := graphStatementOf(t, l, "TicketRead")
	code, fb := graphDirect(t, r, two, l.ws, "/graph", "root", res, "direction", "reverse")
	mustStatus(t, "reverse edges=2", code, fb, 200)
	if f := graphFrontier(fb, ticketStmt, "grant"); f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true {
		t.Errorf("reverse: TicketRead holders frontier = %v, want {count 1, exact}", f)
	}
	if f := graphFrontier(fb, toolbox, "grant"); f != nil {
		t.Errorf("reverse: ToolboxRead holders frontier = %v, want none -- its only grant is ended", f)
	}
	code, fb = graphDirect(t, r, two, l.ws, "/graph", "root", res, "direction", "reverse", "include_ended", "true")
	mustStatus(t, "reverse edges=2 include_ended", code, fb, 200)
	if f := graphFrontier(fb, toolbox, "grant"); f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true {
		t.Errorf("reverse include_ended: ToolboxRead holders frontier = %v, want {count 1, exact}", f)
	}
}

// A retired statement's targets are ended (§5.4: a target is filtered by its
// STATEMENT's lifecycle, D-12). ToolboxRead's document changes: its Sid-less
// statement is keyed by content, so the old one retires and a new one is
// declared. By default neither direction reaches the retired statement's
// target; include_ended shows it, ended.
func TestP2GraphRetiredStatementOnlyWhenAsked(t *testing.T) {
	l := newP2Lab(t, "p2-graph-retired", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	old := graphStatementOf(t, l, "ToolboxRead")
	a.managed("ToolboxRead", s3aDoc("", "s3:PutObject", "arn:aws:s3:::support-tickets/*"))
	l.scanAndProject(a)
	var lifecycle string
	l.db.Raw(`SELECT lifecycle FROM iga_entitlements WHERE id = ?`, refUUID(t, old)).Row().Scan(&lifecycle)
	fresh := graphStatementOf(t, l, "ToolboxRead")
	if lifecycle != "retired" || fresh == old {
		t.Fatalf("setup: the old ToolboxRead statement is %q (new %s), want retired and replaced", lifecycle, fresh)
	}
	api := l.api()
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	if nodes[old] != nil || graphMentions(t, body, old) {
		t.Errorf("reverse default reaches the retired statement %s: %v", old, body["data"])
	}
	if nodes[fresh] == nil {
		t.Errorf("reverse default does not reach the new ToolboxRead statement: %v", body["data"])
	}
	body = graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse", "include_ended", "true"))
	var target *graphEdge
	for _, e := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "target") {
		if e.From == old {
			e := e
			target = &e
		}
	}
	if target == nil || target.State != "ended" || target.To != res {
		t.Errorf("reverse include_ended: the retired statement's target = %+v, want it, ended", target)
	}
	if digs(graphNodes(t, digl(body, "data", "nodes"))[old], "lifecycle") != "retired" {
		t.Errorf("the retired statement node does not say so: %v", graphNodes(t, digl(body, "data", "nodes"))[old])
	}

	// Forward from the retired statement: the same filter, the other end.
	if n := len(digl(graphGet(t, api, "/graph/expand"+qs("node", old, "edge", "target", "direction", "forward")), "data", "edges")); n != 0 {
		t.Errorf("forward expand of a retired statement's targets = %d edges, want 0", n)
	}
	exp := graphGet(t, api, "/graph/expand"+qs("node", old, "edge", "target", "direction", "forward", "include_ended", "true"))
	if es := graphEdges(t, digl(exp, "data", "edges")); len(es) != 1 || es[0].State != "ended" || es[0].To != res {
		t.Errorf("forward expand include_ended = %+v, want the one target, ended", es)
	}
}

func TestP2GraphStaleEdgesAreMarked(t *testing.T) {
	l := newP2Lab(t, "p2-graph-stale", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	api := l.api()
	ticket, role := graphWorkload(t, l, "ticket-tools"), graphIdentity(t, l, "SharedToolRole")

	// Control: while everything is read, nothing is stale and nothing says so.
	before := graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward"))
	for _, e := range graphEdges(t, digl(before, "data", "edges")) {
		if e.State != "current" || dig(e.Raw, "stale_reason") != nil || graphHasCode(e.Limitations, "surface_denied") {
			t.Errorf("before the denial: edge %v, want current with no stale_reason or surface limitation", e.Raw)
		}
	}

	a.iam.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	l.scanAndProject(a)

	body := graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))
	// Still traversed: the whole path is there, marked.
	if len(nodes) != 5 || len(edges) != 5 {
		t.Fatalf("stale graph = %d nodes %d edges, want the whole path (stale is still believed)", len(nodes), len(edges))
	}
	rn := nodes[role]
	if digs(rn, "state") != "stale" || len(digl(rn, "stale_reason")) == 0 ||
		digs(rn, "stale_reason", 0, "surface") != "iam_roles" || digs(rn, "stale_reason", 0, "state") != "denied" {
		t.Errorf("role = %v, want stale with stale_reason iam_roles denied", rn)
	}
	if l := graphLim(digl(rn, "limitations"), "surface_denied"); l == nil || digs(l, "surface") != "iam_roles" ||
		digs(l, "account_id") != accountA {
		t.Errorf("role limitations = %v, want surface_denied iam_roles in %s", digl(rn, "limitations"), accountA)
	}
	for _, kind := range []string{"executes_as", "grant"} {
		for _, e := range graphEdgesOfKind(edges, kind) {
			sr := digl(e.Raw, "stale_reason")
			found := false
			for _, r := range sr {
				if digs(r, "surface") == "iam_roles" && digs(r, "state") == "denied" && digs(r, "account_id") == accountA {
					found = true
				}
			}
			if e.State != "stale" || !found {
				t.Errorf("%s %s = state %s stale_reason %v, want stale naming iam_roles denied", kind, e.Claim, e.State, sr)
			}
			if l := graphLim(e.Limitations, "surface_denied"); l == nil || digs(l, "surface") != "iam_roles" {
				t.Errorf("%s %s limitations = %v, want surface_denied iam_roles", kind, e.Claim, e.Limitations)
			}
		}
	}

	// An external principal has no support rows (D-47): its state is its
	// can_assume edges' (D-1), so a stale principal's stale_reason is theirs
	// (D-74: "a stale row, node or edge carries stale_reason"). The role's
	// trust was not read either, so lambda.amazonaws.com's one edge is stale.
	rev := graphGet(t, api, "/graph"+qs("root", role, "direction", "reverse"))
	var principal map[string]any
	for _, n := range graphNodes(t, digl(rev, "data", "nodes")) {
		if digs(n, "kind") == "external_principal" {
			principal = n
		}
	}
	if principal == nil || digs(principal, "state") != "stale" {
		t.Fatalf("reverse from the role: principal = %v, want lambda.amazonaws.com, stale", principal)
	}
	if sr := digl(principal, "stale_reason"); len(sr) != 1 || digs(sr[0], "surface") != "iam_roles" ||
		digs(sr[0], "state") != "denied" || digs(sr[0], "account_id") != accountA {
		t.Errorf("principal stale_reason = %v, want [iam_roles denied in %s], its stale edge's", sr, accountA)
	}
	if l := graphLim(digl(principal, "limitations"), "surface_denied"); l == nil || digs(l, "surface") != "iam_roles" {
		t.Errorf("principal limitations = %v, want surface_denied iam_roles", digl(principal, "limitations"))
	}
}

// A target has no state of its own: its lifecycle is its statement's (§5.4),
// so a stale statement's targets are stale -- and carry the statement's
// stale_reason (D-74). The customer-managed policy listing is denied, so the
// statements' partition is not reached; the targets keep being traversed,
// marked.
func TestP2GraphStaleTargetsCarryTheirStatementsReason(t *testing.T) {
	l := newP2Lab(t, "p2-graph-stale-target", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	a.iam.fail["GetAccountAuthorizationDetails:LocalManagedPolicy"] = denied("iam:GetAccountAuthorizationDetails")
	l.scanAndProject(a)
	api := l.api()
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	targets := graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "target")
	if len(targets) != 2 {
		t.Fatalf("targets = %+v, want both statements' (stale is still believed)", targets)
	}
	for _, e := range targets {
		st := nodes[e.From]
		want := digl(st, "stale_reason")
		if digs(st, "state") != "stale" || len(want) == 0 {
			t.Fatalf("setup: statement %v, want stale with a stale_reason", st)
		}
		got := digl(e.Raw, "stale_reason")
		if e.State != "stale" || graphRaw(t, map[string]any{"r": got}) != graphRaw(t, map[string]any{"r": want}) {
			t.Errorf("target %s = state %s stale_reason %v, want stale with its statement's %v", e.Claim, e.State, got, want)
		}
		surfaced := false
		for _, l := range e.Limitations {
			if c := digs(l, "code"); len(c) > 8 && c[:8] == "surface_" && digs(l, "surface") == digs(want, 0, "surface") {
				surfaced = true
			}
		}
		if !surfaced {
			t.Errorf("target %s limitations = %v, want the statement's surface_* for %s", e.Claim, e.Limitations, digs(want, 0, "surface"))
		}
	}
}

func TestP2GraphMembershipCarriesRestrictions(t *testing.T) {
	l := newP2Lab(t, "p2-graph-member", true)
	a := l.account(accountA)
	ticketRead := a.managed("TicketRead", docTicketRead)
	noDelete := a.managed("NoDelete", graphDocDenyDelete)
	boundary := a.managed("PriyaBoundary", s3aDoc("Bound", "s3:*", "*"))
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aEditUser(t, a, "priya", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", ticketRead)
	s3aGroupAttach(t, a, "ops", noDelete)
	s3aJoin(a, "priya", "ops")
	// Two more members, for D-22's member rule on the group's grant: sam
	// stays a member but his boundary is removed (the assignment ends); lee
	// keeps her boundary but leaves the group (the membership ends). Neither
	// is a bounded member afterwards: only priya is.
	s3aUser(a, "sam", "AIDASAMSAMSAMSAMSAM1")
	s3aEditUser(t, a, "sam", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a, "sam", "ops")
	s3aUser(a, "lee", "AIDALEELEELEELEELEE1")
	s3aEditUser(t, a, "lee", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a, "lee", "ops")
	l.scanAndProject(a)
	s3aEditUser(t, a, "sam", func(u *iamtypes.User) { u.PermissionsBoundary = nil })
	a.iam.userGroups["lee"] = nil
	l.scanAndProject(a)
	api := l.api()
	priya, ops := graphIdentity(t, l, "priya"), graphIdentity(t, l, "ops")
	sam := graphIdentity(t, l, "sam")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", priya, "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))
	if m := graphEdgesOfKind(edges, "member_of"); len(m) != 1 || m[0].From != priya || m[0].To != ops {
		t.Fatalf("member_of = %+v, want priya -> ops", m)
	}
	grants := graphEdgesOfKind(edges, "grant")
	if len(grants) != 1 || grants[0].From != ops {
		t.Fatalf("grants = %+v, want ops's TicketRead grant (the Deny is not a grant)", grants)
	}
	// D-22: the group-held grant carries permissions_boundary_present with
	// the count and refs of its bounded member users -- priya only: sam's
	// boundary assignment ended, lee's membership ended. The Evidence panel
	// states the same for the same claim (D-35: one function).
	// D-98: /evidence's fields for the code -- member_count and members.
	if l := graphLim(grants[0].Limitations, "permissions_boundary_present"); l == nil || num(l, "member_count") != 1 ||
		len(digl(l, "members")) != 1 || digs(l, "members", 0) != priya || dig(l, "holder") != false {
		t.Errorf("ops grant limitations = %v, want permissions_boundary_present {member_count 1, members [priya]}", grants[0].Limitations)
	}
	if l := graphLim(grants[0].Limitations, "deny_statements_present"); l == nil || num(l, "count") != 1 {
		t.Errorf("ops grant limitations = %v, want the group's own deny_statements_present", grants[0].Limitations)
	}
	// The member rule is the GRANT's: the group node itself has no boundary.
	if graphHasCode(digl(nodes[ops], "limitations"), "permissions_boundary_present") {
		t.Errorf("ops node limitations = %v: the group has no boundary of its own", digl(nodes[ops], "limitations"))
	}
	if nodes[res] == nil || digs(nodes[ops], "kind") != "iam_group" || digs(nodes[priya], "kind") != "iam_user" {
		t.Errorf("nodes = %v, want priya (user) -> ops (group) -> ... -> the selector", nodes)
	}
	// The group's Deny counts against its member; the boundary is priya's.
	if r := nodes[priya]["restrictions"]; num(r, "deny_statements") != 1 || dig(r, "permissions_boundary") != true {
		t.Errorf("priya restrictions = %v, want {deny_statements: 1 (through ops), permissions_boundary: true}", r)
	}
	if r := nodes[ops]["restrictions"]; num(r, "deny_statements") != 1 || dig(r, "permissions_boundary") != false {
		t.Errorf("ops restrictions = %v, want {deny_statements: 1, permissions_boundary: false}", r)
	}

	// The path carries the union of its steps: the group's Deny and priya's
	// boundary -- the grant reaches priya only through restricted nodes.
	p := graphGet(t, api, "/graph/path"+qs("from", priya, "to", res))
	if digs(p, "data", "outcome") != "found" || len(digl(p, "data", "paths")) != 1 {
		t.Fatalf("path priya -> selector = %v, want one path", p["data"])
	}
	lims := digl(p, "data", "paths", 0, "limitations")
	if !graphHasCode(lims, "deny_statements_present") || !graphHasCode(lims, "permissions_boundary_present") {
		t.Errorf("path limitations = %v, want deny_statements_present and permissions_boundary_present", graphCodes(lims))
	}
	steps := digl(p, "data", "paths", 0, "edges")
	if len(steps) != 3 || digs(steps[0], "kind") != "member_of" || digs(steps[1], "kind") != "grant" || digs(steps[2], "kind") != "target" {
		t.Errorf("path steps = %v, want member_of, grant, target", steps)
	}

	// Reverse from the group: its members -- priya and sam; lee left.
	rev := graphGet(t, api, "/graph"+qs("root", ops, "direction", "reverse"))
	from := map[string]bool{}
	for _, m := range graphEdgesOfKind(graphEdges(t, digl(rev, "data", "edges")), "member_of") {
		from[m.From] = true
	}
	if len(from) != 2 || !from[priya] || !from[sam] {
		t.Errorf("reverse from ops = %v, want its members priya and sam", rev["data"])
	}
}
