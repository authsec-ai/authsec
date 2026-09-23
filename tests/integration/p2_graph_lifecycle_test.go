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
	l.scanAndProject(a)
	api := l.api()
	priya, ops := graphIdentity(t, l, "priya"), graphIdentity(t, l, "ops")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")

	body := graphGet(t, api, "/graph"+qs("root", priya, "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	edges := graphEdges(t, digl(body, "data", "edges"))
	if m := graphEdgesOfKind(edges, "member_of"); len(m) != 1 || m[0].From != priya || m[0].To != ops {
		t.Fatalf("member_of = %+v, want priya -> ops", m)
	}
	if g := graphEdgesOfKind(edges, "grant"); len(g) != 1 || g[0].From != ops {
		t.Errorf("grants = %+v, want ops's TicketRead grant (the Deny is not a grant)", g)
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

	// Reverse from the group: its members.
	rev := graphGet(t, api, "/graph"+qs("root", ops, "direction", "reverse"))
	if m := graphEdgesOfKind(graphEdges(t, digl(rev, "data", "edges")), "member_of"); len(m) != 1 || m[0].From != priya {
		t.Errorf("reverse from ops = %v, want its member priya", rev["data"])
	}
}
