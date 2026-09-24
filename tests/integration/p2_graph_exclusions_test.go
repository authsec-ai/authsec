package integration

// T6.4: what is NOT an edge (§5.4), over graphs the REAL pipeline built.
//
//   - A NotResource entry is an exclusion ("every resource except these"): no
//     traversal edge or path to the excluded resource in either direction; it
//     is returned on its statement node as `exclusions` (B19).
//   - Deny statements and boundaries are restrictions on identity nodes, and
//     limitations on the grants those identities hold -- never edges, never a
//     node a path runs through.
//   - Two statements with the same actions and targets share a group_key only
//     when nothing else differs: a Condition makes them two keys (D-37).

import (
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
)

const (
	graphDocAllButFinance = `{"Version":"2012-10-17","Statement":[{` +
		`"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}]}`
	graphDocDenyDelete = `{"Version":"2012-10-17","Statement":[{"Sid":"NoDelete","Effect":"Deny",` +
		`"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`
	graphDocTicketReadTagged = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTaggedTickets","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalTag/team":"support"}}}]}`
)

// B19 and the mutation check of the target mode: NotResource never becomes an
// edge, a frontier entry or a path step.
func TestP2GraphNotResourceIsNeverAnEdge(t *testing.T) {
	l := newP2Lab(t, "p2-graph-notresource", true)
	a := l.account(accountA)
	role := a.role("ArchiveRole", "AROAARCHIVEROLE00001")
	a.attach("ArchiveRole", a.managed("AllButFinance", graphDocAllButFinance))
	listsFunctions(a, "us-east-1", "archiver", role)
	l.scanAndProject(a)
	api := l.api()
	wl := graphWorkload(t, l, "archiver")
	finance := graphResource(t, l, "arn:aws:s3:::finance/*")
	star := graphResource(t, l, "*")

	fwd := graphGet(t, api, "/graph"+qs("root", wl, "direction", "forward"))
	nodes := graphNodes(t, digl(fwd, "data", "nodes"))
	edges := graphEdges(t, digl(fwd, "data", "edges"))
	if nodes[finance] != nil {
		t.Errorf("the excluded resource is a node of the forward graph: %v", nodes[finance])
	}
	for _, e := range edges {
		if e.From == finance || e.To == finance {
			t.Errorf("edge %+v touches the excluded resource", e)
		}
	}
	tg := graphEdgesOfKind(edges, "target")
	if len(tg) != 1 || tg[0].To != star || tg[0].Mode != "resource" {
		t.Fatalf("targets = %+v, want ONE positive target, to the implicit * selector", tg)
	}
	stmt := nodes[tg[0].From]
	ex := digl(stmt, "exclusions")
	if len(ex) != 1 || digs(ex[0], "ref") != finance || digs(ex[0], "text") != "arn:aws:s3:::finance/*" {
		t.Errorf("statement exclusions = %v, want [{ref: %s, text: arn:aws:s3:::finance/*}]", ex, finance)
	}
	if !graphHasCode(digl(stmt, "limitations"), "negated_statement") {
		t.Errorf("NotResource statement limitations = %v, want negated_statement", digl(stmt, "limitations"))
	}
	if g := graphEdgesOfKind(edges, "grant"); len(g) != 1 || !graphHasCode(g[0].Limitations, "negated_statement") {
		t.Errorf("grant = %+v, want its statement's negated_statement on it", g)
	}
	if k := digs(stmt, "group_key"); k == "" || k == "s3:*→"+star {
		t.Errorf("group_key = %q: the exclusion must be in the key, or this statement would group with a plain s3:* on *", k)
	}

	// Reverse from the excluded resource: it is reached by nothing.
	rev := graphGet(t, api, "/graph"+qs("root", finance, "direction", "reverse"))
	if n := len(digl(rev, "data", "nodes")); n != 1 || len(digl(rev, "data", "edges")) != 0 ||
		len(digl(rev, "data", "frontier")) != 0 || dig(rev, "data", "truncated") != nil {
		t.Errorf("reverse from the excluded resource = %v, want only the root, no edges, no frontier, not truncated", rev["data"])
	}
	// Its expansion is empty too: the exclusion is not a hidden neighbour.
	exp := graphGet(t, api, "/graph/expand"+qs("node", finance, "edge", "target", "direction", "reverse"))
	if len(digl(exp, "data", "edges")) != 0 || dig(exp, "data", "next_cursor") != nil {
		t.Errorf("expanding the excluded resource = %v, want nothing", exp["data"])
	}

	// No declared path to it, and the search FINISHED: none_exists.
	p := graphGet(t, api, "/graph/path"+qs("from", wl, "to", finance))
	if digs(p, "data", "outcome") != "none_exists" || len(digl(p, "data", "paths")) != 0 ||
		dig(p, "data", "bound_by") != nil {
		t.Errorf("path to the excluded resource = %v, want none_exists", p["data"])
	}
	// Control: the path to * exists.
	p = graphGet(t, api, "/graph/path"+qs("from", wl, "to", star))
	if digs(p, "data", "outcome") != "found" || len(digl(p, "data", "paths")) != 1 ||
		!graphHasCode(digl(p, "data", "paths", 0, "limitations"), "negated_statement") {
		t.Errorf("path to * = %v, want found, one path carrying negated_statement", p["data"])
	}
}

// Deny statements are restrictions, never edges; a boundary likewise. The
// holder's restrictions are on its node and on every grant it holds.
func TestP2GraphDenyAndBoundaryAreRestrictions(t *testing.T) {
	l := newP2Lab(t, "p2-graph-deny", true)
	a := graphTeaching(t, l)
	a.attach("SharedToolRole", a.managed("NoDelete", graphDocDenyDelete))
	boundary := a.managed("ToolBoundary", s3aDoc("Bound", "s3:*", "*"))
	s3aEditRole(t, a, "SharedToolRole", func(r *iamtypes.Role) { r.PermissionsBoundary = s3aBoundary(boundary) })
	l.scanAndProject(a)
	api := l.api()
	role := graphIdentity(t, l, "SharedToolRole")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")
	var deny uuid.UUID
	l.db.Raw(`SELECT e.id FROM iga_entitlements e WHERE e.workspace_id = ? AND e.effect = 'deny'`, l.ws).Row().Scan(&deny)
	if deny == uuid.Nil {
		t.Fatal("setup: the Deny statement was not projected")
	}
	denyRef := refOf("statement", deny)

	body := graphGet(t, api, "/graph"+qs("root", role, "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	rn := nodes[role]
	if num(rn, "restrictions", "deny_statements") != 1 || dig(rn, "restrictions", "permissions_boundary") != true {
		t.Errorf("role restrictions = %v, want {deny_statements: 1, permissions_boundary: true}", dig(rn, "restrictions"))
	}
	// D-98: the SAME fields /evidence gives the code -- count, statements,
	// truncated.
	d := graphLim(digl(rn, "limitations"), "deny_statements_present")
	if d == nil || num(d, "count") != 1 || len(digl(d, "statements")) != 1 || digs(d, "statements", 0) != denyRef {
		t.Errorf("role deny_statements_present = %v, want count 1 and the Deny statement's ref", d)
	}
	if !graphHasCode(digl(rn, "limitations"), "permissions_boundary_present") {
		t.Errorf("role limitations = %v, want permissions_boundary_present", digl(rn, "limitations"))
	}
	if nodes[denyRef] != nil {
		t.Errorf("the Deny statement is a node of the forward graph: %v", nodes[denyRef])
	}
	grants := graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant")
	// The boundary policy is a boundary assignment, never a grant; the Deny
	// is never a grant: only the two Allow statements are.
	if len(grants) != 2 {
		t.Fatalf("grants = %+v, want exactly TicketRead's and ToolboxRead's", grants)
	}
	for _, g := range grants {
		if !graphHasCode(g.Limitations, "deny_statements_present") || !graphHasCode(g.Limitations, "permissions_boundary_present") {
			t.Errorf("grant %s limitations = %v, want the holder's deny and boundary", g.Claim, graphCodes(g.Limitations))
		}
	}

	// Reverse from the resource the Deny names: the Deny statement is not a
	// node (it names the resource, and restricts; it reaches nothing).
	// (It is still NAMED -- as a restriction ref on the role that holds it.)
	rev := graphGet(t, api, "/graph"+qs("root", res, "direction", "reverse"))
	if graphNodes(t, digl(rev, "data", "nodes"))[denyRef] != nil {
		t.Errorf("reverse from the resource reaches the Deny statement as a node")
	}
	for _, e := range graphEdges(t, digl(rev, "data", "edges")) {
		if e.From == denyRef || e.To == denyRef {
			t.Errorf("reverse from the resource has edge %+v through the Deny statement", e)
		}
	}
	if len(graphRefsOfKind(digl(rev, "data", "nodes"), "statement")) != 2 {
		t.Errorf("reverse statements = %v, want only the two Allow statements", graphRefsOfKind(digl(rev, "data", "nodes"), "statement"))
	}
	// A Deny statement is a legal root, and reaches nothing.
	dr := graphGet(t, api, "/graph"+qs("root", denyRef, "direction", "forward"))
	if len(digl(dr, "data", "edges")) != 0 || digs(dr, "data", "nodes", 0, "effect") != "deny" {
		t.Errorf("forward from the Deny statement = %v, want the node alone, effect deny", dr["data"])
	}

	// Rule 7 at read time: a grant row pointing at a Deny statement is a
	// projector defect the fakes cannot produce, so it is inserted directly
	// -- and the read side must not surface it as access.
	var sample uuid.UUID
	l.db.Raw(`SELECT id FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`, l.ws).Row().Scan(&sample)
	if err := l.db.Exec(`INSERT INTO iga_access_edges (workspace_id, subject_kind, subject_id, entitlement_id, direction,
	        subject_identity_account_id, provider, basis, state, last_confirmed_by, source_key, partition_key, connector_id, assignment_id)
	    SELECT workspace_id, subject_kind, subject_id, ?, direction, subject_identity_account_id, provider, basis, state,
	           last_confirmed_by, source_key || '|deny-probe', partition_key, connector_id, assignment_id
	      FROM iga_access_edges WHERE id = ?`, deny, sample).Error; err != nil {
		t.Fatalf("insert the defective grant: %v", err)
	}
	for _, e := range graphEdges(t, digl(graphGet(t, api, "/graph"+qs("root", role, "direction", "forward")), "data", "edges")) {
		if e.To == denyRef {
			t.Errorf("forward from the role surfaces the Deny statement through grant %s", e.Claim)
		}
	}
	if b := graphGet(t, api, "/graph"+qs("root", denyRef, "direction", "reverse")); len(digl(b, "data", "edges")) != 0 {
		t.Errorf("reverse from the Deny statement = %v, want no grant edge to its holder", b["data"])
	}
	if b := graphGet(t, api, "/graph/expand"+qs("node", role, "edge", "grant", "direction", "forward")); len(digl(b, "data", "edges")) != 2 {
		t.Errorf("expanding the role's grants = %v, want the two Allow grants only", b["data"])
	}
}

// D-37: two statements with the same action and target but one Condition are
// two group keys; the condition is a limitation with its keys listed.
func TestP2GraphConditionSplitsGroupKey(t *testing.T) {
	l := newP2Lab(t, "p2-graph-groupkey", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	a.attach("SharedToolRole", a.managed("TicketReadTagged", graphDocTicketReadTagged))
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	l.scanAndProject(a)
	body := graphGet(t, l.api(), "/graph"+qs("root", graphIdentity(t, l, "SharedToolRole"), "direction", "forward"))
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	stmts := graphRefsOfKind(digl(body, "data", "nodes"), "statement")
	if len(stmts) != 2 {
		t.Fatalf("statements = %v, want two", stmts)
	}
	byPolicy := map[string]map[string]any{}
	for _, s := range stmts {
		byPolicy[digs(nodes[s], "policy")] = nodes[s]
	}
	plain, tagged := byPolicy["TicketRead"], byPolicy["TicketReadTagged"]
	if plain == nil || tagged == nil {
		t.Fatalf("statements by policy = %v", byPolicy)
	}
	if digs(plain, "group_key") == digs(tagged, "group_key") {
		t.Errorf("group_key %q shared by an unconditional and a conditional statement: the canvas would merge two claims", digs(plain, "group_key"))
	}
	c := graphLim(digl(tagged, "limitations"), "conditions_not_evaluated")
	if c == nil || len(digl(c, "keys")) != 1 || digs(c, "keys", 0) != "aws:PrincipalTag/team" {
		t.Errorf("conditional statement limitations = %v, want conditions_not_evaluated with its key", digl(tagged, "limitations"))
	}
	if graphHasCode(digl(plain, "limitations"), "conditions_not_evaluated") {
		t.Errorf("unconditional statement carries conditions_not_evaluated: %v", digl(plain, "limitations"))
	}
}
