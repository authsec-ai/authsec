package integration

// T6.4 /graph/expand (§5.3, D-35, D-62): one node's next neighbours of one
// kind, one step, a page at a time with a signed cursor bound to the node, the
// edge kind, the direction and the filters -- and its frontier names the new
// neighbours' own unexpanded neighbours, counted exactly.

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/internal/igaread"
)

func TestP2GraphExpandPagesAndCursor(t *testing.T) {
	l := newP2Lab(t, "p2-graph-expand", true)
	// Both labs exist before either scans: each empties cloud_scan_run when it
	// is created, and this cleanup (registered last, so run first) removes
	// both workspaces' graph rows before either lab clears the run table.
	other := newP2Lab(t, "p2-graph-expand-other", true)
	t.Cleanup(func() { other.cleanup(); l.cleanup() })
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	r := igaread.NewReader(l.db, readTestCursorKey)
	one := graphBudgets(func(b *igaread.GraphBudgets) { b.Neighbours = 1 })
	role := graphIdentity(t, l, "SharedToolRole")
	ticket, refund := graphWorkload(t, l, "ticket-tools"), graphWorkload(t, l, "refund-tools")

	args := []string{"node", role, "edge", "executes_as", "direction", "reverse"}
	code, p1 := graphDirect(t, r, one, l.ws, "/graph/expand", args...)
	mustStatus(t, "page 1", code, p1, 200)
	e1 := graphEdges(t, digl(p1, "data", "edges"))
	cursor := digs(p1, "data", "next_cursor")
	if len(e1) != 1 || cursor == "" || dig(p1, "data", "truncated") != nil {
		t.Fatalf("page 1 = %v, want one neighbour and a cursor (paging is not truncation)", p1["data"])
	}
	code, p2 := graphDirect(t, r, one, l.ws, "/graph/expand", append(args, "cursor", cursor)...)
	mustStatus(t, "page 2", code, p2, 200)
	e2 := graphEdges(t, digl(p2, "data", "edges"))
	if len(e2) != 1 || dig(p2, "data", "next_cursor") != nil {
		t.Fatalf("page 2 = %v, want the other neighbour and no cursor", p2["data"])
	}
	got := map[string]bool{e1[0].From: true, e2[0].From: true}
	if !got[ticket] || !got[refund] || e1[0].To != role {
		t.Errorf("pages = %+v / %+v, want ticket-tools and refund-tools -> the role, once each", e1, e2)
	}
	// Page order is §5.4's: by the neighbour's source key.
	var k1, k2 string
	l.db.Raw(`SELECT source_key FROM iga_workload WHERE id = ?`, refUUID(t, e1[0].From)).Row().Scan(&k1)
	l.db.Raw(`SELECT source_key FROM iga_workload WHERE id = ?`, refUUID(t, e2[0].From)).Row().Scan(&k2)
	if k1 >= k2 {
		t.Errorf("page order %q then %q, want ascending source_key", k1, k2)
	}
	// Each page's nodes are its neighbours.
	if n := digl(p1, "data", "nodes"); len(n) != 1 || digs(n[0], "ref") != e1[0].From {
		t.Errorf("page 1 nodes = %v, want the neighbour", n)
	}

	// The cursor is bound to what produced it (§5.1, D-62).
	for name, kv := range map[string][]string{
		"another node":      {"node", ticket, "edge", "executes_as", "direction", "forward", "cursor", cursor},
		"another direction": {"node", role, "edge", "can_assume", "direction", "forward", "cursor", cursor},
		"another kind":      {"node", role, "edge", "can_assume", "direction", "reverse", "cursor", cursor},
		"another filter":    append(append([]string{}, args...), "include_ended", "true", "cursor", cursor),
		"tampered":          append(append([]string{}, args...), "cursor", egatesForgeCursor(cursor)),
	} {
		code, body := graphDirect(t, r, one, l.ws, "/graph/expand", kv...)
		if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
			t.Errorf("%s: %d %v, want 400 cursor_invalid", name, code, body)
		}
	}
	// A cursor from another workspace's request is cursor_invalid too.
	code, body := graphDirect(t, r, one, other.ws, "/graph/expand", append(args, "cursor", cursor)...)
	if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
		t.Errorf("another workspace's cursor: %d %v, want 400 cursor_invalid", code, body)
	}
	// A newer publication makes the cursor's revision stale: 409.
	l.scanAndProject(a)
	code, body = graphDirect(t, r, one, l.ws, "/graph/expand", append(args, "cursor", cursor)...)
	if code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("cursor after a new publication: %d %v, want 409 revision_stale", code, body)
	}
}

// An expansion's frontier: the new neighbours' own unexpanded neighbours, in
// the same direction, counted exactly -- so the canvas can show "+1" on each.
func TestP2GraphExpandFrontierCounts(t *testing.T) {
	l := newP2Lab(t, "p2-graph-expand-frontier", true)
	l.scanAndProject(graphTeaching(t, l))
	api := l.api()
	role := graphIdentity(t, l, "SharedToolRole")
	body := graphGet(t, api, "/graph/expand"+qs("node", role, "edge", "grant", "direction", "forward"))
	stmts := graphRefsOfKind(digl(body, "data", "nodes"), "statement")
	if len(stmts) != 2 || len(digl(body, "data", "edges")) != 2 || dig(body, "data", "next_cursor") != nil {
		t.Fatalf("expand grants = %v, want both statements on one page", body["data"])
	}
	for _, s := range stmts {
		f := graphFrontier(body, s, "target")
		if f == nil || num(f, "more", "count") != 1 || dig(f, "more", "exact") != true ||
			digs(f, "expand") != "/api/iga/v1/graph/expand?node="+s+"&edge=target&direction=forward" {
			t.Errorf("statement %s frontier = %v, want target {count 1, exact} with its expand call", s, f)
		}
	}
	// An edge kind the node type does not have, in that direction, is 400.
	for name, kv := range map[string][]string{
		"workload has no grants":     {"node", graphWorkload(t, l, "ticket-tools"), "edge", "grant", "direction", "forward"},
		"resource is terminal":       {"node", graphResource(t, l, "arn:aws:s3:::support-tickets/*"), "edge", "target", "direction", "forward"},
		"unknown kind":               {"node", role, "edge", "owns", "direction", "forward"},
		"no kind":                    {"node", role, "direction", "forward"},
		"no direction":               {"node", role, "edge", "grant"},
		"exclusion is not a kind":    {"node", role, "edge", "not_resource", "direction", "forward"},
		"assume_hops does not apply": {"node", role, "edge", "grant", "direction", "forward", "assume_hops", "1"},
	} {
		if code, b := api.get("/graph/expand" + qs(kv...)); code != 400 || errCode(b) != "invalid_parameter" {
			t.Errorf("%s: %d %v, want 400 invalid_parameter", name, code, b)
		}
	}
}
