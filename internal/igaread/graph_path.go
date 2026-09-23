package igaread

// GET /api/iga/v1/graph/path?from=<ref>&to=<ref> (§5.3 Graph, §5.4
// "/graph/path outcomes"; D-35, D-38): the declared paths between two
// objects, bounded.
//
// A path is a sequence of the traversal graph's edges, each in its own
// direction, from `from` to `to` (§5.4): workload -> executes_as -> role ->
// grant -> statement -> target -> resource, and so on. So the search is a
// bidirectional breadth-first search: forward edges out of `from`, reverse
// edges into `to`, a level at a time on the smaller frontier, every level
// inside its own savepoint -- the same levels /graph runs, under the same node
// and edge budgets and the same time reserve.
//
// It runs until BOTH frontiers are exhausted, a budget binds, or a path is
// known and ONE frontier is exhausted: an exhausted forward frontier has
// expanded everything `from` reaches, and an exhausted reverse one everything
// that reaches `to`, so either way every edge of every path is in hand and
// the path list is complete. The paths are then enumerated from the edges the
// search read, shortest first, at most Paths of them, each with at most
// AssumeHops can_assume steps.
//
// The three outcomes are never merged (§2.14.11 "two forms, never merged"):
//
//	found                    one or more paths, shortest first; more_paths when
//	                         the list is not known to be complete, with the
//	                         budget that stopped it in bound_by
//	none_exists              ONLY when both frontiers were exhausted before any
//	                         budget bound (D-38): no declared path among
//	                         current and stale edges
//	not_found_within_budget  a budget bound first; bound_by names it
//
// One case is neither found nor none: the reverse search reached an external
// principal whose resolution IN FORCE names a node the forward search reached
// (§2.12). The principal is terminal (§5.4) -- its resolution is shown, never
// walked -- so a path through it is neither drawn nor ruled out:
// not_found_within_budget (or more_paths) with bound_by
// "resolution_not_followed", additive to §5.4's vocabulary.
//
// Nothing claims a distance that was not measured: a path's length is the
// path, and no "shortest distance" is reported beside it.

import (
	"context"
	"net/url"

	"github.com/google/uuid"
)

// Path outcomes (§5.4).
const (
	GraphPathFound                = "found"
	GraphPathNoneExists           = "none_exists"
	GraphPathNotFoundWithinBudget = "not_found_within_budget"
)

// graphPathWork bounds the enumeration of simple paths over the edges the
// search read: a dense graph has more simple paths than any response could
// list. When it binds the list is incomplete, and says so (more_paths,
// bound_by: paths).
const graphPathWork = 50000

// GraphPath is one declared path: its nodes in order (from first, to last),
// the edges between them, and the union of their limitations.
type GraphPath struct {
	Nodes       []*GraphNode      `json:"nodes"`
	Edges       []*GraphEdge      `json:"edges"`
	Limitations []GraphLimitation `json:"limitations"`
}

// GraphPathData is /graph/path's data (D-35).
type GraphPathData struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	Outcome   string      `json:"outcome"`
	Paths     []GraphPath `json:"paths"`
	MorePaths bool        `json:"more_paths"`
	BoundBy   *string     `json:"bound_by"`
}

// graphSide is one end of the bidirectional search.
type graphSide struct {
	dir      string
	visited  map[string]bool
	frontier []*GraphNode
}

func (s *graphSide) exhausted() bool { return len(s.frontier) == 0 }

// Path serves GET /graph/path. include_ended is not a parameter here: a path
// is declared among current and stale edges (§5.4, D-12).
func (g *GraphTraversal) Path(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	if perr := graphCheckParams(vals, "from", "to"); perr != nil {
		return nil, perr
	}
	from, perr := graphNodeParam(vals, "from")
	if perr != nil {
		return nil, perr
	}
	to, perr := graphNodeParam(vals, "to")
	if perr != nil {
		return nil, perr
	}
	if from == to {
		return nil, InvalidParameter("to", "to must be a different object from from")
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}

	var out Envelope
	err := g.r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		t, err := newGraphTraversal(q, g.b, g.r.budget, false)
		if err != nil {
			return err
		}
		src, err := t.readRoot(from)
		if err != nil {
			return err
		}
		dst, err := t.readRoot(to)
		if err != nil {
			return err
		}
		if src == nil || dst == nil {
			return NotFound()
		}
		data, err := t.bidirectional(src, dst, g.b)
		if err != nil {
			return err
		}
		out = Envelope{Data: data, Meta: g.meta(q)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// bidirectional is /graph/path's search and verdict.
func (t *graphTraversal) bidirectional(src, dst *GraphNode, b GraphBudgets) (*GraphPathData, error) {
	fwd := &graphSide{dir: GraphForward, visited: map[string]bool{src.Ref: true}, frontier: []*GraphNode{src}}
	rev := &graphSide{dir: GraphReverse, visited: map[string]bool{dst.Ref: true}, frontier: []*GraphNode{dst}}

	var bound string
	found := false
	for {
		if fwd.exhausted() && rev.exhausted() {
			break
		}
		if found && (fwd.exhausted() || rev.exhausted()) {
			break // every edge of every path is in hand
		}
		side := fwd
		switch {
		case fwd.exhausted():
			side = rev
		case rev.exhausted():
			side = fwd
		case len(rev.frontier) < len(fwd.frontier):
			side = rev
		}
		if !t.timeLeft() {
			bound = GraphBoundTime
			break
		}
		// No hop limit while searching: the limit is applied to the paths,
		// so a path with too many can_assume steps is known to exist and
		// reported as bound by assume_hops, never as absent.
		s, ok, err := t.runLevel(side.frontier, side.dir, graphStepOpts{rediscover: true})
		if err != nil {
			return nil, err
		}
		if !ok {
			bound = GraphBoundTime
			break
		}
		t.commit(s)
		var next []*GraphNode
		for _, r := range s.reaches {
			if !side.visited[r.far.Ref] {
				side.visited[r.far.Ref] = true
				next = append(next, r.far)
			}
		}
		side.frontier = next
		if s.bound != "" {
			bound = s.bound
			break
		}
		found = graphReachable(t.edges, src.Ref, dst.Ref)
	}

	edgePaths, overflow, hopBound, workBound := graphEnumeratePaths(t.edges, src.Ref, dst.Ref, b.Paths, b.AssumeHops)
	data := &GraphPathData{From: src.Ref, To: dst.Ref, Paths: []GraphPath{}}
	boundBy := func(s string) {
		if s != "" && data.BoundBy == nil {
			data.BoundBy = &s
		}
	}
	if len(edgePaths) > 0 {
		data.Outcome = GraphPathFound
		for _, ep := range edgePaths {
			data.Paths = append(data.Paths, t.renderPath(src, ep))
		}
		// The list is complete only when the search finished (no budget
		// bound), no path was cut by the hop limit, and every path fit.
		unfollowed := t.unfollowedResolution(fwd, rev)
		data.MorePaths = bound != "" || hopBound || overflow || workBound || unfollowed
		boundBy(bound)
		if hopBound {
			boundBy(GraphBoundAssumeHops)
		}
		if overflow || workBound {
			boundBy(GraphBoundPaths)
		}
		if unfollowed {
			boundBy(GraphBoundResolution)
		}
		return data, nil
	}
	// D-38: none_exists ONLY when both frontiers were exhausted before any
	// budget bound. Anything else is "not found within the limits": the
	// answer is unknown, and must not look like "there is none".
	unfollowed := t.unfollowedResolution(fwd, rev)
	if bound == "" && !hopBound && !workBound && !unfollowed && fwd.exhausted() && rev.exhausted() {
		data.Outcome = GraphPathNoneExists
		return data, nil
	}
	data.Outcome = GraphPathNotFoundWithinBudget
	boundBy(bound)
	if hopBound {
		boundBy(GraphBoundAssumeHops)
	}
	if workBound {
		boundBy(GraphBoundPaths)
	}
	if unfollowed {
		boundBy(GraphBoundResolution)
	}
	return data, nil
}

// unfollowedResolution reports whether the search passed an external
// principal that reaches `to` and whose resolution IN FORCE names a node
// `from` reaches. The principal is terminal (§5.4): its resolution is shown,
// never walked -- so a path through it is neither drawn nor ruled out. D-41
// makes this ordinary: a trust naming an account's role before that account
// connected keeps its external-principal source, with a derived resolution,
// while the same trust projected after the account connected is sourced from
// the role itself.
func (t *graphTraversal) unfollowedResolution(fwd, rev *graphSide) bool {
	for ref := range rev.visited {
		if n := t.nodes[ref]; n != nil && n.typ == RefExternalPrincipal && n.resolvedTo != "" && fwd.visited[n.resolvedTo] {
			return true
		}
	}
	return false
}

// renderPath is one path's nodes, edges and the union of their limitations.
func (t *graphTraversal) renderPath(src *GraphNode, edges []*GraphEdge) GraphPath {
	p := GraphPath{Nodes: []*GraphNode{src}, Edges: edges}
	lims := append([]GraphLimitation{}, src.Limitations...)
	for _, e := range edges {
		n := t.nodes[e.To]
		p.Nodes = append(p.Nodes, n)
		lims = append(lims, e.Limitations...)
		lims = append(lims, n.Limitations...)
	}
	p.Limitations = graphSortLimits(lims)
	return p
}

// graphReachable reports whether dst is reachable from src over edges, each
// in its own direction.
func graphReachable(edges []*GraphEdge, src, dst string) bool {
	out := map[string][]string{}
	for _, e := range edges {
		out[e.From] = append(out[e.From], e.To)
	}
	seen := map[string]bool{src: true}
	queue := []string{src}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == dst {
			return true
		}
		for _, n := range out[cur] {
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return false
}

// graphEnumeratePaths lists the simple paths from src to dst over edges,
// shortest first -- a breadth-first walk over partial paths, children in edge
// order, so paths of one length come out in the order their edges were read
// (deterministic, like the rest of the response). Only nodes on SOME path are
// walked. It stops after maxPaths+1 paths (overflow: more exist than fit),
// after graphPathWork extensions (workBound), and never extends a path past
// maxHops can_assume steps (hopBound: a longer path may exist).
func graphEnumeratePaths(edges []*GraphEdge, src, dst string, maxPaths, maxHops int) (
	paths [][]*GraphEdge, overflow, hopBound, workBound bool) {
	out := map[string][]*GraphEdge{}
	in := map[string][]*GraphEdge{}
	for _, e := range edges {
		out[e.From] = append(out[e.From], e)
		in[e.To] = append(in[e.To], e)
	}
	reach := func(start string, next func(string) []string) map[string]bool {
		seen := map[string]bool{start: true}
		queue := []string{start}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, n := range next(cur) {
				if !seen[n] {
					seen[n] = true
					queue = append(queue, n)
				}
			}
		}
		return seen
	}
	fw := reach(src, func(n string) []string {
		var xs []string
		for _, e := range out[n] {
			xs = append(xs, e.To)
		}
		return xs
	})
	co := reach(dst, func(n string) []string {
		var xs []string
		for _, e := range in[n] {
			xs = append(xs, e.From)
		}
		return xs
	})
	if !fw[dst] {
		return nil, false, false, false
	}

	type partial struct {
		at    string
		edges []*GraphEdge
		on    map[string]bool
		hops  int
	}
	queue := []partial{{at: src, on: map[string]bool{src: true}}}
	work := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range out[cur.at] {
			if !fw[e.To] || !co[e.To] || cur.on[e.To] {
				continue // off every path, or a cycle
			}
			hops := cur.hops
			if e.Kind == GraphEdgeCanAssume {
				hops++
			}
			if hops > maxHops {
				hopBound = true
				continue
			}
			work++
			if work > graphPathWork {
				return paths, overflow, hopBound, true
			}
			path := append(append([]*GraphEdge{}, cur.edges...), e)
			if e.To == dst {
				if len(paths) == maxPaths {
					return paths, true, hopBound, workBound
				}
				paths = append(paths, path)
				continue
			}
			on := make(map[string]bool, len(cur.on)+1)
			for k := range cur.on {
				on[k] = true
			}
			on[e.To] = true
			queue = append(queue, partial{at: e.To, edges: path, on: on, hops: hops})
		}
	}
	return paths, overflow, hopBound, workBound
}
