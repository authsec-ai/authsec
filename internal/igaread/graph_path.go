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
// One case is neither found nor none: the search passed an external
// principal whose resolution IN FORCE links the two sides (§2.12). The
// principal is terminal (§5.4) -- its resolution is shown, never walked -- so
// a path through it is neither drawn nor ruled out: not_found_within_budget
// (or more_paths) with bound_by "resolution_not_followed", additive to §5.4's
// vocabulary and raised (D-105): none_exists would claim more than was
// searched, and the outcome table has no other value. /graph says the same
// fact in its own resolution_not_followed field, never in truncated.
//
// Both orientations. The route has no direction, and a path runs along its
// edges' own directions -- but §5.4's reverse question ("what reaches this":
// Resource › Access, *View in graph* from a resource) asks for a path from a
// resource to what reaches it, against the edges. So when no path runs from
// `from` to `to`, the same bounded search runs from `to` to `from`, in the
// same traversal state (the budgets are the request's, and edges already read
// cost nothing). data.direction says which orientation the paths are in:
// forward (each edge runs from its node toward `to`) or reverse (each edge
// runs toward `from`: `to` reaches `from`). Either way a path's nodes run from
// `from` to `to`. none_exists is said only when BOTH orientations were
// searched to exhaustion before any budget bound: an orientation that was not
// searched is never reported as having no path. direction is additive to
// D-35's shape, null when no path was found.
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

// GraphPathData is /graph/path's data (D-35), plus direction: the orientation
// the paths run in (forward | reverse), null when none was found.
type GraphPathData struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	Outcome   string      `json:"outcome"`
	Direction *string     `json:"direction"`
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
	ctx, perr := bindOptIn(ctx, vals)
	if perr != nil {
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
		data, err := t.pathVerdict(src, dst, g.b)
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

// graphSearch is one orientation's bounded bidirectional search: a forward
// side out of `src`, a reverse side into `dst`, and the paths enumerated from
// the edges it read.
type graphSearch struct {
	fwd, rev  *graphSide
	bound     string // the budget that stopped the search, "" when none did
	paths     [][]*GraphEdge
	overflow  bool // more paths than the path budget
	hopBound  bool // a path was cut by the hop limit
	workBound bool // the enumeration's work bound stopped it
	// unfollowed: a resolution in force links the two sides (§2.12) and was
	// not walked.
	unfollowed bool
}

// boundBy is the first reason the search's answer is not known complete, ""
// when it is: a budget, the hop limit, the path budget, an unfollowed
// resolution -- in that order.
func (s *graphSearch) boundBy() string {
	switch {
	case s.bound != "":
		return s.bound
	case s.hopBound:
		return GraphBoundAssumeHops
	case s.overflow || s.workBound:
		return GraphBoundPaths
	case s.unfollowed:
		return GraphBoundResolution
	}
	return ""
}

// noneExists is D-38 for one orientation: no path, both frontiers exhausted,
// and nothing bound first.
func (s *graphSearch) noneExists() bool {
	return len(s.paths) == 0 && s.boundBy() == "" && s.fwd.exhausted() && s.rev.exhausted()
}

// pathVerdict is /graph/path's answer: the paths from `from` to `to` along
// the edges (forward) when there are any, else the paths from `to` to `from`
// (reverse) -- and none_exists only when both orientations say none (see the
// file comment). The second search runs only when the first found nothing.
func (t *graphTraversal) pathVerdict(src, dst *GraphNode, b GraphBudgets) (*GraphPathData, error) {
	there, err := t.pathSearch(src, dst, b)
	if err != nil {
		return nil, err
	}
	var back *graphSearch
	if len(there.paths) == 0 {
		if back, err = t.pathSearch(dst, src, b); err != nil {
			return nil, err
		}
	}
	d := graphPathDecide(there, back)
	data := &GraphPathData{From: src.Ref, To: dst.Ref, Outcome: d.outcome, Paths: []GraphPath{}, MorePaths: d.morePaths}
	if d.boundBy != "" {
		data.BoundBy = &d.boundBy
	}
	if d.outcome == GraphPathFound {
		dir, paths := GraphForward, there.paths
		if d.reverse {
			dir, paths = GraphReverse, back.paths
		}
		data.Direction = &dir
		for _, ep := range paths {
			data.Paths = append(data.Paths, t.renderPath(src, ep, d.reverse))
		}
	}
	return data, nil
}

// graphPathDecision is the verdict over one or two orientations' searches.
type graphPathDecision struct {
	outcome   string
	reverse   bool // the paths are the reverse orientation's
	morePaths bool
	boundBy   string
}

// graphPathDecide combines the two orientations (back is nil when the
// forward one found paths, and was then not run):
//
//   - forward paths: found, complete unless its own search says otherwise --
//     the search finished (no budget bound), no path was cut by the hop
//     limit, every path fit, and no resolution was left unfollowed;
//   - else reverse paths: found, complete only when the reverse list is
//     complete AND the forward orientation was searched to the end -- an
//     unfinished forward search may hold paths the list lacks;
//   - else D-38 in both orientations: none_exists ONLY when each was searched
//     to exhaustion before any budget bound. Anything else is "not found
//     within the limits", bound_by naming the first reason: the answer is
//     unknown, and must not look like "there is none".
func graphPathDecide(there, back *graphSearch) graphPathDecision {
	first := func(reasons ...string) string {
		for _, r := range reasons {
			if r != "" {
				return r
			}
		}
		return ""
	}
	switch {
	case len(there.paths) > 0:
		bb := there.boundBy()
		return graphPathDecision{outcome: GraphPathFound, morePaths: bb != "", boundBy: bb}
	case back == nil:
		// Never: the reverse orientation runs whenever the forward one found
		// nothing. Were it skipped, nothing could be claimed of it.
		return graphPathDecision{outcome: GraphPathNotFoundWithinBudget, boundBy: first(there.boundBy(), GraphBoundTime)}
	case len(back.paths) > 0:
		bb := first(back.boundBy(), there.boundBy())
		return graphPathDecision{outcome: GraphPathFound, reverse: true, morePaths: bb != "", boundBy: bb}
	case there.noneExists() && back.noneExists():
		return graphPathDecision{outcome: GraphPathNoneExists}
	}
	return graphPathDecision{outcome: GraphPathNotFoundWithinBudget, boundBy: first(there.boundBy(), back.boundBy())}
}

// pathSearch is one orientation's search: from src along the edges, to dst.
//
// It runs until BOTH frontiers are exhausted, a budget binds, or a path is
// known and ONE frontier is exhausted (every edge of every path is then in
// hand); then it enumerates the paths.
func (t *graphTraversal) pathSearch(src, dst *GraphNode, b GraphBudgets) (*graphSearch, error) {
	fwd := &graphSide{dir: GraphForward, visited: map[string]bool{src.Ref: true}, frontier: []*GraphNode{src}}
	rev := &graphSide{dir: GraphReverse, visited: map[string]bool{dst.Ref: true}, frontier: []*GraphNode{dst}}
	out := &graphSearch{fwd: fwd, rev: rev}

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
			out.bound = GraphBoundTime
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
			out.bound = GraphBoundTime
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
			out.bound = s.bound
			break
		}
		found = graphReachable(t.edges, src.Ref, dst.Ref)
	}
	out.paths, out.overflow, out.hopBound, out.workBound = graphEnumeratePaths(t.edges, src.Ref, dst.Ref, b.Paths, b.AssumeHops)
	out.unfollowed = t.unfollowedResolution(fwd, rev)
	return out, nil
}

// unfollowedResolution reports whether the search passed an external
// principal whose resolution IN FORCE links its two sides: the principal is
// terminal (§5.4) -- its resolution is shown, never walked -- so a path
// through it is neither drawn nor ruled out. The principal and its resolved
// node are one principal (§2.12), so either end of the link may be on either
// side:
//
//   - the reverse side reached the principal (it may assume something that
//     leads to dst) and the forward side reached its resolved node;
//   - the forward side holds the principal (src itself: nothing leads to a
//     principal) and the reverse side reached its resolved node, whose own
//     edges lead to dst.
//
// D-41 makes this ordinary: a trust naming an account's role before that
// account connected keeps its external-principal source, with a derived
// resolution, while the same trust projected after the account connected is
// sourced from the role itself.
func (t *graphTraversal) unfollowedResolution(fwd, rev *graphSide) bool {
	links := func(principals, other *graphSide) bool {
		for ref := range principals.visited {
			if n := t.nodes[ref]; n != nil && n.typ == RefExternalPrincipal && n.resolvedTo != "" && other.visited[n.resolvedTo] {
				return true
			}
		}
		return false
	}
	return links(rev, fwd) || links(fwd, rev)
}

// renderPath is one path's nodes, from `from` (src) to `to`, its edges in
// that order, and the union of their limitations. A forward path's edges
// each run toward `to`; a reverse one (edges enumerated from `to` to `from`)
// is walked backwards, so its edges each run toward `from`. Every edge keeps
// its own from and to.
func (t *graphTraversal) renderPath(src *GraphNode, edges []*GraphEdge, reverse bool) GraphPath {
	if reverse {
		rs := make([]*GraphEdge, len(edges))
		for i, e := range edges {
			rs[len(edges)-1-i] = e
		}
		edges = rs
	}
	p := GraphPath{Nodes: []*GraphNode{src}, Edges: edges}
	lims := append([]GraphLimitation{}, src.Limitations...)
	for _, e := range edges {
		next := e.To
		if reverse {
			next = e.From
		}
		n := t.nodes[next]
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
