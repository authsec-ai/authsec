package igaread

// Limitations on graph elements (D-35): every node and edge of /graph,
// /graph/expand and /graph/path carries the §5.3 limitation codes that need
// no facts (FactFreeLimitations: account_not_connected, surface_*,
// conditions_not_evaluated, negated_statement, not_principal_unresolved,
// caller_permission_not_evaluated, deny_statements_present,
// permissions_boundary_present) and each path carries the union of its
// steps. effective_access_not_evaluated and organizations_not_collected hold
// for EVERY claim, so they are stated once, in meta.
//
// "Computed by the SAME function as /evidence" is meant literally: every
// element's limitations come from Query.ClaimLimitations -- the computation
// /evidence renders -- restricted to FactFreeLimitations, in ONE call per
// level for all its new nodes and edges (§5.6: never per element). So an
// edge on the canvas and the Evidence panel it opens list the same codes with
// the same fields in the same order, and the console has one type per code.
//
// Two additions, each by /evidence's own per-code constructors
// (contract_limitations.go), so a code has one set of fields wherever it
// appears (D-98):
//
//   - A NODE also carries the limitations of its restrictions (§5.4 "Deny
//     statements and boundaries are not edges ... every path through a
//     restricted node carries the matching limitation"): an identity's Deny
//     statements (its own and its live groups') and its OWN boundary -- read
//     by loadRestrictions, the reader /evidence's grant limitations use -- and
//     a role whose trust uses NotPrincipal (D-44); a statement's Condition and
//     negation. /evidence's presence claim for the node has none of these (a
//     presence is not access), so without them a path through a restricted
//     node would not say so.
//   - Every crosses_account EDGE also carries the FAR account's coverage (§5.4
//     "the far account's coverage appears as limitations on the edge";
//     §2.14.10 "Coverage for the far segment stays visible"): the far account
//     is the connected endpoint account that is not the claim's own
//     connector's, and each of its surfaces the current revision's runs did
//     not reach is named. An unconnected far account is already
//     account_not_connected in /evidence's list.
//
// Each code applies only when its condition holds (§2.14.7 "never generic").

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// GraphLimitation is one limitation on a graph element -- the SAME type as
// /evidence's (D-35): {code, ...its code's fields}.
type GraphLimitation = Limitation

// The limitation codes the graph meta states once for every element.
const (
	graphLimEffectiveAccess = LimEffectiveAccessNotEvaluated
	graphLimOrganizations   = LimOrganizationsNotCollected
)

// decorateLimitations sets the limitations of a level's new nodes and edges
// (or of a root): one Query.ClaimLimitations call for all of them, then each
// node's restriction limitations and each crossing edge's far coverage.
// Everything else about them -- an edge's state, crosses_account, a node's
// restrictions -- is decided before (decorateNodes, decorateEdges).
func (t *graphTraversal) decorateLimitations(lv *graphLevel, nodes []*GraphNode, edges []*GraphEdge) error {
	if len(nodes)+len(edges) == 0 {
		return nil
	}
	refs := make([]Ref, 0, len(nodes)+len(edges))
	for _, n := range nodes {
		refs = append(refs, Ref{Type: n.typ, ID: n.id})
	}
	for _, e := range edges {
		refs = append(refs, e.claimRef)
	}
	if _, err := lv.db(); err != nil { // the level's allowance is spent
		return err
	}
	// ClaimLimitations is a dozen statements (claims, restrictions, coverage,
	// a nested optional history read): the level's query holds each of them
	// to the level's allowance.
	byRef, err := lv.query().ClaimLimitations(t.accts, refs, FactFreeLimitations)
	if err != nil {
		return err
	}
	of := func(ref string) ([]GraphLimitation, error) {
		ls, ok := byRef[ref]
		if !ok {
			// The traversal read it in this same snapshot, by the same
			// readability rule (D-6): a miss is a defect, never an element to
			// show without its limitations.
			return nil, fmt.Errorf("igaread: no limitations for %s, which the traversal read", ref)
		}
		return ls, nil
	}
	for _, n := range nodes {
		ls, err := of(n.Ref)
		if err != nil {
			return err
		}
		n.Limitations = graphWith(ls, graphRestrictionLimitations(n))
	}
	for _, e := range edges {
		ls, err := of(e.Claim)
		if err != nil {
			return err
		}
		e.Limitations = graphWith(ls, e.farCoverage)
	}
	return nil
}

// graphWith is a claim's own limitations plus the graph's additions. With
// none, the list is /evidence's exactly, in its order; with some, the union
// is ordered as /evidence orders a list (graphSortLimits).
func graphWith(own, more []GraphLimitation) []GraphLimitation {
	if len(more) == 0 {
		if own == nil {
			return []GraphLimitation{}
		}
		return own
	}
	return graphSortLimits(append(append([]GraphLimitation{}, own...), more...))
}

// graphRestrictionLimitations are the limitations of a node's restrictions
// (see the file comment): an identity's Deny statements, its own boundary and
// a NotPrincipal trust; a statement's Condition and negation, by /evidence's
// own rule over the statement's text as /evidence parses it.
func graphRestrictionLimitations(n *GraphNode) []GraphLimitation {
	var ls []GraphLimitation
	switch n.typ {
	case RefIdentity:
		if l := LimDeny(n.denyIDs); l != nil {
			ls = append(ls, l)
		}
		// Its OWN boundary. A group's member boundaries (D-22) bear on the
		// group's GRANTS, and are theirs (/evidence's); the group itself has
		// no boundary, as its restrictions say.
		if l := LimBoundary(n.boundaryPolicies, nil); l != nil {
			ls = append(ls, l)
		}
		if n.notPrincipal {
			ls = append(ls, GraphLimitation{"code": LimNotPrincipalUnresolved}) // D-44
		}
	case RefStatement:
		if n.conditional || hasCondition(n.text.Condition) {
			ls = append(ls, LimConditions(n.text.Condition))
		}
		if n.negated {
			ls = append(ls, LimNegated(n.text))
		}
	}
	return ls
}

// graphSortLimits dedupes limitations and orders them as /evidence does --
// by the §5.3 table's order, then account, then surface -- and, among equals,
// by canonical JSON, so the same union (a path's) renders the same list every
// time.
func graphSortLimits(ls []GraphLimitation) []GraphLimitation {
	type keyed struct {
		key string
		l   GraphLimitation
	}
	seen := map[string]bool{}
	var ks []keyed
	for _, l := range ls {
		raw, _ := json.Marshal(l) // map keys are sorted: canonical
		k := string(raw)
		if seen[k] {
			continue
		}
		seen[k] = true
		ks = append(ks, keyed{k, l})
	}
	sort.SliceStable(ks, func(i, j int) bool { return ks[i].key < ks[j].key })
	out := make([]GraphLimitation, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.l)
	}
	sortLimitations(out)
	return out
}

// graphSortPairs orders frontier pairs by the node's place in the response,
// then by edge kind.
func graphSortPairs(ps []graphPair, pos, kindPos map[string]int) {
	sort.SliceStable(ps, func(i, j int) bool {
		if pos[ps[i].ref] != pos[ps[j].ref] {
			return pos[ps[i].ref] < pos[ps[j].ref]
		}
		return kindPos[ps[i].kind] < kindPos[ps[j].kind]
	})
}

/* ---------------------------------- edges ---------------------------------- */

// decorateEdges completes a level's new edges once both endpoints are read:
// a target's state (its statement's, §5.4), crosses_account (D-36), the
// stale_reason of every stale edge (D-74), and a crossing edge's far
// coverage. Their limitations follow (decorateLimitations).
func (t *graphTraversal) decorateEdges(lv *graphLevel, edges []*GraphEdge, node func(string) *GraphNode) error {
	if len(edges) == 0 {
		return nil
	}
	crossing := false
	for _, e := range edges {
		from, to := node(e.From), node(e.To)
		if e.Kind == GraphEdgeTarget {
			// A target's lifecycle is its statement's: active is the
			// statement's own D-1 state, retired is ended.
			e.State, e.LastConfirmedAt = from.State, from.LastConfirmedAt
			if from.Lifecycle != models.IGALifecycleActive {
				e.State = StateEnded
			}
		}
		// D-36: both endpoints have a known account and they differ.
		// Statements have no account, so grants and targets never cross.
		e.CrossesAccount = from.acct != "" && to.acct != "" && from.acct != to.acct
		if e.CrossesAccount && (from.connected || to.connected) {
			crossing = true
		}
	}
	if err := t.edgeStaleReasons(lv, edges, node); err != nil {
		return err
	}
	if crossing {
		if err := t.loadFarCoverage(lv); err != nil {
			return err
		}
	}
	for _, e := range edges {
		if !e.CrossesAccount {
			continue
		}
		own := ""
		if e.connectorID != nil {
			if c := t.accts.Connector(*e.connectorID); c != nil {
				own = c.AccountID
			}
		}
		for _, n := range []*GraphNode{node(e.From), node(e.To)} {
			if n.acct != own && n.connected {
				e.farCoverage = append(e.farCoverage, t.cov[n.acct]...)
			}
		}
	}
	return nil
}

// loadFarCoverage reads, once per request, every connected account's coverage
// in the current revision (Query.Coverage, the /coverage route's own reader)
// as surface_* limitations: each surface whose state prevents a conclusion
// (D-58).
func (t *graphTraversal) loadFarCoverage(lv *graphLevel) error {
	if t.covDone {
		return nil
	}
	if _, err := lv.db(); err != nil { // the level's allowance is spent
		return err
	}
	// Coverage is several statements and a nested optional read: the level's
	// query holds every one of them to the level's allowance.
	accounts, err := lv.query().Coverage(nil)
	if err != nil {
		return err
	}
	cov := map[string][]GraphLimitation{}
	for _, a := range accounts {
		if a.Account == nil {
			continue
		}
		for _, s := range a.Surfaces {
			code, _ := s.Prevents.(string)
			switch code {
			case PreventsSurfaceDenied, PreventsSurfacePartial, PreventsSurfaceStale:
				cov[a.Account.ID] = append(cov[a.Account.ID], LimSurface(code, a.Account.ID, s.Surface, s.State, s.Since))
			}
		}
	}
	t.cov, t.covDone = cov, true
	return nil
}

// graphPartStale is one stale thing whose D-74 stale_reason comes from ONE
// edge partition: a stale relationship or grant, or a stale external
// principal through one of its stale can_assume edges (it has no support rows
// of its own, D-47). into is the stale_reason being filled.
type graphPartStale struct {
	conn  uuid.UUID
	key   string
	class string // "" for relationships; ObjectEntitlement for a grant (document-protected)
	into  *[]StaleReason
}

// edgeStaleReasons fills D-74's stale_reason on stale relationships, grants
// and targets. A relationship's or grant's is its OWN partition's
// (partitionStaleReasons). A target has no state or partition of its own: its
// state is its statement's (§5.4 "Filtered by: statement lifecycle"), so a
// stale target carries its statement's stale_reason -- the statement node is
// decorated before its edges, in this level or an earlier one.
func (t *graphTraversal) edgeStaleReasons(lv *graphLevel, edges []*GraphEdge, node func(string) *GraphNode) error {
	var items []graphPartStale
	for _, e := range edges {
		if e.State != StateStale {
			continue
		}
		empty := []StaleReason{}
		e.StaleReason = &empty
		if e.Kind == GraphEdgeTarget {
			if st := node(e.From); st != nil && st.StaleReason != nil {
				rs := append([]StaleReason{}, (*st.StaleReason)...)
				e.StaleReason = &rs
			}
			continue
		}
		if e.connectorID == nil || e.partitionKey == "" {
			continue // nothing recorded explains it
		}
		class := ""
		if e.Kind == GraphEdgeGrant {
			class = models.ObjectEntitlement // document-protected, like its statement
		}
		items = append(items, graphPartStale{conn: *e.connectorID, key: e.partitionKey, class: class, into: e.StaleReason})
	}
	return t.partitionStaleReasons(lv, items)
}

// principalStaleReasons fills stale_reason on stale external principals. A
// principal's state is derived from its can_assume edges (D-1, D-47): stale
// when none is current and one is stale. So its stale_reason is the union of
// the stale_reasons of those stale edges -- read in one statement for the
// level, whether or not the response carries the edges themselves.
func (t *graphTraversal) principalStaleReasons(lv *graphLevel, nodes []*GraphNode) error {
	byID := map[uuid.UUID]*GraphNode{}
	var ids []uuid.UUID
	for _, n := range nodes {
		if n.State != StateStale {
			continue
		}
		empty := []StaleReason{}
		n.StaleReason = &empty
		byID[n.id] = n
		ids = append(ids, n.id)
	}
	if len(ids) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []struct {
		NodeID       uuid.UUID
		ConnectorID  uuid.UUID
		PartitionKey string
	}
	if err := tx.Raw(`SELECT r.source_external_principal_id AS node_id, r.connector_id, r.partition_key
	                    FROM iga_relationship r
	                   WHERE r.workspace_id = ? AND r.source_external_principal_id IN ?
	                     AND r.relationship_type = 'can_assume' AND r.state = 'stale'
	                     AND r.connector_id IS NOT NULL AND r.partition_key <> ''
	                   GROUP BY r.source_external_principal_id, r.connector_id, r.partition_key
	                   ORDER BY r.source_external_principal_id, r.connector_id, r.partition_key`,
		t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	var items []graphPartStale
	for _, r := range rows {
		items = append(items, graphPartStale{conn: r.ConnectorID, key: r.PartitionKey, into: byID[r.NodeID].StaleReason})
	}
	return t.partitionStaleReasons(lv, items)
}

// partitionStaleReasons appends to each item's stale_reason the surfaces of
// its partition that the run the current revision holds that partition from
// did not reach. The partition is the projector's own (igagraph.Partitions
// over that run's coverage, with the watermark's scope and connector), matched
// by its key -- never parsed out of the key. since is read as optional work,
// as NodeStaleReasons reads it. Each list is sorted by (account, surface) and
// deduplicated.
func (t *graphTraversal) partitionStaleReasons(lv *graphLevel, items []graphPartStale) error {
	type part struct {
		conn uuid.UUID
		key  string
	}
	want := map[part][]graphPartStale{}
	var conns []uuid.UUID
	var keys []string
	seenConn, seenKey := map[uuid.UUID]bool{}, map[string]bool{}
	for _, it := range items {
		p := part{it.conn, it.key}
		want[p] = append(want[p], it)
		if !seenConn[p.conn] {
			seenConn[p.conn] = true
			conns = append(conns, p.conn)
		}
		if !seenKey[p.key] {
			seenKey[p.key] = true
			keys = append(keys, p.key)
		}
	}
	if len(want) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var marks []struct {
		ConnectorID   uuid.UUID
		PartitionKey  string
		EstateScopeID uuid.UUID
		LastRunID     uuid.UUID
	}
	if err := tx.Raw(`SELECT connector_id, partition_key, estate_scope_id, last_run_id
	                    FROM iga_projection_state
	                   WHERE workspace_id = ? AND connector_id IN ? AND partition_key IN ?`,
		t.q.WS, conns, keys).Scan(&marks).Error; err != nil {
		return err
	}
	var runIDs []uuid.UUID
	for _, m := range marks {
		runIDs = append(runIDs, m.LastRunID)
	}
	if len(runIDs) == 0 {
		return nil
	}
	if tx, err = lv.db(); err != nil {
		return err
	}
	var runs []staleRun
	if err := tx.Raw(`SELECT id, connector_id, published_at, coverage FROM cloud_scan_run
	                   WHERE workspace_id = ? AND id IN ?`, t.q.WS, runIDs).Scan(&runs).Error; err != nil {
		return err
	}
	runByID := map[uuid.UUID]*staleRun{}
	for i := range runs {
		runs[i].decode()
		runByID[runs[i].ID] = &runs[i]
	}

	type pending struct {
		into *[]StaleReason
		run  *staleRun
		gap  surfaceGap
	}
	var found []pending
	for _, m := range marks {
		its := want[part{m.ConnectorID, m.PartitionKey}]
		run := runByID[m.LastRunID]
		if len(its) == 0 || run == nil {
			continue
		}
		snap := &igagraph.Snapshot{
			ScopeID:  m.EstateScopeID,
			Run:      models.CloudScanRun{ID: run.ID, ConnectorID: run.ConnectorID},
			Coverage: run.cov.Surfaces,
		}
		for _, p := range igagraph.Partitions(snap) {
			if p.Key() != m.PartitionKey {
				continue
			}
			for _, it := range its {
				for _, g := range partitionGaps(p, run.cov, it.class) {
					found = append(found, pending{into: it.into, run: run, gap: g})
				}
			}
			break
		}
	}
	if len(found) == 0 {
		return nil
	}

	var hconns []uuid.UUID
	hseen := map[uuid.UUID]bool{}
	for _, f := range found {
		if !hseen[f.run.ConnectorID] {
			hseen[f.run.ConnectorID] = true
			hconns = append(hconns, f.run.ConnectorID)
		}
	}
	history, haveHistory, err := graphRunHistory(lv.query(), hconns)
	if err != nil {
		return err
	}
	for _, f := range found {
		var since any
		if haveHistory {
			since = TS(streakSince(history[f.run.ConnectorID], f.run.ID, f.gap.surface, f.gap.state))
		}
		acct := ""
		if c := t.accts.Connector(f.run.ConnectorID); c != nil {
			acct = c.AccountID
		}
		*f.into = append(*f.into, StaleReason{AccountID: acct, Surface: f.gap.surface, State: f.gap.state, Since: since})
	}
	sorted := map[*[]StaleReason]bool{}
	for _, it := range items {
		if sorted[it.into] {
			continue
		}
		sorted[it.into] = true
		rs := *it.into
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].AccountID != rs[j].AccountID {
				return rs[i].AccountID < rs[j].AccountID
			}
			return rs[i].Surface < rs[j].Surface
		})
		*it.into = dedupeReasons(rs)
	}
	return nil
}

// graphRunHistory reads each connector's recent published runs, newest first,
// as NodeStaleReasons does for since: OPTIONAL work -- ok=false leaves every
// since null, never a guess.
func graphRunHistory(q *Query, conns []uuid.UUID) (map[uuid.UUID][]staleRun, bool, error) {
	var hist []staleRun
	ok, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, connector_id, published_at, coverage FROM (
		                   SELECT sr.id, sr.connector_id, sr.published_at, sr.coverage,
		                          row_number() OVER (PARTITION BY sr.connector_id
		                                             ORDER BY sr.published_at DESC, sr.id DESC) AS n
		                     FROM cloud_scan_run sr
		                    WHERE sr.workspace_id = ? AND sr.connector_id IN ? AND sr.published_at IS NOT NULL
		                      AND sr.published_at <= (
		                          SELECT max(pr.published_at)
		                            FROM iga_projection_state ps
		                            JOIN cloud_scan_run pr ON pr.workspace_id = ps.workspace_id AND pr.id = ps.last_run_id
		                           WHERE ps.workspace_id = sr.workspace_id AND ps.connector_id = sr.connector_id)) x
		                WHERE n <= ?
		                ORDER BY connector_id, published_at DESC, id DESC`,
			q.WS, conns, StaleHistoryRuns+1).Scan(&hist).Error
	})
	if err != nil || !ok {
		return nil, false, err
	}
	out := map[uuid.UUID][]staleRun{}
	for i := range hist {
		hist[i].decode()
		out[hist[i].ConnectorID] = append(out[hist[i].ConnectorID], hist[i])
	}
	return out, true, nil
}
