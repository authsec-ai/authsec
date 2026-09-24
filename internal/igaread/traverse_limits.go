package igaread

// Limitations on graph elements (D-35): every node and edge of /graph,
// /graph/expand and /graph/path carries the §5.3 limitation codes that need
// no facts -- account_not_connected, surface_*, conditions_not_evaluated,
// negated_statement, not_principal_unresolved, caller_permission_not_evaluated,
// deny_statements_present and permissions_boundary_present -- and each path
// carries the union of its steps. effective_access_not_evaluated and
// organizations_not_collected hold for EVERY claim, so they are stated once,
// in meta.
//
// An EDGE is a claim, and its limitations are /evidence's for that claim,
// from the SAME function (Query.ClaimLimitations with FactFreeLimitations):
// same codes, same fields, same order, so an edge on the canvas and the
// Evidence panel it opens never disagree (D-35). A NODE's are built here from
// the rows the traversal holds -- its own account, its staleness, a
// statement's Condition and negation, an identity's restrictions (§5.4 "every
// path through a restricted node carries the matching limitation") -- by the
// SAME per-code constructors /evidence uses (contract_limitations.go), so a
// code has one set of fields wherever it appears.
//
// Every crosses_account edge also carries the FAR account's coverage (§5.4
// "the far account's coverage appears as limitations on the edge";
// §2.14.10 "Coverage for the far segment stays visible"): the far account is
// the endpoint account that is not the claim's own connector's -- an
// unconnected one is account_not_connected (from /evidence's endpoints), a
// connected one names each of its surfaces the current revision's runs did
// not reach. That is the graph's one addition to a claim's limitations.
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

// graphSurfaceLimitations maps stale_reason entries to surface_* limitations
// by the one D-58 mapping (Prevents). A state that prevents nothing, and the
// organizations gap (stated in meta), are not repeated here.
func graphSurfaceLimitations(reasons []StaleReason) []GraphLimitation {
	var out []GraphLimitation
	for _, r := range reasons {
		code, _ := Prevents(r.Surface, r.State).(string)
		switch code {
		case PreventsSurfaceDenied, PreventsSurfacePartial, PreventsSurfaceStale:
			out = append(out, LimSurface(code, r.AccountID, r.Surface, r.State, r.Since))
		}
	}
	return out
}

// nodeLimitations is a node's own limitations.
func (t *graphTraversal) nodeLimitations(n *GraphNode) []GraphLimitation {
	var ls []GraphLimitation
	if !n.connected {
		if l := LimNotConnected([]string{n.acct}); l != nil {
			ls = append(ls, l)
		}
	}
	ls = append(ls, n.surfaceLims...)
	switch n.typ {
	case RefStatement:
		ls = append(ls, graphStatementLimitations(n)...)
	case RefIdentity:
		ls = append(ls, graphHolderLimitations(n)...)
		if n.notPrincipal {
			ls = append(ls, GraphLimitation{"code": LimNotPrincipalUnresolved})
		}
	}
	return graphSortLimits(ls)
}

// graphStatementLimitations: the statement's Condition (its keys listed) and
// its negation (NotAction or NotResource), by /evidence's own rule and
// constructors, over the statement's text as /evidence parses it.
func graphStatementLimitations(stmt *GraphNode) []GraphLimitation {
	var ls []GraphLimitation
	if stmt.conditional || hasCondition(stmt.text.Condition) {
		ls = append(ls, LimConditions(stmt.text.Condition))
	}
	if stmt.negated {
		ls = append(ls, LimNegated(stmt.text))
	}
	return ls
}

// graphHolderLimitations: the identity's Deny statements (its own and its
// groups') and its OWN boundary -- restrictions on everything it is granted.
// A group's member boundaries (D-22) are a limitation of the group's GRANTS,
// which /evidence computes for those edges; the group node itself has no
// boundary (its restrictions say so).
func graphHolderLimitations(holder *GraphNode) []GraphLimitation {
	var ls []GraphLimitation
	if l := LimDeny(holder.denyIDs); l != nil {
		ls = append(ls, l)
	}
	if l := LimBoundary(holder.boundaryPolicies, nil); l != nil {
		ls = append(ls, l)
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
// stale_reason of every stale edge (D-74), and limitations.
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
		e.Limitations = t.edgeLimitations(e, node(e.From), node(e.To))
	}
	return nil
}

// edgeLimitations is one edge's limitations.
func (t *graphTraversal) edgeLimitations(e *GraphEdge, from, to *GraphNode) []GraphLimitation {
	var ls []GraphLimitation
	for _, n := range []*GraphNode{from, to} {
		if n.acct != "" && !n.connected {
			ls = append(ls, graphNotConnected(n.acct))
		}
	}
	if e.StaleReason != nil {
		ls = append(ls, graphSurfaceLimitations(*e.StaleReason)...)
	}
	if e.CrossesAccount {
		own := ""
		if e.connectorID != nil {
			if c := t.accts.Connector(*e.connectorID); c != nil {
				own = c.AccountID
			}
		}
		for _, n := range []*GraphNode{from, to} {
			if n.acct != own && n.connected {
				ls = append(ls, t.cov[n.acct]...)
			}
		}
	}
	switch e.Kind {
	case GraphEdgeCanAssume:
		// The trust policy permits it; the caller's own sts:AssumeRole
		// permission is not checked (§5.3).
		ls = append(ls, GraphLimitation{"code": graphLimCallerPermission})
		if len(e.conditions) > 0 {
			keys := graphConditionKeys(e.conditions)
			if keys == nil {
				keys = []string{}
			}
			ls = append(ls, GraphLimitation{"code": graphLimConditions, "keys": keys})
		}
		if to.negatedTrust[e.statementKey] {
			ls = append(ls, GraphLimitation{"code": graphLimNegated}) // D-88
		}
		if to.notPrincipal {
			ls = append(ls, GraphLimitation{"code": graphLimNotPrincipal}) // D-44
		}
	case GraphEdgeGrant:
		ls = append(ls, graphStatementLimitations(to)...)
		ls = append(ls, graphHolderLimitations(from)...)
		ls = append(ls, graphMemberBoundaryLimitations(from)...)
	case GraphEdgeTarget:
		// The target's staleness is its statement's.
		ls = append(ls, from.surfaceLims...)
	}
	return graphSortLimits(ls)
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
				cov[a.Account.ID] = append(cov[a.Account.ID], GraphLimitation{
					"code": code, "account_id": a.Account.ID, "surface": s.Surface, "state": s.State, "since": s.Since})
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
	if err := t.partitionStaleReasons(lv, items); err != nil {
		return err
	}
	for _, n := range byID {
		n.surfaceLims = graphSurfaceLimitations(*n.StaleReason)
	}
	return nil
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
