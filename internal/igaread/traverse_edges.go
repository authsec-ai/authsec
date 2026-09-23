package igaread

// The traversal's edge queries (§5.4 "Algorithm and queries", §5.6): ONE
// statement per edge kind per level, for the whole frontier, on the typed
// columns and the indexes 030, 031 and 036 built for them:
//
//	relationship forward   COALESCE(source_identity_account_id, source_workload_id)
//	                       -- the expression idx_iga_relationship_source is built on
//	                       source_external_principal_id (idx_iga_relationship_source_external)
//	relationship reverse   target_identity_account_id (idx_iga_relationship_target)
//	grant forward          subject_identity_account_id (idx_iga_access_edges_subject_identity)
//	grant reverse          entitlement_id, with state <> 'ended' written literally:
//	                       idx_iga_access_edges_entitlement is partial on it
//	target forward         the (workspace_id, entitlement_id) prefix of iga_et_key
//	target reverse         idx_iga_et_resource
//
// Every statement is ordered by (target source_key, id), the kinds are issued
// in graphEdgeKinds order, so a level's edges are ordered by (edge kind,
// target source_key, id) and the same request returns the same response.
//
// Three rules are enforced HERE, in SQL, never after the fact:
//
//   - A grant is to an Allow statement (§3 Rule 7): every grant query joins its
//     statement with effect = 'allow', so a projector defect cannot surface a
//     Deny as access. Target edges are read through Allow statements too: a
//     Deny statement is a restriction on its holder, never a node a path runs
//     through (§5.4; the named_by rule of D-17).
//   - A target edge is mode = 'resource' ONLY. A NotResource entry is an
//     exclusion (AWS: "every resource except these"): it is never traversed,
//     in either direction (§5.4, B19).
//   - The far node is readable (D-6): an AWS row with a support row, or an
//     external principal. The node read of the same level uses the same
//     predicate, in the same snapshot.
//
// A target has no state of its own: its lifecycle is its statement's
// (§5.4 "Filtered by: statement lifecycle"), so the default reads only active
// statements' targets, and the edge's state is the statement's (D-1).

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// graphEdgeSpec is how to read one edge kind in one direction. Every SQL
// fragment is free of bind variables except where a caller appends them. The
// edge row is aliased e0.
type graphEdgeSpec struct {
	kind  string
	claim string // the claim reference type: relationship | grant | target
	// from is the FROM clause with its joins; far names the far node's table
	// where there is one alias for it.
	from string
	// where is always applied: the kind, the far node's readability, Rule 7,
	// target mode.
	where string
	// live is the lifecycle filter (§5.4, D-12), dropped by include_ended.
	live string
	// near maps a frontier node type to the SQL expression of the near
	// endpoint's id; the kind is read only from those types.
	near map[string]string
	// farKey is the far node's source_key: the order, and the page keyset.
	farKey string
	// cols is the select list, in graphEdgeRow's columns.
	cols string
}

func (s *graphEdgeSpec) claimRef(id uuid.UUID) string { return R(s.claim, id) }

// graphEdgeRow is one edge row as every spec's cols read it.
type graphEdgeRow struct {
	ClaimID         uuid.UUID
	FromID          uuid.UUID
	FromType        string
	ToID            uuid.UUID
	ToType          string
	FarKey          string
	State           *string
	Basis           string
	Mechanism       string
	StatementKey    string
	Conditions      *string
	LastConfirmedAt *time.Time
	ConnectorID     *uuid.UUID
	PartitionKey    string
	PolicyName      *string
}

// edge renders the row as a GraphEdge; decorateEdges completes it once both
// endpoints are read.
func (r graphEdgeRow) edge(kind, claim, from, to string) *GraphEdge {
	e := &GraphEdge{
		Claim: claim, Kind: kind, From: from, To: to,
		Basis: r.Basis, Mechanism: r.Mechanism, LastConfirmedAt: TS(r.LastConfirmedAt),
		Limitations:  []GraphLimitation{},
		connectorID:  r.ConnectorID,
		partitionKey: r.PartitionKey,
		statementKey: r.StatementKey,
	}
	if r.State != nil {
		e.State = *r.State
	}
	if r.PolicyName != nil {
		e.Policy = *r.PolicyName
	}
	if r.Conditions != nil && *r.Conditions != "" && *r.Conditions != "null" {
		e.conditions = []byte(*r.Conditions)
	}
	if kind == GraphEdgeTarget {
		e.Mode = "resource"
	}
	return e
}

// Column lists per claim table, in graphEdgeRow's order.
const (
	graphRelCols = `e0.id AS claim_id,
	       COALESCE(e0.source_identity_account_id, e0.source_workload_id, e0.source_external_principal_id) AS from_id,
	       (CASE WHEN e0.source_workload_id IS NOT NULL THEN 'workload'
	             WHEN e0.source_identity_account_id IS NOT NULL THEN 'identity'
	             ELSE 'external_principal' END) AS from_type,
	       e0.target_identity_account_id AS to_id, 'identity' AS to_type,
	       e0.state, e0.basis, e0.mechanism, e0.statement_key, e0.conditions::text AS conditions,
	       e0.last_confirmed_at, e0.connector_id, e0.partition_key, NULL::text AS policy_name`
	graphGrantCols = `e0.id AS claim_id,
	       e0.subject_identity_account_id AS from_id, 'identity' AS from_type,
	       e0.entitlement_id AS to_id, 'statement' AS to_type,
	       e0.state, e0.basis, '' AS mechanism, '' AS statement_key, NULL::text AS conditions,
	       e0.last_confirmed_at, e0.connector_id, e0.partition_key, p.display_name AS policy_name`
	graphTargetCols = `e0.id AS claim_id,
	       e0.entitlement_id AS from_id, 'statement' AS from_type,
	       e0.resource_id AS to_id, 'resource' AS to_type,
	       NULL::text AS state, 'declared' AS basis, '' AS mechanism, '' AS statement_key, NULL::text AS conditions,
	       NULL::timestamptz AS last_confirmed_at, NULL::uuid AS connector_id, '' AS partition_key, NULL::text AS policy_name`
)

// graphRelSource is the expression idx_iga_relationship_source is built on:
// written exactly so, or the index is not used.
const graphRelSource = `COALESCE(e0.source_identity_account_id, e0.source_workload_id)`

const graphRelLive = `e0.state IN ('current', 'stale')`

// graphRelForward reads a relationship kind from its source to its target
// identity.
func graphRelForward(kind string, nearTypes ...string) *graphEdgeSpec {
	near := map[string]string{}
	for _, t := range nearTypes {
		near[t] = graphRelSource
	}
	if kind == GraphEdgeCanAssume {
		near[RefExternalPrincipal] = `e0.source_external_principal_id`
	}
	return &graphEdgeSpec{
		kind: kind, claim: RefRelationship,
		from: `iga_relationship e0
		  JOIN iga_identity_accounts far ON far.workspace_id = e0.workspace_id AND far.id = e0.target_identity_account_id`,
		where:  `e0.relationship_type = '` + kind + `' AND far.provider = 'aws' AND ` + SupportedSQL("far", "identity_account_id"),
		live:   graphRelLive,
		near:   near,
		farKey: `far.source_key`,
		cols:   graphRelCols,
	}
}

// graphRelReverse reads a relationship kind from its target identity back to
// its sources, of the one type the kind allows (031's pair check).
func graphRelReverse(kind, farTable, farColumn, farSupport string) *graphEdgeSpec {
	return &graphEdgeSpec{
		kind: kind, claim: RefRelationship,
		from: `iga_relationship e0
		  JOIN ` + farTable + ` far ON far.workspace_id = e0.workspace_id AND far.id = e0.` + farColumn,
		where:  `e0.relationship_type = '` + kind + `' AND far.provider = 'aws' AND ` + SupportedSQL("far", farSupport),
		live:   graphRelLive,
		near:   map[string]string{RefIdentity: `e0.target_identity_account_id`},
		farKey: `far.source_key`,
		cols:   graphRelCols,
	}
}

// graphSpecs is §5.4's edge table, per direction.
var graphSpecs = map[string]map[string]*graphEdgeSpec{
	GraphForward: {
		GraphEdgeExecutesAs:        graphRelForward(GraphEdgeExecutesAs, RefWorkload),
		GraphEdgeTaskExecutionRole: graphRelForward(GraphEdgeTaskExecutionRole, RefWorkload),
		GraphEdgeMemberOf:          graphRelForward(GraphEdgeMemberOf, RefIdentity),
		GraphEdgeCanAssume:         graphRelForward(GraphEdgeCanAssume, RefIdentity),
		GraphEdgeGrant: {
			kind: GraphEdgeGrant, claim: RefGrant,
			from: `iga_access_edges e0
			  JOIN iga_entitlements far ON far.workspace_id = e0.workspace_id AND far.id = e0.entitlement_id
			  LEFT JOIN iga_policy p ON p.workspace_id = far.workspace_id AND p.id = far.policy_id`,
			where: `e0.provider = 'aws' AND far.provider = 'aws' AND far.effect = 'allow' AND ` +
				SupportedSQL("far", "entitlement_id"),
			live:   `e0.state IN ('current', 'stale')`,
			near:   map[string]string{RefIdentity: `e0.subject_identity_account_id`},
			farKey: `far.source_key`,
			cols:   graphGrantCols,
		},
		GraphEdgeTarget: {
			kind: GraphEdgeTarget, claim: RefTarget,
			from: `iga_entitlement_target e0
			  JOIN iga_entitlements st ON st.workspace_id = e0.workspace_id AND st.id = e0.entitlement_id
			  JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id`,
			where: `e0.target_mode = 'resource' AND st.provider = 'aws' AND st.effect = 'allow'
			        AND far.provider = 'aws' AND ` + SupportedSQL("far", "resource_id"),
			live:   `st.lifecycle = 'active'`,
			near:   map[string]string{RefStatement: `e0.entitlement_id`},
			farKey: `far.source_key`,
			cols:   graphTargetCols,
		},
	},
	GraphReverse: {
		GraphEdgeExecutesAs:        graphRelReverse(GraphEdgeExecutesAs, "iga_workload", "source_workload_id", "workload_id"),
		GraphEdgeTaskExecutionRole: graphRelReverse(GraphEdgeTaskExecutionRole, "iga_workload", "source_workload_id", "workload_id"),
		GraphEdgeMemberOf:          graphRelReverse(GraphEdgeMemberOf, "iga_identity_accounts", "source_identity_account_id", "identity_account_id"),
		GraphEdgeCanAssume: {
			// A role's principals are identities or external principals; an
			// external principal has no provider and no support rows, and is
			// readable as it is (D-6).
			kind: GraphEdgeCanAssume, claim: RefRelationship,
			from: `iga_relationship e0
			  LEFT JOIN iga_identity_accounts fi ON fi.workspace_id = e0.workspace_id AND fi.id = e0.source_identity_account_id
			  LEFT JOIN iga_external_principal fe ON fe.workspace_id = e0.workspace_id AND fe.id = e0.source_external_principal_id`,
			where: `e0.relationship_type = 'can_assume'
			        AND ((fi.id IS NOT NULL AND fi.provider = 'aws' AND ` + SupportedSQL("fi", "identity_account_id") + `)
			             OR fe.id IS NOT NULL)`,
			live:   graphRelLive,
			near:   map[string]string{RefIdentity: `e0.target_identity_account_id`},
			farKey: `COALESCE(fi.source_key, fe.source_key)`,
			cols:   graphRelCols,
		},
		GraphEdgeGrant: {
			kind: GraphEdgeGrant, claim: RefGrant,
			from: `iga_access_edges e0
			  JOIN iga_entitlements st ON st.workspace_id = e0.workspace_id AND st.id = e0.entitlement_id
			  JOIN iga_identity_accounts far ON far.workspace_id = e0.workspace_id AND far.id = e0.subject_identity_account_id
			  LEFT JOIN iga_policy p ON p.workspace_id = st.workspace_id AND p.id = st.policy_id`,
			where: `e0.provider = 'aws' AND st.provider = 'aws' AND st.effect = 'allow'
			        AND far.provider = 'aws' AND ` + SupportedSQL("far", "identity_account_id"),
			// Literally <> 'ended': idx_iga_access_edges_entitlement is partial
			// on exactly this predicate.
			live:   `e0.state <> 'ended'`,
			near:   map[string]string{RefStatement: `e0.entitlement_id`},
			farKey: `far.source_key`,
			cols:   graphGrantCols,
		},
		GraphEdgeTarget: {
			kind: GraphEdgeTarget, claim: RefTarget,
			from: `iga_entitlement_target e0
			  JOIN iga_entitlements far ON far.workspace_id = e0.workspace_id AND far.id = e0.entitlement_id`,
			where: `e0.target_mode = 'resource' AND far.provider = 'aws' AND far.effect = 'allow' AND ` +
				SupportedSQL("far", "entitlement_id"),
			live:   `far.lifecycle = 'active'`,
			near:   map[string]string{RefResource: `e0.resource_id`},
			farKey: `far.source_key`,
			cols:   graphTargetCols,
		},
	},
}

// graphSpecFor is the spec for one kind in one direction, or nil.
func graphSpecFor(dir, kind string) *graphEdgeSpec { return graphSpecs[dir][kind] }

// graphNodeTables is each node type's table, for the neighbour counts.
var graphNodeTables = map[string]string{
	RefWorkload:          "iga_workload",
	RefIdentity:          "iga_identity_accounts",
	RefExternalPrincipal: "iga_external_principal",
	RefStatement:         "iga_entitlements",
	RefResource:          "iga_resources",
}

// predicates is the spec's WHERE after the workspace: its own predicates and,
// unless the request asked for ended edges, its lifecycle filter.
func (t *graphTraversal) predicates(s *graphEdgeSpec) string {
	p := s.where
	if !t.ended {
		p += " AND " + s.live
	}
	return p
}

// queryEdges is ONE level's statement for one edge kind: every frontier node
// of the kind's near types at once, ordered by (target source_key, id), at
// most limit rows, after the keyset when one is given (/graph/expand).
func (t *graphTraversal) queryEdges(lv *graphLevel, s *graphEdgeSpec, groups map[string][]uuid.UUID,
	after *graphKeyset, limit int) ([]graphEdgeRow, error) {
	var ors []string
	args := []any{t.q.WS}
	for _, typ := range graphNodeTypes {
		ids := groups[typ]
		expr, ok := s.near[typ]
		if len(ids) == 0 || !ok {
			continue
		}
		ors = append(ors, expr+" IN ?")
		args = append(args, ids)
	}
	if len(ors) == 0 {
		return nil, nil
	}
	sql := `SELECT ` + s.cols + `, ` + s.farKey + ` AS far_key
	          FROM ` + s.from + `
	         WHERE e0.workspace_id = ? AND (` + strings.Join(ors, " OR ") + `)
	           AND ` + t.predicates(s)
	if after != nil {
		sql += ` AND (` + s.farKey + `, e0.id) > (?, ?)`
		args = append(args, after.Key, after.ID)
	}
	sql += ` ORDER BY ` + s.farKey + `, e0.id LIMIT ?`
	args = append(args, limit)
	tx, err := lv.db()
	if err != nil {
		return nil, err
	}
	var rows []graphEdgeRow
	if err := tx.Raw(sql, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// countNeighbours counts, per node, its neighbours of one kind in one
// direction under the SAME predicates the level reads them with -- so a
// frontier count and an expansion agree -- each count capped at CountCap+1
// (a hub costs what a leaf costs). One statement per near type (a count needs
// the near node's table to drive it). A count over the cap is nil: not a
// number that could read as exact.
func (t *graphTraversal) countNeighbours(lv *graphLevel, dir, kind string, nodes []*GraphNode) (map[string]*int64, error) {
	s := graphSpecFor(dir, kind)
	out := map[string]*int64{}
	if s == nil {
		return out, nil
	}
	byType := map[string][]uuid.UUID{}
	refOf := map[uuid.UUID]string{}
	for _, n := range nodes {
		if n == nil {
			continue
		}
		byType[n.typ] = append(byType[n.typ], n.id)
		refOf[n.id] = n.Ref
	}
	for _, typ := range graphNodeTypes {
		expr, ok := s.near[typ]
		if !ok || len(byType[typ]) == 0 {
			continue
		}
		tx, err := lv.db()
		if err != nil {
			return nil, err
		}
		var rows []struct {
			ID uuid.UUID
			N  int64
		}
		if err := tx.Raw(`SELECT n.id, (SELECT count(*) FROM (
		                          SELECT 1 FROM `+s.from+`
		                           WHERE e0.workspace_id = n.workspace_id AND `+expr+` = n.id
		                             AND `+t.predicates(s)+`
		                           LIMIT ?) d) AS n
		                    FROM `+graphNodeTables[typ]+` n
		                   WHERE n.workspace_id = ? AND n.id IN ?`,
			CountCap+1, t.q.WS, byType[typ]).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.N > CountCap {
				out[refOf[r.ID]] = nil
				continue
			}
			n := r.N
			out[refOf[r.ID]] = &n
		}
	}
	return out, nil
}
