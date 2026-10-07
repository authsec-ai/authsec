// Package k8sread serves the Kubernetes half of the identity graph.
//
// A SIBLING OF internal/igaread, NOT AN EDIT OF IT -- the same call made for
// k8sgraph, for the same reason and one more. igaread filters `provider = 'aws'`
// in 112 places, but the deeper obstacle is that its read MODEL is AWS's shape:
// it loads accounts from cloud_connector, keys everything by connector and
// region, and hands the console an account directory. Kubernetes has no
// accounts, no connectors and no regions. It has clusters, namespaces and one
// agent per cluster. Bending one package around both would not produce a shared
// abstraction, it would produce two half-expressed ones.
//
// # WHAT EVERY ANSWER HERE MUST CARRY
//
// SPEC-iga-phase2-graph's invariants are not presentation preferences; they are
// the difference between a governance product and a dashboard:
//
//   - COVERAGE IS A STATE, NEVER A PERCENTAGE. "83% covered" invites a reader
//     to assume the missing 17% resembles the rest. It does not: the unread
//     part is usually the cluster-scoped part, which is where the dangerous
//     grants are.
//   - STALE IS NOT ENDED. A row we could not re-read is still believed, with
//     the time we last confirmed it. Rendering it as gone turns an outage into
//     a revocation.
//   - AN EMPTY LIST IS NOT "NO ACCESS". It may be "not calculated". Every list
//     here reports the sweep that produced it so the caller can tell.
package k8sread

import (
	"sort"
	"time"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Query is one read, bound to a workspace.
type Query struct {
	tx *gorm.DB
	WS uuid.UUID
}

func New(tx *gorm.DB, ws uuid.UUID) *Query { return &Query{tx: tx, WS: ws} }

// Coverage states. A vocabulary, never a number.
const (
	// CoverageComplete: the sweep finished and read cluster-wide. Absence is
	// evidence; the graph is as true as the cluster.
	CoverageComplete = "complete"
	// CoverageNamespaced: the sweep finished but could not read cluster-scoped
	// objects. NOT a smaller answer -- a different one. ClusterRoleBindings are
	// unknown, and that is where cluster-admin lives.
	CoverageNamespaced = "namespaced_only"
	// CoverageIncomplete: a LIST failed. Nothing may be concluded from absence.
	CoverageIncomplete = "incomplete"
	// CoverageNone: no sweep has ever landed for this cluster.
	CoverageNone = "not_swept"
)

// Sweep is the reading behind an answer, so a caller can judge the answer.
type Sweep struct {
	ID            uuid.UUID `json:"id"`
	Generation    int64     `json:"generation"`
	Status        string    `json:"status"`
	Complete      bool      `json:"complete"`
	ClusterScoped bool      `json:"cluster_scoped"`
	Namespaces    []string  `json:"namespaces"`
	ObservedAt    time.Time `json:"observed_at"`

	// Coverage is the state above. AgeSeconds is how old the reading is --
	// reported rather than judged, because what counts as stale is the
	// operator's call and depends on their sweep interval.
	Coverage   string `json:"coverage"`
	AgeSeconds int64  `json:"age_seconds"`

	// Limitation is the one sentence a screen should show when coverage is not
	// complete. Written here, once, so two screens cannot describe the same
	// gap differently.
	Limitation string `json:"limitation,omitempty"`
}

// Cluster is one cluster's inventory and the reading behind it.
type Cluster struct {
	Cluster  string    `json:"cluster"`
	SourceID uuid.UUID `json:"discovery_source_id"`

	ServiceAccounts int `json:"service_accounts"`
	Roles           int `json:"roles"`
	Bindings        int `json:"bindings"`
	Grants          int `json:"grants"`

	// Stale counts rows the latest sweep could not confirm. A non-zero value
	// beside an unchanged inventory is the signal that the agent is losing
	// access to part of the cluster.
	Stale int `json:"stale"`

	LastSweep *Sweep `json:"last_sweep"`
}

// Clusters lists every cluster the workspace has a Kubernetes graph for.
func (q *Query) Clusters() ([]Cluster, error) {
	var rows []struct {
		Cluster  string
		SourceID uuid.UUID
	}
	if err := q.tx.Raw(`
		SELECT DISTINCT cluster, discovery_source_id AS source_id
		  FROM iga_k8s_sweep WHERE workspace_id = ?
		 ORDER BY cluster`, q.WS).Scan(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]Cluster, 0, len(rows))
	for _, r := range rows {
		c := Cluster{Cluster: r.Cluster, SourceID: r.SourceID}
		sw, err := q.latestSweep(r.SourceID, r.Cluster)
		if err != nil {
			return nil, err
		}
		c.LastSweep = sw
		if err := q.countInto(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (q *Query) latestSweep(sourceID uuid.UUID, cluster string) (*Sweep, error) {
	var s models.IGAK8sSweep
	err := q.tx.Where("workspace_id = ? AND discovery_source_id = ? AND cluster = ?",
		q.WS, sourceID, cluster).
		Order("generation DESC").First(&s).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return sweepOf(s), nil
}

// sweepOf is the one place a stored sweep becomes the reading behind an
// answer, so latestSweep and LatestSweeps cannot disagree about it.
func sweepOf(s models.IGAK8sSweep) *Sweep {
	out := &Sweep{
		ID: s.ID, Generation: s.Generation, Status: s.Status,
		Complete: s.Complete, ClusterScoped: s.ClusterScoped,
		Namespaces: []string(s.Namespaces), ObservedAt: s.ObservedAt,
		AgeSeconds: int64(time.Since(s.ObservedAt).Seconds()),
	}
	out.Coverage, out.Limitation = coverageOf(s.Complete, s.ClusterScoped)
	return out
}

// ClusterSweep is one (source, cluster) pair and its newest sweep.
type ClusterSweep struct {
	SourceID uuid.UUID
	Cluster  string
	// Sweep is nil for a Kubernetes source that names its cluster and has
	// never delivered a sweep: coverage not_swept.
	Sweep *Sweep
}

// LatestSweeps is latestSweep for every (source, cluster) of the workspace in
// two statements, plus the Kubernetes sources that have never swept (their
// cluster_name, with a nil Sweep). Ordered by cluster, then source, so a
// caller's output is deterministic.
func (q *Query) LatestSweeps() ([]ClusterSweep, error) {
	var sweeps []models.IGAK8sSweep
	// DISTINCT ON with generation DESC is latestSweep's ORDER BY ... First,
	// once per (source, cluster).
	if err := q.tx.Raw(`
		SELECT DISTINCT ON (discovery_source_id, cluster) *
		  FROM iga_k8s_sweep WHERE workspace_id = ?
		 ORDER BY discovery_source_id, cluster, generation DESC`, q.WS).Scan(&sweeps).Error; err != nil {
		return nil, err
	}
	out := make([]ClusterSweep, 0, len(sweeps))
	for _, s := range sweeps {
		out = append(out, ClusterSweep{SourceID: s.DiscoverySourceID, Cluster: s.Cluster, Sweep: sweepOf(s)})
	}

	var idle []struct {
		ID          uuid.UUID
		ClusterName string
	}
	if err := q.tx.Raw(`
		SELECT s.id, s.cluster_name
		  FROM discovery_sources s
		 WHERE s.workspace_id = ? AND s.kind = ? AND s.cluster_name <> ''
		   AND NOT EXISTS (SELECT 1 FROM iga_k8s_sweep w
		                    WHERE w.workspace_id = s.workspace_id AND w.discovery_source_id = s.id)`,
		q.WS, models.DiscoverySourceK8sWebhook).Scan(&idle).Error; err != nil {
		return nil, err
	}
	for _, s := range idle {
		out = append(out, ClusterSweep{SourceID: s.ID, Cluster: s.ClusterName})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cluster != out[j].Cluster {
			return out[i].Cluster < out[j].Cluster
		}
		return out[i].SourceID.String() < out[j].SourceID.String()
	})
	return out, nil
}

// SweepKey is one (source, cluster) pair.
type SweepKey struct {
	SourceID uuid.UUID
	Cluster  string
}

// LatestProjectedSweeps is the newest sweep of each (source, cluster) whose
// rows were applied to the shared tables (status projected): the reading the
// inventory's Kubernetes rows actually come from. It differs from
// LatestSweeps when the newest sweep has arrived and not been applied, or has
// failed to apply: that sweep's coverage describes rows that do not exist yet,
// so a caller reporting what the inventory covers must use this one.
func (q *Query) LatestProjectedSweeps() (map[SweepKey]*Sweep, error) {
	var sweeps []models.IGAK8sSweep
	if err := q.tx.Raw(`
		SELECT DISTINCT ON (discovery_source_id, cluster) *
		  FROM iga_k8s_sweep WHERE workspace_id = ? AND status = ?
		 ORDER BY discovery_source_id, cluster, generation DESC`, q.WS, models.K8sSweepProjected).Scan(&sweeps).Error; err != nil {
		return nil, err
	}
	out := make(map[SweepKey]*Sweep, len(sweeps))
	for _, s := range sweeps {
		out[SweepKey{SourceID: s.DiscoverySourceID, Cluster: s.Cluster}] = sweepOf(s)
	}
	return out, nil
}

// Affects is the short sentence saying what a coverage state means for the
// inventory of its cluster, for a coverage note. Limitation is the long form
// for a sweep's own header; this is the one-line form a list's coverage
// carries, written here beside the states so the two cannot drift.
func Affects(coverage string) string {
	switch coverage {
	case CoverageComplete:
		return "nothing: the latest sweep read the whole cluster"
	case CoverageNamespaced:
		return "cluster-scoped roles and bindings were not read, so cluster-wide access is not covered"
	case CoverageIncomplete:
		return "a list failed in the latest sweep, so absence from this cluster's inventory proves nothing"
	default:
		return "no sweep has been received, so this cluster has no inventory yet"
	}
}

// coverageOf turns the two sweep flags into a state and the sentence that
// explains it. One place, so no screen invents its own wording for a gap.
func coverageOf(complete, clusterScoped bool) (string, string) {
	switch {
	case !complete:
		return CoverageIncomplete, "A list failed during this sweep, so anything " +
			"missing from it may simply not have been read. Nothing was retired."
	case !clusterScoped:
		return CoverageNamespaced, "This sweep could not read cluster-scoped objects. " +
			"ClusterRoles and ClusterRoleBindings are not covered -- which is where " +
			"cluster-wide access is granted -- so absence of one proves nothing."
	default:
		return CoverageComplete, ""
	}
}

func (q *Query) countInto(c *Cluster) error {
	type row struct{ N int }
	one := func(sql string, args ...any) (int, error) {
		var r row
		if err := q.tx.Raw(sql, args...).Scan(&r).Error; err != nil {
			return 0, err
		}
		return r.N, nil
	}
	// Every count is this cluster's, not the workspace's: a row belongs to a
	// cluster by its key's "k8s␟<cluster>␟" prefix (k8sgraph.Key). Compared
	// with left() rather than LIKE so a cluster name needs no escaping and
	// "prod" never matches "prod2". Two clusters that share a name share
	// keys, and so share these counts (D-112).
	prefix := k8sgraph.ClusterPrefix(c.Cluster) // "k8s␟<cluster>␟"
	var err error
	if c.ServiceAccounts, err = one(`
		SELECT count(*) AS n FROM iga_identity_accounts
		 WHERE workspace_id = ? AND provider = ? AND lifecycle = 'active'
		   AND account_kind = 'k8s_service_account'
		   AND left(source_key, length(?)) = ?`, q.WS, models.ProviderK8s, prefix, prefix); err != nil {
		return err
	}
	if c.Roles, err = one(`
		SELECT count(*) AS n FROM iga_policy
		 WHERE workspace_id = ? AND provider = ? AND lifecycle = 'active'
		   AND left(source_key, length(?)) = ?`,
		q.WS, models.ProviderK8s, prefix, prefix); err != nil {
		return err
	}
	if c.Bindings, err = one(`
		SELECT count(*) AS n FROM iga_policy_assignment
		 WHERE workspace_id = ? AND discovery_source_id = ? AND state <> 'ended'`,
		q.WS, c.SourceID); err != nil {
		return err
	}
	if c.Grants, err = one(`
		SELECT count(*) AS n FROM iga_access_edges
		 WHERE workspace_id = ? AND provider = ? AND state = 'current'
		   AND left(source_key, length(?)) = ?`,
		q.WS, models.ProviderK8s, prefix, prefix); err != nil {
		return err
	}
	if c.Stale, err = one(`
		SELECT count(*) AS n FROM iga_access_edges
		 WHERE workspace_id = ? AND provider = ? AND state = 'stale'
		   AND left(source_key, length(?)) = ?`,
		q.WS, models.ProviderK8s, prefix, prefix); err != nil {
		return err
	}
	return nil
}

/* ------------------------------- access rows ------------------------------- */

// accessRowsSQL is every live access row of the HOLDERS BOUND TO IT -- a
// page's identities, or one identity -- never the whole workspace's (D-113):
// the flat form of the two paths the graph walk takes from an identity to a
// rule (traverse_edges.go's forward specs, D-110, D-112):
//
//	direct  identity -grant-> rule
//	group   identity -member_of-> group -grant-> rule
//
// with the walk's own predicates: a grant and a membership are live when
// their state is current or stale (graphRelLive; ended is hidden), a group is
// a Kubernetes identity with a support row (D-6's readability predicate,
// igaread.SupportedSQL -- written out here because igaread imports this
// package, not the reverse), and every join is bound to the row's workspace.
// A grant with no rule (its binding's role was not in the sweep) is a row
// too, through either path: unresolved is not none.
//
// A group-derived row's state is the weaker of its two links: current only
// when both the membership and the group's grant are current, stale when
// either is stale. One grant of one group reached through two live
// memberships of the same holder is one row (the current membership wins):
// the row is the grant, and the via names the group it came through.
//
// The holder restriction is in both branches, on the scanned rows -- the
// direct grant's subject, the membership's source -- so a list's counts cost
// its page, not its workspace (idx_iga_access_edges_subject_identity;
// idx_iga_relationship_source, whose COALESCE expression the second
// predicate spells out so the index applies).
//
// Columns: holder_id, edge_id, entitlement_id, state, group_id,
// membership_state, membership_basis. Bind values: accessRowsArgs.
const accessRowsSQL = `
	SELECT e.subject_identity_account_id AS holder_id, e.id AS edge_id, e.entitlement_id, e.state AS state,
	       NULL::uuid AS group_id, NULL::text AS membership_state, NULL::text AS membership_basis
	  FROM iga_access_edges e
	 WHERE e.workspace_id = ? AND e.subject_identity_account_id IN ?
	   AND e.provider = 'k8s' AND e.state IN ('current', 'stale')
	UNION ALL
	SELECT * FROM (
	  SELECT DISTINCT ON (m.source_identity_account_id, e.id)
	         m.source_identity_account_id AS holder_id, e.id AS edge_id, e.entitlement_id,
	         CASE WHEN e.state = 'current' AND m.state = 'current' THEN 'current' ELSE 'stale' END AS state,
	         g.id AS group_id, m.state AS membership_state, m.basis AS membership_basis
	    FROM iga_relationship m
	    JOIN iga_identity_accounts g
	      ON g.workspace_id = m.workspace_id AND g.id = m.target_identity_account_id AND g.provider = 'k8s'
	     AND EXISTS (SELECT 1 FROM iga_object_support s0
	                  WHERE s0.workspace_id = g.workspace_id AND s0.identity_account_id = g.id)
	    JOIN iga_access_edges e
	      ON e.workspace_id = g.workspace_id AND e.subject_identity_account_id = g.id
	     AND e.provider = 'k8s' AND e.state IN ('current', 'stale')
	   WHERE m.workspace_id = ? AND m.relationship_type = 'member_of'
	     AND COALESCE(m.source_identity_account_id, m.source_workload_id) IN ?
	     AND m.source_identity_account_id IN ?
	     AND m.state IN ('current', 'stale')
	   ORDER BY m.source_identity_account_id, e.id, (m.state = 'current') DESC) via`

// accessRowsArgs is accessRowsSQL's bind values for the holders. Never call
// it with no holder: the caller has nothing to count.
func accessRowsArgs(ws uuid.UUID, holders []uuid.UUID) []any {
	return []any{ws, holders, ws, holders, holders}
}

// heldCounts is how much each holder can do: the current and stale rows of
// its access (accessRowsSQL), and whether any current one comes from a
// wildcard rule.
type heldCounts struct {
	Grants   int
	Stale    int
	Wildcard bool
}

// countsFor counts the access rows of the holders, and only theirs (D-113):
// the one statement behind every list's grants, stale and wildcard, so a
// list row's counts equal its access summary's partial and stale (D-112).
func (q *Query) countsFor(holders []uuid.UUID) (map[uuid.UUID]heldCounts, error) {
	out := map[uuid.UUID]heldCounts{}
	if len(holders) == 0 {
		return out, nil
	}
	var rows []struct {
		HolderID uuid.UUID
		Grants   int
		Stale    int
		Wildcard bool
	}
	args := append(accessRowsArgs(q.WS, holders), q.WS)
	if err := q.tx.Raw(`
		WITH acc AS (`+accessRowsSQL+`)
		SELECT acc.holder_id,
		       COUNT(*) FILTER (WHERE acc.state = 'current') AS grants,
		       COUNT(*) FILTER (WHERE acc.state = 'stale')   AS stale,
		       COALESCE(bool_or((n.normalized_rights->>'wildcard')::bool)
		                FILTER (WHERE acc.state = 'current'), false) AS wildcard
		  FROM acc
		  LEFT JOIN iga_entitlements n
		         ON n.workspace_id = ? AND n.id = acc.entitlement_id
		 GROUP BY acc.holder_id`, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.HolderID] = heldCounts{Grants: r.Grants, Stale: r.Stale, Wildcard: r.Wildcard}
	}
	return out, nil
}

// Identity is one Kubernetes identity -- a ServiceAccount, or a User or Group
// a binding names -- with how much it can do.
type Identity struct {
	ID uuid.UUID `json:"id"`
	// Anchor is the RBAC subject name: system:serviceaccount:<ns>:<name> for
	// a ServiceAccount, the User's or Group's own name otherwise.
	Anchor string `json:"anchor"`
	// Namespace is a ServiceAccount's; "" for a User or Group, which
	// Kubernetes does not scope.
	Namespace string `json:"namespace"`
	Lifecycle string `json:"lifecycle"`

	// Kind is the account kind: k8s_service_account | k8s_user | k8s_group
	// (D-113). Name is the object's own name (a ServiceAccount's without its
	// namespace), Cluster the cluster its key names, LastSeenAt when a sweep
	// last confirmed it.
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Cluster    string    `json:"cluster"`
	LastSeenAt time.Time `json:"last_seen_at"`
	// Members is set for a group only: its live (current or stale) member_of
	// rows -- the ServiceAccounts the projection places in it. Users who
	// authenticate into a group are not readable from RBAC, so it is a lower
	// bound, never "everyone in the group".
	Members *int `json:"members,omitempty"`

	// Grants counts the current rows of its access (AccessFor): its own
	// grants and, for a ServiceAccount, those reached through implicit group
	// membership. Equal to that response's summary.partial.
	Grants int `json:"grants"`
	// Wildcard is true when any current grant reaching this account -- directly
	// or through a group -- comes from a rule with `*` in a group, resource or
	// verb. Surfaced rather than expanded: the rule is the fact, and an
	// expansion is an interpretation with an expiry.
	Wildcard bool `json:"wildcard"`
	// Stale counts the rows that could not be reconfirmed by the latest sweep
	// (the grant or the membership it came through). Equal to summary.stale.
	Stale int `json:"stale"`
}

// Identities lists the ServiceAccounts in the workspace's Kubernetes graph,
// the first page of ListIdentities' default filter. Kept for its callers;
// its clamp is the original one.
func (q *Query) Identities(limit int) ([]Identity, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	page, err := q.ListIdentities(IdentityFilter{Limit: limit})
	return page.Items, err
}

// Workload is a runtime object and what it runs as.
type Workload struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Namespace   string    `json:"namespace"`
	Lifecycle   string    `json:"lifecycle"`

	// RunsAs is the ServiceAccount this workload executes as, when one was
	// resolvable. Empty is a real answer: a workload whose identity we could
	// not determine is a gap, not an absence of access.
	RunsAs   string     `json:"runs_as,omitempty"`
	RunsAsID *uuid.UUID `json:"runs_as_id,omitempty"`
	// Basis is 'observed' when the agent saw the Pod's serviceAccountName and
	// 'declared' when only the configured anchor is known.
	Basis string `json:"basis,omitempty"`
	// Grants is how many current declared grants that identity holds -- its
	// own and those reached through implicit group membership -- the same
	// count as its Identities row and its access summary's partial.
	Grants int `json:"grants"`
}

// Workloads lists the runtime objects and their execution identities, by
// name (then id). The page is chosen first and its identities' counts are
// read for that page alone (D-113): ordering by grants would need every
// identity's count before the first row could be chosen.
func (q *Query) Workloads(limit int) ([]Workload, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Workload
	if err := q.tx.Raw(`
		SELECT w.id,
		       w.display_name,
		       COALESCE(w.provider_attrs->>'namespace', '') AS namespace,
		       w.lifecycle,
		       COALESCE(i.display_name, '') AS runs_as,
		       i.id   AS runs_as_id,
		       COALESCE(r.basis, '') AS basis
		  FROM iga_workload w
		  LEFT JOIN iga_relationship r
		         ON r.workspace_id = w.workspace_id
		        AND r.source_workload_id = w.id
		        AND r.relationship_type = 'executes_as'
		        AND r.state <> 'ended'
		  LEFT JOIN iga_identity_accounts i
		         ON i.workspace_id = w.workspace_id AND i.id = r.target_identity_account_id
		 WHERE w.workspace_id = ? AND w.provider = ?
		 ORDER BY w.display_name, w.id, i.id
		 LIMIT ?`, q.WS, models.ProviderK8s, limit).Scan(&out).Error; err != nil {
		return nil, err
	}
	var holders []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, w := range out {
		if w.RunsAsID != nil && !seen[*w.RunsAsID] {
			seen[*w.RunsAsID] = true
			holders = append(holders, *w.RunsAsID)
		}
	}
	counts, err := q.countsFor(holders)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if id := out[i].RunsAsID; id != nil {
			out[i].Grants = counts[*id].Grants
		}
	}
	return out, nil
}

// Grant is one resolved step of what an identity can do.
//
// It is deliberately the WHOLE chain in one row -- binding, role, rule -- rather
// than three joined objects, because the question a reviewer asks is "why can
// this account read secrets", and the answer is the chain. A grant reached
// through a group carries the group in Via: the chain then starts with the
// membership.
type Grant struct {
	RoleName string `json:"role_name"`
	RoleKind string `json:"role_kind"` // k8s_role | k8s_cluster_role
	// Binding is the assignment's source key, as before ("" when the grant
	// has no assignment row: a binding whose role was never seen).
	// BindingName is the binding's own name, read back from the assignment's
	// key or, without one, the grant's.
	Binding     string `json:"binding"`
	BindingName string `json:"binding_name"`
	BindKind    string `json:"binding_kind"`
	// Namespace is the ROLE's namespace ("" for a ClusterRole), as before.
	// Where the rule applies is EffectiveScope's, never this field's.
	Namespace string `json:"namespace"`
	// EffectiveScope is where the rule applies (D-109): {kind: namespace,
	// namespace: <the binding's>} for a RoleBinding -- of a Role or of a
	// ClusterRole -- and {kind: cluster, namespace: null} for a
	// ClusterRoleBinding. Read from the binding's key -- the assignment's, or
	// for a binding whose role was never seen (no assignment row) the grant's
	// own -- so an unresolved grant says where it would apply too. Null only
	// when neither key names a binding.
	EffectiveScope *EffectiveScope `json:"effective_scope"`

	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"api_groups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resource_names,omitempty"`
	NonResourceURLs []string `json:"non_resource_urls,omitempty"`
	Wildcard        bool     `json:"wildcard"`
	// Constrained: the rule names specific instances, so it grants far less
	// than the same rule without them.
	Constrained bool `json:"constrained"`

	// State is current | stale; for a group-derived grant, the weaker of the
	// grant's and the membership's (Via.State is the membership's own).
	State string `json:"state"`

	// Basis is the grant's: always 'declared' for Kubernetes -- RBAC says what
	// is allowed; nothing observed a request.
	Basis string `json:"basis"`
	// CalculationState is always 'partial' for Kubernetes: the chain is
	// declared, and the layers that can still refuse a request (admission,
	// token automount and audiences, resourceNames semantics) are not read.
	CalculationState string `json:"calculation_state"`
	// Resolved: binding -> role -> rule all resolved. False is a binding whose
	// role was not in the sweep: no rule, and the honest record that something
	// was bound to something we could not see.
	Resolved bool `json:"resolved"`

	// Via is null for a grant held directly, and names the group for one
	// reached through group membership.
	Via *Via `json:"via"`
}

// EffectiveScope is where a grant's rule applies (D-109), the shape of the
// graph's grant edge field of the same name.
type EffectiveScope struct {
	Kind      string  `json:"kind"`
	Namespace *string `json:"namespace"`
}

// Via is the membership a group-derived grant came through: the graph walk's
// member_of edge, flattened onto the grant (D-110, D-112).
type Via struct {
	Relationship string    `json:"relationship"` // member_of
	Group        string    `json:"group"`        // the group's name, e.g. system:serviceaccounts:shop
	GroupID      uuid.UUID `json:"group_id"`
	// ImplicitMembership: the holder is a ServiceAccount and the group is one
	// the API server places it in (system:serviceaccounts,
	// system:serviceaccounts:<ns>, system:authenticated); no object declares
	// the membership. The graph's member_of edge carries the same flag.
	ImplicitMembership bool   `json:"implicit_membership"`
	State              string `json:"state"` // the membership's: current | stale
	Basis              string `json:"basis"` // the membership's: declared
}

// AccessSummary says how much of an answer was actually calculated, so an empty
// or short list is never mistaken for "no access".
//
// Every row is counted in exactly one of each pair: partial + stale = total,
// resolved + unresolved = total, direct + via_group = total.
type AccessSummary struct {
	Total int `json:"total"`
	// Partial counts the current rows (calculation_state partial: declared,
	// not evaluated); Stale the rows not reconfirmed by the latest sweep.
	Partial int `json:"partial"`
	Stale   int `json:"stale"`
	// Resolved counts rows whose binding -> role -> rule chain resolved;
	// Unresolved rows whose binding names a role the sweep did not see.
	Resolved   int `json:"resolved"`
	Unresolved int `json:"unresolved"`
	// Direct counts grants held by the identity itself; ViaGroup grants
	// reached through its group memberships.
	Direct   int `json:"direct"`
	ViaGroup int `json:"via_group"`

	// Note is always set: grants are declared, not evaluated, and saying so on
	// every response keeps the claim attached to its limits.
	Note string `json:"note"`
}

// AccessNote is the summary's note. No word in it claims that access is
// evaluated: the route reports declared grants only (D-112).
const AccessNote = "Kubernetes grants are declared, not evaluated (basis declared, calculation_state " +
	"partial): RBAC is allow-only, so a resolved chain is what RBAC allows, but admission control, " +
	"token automount and audiences, and resourceNames semantics are not read, so whether a request " +
	"would succeed is unknown. A RoleBinding confines even a ClusterRole's rule to its namespace. " +
	"Grants reached through group membership name the group. A grant with no rule is a binding " +
	"whose role was not in the sweep."

// AccessFor answers "what can this identity do, and how much of that did we
// actually work out": its own grants and those of the groups it is a member
// of, each with where its rule applies. Any Kubernetes identity (D-113): a
// User's or Group's rows are its own grants -- the projection records no
// membership of either.
func (q *Query) AccessFor(identityID uuid.UUID) ([]Grant, AccessSummary, error) {
	// Scanned flat, then shaped: the grant's nested fields are built here,
	// never by the scanner.
	var rows []struct {
		RoleName         string
		RoleKind         string
		Binding          string
		BindKind         string
		BindingKey       string
		Namespace        string
		State            string
		Basis            string
		CalculationState string
		Resolved         bool
		Wildcard         bool
		Constrained      bool
		Native           []byte
		GroupID          *uuid.UUID
		GroupName        string
		GroupKey         string
		HolderKind       string
		MembershipState  string
		MembershipBasis  string
	}
	err := q.tx.Raw(`
		WITH acc AS (`+accessRowsSQL+`)
		SELECT p.display_name AS role_name,
		       p.policy_kind  AS role_kind,
		       COALESCE(a.source_key, '') AS binding,
		       COALESCE(a.assignment_kind, '') AS bind_kind,
		       -- The binding a grant came through: its assignment's key, or --
		       -- for a grant whose role was never seen, which has no assignment
		       -- row -- the grant's own key, which starts with the same
		       -- binding key (k8sgraph.Edge; the graph names an unresolved
		       -- binding from it too, k8s_unresolved_bindings).
		       COALESCE(a.source_key, e.source_key, '') AS binding_key,
		       -- iga_policy has no namespace column and no provider_attrs, so
		       -- the namespace is decoded from the source key. The format is
		       -- k8sgraph.RoleKey's: k8s <US> cluster <US> role <US> ns <US> name
		       -- for a Role, and k8s <US> cluster <US> clusterrole <US> name for
		       -- a ClusterRole, which has no namespace by definition. Decoding a
		       -- key is not the same as formatting one -- k8sgraph.RoleKey
		       -- remains the only place a key is BUILT -- but if that format
		       -- ever changes, this changes with it.
		       CASE WHEN p.policy_kind = 'k8s_role'
		            THEN split_part(p.source_key, E'\037', 4) ELSE '' END AS namespace,
		       acc.state,
		       e.basis,
		       e.calculation_state,
		       e.entitlement_id IS NOT NULL AS resolved,
		       COALESCE((n.normalized_rights->>'wildcard')::bool, false)    AS wildcard,
		       COALESCE((n.normalized_rights->>'constrained')::bool, false) AS constrained,
		       n.native_rights AS native,
		       acc.group_id,
		       COALESCE(g.display_name, '') AS group_name,
		       COALESCE(g.source_key, '')   AS group_key,
		       COALESCE(h.account_kind, '') AS holder_kind,
		       COALESCE(acc.membership_state, '') AS membership_state,
		       COALESCE(acc.membership_basis, '') AS membership_basis
		  FROM acc
		  JOIN iga_access_edges e
		    ON e.workspace_id = ? AND e.id = acc.edge_id
		  LEFT JOIN iga_entitlements n
		         ON n.workspace_id = e.workspace_id AND n.id = e.entitlement_id
		  LEFT JOIN iga_policy_assignment a
		         ON a.workspace_id = e.workspace_id AND a.id = e.assignment_id
		  LEFT JOIN iga_policy p
		         ON p.workspace_id = e.workspace_id AND p.id = a.policy_id
		  LEFT JOIN iga_identity_accounts g
		         ON g.workspace_id = e.workspace_id AND g.id = acc.group_id
		  LEFT JOIN iga_identity_accounts h
		         ON h.workspace_id = e.workspace_id AND h.id = acc.holder_id
		 WHERE acc.holder_id = ?
		 ORDER BY wildcard DESC, p.display_name, acc.group_id IS NOT NULL, g.display_name,
		          a.source_key, e.id`,
		append(accessRowsArgs(q.WS, []uuid.UUID{identityID}), q.WS, identityID)...).Scan(&rows).Error
	if err != nil {
		return nil, AccessSummary{}, err
	}

	out := make([]Grant, 0, len(rows))
	sum := AccessSummary{Total: len(rows), Note: AccessNote}

	for i := range rows {
		r := rows[i]
		g := Grant{
			RoleName: r.RoleName, RoleKind: r.RoleKind, Binding: r.Binding, BindKind: r.BindKind,
			Namespace: r.Namespace, State: r.State, Basis: r.Basis, CalculationState: r.CalculationState,
			Resolved: r.Resolved, Wildcard: r.Wildcard, Constrained: r.Constrained,
		}
		expandRights(&g, r.Native)
		if r.BindingKey != "" {
			kind, ns := BindingScope(r.BindingKey)
			g.EffectiveScope = &EffectiveScope{Kind: kind}
			if ns != "" {
				g.EffectiveScope.Namespace = &ns
			}
			if k, ok := k8sgraph.ParseKey(r.BindingKey); ok {
				g.BindingName = k.Name
			}
		}
		if r.GroupID != nil {
			g.Via = &Via{
				Relationship: models.RelTypeMemberOf,
				Group:        r.GroupName, GroupID: *r.GroupID,
				ImplicitMembership: r.HolderKind == models.K8sAccountKindServiceAccount &&
					ImplicitGroupKey(r.GroupKey),
				State: r.MembershipState, Basis: r.MembershipBasis,
			}
			sum.ViaGroup++
		} else {
			sum.Direct++
		}
		if g.State == models.RelStale {
			sum.Stale++
		} else {
			sum.Partial++
		}
		if g.Resolved {
			sum.Resolved++
		} else {
			sum.Unresolved++
		}
		out = append(out, g)
	}
	return out, sum, nil
}
