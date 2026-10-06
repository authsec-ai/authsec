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
	var err error
	if c.ServiceAccounts, err = one(`
		SELECT count(*) AS n FROM iga_identity_accounts
		 WHERE workspace_id = ? AND provider = ? AND lifecycle = 'active'
		   AND account_kind = 'k8s_service_account'`, q.WS, models.ProviderK8s); err != nil {
		return err
	}
	if c.Roles, err = one(`
		SELECT count(*) AS n FROM iga_policy
		 WHERE workspace_id = ? AND provider = ? AND lifecycle = 'active'`,
		q.WS, models.ProviderK8s); err != nil {
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
		 WHERE workspace_id = ? AND provider = ? AND state = 'current'`,
		q.WS, models.ProviderK8s); err != nil {
		return err
	}
	if c.Stale, err = one(`
		SELECT count(*) AS n FROM iga_access_edges
		 WHERE workspace_id = ? AND provider = ? AND state = 'stale'`,
		q.WS, models.ProviderK8s); err != nil {
		return err
	}
	return nil
}

// Identity is one ServiceAccount, with how much it can do.
type Identity struct {
	ID        uuid.UUID `json:"id"`
	Anchor    string    `json:"anchor"` // system:serviceaccount:<ns>:<name>
	Namespace string    `json:"namespace"`
	Lifecycle string    `json:"lifecycle"`

	Grants int `json:"grants"`
	// Wildcard is true when any grant reaching this account comes from a rule
	// with `*` in a group, resource or verb. Surfaced rather than expanded: the
	// rule is the fact, and an expansion is an interpretation with an expiry.
	Wildcard bool `json:"wildcard"`
	// Stale grants exist but could not be reconfirmed by the latest sweep.
	Stale int `json:"stale"`
}

// Identities lists the ServiceAccounts in the workspace's Kubernetes graph.
func (q *Query) Identities(limit int) ([]Identity, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Identity
	err := q.tx.Raw(`
		SELECT i.id,
		       i.display_name AS anchor,
		       COALESCE(i.provider_attrs->>'namespace', '') AS namespace,
		       i.lifecycle,
		       COUNT(*) FILTER (WHERE e.state = 'current') AS grants,
		       COUNT(*) FILTER (WHERE e.state = 'stale')   AS stale,
		       COALESCE(bool_or((n.normalized_rights->>'wildcard')::bool)
		                FILTER (WHERE e.state = 'current'), false) AS wildcard
		  FROM iga_identity_accounts i
		  LEFT JOIN iga_access_edges e
		         ON e.workspace_id = i.workspace_id
		        AND e.subject_identity_account_id = i.id
		        AND e.provider = ?
		  LEFT JOIN iga_entitlements n
		         ON n.workspace_id = i.workspace_id AND n.id = e.entitlement_id
		 WHERE i.workspace_id = ? AND i.provider = ?
		   AND i.account_kind = 'k8s_service_account'
		 GROUP BY i.id, i.display_name, i.provider_attrs, i.lifecycle
		 ORDER BY grants DESC, i.display_name
		 LIMIT ?`, models.ProviderK8s, q.WS, models.ProviderK8s, limit).Scan(&out).Error
	return out, err
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
	// Grants is how much that identity can do. This is the number the product
	// exists to produce: what this agent can actually reach.
	Grants int `json:"grants"`
}

// Workloads lists the runtime objects and their execution identities.
func (q *Query) Workloads(limit int) ([]Workload, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Workload
	err := q.tx.Raw(`
		SELECT w.id,
		       w.display_name,
		       COALESCE(w.provider_attrs->>'namespace', '') AS namespace,
		       w.lifecycle,
		       COALESCE(i.display_name, '') AS runs_as,
		       i.id   AS runs_as_id,
		       COALESCE(r.basis, '') AS basis,
		       (SELECT count(*) FROM iga_access_edges e
		         WHERE e.workspace_id = w.workspace_id
		           AND e.provider = ?
		           AND e.subject_identity_account_id = i.id
		           AND e.state = 'current') AS grants
		  FROM iga_workload w
		  LEFT JOIN iga_relationship r
		         ON r.workspace_id = w.workspace_id
		        AND r.source_workload_id = w.id
		        AND r.relationship_type = 'executes_as'
		        AND r.state <> 'ended'
		  LEFT JOIN iga_identity_accounts i
		         ON i.workspace_id = w.workspace_id AND i.id = r.target_identity_account_id
		 WHERE w.workspace_id = ? AND w.provider = ?
		 ORDER BY grants DESC, w.display_name
		 LIMIT ?`, models.ProviderK8s, q.WS, models.ProviderK8s, limit).Scan(&out).Error
	return out, err
}

// Grant is one resolved step of what an identity can do.
//
// It is deliberately the WHOLE chain in one row -- binding, role, rule -- rather
// than three joined objects, because the question a reviewer asks is "why can
// this account read secrets", and the answer is the chain.
type Grant struct {
	RoleName  string `json:"role_name"`
	RoleKind  string `json:"role_kind"` // k8s_role | k8s_cluster_role
	Binding   string `json:"binding"`
	BindKind  string `json:"binding_kind"`
	Namespace string `json:"namespace"`

	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"api_groups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resource_names,omitempty"`
	NonResourceURLs []string `json:"non_resource_urls,omitempty"`
	Wildcard        bool     `json:"wildcard"`
	// Constrained: the rule names specific instances, so it grants far less
	// than the same rule without them.
	Constrained bool `json:"constrained"`

	State string `json:"state"` // current | stale

	// CalculationState is 'complete' only when binding -> role -> rule all
	// resolved. 'partial' means the role was not in the sweep, and the
	// conclusion is 'unknown' -- the honest record that something was bound to
	// something we could not see.
	CalculationState    string `json:"calculation_state"`
	EffectiveConclusion string `json:"effective_conclusion"`
}

// AccessSummary says how much of an answer was actually calculated, so an empty
// or short list is never mistaken for "no access".
type AccessSummary struct {
	Total    int `json:"total"`
	Complete int `json:"complete"`
	Partial  int `json:"partial"`
	Stale    int `json:"stale"`

	// Note is always set. Every Kubernetes grant is declared, not evaluated
	// (calculation_state partial, effective_conclusion unknown): RBAC says what
	// is allowed, and the layers that can still refuse a request are not read.
	// Saying so on every response keeps the claim attached to its limits.
	Note string `json:"note"`
}

// AccessFor answers "what can this ServiceAccount do, and how much of that did
// we actually work out".
func (q *Query) AccessFor(identityID uuid.UUID) ([]Grant, AccessSummary, error) {
	var rows []struct {
		Grant
		Native []byte
	}
	err := q.tx.Raw(`
		SELECT p.display_name AS role_name,
		       p.policy_kind  AS role_kind,
		       COALESCE(a.source_key, '') AS binding,
		       COALESCE(a.assignment_kind, '') AS bind_kind,
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
		       e.state,
		       e.calculation_state,
		       e.effective_conclusion,
		       COALESCE((n.normalized_rights->>'wildcard')::bool, false)    AS wildcard,
		       COALESCE((n.normalized_rights->>'constrained')::bool, false) AS constrained,
		       n.native_rights AS native
		  FROM iga_access_edges e
		  LEFT JOIN iga_entitlements n
		         ON n.workspace_id = e.workspace_id AND n.id = e.entitlement_id
		  LEFT JOIN iga_policy_assignment a
		         ON a.workspace_id = e.workspace_id AND a.id = e.assignment_id
		  LEFT JOIN iga_policy p
		         ON p.workspace_id = e.workspace_id AND p.id = a.policy_id
		 WHERE e.workspace_id = ? AND e.provider = ?
		   AND e.subject_identity_account_id = ?
		   AND e.state <> 'ended'
		 ORDER BY wildcard DESC, p.display_name`,
		q.WS, models.ProviderK8s, identityID).Scan(&rows).Error
	if err != nil {
		return nil, AccessSummary{}, err
	}

	out := make([]Grant, 0, len(rows))
	sum := AccessSummary{Total: len(rows), Note: "Kubernetes grants are declared, not " +
		"evaluated: RBAC is allow-only, so a resolved chain is what RBAC allows, but admission " +
		"control, token automount and audiences, and resourceNames semantics are not evaluated, " +
		"so no grant is concluded effective. A grant with no rule is a binding whose role was " +
		"not in the sweep."}

	for i := range rows {
		g := rows[i].Grant
		expandRights(&g, rows[i].Native)
		switch {
		case g.State == models.RelStale:
			sum.Stale++
		case g.CalculationState == "complete":
			sum.Complete++
		default:
			sum.Partial++
		}
		out = append(out, g)
	}
	return out, sum, nil
}
