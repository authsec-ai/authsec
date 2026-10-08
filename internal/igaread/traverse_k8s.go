package igaread

// Kubernetes on the traversal routes (/graph, /graph/expand, /graph/path).
//
// The Kubernetes projection (internal/k8sgraph, services/k8s_rbac_service.go)
// writes into the SAME tables as AWS, under provider 'k8s':
//
//	workload    iga_workload, runtime_kind k8s_<kind>
//	identity    iga_identity_accounts, account_kind k8s_service_account |
//	            k8s_user | k8s_group
//	statement   iga_entitlements, one per PolicyRule of a Role or ClusterRole
//	            (iga_policy, policy_kind k8s_role | k8s_cluster_role)
//	executes_as iga_relationship, workload -> ServiceAccount, basis observed
//	            (the Pod's serviceAccountName was seen) or declared (only the
//	            configured anchor is known)
//	member_of   iga_relationship, ServiceAccount -> the implicit groups the
//	            API server puts it in (system:serviceaccounts,
//	            system:serviceaccounts:<ns>, system:authenticated), written
//	            only for a group some binding names; basis declared (D-110)
//	grant       iga_access_edges, identity -> rule, through a RoleBinding or
//	            ClusterRoleBinding (iga_policy_assignment, assignment_id)
//
// so a Kubernetes walk is the AWS walk with the provider slot rendered 'k8s'
// (traverse_edges.go) and three of its six edge kinds: there is no
// can_assume or task_execution_role row, and no target -- a Kubernetes rule
// names resource TYPES ("secrets in namespace prod"), never a resource
// instance, so 040 forbids a resource_id and a rule's node states what it
// allows itself (k8s_rule). A ServiceAccount an AWS trust names (IRSA, EKS
// Pod Identity) has one more way out: the crossing into the AWS role
// (traverse_cross.go, D-108).
//
// What differs, and why:
//
//   - Nodes carry the unified inventory's scope instead of an AWS account:
//     scope {kind k8s_cluster, id, label}, sub_scope (the namespace, null when
//     cluster-scoped) and native_id (namespace/name), read by the inventory's
//     own expressions (inventoryClass.nativeSQL, attr) so the canvas and the
//     inventory row agree. No account, no ARN: both are absent.
//   - A grant names its binding and its role (assignment, policy_ref,
//     policy_kind beside the existing policy): the binding is what decides
//     where a ClusterRole's rule applies.
//   - Limitations are Kubernetes coverage, never AWS surfaces: each element's
//     partition (its support rows' for a node, its own row's for an edge) is
//     read back by k8sgraph.ParsePartitionKey and judged against the newest
//     APPLIED sweep of its source and cluster (k8sread.LatestProjectedSweeps,
//     the reading the rows came from) by the reconciler's own rule
//     (k8sgraph.Scope.CanEnd): not_swept, incomplete, namespaced_only,
//     namespace_not_swept, or unattributed when no sweep stands behind the
//     row. A stale element's stale_reason says the same gap.
//   - An identity bound to a role the sweep did not see has grants with no
//     rule (calculation_state partial, no entitlement): there is no statement
//     to draw, and drawing nothing would read as "no access". The identity
//     carries k8s_unresolved_bindings instead.
//   - Evidence: no cloud_observation row backs a Kubernetes claim (the agent
//     pushes a snapshot; nothing per claim is stored), and /evidence is AWS's.
//     The meta says so once (k8s_observations_not_recorded), instead of
//     AWS's organizations_not_collected, which says nothing about a cluster.
//   - Revisions (D-111): Kubernetes rows are written straight from a sweep
//     and belong to no publication. They are read in the request's one
//     REPEATABLE READ snapshot, which is the consistency unit. A response of
//     Kubernetes nodes only has meta.graph_state "unrevisioned" (the
//     inventory's word) and meta.rev and published_at null: it neither pins
//     nor reports an AWS publication, and a rev= on a Kubernetes root is
//     ignored (never 409). A response that crossed into AWS (traverse_cross.go)
//     is "mixed", with the AWS rev it read. A workspace with Kubernetes rows
//     and no publication graphs them all the same; an AWS root there is still
//     404 (D-4). An expansion cursor of a Kubernetes node is unrevisioned
//     (graphK8sCursorRev), so a publication between two pages does not make
//     it stale.
//   - Where a rule applies (D-109): a grant names its binding, and its
//     effective_scope says where the rule applies -- the binding's namespace
//     for a RoleBinding (of a Role or of a ClusterRole), the cluster for a
//     ClusterRoleBinding -- so a ClusterRole's rule reached through a
//     RoleBinding never reads as cluster-wide.

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/authsec-ai/authsec/models"
)

// graphK8sEdgeKinds are the edge kinds the Kubernetes projection writes, in
// graphEdgeKinds order.
var graphK8sEdgeKinds = []string{GraphEdgeExecutesAs, GraphEdgeGrant, GraphEdgeMemberOf}

// graphK8sCursorRev is the revision an expansion cursor of a Kubernetes node
// carries: none. A publication is numbered from 1, so 0 is never a real one.
const graphK8sCursorRev int64 = 0

// The Kubernetes limitation codes. Additive to the §5.3 vocabulary, each with
// one exact condition and its own fields:
//
//	k8s_coverage_gap              cluster (null when no sweep is attributed),
//	                              namespace (null: the cluster-scoped part),
//	                              state, observed_at (the sweep's, null when
//	                              there is none)
//	k8s_unresolved_bindings       count, bindings (namespace/name or name, at
//	                              most LimitationRefCap), truncated
//	k8s_observations_not_recorded none -- meta only, for every element
const (
	LimK8sCoverageGap             = "k8s_coverage_gap"
	LimK8sUnresolvedBindings      = "k8s_unresolved_bindings"
	LimK8sObservationsNotRecorded = "k8s_observations_not_recorded"
)

// k8s_coverage_gap states, from the reconciler's rule (k8sgraph.Scope.CanEnd)
// and k8sread's vocabulary.
const (
	K8sGapNotSwept          = k8sread.CoverageNone       // no applied sweep of this source and cluster
	K8sGapIncomplete        = k8sread.CoverageIncomplete // a LIST failed: absence proves nothing
	K8sGapNamespacedOnly    = k8sread.CoverageNamespaced // the cluster-scoped part was not readable
	K8sGapNamespaceNotSwept = "namespace_not_swept"      // the sweep did not read this namespace
	K8sGapUnattributed      = "unattributed"             // no sweep stands behind the row at all
)

// graphK8sStaleSurface is a Kubernetes stale_reason's surface: the cluster's
// sweep, as the inventory's coverage notes name it (inventoryK8sSurface).
const graphK8sStaleSurface = inventoryK8sSurface

// graphK8sMeta makes a Kubernetes traversal's meta: graph_state
// unrevisioned, no AWS revision (D-111), and the limitations that hold for
// every Kubernetes element.
func graphK8sMeta(m *GraphMeta) {
	m.Rev, m.PublishedAt = nil, nil
	m.GraphState = inventoryUnrevisioned
	m.Limitations = []GraphLimitation{
		{"code": graphLimEffectiveAccess},
		{"code": LimK8sObservationsNotRecorded},
	}
}

// graphMixedMeta makes the meta of a response holding nodes of both
// providers (traverse_cross.go): graph_state mixed, the AWS revision it read,
// and the limitations of both.
func graphMixedMeta(m *GraphMeta) {
	m.GraphState = GraphMixed
	m.Limitations = []GraphLimitation{
		{"code": graphLimEffectiveAccess},
		{"code": graphLimOrganizations},
		{"code": LimK8sObservationsNotRecorded},
	}
}

/* ------------------------------ response shapes ---------------------------- */

// GraphScope is a Kubernetes node's scope: the cluster (kind k8s_cluster, id
// and label both the cluster name, as k8sgraph.WithScope writes them).
type GraphScope struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

// graphOptional is a string that is stated as null when empty: sub_scope is
// present on every Kubernetes node -- null for a cluster-scoped one -- and
// absent on every AWS node (a nil *graphOptional).
type graphOptional struct{ v string }

func (o graphOptional) MarshalJSON() ([]byte, error) {
	if o.v == "" {
		return []byte("null"), nil
	}
	return json.Marshal(o.v)
}

// GraphK8sRule is a Kubernetes statement's PolicyRule, as the projection
// stored it (native_rights): never expanded -- "*" is "*".
type GraphK8sRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"api_groups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resource_names"`
	NonResourceURLs []string `json:"non_resource_urls"`
}

// GraphAssignment is the binding a Kubernetes grant comes through: its claim
// ref, kind (k8s_role_binding | k8s_cluster_role_binding), name, and namespace
// -- null for a ClusterRoleBinding, which grants cluster-wide.
type GraphAssignment struct {
	Ref       string  `json:"ref"`
	Kind      string  `json:"kind"`
	Name      string  `json:"name"`
	Namespace *string `json:"namespace"`
}

// Effective scope kinds (D-109).
const (
	GraphScopeNamespace = k8sread.ScopeNamespace
	GraphScopeCluster   = k8sread.ScopeCluster
)

// GraphEffectiveScope is where a Kubernetes grant's rule applies (D-109):
// {kind: namespace, namespace: <the binding's>} or {kind: cluster,
// namespace: null}.
type GraphEffectiveScope struct {
	Kind      string  `json:"kind"`
	Namespace *string `json:"namespace"`
}

/* ---------------------------------- nodes ---------------------------------- */

// fetchK8sNodes reads Kubernetes nodes: workloads, identities and statements.
// External principals and resources have no Kubernetes rows. Every read
// carries D-6's readability predicate (a support row), as AWS's do.
func (t *graphTraversal) fetchK8sNodes(lv *graphLevel, nodes []*GraphNode) error {
	byType := map[string]map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		if byType[n.typ] == nil {
			byType[n.typ] = map[uuid.UUID]*GraphNode{}
		}
		byType[n.typ][n.id] = n
	}
	for _, typ := range []string{RefWorkload, RefIdentity, RefStatement} {
		set := byType[typ]
		if len(set) == 0 {
			continue
		}
		ids := make([]uuid.UUID, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		var err error
		switch typ {
		case RefWorkload:
			err = t.fetchK8sScoped(lv, inventoryWorkloads, ids, set)
		case RefIdentity:
			err = t.fetchK8sScoped(lv, inventoryIdentities, ids, set)
		case RefStatement:
			err = t.fetchK8sStatements(lv, ids, set)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// graphK8sScopedRow is a Kubernetes workload or identity with the inventory's
// scope and native id.
type graphK8sScopedRow struct {
	ID              uuid.UUID
	DisplayName     string
	Kind            string
	SourceKey       string
	Lifecycle       string
	ScopeKind       string
	ScopeID         string
	ScopeLabel      string
	SubScope        string
	NativeID        string
	State           string
	LastConfirmedAt *time.Time
}

// fetchK8sScoped reads Kubernetes workloads or identities through the unified
// inventory's class (its table, alias, kind column and expressions).
func (t *graphTraversal) fetchK8sScoped(lv *graphLevel, c *inventoryClass, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	a := c.alias
	var rows []graphK8sScopedRow
	if err := tx.Raw(`SELECT `+a+`.id, `+a+`.display_name, `+c.kindCol+` AS kind, `+a+`.source_key, `+a+`.lifecycle,
	                         `+c.attr("scope_kind")+` AS scope_kind, `+c.attr("scope_id")+` AS scope_id,
	                         `+c.attr("scope_label")+` AS scope_label, `+c.attr("sub_scope")+` AS sub_scope,
	                         `+c.nativeSQL()+` AS native_id,
	                         sup.state, sup.last_confirmed_at
	                    FROM `+TableOf(c.refType)+` `+a+`
	                    `+SupportLateral(a, c.supportCol)+`
	                   WHERE `+a+`.workspace_id = ? AND `+a+`.provider = 'k8s' AND `+SupportedSQL(a, c.supportCol)+`
	                     AND `+a+`.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		n.provider, n.Provider, n.key = models.ProviderK8s, models.ProviderK8s, r.SourceKey
		n.Label = r.DisplayName
		if c.refType == RefWorkload {
			n.Kind, n.RuntimeKind = RefWorkload, r.Kind
		} else {
			n.Kind = r.Kind
		}
		if r.ScopeID != "" {
			label := r.ScopeLabel
			if label == "" {
				label = r.ScopeID
			}
			n.Scope = &GraphScope{Kind: r.ScopeKind, ID: r.ScopeID, Label: label}
		}
		n.SubScope = &graphOptional{r.SubScope}
		n.NativeID = r.NativeID
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = StaleSubject{ID: r.ID}
		n.fetched = true
	}
	return nil
}

// graphK8sStatementRow is one Kubernetes rule with its role.
type graphK8sStatementRow struct {
	ID              uuid.UUID
	SourceKey       string
	Sid             string
	Effect          string
	Lifecycle       string
	NativeRights    string
	PolicyID        *uuid.UUID
	PolicyName      string
	PolicyKind      string
	State           string
	LastConfirmedAt *time.Time
}

func (t *graphTraversal) fetchK8sStatements(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphK8sStatementRow
	if err := tx.Raw(`SELECT e.id, e.source_key, e.sid, e.effect, e.lifecycle,
	                         COALESCE(e.native_rights::text, '') AS native_rights,
	                         p.id AS policy_id, COALESCE(p.display_name, '') AS policy_name,
	                         COALESCE(p.policy_kind, '') AS policy_kind,
	                         sup.state, sup.last_confirmed_at
	                    FROM iga_entitlements e
	                    LEFT JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                                          AND p.provider = 'k8s'
	                    `+SupportLateral("e", "entitlement_id")+`
	                   WHERE e.workspace_id = ? AND e.provider = 'k8s' AND `+SupportedSQL("e", "entitlement_id")+`
	                     AND e.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		rule := graphK8sParseRule(r.NativeRights)
		n.provider, n.Provider, n.key = models.ProviderK8s, models.ProviderK8s, r.SourceKey
		n.Kind, n.Label, n.K8sRule = RefStatement, graphK8sRuleLabel(rule), &rule
		sid := r.Sid
		n.Policy, n.Effect, n.Sid = r.PolicyName, r.Effect, &sid
		if r.PolicyID != nil {
			n.PolicyRef = R(RefPolicy, *r.PolicyID)
		}
		n.policyKind = r.PolicyKind
		// The rule's scope is its role's: a Role's rules are its namespace's,
		// a ClusterRole's the cluster's (a RoleBinding may still narrow a
		// ClusterRole's rule to one namespace: that is the grant's, and its
		// assignment says so).
		var ns string
		if k, ok := k8sgraph.ParseKey(r.SourceKey); ok {
			n.Scope = &GraphScope{Kind: k8sgraph.ScopeKindCluster, ID: k.Cluster, Label: k.Cluster}
			ns = k.Namespace
		}
		n.SubScope = &graphOptional{ns}
		n.GroupKey = graphK8sGroupKey(rule, n.Scope, ns)
		empty := []GraphExclusion{}
		n.Exclusions = &empty
		n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
		n.stale = StaleSubject{ID: r.ID}
		n.fetched = true
	}
	return nil
}

// graphK8sParseRule reads a rule's native_rights ({verbs, api_groups,
// resources, resource_names, non_resource_urls}); every list is [] rather than
// null, so the console never tells "none" from "not stated".
func graphK8sParseRule(native string) GraphK8sRule {
	var r GraphK8sRule
	_ = json.Unmarshal([]byte(native), &r)
	for _, p := range []*[]string{&r.Verbs, &r.APIGroups, &r.Resources, &r.ResourceNames, &r.NonResourceURLs} {
		if *p == nil {
			*p = []string{}
		}
	}
	return r
}

// graphK8sTargets is what a rule names, each as one string: a resource type
// as group/resource (the core group's as resource alone), narrowed to
// resource names as group/resource/name, and each non-resource URL as is.
// Wildcards stay wildcards.
func graphK8sTargets(r GraphK8sRule) []string {
	groups := r.APIGroups
	if len(groups) == 0 && len(r.Resources) > 0 {
		groups = []string{""}
	}
	var out []string
	for _, g := range groups {
		for _, res := range r.Resources {
			base := res
			if g != "" {
				base = g + "/" + res
			}
			if len(r.ResourceNames) == 0 {
				out = append(out, base)
				continue
			}
			for _, name := range r.ResourceNames {
				out = append(out, base+"/"+name)
			}
		}
	}
	out = append(out, r.NonResourceURLs...)
	return graphDedupe(out)
}

// graphK8sRuleLabel is a rule node's label: its verbs, then what they apply
// to ("get, list on secrets"). Never empty: a rule with no verbs grants
// nothing, and says so.
func graphK8sRuleLabel(r GraphK8sRule) string {
	verbs := strings.Join(graphDedupe(r.Verbs), ", ")
	if verbs == "" {
		verbs = "no verbs"
	}
	if ts := graphK8sTargets(r); len(ts) > 0 {
		return verbs + " on " + strings.Join(ts, ", ")
	}
	return verbs
}

// graphK8sGroupKey is a rule's group_key (D-37): its sorted verbs, "→", its
// sorted targets, and where it applies -- the cluster, and the role's
// namespace or * for a ClusterRole -- so the same rule in two namespaces or
// two clusters never shares a key. The k8s: prefix keeps it apart from every
// AWS key.
func graphK8sGroupKey(r GraphK8sRule, scope *GraphScope, namespace string) string {
	verbs := graphDedupe(append([]string{}, r.Verbs...))
	sort.Strings(verbs)
	ts := graphK8sTargets(r)
	sort.Strings(ts)
	cluster := ""
	if scope != nil {
		cluster = scope.ID
	}
	if namespace == "" {
		namespace = "*"
	}
	return "k8s:" + strings.Join(verbs, ",") + "→" + strings.Join(ts, ",") + "@" + cluster + "/" + namespace
}

// decorateK8sNodes completes Kubernetes nodes a level found. Identities: no
// restrictions -- Kubernetes RBAC has no Deny and no boundary -- and the
// used-by count, by the list's own function. Statements were completed when
// read. Limitations and stale reasons are decorateK8sLimitations'.
func (t *graphTraversal) decorateK8sNodes(lv *graphLevel, nodes []*GraphNode) error {
	var ids []uuid.UUID
	var idents []*GraphNode
	for _, n := range nodes {
		if n.typ == RefIdentity {
			ids = append(ids, n.id)
			idents = append(idents, n)
		}
	}
	if len(idents) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	used, err := UsedByCounts(tx, t.q.WS, ids)
	if err != nil {
		return err
	}
	for _, n := range idents {
		n.Restrictions = &GraphRestrictions{}
		c, ok := used[n.id]
		if !ok {
			c = Unknown()
		}
		n.UsedByCount = &c
	}
	return nil
}

/* ---------------------------------- edges ---------------------------------- */

// decorateK8sEdges completes Kubernetes edges once both endpoints are read:
// the provider; on a member_of whether the membership is implicit (D-110);
// and on a grant its binding (assignment), where its rule applies
// (effective_scope, D-109) and its role (policy_ref, policy_kind -- the
// rule's own role, as policy already names). Nothing crosses an account:
// Kubernetes nodes have none.
func (t *graphTraversal) decorateK8sEdges(lv *graphLevel, edges []*GraphEdge, node func(string) *GraphNode) error {
	var grants []uuid.UUID
	byID := map[uuid.UUID]*GraphEdge{}
	for _, e := range edges {
		e.Provider = models.ProviderK8s
		if e.Kind == GraphEdgeMemberOf {
			from, to := node(e.From), node(e.To)
			e.ImplicitMembership = from != nil && to != nil && from.Kind == models.K8sAccountKindServiceAccount &&
				graphK8sImplicitGroup(to.key)
			continue
		}
		if e.Kind != GraphEdgeGrant {
			continue
		}
		if st := node(e.To); st != nil {
			e.PolicyRef, e.PolicyKind = st.PolicyRef, st.policyKind
		}
		grants = append(grants, e.claimRef.ID)
		byID[e.claimRef.ID] = e
	}
	if len(grants) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []struct {
		EdgeID         uuid.UUID
		AssignmentID   uuid.UUID
		AssignmentKind string
		SourceKey      string
	}
	if err := tx.Raw(`SELECT e.id AS edge_id, pa.id AS assignment_id, pa.assignment_kind, pa.source_key
	                    FROM iga_access_edges e
	                    JOIN iga_policy_assignment pa ON pa.workspace_id = e.workspace_id AND pa.id = e.assignment_id
	                   WHERE e.workspace_id = ? AND e.provider = 'k8s' AND e.id IN ?`,
		t.q.WS, grants).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		a := &GraphAssignment{Ref: R(RefAssignment, r.AssignmentID), Kind: r.AssignmentKind}
		if k, ok := k8sgraph.ParseKey(r.SourceKey); ok {
			a.Name = k.Name
			if k.Namespace != "" {
				ns := k.Namespace
				a.Namespace = &ns
			}
		}
		// Where the rule applies is the flat access route's rule too
		// (k8sread.BindingScope, D-112): one statement of D-109.
		kind, ns := k8sread.BindingScope(r.SourceKey)
		scope := &GraphEffectiveScope{Kind: kind}
		if ns != "" {
			scope.Namespace = &ns
		}
		e := byID[r.EdgeID]
		e.Assignment, e.EffectiveScope = a, scope
	}
	return nil
}

// graphK8sImplicitGroup reports whether a Kubernetes group identity's source
// key names a group the API server places subjects in implicitly:
// system:serviceaccounts, system:serviceaccounts:<ns> or
// system:authenticated (D-110).
func graphK8sImplicitGroup(sourceKey string) bool {
	return k8sread.ImplicitGroupKey(sourceKey)
}

/* ------------------------------- limitations -------------------------------- */

// graphK8sCoverage is the newest applied sweep of every (source, cluster) of
// the workspace, read once per request in its snapshot.
type graphK8sCoverage struct {
	sweeps map[k8sread.SweepKey]*k8sread.Sweep
}

// graphK8sGap is one coverage gap an element stands on.
type graphK8sGap struct {
	cluster, namespace, state string
	observedAt                *time.Time
}

// gapOf is the gap of one partition, or nil when the newest applied sweep of
// its source and cluster covered it: complete, and either the cluster-scoped
// part read (cluster_scoped) or the namespace among those read -- exactly
// what lets the reconciler end a row there (k8sgraph.Scope.CanEnd). A key no
// sweep wrote is unattributed: nothing stands behind the row.
func (c *graphK8sCoverage) gapOf(partitionKey string) *graphK8sGap {
	p, ok := k8sgraph.ParsePartitionKey(partitionKey)
	if !ok {
		return &graphK8sGap{state: K8sGapUnattributed}
	}
	g := &graphK8sGap{cluster: p.Cluster, namespace: p.Namespace}
	sw := c.sweeps[k8sread.SweepKey{SourceID: p.SourceID, Cluster: p.Cluster}]
	if sw == nil {
		g.state = K8sGapNotSwept
		return g
	}
	at := sw.ObservedAt
	g.observedAt = &at
	scope := k8sgraph.Scope{SourceID: p.SourceID, Cluster: p.Cluster, Complete: sw.Complete,
		ClusterScoped: sw.ClusterScoped, Namespaces: sw.Namespaces}
	switch {
	case scope.CanEnd(p):
		return nil
	case !sw.Complete:
		g.state = K8sGapIncomplete
	case p.ClusterScoped():
		g.state = K8sGapNamespacedOnly
	default:
		g.state = K8sGapNamespaceNotSwept
	}
	return g
}

func (g *graphK8sGap) limitation() GraphLimitation {
	return GraphLimitation{
		"code": LimK8sCoverageGap, "cluster": nullIfBlank(g.cluster), "namespace": nullIfBlank(g.namespace),
		"state": g.state, "observed_at": TS(g.observedAt),
	}
}

func (g *graphK8sGap) staleReason() StaleReason {
	return StaleReason{AccountID: g.cluster, Surface: graphK8sStaleSurface, State: g.state, Since: nil}
}

// loadK8sCoverage reads the coverage, once per request.
func (t *graphTraversal) loadK8sCoverage(lv *graphLevel) error {
	if t.k8s != nil {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	sweeps, err := k8sread.New(tx, t.q.WS).LatestProjectedSweeps()
	if err != nil {
		return err
	}
	t.k8s = &graphK8sCoverage{sweeps: sweeps}
	return nil
}

// decorateK8sLimitations sets the limitations of a level's Kubernetes nodes
// and edges, and the stale_reason of the stale ones: one statement per node
// type for their support rows' partitions, one for the identities' unresolved
// bindings, and the coverage read once per request.
func (t *graphTraversal) decorateK8sLimitations(lv *graphLevel, nodes []*GraphNode, edges []*GraphEdge) error {
	if len(nodes)+len(edges) == 0 {
		return nil
	}
	if err := t.loadK8sCoverage(lv); err != nil {
		return err
	}
	parts, err := t.k8sNodePartitions(lv, nodes)
	if err != nil {
		return err
	}
	unresolved, err := t.k8sUnresolvedBindings(lv, nodes)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		gaps := t.k8sGaps(parts[n.Ref])
		ls := make([]GraphLimitation, 0, len(gaps)+1)
		for _, g := range gaps {
			ls = append(ls, g.limitation())
		}
		if l := unresolved[n.id]; l != nil {
			ls = append(ls, l)
		}
		n.Limitations = ls
		if n.State == StateStale {
			n.StaleReason = graphK8sStaleReasons(gaps)
		}
	}
	for _, e := range edges {
		gaps := t.k8sGaps([]string{e.partitionKey})
		ls := make([]GraphLimitation, 0, len(gaps))
		for _, g := range gaps {
			ls = append(ls, g.limitation())
		}
		e.Limitations = ls
		if e.State == StateStale {
			e.StaleReason = graphK8sStaleReasons(gaps)
		}
	}
	return nil
}

// k8sGaps is the distinct gaps of a set of partitions, ordered by cluster,
// namespace (the cluster-scoped part first) and state.
func (t *graphTraversal) k8sGaps(keys []string) []*graphK8sGap {
	seen := map[[3]string]bool{}
	var out []*graphK8sGap
	for _, k := range keys {
		g := t.k8s.gapOf(k)
		if g == nil {
			continue
		}
		id := [3]string{g.cluster, g.namespace, g.state}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.cluster != b.cluster {
			return a.cluster < b.cluster
		}
		if a.namespace != b.namespace {
			return a.namespace < b.namespace
		}
		return a.state < b.state
	})
	return out
}

func graphK8sStaleReasons(gaps []*graphK8sGap) *[]StaleReason {
	rs := []StaleReason{}
	for _, g := range gaps {
		rs = append(rs, g.staleReason())
	}
	return &rs
}

// k8sNodePartitions reads the partitions each node's Kubernetes support rows
// stand on, keyed by node ref: the rows that have not ended -- an ended
// support row is a partition that concluded the node's absence there, which
// is no gap -- or, for a node whose every row has ended, all of them.
func (t *graphTraversal) k8sNodePartitions(lv *graphLevel, nodes []*GraphNode) (map[string][]string, error) {
	out := map[string][]string{}
	byType := map[string][]*GraphNode{}
	for _, n := range nodes {
		byType[n.typ] = append(byType[n.typ], n)
	}
	for _, tc := range []struct{ typ, column string }{
		{RefWorkload, "workload_id"}, {RefIdentity, "identity_account_id"}, {RefStatement, "entitlement_id"},
	} {
		ns := byType[tc.typ]
		if len(ns) == 0 {
			continue
		}
		refOf := map[uuid.UUID]string{}
		for _, n := range ns {
			refOf[n.id] = n.Ref
		}
		tx, err := lv.db()
		if err != nil {
			return nil, err
		}
		var rows []struct {
			NodeID       uuid.UUID
			PartitionKey string
			Ended        bool
		}
		if err := tx.Raw(`SELECT s.`+tc.column+` AS node_id, s.partition_key, s.state = 'ended' AS ended
		                    FROM iga_object_support s
		                   WHERE s.workspace_id = ? AND s.`+tc.column+` IN ? AND s.discovery_source_id IS NOT NULL
		                   ORDER BY s.`+tc.column+`, s.partition_key`, t.q.WS, graphIDs(ns)).Scan(&rows).Error; err != nil {
			return nil, err
		}
		live, all := map[string][]string{}, map[string][]string{}
		for _, r := range rows {
			ref := refOf[r.NodeID]
			all[ref] = append(all[ref], r.PartitionKey)
			if !r.Ended {
				live[ref] = append(live[ref], r.PartitionKey)
			}
		}
		for ref, keys := range all {
			if len(live[ref]) > 0 {
				keys = live[ref]
			}
			out[ref] = keys
		}
	}
	return out, nil
}

// k8sUnresolvedBindings is, per identity, k8s_unresolved_bindings: its grants
// that are not ended and reach no rule (the binding's role was not in the
// sweep, so the projector wrote the grant partial with no entitlement). Their
// count is exact; the bindings named are the first LimitationRefCap by key.
func (t *graphTraversal) k8sUnresolvedBindings(lv *graphLevel, nodes []*GraphNode) (map[uuid.UUID]GraphLimitation, error) {
	out := map[uuid.UUID]GraphLimitation{}
	var ids []uuid.UUID
	for _, n := range nodes {
		if n.typ == RefIdentity {
			ids = append(ids, n.id)
		}
	}
	if len(ids) == 0 {
		return out, nil
	}
	tx, err := lv.db()
	if err != nil {
		return nil, err
	}
	var rows []struct {
		SubjectID uuid.UUID
		SourceKey string
		N         int
	}
	if err := tx.Raw(`SELECT subject_id, source_key, n FROM (
	                    SELECT e.subject_identity_account_id AS subject_id, e.source_key,
	                           count(*) OVER (PARTITION BY e.subject_identity_account_id) AS n,
	                           row_number() OVER (PARTITION BY e.subject_identity_account_id ORDER BY e.source_key, e.id) AS i
	                      FROM iga_access_edges e
	                     WHERE e.workspace_id = ? AND e.provider = 'k8s' AND e.subject_identity_account_id IN ?
	                       AND e.entitlement_id IS NULL AND e.state <> 'ended') x
	                  WHERE i <= ?
	                  ORDER BY subject_id, source_key`, t.q.WS, ids, LimitationRefCap).Scan(&rows).Error; err != nil {
		return nil, err
	}
	names := map[uuid.UUID][]string{}
	count := map[uuid.UUID]int{}
	for _, r := range rows {
		count[r.SubjectID] = r.N
		name := r.SourceKey
		if k, ok := k8sgraph.ParseKey(r.SourceKey); ok {
			name = k.Name
			if k.Namespace != "" {
				name = k.Namespace + "/" + k.Name
			}
		}
		names[r.SubjectID] = append(names[r.SubjectID], name)
	}
	for id, n := range count {
		out[id] = GraphLimitation{"code": LimK8sUnresolvedBindings, "count": n,
			"bindings": names[id], "truncated": n > len(names[id])}
	}
	return out, nil
}
