package igaread

// Azure on the traversal routes (/graph, /graph/expand, /graph/path).
//
// The Azure projection (internal/azuregraph) writes into the SAME tables as
// AWS and Kubernetes, under provider 'azure', every source key starting
// azure␟<tenant lower>␟:
//
//	identity    iga_identity_accounts: Entra users, groups, applications,
//	            service principals, managed and agent identities
//	workload    iga_workload: what runs as a managed identity
//	resource    iga_resources: ARM resources and API-plane permissions
//	external    iga_external_principal: a federated credential's subject
//	grant       iga_access_edges, one per role assignment (RBAC, directory
//	            role, application or delegated permission, Key Vault access
//	            policy): the holder (subject_identity_account_id), the role it
//	            confers (entitlement_id, a content-keyed role definition), the
//	            resource it applies to when the scope is one (resource_id) and
//	            the scope as Azure states it (native_scope)
//	member_of, can_assume, executes_as  iga_relationship
//
// So an Azure walk is the AWS walk with the provider slot rendered 'azure'
// for the relationship kinds, and its own grant and target specs below:
//
//   - The middle node is the ROLE ASSIGNMENT, one per iga_access_edges row
//     (role_assignment:<edge id>, kind statement, labelled by its role), never
//     the role definition: the projector keys a definition by content, so two
//     assignments of one role share one row, and a walk through it would draw
//     a path from each holder to every other assignment's scope.
//   - grant: identity -> role assignment, claim grant:<edge id>.
//   - target: role assignment -> resource (resource_id) or, when the scope is
//     not a resource row, a SCOPE node built from native_scope
//     (scope:<uuid v5 of the lowercased path>; "Subscription <name>",
//     "Resource group <rg>", "Tenant root", "Entra directory"). Claim
//     target:<edge id>. A scope is a leaf: never a root, never expanded, no
//     frontier.
//   - Reverse from a resource reads its role assignments, and from them their
//     holders: the "who can reach this" list.
//
// Nodes carry the unified inventory's scope (kind azure_tenant), sub_scope
// (the subscription's name) and native_id, read by the inventory's own
// expressions, as Kubernetes nodes do. No account, no ARN.
//
// Revisions: Azure has no publication. Its rows are read in the request's one
// REPEATABLE READ snapshot; a response of Azure nodes is graph_state
// "unrevisioned" with rev and published_at null, ignores rev=, and its
// expansion cursors are unrevisioned. One provider per traversal: every edge
// is read in the provider of the node it is read from, and an Azure walk
// never crosses (an external principal's resolution to an AKS ServiceAccount
// is displayed, not walked).
//
// Limitations: effective access is not evaluated (deny assignments are not
// read) and conditions are not evaluated -- both hold for every Azure
// element, and are stated once, in meta. Elements carry none of their own
// (per-partition Azure coverage is not read yet), except a resource that an
// assignment at a broader scope reaches without being drawn from it
// (azure_scope_access_not_drawn). A stale element's stale_reason is
// {surface: azure_scan, state: stale} (D-114).

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/models"
)

// graphAzureEdgeKinds are the edge kinds the Azure projection writes, in
// graphEdgeKinds order: all but task_execution_role.
var graphAzureEdgeKinds = []string{
	GraphEdgeCanAssume, GraphEdgeExecutesAs, GraphEdgeGrant, GraphEdgeMemberOf, GraphEdgeTarget,
}

// graphAzureKeyPrefix starts every Azure source key (azuregraph.Key).
const graphAzureKeyPrefix = models.ProviderAzure + azuregraph.Sep

// graphAzureScopeNS is the namespace of a scope node's UUID v5.
var graphAzureScopeNS = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://authsec.ai/iga/graph/azure-scope"))

// graphAzureStaleSurface is an Azure stale_reason's surface (D-114): the
// scan that last confirmed the element did not confirm it again.
const graphAzureStaleSurface = "azure_scan"

// What a scope path names (graphAzureScopeOf), which its label follows. A
// scope node's own kind is always "scope" (RefScope).
const (
	GraphAzureScopeTenantRoot      = "azure_tenant_root"
	GraphAzureScopeManagementGroup = "azure_management_group"
	GraphAzureScopeSubscription    = "azure_subscription"
	GraphAzureScopeResourceGroup   = "azure_resource_group"
	GraphAzureScopeResource        = "azure_resource"
	GraphAzureScopeDirectory       = "entra_directory"
	GraphAzureScopeOther           = "azure_scope"
)

/* ------------------------------ response shapes ---------------------------- */

// GraphAzureRole is a role assignment node's role: its name, the kind of
// grant (the access edge's path_kind: azure_rbac, entra_directory_role,
// entra_app_permission, entra_delegated_permission,
// key_vault_access_policy), its actions and not_actions as the projection
// stored them ([] rather than null), and its condition verbatim (null when it
// has none). Nothing is evaluated.
type GraphAzureRole struct {
	RoleName   string          `json:"role_name"`
	GrantKind  string          `json:"grant_kind"`
	Actions    []string        `json:"actions"`
	NotActions []string        `json:"not_actions"`
	Condition  json.RawMessage `json:"condition"`
}

// graphAzureState is what an Azure walk reads once per request: every Azure
// subscription connector's display name, by lowercased subscription id.
type graphAzureState struct {
	subs map[string]string
}

// graphAzureMeta makes an Azure traversal's meta: graph_state unrevisioned,
// no AWS revision, and the limitations that hold for every Azure element. A
// response that also holds another provider's nodes (a /graph/path between
// two providers' ends) is mixed, and states every provider's limitations.
func graphAzureMeta(m *GraphMeta, aws, k8s bool) {
	if !aws && !k8s {
		m.Rev, m.PublishedAt = nil, nil
		m.GraphState = inventoryUnrevisioned
		m.Limitations = []GraphLimitation{
			{"code": graphLimEffectiveAccess},
			{"code": LimAzureConditionsNotEvaluated},
		}
		return
	}
	m.GraphState = GraphMixed
	if !aws {
		m.Rev, m.PublishedAt = nil, nil
	}
	ls := []GraphLimitation{{"code": graphLimEffectiveAccess}}
	if aws {
		ls = append(ls, GraphLimitation{"code": graphLimOrganizations})
	}
	if k8s {
		ls = append(ls, GraphLimitation{"code": LimK8sObservationsNotRecorded})
	}
	m.Limitations = append(ls, GraphLimitation{"code": LimAzureConditionsNotEvaluated})
}

/* ---------------------------------- specs ---------------------------------- */

// The Azure grant and target column lists, in graphEdgeRow's order. Both
// claims are one iga_access_edges row, so both carry its state, basis and
// confirmation.
const (
	graphAzureGrantCols = `e0.id AS claim_id,
	       e0.subject_identity_account_id AS from_id, 'identity' AS from_type,
	       e0.id AS to_id, '` + RefRoleAssignment + `' AS to_type,
	       e0.state, e0.basis, '' AS mechanism,
	       e0.last_confirmed_at, e0.connector_id, e0.partition_key, NULL::text AS policy_name`
	graphAzureTargetCols = `e0.id AS claim_id,
	       e0.id AS from_id, '` + RefRoleAssignment + `' AS from_type,
	       COALESCE(far.id, e0.id) AS to_id,
	       (CASE WHEN far.id IS NULL THEN '` + RefScope + `' ELSE '` + RefResource + `' END) AS to_type,
	       e0.state, e0.basis, '' AS mechanism,
	       e0.last_confirmed_at, e0.connector_id, e0.partition_key, NULL::text AS policy_name`
	graphAzureTargetReverseCols = `e0.id AS claim_id,
	       e0.id AS from_id, '` + RefRoleAssignment + `' AS from_type,
	       e0.resource_id AS to_id, '` + RefResource + `' AS to_type,
	       e0.state, e0.basis, '' AS mechanism,
	       e0.last_confirmed_at, e0.connector_id, e0.partition_key, NULL::text AS policy_name`
	graphAzureLive = `e0.state IN ('current', 'stale')`
)

// graphAzureSpecs are Azure's grant and target, per direction; its
// relationship kinds are graphSpecs' own, rendered 'azure'. Every statement
// is the access edge row aliased e0, of the workspace (queryEdges and
// countSide bind e0.workspace_id), every join matching workspace_id on both
// sides.
var graphAzureSpecs = map[string]map[string]*graphEdgeSpec{
	GraphForward: {
		GraphEdgeGrant: {
			kind: GraphEdgeGrant, claim: RefGrant,
			from:   `iga_access_edges e0`,
			where:  `e0.provider = ` + graphProviderSlot,
			live:   graphAzureLive,
			near:   map[string]string{RefIdentity: `e0.subject_identity_account_id`},
			farKey: `e0.source_key`,
			cols:   graphAzureGrantCols,
		},
		GraphEdgeTarget: {
			// The resource when the scope is one the projection holds; the
			// scope node otherwise. An assignment to a resource that is not
			// readable (D-6) has no target.
			kind: GraphEdgeTarget, claim: RefTarget,
			from: `iga_access_edges e0
			  LEFT JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id`,
			where: `e0.provider = ` + graphProviderSlot + `
			        AND ((e0.resource_id IS NULL AND e0.native_scope <> '')
			             OR (far.provider = ` + graphProviderSlot + ` AND ` + SupportedSQL("far", "resource_id") + `))`,
			live:   graphAzureLive,
			near:   map[string]string{RefRoleAssignment: `e0.id`},
			farKey: `COALESCE(far.source_key, lower(e0.native_scope))`,
			cols:   graphAzureTargetCols,
			rows:   graphAzureScopeRows,
		},
	},
	GraphReverse: {
		GraphEdgeGrant: {
			kind: GraphEdgeGrant, claim: RefGrant,
			from: `iga_access_edges e0
			  JOIN iga_identity_accounts far ON far.workspace_id = e0.workspace_id AND far.id = e0.subject_identity_account_id`,
			where: `e0.provider = ` + graphProviderSlot + ` AND far.provider = ` + graphProviderSlot + ` AND ` +
				SupportedSQL("far", "identity_account_id"),
			live:   graphAzureLive,
			near:   map[string]string{RefRoleAssignment: `e0.id`},
			farKey: `far.source_key`,
			cols:   graphAzureGrantCols,
		},
		GraphEdgeTarget: {
			kind: GraphEdgeTarget, claim: RefTarget,
			from:   `iga_access_edges e0`,
			where:  `e0.provider = ` + graphProviderSlot,
			live:   graphAzureLive,
			near:   map[string]string{RefResource: `e0.resource_id`},
			farKey: `e0.source_key`,
			cols:   graphAzureTargetReverseCols,
		},
	},
}

// graphSpecForSide is the spec one provider reads a kind with: Azure's own
// grant and target, graphSpecs' otherwise.
func graphSpecForSide(dir, kind, side string) *graphEdgeSpec {
	if side == models.ProviderAzure {
		if s := graphAzureSpecs[dir][kind]; s != nil {
			return s
		}
	}
	return graphSpecFor(dir, kind)
}

// graphAzureScopeRows names a scope target's far node: its far key is the
// lowercased scope path, and its id that path's UUID v5.
func graphAzureScopeRows(rows []graphEdgeRow) {
	for i := range rows {
		if rows[i].ToType == RefScope {
			rows[i].ToID = graphAzureScopeID(rows[i].FarKey)
		}
	}
}

// graphAzureScopeID is a scope node's id: the UUID v5 of its lowercased path.
func graphAzureScopeID(path string) uuid.UUID {
	return uuid.NewSHA1(graphAzureScopeNS, []byte(strings.ToLower(path)))
}

/* ---------------------------------- keys ----------------------------------- */

// graphAzureKey reports whether a source key is the Azure projection's.
func graphAzureKey(key string) bool { return strings.HasPrefix(key, graphAzureKeyPrefix) }

// graphAzureKeyParts is an Azure source key's segments after the provider:
// the tenant, the part, then the part's own segments. nil for another key.
func graphAzureKeyParts(key string) []string {
	if !graphAzureKey(key) {
		return nil
	}
	return strings.Split(strings.TrimPrefix(key, graphAzureKeyPrefix), azuregraph.Sep)
}

// graphAzureTenantScope is the scope an Azure key's tenant names (as the
// projection states it on every row: kind azure_tenant, id and label the
// lowercased tenant id), or nil.
func graphAzureTenantScope(key string) *GraphScope {
	parts := graphAzureKeyParts(key)
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}
	return &GraphScope{Kind: azuregraph.ScopeKindTenant, ID: parts[0], Label: parts[0]}
}

// graphAzureSubscription is the subscription id a scope path is under, "" for
// none.
func graphAzureSubscription(path string) string {
	rest, ok := strings.CutPrefix(strings.ToLower(path), "/subscriptions/")
	if !ok {
		return ""
	}
	sub, _, _ := strings.Cut(rest, "/")
	return sub
}

// graphAzureSubscriptionName is a subscription's name, else its id.
func graphAzureSubscriptionName(sub string, subs map[string]string) string {
	if n := subs[sub]; n != "" {
		return n
	}
	return sub
}

// graphAzureScopeOf is what a scope path names, and its label:
//
//	/                                          Tenant root
//	/providers/microsoft.management/managementgroups/<mg>   Management group <mg>
//	/subscriptions/<id>                        Subscription <name>
//	/subscriptions/<id>/resourcegroups/<rg>    Resource group <rg>
//	/subscriptions/<id>/.../<name>             Resource <name>
//	directory                                  Entra directory
//	directory<scope>                           Entra directory scope <scope>
//
// and anything else is its path.
func graphAzureScopeOf(path string, subs map[string]string) (kind, label string) {
	p := strings.ToLower(strings.TrimSpace(path))
	switch {
	case p == "/" || p == "":
		return GraphAzureScopeTenantRoot, "Tenant root"
	case p == "directory":
		return GraphAzureScopeDirectory, "Entra directory"
	case strings.HasPrefix(p, "directory"):
		return GraphAzureScopeDirectory, "Entra directory scope " + strings.TrimPrefix(strings.TrimPrefix(p, "directory"), "/")
	}
	if mg, ok := strings.CutPrefix(p, "/providers/microsoft.management/managementgroups/"); ok && mg != "" && !strings.Contains(mg, "/") {
		return GraphAzureScopeManagementGroup, "Management group " + mg
	}
	if sub := graphAzureSubscription(p); sub != "" {
		segs := strings.Split(strings.Trim(p, "/"), "/")
		switch {
		case len(segs) == 2:
			return GraphAzureScopeSubscription, "Subscription " + graphAzureSubscriptionName(sub, subs)
		case len(segs) == 4 && segs[2] == "resourcegroups":
			return GraphAzureScopeResourceGroup, "Resource group " + segs[3]
		case len(segs) > 4:
			return GraphAzureScopeResource, "Resource " + segs[len(segs)-1]
		}
	}
	return GraphAzureScopeOther, path
}

/* ---------------------------------- nodes ---------------------------------- */

// graphSplitAzureNodes splits off Azure's nodes.
func graphSplitAzureNodes(nodes []*GraphNode) (rest, azure []*GraphNode) {
	for _, n := range nodes {
		if n.side() == models.ProviderAzure {
			azure = append(azure, n)
		} else {
			rest = append(rest, n)
		}
	}
	return rest, azure
}

// graphSplitAzureEdges splits off Azure's edges.
func graphSplitAzureEdges(edges []*GraphEdge) (rest, azure []*GraphEdge) {
	for _, e := range edges {
		if e.side == models.ProviderAzure {
			azure = append(azure, e)
		} else {
			rest = append(rest, e)
		}
	}
	return rest, azure
}

// azureSubscriptions reads, once per request, every Azure subscription
// connector's display name -- the name the projection states as a node's
// sub_scope.
func (t *graphTraversal) azureSubscriptions(lv *graphLevel) (map[string]string, error) {
	if t.az != nil {
		return t.az.subs, nil
	}
	tx, err := lv.db()
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID   string
		Name string
	}
	if err := tx.Raw(`SELECT lower(c.scope_id) AS id, COALESCE(c.attrs->>'display_name', '') AS name
	                    FROM cloud_connector c
	                   WHERE c.workspace_id = ? AND c.provider = ? AND c.scope_kind = ?
	                   ORDER BY c.id`, t.q.WS, models.CloudProviderAzure, models.CloudScopeSubscription).Scan(&rows).Error; err != nil {
		return nil, err
	}
	subs := map[string]string{}
	for _, r := range rows {
		if r.Name != "" && subs[r.ID] == "" {
			subs[r.ID] = r.Name
		}
	}
	t.az = &graphAzureState{subs: subs}
	return subs, nil
}

// fetchAzureNodes reads Azure nodes: workloads, identities and resources
// through the unified inventory's classes, external principals the Azure
// projection wrote, role assignments, and scopes (no row: their path). Every
// row read carries D-6's readability predicate, as AWS's do.
func (t *graphTraversal) fetchAzureNodes(lv *graphLevel, nodes []*GraphNode) error {
	byType := map[string]map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		if byType[n.typ] == nil {
			byType[n.typ] = map[uuid.UUID]*GraphNode{}
		}
		byType[n.typ][n.id] = n
	}
	for _, typ := range []string{RefWorkload, RefIdentity, RefExternalPrincipal, RefResource, RefRoleAssignment, RefScope} {
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
			err = t.fetchAzureScoped(lv, inventoryWorkloads, ids, set)
		case RefIdentity:
			err = t.fetchAzureScoped(lv, inventoryIdentities, ids, set)
		case RefResource:
			err = t.fetchAzureScoped(lv, inventoryResources, ids, set)
		case RefExternalPrincipal:
			err = t.fetchAzureExternal(lv, ids, set)
		case RefRoleAssignment:
			err = t.fetchAzureAssignments(lv, ids, set)
		case RefScope:
			err = t.fetchAzureScopes(lv, set)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// fetchAzureScoped reads Azure workloads, identities or resources through the
// unified inventory's class (its table, alias, kind column and expressions),
// as fetchK8sScoped reads Kubernetes'.
func (t *graphTraversal) fetchAzureScoped(lv *graphLevel, c *inventoryClass, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
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
	                   WHERE `+a+`.workspace_id = ? AND `+a+`.provider = 'azure' AND `+SupportedSQL(a, c.supportCol)+`
	                     AND `+a+`.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		graphAzureScopedNode(set[r.ID], c.refType, r)
	}
	return nil
}

// graphAzureScopedNode completes a workload, identity or resource node from
// its inventory row.
func graphAzureScopedNode(n *GraphNode, refType string, r graphK8sScopedRow) {
	n.provider, n.Provider, n.key = models.ProviderAzure, models.ProviderAzure, r.SourceKey
	n.Label = r.DisplayName
	if refType == RefWorkload {
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
	} else {
		n.Scope = graphAzureTenantScope(r.SourceKey)
	}
	n.SubScope = &graphOptional{r.SubScope}
	n.NativeID = r.NativeID
	n.State, n.Lifecycle, n.LastConfirmedAt = r.State, r.Lifecycle, TS(r.LastConfirmedAt)
	n.stale = StaleSubject{ID: r.ID}
	n.fetched = true
}

// fetchAzureExternal reads external principals the Azure projection wrote
// (their source key is Azure's), with the D-1 state AWS's are read with: from
// their can_assume edges.
func (t *graphTraversal) fetchAzureExternal(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphExternalRow
	if err := tx.Raw(`SELECT ep.id, ep.issuer, ep.subject_claim, ep.mechanism, ep.source_key,
	                         ep.resolved_identity_account_id, ep.resolved_workload_id, ep.resolution_basis,
	                         ep.resolution_rule, ep.resolved_by, ep.resolution_state,
	                         st.state, st.last_confirmed_at
	                    FROM iga_external_principal ep
	                    LEFT JOIN LATERAL (
	                          SELECT CASE WHEN bool_or(r.state = 'current') THEN 'current'
	                                      WHEN bool_or(r.state = 'stale') THEN 'stale'
	                                      ELSE 'ended' END AS state,
	                                 max(r.last_confirmed_at) FILTER (WHERE r.state <> 'ended') AS last_confirmed_at
	                            FROM iga_relationship r
	                           WHERE r.workspace_id = ep.workspace_id AND r.source_external_principal_id = ep.id
	                             AND r.relationship_type = 'can_assume') st ON true
	                   WHERE ep.workspace_id = ? AND ep.source_key LIKE ? AND ep.id IN ?`,
		t.q.WS, graphAzureKeyPrefix+"%", ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		graphAzureExternalNode(set[r.ID], r)
	}
	return nil
}

// graphAzureExternalNode completes an Azure external principal: its label,
// mechanism, issuer and subject as AWS's, the tenant its key names, and a
// stored resolution DISPLAYED, never followed (D-87): an AKS ServiceAccount
// the projector tied it to is shown, and the walk stays in Azure.
func graphAzureExternalNode(n *GraphNode, r graphExternalRow) {
	n.provider, n.Provider, n.Kind, n.key = models.ProviderAzure, models.ProviderAzure, RefExternalPrincipal, r.SourceKey
	n.Label = GraphExternalLabel(r.Mechanism, r.Issuer, r.SubjectClaim)
	n.Mechanism, n.Issuer, n.Subject = r.Mechanism, r.Issuer, r.SubjectClaim
	n.Scope = graphAzureTenantScope(r.SourceKey)
	n.SubScope = &graphOptional{}
	n.NativeID = r.SubjectClaim
	n.State, n.Lifecycle, n.LastConfirmedAt = r.State, ExternalLifecycleOf(r.State), TS(r.LastConfirmedAt)
	if r.ResolutionBasis != "" {
		var to any
		switch {
		case r.ResolvedIdentityAccountID != nil:
			to = R(RefIdentity, *r.ResolvedIdentityAccountID)
		case r.ResolvedWorkloadID != nil:
			to = R(RefWorkload, *r.ResolvedWorkloadID)
		}
		n.Resolution = map[string]any{
			"state": r.ResolutionState, "basis": r.ResolutionBasis, "rule": nullIfBlank(r.ResolutionRule),
			"resolved_to": to, "resolved_by": nullIfBlank(r.ResolvedBy),
		}
		if ref, ok := to.(string); ok && r.ResolutionState == graphResolutionActive {
			n.resolvedTo = ref
		}
	}
	n.fetched = true
}

// graphAzureAssignmentRow is one role assignment: its access edge, and the
// role its entitlement states.
type graphAzureAssignmentRow struct {
	ID              uuid.UUID
	SourceKey       string
	State           string
	LastConfirmedAt *time.Time
	PathKind        string
	NativeScope     string
	NativeRights    string
}

func (t *graphTraversal) fetchAzureAssignments(lv *graphLevel, ids []uuid.UUID, set map[uuid.UUID]*GraphNode) error {
	subs, err := t.azureSubscriptions(lv)
	if err != nil {
		return err
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []graphAzureAssignmentRow
	if err := tx.Raw(`SELECT e.id, e.source_key, e.state, e.last_confirmed_at, e.path_kind, e.native_scope,
	                         COALESCE(en.native_rights::text, '') AS native_rights
	                    FROM iga_access_edges e
	                    LEFT JOIN iga_entitlements en ON en.workspace_id = e.workspace_id AND en.id = e.entitlement_id
	                                                 AND en.provider = 'azure'
	                   WHERE e.workspace_id = ? AND e.provider = 'azure' AND e.id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		graphAzureAssignmentNode(set[r.ID], r, subs)
	}
	return nil
}

// graphAzureAssignmentNode completes a role assignment node: kind statement,
// labelled by its role, with azure_role; its state and last_confirmed_at are
// the access edge's own; its scope is its tenant, its
// sub_scope the subscription its scope is under (null above one), its
// native_id the assignment's own id as Azure states it.
func graphAzureAssignmentNode(n *GraphNode, r graphAzureAssignmentRow, subs map[string]string) {
	var nr struct {
		RoleName   string          `json:"role_name"`
		Actions    []string        `json:"actions"`
		NotActions []string        `json:"not_actions"`
		Condition  json.RawMessage `json:"condition"`
	}
	_ = json.Unmarshal([]byte(r.NativeRights), &nr)
	if nr.Actions == nil {
		nr.Actions = []string{}
	}
	if nr.NotActions == nil {
		nr.NotActions = []string{}
	}
	if string(nr.Condition) == "null" {
		nr.Condition = nil
	}
	n.provider, n.Provider, n.key = models.ProviderAzure, models.ProviderAzure, r.SourceKey
	n.Kind, n.Label = RefStatement, nr.RoleName
	if n.Label == "" {
		n.Label = "Role assignment"
	}
	// It takes the statement's place and columns (D-114): its policy is its
	// role, Allow, no sid, no exclusions, and a group key of the role and the
	// scope it applies at.
	sid, empty := "", []GraphExclusion{}
	n.Policy, n.Effect, n.Sid, n.Exclusions = nr.RoleName, models.EffectAllow, &sid, &empty
	n.GroupKey = "azure:" + nr.RoleName + "@" + strings.ToLower(r.NativeScope)
	n.AzureRole = &GraphAzureRole{RoleName: nr.RoleName, GrantKind: r.PathKind,
		Actions: nr.Actions, NotActions: nr.NotActions, Condition: nr.Condition}
	n.Scope = graphAzureTenantScope(r.SourceKey)
	sub := ""
	if id := graphAzureSubscription(r.NativeScope); id != "" {
		sub = graphAzureSubscriptionName(id, subs)
	}
	n.SubScope = &graphOptional{sub}
	// azure␟tenant␟grant␟<subject>␟<assignment>␟<resource> (azuregraph.GrantKey).
	if parts := graphAzureKeyParts(r.SourceKey); len(parts) >= 4 {
		n.NativeID = parts[3]
	}
	n.State, n.LastConfirmedAt = r.State, TS(r.LastConfirmedAt)
	n.fetched = true
}

// fetchAzureScopes completes scope nodes from their path (the far key the
// target read): nothing is read but the subscriptions' names.
func (t *graphTraversal) fetchAzureScopes(lv *graphLevel, set map[uuid.UUID]*GraphNode) error {
	subs, err := t.azureSubscriptions(lv)
	if err != nil {
		return err
	}
	for _, n := range set {
		if n.key == "" || graphAzureScopeID(n.key) != n.id {
			continue // not a scope a target named: never read
		}
		graphAzureScopeNode(n, subs)
	}
	return nil
}

// graphAzureScopeNode completes a scope node from its path. Its state and
// tenant are the targets' that reach it (graphAzureDecorateEdges).
func graphAzureScopeNode(n *GraphNode, subs map[string]string) {
	_, label := graphAzureScopeOf(n.key, subs)
	n.provider, n.Provider = models.ProviderAzure, models.ProviderAzure
	n.Kind, n.Label, n.NativeID = RefScope, label, n.key
	sub := ""
	if id := graphAzureSubscription(n.key); id != "" {
		sub = graphAzureSubscriptionName(id, subs)
	}
	n.SubScope = &graphOptional{sub}
	n.fetched = true
}

// decorateAzureNodes completes Azure nodes a level found: an identity's
// restrictions -- always {0, false}: deny assignments are not read (D-114) --
// and used-by count, by the list's own function; a resource's
// azure_scope_access_not_drawn, when its condition holds; a stale node's
// stale_reason (graphAzureStaleReason).
func (t *graphTraversal) decorateAzureNodes(lv *graphLevel, nodes []*GraphNode) error {
	var ids, resources []uuid.UUID
	var idents []*GraphNode
	byID := map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		if n.State == StateStale {
			n.StaleReason = graphAzureStaleReason(n.Scope)
		}
		switch n.typ {
		case RefIdentity:
			n.Restrictions = &GraphRestrictions{}
			ids = append(ids, n.id)
			idents = append(idents, n)
		case RefResource:
			resources = append(resources, n.id)
			byID[n.id] = n
		}
	}
	if len(resources) > 0 {
		reached, err := t.azureScopeAccess(lv, resources)
		if err != nil {
			return err
		}
		for _, id := range reached {
			if n := byID[id]; n != nil {
				n.Limitations = []GraphLimitation{{"code": LimAzureScopeAccessNotDrawn}}
			}
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
		c, ok := used[n.id]
		if !ok {
			c = Unknown()
		}
		n.UsedByCount = &c
	}
	return nil
}

// azureScopeAccess is, of the given Azure resources, those an assignment of
// their tenant at a broader scope reaches without naming them -- the
// condition of azure_scope_access_not_drawn (D-114): the tenant root or a
// management group (whose subscriptions are not read, so it may reach it), or
// a path the resource's ARM id is under (its subscription, resource group or
// a parent resource). Never the resource's own assignments. One statement.
func (t *graphTraversal) azureScopeAccess(lv *graphLevel, ids []uuid.UUID) ([]uuid.UUID, error) {
	tx, err := lv.db()
	if err != nil {
		return nil, err
	}
	native := `lower(` + inventoryResources.nativeSQL() + `)`
	var out []uuid.UUID
	if err := tx.Raw(`SELECT r.id FROM iga_resources r
	                   WHERE r.workspace_id = ? AND r.provider = 'azure' AND r.id IN ?
	                     AND starts_with(`+native+`, '/subscriptions/')
	                     AND EXISTS (SELECT 1 FROM iga_access_edges e
	                                  WHERE e.workspace_id = r.workspace_id AND e.provider = 'azure'
	                                    AND e.state <> 'ended' AND e.native_scope <> ''
	                                    AND e.resource_id IS DISTINCT FROM r.id
	                                    AND split_part(e.source_key, chr(31), 2) = split_part(r.source_key, chr(31), 2)
	                                    AND (e.native_scope = '/'
	                                         OR starts_with(lower(e.native_scope), '/providers/microsoft.management/managementgroups/')
	                                         OR starts_with(`+native+`, rtrim(lower(e.native_scope), '/') || '/')))
	                   ORDER BY r.id`, t.q.WS, ids).Scan(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// graphAzureStaleReason is a stale Azure element's stale_reason (D-114):
// {surface: azure_scan, state: stale}, under its tenant (account_id, as a
// Kubernetes one names its cluster), since not known. Per-partition Azure
// coverage is not read yet.
func graphAzureStaleReason(scope *GraphScope) *[]StaleReason {
	tenant := ""
	if scope != nil {
		tenant = scope.ID
	}
	return &[]StaleReason{{AccountID: tenant, Surface: graphAzureStaleSurface, State: StateStale, Since: nil}}
}

/* ---------------------------------- edges ---------------------------------- */

// graphAzureStateRank orders states for a scope node reached by several
// targets: the strongest wins.
var graphAzureStateRank = map[string]int{StateEnded: 1, StateStale: 2, StateCurrent: 3}

// graphAzureDecorateEdges completes Azure edges once both endpoints are read:
// the provider; on a grant its policy_kind (the assignment's grant kind,
// D-114); a stale edge's stale_reason; and a scope node's tenant and state --
// its targets'. Nothing crosses an account: Azure nodes have none.
func graphAzureDecorateEdges(edges []*GraphEdge, node func(string) *GraphNode) {
	for _, e := range edges {
		e.Provider = models.ProviderAzure
		from, to := node(e.From), node(e.To)
		if e.State == StateStale {
			var scope *GraphScope
			for _, n := range []*GraphNode{from, to} {
				if scope == nil && n != nil {
					scope = n.Scope
				}
			}
			e.StaleReason = graphAzureStaleReason(scope)
		}
		if e.Kind == GraphEdgeGrant && to != nil && to.AzureRole != nil {
			e.PolicyKind = to.AzureRole.GrantKind
		}
		if e.Kind != GraphEdgeTarget || to == nil || to.typ != RefScope {
			continue
		}
		if to.Scope == nil && from != nil && from.Scope != nil {
			s := *from.Scope
			to.Scope = &s
		}
		if graphAzureStateRank[e.State] > graphAzureStateRank[to.State] {
			to.State, to.StaleReason = e.State, nil
			if to.State == StateStale {
				to.StaleReason = graphAzureStaleReason(to.Scope)
			}
		}
	}
}

// graphAzureLimitations sets an Azure element's limitations: none of its own.
// What holds for every Azure element -- effective access and conditions not
// evaluated -- is the meta's (graphAzureMeta).
func graphAzureLimitations(nodes []*GraphNode, edges []*GraphEdge) {
	for _, n := range nodes {
		if n.Limitations == nil {
			n.Limitations = []GraphLimitation{}
		}
	}
	for _, e := range edges {
		if e.Limitations == nil {
			e.Limitations = []GraphLimitation{}
		}
	}
}
