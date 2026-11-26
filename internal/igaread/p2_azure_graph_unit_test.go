package igaread

// Unit tests for the Azure traversal's pure parts (traverse_azure.go): node
// shapes (identity, role assignment, scope, external principal), edge claims,
// scope labels and ids, the provider rendering of Azure's specs, the kinds
// each Azure node leads out by, and the meta. The traversal itself is tested
// against real PostgreSQL in tests/integration/p2_azure_graph_test.go.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/models"
)

const azTestTenant = "0f0e0d0c-1111-2222-3333-444455556666"

// azJSON renders a node or edge as the route does.
func azJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestP2AzureGraphScopeLabelsAndIDs(t *testing.T) {
	sub := "9a8b7c6d-0000-1111-2222-333344445555"
	subs := map[string]string{sub: "Authnull"}
	for _, tc := range []struct{ path, kind, label string }{
		{"/", GraphAzureScopeTenantRoot, "Tenant root"},
		{"/subscriptions/" + sub, GraphAzureScopeSubscription, "Subscription Authnull"},
		{"/SUBSCRIPTIONS/" + strings.ToUpper(sub), GraphAzureScopeSubscription, "Subscription Authnull"},
		{"/subscriptions/unknown-sub", GraphAzureScopeSubscription, "Subscription unknown-sub"},
		{"/subscriptions/" + sub + "/resourcegroups/rg-prod", GraphAzureScopeResourceGroup, "Resource group rg-prod"},
		{"/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo", GraphAzureScopeResource, "Resource stdemo"},
		{"/providers/microsoft.management/managementgroups/mg-root", GraphAzureScopeManagementGroup, "Management group mg-root"},
		{"directory", GraphAzureScopeDirectory, "Entra directory"},
		{"directory/administrativeunits/au-1", GraphAzureScopeDirectory, "Entra directory scope administrativeunits/au-1"},
		{"Microsoft Graph", GraphAzureScopeOther, "Microsoft Graph"},
	} {
		kind, label := graphAzureScopeOf(tc.path, subs)
		if kind != tc.kind || label != tc.label {
			t.Errorf("scope %q = (%s, %q), want (%s, %q)", tc.path, kind, label, tc.kind, tc.label)
		}
	}
	// scope:<uuid v5 of the lowercased path>: one node per path, whatever its case.
	a, b := graphAzureScopeID("/subscriptions/"+sub), graphAzureScopeID("/Subscriptions/"+strings.ToUpper(sub))
	if a != b || a.Version() != 5 {
		t.Errorf("scope ids %s %s (version %d): want one v5 id per lowercased path", a, b, a.Version())
	}
	if graphAzureScopeID("/") == a {
		t.Error("two paths share a scope id")
	}
	// A target read to a scope is named by its far key (the lowercased path);
	// a target to a resource keeps the resource's id.
	res := uuid.New()
	rows := []graphEdgeRow{
		{ClaimID: uuid.New(), ToID: uuid.New(), ToType: RefScope, FarKey: "/subscriptions/" + sub},
		{ClaimID: uuid.New(), ToID: res, ToType: RefResource, FarKey: "azure\x1fx\x1fresource\x1fr"},
	}
	graphAzureScopeRows(rows)
	if rows[0].ToID != a || rows[1].ToID != res {
		t.Errorf("scope rows = %+v", rows)
	}
}

// Every Azure spec renders to 'azure' and nothing else, names the provider in
// its where, and matches workspace_id on both sides of every join.
func TestP2AzureGraphSpecsRenderAzure(t *testing.T) {
	for dir, specs := range graphAzureSpecs {
		for kind, s := range specs {
			for _, part := range []string{s.from, graphPredicates(s, false), graphPredicates(s, true), s.cols} {
				r := graphRender(part, models.ProviderAzure)
				if strings.Contains(r, graphProviderSlot) || strings.Contains(r, "'aws'") || strings.Contains(r, "'k8s'") {
					t.Errorf("%s %s azure render: %s", dir, kind, r)
				}
			}
			if !strings.Contains(s.where, "e0.provider = "+graphProviderSlot) {
				t.Errorf("%s %s: where does not hold the access edge to the provider", dir, kind)
			}
			if strings.Contains(s.from, "JOIN") && !strings.Contains(s.from, "far.workspace_id = e0.workspace_id") {
				t.Errorf("%s %s: a join does not match workspace_id: %s", dir, kind, s.from)
			}
			if graphSpecForSide(dir, kind, models.ProviderAzure) != s {
				t.Errorf("%s %s: Azure does not read its own spec", dir, kind)
			}
			if graphSpecForSide(dir, kind, models.ProviderAWS) == s || graphSpecForSide(dir, kind, models.ProviderK8s) == s {
				t.Errorf("%s %s: another provider reads Azure's spec", dir, kind)
			}
		}
	}
	// The relationship kinds are graphSpecs' own, rendered 'azure'.
	if graphSpecForSide(GraphForward, GraphEdgeMemberOf, models.ProviderAzure) != graphSpecFor(GraphForward, GraphEdgeMemberOf) {
		t.Error("Azure member_of is not the shared spec")
	}
	if !strings.Contains(graphRender(graphSpecFor(GraphReverse, GraphEdgeExecutesAs).where, models.ProviderAzure), "far.provider = 'azure'") {
		t.Error("executes_as does not render 'azure'")
	}
}

func TestP2AzureGraphClaims(t *testing.T) {
	id, holder, res := uuid.New(), uuid.New(), uuid.New()
	grant := graphAzureSpecs[GraphForward][GraphEdgeGrant]
	target := graphAzureSpecs[GraphForward][GraphEdgeTarget]
	if got := grant.claimRef(id).String(); got != "grant:"+id.String() {
		t.Errorf("grant claim %s", got)
	}
	if got := target.claimRef(id).String(); got != "target:"+id.String() {
		t.Errorf("target claim %s", got)
	}
	if graphAzureSpecs[GraphReverse][GraphEdgeGrant].claim != RefGrant || graphAzureSpecs[GraphReverse][GraphEdgeTarget].claim != RefTarget {
		t.Error("reverse claims differ from forward")
	}
	cur := StateCurrent
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	g := graphEdgeRow{ClaimID: id, FromID: holder, FromType: RefIdentity, ToID: id, ToType: RefRoleAssignment,
		State: &cur, Basis: models.BasisObserved, LastConfirmedAt: &at}.
		edge(GraphEdgeGrant, grant.claimRef(id), R(RefIdentity, holder), R(RefRoleAssignment, id))
	tg := graphEdgeRow{ClaimID: id, FromID: id, FromType: RefRoleAssignment, ToID: res, ToType: RefResource,
		State: &cur, Basis: models.BasisObserved, LastConfirmedAt: &at}.
		edge(GraphEdgeTarget, target.claimRef(id), R(RefRoleAssignment, id), R(RefResource, res))
	g.side, tg.side = models.ProviderAzure, models.ProviderAzure
	rest, az := graphSplitAzureEdges([]*GraphEdge{g, tg})
	if len(rest) != 0 || len(az) != 2 {
		t.Fatalf("split = %d, %d", len(rest), len(az))
	}
	assignment := &GraphNode{typ: RefRoleAssignment, id: id, Scope: &GraphScope{Kind: "azure_tenant", ID: azTestTenant, Label: azTestTenant},
		AzureRole: &GraphAzureRole{GrantKind: "azure_rbac"}}
	graphAzureDecorateEdges(az, func(ref string) *GraphNode {
		if ref == R(RefRoleAssignment, id) {
			return assignment
		}
		return nil
	})
	graphAzureLimitations(nil, az)
	ge, te := azJSON(t, g), azJSON(t, tg)
	for name, want := range map[string]any{
		"claim": "grant:" + id.String(), "kind": "grant", "from": "identity:" + holder.String(),
		"to": "role_assignment:" + id.String(), "state": "current", "provider": "azure", "crosses_account": false,
		"policy_kind": "azure_rbac",
	} {
		if ge[name] != want {
			t.Errorf("grant %s = %v, want %v", name, ge[name], want)
		}
	}
	for name, want := range map[string]any{
		"claim": "target:" + id.String(), "kind": "target", "from": "role_assignment:" + id.String(),
		"to": "resource:" + res.String(), "provider": "azure",
	} {
		if te[name] != want {
			t.Errorf("target %s = %v, want %v", name, te[name], want)
		}
	}
	if ls, ok := ge["limitations"].([]any); !ok || len(ls) != 0 {
		t.Errorf("grant limitations = %v, want []", ge["limitations"])
	}
	if _, ok := te["policy_kind"]; ok {
		t.Errorf("a target carries policy_kind: %v", te)
	}
	// A stale Azure edge's stale_reason is D-114's {surface: azure_scan, state: stale}.
	stale := StateStale
	se := graphEdgeRow{ClaimID: id, State: &stale}.edge(GraphEdgeGrant, grant.claimRef(id), R(RefIdentity, holder), R(RefRoleAssignment, id))
	graphAzureDecorateEdges([]*GraphEdge{se}, func(ref string) *GraphNode {
		if ref == R(RefRoleAssignment, id) {
			return assignment
		}
		return nil
	})
	sr, _ := azJSON(t, se)["stale_reason"].([]any)
	if len(sr) != 1 || digAz(sr[0], "surface") != "azure_scan" || digAz(sr[0], "state") != "stale" || digAz(sr[0], "account_id") != azTestTenant {
		t.Errorf("stale_reason = %v", sr)
	}
}

func digAz(v any, k string) any {
	m, _ := v.(map[string]any)
	return m[k]
}

func TestP2AzureGraphNodeShapes(t *testing.T) {
	sub := "9a8b7c6d-0000-1111-2222-333344445555"
	subs := map[string]string{sub: "Authnull"}
	assignment := "/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo" +
		"/providers/microsoft.authorization/roleassignments/ra-1"
	edgeID := uuid.New()
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

	// The role assignment: kind statement, labelled by its role, azure_role.
	ra := &GraphNode{typ: RefRoleAssignment, id: edgeID, Ref: R(RefRoleAssignment, edgeID)}
	graphAzureAssignmentNode(ra, graphAzureAssignmentRow{
		ID: edgeID, SourceKey: azuregraph.GrantKey(azTestTenant, "sp-oid", assignment, "/subscriptions/"+sub+"/x"),
		State: StateCurrent, LastConfirmedAt: &at, PathKind: "azure_rbac",
		NativeScope: "/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo",
		NativeRights: `{"role_name":"Storage Blob Data Reader","actions":["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],` +
			`"not_actions":null,"condition":{"expression":"@Resource[x] == 'y'"}}`,
	}, subs)
	graphAzureLimitations([]*GraphNode{ra}, nil)
	j := azJSON(t, ra)
	for name, want := range map[string]any{
		"ref": "role_assignment:" + edgeID.String(), "kind": "statement", "label": "Storage Blob Data Reader",
		"provider": "azure", "state": "current", "sub_scope": "Authnull", "native_id": strings.ToLower(assignment),
		"last_confirmed_at": "2026-10-20T09:00:00Z",
		// D-114: it takes the statement's columns.
		"policy": "Storage Blob Data Reader", "effect": "allow", "sid": "",
		"group_key": "azure:Storage Blob Data Reader@/subscriptions/" + sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo",
	} {
		if j[name] != want {
			t.Errorf("assignment %s = %v, want %v", name, j[name], want)
		}
	}
	if ex, ok := j["exclusions"].([]any); !ok || len(ex) != 0 {
		t.Errorf("assignment exclusions = %v, want []", j["exclusions"])
	}
	for _, absent := range []string{"account", "arn", "k8s_rule", "restrictions"} {
		if _, ok := j[absent]; ok {
			t.Errorf("assignment carries %s: %v", absent, j[absent])
		}
	}
	scope, _ := j["scope"].(map[string]any)
	if scope["kind"] != "azure_tenant" || scope["id"] != azTestTenant || scope["label"] != azTestTenant {
		t.Errorf("assignment scope = %v", j["scope"])
	}
	role, _ := j["azure_role"].(map[string]any)
	if role["role_name"] != "Storage Blob Data Reader" || role["grant_kind"] != "azure_rbac" {
		t.Errorf("azure_role = %v", role)
	}
	if acts, _ := role["actions"].([]any); len(acts) != 1 {
		t.Errorf("azure_role.actions = %v", role["actions"])
	}
	if na, ok := role["not_actions"].([]any); !ok || len(na) != 0 {
		t.Errorf("azure_role.not_actions = %v, want []", role["not_actions"])
	}
	if cond, _ := role["condition"].(map[string]any); cond["expression"] == nil {
		t.Errorf("azure_role.condition = %v, want verbatim", role["condition"])
	}
	// No condition is null, never absent.
	plain := &GraphNode{typ: RefRoleAssignment, id: uuid.New()}
	graphAzureAssignmentNode(plain, graphAzureAssignmentRow{SourceKey: azuregraph.GrantKey(azTestTenant, "u", "directoryroleassignment", ""),
		State: StateStale, PathKind: "entra_directory_role", NativeScope: "directory",
		NativeRights: `{"role_name":"Global Reader","actions":["microsoft.directory/allEntities/read"]}`}, subs)
	pj := azJSON(t, plain)
	if r, _ := pj["azure_role"].(map[string]any); r == nil || r["condition"] != nil {
		t.Errorf("unconditioned azure_role = %v", pj["azure_role"])
	} else if _, ok := r["condition"]; !ok {
		t.Error("azure_role.condition is absent, want null")
	}
	if pj["sub_scope"] != nil {
		t.Errorf("directory assignment sub_scope = %v, want null", pj["sub_scope"])
	}

	// The scope node: a leaf named from its path, with its target's tenant
	// and state.
	subPath := "/subscriptions/" + sub
	sc := &GraphNode{typ: RefScope, id: graphAzureScopeID(subPath), Ref: R(RefScope, graphAzureScopeID(subPath)),
		key: subPath, want: models.ProviderAzure}
	graphAzureScopeNode(sc, subs)
	sub2 := &GraphNode{typ: RefRoleAssignment, id: uuid.New(), Scope: ra.Scope, State: StateCurrent}
	sub2.Ref = R(RefRoleAssignment, sub2.id)
	cur := StateCurrent
	e := graphEdgeRow{State: &cur}.edge(GraphEdgeTarget, Ref{Type: RefTarget, ID: sub2.id}, sub2.Ref, sc.Ref)
	nodes := map[string]*GraphNode{sc.Ref: sc, sub2.Ref: sub2}
	graphAzureDecorateEdges([]*GraphEdge{e}, func(ref string) *GraphNode { return nodes[ref] })
	graphAzureLimitations([]*GraphNode{sc}, nil)
	sj := azJSON(t, sc)
	for name, want := range map[string]any{
		"ref": "scope:" + graphAzureScopeID(subPath).String(), "kind": "scope",
		"label": "Subscription Authnull", "provider": "azure", "state": "current", "sub_scope": "Authnull",
		"native_id": subPath,
	} {
		if sj[name] != want {
			t.Errorf("scope %s = %v, want %v", name, sj[name], want)
		}
	}
	if s, _ := sj["scope"].(map[string]any); s["kind"] != "azure_tenant" || s["id"] != azTestTenant {
		t.Errorf("scope node's scope = %v", sj["scope"])
	}
	tr := &graphTraversal{}
	for _, dir := range []string{GraphForward, GraphReverse} {
		if ks := tr.kindsFor(sc, dir); len(ks) != 0 {
			t.Errorf("a scope leads out %s by %v: it is a leaf", dir, ks)
		}
	}

	// An identity, as the inventory reads it.
	idn := &GraphNode{typ: RefIdentity, id: uuid.New()}
	graphAzureScopedNode(idn, RefIdentity, graphK8sScopedRow{ID: idn.id, DisplayName: "sp-reader",
		Kind: models.CloudIdentityEntraServicePrincipal, SourceKey: azuregraph.IdentityKey(azTestTenant, "sp-oid"),
		Lifecycle: models.IGALifecycleActive, ScopeKind: "azure_tenant", ScopeID: azTestTenant, ScopeLabel: azTestTenant,
		NativeID: "sp-oid", State: StateCurrent})
	ij := azJSON(t, idn)
	if ij["provider"] != "azure" || ij["kind"] != models.CloudIdentityEntraServicePrincipal || ij["native_id"] != "sp-oid" ||
		ij["label"] != "sp-reader" {
		t.Errorf("identity = %v", ij)
	}
	if v, ok := ij["sub_scope"]; !ok || v != nil {
		t.Errorf("identity sub_scope = %v (present %v), want null", v, ok)
	}
	for _, absent := range []string{"account", "arn", "azure_role"} {
		if _, ok := ij[absent]; ok {
			t.Errorf("identity carries %s", absent)
		}
	}

	// An external principal the Azure projection wrote.
	ep := &GraphNode{typ: RefExternalPrincipal, id: uuid.New()}
	k8sSA := uuid.New()
	graphAzureExternalNode(ep, graphExternalRow{ID: ep.id, Issuer: "https://oidc.aks/x/", SubjectClaim: "system:serviceaccount:shop:api",
		Mechanism: "oidc", SourceKey: azuregraph.ExternalPrincipalKey(azTestTenant, "https://oidc.aks/x/", "system:serviceaccount:shop:api"),
		ResolvedIdentityAccountID: &k8sSA, ResolutionBasis: models.BasisDerived, ResolutionRule: "aks_oidc_issuer_and_cluster_name",
		ResolutionState: graphResolutionActive, State: StateCurrent})
	ej := azJSON(t, ep)
	if ej["provider"] != "azure" || ej["kind"] != RefExternalPrincipal || ej["native_id"] != "system:serviceaccount:shop:api" {
		t.Errorf("external principal = %v", ej)
	}
	if s, _ := ej["scope"].(map[string]any); s["id"] != azTestTenant {
		t.Errorf("external principal scope = %v", ej["scope"])
	}
	if ep.resolvedTo != R(RefIdentity, k8sSA) {
		t.Errorf("resolution in force not displayed: %q", ep.resolvedTo)
	}
}

func TestP2AzureGraphKindsAndRefs(t *testing.T) {
	az := func(typ string) *GraphNode {
		return &GraphNode{typ: typ, id: uuid.New(), provider: models.ProviderAzure}
	}
	tr := &graphTraversal{}
	for _, tc := range []struct {
		typ, dir, want string
	}{
		{RefIdentity, GraphForward, "can_assume,grant,member_of"},
		{RefIdentity, GraphReverse, "can_assume,executes_as,member_of"},
		{RefRoleAssignment, GraphForward, "target"},
		{RefRoleAssignment, GraphReverse, "grant"},
		{RefResource, GraphReverse, "target"},
		{RefResource, GraphForward, ""},
		{RefWorkload, GraphForward, "executes_as"},
		{RefExternalPrincipal, GraphForward, "can_assume"},
	} {
		if got := strings.Join(tr.kindsFor(az(tc.typ), tc.dir), ","); got != tc.want {
			t.Errorf("azure %s %s kinds = %q, want %q", tc.typ, tc.dir, got, tc.want)
		}
	}
	// AWS's kinds are what they were.
	aws := func(typ string) *GraphNode { return &GraphNode{typ: typ, provider: models.ProviderAWS} }
	for _, tc := range []struct{ typ, dir, want string }{
		{RefIdentity, GraphForward, "can_assume,grant,member_of"},
		{RefStatement, GraphForward, "target"},
		{RefStatement, GraphReverse, "grant"},
		{RefResource, GraphReverse, "target"},
		{RefWorkload, GraphForward, "executes_as,task_execution_role"},
	} {
		if got := strings.Join(tr.kindsFor(aws(tc.typ), tc.dir), ","); got != tc.want {
			t.Errorf("aws %s %s kinds = %q, want %q", tc.typ, tc.dir, got, tc.want)
		}
	}
	if az(RefIdentity).side() != models.ProviderAzure || graphSideHasKind(models.ProviderAzure, GraphEdgeTaskExecutionRole) {
		t.Error("Azure side")
	}
	// A role assignment is a node a request may name; a scope is not.
	id := uuid.New()
	if _, perr := ParseRefParam("node", "role_assignment:"+id.String(), graphNodeTypes...); perr != nil {
		t.Errorf("role_assignment ref refused: %v", perr)
	}
	if _, perr := ParseRefParam("node", "scope:"+id.String(), graphNodeTypes...); perr == nil {
		t.Error("scope ref accepted as a traversal node")
	}
	if !graphAzureKey(azuregraph.IdentityKey(azTestTenant, "x")) || graphAzureKey("aws\x1fx") {
		t.Error("graphAzureKey")
	}
}

func TestP2AzureGraphMeta(t *testing.T) {
	rev := int64(7)
	now := time.Now()
	m := GraphMeta{DetailMeta: DetailMeta{Rev: &rev, PublishedAt: &now, GraphState: GraphPublished}}
	graphAzureMeta(&m, false, false)
	j := azJSON(t, m)
	if j["graph_state"] != "unrevisioned" || j["rev"] != nil || j["published_at"] != nil {
		t.Errorf("meta = %v", j)
	}
	ls, _ := j["limitations"].([]any)
	var codes []string
	for _, l := range ls {
		codes = append(codes, l.(map[string]any)["code"].(string))
	}
	if strings.Join(codes, ",") != "effective_access_not_evaluated,azure_conditions_not_evaluated" {
		t.Errorf("meta limitations = %v", codes)
	}
	// With an AWS end (a /graph/path between providers): mixed, AWS's rev kept.
	m = GraphMeta{DetailMeta: DetailMeta{Rev: &rev, PublishedAt: &now, GraphState: GraphPublished}}
	graphAzureMeta(&m, true, false)
	if m.GraphState != GraphMixed || m.Rev == nil || len(m.Limitations) != 3 {
		t.Errorf("mixed meta = %+v", m)
	}
}
