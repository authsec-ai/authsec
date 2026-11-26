package integration

// Azure on the traversal routes (internal/igaread/traverse_azure.go), against
// real PostgreSQL: rows shaped exactly as internal/azuregraph projects them
// (its own key functions), read back through the traversal.
//
// The world (tenant azTenant, subscription "Authnull"):
//
//	fn-ingest (workload)  --executes_as-->  sp-reader (service principal)
//	sp-reader  --member_of-->  readers (group)
//	sp-reader  --grant-->  [Storage Blob Data Reader]  --target-->  stdemo (storage account)
//	sp-reader  --grant-->  [Reader]                     --target-->  scope "Subscription Authnull"

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

type azGraphFixture struct {
	*p2Lab
	tenant, sub                string
	sp, group, fn, storage     uuid.UUID
	blobReader, subReader      uuid.UUID // access edges
	subScopeRef, storageNative string
}

func newAzGraphFixture(t *testing.T, name string) *azGraphFixture {
	t.Helper()
	l := newP2Lab(t, name, false)
	f := &azGraphFixture{p2Lab: l, tenant: strings.ToLower(uuid.NewString()), sub: strings.ToLower(uuid.NewString())}
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(q string, args ...any) {
		t.Helper()
		if err := l.db.Exec(q, args...).Error; err != nil {
			t.Fatalf("fixture: %v\n%s", err, q)
		}
	}
	tenantConn, subConn := uuid.New(), uuid.New()
	exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
	      VALUES (?, ?, 'azure', 'tenant', ?, 'active', 'vault://azure/test')`, tenantConn, l.ws, f.tenant)
	exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref, attrs)
	      VALUES (?, ?, 'azure', 'subscription', ?, ?, 'active', 'vault://azure/test', ?::jsonb)`,
		subConn, l.ws, f.sub, f.tenant, `{"display_name":"Authnull","tenant_id":"`+f.tenant+`"}`)

	scopeAttrs := func(native, subScope string) string {
		m := map[string]any{"scope_kind": azuregraph.ScopeKindTenant, "scope_id": f.tenant, "scope_label": f.tenant, "native_id": native}
		if subScope != "" {
			m["sub_scope"], m["subscription_id"] = subScope, f.sub
		}
		raw, _ := json.Marshal(m)
		return string(raw)
	}
	support := func(col string, id, conn uuid.UUID) {
		exec(`INSERT INTO iga_object_support (workspace_id, `+col+`, connector_id, partition_key, state, last_confirmed_at)
		      VALUES (?, ?, ?, ?, 'current', ?)`, l.ws, id, conn, "azure-test-"+col, now)
	}
	identity := func(kind, name string) uuid.UUID {
		id, oid := uuid.New(), strings.ToLower(uuid.NewString())
		exec(`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key,
		                                        display_name, provider_attrs, lifecycle)
		      VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, ?::jsonb, 'active')`,
			id, l.ws, kind, azuregraph.IdentityKey(f.tenant, oid), oid, name, scopeAttrs(oid, ""))
		support("identity_account_id", id, tenantConn)
		return id
	}
	f.sp = identity(models.CloudIdentityEntraServicePrincipal, "sp-reader")
	f.group = identity(models.CloudIdentityEntraGroup, "readers")

	f.storageNative = "/subscriptions/" + f.sub + "/resourcegroups/rg/providers/microsoft.storage/storageaccounts/stdemo"
	f.storage = uuid.New()
	exec(`INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key, provider_attrs, lifecycle)
	      VALUES (?, ?, 'microsoft.storage/storageaccounts', 'stdemo', 'azure', ?, ?::jsonb, 'active')`,
		f.storage, l.ws, azuregraph.ResourceKey(f.tenant, f.storageNative), scopeAttrs(f.storageNative, "Authnull"))
	support("resource_id", f.storage, subConn)

	fnNative := "/subscriptions/" + f.sub + "/resourcegroups/rg/providers/microsoft.web/sites/fn-ingest"
	f.fn = uuid.New()
	exec(`INSERT INTO iga_workload (id, workspace_id, provider, runtime_kind, display_name, source_key, provider_attrs, lifecycle)
	      VALUES (?, ?, 'azure', 'microsoft.web/sites', 'fn-ingest', ?, ?::jsonb, 'active')`,
		f.fn, l.ws, azuregraph.WorkloadKey(f.tenant, fnNative), scopeAttrs(fnNative, "Authnull"))
	support("workload_id", f.fn, subConn)

	rel := func(typ, srcCol string, src, target uuid.UUID, conn uuid.UUID) {
		exec(`INSERT INTO iga_relationship (workspace_id, relationship_type, `+srcCol+`, target_identity_account_id,
		                                    basis, state, source_key, partition_key, connector_id, last_confirmed_at)
		      VALUES (?, ?, ?, ?, 'observed', 'current', ?, 'azure-test-rel', ?, ?)`,
			l.ws, typ, src, target, azuregraph.RelationshipKey(f.tenant, typ, src.String(), target.String()), conn, now)
	}
	rel(models.RelTypeExecutesAs, "source_workload_id", f.fn, f.sp, subConn)
	rel(models.RelTypeMemberOf, "source_identity_account_id", f.sp, f.group, tenantConn)

	entitlement := func(role string, actions []string) uuid.UUID {
		id := uuid.New()
		native, _ := json.Marshal(map[string]any{"role_name": role, "actions": actions, "not_actions": nil})
		key := azuregraph.EntitlementKey(f.tenant, "azure_role_definition", role, actions, nil)
		exec(`INSERT INTO iga_entitlements (id, workspace_id, native_grant_kind, native_rights, lifecycle, provider, source_key,
		                                    continuity, statement_key, content_hash, effect)
		      VALUES (?, ?, 'azure_role_definition', ?::jsonb, 'active', 'azure', ?, 'recognition_only', ?, ?, 'allow')`,
			id, l.ws, string(native), key, key, azuregraph.ContentHash(role, actions, nil))
		support("entitlement_id", id, subConn)
		return id
	}
	grant := func(ent uuid.UUID, resource *uuid.UUID, assignmentScope string) uuid.UUID {
		id := uuid.New()
		assignment := assignmentScope + "/providers/microsoft.authorization/roleassignments/" + uuid.NewString()
		resNative := ""
		if resource != nil {
			resNative = assignmentScope
		}
		exec(`INSERT INTO iga_access_edges (id, workspace_id, subject_kind, subject_id, subject_identity_account_id, entitlement_id,
		                                    resource_id, direction, path_kind, calculation_state, effective_conclusion, native_scope,
		                                    provider, basis, state, last_confirmed_at, connector_id, source_key, partition_key)
		      VALUES (?, ?, 'identity_account', ?, ?, ?, ?, 'outbound', 'azure_rbac', 'partial', 'unknown', ?,
		              'azure', 'observed', 'current', ?, ?, ?, 'azure-test-grants')`,
			id, l.ws, f.sp, f.sp, ent, resource, assignmentScope, now, subConn,
			azuregraph.GrantKey(f.tenant, "sp-oid", assignment, resNative))
		return id
	}
	f.blobReader = grant(entitlement("Storage Blob Data Reader",
		[]string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}), &f.storage, f.storageNative)
	f.subReader = grant(entitlement("Reader", []string{"*/read"}), nil, "/subscriptions/"+f.sub)
	f.subScopeRef = "scope:" + uuid.NewSHA1(uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://authsec.ai/iga/graph/azure-scope")),
		[]byte("/subscriptions/"+f.sub)).String()
	return f
}

func azGraph(t *testing.T, f *azGraphFixture, route string, kv ...string) map[string]any {
	t.Helper()
	code, body := graphDirect(t, igaread.NewReader(f.db, readTestCursorKey), igaread.DefaultGraphBudgets, f.ws, route, kv...)
	mustStatus(t, route, code, body, 200)
	return body
}

func azCheckMeta(t *testing.T, body map[string]any) {
	t.Helper()
	if digs(body, "meta", "graph_state") != "unrevisioned" || dig(body, "meta", "rev") != nil {
		t.Errorf("meta = %v, want unrevisioned with no rev", body["meta"])
	}
	var codes []string
	for _, l := range digl(body, "meta", "limitations") {
		codes = append(codes, digs(l, "code"))
	}
	if strings.Join(codes, ",") != "effective_access_not_evaluated,azure_conditions_not_evaluated" {
		t.Errorf("meta limitations = %v", codes)
	}
}

func TestP2AzureGraphReverseFromResource(t *testing.T) {
	f := newAzGraphFixture(t, "p2-azure-graph-reverse")
	storage, ra := refOf("resource", f.storage), refOf("role_assignment", f.blobReader)
	body := azGraph(t, f, "/graph", "root", storage, "direction", "reverse")
	azCheckMeta(t, body)
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	es := graphEdges(t, digl(body, "data", "edges"))

	// storage account <- "Storage Blob Data Reader" assignment <- the service
	// principal, and on back: the workload that runs as it.
	n := nodes[storage]
	if digs(n, "provider") != "azure" || digs(n, "sub_scope") != "Authnull" || digs(n, "native_id") != f.storageNative ||
		digs(n, "scope", "kind") != "azure_tenant" || digs(n, "scope", "id") != f.tenant {
		t.Errorf("storage node = %v", n)
	}
	if _, ok := n["account"]; ok {
		t.Errorf("an Azure node carries an account: %v", n)
	}
	// The subscription-wide Reader reaches stdemo without naming it: not
	// drawn, and the node says so (D-114).
	if !graphHasCode(digl(n, "limitations"), "azure_scope_access_not_drawn") {
		t.Errorf("storage limitations = %v, want azure_scope_access_not_drawn", n["limitations"])
	}
	sp := nodes[refOf("identity", f.sp)]
	if dig(sp, "restrictions", "deny_statements") != float64(0) || dig(sp, "restrictions", "permissions_boundary") != false {
		t.Errorf("identity restrictions = %v, want {0, false}", dig(sp, "restrictions"))
	}
	a := nodes[ra]
	if digs(a, "kind") != "statement" || digs(a, "label") != "Storage Blob Data Reader" ||
		digs(a, "azure_role", "role_name") != "Storage Blob Data Reader" || digs(a, "azure_role", "grant_kind") != "azure_rbac" ||
		digs(a, "sub_scope") != "Authnull" {
		t.Errorf("assignment node = %v", a)
	}
	if nodes[refOf("identity", f.sp)] == nil || nodes[refOf("workload", f.fn)] == nil {
		t.Errorf("reverse nodes = %v, want the service principal and the workload", nodes)
	}
	if nodes[refOf("role_assignment", f.subReader)] != nil {
		t.Error("an assignment not on the resource reached it (a path through the role definition)")
	}
	want := map[string][2]string{
		"target:" + f.blobReader.String(): {ra, storage},
		"grant:" + f.blobReader.String():  {refOf("identity", f.sp), ra},
	}
	for claim, ends := range want {
		found := false
		for _, e := range es {
			if e.Claim == claim {
				found = true
				if e.From != ends[0] || e.To != ends[1] || digs(e.Raw, "provider") != "azure" || e.State != "current" {
					t.Errorf("%s = %+v", claim, e)
				}
				if e.Kind == "grant" && digs(e.Raw, "policy_kind") != "azure_rbac" {
					t.Errorf("%s policy_kind = %v", claim, e.Raw["policy_kind"])
				}
			}
		}
		if !found {
			t.Errorf("no edge %s in %+v", claim, es)
		}
	}
	if len(graphEdgesOfKind(es, "executes_as")) != 1 {
		t.Errorf("executes_as edges = %+v", graphEdgesOfKind(es, "executes_as"))
	}

	// The same through /graph/expand: the assignments on the resource, then
	// the identity holding one.
	exp := azGraph(t, f, "/graph/expand", "node", storage, "edge", "target", "direction", "reverse")
	azCheckMeta(t, exp)
	if es := graphEdges(t, digl(exp, "data", "edges")); len(es) != 1 || es[0].From != ra {
		t.Errorf("expand target reverse = %+v", es)
	}
	holders := azGraph(t, f, "/graph/expand", "node", ra, "edge", "grant", "direction", "reverse")
	if es := graphEdges(t, digl(holders, "data", "edges")); len(es) != 1 || es[0].From != refOf("identity", f.sp) {
		t.Errorf("expand grant reverse = %+v", es)
	}

	// A path from the workload to the storage account runs through the
	// assignment.
	path := azGraph(t, f, "/graph/path", "from", refOf("workload", f.fn), "to", storage)
	if digs(path, "data", "outcome") != "found" {
		t.Errorf("path = %v", path["data"])
	}
}

func TestP2AzureGraphForwardFromIdentity(t *testing.T) {
	f := newAzGraphFixture(t, "p2-azure-graph-forward")
	sp := refOf("identity", f.sp)
	body := azGraph(t, f, "/graph", "root", sp, "direction", "forward")
	azCheckMeta(t, body)
	nodes := graphNodes(t, digl(body, "data", "nodes"))
	es := graphEdges(t, digl(body, "data", "edges"))
	if len(graphEdgesOfKind(es, "grant")) != 2 || len(graphEdgesOfKind(es, "target")) != 2 || len(graphEdgesOfKind(es, "member_of")) != 1 {
		t.Errorf("forward edges = %+v", es)
	}
	sc := nodes[f.subScopeRef]
	if sc == nil {
		t.Fatalf("no scope node %s in %v", f.subScopeRef, nodes)
	}
	if digs(sc, "kind") != "scope" || digs(sc, "label") != "Subscription Authnull" || digs(sc, "provider") != "azure" ||
		digs(sc, "scope", "id") != f.tenant {
		t.Errorf("scope node = %v", sc)
	}
	for _, e := range graphEdgesOfKind(es, "target") {
		if e.Claim == "target:"+f.subReader.String() && e.To != f.subScopeRef {
			t.Errorf("subscription assignment targets %s", e.To)
		}
	}
	// A scope is a leaf: never on the frontier, never expanded.
	for _, fr := range digl(body, "data", "frontier") {
		if digs(fr, "node") == f.subScopeRef {
			t.Errorf("scope on the frontier: %v", fr)
		}
	}
	code, _ := graphDirect(t, igaread.NewReader(f.db, readTestCursorKey), igaread.DefaultGraphBudgets, f.ws, "/graph/expand",
		"node", f.subScopeRef, "edge", "target", "direction", "reverse")
	if code != 400 {
		t.Errorf("expand of a scope = %d, want 400", code)
	}
}

// Tenant isolation: another workspace cannot read any of it -- the identity,
// the resource or the role assignment is 404 there.
func TestP2AzureGraphIsolation(t *testing.T) {
	f := newAzGraphFixture(t, "p2-azure-graph-iso-a")
	other := newP2Lab(t, "p2-azure-graph-iso-b", false)
	r := igaread.NewReader(f.db, readTestCursorKey)
	for root, edge := range map[string]string{
		refOf("identity", f.sp): "member_of", refOf("resource", f.storage): "target", refOf("role_assignment", f.blobReader): "grant",
	} {
		code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, other.ws, "/graph", "root", root, "direction", "reverse")
		if code != 404 {
			t.Errorf("workspace B read %s: %d %v", root, code, body)
		}
		code, body = graphDirect(t, r, igaread.DefaultGraphBudgets, other.ws, "/graph/expand",
			"node", root, "edge", edge, "direction", "reverse")
		if code != 404 {
			t.Errorf("workspace B expanded %s: %d %v", root, code, body)
		}
	}
	// And A still reads it.
	if code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, f.ws, "/graph", "root", refOf("resource", f.storage),
		"direction", "reverse"); code != 200 {
		t.Errorf("workspace A: %d %v", code, body)
	}
}

// AS-168: an Azure tenant's connection is named by its organization name once
// a scan has stored it, and by its id until then -- never another workspace's.
func TestP2AzureConnectionNamedByTenant(t *testing.T) {
	f := newAzGraphFixture(t, "p2-azure-conn-name")
	r := igaread.NewReader(f.db, readTestCursorKey)
	nameOf := func(ws uuid.UUID) string {
		t.Helper()
		res, err := r.ListConnections(wsCtx(context.Background(), ws))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.(igaread.ConnectionList).Connections {
			if c.Provider == "azure" && c.ScopeID == f.tenant {
				return c.Name
			}
		}
		return ""
	}
	if got := nameOf(f.ws); got != f.tenant {
		t.Fatalf("before a scan read the name: %q, want the tenant id", got)
	}
	if err := f.db.Exec(`UPDATE cloud_connector SET attrs = attrs || '{"tenant_display_name":"Authnull"}'::jsonb
	                      WHERE workspace_id = ? AND scope_kind = 'tenant' AND scope_id = ?`, f.ws, f.tenant).Error; err != nil {
		t.Fatal(err)
	}
	if got := nameOf(f.ws); got != "Authnull" {
		t.Fatalf("after: %q, want Authnull", got)
	}
	if got := nameOf(newP2Lab(t, "p2-azure-conn-name-b", false).ws); got != "" {
		t.Fatalf("another workspace lists the tenant as %q", got)
	}
}
