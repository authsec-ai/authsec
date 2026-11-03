package integration

// Azure's subscription and resource group filters on the unified inventory
// (internal/igaread/inventory.go), against real PostgreSQL: rows carry
// subscription_id, sub_scope and resource_group in provider_attrs as
// internal/azuregraph writes them.
//
// Workspace A, tenant azTenant:
//
//	subscription Prod  (rg-app: st-app, kv-app; RG-Data: st-data)
//	subscription Sales (rg-app: st-sales)
//	an Entra app role (tenant-wide: no subscription)
//
// Workspace B has its own subscription with the same resource group name.

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azuregraph"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

type azInvWorld struct {
	*p2Lab
	tenant, conn string
	connID       uuid.UUID
}

func newAzInvWorld(t *testing.T, name string) *azInvWorld {
	t.Helper()
	l := newP2Lab(t, name, false)
	w := &azInvWorld{p2Lab: l, tenant: strings.ToLower(uuid.NewString()), connID: uuid.New()}
	if err := l.db.Exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
	      VALUES (?, ?, 'azure', 'tenant', ?, 'active', 'vault://azure/test')`, w.connID, l.ws, w.tenant).Error; err != nil {
		t.Fatalf("connector: %v", err)
	}
	return w
}

// resource adds an Azure resource under sub (named subName) and rg; sub "" is
// a tenant-wide row.
func (w *azInvWorld) resource(name, sub, subName, rg string) {
	w.t.Helper()
	native := "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/microsoft.storage/storageaccounts/" + name
	attrs := map[string]any{"scope_kind": azuregraph.ScopeKindTenant, "scope_id": w.tenant, "scope_label": w.tenant, "native_id": native}
	kind := "microsoft.storage/storageaccounts"
	if sub == "" {
		native, kind = "app-role-"+name, models.CloudResourceEntraAppRole
		attrs["native_id"] = native
	} else {
		attrs["sub_scope"], attrs["subscription_id"], attrs["resource_group"] = subName, sub, rg
	}
	raw, _ := json.Marshal(attrs)
	id := uuid.New()
	if err := w.db.Exec(`INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key, provider_attrs, lifecycle)
	      VALUES (?, ?, ?, ?, 'azure', ?, ?::jsonb, 'active')`,
		id, w.ws, kind, name, azuregraph.ResourceKey(w.tenant, native), string(raw)).Error; err != nil {
		w.t.Fatalf("resource %s: %v", name, err)
	}
	if err := w.db.Exec(`INSERT INTO iga_object_support (workspace_id, resource_id, connector_id, partition_key, state, last_confirmed_at)
	      VALUES (?, ?, ?, 'azure-test-inv', 'current', ?)`, w.ws, id, w.connID, time.Now().UTC()).Error; err != nil {
		w.t.Fatalf("support %s: %v", name, err)
	}
}

func azInvList(t *testing.T, db *azInvWorld, ws uuid.UUID, kv ...string) map[string]any {
	t.Helper()
	vals := url.Values{"provider": {"azure"}}
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Add(kv[i], kv[i+1])
	}
	res, err := igaread.NewReader(db.db, readTestCursorKey).ListInventoryResources(wsCtx(context.Background(), ws), vals)
	if err != nil {
		e := igaread.AsError(err)
		t.Fatalf("list %v: %d %v", vals, e.Status, e.Body())
	}
	return graphJSON(t, res)
}

func TestP2AzureInventorySubscriptionAndResourceGroup(t *testing.T) {
	a := newAzInvWorld(t, "p2-azure-inv-filters-a")
	prod, sales := strings.ToLower(uuid.NewString()), strings.ToLower(uuid.NewString())
	a.resource("st-app", prod, "Prod", "rg-app")
	a.resource("kv-app", prod, "Prod", "RG-APP") // Azure compares resource group names without case
	a.resource("st-data", prod, "Prod", "RG-Data")
	a.resource("st-sales", sales, "Sales", "rg-app")
	a.resource("reader", "", "", "")

	b := newAzInvWorld(t, "p2-azure-inv-filters-b")
	other := strings.ToLower(uuid.NewString())
	b.resource("st-other", other, "Other", "rg-app")

	for _, c := range []struct {
		kv   []string
		want []string
	}{
		{nil, []string{"kv-app", "reader", "st-app", "st-data", "st-sales"}},
		{[]string{"subscription", prod}, []string{"kv-app", "st-app", "st-data"}},
		{[]string{"subscription", strings.ToUpper(sales)}, []string{"st-sales"}},
		{[]string{"subscription", prod, "subscription", sales}, []string{"kv-app", "st-app", "st-data", "st-sales"}},
		// A resource group is its subscription's: the same name in Sales is another group.
		{[]string{"resource_group", prod + "/rg-app"}, []string{"kv-app", "st-app"}},
		{[]string{"resource_group", prod + "/RG-App"}, []string{"kv-app", "st-app"}},
		{[]string{"resource_group", sales + "/rg-app"}, []string{"st-sales"}},
		{[]string{"resource_group", "rg-app"}, []string{}},
		{[]string{"subscription", sales, "resource_group", prod + "/rg-data"}, []string{}},
		// Another workspace's subscription and resource group are no rows here.
		{[]string{"subscription", other}, []string{}},
		{[]string{"resource_group", other + "/rg-app"}, []string{}},
	} {
		body := azInvList(t, a, a.ws, c.kv...)
		var names []string
		for _, r := range digl(body, "data") {
			names = append(names, digs(r, "name"))
		}
		if names == nil {
			names = []string{}
		}
		invWant(t, strings.Join(c.kv, "="), names, c.want)
		if n := num(body, "meta", "total"); n != int64(len(c.want)) {
			t.Errorf("%v total = %d, want %d", c.kv, n, len(c.want))
		}
	}

	// Facets: subscriptions by name; resource groups as written, counted under
	// the chosen subscription (each facet applies every OTHER filter).
	body := azInvList(t, a, a.ws, "facets", "subscription,resource_group")
	invWant(t, "subscription facet", invFacet(body, "subscription"), map[string]string{prod: "Prod:3", sales: "Sales:1"})
	invWant(t, "resource group facet", invFacet(body, "resource_group"),
		map[string]string{prod + "/rg-app": "RG-APP:2", prod + "/rg-data": "RG-Data:1", sales + "/rg-app": "rg-app:1"})
	body = azInvList(t, a, a.ws, "facets", "subscription,resource_group", "subscription", sales)
	invWant(t, "resource groups of Sales", invFacet(body, "resource_group"), map[string]string{sales + "/rg-app": "rg-app:1"})
	invWant(t, "subscription facet ignores subscription", invFacet(body, "subscription"), map[string]string{prod: "Prod:3", sales: "Sales:1"})

	// Isolation: neither workspace's facets or rows name the other's.
	raw, _ := json.Marshal(azInvList(t, a, a.ws, "facets", "subscription,resource_group", "lifecycle", "all"))
	if strings.Contains(string(raw), other) || strings.Contains(string(raw), "st-other") {
		t.Errorf("workspace A shows workspace B's subscription: %s", raw)
	}
	body = azInvList(t, b, b.ws, "facets", "subscription,resource_group")
	invWant(t, "workspace B subscriptions", invFacet(body, "subscription"), map[string]string{other: "Other:1"})
	invWant(t, "workspace B resource groups", invFacet(body, "resource_group"), map[string]string{other + "/rg-app": "rg-app:1"})
	body = azInvList(t, b, b.ws, "subscription", prod)
	if n := num(body, "meta", "total"); n != 0 {
		t.Errorf("workspace B filtered by A's subscription: total %d", n)
	}
}

// arm adds a resource, or with workload a workload, at its ARM id, confirmed by
// the latest pass.
func (w *azInvWorld) arm(name, native, sub, subName, rg string, workload bool) {
	w.t.Helper()
	raw, _ := json.Marshal(map[string]any{"scope_kind": azuregraph.ScopeKindTenant, "scope_id": w.tenant, "scope_label": w.tenant,
		"native_id": native, "sub_scope": subName, "subscription_id": sub, "resource_group": rg})
	id, table, kindCol, col, key := uuid.New(), "iga_resources", "resource_kind", "resource_id", azuregraph.ResourceKey(w.tenant, native)
	if workload {
		table, kindCol, col, key = "iga_workload", "runtime_kind", "workload_id", azuregraph.WorkloadKey(w.tenant, native)
	}
	if err := w.db.Exec(`INSERT INTO `+table+` (id, workspace_id, `+kindCol+`, display_name, provider, source_key, provider_attrs, lifecycle)
	      VALUES (?, ?, 'azure-test', ?, 'azure', ?, ?::jsonb, 'active')`, id, w.ws, name, key, string(raw)).Error; err != nil {
		w.t.Fatalf("%s %s: %v", table, name, err)
	}
	if err := w.db.Exec(`INSERT INTO iga_object_support (workspace_id, `+col+`, connector_id, partition_key, state, last_confirmed_at)
	      VALUES (?, ?, ?, 'azure-test-inv', 'current', ?)`, w.ws, id, w.connID, time.Now().UTC()).Error; err != nil {
		w.t.Fatalf("support %s: %v", name, err)
	}
}

// identity adds an Entra object and returns its object id; a managed identity
// names its resource's ARM id as Entra keeps it (lowercased), an agent identity
// its owners' object ids.
func (w *azInvWorld) identity(name, kind, resource string, owners ...string) string {
	w.t.Helper()
	oid := strings.ToLower(uuid.NewString())
	attrs := map[string]any{"scope_kind": azuregraph.ScopeKindTenant, "scope_id": w.tenant, "scope_label": w.tenant, "native_id": oid, "object_id": oid}
	if resource != "" {
		attrs["managed_identity_resource"] = strings.ToLower(resource)
	}
	if len(owners) > 0 {
		var list []map[string]any
		for _, o := range owners {
			list = append(list, map[string]any{"id": o, "kind": "servicePrincipal", "active": true})
		}
		attrs["owners"] = list
	}
	raw, _ := json.Marshal(attrs)
	id := uuid.New()
	if err := w.db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key,
	                                        display_name, provider_attrs, lifecycle)
	      VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, ?::jsonb, 'active')`,
		id, w.ws, kind, azuregraph.IdentityKey(w.tenant, oid), oid, name, string(raw)).Error; err != nil {
		w.t.Fatalf("identity %s: %v", name, err)
	}
	if err := w.db.Exec(`INSERT INTO iga_object_support (workspace_id, identity_account_id, connector_id, partition_key, state, last_confirmed_at)
	      VALUES (?, ?, ?, 'azure-test-inv', 'current', ?)`, w.ws, id, w.connID, time.Now().UTC()).Error; err != nil {
		w.t.Fatalf("support %s: %v", name, err)
	}
	return oid
}

func azInvIdentities(t *testing.T, w *azInvWorld, kv ...string) []string {
	t.Helper()
	vals := url.Values{"provider": {"azure"}}
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Add(kv[i], kv[i+1])
	}
	res, err := igaread.NewReader(w.db, readTestCursorKey).ListInventoryIdentities(wsCtx(context.Background(), w.ws), vals)
	if err != nil {
		e := igaread.AsError(err)
		t.Fatalf("identities %v: %d %v", vals, e.Status, e.Body())
	}
	names := []string{}
	for _, r := range digl(graphJSON(t, res), "data") {
		names = append(names, digs(r, "name"))
	}
	return names
}

// A managed identity is listed under the subscription and resource group of
// the resource it belongs to, where that resource is NOW: Entra keeps the ARM
// id from when the identity was made, so a moved resource is found by its id
// below the resource group. Users and other Entra objects belong to the tenant
// and are under no subscription.
func TestP2AzureManagedIdentityPlacement(t *testing.T) {
	a := newAzInvWorld(t, "p2-azure-mi-placement-a")
	prod, sales, gone := strings.ToLower(uuid.NewString()), strings.ToLower(uuid.NewString()), strings.ToLower(uuid.NewString())
	at := func(sub, rg, rel string) string {
		return "/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/" + rel
	}

	a.arm("kv-app", at(prod, "rg-app", "Microsoft.KeyVault/vaults/kv-app"), prod, "Prod", "rg-app", false)
	miKV := a.identity("mi-kv", models.CloudIdentityEntraManagedIdentity, at(prod, "rg-app", "Microsoft.KeyVault/vaults/kv-app"))
	// Moved from Prod/rg-old to Sales/rg-new; Entra still names the old id.
	a.arm("proj", at(sales, "rg-new", "Microsoft.CognitiveServices/accounts/acc/projects/proj"), sales, "Sales", "rg-new", true)
	miProj := a.identity("mi-proj", models.CloudIdentityEntraManagedIdentity, at(prod, "rg-old", "Microsoft.CognitiveServices/accounts/acc/projects/proj"))
	// Two VMs of one name: each identity is its own VM's; one whose VM is in
	// neither subscription cannot be told apart and is not placed.
	a.arm("demo", at(prod, "rg-a", "Microsoft.Compute/virtualMachines/demo"), prod, "Prod", "rg-a", true)
	a.arm("demo", at(sales, "rg-b", "Microsoft.Compute/virtualMachines/demo"), sales, "Sales", "rg-b", true)
	miDemo := a.identity("mi-demo-prod", models.CloudIdentityEntraManagedIdentity, at(prod, "rg-a", "Microsoft.Compute/virtualMachines/demo"))
	a.identity("mi-demo-gone", models.CloudIdentityEntraManagedIdentity, at(gone, "rg-c", "Microsoft.Compute/virtualMachines/demo"))
	miUnseen := a.identity("mi-unseen", models.CloudIdentityEntraManagedIdentity, at(prod, "rg-app", "Microsoft.Web/sites/never-scanned"))
	alice := a.identity("alice", models.CloudIdentityEntraUser, "")
	// Agent identities are where the managed identity owning them is (a
	// Foundry project's, for its agents): not by a user owner, an unplaced
	// owner, or owners in two resource groups.
	a.identity("ag-proj", models.CloudIdentityEntraAgentIdentity, "", alice, miProj)
	a.identity("ag-two", models.CloudIdentityEntraAgentIdentity, "", miKV, miDemo)
	a.identity("ag-unplaced", models.CloudIdentityEntraAgentIdentity, "", miUnseen)

	b := newAzInvWorld(t, "p2-azure-mi-placement-b")
	b.identity("mi-kv-b", models.CloudIdentityEntraManagedIdentity, at(prod, "rg-app", "Microsoft.KeyVault/vaults/kv-app"))

	n, err := azuregraph.PlaceManagedIdentities(a.db, a.ws)
	if err != nil || n != 3 {
		t.Fatalf("placed %d, %v; want 3", n, err)
	}
	if n, err := azuregraph.PlaceManagedIdentities(a.db, a.ws); err != nil || n != 0 {
		t.Fatalf("second run placed %d, %v; want 0 (nothing changed)", n, err)
	}
	if n, err := azuregraph.PlaceManagedIdentities(b.db, b.ws); err != nil || n != 0 {
		t.Fatalf("workspace B placed %d, %v; want 0 (its resources are not A's)", n, err)
	}
	if n, err := azuregraph.PlaceAgentIdentities(a.db, a.ws); err != nil || n != 1 {
		t.Fatalf("agent identities placed %d, %v; want 1", n, err)
	}
	if n, err := azuregraph.PlaceAgentIdentities(a.db, a.ws); err != nil || n != 0 {
		t.Fatalf("agent identities second run placed %d, %v; want 0", n, err)
	}

	for _, c := range []struct {
		kv   []string
		want []string
	}{
		{nil, []string{"ag-proj", "ag-two", "ag-unplaced", "alice", "mi-demo-gone", "mi-demo-prod", "mi-kv", "mi-proj", "mi-unseen"}},
		{[]string{"subscription", prod}, []string{"mi-demo-prod", "mi-kv"}},
		{[]string{"subscription", sales}, []string{"ag-proj", "mi-proj"}},
		{[]string{"resource_group", sales + "/rg-new"}, []string{"ag-proj", "mi-proj"}},
		{[]string{"resource_group", prod + "/rg-old"}, []string{}},
		{[]string{"subscription", gone}, []string{}},
	} {
		invWant(t, "identities "+strings.Join(c.kv, "="), azInvIdentities(t, a, c.kv...), c.want)
	}
	invWant(t, "workspace B under A's subscription", azInvIdentities(t, b, "subscription", prod), []string{})
}
