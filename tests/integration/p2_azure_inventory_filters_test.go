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
