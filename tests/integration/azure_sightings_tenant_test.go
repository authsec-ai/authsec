package integration

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// An Azure agent has no discovery source, so the Sightings tenant filter runs
// on its metadata's tenant_id, on the server: the page and the total count
// only that tenant (before, the console filtered one page of every tenant).
func TestListAgentsByTenant(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-sightings-tenant")
	tA, tB := uuid.NewString(), uuid.NewString()
	for i, tenant := range []string{tA, tA, tA, tB} {
		if err := db.Exec(`INSERT INTO discovered_agents (workspace_id, source, fingerprint, display_name, metadata, status, runtime_status)
			VALUES (?, ?, ?, ?, jsonb_build_object('tenant_id', ?::text), 'unregistered', 'running')`,
			ws, models.DiscoverySourceAzure, "fp-"+uuid.NewString(), "agent", tenant).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	repo := repositories.NewDiscoveryRepository(db)
	rows, total, err := repo.ListAgents(ws, repositories.AgentFilter{TenantID: tA, Limit: 2})
	if err != nil || total != 3 || len(rows) != 2 {
		t.Fatalf("tenant A: %d rows, total %d, %v", len(rows), total, err)
	}
	// Case-insensitive, as tenant ids are stored lower case.
	if _, total, _ := repo.ListAgents(ws, repositories.AgentFilter{TenantID: strings.ToUpper(tB)}); total != 1 {
		t.Fatalf("tenant B: total %d", total)
	}
}

// An Azure agent lives where its resource or Foundry project does: the
// subscription and resource group filters read its metadata's subscription_id
// and the resource group in its ARM id, as the inventory's filters of the same
// names do. An Entra agent (no subscription) matches neither, and another
// workspace's agents are never counted.
func TestListAgentsBySubscriptionAndResourceGroup(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-sightings-subscription")
	other := newWorkspace(t, db, "ws-sightings-subscription-other")
	prod, sales := strings.ToLower(uuid.NewString()), strings.ToLower(uuid.NewString())
	seed := func(w uuid.UUID, name, sub, key, arm string) {
		t.Helper()
		meta := map[string]string{"tenant_id": "t1"}
		if sub != "" {
			meta["subscription_id"], meta[key] = sub, arm
		}
		raw, _ := json.Marshal(meta)
		if err := db.Exec(`INSERT INTO discovered_agents (workspace_id, source, fingerprint, display_name, metadata, status, runtime_status)
			VALUES (?, ?, ?, ?, ?::jsonb, 'unregistered', 'running')`,
			w, models.DiscoverySourceAzure, "fp-"+uuid.NewString(), name, string(raw)).Error; err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed(ws, "foundry-agent", prod, "foundry_project_id", "/subscriptions/"+prod+"/resourceGroups/IGA-Test/providers/Microsoft.CognitiveServices/accounts/a/projects/p")
	seed(ws, "bot", prod, "resource_id", "/subscriptions/"+prod+"/resourcegroups/rg-bots/providers/microsoft.botservice/botservices/b")
	seed(ws, "logic-app", sales, "resource_id", "/subscriptions/"+sales+"/resourcegroups/iga-test/providers/microsoft.logic/workflows/l")
	seed(ws, "entra-agent", "", "", "")
	seed(other, "elsewhere", prod, "resource_id", "/subscriptions/"+prod+"/resourcegroups/iga-test/providers/microsoft.logic/workflows/x")
	// An agent with no ARM id of its own (Agent ID's, or inferred from sign-ins)
	// is where the Azure projection placed its identity; another workspace's
	// identity with the same object id never places it.
	identity := func(w uuid.UUID, oid, sub, rg string) {
		t.Helper()
		attrs, _ := json.Marshal(map[string]string{"object_id": oid, "subscription_id": sub, "sub_scope": "S", "resource_group": rg})
		if err := db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key,
		                                        display_name, provider_attrs, lifecycle)
		      VALUES (?, ?, ?, 'azure', ?, 'immutable', ?, ?, ?::jsonb, 'active')`,
			uuid.New(), w, models.CloudIdentityEntraAgentIdentity, "azure:test:"+uuid.NewString(), uuid.NewString(), oid, string(attrs)).Error; err != nil {
			t.Fatalf("identity %s: %v", oid, err)
		}
	}
	placedOID, otherOID := strings.ToLower(uuid.NewString()), strings.ToLower(uuid.NewString())
	identity(ws, placedOID, sales, "IGA-Test")
	identity(other, otherOID, prod, "iga-test")
	agentOf := func(name, oid string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"tenant_id": "t1", "object_id": strings.ToUpper(oid)})
		if err := db.Exec(`INSERT INTO discovered_agents (workspace_id, source, fingerprint, display_name, metadata, status, runtime_status)
			VALUES (?, ?, ?, ?, ?::jsonb, 'unregistered', 'running')`,
			ws, models.DiscoverySourceAzure, "fp-"+uuid.NewString(), name, string(raw)).Error; err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	agentOf("placed-agent", placedOID)
	agentOf("cross-workspace-agent", otherOID)

	repo := repositories.NewDiscoveryRepository(db)
	for _, c := range []struct {
		f    repositories.AgentFilter
		want []string
	}{
		{repositories.AgentFilter{Subscriptions: []string{prod}}, []string{"bot", "foundry-agent"}},
		{repositories.AgentFilter{Subscriptions: []string{strings.ToUpper(sales)}}, []string{"logic-app", "placed-agent"}},
		// Any one of several.
		{repositories.AgentFilter{Subscriptions: []string{prod, sales}}, []string{"bot", "foundry-agent", "logic-app", "placed-agent"}},
		// A resource group is its subscription's: iga-test in Sales is another group.
		{repositories.AgentFilter{ResourceGroups: []string{prod + "/iga-test"}}, []string{"foundry-agent"}},
		{repositories.AgentFilter{ResourceGroups: []string{sales + "/IGA-TEST"}}, []string{"logic-app", "placed-agent"}},
		{repositories.AgentFilter{ResourceGroups: []string{prod + "/iga-test", prod + "/rg-bots"}}, []string{"bot", "foundry-agent"}},
		{repositories.AgentFilter{ResourceGroups: []string{"iga-test"}}, nil},
		{repositories.AgentFilter{Subscriptions: []string{sales}, ResourceGroups: []string{prod + "/rg-bots"}}, nil},
	} {
		c.f.Limit = 50
		rows, total, err := repo.ListAgents(ws, c.f)
		if err != nil {
			t.Fatalf("%+v: %v", c.f, err)
		}
		var names []string
		for _, r := range rows {
			names = append(names, r.DisplayName)
		}
		sort.Strings(names)
		if strings.Join(names, ",") != strings.Join(c.want, ",") || int(total) != len(c.want) {
			t.Fatalf("%+v: got %v (total %d), want %v", c.f, names, total, c.want)
		}
	}
}
