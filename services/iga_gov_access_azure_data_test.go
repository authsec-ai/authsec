package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/igagov"
)

func azureTestRole(t *testing.T, actions, dataActions []string) azure.RoleDefinition {
	t.Helper()
	var d azure.RoleDefinition
	raw, _ := json.Marshal(map[string]any{"id": "r", "properties": map[string]any{
		"permissions": []map[string]any{{"actions": actions, "dataActions": dataActions}}}})
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func azureTestTarget(typePath string) *azureTarget {
	return &azureTarget{TypePath: typePath, Storage: strings.HasPrefix(typePath, "microsoft.storage/storageaccounts")}
}

// A storage account's block covers blobs and, since step 7, its queues,
// tables and file shares and every key and SAS path; a container keeps its
// blobs only. Allow roles are unchanged (blobs).
func TestAzureActionsStorageUnchanged(t *testing.T) {
	st := azureTestTarget("microsoft.storage/storageaccounts")
	acts, data := azureActions(st, []string{igagov.AccessRead})
	for _, want := range []string{"Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.Storage/storageAccounts/listAccountSas/action"} {
		if !containsString(acts, want) {
			t.Fatalf("storage read actions %v lack %s", acts, want)
		}
	}
	for _, want := range []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
		"Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"} {
		if !containsString(data, want) {
			t.Fatalf("storage read data %v lack %s", data, want)
		}
	}
	container := &azureTarget{TypePath: "microsoft.storage/storageaccounts/blobservices/containers", Storage: true}
	if _, data := azureActions(container, []string{igagov.AccessRead}); strings.Join(data, ",") != "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" {
		t.Fatalf("container read = %v", data)
	}
	if g, n := azureAllowRole(st, []string{igagov.AccessRead}); g != azure.RoleStorageBlobDataReader || n != "Storage Blob Data Reader" {
		t.Fatalf("storage allow read = %s %s", g, n)
	}
	if g, _ := azureAllowRole(st, []string{igagov.AccessWrite}); g != azure.RoleStorageBlobDataContributor {
		t.Fatalf("storage allow write = %s", g)
	}
}

// A resource type with no data plane in the table keeps only its management actions.
func TestAzureActionsOtherTypesUnchanged(t *testing.T) {
	vm := azureTestTarget("microsoft.compute/virtualmachines")
	acts, data := azureActions(vm, []string{igagov.AccessRead})
	if strings.Join(acts, ",") != "microsoft.compute/virtualmachines/read" || len(data) != 0 {
		t.Fatalf("vm read = %v / %v", acts, data)
	}
	if g, _ := azureAllowRole(vm, []string{igagov.AccessRead}); g != azure.RoleReader {
		t.Fatalf("vm allow read = %s", g)
	}
	if g, _ := azureAllowRole(vm, []string{igagov.AccessWrite}); g != azure.RoleContributor {
		t.Fatalf("vm allow write = %s", g)
	}
}

// The case that failed in production: an agent querying an AI Search index
// with Search Index Data Reader, which grants no management action, kept its
// access through a block.
func TestAzureBlockReachesSearchIndexData(t *testing.T) {
	search := azureTestTarget("microsoft.search/searchservices")
	acts, data := azureActions(search, []string{igagov.AccessRead})
	for _, want := range []string{"Microsoft.Search/searchServices/listQueryKeys/action", "Microsoft.Search/searchServices/listAdminKeys/action"} {
		if !containsString(acts, want) {
			t.Fatalf("search read actions %v lack %s", acts, want)
		}
	}
	// Not the management read: a Reader role reaches no document (step 2).
	if containsString(acts, "microsoft.search/searchservices/read") {
		t.Fatalf("search read takes the management read: %v", acts)
	}
	if strings.Join(data, ",") != "Microsoft.Search/searchServices/indexes/documents/read" {
		t.Fatalf("search read data actions = %v", data)
	}

	indexReader := azureTestRole(t, nil, []string{"Microsoft.Search/searchServices/indexes/documents/read"})
	if !roleGrants(indexReader, acts, data) {
		t.Fatal("Search Index Data Reader is not removed by a read block")
	}
	indexContributor := azureTestRole(t, nil, []string{"Microsoft.Search/searchServices/indexes/documents/*"})
	if !roleGrants(indexContributor, acts, data) {
		t.Fatal("Search Index Data Contributor is not removed by a read block")
	}
	serviceContributor := azureTestRole(t, []string{"Microsoft.Search/searchServices/*"}, nil)
	if !roleGrants(serviceContributor, acts, data) {
		t.Fatal("Search Service Contributor is not removed by a read block")
	}
	// A role for another service is left alone.
	blobReader := azureTestRole(t, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"})
	if roleGrants(blobReader, acts, data) {
		t.Fatal("a storage role was taken for a search role")
	}
	// A write block does not take a reader's role.
	wActs, wData := azureActions(search, []string{igagov.AccessWrite})
	readerOnly := azureTestRole(t, nil, []string{"Microsoft.Search/searchServices/indexes/documents/read"})
	if roleGrants(readerOnly, wActs, wData) {
		t.Fatal("a write block removed a read-only data role")
	}
}

func TestAzureAllowAssignsDataRoles(t *testing.T) {
	search := azureTestTarget("microsoft.search/searchservices")
	if g, n := azureAllowRole(search, []string{igagov.AccessRead}); g != azure.RoleSearchIndexDataReader || n != "Search Index Data Reader" {
		t.Fatalf("search allow read = %s %s", g, n)
	}
	if g, _ := azureAllowRole(search, []string{igagov.AccessRead, igagov.AccessWrite}); g != azure.RoleSearchIndexDataContributor {
		t.Fatalf("search allow write = %s", g)
	}
	kv := azureTestTarget("microsoft.keyvault/vaults")
	if g, _ := azureAllowRole(kv, []string{igagov.AccessRead}); g != azure.RoleKeyVaultSecretsUser {
		t.Fatalf("key vault allow read = %s", g)
	}
	// Service Bus and Event Hubs: Reader would reach no message, so an allow
	// assigns the data role -- Receiver, Sender, or Owner for both.
	sb := azureTestTarget("microsoft.servicebus/namespaces")
	if g, _ := azureAllowRole(sb, []string{igagov.AccessRead}); g != azure.RoleServiceBusDataReceiver {
		t.Fatalf("service bus allow read = %s", g)
	}
	if g, _ := azureAllowRole(sb, []string{igagov.AccessWrite}); g != azure.RoleServiceBusDataSender {
		t.Fatalf("service bus allow write = %s", g)
	}
	if g, _ := azureAllowRole(sb, []string{igagov.AccessRead, igagov.AccessWrite}); g != azure.RoleServiceBusDataOwner {
		t.Fatalf("service bus allow read+write = %s", g)
	}
	eh := azureTestTarget("microsoft.eventhub/namespaces/eventhubs")
	if g, _ := azureAllowRole(eh, []string{igagov.AccessRead}); g != azure.RoleEventHubsDataReceiver {
		t.Fatalf("event hubs allow read = %s", g)
	}
	// Search and Key Vault keep their contributor role for read+write.
	if g, _ := azureAllowRole(kv, []string{igagov.AccessRead, igagov.AccessWrite}); g != azure.RoleKeyVaultSecretsOfficer {
		t.Fatalf("key vault allow read+write = %s", g)
	}
}

func TestAzureDataPlaneChildTypes(t *testing.T) {
	q := azureTestTarget("microsoft.servicebus/namespaces/queues")
	_, data := azureActions(q, []string{igagov.AccessRead})
	if strings.Join(data, ",") != "Microsoft.ServiceBus/namespaces/messages/receive/action" {
		t.Fatalf("queue read data = %v", data)
	}
	receiver := azureTestRole(t, nil, []string{"Microsoft.ServiceBus/*/receive/action"})
	acts, data := azureActions(q, []string{igagov.AccessRead})
	if !roleGrants(receiver, acts, data) {
		t.Fatal("Azure Service Bus Data Receiver is not removed by a read block")
	}
	// A prefix that is not a child type does not match.
	if azureDataPlaneOf(azureTestTarget("microsoft.search/searchservicesx")) != nil {
		t.Fatal("a look-alike type matched a data plane")
	}
}
