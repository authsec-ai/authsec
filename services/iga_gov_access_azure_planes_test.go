package services

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
)

func planeTarget(typePath string) *azureTarget {
	return &azureTarget{TypePath: typePath, Storage: azureIsStorage(typePath)}
}

func planeDef(t *testing.T, actions, dataActions []string) azure.RoleDefinition {
	t.Helper()
	var d azure.RoleDefinition
	raw, _ := json.Marshal(map[string]any{"properties": map[string]any{"permissions": []map[string]any{{"actions": actions, "dataActions": dataActions}}}})
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A storage account covers every data service and every way to a key or a
// SAS; a container its blobs only; unmapped types keep their mapping.
func TestAzureActionsUnmappedTypesUnchanged(t *testing.T) {
	acts, data := azureActions(planeTarget("microsoft.storage/storageaccounts"), []string{"read"})
	if !slices.Equal(acts, []string{"Microsoft.Storage/storageAccounts/listAccountSas/action", "Microsoft.Storage/storageAccounts/listKeys/action",
		"Microsoft.Storage/storageAccounts/listServiceSas/action"}) ||
		!slices.Equal(data, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
			"Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read", "Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action",
			"Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action", "Microsoft.Storage/storageAccounts/queueServices/queues/messages/read",
			"Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"}) {
		t.Fatalf("storage read: %v %v", acts, data)
	}
	container := &azureTarget{TypePath: "microsoft.storage/storageaccounts/blobservices/containers", Storage: azureIsStorage("microsoft.storage/storageaccounts/blobservices/containers")}
	if _, data := azureActions(container, []string{"read"}); !slices.Equal(data, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}) {
		t.Fatalf("container read: %v", data)
	}
	acts, data = azureActions(planeTarget("microsoft.web/sites"), []string{"write"})
	if !slices.Equal(acts, []string{"microsoft.web/sites/write"}) || len(data) != 0 {
		t.Fatalf("web write: %v %v", acts, data)
	}
}

// Key Vault and AI Search map to their data and key actions, never the
// management read (a Reader role grants no secret).
func TestAzureActionsDataPlanes(t *testing.T) {
	acts, data := azureActions(planeTarget("microsoft.keyvault/vaults"), []string{"read"})
	if len(acts) != 0 || !slices.Contains(data, "Microsoft.KeyVault/vaults/secrets/getSecret/action") || slices.Contains(data, "microsoft.keyvault/vaults/read") {
		t.Fatalf("vault read: %v %v", acts, data)
	}
	acts, data = azureActions(planeTarget("microsoft.search/searchservices"), []string{"write"})
	if !slices.Equal(data, []string{"Microsoft.Search/searchServices/indexes/documents/write"}) ||
		slices.Contains(acts, "Microsoft.Search/searchServices/listQueryKeys/action") || !slices.Contains(acts, "Microsoft.Search/searchServices/listAdminKeys/action") {
		t.Fatalf("search write: query keys only read, admin keys write: %v %v", acts, data)
	}
	// A child type is the same plane; a look-alike or an unmapped child is not.
	if azureDataPlaneOf(planeTarget("microsoft.search/searchservices/indexes")) == nil ||
		azureDataPlaneOf(planeTarget("microsoft.keyvault/vaults/secrets")) == nil {
		t.Fatal("child types not mapped")
	}
	for _, tp := range []string{"microsoft.search/searchservicesx", "microsoft.keyvault/vaults/keys", "microsoft.keyvault/vaultsx"} {
		if azureDataPlaneOf(planeTarget(tp)) != nil {
			t.Fatalf("%s mapped", tp)
		}
	}
	// "all" keeps the management actions too.
	acts, _ = azureActions(planeTarget("microsoft.keyvault/vaults"), []string{"all"})
	if !slices.Contains(acts, "microsoft.keyvault/vaults/write") {
		t.Fatalf("vault all: %v", acts)
	}
}

func TestAzureAllowRolesDataPlanes(t *testing.T) {
	for _, c := range []struct {
		tp     string
		access []string
		want   string
	}{
		{"microsoft.keyvault/vaults", []string{"read"}, azure.RoleKeyVaultSecretsUser},
		{"microsoft.keyvault/vaults", []string{"write"}, azure.RoleKeyVaultSecretsOfficer},
		{"microsoft.search/searchservices", []string{"read"}, azure.RoleSearchIndexDataReader},
		{"microsoft.search/searchservices", []string{"delete"}, azure.RoleSearchIndexDataContributor},
		{"microsoft.cognitiveservices/accounts", []string{"read"}, azure.RoleCognitiveOpenAIUser},
		{"microsoft.cognitiveservices/accounts/deployments", []string{"write"}, azure.RoleCognitiveOpenAIContributor},
		{"microsoft.storage/storageaccounts/queueservices/queues", []string{"read"}, azure.RoleStorageQueueDataReader},
		{"microsoft.storage/storageaccounts/tableservices/tables", []string{"delete"}, azure.RoleStorageTableDataContributor},
		{"microsoft.storage/storageaccounts/fileservices/shares", []string{"read"}, azure.RoleStorageFileSMBReader},
		{"microsoft.servicebus/namespaces/topics/subscriptions", []string{"read"}, azure.RoleServiceBusDataReceiver},
		{"microsoft.servicebus/namespaces/queues", []string{"write"}, azure.RoleServiceBusDataSender},
		{"microsoft.eventhub/namespaces/eventhubs", []string{"read"}, azure.RoleEventHubsDataReceiver},
		{"microsoft.eventhub/namespaces", []string{"write"}, azure.RoleEventHubsDataSender},
		{"microsoft.storage/storageaccounts", []string{"read"}, azure.RoleStorageBlobDataReader},
		{"microsoft.web/sites", []string{"read"}, azure.RoleReader},
	} {
		if got, _ := azureAllowRole(planeTarget(c.tp), c.access); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.tp, c.access, got, c.want)
		}
	}
}

// A role with data the plane maps is classified; one with Key Vault keys is
// not (a secrets block cannot remove it).
func TestRoleDataOutside(t *testing.T) {
	ns, mapped := "microsoft.keyvault", []string{"microsoft.keyvault/vaults/secrets/"}
	if roleDataOutside(planeDef(t, nil, []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}), ns, mapped) {
		t.Fatal("Secrets User reads as unclassified")
	}
	if !roleDataOutside(planeDef(t, nil, []string{"Microsoft.KeyVault/vaults/keys/decrypt/action"}), ns, mapped) {
		t.Fatal("Crypto User reads as classified")
	}
	if roleDataOutside(planeDef(t, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}), ns, mapped) {
		t.Fatal("another provider's data counted")
	}
}

func TestAzureAuthModes(t *testing.T) {
	kv, search := azureDataPlaneOf(planeTarget("microsoft.keyvault/vaults")), azureDataPlaneOf(planeTarget("microsoft.search/searchservices"))
	if b, _ := kv.authMode(map[string]any{"enableRbacAuthorization": false}); b == nil || b.Code != GovCodeAzureVaultAccessPolicies {
		t.Fatalf("vault on access policies: %+v", b)
	}
	if b, w := kv.authMode(map[string]any{"enableRbacAuthorization": true}); b != nil || w != nil {
		t.Fatal("RBAC vault refused")
	}
	if b, _ := search.authMode(map[string]any{}); b == nil || b.Code != GovCodeAzureSearchKeysOnly {
		t.Fatalf("keys-only search (the default): %+v", b)
	}
	if b, w := search.authMode(map[string]any{"authOptions": map[string]any{"aadOrApiKey": map[string]any{}}}); b != nil || w == nil || w.Code != GovCodeAzureSearchKeys {
		t.Fatalf("both: %+v %+v", b, w)
	}
	if b, w := search.authMode(map[string]any{"disableLocalAuth": true}); b != nil || w != nil {
		t.Fatal("role-only search refused")
	}
}

// Azure OpenAI: read is inference and stored data, never the management read;
// every level hands out keys; the built-in OpenAI and Cognitive Services roles
// classify by what they grant.
func TestAzureActionsOpenAI(t *testing.T) {
	acct := planeTarget("microsoft.cognitiveservices/accounts")
	acts, data := azureActions(acct, []string{"read"})
	if !slices.Contains(data, "Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action") ||
		slices.Contains(data, "Microsoft.CognitiveServices/accounts/OpenAI/files/write") ||
		!slices.Equal(acts, []string{"Microsoft.CognitiveServices/accounts/listKeys/action", "Microsoft.CognitiveServices/accounts/regenerateKey/action"}) {
		t.Fatalf("read: %v %v", acts, data)
	}
	ns, mapped := "microsoft.cognitiveservices", azureDataPlaneOf(acct).mapped
	openAIUser := planeDef(t, []string{"Microsoft.CognitiveServices/*/read"}, []string{"Microsoft.CognitiveServices/accounts/OpenAI/*/read",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action"})
	cogUser := planeDef(t, []string{"Microsoft.CognitiveServices/*/read", "Microsoft.CognitiveServices/accounts/listkeys/action"}, []string{"Microsoft.CognitiveServices/*"})
	speech := planeDef(t, nil, []string{"Microsoft.CognitiveServices/accounts/SpeechServices/*"})
	reader := planeDef(t, []string{"*/read"}, nil)
	_, del := azureActions(acct, []string{"delete"})
	delActs, _ := azureActions(acct, []string{"delete"})
	for _, c := range []struct {
		name  string
		def   azure.RoleDefinition
		acts  []string
		data  []string
		grant bool
	}{
		{"OpenAI User grants read", openAIUser, acts, data, true},
		{"OpenAI User grants no delete", openAIUser, nil, del, false},
		{"Cognitive Services User grants read (data and keys)", cogUser, acts, data, true},
		{"Cognitive Services User grants delete", cogUser, delActs, del, true},
		{"Reader grants nothing of the data", reader, acts, data, false},
		{"Speech User grants no OpenAI data", speech, acts, data, false},
	} {
		if got := roleGrants(c.def, c.acts, c.data); got != c.grant {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	if !roleDataOutside(speech, ns, mapped) || roleDataOutside(openAIUser, ns, mapped) {
		t.Fatal("Speech data is outside the plane, OpenAI data inside")
	}
	if azureDataPlaneOf(planeTarget("microsoft.cognitiveservices/accounts/deployments")) == nil ||
		azureDataPlaneOf(planeTarget("microsoft.cognitiveservices/accountsx")) != nil {
		t.Fatal("deployments mapped, a look-alike not")
	}
	dp := azureDataPlaneOf(acct)
	if b, _ := dp.authMode(map[string]any{}); b == nil || b.Code != GovCodeAzureAIKeysOnly {
		t.Fatalf("no custom subdomain: %+v", b)
	}
	if b, w := dp.authMode(map[string]any{"customSubDomainName": "acme-ai"}); b != nil || w == nil || w.Code != GovCodeAzureAIKeys {
		t.Fatalf("keys also: %+v %+v", b, w)
	}
	if b, w := dp.authMode(map[string]any{"customSubDomainName": "acme-ai", "disableLocalAuth": true}); b != nil || w != nil {
		t.Fatal("Entra only refused")
	}
}

// Step 7: a queue, table or file share is its own plane: a blob role on the
// account never reaches it, a role with all storage data does; Service Bus
// and Event Hubs roles classify by receive and send.
func TestAzureStep7Planes(t *testing.T) {
	queue := planeTarget("microsoft.storage/storageaccounts/queueservices/queues")
	if queue.Storage || azureDataNS(queue) != "microsoft.storage/storageaccounts/queueservices" {
		t.Fatalf("queue: %+v %s", queue, azureDataNS(queue))
	}
	blobReader := planeDef(t, nil, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"})
	allStorage := planeDef(t, nil, []string{"Microsoft.Storage/*"})
	queueReader := planeDef(t, []string{"Microsoft.Storage/storageAccounts/queueServices/queues/read"}, []string{"Microsoft.Storage/storageAccounts/queueServices/queues/messages/read"})
	acts, data := azureActions(queue, []string{"read"})
	if roleGrants(blobReader, acts, data) || roleDataIn(blobReader, azureDataNS(queue)) || azureGrants(queue, []string{"all"}, blobReader, nil, nil) {
		t.Fatal("a blob role reaches a queue")
	}
	if !roleGrants(queueReader, acts, data) || !roleDataIn(allStorage, azureDataNS(queue)) || !roleGrants(allStorage, acts, data) {
		t.Fatal("queue roles not matched")
	}
	sb := planeTarget("microsoft.servicebus/namespaces/queues")
	receiver := planeDef(t, []string{"Microsoft.ServiceBus/*/queues/read"}, []string{"Microsoft.ServiceBus/*/receive/action"})
	sender := planeDef(t, []string{"Microsoft.ServiceBus/*/queues/read"}, []string{"Microsoft.ServiceBus/*/send/action"})
	ra, rd := azureActions(sb, []string{"read"})
	wa, wd := azureActions(sb, []string{"write"})
	if !roleGrants(receiver, ra, rd) || roleGrants(receiver, nil, wd) || !roleGrants(sender, wa, wd) || roleGrants(sender, nil, rd) {
		t.Fatal("Service Bus roles misclassified")
	}
	if roleDataOutside(sender, "microsoft.servicebus", azureDataPlaneOf(sb).mapped) {
		t.Fatal("Sender reads as unclassified")
	}
	if dp := azureDataPlaneOf(sb); !dp.noDelete || !dp.oneAllowLevel {
		t.Fatal("Service Bus: no delete, one allow level")
	}
	for scope, want := range map[string]string{
		"/subscriptions/s/resourcegroups/rg/providers/microsoft.servicebus/namespaces/ns/queues/q":           "/subscriptions/s/resourcegroups/rg/providers/microsoft.servicebus/namespaces/ns",
		"/subscriptions/s/resourcegroups/rg/providers/microsoft.cognitiveservices/accounts/ai/deployments/d": "/subscriptions/s/resourcegroups/rg/providers/microsoft.cognitiveservices/accounts/ai",
		"/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv":                          "/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv",
	} {
		if got := azureTopResource(scope); got != want {
			t.Errorf("%s: %s", scope, got)
		}
	}
	if b, w := localAuthMode("namespace")(map[string]any{}); b != nil || w == nil || w.Code != GovCodeAzureSASKeys {
		t.Fatalf("SAS keys: %+v %+v", b, w)
	}
}

// Writing a secret through ARM (a management action) is part of a write block.
func TestKeyVaultARMSecretWrite(t *testing.T) {
	acts, _ := azureActions(planeTarget("microsoft.keyvault/vaults"), []string{"write"})
	if !slices.Contains(acts, "Microsoft.KeyVault/vaults/secrets/write") {
		t.Fatalf("vault write: %v", acts)
	}
	contributor := planeDef(t, []string{"Microsoft.KeyVault/*"}, nil)
	acts, data := azureActions(planeTarget("microsoft.keyvault/vaults"), []string{"write"})
	if !roleGrants(contributor, acts, data) {
		t.Fatal("a role that writes secrets through ARM is not taken by a write block")
	}
	if acts, _ := azureActions(planeTarget("microsoft.keyvault/vaults"), []string{"read"}); len(acts) != 0 {
		t.Fatalf("vault read takes management actions: %v", acts)
	}
}
