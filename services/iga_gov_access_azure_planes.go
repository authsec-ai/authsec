package services

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
)

// Azure data planes access policies map, beyond storage blobs (step 2:
// Key Vault secrets, AI Search documents; step 4: Azure OpenAI on an Azure
// OpenAI or AI Services account; step 7: storage queues, tables and file
// shares, Service Bus and Event Hubs). Action names and role GUIDs were
// checked against Microsoft's built-in roles and provider operations pages
// (2026-10-24). For such a type read, write and
// delete name its data actions and the management actions that hand out its
// keys -- never the management read: a block of reading secrets has nothing to
// do with a Reader role, which grants none. An allow assigns the type's data
// role. Data the table does not map (Key Vault keys and certificates) stays
// refused as unclassified unless the block is "all" (AS-121).

// azureDataPlane is one mapped type.
type azureDataPlane struct {
	typePath         string   // e.g. "microsoft.keyvault/vaults"
	children         []string // child types mapped the same way, e.g. "secrets"
	what             string   // "Key Vault secrets"
	read, write, del []string
	// readKeys and writeKeys are the management actions that return keys
	// giving read, or write and delete, access to the data.
	readKeys, writeKeys []string
	// mapped are the data-action prefixes the levels cover (lower case): a
	// data role outside them is unclassified.
	mapped []string
	// dataNS is the data-action prefix that can reach this type's data (lower
	// case, no trailing "/"); "" is the provider namespace. A queue's is the
	// account's queue service: a blob role on the account never reaches it.
	dataNS string
	// noDelete: the type has no delete (messages are removed by receiving);
	// oneAllowLevel: no built-in role allows read and write without
	// management, so an allow names one of them.
	noDelete, oneAllowLevel bool
	// The roles an allow assigns, and what the write role allows beyond
	// write (warned).
	readRole, readRoleName, writeRole, writeRoleName string
	// readRoleAlso is what the read role allows beyond read, warned on an
	// allow of read ("" when nothing).
	readRoleAlso string
	apiVersion   string
	// authMode reads the resource's properties: a blocker when role
	// assignments do not control its data, a warning when keys still can.
	authMode func(props map[string]any) (blocker, warning *AccessIssue)
}

// Azure OpenAI data actions per level. Read is using the models (every
// inference call) and reading what the account stores; write creates and
// changes data (files, fine-tunes, assistants, responses, batches, deployments
// through the data plane); delete removes it.
var (
	openAIRead = []string{
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/chat/completions/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/completions/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/embeddings/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/audio/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/realtime/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/search/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/extensions/chat/completions/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/images/generations/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/engines/completions/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/files/read",
		"Microsoft.CognitiveServices/accounts/OpenAI/stored-completions/read",
		"Microsoft.CognitiveServices/accounts/OpenAI/assistants/threads/messages/read",
		"Microsoft.CognitiveServices/accounts/OpenAI/responses/read",
	}
	openAIWrite = []string{
		"Microsoft.CognitiveServices/accounts/OpenAI/files/write",
		"Microsoft.CognitiveServices/accounts/OpenAI/fine-tunes/write",
		"Microsoft.CognitiveServices/accounts/OpenAI/assistants/write",
		"Microsoft.CognitiveServices/accounts/OpenAI/responses/write",
		"Microsoft.CognitiveServices/accounts/OpenAI/batches/action",
		"Microsoft.CognitiveServices/accounts/OpenAI/stored-completions/write",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/write",
	}
	openAIDelete = []string{
		"Microsoft.CognitiveServices/accounts/OpenAI/files/delete",
		"Microsoft.CognitiveServices/accounts/OpenAI/fine-tunes/delete",
		"Microsoft.CognitiveServices/accounts/OpenAI/assistants/delete",
		"Microsoft.CognitiveServices/accounts/OpenAI/responses/delete",
		"Microsoft.CognitiveServices/accounts/OpenAI/stored-completions/delete",
		"Microsoft.CognitiveServices/accounts/OpenAI/deployments/delete",
	}
	// An account key reaches every data action.
	cognitiveKeys = []string{"Microsoft.CognitiveServices/accounts/listKeys/action", "Microsoft.CognitiveServices/accounts/regenerateKey/action"}
)

// Storage data services beyond blobs, and the account-wide actions that hand
// out every service's data (keys and SAS).
const storageNS = "Microsoft.Storage/storageAccounts/"

var storageKeys = []string{storageNS + "listKeys/action", storageNS + "listAccountSas/action", storageNS + "listServiceSas/action"}

var (
	queueRead  = []string{storageNS + "queueServices/queues/messages/read", storageNS + "queueServices/queues/messages/process/action"}
	queueWrite = []string{storageNS + "queueServices/queues/messages/write", storageNS + "queueServices/queues/messages/add/action"}
	queueDel   = []string{storageNS + "queueServices/queues/messages/delete", storageNS + "queueServices/queues/messages/process/action"}
	tableRead  = []string{storageNS + "tableServices/tables/entities/read"}
	tableWrite = []string{storageNS + "tableServices/tables/entities/write", storageNS + "tableServices/tables/entities/add/action",
		storageNS + "tableServices/tables/entities/update/action"}
	tableDel  = []string{storageNS + "tableServices/tables/entities/delete"}
	fileRead  = []string{storageNS + "fileServices/fileshares/files/read", storageNS + "fileServices/readFileBackupSemantics/action"}
	fileWrite = []string{storageNS + "fileServices/fileshares/files/write", storageNS + "fileServices/fileshares/files/modifypermissions/action",
		storageNS + "fileServices/writeFileBackupSemantics/action"}
	fileDel = []string{storageNS + "fileServices/fileshares/files/delete"}
)

// SAS keys of a Service Bus or Event Hubs namespace and its entities.
var (
	serviceBusKeys = []string{"Microsoft.ServiceBus/namespaces/authorizationRules/listkeys/action", "Microsoft.ServiceBus/namespaces/queues/authorizationRules/listkeys/action",
		"Microsoft.ServiceBus/namespaces/topics/authorizationRules/listkeys/action", "Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"}
	eventHubKeys = []string{"Microsoft.EventHub/namespaces/authorizationRules/listkeys/action", "Microsoft.EventHub/namespaces/eventhubs/authorizationRules/listkeys/action",
		"Microsoft.EventHub/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action"}
)

// localAuthMode warns when a namespace still takes SAS keys.
func localAuthMode(what string) func(props map[string]any) (*AccessIssue, *AccessIssue) {
	return func(props map[string]any) (*AccessIssue, *AccessIssue) {
		if off, _ := props["disableLocalAuth"].(bool); off {
			return nil, nil
		}
		return nil, &AccessIssue{Code: GovCodeAzureSASKeys,
			Message: "This " + what + " also accepts SAS keys: anyone already holding a key or SAS token keeps access. Disable local authentication on it to make a block complete."}
	}
}

var azureDataPlanes = []azureDataPlane{
	{
		typePath: "microsoft.keyvault/vaults", children: []string{"secrets"}, what: "Key Vault secrets",
		read:     []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action", "Microsoft.KeyVault/vaults/secrets/readMetadata/action", "Microsoft.KeyVault/vaults/secrets/backup/action"},
		write:    []string{"Microsoft.KeyVault/vaults/secrets/setSecret/action", "Microsoft.KeyVault/vaults/secrets/update/action", "Microsoft.KeyVault/vaults/secrets/restore/action", "Microsoft.KeyVault/vaults/secrets/recover/action"},
		del:      []string{"Microsoft.KeyVault/vaults/secrets/delete", "Microsoft.KeyVault/vaults/secrets/purge/action"},
		mapped:   []string{"microsoft.keyvault/vaults/secrets/"},
		readRole: azure.RoleKeyVaultSecretsUser, readRoleName: "Key Vault Secrets User",
		writeRole: azure.RoleKeyVaultSecretsOfficer, writeRoleName: "Key Vault Secrets Officer",
		apiVersion: "2023-07-01",
		authMode: func(props map[string]any) (*AccessIssue, *AccessIssue) {
			if rbac, _ := props["enableRbacAuthorization"].(bool); rbac {
				return nil, nil
			}
			return &AccessIssue{Code: GovCodeAzureVaultAccessPolicies,
				Message: "This key vault uses vault access policies, which Azure role assignments do not control. Switch it to the Azure role-based access control permission model first."}, nil
		},
	},
	{
		typePath: "microsoft.search/searchservices", children: []string{"indexes"}, what: "AI Search documents",
		read:      []string{"Microsoft.Search/searchServices/indexes/documents/read"},
		write:     []string{"Microsoft.Search/searchServices/indexes/documents/write"},
		del:       []string{"Microsoft.Search/searchServices/indexes/documents/delete"},
		readKeys:  []string{"Microsoft.Search/searchServices/listQueryKeys/action", "Microsoft.Search/searchServices/createQueryKey/action", "Microsoft.Search/searchServices/listAdminKeys/action", "Microsoft.Search/searchServices/regenerateAdminKey/action"},
		writeKeys: []string{"Microsoft.Search/searchServices/listAdminKeys/action", "Microsoft.Search/searchServices/regenerateAdminKey/action"},
		mapped:    []string{"microsoft.search/searchservices/indexes/documents/"},
		readRole:  azure.RoleSearchIndexDataReader, readRoleName: "Search Index Data Reader",
		writeRole: azure.RoleSearchIndexDataContributor, writeRoleName: "Search Index Data Contributor",
		apiVersion: "2023-11-01",
		authMode: func(props map[string]any) (*AccessIssue, *AccessIssue) {
			if off, _ := props["disableLocalAuth"].(bool); off {
				return nil, nil // role assignments only
			}
			if opts, _ := props["authOptions"].(map[string]any); opts != nil {
				if _, both := opts["aadOrApiKey"]; both {
					return nil, &AccessIssue{Code: GovCodeAzureSearchKeys,
						Message: "This search service also accepts API keys: anyone already holding a key keeps access. Disable API keys on the service to make a block complete."}
				}
			}
			// API keys only (the default): roles do not reach the data.
			return &AccessIssue{Code: GovCodeAzureSearchKeysOnly,
				Message: "This search service accepts API keys only, so Azure role assignments do not control its data. Turn on role-based access on the service first."}, nil
		},
	},
	{
		// An Azure OpenAI or AI Services account. Its other data planes
		// (Speech, Language, Content Safety...) are not mapped: a role
		// reaching only those is refused as unclassified unless the block is
		// "all".
		typePath: "microsoft.cognitiveservices/accounts", children: []string{"deployments"}, what: "Azure OpenAI models and data",
		read: openAIRead, write: openAIWrite, del: openAIDelete,
		readKeys: cognitiveKeys, writeKeys: cognitiveKeys,
		mapped:   []string{"microsoft.cognitiveservices/accounts/openai/"},
		readRole: azure.RoleCognitiveOpenAIUser, readRoleName: "Cognitive Services OpenAI User",
		writeRole: azure.RoleCognitiveOpenAIContributor, writeRoleName: "Cognitive Services OpenAI Contributor",
		readRoleAlso: "creating assistants and responses, and image and video generations",
		apiVersion:   "2023-05-01",
		dataNS:       "microsoft.cognitiveservices/accounts",
		authMode: func(props map[string]any) (*AccessIssue, *AccessIssue) {
			// Entra tokens need the account's custom subdomain: without it
			// only keys work, so role assignments do not reach the data.
			if sub, _ := props["customSubDomainName"].(string); sub == "" {
				return &AccessIssue{Code: GovCodeAzureAIKeysOnly,
					Message: "This account has no custom subdomain, so it accepts API keys only and Azure role assignments do not control its data. Give it a custom domain name first."}, nil
			}
			if off, _ := props["disableLocalAuth"].(bool); off {
				return nil, nil
			}
			return nil, &AccessIssue{Code: GovCodeAzureAIKeys,
				Message: "This account also accepts API keys: anyone already holding a key keeps access. Disable local authentication on the account to make a block complete."}
		},
	},
	{
		typePath: "microsoft.storage/storageaccounts/queueservices", children: []string{"queues"}, what: "queue messages",
		read: queueRead, write: queueWrite, del: queueDel, readKeys: storageKeys, writeKeys: storageKeys,
		mapped: []string{"microsoft.storage/storageaccounts/queueservices/"}, dataNS: "microsoft.storage/storageaccounts/queueservices",
		readRole: azure.RoleStorageQueueDataReader, readRoleName: "Storage Queue Data Reader",
		writeRole: azure.RoleStorageQueueDataContributor, writeRoleName: "Storage Queue Data Contributor",
	},
	{
		typePath: "microsoft.storage/storageaccounts/tableservices", children: []string{"tables"}, what: "table entities",
		read: tableRead, write: tableWrite, del: tableDel, readKeys: storageKeys, writeKeys: storageKeys,
		mapped: []string{"microsoft.storage/storageaccounts/tableservices/"}, dataNS: "microsoft.storage/storageaccounts/tableservices",
		readRole: azure.RoleStorageTableDataReader, readRoleName: "Storage Table Data Reader",
		writeRole: azure.RoleStorageTableDataContributor, writeRoleName: "Storage Table Data Contributor",
	},
	{
		// SMB roles: they keep the share's file permissions (the privileged
		// REST roles bypass them).
		typePath: "microsoft.storage/storageaccounts/fileservices", children: []string{"shares"}, what: "file share data",
		read: fileRead, write: fileWrite, del: fileDel, readKeys: storageKeys, writeKeys: storageKeys,
		mapped: []string{"microsoft.storage/storageaccounts/fileservices/"}, dataNS: "microsoft.storage/storageaccounts/fileservices",
		readRole: azure.RoleStorageFileSMBReader, readRoleName: "Storage File Data SMB Share Reader",
		writeRole: azure.RoleStorageFileSMBContributor, writeRoleName: "Storage File Data SMB Share Contributor",
	},
	{
		typePath: "microsoft.servicebus/namespaces", children: []string{"queues", "topics", "topics/subscriptions"}, what: "Service Bus messages",
		read: []string{"Microsoft.ServiceBus/namespaces/messages/receive/action"}, write: []string{"Microsoft.ServiceBus/namespaces/messages/send/action"},
		readKeys: serviceBusKeys, writeKeys: serviceBusKeys, mapped: []string{"microsoft.servicebus/"}, noDelete: true, oneAllowLevel: true,
		readRole: azure.RoleServiceBusDataReceiver, readRoleName: "Azure Service Bus Data Receiver",
		writeRole: azure.RoleServiceBusDataSender, writeRoleName: "Azure Service Bus Data Sender",
		apiVersion: "2021-11-01", authMode: localAuthMode("namespace"),
	},
	{
		typePath: "microsoft.eventhub/namespaces", children: []string{"eventhubs", "eventhubs/consumergroups"}, what: "Event Hubs events",
		read: []string{"Microsoft.EventHub/namespaces/messages/receive/action"}, write: []string{"Microsoft.EventHub/namespaces/messages/send/action"},
		readKeys: eventHubKeys, writeKeys: eventHubKeys, mapped: []string{"microsoft.eventhub/"}, noDelete: true, oneAllowLevel: true,
		readRole: azure.RoleEventHubsDataReceiver, readRoleName: "Azure Event Hubs Data Receiver",
		writeRole: azure.RoleEventHubsDataSender, writeRoleName: "Azure Event Hubs Data Sender",
		apiVersion: "2021-11-01", authMode: localAuthMode("namespace"),
	},
}

// azureDataNS is the data-action prefix that can reach t's data.
func azureDataNS(t *azureTarget) string {
	if dp := azureDataPlaneOf(t); dp != nil && dp.dataNS != "" {
		return dp.dataNS
	}
	return azureNamespace(t)
}

// azureTopResource is the top-level resource of a scope (a queue's storage
// account, a deployment's AI account): where a plane's auth mode is set.
func azureTopResource(scope string) string {
	segs := strings.Split(scope, "/")
	if i := indexOf(segs, "providers"); i >= 0 && i+4 <= len(segs) {
		return strings.Join(segs[:i+4], "/")
	}
	return scope
}

// Preview codes of the mapped types.
const (
	GovCodeAzureVaultAccessPolicies = "azure_keyvault_access_policies"
	GovCodeAzureSearchKeysOnly      = "azure_search_keys_only"
	GovCodeAzureSearchKeys          = "azure_search_keys_also"
	GovCodeAzureAIKeysOnly          = "azure_ai_keys_only"
	GovCodeAzureAIKeys              = "azure_ai_keys_also"
	GovCodeAzureSASKeys             = "azure_sas_keys_also"
	GovCodeAzureAuthUnchecked       = "azure_auth_mode_unchecked"
)

// azureDataPlaneOf is the mapped type t is (or is a mapped child of), else nil.
func azureDataPlaneOf(t *azureTarget) *azureDataPlane {
	for i := range azureDataPlanes {
		dp := &azureDataPlanes[i]
		if t.TypePath == dp.typePath {
			return dp
		}
		for _, c := range dp.children {
			if t.TypePath == dp.typePath+"/"+c {
				return dp
			}
		}
	}
	return nil
}

// dataActionsOf is the plane's data and key actions for the access levels.
func (dp *azureDataPlane) dataActionsOf(access []string) (actions, dataActions []string) {
	for _, a := range access {
		switch a {
		case "read":
			dataActions = append(dataActions, dp.read...)
			actions = append(actions, dp.readKeys...)
		case "write":
			dataActions = append(dataActions, dp.write...)
			actions = append(actions, dp.writeKeys...)
		case "delete":
			dataActions = append(dataActions, dp.del...)
			actions = append(actions, dp.writeKeys...)
		case "all":
			dataActions = append(append(append(dataActions, dp.read...), dp.write...), dp.del...)
			actions = append(append(actions, dp.readKeys...), dp.writeKeys...)
		}
	}
	return actions, dataActions
}

// roleDataOutside reports whether def grants data actions in the namespace
// that the plane does not map (Key Vault keys or certificates): those a
// read, write or delete block cannot classify.
func roleDataOutside(def azure.RoleDefinition, ns string, mapped []string) bool {
	for _, p := range def.Properties.Permissions {
		for _, a := range p.DataActions {
			a = strings.ToLower(a)
			if a != "*" && !dataPatternIn(a, ns) {
				continue
			}
			inside := false
			for _, m := range mapped {
				inside = inside || strings.HasPrefix(a, m)
			}
			if !inside {
				return true
			}
		}
	}
	return false
}
