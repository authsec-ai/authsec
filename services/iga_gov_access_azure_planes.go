package services

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
)

// Azure data planes access policies map, beyond storage blobs (step 2:
// Key Vault secrets, AI Search documents). For such a type read, write and
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
	// The roles an allow assigns, and what the write role allows beyond
	// write (warned).
	readRole, readRoleName, writeRole, writeRoleName string
	apiVersion                                       string
	// authMode reads the resource's properties: a blocker when role
	// assignments do not control its data, a warning when keys still can.
	authMode func(props map[string]any) (blocker, warning *AccessIssue)
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
}

// Preview codes of the mapped types.
const (
	GovCodeAzureVaultAccessPolicies = "azure_keyvault_access_policies"
	GovCodeAzureSearchKeysOnly      = "azure_search_keys_only"
	GovCodeAzureSearchKeys          = "azure_search_keys_also"
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
			if a != "*" && !strings.HasPrefix(a, ns+"/") {
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
