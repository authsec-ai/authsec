package services

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
)

func planeTarget(typePath string) *azureTarget {
	return &azureTarget{TypePath: typePath, Storage: typePath == "microsoft.storage/storageaccounts"}
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

// Storage and unmapped types keep their mapping exactly.
func TestAzureActionsUnmappedTypesUnchanged(t *testing.T) {
	acts, data := azureActions(planeTarget("microsoft.storage/storageaccounts"), []string{"read"})
	if !slices.Equal(acts, []string{"Microsoft.Storage/storageAccounts/listKeys/action"}) ||
		!slices.Equal(data, []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}) {
		t.Fatalf("storage read: %v %v", acts, data)
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
