// Package azuregraph projects Azure discovery (Microsoft Entra and Azure
// Resource Manager) into the shared iga_* graph under provider 'azure'.
//
// A SIBLING OF internal/igagraph AND internal/k8sgraph, NOT AN EDIT OF EITHER.
// igagraph is written against the AWS scan pipeline (cloud_scan_run jobs, the
// workspace barrier, ARN-shaped keys) and filters provider = 'aws' throughout;
// k8sgraph is written against a pushed RBAC snapshot. Azure discovery is a
// third shape: two kinds of connector per tenant (the tenant for Microsoft
// Graph, one per subscription for ARM), each pass a cloud_scan_run that its
// own process runs and publishes. The tables are provider-neutral by design
// (SPEC §1.5); the projector for each provider is not.
//
// Every pass projects only what THAT pass confirmed: the cloud_* rows of its
// connector stamped with its generation. Reconciliation is per partition and
// licensed only by that pass's own coverage (§2.7): a row a pass did not see
// goes stale, and is ended only when every surface that writes its partition
// was read in full.
//
// It writes NO iga_agents or iga_agent_instances rows, for the reason k8sgraph
// gives: the bridge matches sightings against every active iga_agent by name,
// and rows a projector invented would both fabricate and break matches.
package azuregraph

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/models"
)

// Sep is the unit separator joining key segments, as in igagraph and k8sgraph:
// it cannot occur in an object id, an ARM id or a permission name.
const Sep = "\x1f"

// Key builds a source key: azure ␟ tenant ␟ part ␟ part…
//
// THE ONLY PLACE A KEY IS FORMATTED. The unique indexes on the graph tables are
// (workspace_id, source_key) with no provider column, so the provider prefix is
// what keeps an Azure key from ever colliding with another provider's, and the
// tenant segment what keeps two tenants of one workspace apart.
func Key(tenant string, parts ...string) string {
	return models.ProviderAzure + Sep + strings.ToLower(tenant) + Sep + strings.Join(parts, Sep)
}

// TenantPrefix is the prefix every key of one tenant starts with.
func TenantPrefix(tenant string) string {
	return models.ProviderAzure + Sep + strings.ToLower(tenant) + Sep
}

// IdentityKey identifies an Entra directory object -- user, group, app
// registration, service principal, managed identity -- by its object id.
func IdentityKey(tenant, objectID string) string {
	return Key(tenant, "object", strings.ToLower(objectID))
}

// ResourceKey identifies a cloud_resource by its native id: an ARM resource id,
// or an API-plane permission ("<api sp>/approles/<role>", "<api sp>/scopes/<scope>").
func ResourceKey(tenant, nativeID string) string {
	return Key(tenant, "resource", strings.ToLower(nativeID))
}

// WorkloadKey identifies one (resource, identity) a resource runs as.
func WorkloadKey(tenant, nativeID string) string {
	return Key(tenant, "workload", strings.ToLower(nativeID))
}

// CredentialKey identifies a client secret or certificate (metadata only).
func CredentialKey(tenant, nativeID string) string {
	return Key(tenant, "credential", strings.ToLower(nativeID))
}

// GrantKey identifies one grant: who, from which source statement, on what.
// cloud_permission is unique on (identity, native_id, resource), so this is.
func GrantKey(tenant, subjectObjectID, permissionNativeID, resourceNativeID string) string {
	return Key(tenant, "grant", strings.ToLower(subjectObjectID), strings.ToLower(permissionNativeID), strings.ToLower(resourceNativeID))
}

// RelationshipKey identifies a typed edge between two endpoint keys.
func RelationshipKey(tenant, relType, from, to string) string {
	return Key(tenant, "rel", relType, from, to)
}

// ExternalPrincipalKey identifies an outside token subject: an OIDC issuer and
// the subject claim it vouches for.
func ExternalPrincipalKey(tenant, issuer, subject string) string {
	return Key(tenant, "external", issuer, subject)
}

// EntitlementKey identifies what a grant confers, by CONTENT: two role
// assignments of the same role share one entitlement node, and a role whose
// definition changes becomes a new one. kind separates sources that could
// otherwise hash alike (a delegated and an application permission of the same
// name are different rights).
func EntitlementKey(tenant, kind, roleName string, actions, notActions []string) string {
	return Key(tenant, "entitlement", kind, ContentHash(roleName, actions, notActions))
}

// ContentHash is a stable digest of an entitlement's content. Lists are sorted,
// so a cosmetic reordering is not a new entitlement.
func ContentHash(roleName string, actions, notActions []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(roleName))
	_, _ = h.Write([]byte{1})
	for _, list := range [][]string{actions, notActions} {
		cp := append([]string(nil), list...)
		sort.Strings(cp)
		for _, v := range cp {
			_, _ = h.Write([]byte(v))
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

// ScopeKey identifies an estate scope row (tenant or subscription), spelled as
// igagraph spells AWS's: provider ␟ scope kind ␟ scope id.
func ScopeKey(kind, id string) string {
	return models.ProviderAzure + Sep + kind + Sep + strings.ToLower(id)
}
