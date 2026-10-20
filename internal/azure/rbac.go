package azure

import (
	"strings"

	"github.com/google/uuid"
)

// ReaderRoleDefinitionID is Azure's built-in Reader role, identical in every
// tenant. It grants */read and nothing else -- in particular not
// Microsoft.Authorization/roleAssignments/write, which is why AuthSec's own
// service principal can never grant itself anything and every assignment is
// made with the customer administrator's delegated token instead.
const ReaderRoleDefinitionID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

// RoleAssignmentWriteAction is the permission the signed-in administrator
// needs on a subscription for AuthSec to create the Reader assignment. Owner,
// User Access Administrator and Role Based Access Control Administrator hold it.
const RoleAssignmentWriteAction = "Microsoft.Authorization/roleAssignments/write"

// RequiredGraphAppRoles are the Microsoft Graph application permissions the
// AuthSec app registration requests, by their stable value names. The ids are
// resolved from the Graph service principal in each tenant rather than
// hard-coded.
var RequiredGraphAppRoles = []string{
	"Application.Read.All",
	"Directory.Read.All",
	"AuditLog.Read.All",
}

// OptionalGraphAppRoles are requested by the app registration but not needed
// to connect: a tenant that consented before they were added keeps working,
// and only the surfaces that need them report the gap until an administrator
// consents again.
//
// Policy.Read.All reads the tenant's guardrails -- app management policies and
// Conditional Access policies for workload identities. The AgentIdentity*
// permissions read Microsoft Entra Agent ID: agent identities, the blueprints
// they are created from (which hold their credentials), and the blueprints'
// service principals. CopilotPackages.Read.All reads the Microsoft 365 agent
// registry (the Copilot catalog: Copilot Studio and Agent Builder agents). All
// read-only.
var OptionalGraphAppRoles = []string{
	"Policy.Read.All",
	"AgentIdentity.Read.All",
	"AgentIdentityBlueprint.Read.All",
	"AgentIdentityBlueprintPrincipal.Read.All",
	"CopilotPackages.Read.All",
	// AppCatalog.Read.All reads the organization's Teams app catalog: the
	// Copilot Studio agents and custom bots published to Teams. No licence.
	"AppCatalog.Read.All",
}

// LicensedGraphPermissions are permissions whose API also needs a licence in
// the tenant: granted but refused there means the licence is missing.
var LicensedGraphPermissions = map[string]string{
	"CopilotPackages.Read.All": "Microsoft Agent 365",
}

// GraphProbePaths is the cheapest read each Graph permission must allow, used
// to prove a granted permission is also usable. Each reads one id at most.
var GraphProbePaths = map[string]string{
	"Application.Read.All": "/v1.0/applications?$top=1&$select=id",
	"AppCatalog.Read.All":  "/v1.0/appCatalogs/teamsApps?$filter=distributionMethod%20eq%20'organization'&$select=id",
	"Directory.Read.All":   "/v1.0/users?$top=1&$select=id",
	// directoryAudits does not support $select; $top=1 keeps it to one record.
	// Sign-in logs are not probed: they need Entra ID P1/P2, and a free
	// tenant's 403 there says nothing about the permission.
	"AuditLog.Read.All": "/v1.0/auditLogs/directoryAudits?$top=1",
	// The tenant-wide policy always exists and needs no licence.
	"Policy.Read.All": "/v1.0/policies/defaultAppManagementPolicy",
	// The agent listings answer an empty page in a tenant with no agents.
	"AgentIdentity.Read.All":                   "/v1.0/servicePrincipals/microsoft.graph.agentIdentity?$top=1&$select=id",
	"AgentIdentityBlueprint.Read.All":          "/v1.0/applications/microsoft.graph.agentIdentityBlueprint?$top=1&$select=id",
	"AgentIdentityBlueprintPrincipal.Read.All": "/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$top=1&$select=id",
	// The agent catalog, filtered to agents as Microsoft documents it; it
	// offers no $top.
	"CopilotPackages.Read.All": "/v1.0/copilot/admin/catalog/packages?$filter=supportedHosts/any(h:h%20eq%20'Copilot')",
}

// Directory roles allowed to attach a tenant to an AuthSec workspace for the
// first time: the roles that can grant tenant-wide consent to Microsoft Graph
// application permissions in the first place.
var BindingDirectoryRoleTemplateIDs = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}

// Azure RBAC roles that can grant access to others, by role definition GUID.
// Holding one is control over the scope, not just use of it.
var AccessGrantingRoleIDs = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
}

// ContributorRoleID is Azure's built-in Contributor: full write, but cannot
// grant access.
const ContributorRoleID = "b24988ac-6180-42a0-ab88-20f7382dd24c"

// PrivilegedDirectoryRoleTemplateIDs are the Entra directory roles Microsoft
// marks privileged: they can change who has access, or reset credentials for
// those who do.
var PrivilegedDirectoryRoleTemplateIDs = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
	"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
	"729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
	"8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
	"3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
}

// MicrosoftTenantIDs own Microsoft's first-party applications; a service
// principal whose app they own is Microsoft's, not the customer's.
var MicrosoftTenantIDs = map[string]bool{
	"f8cdef31-a31e-4b4a-93e4-5f571e91255a": true,
	"72f988bf-86f1-41af-91ab-2d7cd011db47": true,
}

// GUIDSuffix returns the last path segment of an ARM id, lowercased: the
// GUID of a role definition or role assignment.
func GUIDSuffix(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return strings.ToLower(id)
}

// SubscriptionScope is the ARM scope of a subscription.
func SubscriptionScope(subscriptionID string) string {
	return "/subscriptions/" + strings.ToLower(subscriptionID)
}

// ReaderRoleDefinitionResourceID is the Reader role's resource id at scope.
func ReaderRoleDefinitionResourceID(scope string) string {
	return scope + "/providers/Microsoft.Authorization/roleDefinitions/" + ReaderRoleDefinitionID
}

// roleAssignmentNamespace namespaces AuthSec's deterministic assignment names.
var roleAssignmentNamespace = uuid.MustParse("6a0f3b8e-3c55-4f4e-9d1e-7a2c6f0b9e21")

// RoleAssignmentName derives the assignment's name (a GUID) from its scope,
// principal and role. The same inputs always yield the same name, so a
// repeated PUT addresses the same assignment instead of creating a second one.
func RoleAssignmentName(scope, principalID, roleDefinitionID string) string {
	key := strings.ToLower(scope) + "|" + strings.ToLower(principalID) + "|" + strings.ToLower(roleDefinitionID)
	return uuid.NewSHA1(roleAssignmentNamespace, []byte(key)).String()
}

// IsReader reports whether a role assignment grants the built-in Reader role.
func IsReader(ra RoleAssignment) bool {
	return strings.HasSuffix(strings.ToLower(ra.Properties.RoleDefinitionID),
		"/roledefinitions/"+ReaderRoleDefinitionID)
}

// AllowsAction reports whether a set of effective permissions (the output of
// Microsoft.Authorization/permissions) allows action: some entry's actions
// match it and that same entry's notActions do not. Azure evaluates each role
// assignment independently, so a notAction in one entry does not cancel an
// action granted by another.
func AllowsAction(perms []Permission, action string) bool {
	for _, p := range perms {
		allowed := false
		for _, a := range p.Actions {
			if actionMatches(a, action) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		denied := false
		for _, n := range p.NotActions {
			if actionMatches(n, action) {
				denied = true
				break
			}
		}
		if !denied {
			return true
		}
	}
	return false
}

// actionMatches is Azure's action wildcard match: case-insensitive, with '*'
// matching any run of characters.
func actionMatches(pattern, action string) bool {
	return globMatch(strings.ToLower(pattern), strings.ToLower(action))
}

func globMatch(p, s string) bool {
	star, mark := -1, 0
	i, j := 0, 0
	for j < len(s) {
		switch {
		case i < len(p) && p[i] == s[j]:
			i++
			j++
		case i < len(p) && p[i] == '*':
			star, mark = i, j
			i++
		case star >= 0:
			i = star + 1
			mark++
			j = mark
		default:
			return false
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}
