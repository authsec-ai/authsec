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
// service principals. All read-only.
var OptionalGraphAppRoles = []string{
	"Policy.Read.All",
	"AgentIdentity.Read.All",
	"AgentIdentityBlueprint.Read.All",
	"AgentIdentityBlueprintPrincipal.Read.All",
}

// GraphProbePaths is the cheapest read each Graph permission must allow, used
// to prove a granted permission is also usable. Each reads one id at most.
var GraphProbePaths = map[string]string{
	"Application.Read.All": "/v1.0/applications?$top=1&$select=id",
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
}

// Directory roles allowed to attach a tenant to an AuthSec workspace for the
// first time: the roles that can grant tenant-wide consent to Microsoft Graph
// application permissions in the first place.
var BindingDirectoryRoleTemplateIDs = map[string]string{
	"62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
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
