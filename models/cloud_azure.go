package models

import (
	"encoding/json"
	"time"
)

/* ------------------------- Azure connector attrs ---------------------------

   Azure joins the shared cloud_connector table with the discipline AWS and
   GCP established: no Azure-specific column on a shared table, one typed
   provider struct serialized into the existing attrs jsonb.

   One Entra tenant onboards as:

     cloud_connector  provider=azure  scope_kind=tenant        scope_id=<tenant id>
     cloud_connector  provider=azure  scope_kind=subscription  scope_id=<sub id>
                                                               parent_scope_id=<tenant id>
     ... one subscription row per subscription the Reader assignment was attempted on

   The tenant row records the Microsoft Graph side (the AuthSec service
   principal and its granted application permissions). Each subscription row
   records the Azure RBAC side (the Reader assignment on that subscription) and
   owns the subscription's resource inventory in cloud_resource. The two are
   separate rows because they fail separately: Graph consent never grants a
   subscription role, and a subscription can lose its Reader assignment while
   the directory stays readable. */

// Azure Reader assignment outcomes, recorded per subscription.
const (
	// AzureReaderCreated: AuthSec created the assignment in this onboarding.
	AzureReaderCreated = "created"
	// AzureReaderExisting: a Reader assignment for the AuthSec service
	// principal already existed at the subscription.
	AzureReaderExisting = "already_assigned"
	// AzureReaderInherited: Reader is inherited from a management group above
	// the subscription. Nothing was created; nothing needs to be.
	AzureReaderInherited = "inherited"
	// AzureReaderDenied: the signed-in administrator may not create role
	// assignments on this subscription (no roleAssignments/write).
	AzureReaderDenied = "permission_denied"
	// AzureReaderSkipped: the subscription is not in a state that accepts
	// role assignments (Disabled, Deleted, Expired).
	AzureReaderSkipped = "skipped"
	// AzureReaderFailed: ARM refused the assignment for another reason.
	AzureReaderFailed = "failed"
	// AzureReaderUnchecked: the read that proves access failed for a passing
	// reason (a timeout, throttling, Microsoft's 5xx), so nothing is known
	// about the subscription; verifying it again settles it.
	AzureReaderUnchecked = "not_checked"
)

// Azure onboarding paths.
const (
	AzureProvisionedViaAdminConsent      = "entra_admin_consent"
	AzureProvisionedViaClientCredentials = "client_credentials"
)

// What started an Azure discovery pass, recorded on its cloud_scan_run.
const (
	AzureTriggerConnect  = "connect"
	AzureTriggerVerify   = "verify"
	AzureTriggerSchedule = "schedule"
)

// Azure Graph permission states, from "granted" (an app role assignment
// exists) to "usable" (a read that permission allows actually succeeded).
const (
	AzureGraphPermissionUsable     = "usable"
	AzureGraphPermissionNotGranted = "not_granted"
	AzureGraphPermissionDenied     = "denied"
	// AzureGraphPermissionLicense: granted, but the tenant's Entra licence does
	// not include the data (sign-in logs need Entra ID P1/P2).
	AzureGraphPermissionLicense = "license_required"
	AzureGraphPermissionUnknown = "unknown"
)

// AzureGraphPermission is one Microsoft Graph application permission as seen in
// the customer tenant.
type AzureGraphPermission struct {
	Name    string `json:"name"`
	Granted bool   `json:"granted"`
	// Optional permissions are requested but not needed to connect; one not
	// granted means a tenant consented before AuthSec asked for it.
	Optional bool   `json:"optional,omitempty"`
	State    string `json:"state"`
	Detail   string `json:"detail,omitempty"`
}

// AzureTenantAttrs is the Azure tenant shape of CloudConnector.Attrs.
type AzureTenantAttrs struct {
	TenantID string `json:"tenant_id"`
	// AppID is AuthSec's multi-tenant application (client) id.
	AppID string `json:"app_id"`
	// ServicePrincipalObjectID is the object id of the AuthSec service
	// principal IN THIS TENANT -- the principal every Reader assignment names.
	ServicePrincipalObjectID string                 `json:"service_principal_object_id"`
	ServicePrincipalName     string                 `json:"service_principal_display_name,omitempty"`
	GraphPermissions         []AzureGraphPermission `json:"graph_permissions"`
	GraphVerifiedAt          *time.Time             `json:"graph_verified_at,omitempty"`
	// SubscriptionsVisible is how many subscriptions the signed-in
	// administrator could see at the last onboarding.
	SubscriptionsVisible int    `json:"subscriptions_visible"`
	ProvisionedVia       string `json:"provisioned_via"`
	// ProvisionedBy is the AuthSec actor, never the Microsoft account: the
	// administrator's Entra identity is not persisted.
	ProvisionedBy string `json:"provisioned_by"`

	// Licensing and Guardrails are written by identity discovery, not by
	// onboarding. Nil until a tenant pass has read them.
	Licensing  *AzureLicensing  `json:"licensing,omitempty"`
	Guardrails *AzureGuardrails `json:"guardrails,omitempty"`

	// TenantDisplayName is the tenant's organization name, read by identity
	// discovery (GET /v1.0/organization). Empty until a tenant pass reads it.
	TenantDisplayName string `json:"tenant_display_name,omitempty"`
}

// AzureLicensing is what the tenant's licences make readable or enforceable.
// Decided from the licences' service plans, then corrected by what Graph
// actually answers: a sign-in read refused for licensing wins over a plan list.
type AzureLicensing struct {
	// EntraIDP1 / EntraIDP2: sign-in logs and sign-in activity need P1 or P2.
	EntraIDP1 bool `json:"entra_id_p1"`
	EntraIDP2 bool `json:"entra_id_p2"`
	// WorkloadIDPremium: Conditional Access for workload identities needs it.
	WorkloadIDPremium bool `json:"workload_id_premium"`
	// SignInLogsAvailable is what the sign-in read itself proved; nil when it
	// was not attempted.
	SignInLogsAvailable *bool      `json:"sign_in_logs_available,omitempty"`
	SKUs                []string   `json:"skus"`
	ReadAt              *time.Time `json:"read_at,omitempty"`
}

// AzureGuardrails are the tenant's own preventive controls over workload
// identities, read with Policy.Read.All. Nil until read; Error says why not.
type AzureGuardrails struct {
	// DefaultAppManagement is the tenant-wide app management policy.
	DefaultAppManagement *AzureAppManagementPolicy `json:"default_app_management,omitempty"`
	// AppManagementPolicies are policies applied to chosen apps.
	AppManagementPolicies []AzureAppManagementPolicy `json:"app_management_policies"`
	// ConditionalAccessTotal counts every Conditional Access policy;
	// WorkloadConditionalAccess lists those that target service principals.
	ConditionalAccessTotal    int                         `json:"conditional_access_total"`
	WorkloadConditionalAccess []AzureWorkloadAccessPolicy `json:"workload_conditional_access"`
	// AgentConditionalAccess lists those that target agent identities or
	// apply at an agent risk level.
	AgentConditionalAccess []AzureAgentAccessPolicy `json:"agent_conditional_access"`
	ReadAt                 *time.Time               `json:"read_at,omitempty"`
	Error                  string                   `json:"error,omitempty"`
}

// AzureAgentAccessPolicy is one Conditional Access policy that targets
// Microsoft Entra Agent ID agent identities. Policies for agent identities use
// the Block grant; agent risk (preview) is one condition among others, and
// targeting can be by blueprint or custom security attributes.
type AzureAgentAccessPolicy struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	// IncludeAgents / ExcludeAgents are object ids (an agent identity's or a
	// blueprint principal's, covering its agents) or a keyword for all agents,
	// recorded as Microsoft wrote it.
	IncludeAgents []string `json:"include_agents"`
	ExcludeAgents []string `json:"exclude_agents,omitempty"`
	// AgentFilter is a custom-security-attribute rule ("include: <rule>"):
	// AuthSec does not read those attributes, so whom it selects is unknown.
	AgentFilter     string   `json:"agent_filter,omitempty"`
	AgentRiskLevels []string `json:"agent_risk_levels,omitempty"`
	// IncludeApplications are the resources it protects ("All", or app ids).
	IncludeApplications []string `json:"include_applications,omitempty"`
	GrantControls       []string `json:"grant_controls,omitempty"`
}

// AzureAppManagementPolicy is one app management policy, reduced to its
// credential rules.
type AzureAppManagementPolicy struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
	// Rules are "<credential>:<restrictionType>[=<maxLifetime>]", e.g.
	// "application.password:passwordLifetime=P90D".
	Rules []string `json:"rules"`
	// AppliesTo counts the applications and service principals a per-app
	// policy is attached to (the object ids are on each identity's attrs).
	AppliesTo int `json:"applies_to,omitempty"`
}

// AzureWorkloadAccessPolicy is one Conditional Access policy that targets
// service principals.
type AzureWorkloadAccessPolicy struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	State            string   `json:"state"`
	IncludeSPs       []string `json:"include_service_principals"`
	ExcludeSPs       []string `json:"exclude_service_principals,omitempty"`
	IncludeLocations []string `json:"include_locations,omitempty"`
	ExcludeLocations []string `json:"exclude_locations,omitempty"`
	GrantControls    []string `json:"grant_controls,omitempty"`
}

// AzureReaderAssignment is the Reader assignment state of one subscription.
type AzureReaderAssignment struct {
	Status string `json:"status"`
	// AssignmentID is the ARM resource id of the assignment AuthSec created
	// or found, when known.
	AssignmentID string `json:"assignment_id,omitempty"`
	// Scope is where the effective Reader assignment lives: the subscription,
	// or a management group above it.
	Scope     string     `json:"scope,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Verified is whether AuthSec's OWN app-only token could read the
	// subscription -- the only proof that counts. A created assignment is not
	// proven access until this is true.
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// AzureSubscriptionAttrs is the Azure subscription shape of CloudConnector.Attrs.
type AzureSubscriptionAttrs struct {
	TenantID                 string                `json:"tenant_id"`
	DisplayName              string                `json:"display_name"`
	State                    string                `json:"state"`
	ServicePrincipalObjectID string                `json:"service_principal_object_id"`
	Reader                   AzureReaderAssignment `json:"reader"`
	ProvisionedVia           string                `json:"provisioned_via"`
	ProvisionedBy            string                `json:"provisioned_by"`
	// Tags and Stage are the subscription's own environment tags and what
	// they mean (AzureStage*), written by discovery.
	Tags  map[string]string `json:"tags,omitempty"`
	Stage string            `json:"stage,omitempty"`
}

// Environment stages read from a subscription's or resource group's tags. The
// same three values iga_estate_scopes.stage and iga_resources.stage take.
const (
	AzureStageProduction    = "production"
	AzureStageNonProduction = "non_production"
	AzureStageUnknown       = "unknown"
)

// SurfaceAzureContainers is the subscription's and its resource groups' tags.
const SurfaceAzureContainers = "resource_containers"

// AzureTenantAttrs decodes the tenant shape. Empty when unreadable.
func (c *CloudConnector) AzureTenantAttrs() AzureTenantAttrs {
	var a AzureTenantAttrs
	if len(c.Attrs) > 0 {
		_ = json.Unmarshal(c.Attrs, &a)
	}
	return a
}

// SetAzureTenantAttrs encodes the tenant shape into Attrs.
func (c *CloudConnector) SetAzureTenantAttrs(a AzureTenantAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}

// AzureSubscriptionAttrs decodes the subscription shape. Empty when unreadable.
func (c *CloudConnector) AzureSubscriptionAttrs() AzureSubscriptionAttrs {
	var a AzureSubscriptionAttrs
	if len(c.Attrs) > 0 {
		_ = json.Unmarshal(c.Attrs, &a)
	}
	return a
}

// SetAzureSubscriptionAttrs encodes the subscription shape into Attrs.
func (c *CloudConnector) SetAzureSubscriptionAttrs(a AzureSubscriptionAttrs) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	c.Attrs = raw
	return nil
}

// Azure inventory surface, written into a subscription connector's Coverage.
const SurfaceAzureResources = "resources"

/* ------------------------- Azure identity discovery ------------------------

   Directory objects are written to cloud_identity under the TENANT connector,
   keyed by their Entra object id (lowercased), so a role assignment's
   principalId joins to its identity directly. An application (the app
   registration) and its service principal (the identity that actually signs
   in) are separate objects with separate object ids, linked by attrs.app_id.

   Grants are written to cloud_permission:
     plane=api    an Entra directory role held by the identity (tenant connector)
     plane=cloud  an Azure RBAC role assignment (subscription connector)

   This is the split the shared schema reserved `plane` for (013). */

// Azure identity kinds in cloud_identity.kind.
const (
	CloudIdentityEntraUser             = "entra_user"
	CloudIdentityEntraGroup            = "entra_group"
	CloudIdentityEntraApplication      = "entra_application"
	CloudIdentityEntraServicePrincipal = "entra_service_principal"
	// A managed identity is a service principal Azure manages; its
	// attrs.managed_identity_resource names the resource it belongs to
	// (system-assigned) or is (user-assigned).
	CloudIdentityEntraManagedIdentity = "entra_managed_identity"
	// An agent identity (Microsoft Entra Agent ID) is the service principal an
	// AI agent signs in as. It has no credentials of its own: its blueprint's
	// obtain its tokens. attrs.agent_blueprint_app_id names the blueprint.
	CloudIdentityEntraAgentIdentity = "entra_agent_identity"
	// An agent user is the user account an agent acts as when it needs one (a
	// mailbox, Teams). attrs.agent_identity_id names the agent identity.
	CloudIdentityEntraAgentUser = "entra_agent_user"
)

// attrs.agent_type on the two Entra Agent ID objects that keep their base
// kind: a blueprint is an app registration (entra_application) and its
// service principal is a service principal (entra_service_principal).
const (
	AgentTypeBlueprint          = "agent_identity_blueprint"
	AgentTypeBlueprintPrincipal = "agent_identity_blueprint_principal"
)

// cloud_assume_edge mechanisms of Entra Agent ID: who may obtain an agent's
// tokens. A blueprint's credentials obtain its agent identities' tokens, and
// an agent identity obtains its agent user's.
const (
	AssumeMechanismAgentBlueprint = "agent_identity_blueprint"
	AssumeMechanismAgentUser      = "agent_user"
)

// Azure secret kinds in cloud_secret.kind. Metadata only: name, validity and
// owner -- never a value or the value's hint.
const (
	CloudSecretEntraClientSecret = "entra_client_secret"
	CloudSecretEntraCertificate  = "entra_certificate"
)

// Tenant discovery surfaces, written into the tenant connector's Coverage.
const (
	SurfaceEntraUsers             = "users"
	SurfaceEntraGroups            = "groups"
	SurfaceEntraGroupMembers      = "group_members"
	SurfaceEntraApplications      = "applications"
	SurfaceEntraServicePrincipals = "service_principals"
	SurfaceEntraDirectoryRoles    = "directory_roles"
	// API permissions: application permissions (app role assignments) and
	// delegated permissions (OAuth2 permission grants).
	SurfaceEntraAppRoleAssignments = "app_role_assignments"
	SurfaceEntraDelegatedGrants    = "delegated_permission_grants"
	// Federated identity credentials on app registrations.
	SurfaceEntraFederatedCredentials = "federated_credentials"
	// Sign-in evidence (Entra ID P1/P2): per-app and per-credential last use,
	// and the service principal / managed identity sign-in log.
	SurfaceEntraSignInActivity     = "sign_in_activity"
	SurfaceEntraCredentialActivity = "credential_activity"
	SurfaceEntraSignIns            = "sign_ins"
	SurfaceEntraLicenses           = "licenses"
	// Guardrails (Policy.Read.All).
	SurfaceEntraAppManagementPolicies = "app_management_policies"
	SurfaceEntraConditionalAccess     = "conditional_access"
	// Microsoft Entra Agent ID (AgentIdentity*.Read.All; agent users with
	// Directory.Read.All). A blueprint's surface covers its federated
	// credentials too: they are how its agents sign in without a secret.
	SurfaceEntraAgentIdentities          = "agent_identities"
	SurfaceEntraAgentBlueprints          = "agent_blueprints"
	SurfaceEntraAgentBlueprintPrincipals = "agent_blueprint_principals"
	SurfaceEntraAgentUsers               = "agent_users"
	// Owners of every app registration and service principal the tenant
	// controls: an owner can add a credential, and so become the object.
	SurfaceEntraOwners = "owners"
	// Agent ID details: who sponsors each agent object, what each blueprint
	// lets its agents inherit, and directory changes to or by an agent
	// (directoryAudits).
	SurfaceEntraAgentSponsors    = "agent_sponsors"
	SurfaceEntraAgentInheritance = "agent_inheritable_permissions"
	// The Microsoft 365 agent registry (Copilot catalog): Copilot Studio and
	// Agent Builder agents, CopilotPackages.Read.All and an Agent 365 licence.
	SurfaceEntraAgentRegistry = "agent_registry"
	// The organization's Teams app catalog: apps with a bot, Copilot Studio
	// agents and custom bots published to Teams. AppCatalog.Read.All.
	SurfaceEntraTeamsApps  = "teams_apps"
	SurfaceEntraAgentAudit = "agent_audit"
)

// AssumeMechanismEntraOwner is an owner of an app registration or service
// principal (an agent identity blueprint among them): an owner can add a
// credential to it, and so obtain the tokens its credentials obtain.
const AssumeMechanismEntraOwner = "entra_app_owner"

// AssumeMechanismEntraAppRegistration is an app registration and its service
// principal in the tenant (the same appId): the app registration's secrets
// and certificates sign in as the service principal, which holds its
// permissions and role assignments.
const AssumeMechanismEntraAppRegistration = "entra_app_registration"

// InheritedGrantMarker separates a derived grant's native id from the grant
// it was derived from: "<grant native id>#inherited:<agent object id>" is the
// blueprint principal's grant, as the agent identity inherits it.
const InheritedGrantMarker = "#inherited:"

// Subscription surfaces beyond the resource inventory.
const (
	SurfaceAzureRoleAssignments = "role_assignments"
	// Key Vaults still on the access-policy model grant data access that
	// Azure RBAC does not show.
	SurfaceAzureKeyVaultAccessPolicies = "key_vault_access_policies"
	// Resources that run as a managed identity, and AKS clusters' OIDC issuer.
	SurfaceAzureWorkloads = "workloads"
	// Federated credentials on user-assigned managed identities.
	SurfaceAzureIdentityFederation = "managed_identity_federated_credentials"
	// Cognitive Services accounts and Microsoft Foundry: projects, model
	// deployments and connections (armcognitiveservices).
	SurfaceAzureFoundry = "foundry"
	// SurfaceAzureFoundryAgents is each Foundry project's agents, read from
	// its data plane; it needs a Foundry data-plane role assigned to AuthSec.
	SurfaceAzureFoundryAgents = "foundry_agents"
)

// AzureFoundryRuntimeKinds are the cloud_workload runtime kinds the Foundry
// surface writes, and the generic workloads surface therefore leaves out:
// each row has one owner, so each owner's reconciliation ends only its own.
var AzureFoundryRuntimeKinds = []string{
	"microsoft.cognitiveservices/accounts",
	"microsoft.cognitiveservices/accounts/projects",
	// Machine Learning workspaces: hub-based Foundry's hubs and projects, and
	// classic Machine Learning workspaces (one ARM type for all three).
	"microsoft.machinelearningservices/workspaces",
}

// Azure API-plane resources in cloud_resource: one permission an API exposes.
// Graph scopes are resources in the API plane, rated by what they allow.
const (
	// CloudResourceEntraAppRole is an application permission (an app role).
	CloudResourceEntraAppRole = "entra_app_role"
	// CloudResourceEntraDelegatedScope is a delegated permission (a scope).
	CloudResourceEntraDelegatedScope = "entra_delegated_scope"
)

// UsageSourceEntraSignIn is cloud_usage evidence aggregated from Entra
// service principal and managed identity sign-ins: one row per identity per
// resource it obtained tokens for.
const UsageSourceEntraSignIn = "entra_sign_in"

// UsageSourceActivityLog is cloud_usage evidence aggregated from the Azure
// Activity Log: one row per identity per resource provider whose management
// operations it performed (migration 143).
const UsageSourceActivityLog = "activity_log"

// SurfaceAzurePublicIPs is a subscription's public IP addresses and prefixes,
// and what each is attached to: where a sign-in from that address ran.
const SurfaceAzurePublicIPs = "public_ips"

// SurfaceAzureActivityLog is a subscription's management-plane operations.
const SurfaceAzureActivityLog = "activity_log"
