# Azure onboarding (Microsoft Entra + Azure subscriptions)

AuthSec connects a customer's Entra tenant and Azure subscriptions through
**one multi-tenant Entra app registration owned by AuthSec**. The customer does
not create an app, a secret, or run a script. Their only actions are
Microsoft's own admin-consent and sign-in screens.

```
AuthSec tenant
└── AuthSec app registration (multi-tenant, one for all customers)
      ├── Microsoft Graph application permissions
      │     Application.Read.All · Directory.Read.All · AuditLog.Read.All
      │     Policy.Read.All (optional: guardrails)
      │     AgentIdentity.Read.All · AgentIdentityBlueprint.Read.All ·
      │     AgentIdentityBlueprintPrincipal.Read.All (optional: Entra Agent ID)
      │     CopilotPackages.Read.All (optional: Microsoft 365 agent registry)
      │     AppCatalog.Read.All (optional: Teams app catalog)
      └── Azure Service Management delegated permission: user_impersonation
            │
            │  admin consent in each customer tenant creates…
            ▼
Customer tenant
└── AuthSec service principal
      ├── Graph access (from consent)
      └── Azure RBAC Reader, assigned per subscription
            ├── Subscription A
            ├── Subscription B
            └── Subscription C
```

Graph consent and Azure RBAC are separate grants. Consent gives the service
principal directory read access and **nothing in any subscription**. The service
principal never holds `Microsoft.Authorization/roleAssignments/write`, so it can
never grant itself Reader. Each Reader assignment is created with the delegated
ARM token of the customer administrator who signed in, through the same ARM
REST API the portal uses.

Code: `internal/azure` (Azure SDK for Resource Manager and AuthSec's app-only
tokens via `azidentity`; Microsoft Graph SDK for Graph, with the same adapter
sending the beta and Agent ID listings no SDK builder covers; plain REST only
for the authorization-code redemption and the caller-permissions read),
`services/azure_onboarding_service.go`
(flow and RBAC), `services/azure_discovery.go` (inventory),
`services/azure_identity_discovery.go` (directory and RBAC),
`services/azure_access_discovery.go` (API permissions, federation, sign-ins,
guardrails), `services/azure_workload_discovery.go` (workloads, Key Vault
access policies), `services/azure_foundry_discovery.go` (Microsoft Foundry),
`services/azure_agent_details.go` (Agent ID owners, sponsors, inheritance and
audit),
`repository/cloud_azure_repository.go`,
`controllers/platform/cloud_azure_controller.go`.

## One-time setup (AuthSec operator)

In AuthSec's own tenant, create **one** app registration:

1. **Supported account types:** accounts in any organizational directory (multitenant).
2. **Redirect URI, Web platform:** the value of `AZURE_REDIRECT_URI`, exactly.
   For example `https://<authsec-host>/api/v1/auth/azure/callback`.
3. **API permissions:**
   - Microsoft Graph, **Application**: `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`,
     and `Policy.Read.All` (optional, read-only: app management and Conditional Access policies),
     and `AgentIdentity.Read.All`, `AgentIdentityBlueprint.Read.All`, `AgentIdentityBlueprintPrincipal.Read.All`
     (optional, read-only: Microsoft Entra Agent ID), and `CopilotPackages.Read.All` (optional, read-only:
     the Microsoft 365 agent registry -- Copilot Studio and Agent Builder agents)
   - Azure Service Management, **Delegated**: `user_impersonation`
   - Microsoft Graph, **Delegated**: `openid`, `profile`

   Declaring `user_impersonation` is required. Admin consent only grants what is
   declared. Without it, the sign-in leg asks each administrator to consent
   individually, and fails with AADSTS65001 where user consent is disabled.
4. **Certificates & secrets:** create a client secret. Put it only in the
   deployment environment.

Do **not** grant admin consent in AuthSec's own tenant on the customers' behalf.
Consent happens in each customer tenant.

`Policy.Read.All` is optional. A tenant that consented before it was added keeps
working: Verify reports it `not_granted` with `optional: true` instead of failing,
and only the two guardrail surfaces are `denied`. Running Connect again shows the
consent screen with it included.

The three `AgentIdentity*` permissions are optional the same way: without them
the agent identity, blueprint and blueprint principal surfaces are `denied`
(their error names the permission), and everything else is read as before.
Agent users need no new permission (`Directory.Read.All`).

`CopilotPackages.Read.All` is optional too, and its API also needs a Microsoft
Agent 365 licence in the customer's tenant: granted without the licence, Verify
records it `license_required` and the `agent_registry` surface `unsupported`.

`AppCatalog.Read.All` is optional and needs no licence: it reads the
organization's Teams app catalog, where Copilot Studio agents and custom bots
published to Teams appear. Not granted, the `teams_apps` surface is `denied`
with `not_granted`.

Foundry projects' agents are read from the Foundry data plane, which Reader
does not reach. It is optional: assign AuthSec's service principal a Foundry
role that can read agents on the Foundry resources (a custom role with only
the agents read action is the narrowest). Without one, the subscription's
`foundry_agents` surface is `denied` with `foundry_role_not_assigned`.

### Environment

| Variable | Meaning |
|---|---|
| `AZURE_AUTHSEC_CLIENT_ID` | The app registration's application (client) id |
| `AZURE_AUTHSEC_CLIENT_SECRET` | Its client secret. Never stored in the database |
| `AZURE_REDIRECT_URI` | The redirect URI registered above. Its path must be `/api/v1/auth/azure/callback` |
| `AZURE_AUTHSEC_TENANT_ID` | *Optional.* The tenant that owns the registration. No token is ever requested from it. When set, each customer's service principal must name it as `appOwnerOrganizationId`, which catches a misconfigured deployment |

Redis (`REDIS_URL`) must be reachable. It holds the one-time OAuth state and the
short-lived sign-in session. `GET /authsec/discovery/azure/oauth/status`
reports `available:false` until the three required variables are set.

Local development example:

```env
AZURE_AUTHSEC_CLIENT_ID=<app id>
AZURE_AUTHSEC_CLIENT_SECRET=<secret>
AZURE_REDIRECT_URI=http://localhost:7001/api/v1/auth/azure/callback
# optional
# AZURE_AUTHSEC_TENANT_ID=<authsec tenant id>
```

The callback route is served by the **backend** (`PORT`, default 7468). If the
redirect URI points at the UI dev server on `:3000`, that server must proxy
`/api/v1/auth/azure/*` to the backend. Otherwise, register and configure
`http://localhost:7468/api/v1/auth/azure/callback` instead. Entra allows
`http://localhost` redirect URIs for development.

## Customer flow

```
UI                  AuthSec backend                    Microsoft
│ POST /oauth/start ─▶ state+PKCE → Redis
│ ◀── authorize_url (admin consent)
│ ─────────────────────────────────────────────────────▶ /common/adminconsent
│                                    admin consents → SP created in tenant
│                    GET /api/v1/auth/azure/callback ◀── admin_consent=True&tenant=…
│                    state consumed; new state → Redis
│                    302 ──────────────────────────────▶ /{tenant}/oauth2/v2.0/authorize
│                                    admin signs in (ARM user_impersonation, PKCE)
│                    GET /api/v1/auth/azure/callback ◀── code
│                    code → token (server to server); tid must equal tenant
│                    ARM token → Redis (≤15 min), session_id
│ ◀── 302 /discovery/cloud/azure/oauth/callback?session_id=…
│ GET /oauth/session  (preview: subscriptions, can_assign_reader)
│ POST /oauth/connect ─▶ Graph app token → find SP → verify permissions
│                       → verify the signed-in user may bind the tenant
│                       → list subscriptions (admin token)
│                       → Reader per subscription (admin token, ARM PUT)
│                       → prove access (AuthSec app token)
│                       → Resource Graph inventory (AuthSec app token)
│ ◀── tenant + per-subscription results
```

### Why there are two legs

1. **Admin consent** (`/{tenant|common}/adminconsent`) grants every permission
   statically configured on the app and creates the customer's service
   principal. `prompt=admin_consent` on `/authorize` is not used, because v2.0
   rejects it (AADSTS901001).
2. **Delegated sign-in** (authorization code + PKCE, against the consented
   tenant) gets the administrator's own ARM access, which is needed to write
   role assignments. `offline_access` is not requested, so no refresh token
   exists. The access token lives only in Redis and is deleted once Connect
   completes.

### Where the browser comes back to

The onboarding leaves the page for Microsoft (a full-page redirect) and comes
back through AuthSec's one registered callback. An administrator works on
their workspace's own UI origin (`https://<workspace>.app.authsec.ai`, or a
verified custom domain), and the browser keeps their session for that origin
only. So Start records the origin it was called from (the browser's `Origin`
header on `POST /azure/oauth/start`) in the OAuth state, and the callback
returns there, on success and on failure. It is kept only when it is one of
this workspace's own UI origins: the configured UI origin
(`PUBLIC_UI_ORIGIN`), the workspace's own domain (`workspaces.workspace_domain`)
or one of its verified domains (`workspace_domains`), over https (http only on
a local host), with no path, query or credentials. Anything else is ignored and
the configured UI origin is used, so the callback cannot redirect anywhere
AuthSec does not serve this workspace's UI (`services/azure_oauth_return.go`).

### Which tenant is trusted

The `tenant=` parameter on the consent redirect passes through the browser and
can be edited. The tenant AuthSec binds is the `tid` in the sign-in leg's token
response. That response comes server to server, authenticated with AuthSec's
client secret and the PKCE verifier, and its `tid` must equal the tenant from
the consent leg.

The signed-in user must be a **Member** (not a guest) of that tenant. To attach
the tenant to a workspace for the first time, they must also hold an active
**Global Administrator** or **Privileged Role Administrator** role, the roles
that can grant consent to Graph application permissions. Without this check,
anyone could bind a tenant that already consented AuthSec for one customer
workspace to their own workspace. Once the tenant is connected to a workspace,
any member, for example a subscription Owner, can re-run the flow to add Reader
on more subscriptions.

## RBAC: Reader per subscription

For each selected subscription (all visible ones by default):

1. Subscriptions in the Disabled, Expired or Deleted state are skipped.
2. AuthSec lists the role assignments for the service principal
   (`$filter=principalId eq '<sp>'`). An existing Reader at the subscription
   scope gives **already_assigned**. Reader from a management group above it
   gives **inherited**. Neither case writes anything.
3. Otherwise AuthSec sends the following request:
   ```
   PUT https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments/{name}?api-version=2022-04-01
   { "properties": { "roleDefinitionId": "/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
                     "principalId": "<sp object id>", "principalType": "ServicePrincipal" } }
   ```
   `{name}` is a UUIDv5 of (scope, principal, role), so a repeated PUT addresses
   the same assignment. `409 RoleAssignmentExists` counts as success.
   `403 AuthorizationFailed` means the administrator lacks
   `roleAssignments/write` there (Owner, User Access Administrator or Role Based
   Access Control Administrator is needed), and is recorded as
   **permission_denied** for that subscription only. `PrincipalNotFound` is
   retried briefly, because a just-created service principal may still be
   replicating.
4. Access is proven with AuthSec's **own** client-credentials ARM token
   (`GET /subscriptions/{sub}`). Azure applies new assignments within minutes,
   so Connect polls for up to about 60 seconds. A subscription that is still not
   readable is stored with `status=error`, `last_error_code=rbac_propagating`.
   `POST /connectors/:id/verify` finishes it later without the administrator.

No management-group assignment, no `elevateAccess`, no Azure CLI and no portal
step are involved.

## What is stored

Nothing secret. `cloud_connector.auth_ref` is the handle `azure-app:<client id>`.

| Row | scope_kind | scope_id | parent_scope_id | attrs |
|---|---|---|---|---|
| Tenant | `tenant` (migration 141) | tenant id | NULL | service principal object id, Graph permissions (granted, and usable, denied or license_required), `licensing` and `guardrails` (written by discovery) |
| Subscription | `subscription` | subscription id | tenant id | display name, state, Reader assignment (status, assignment id, verified) |

Inventory goes to `cloud_resource`, one row per resource Azure Resource Graph
returns for the subscription:
- `kind` is the lowercased ARM type, `native_id` the lowercased resource id, and `resource_account` the subscription.
- Sensitivity follows the PRD's Azure resource table: Key Vault, Managed HSM and
  user-assigned identities high; databases and storage medium, high when tagged
  production (`env`/`environment`/`stage`/`tier` = `prod`/`production`/`prd`/`live`);
  messaging, compute (VMs, Function/Web Apps, Container Apps, AKS) and AI services
  medium; everything else low. Labelled `heuristic_service`; a customer's own
  classification is never overwritten.
- Each pass bumps the connector's `scan_generation`, and coverage is written to `cloud_connector.coverage` (`surfaces.resources`).
- Rows not seen are deleted only after a complete pass. Denied, throttled or capped passes (50,000 resources) are partial and delete nothing.

### Passes are runs

Every pass over a connector (the tenant, or one subscription) is a
`cloud_scan_run` row, as an AWS scan is: `trigger` is `connect`, `verify` or
`schedule`; the pass holds a 3-minute lease it renews every minute; it gets the
connector's next generation in the same transaction that creates it; and it
ends `published` with its final coverage (or `failed` when it read nothing).

- `uq_cloud_scan_run_live` admits ONE live run per connector, so two replicas
  can never scan one tenant or subscription at once.
- A pass whose process stopped is `abandoned` by the next pass over that
  connector once its lease lapses.
- Azure runs its passes itself. The AWS scan worker's claim is restricted to
  AWS connectors, so it never picks one up.

### Scheduled rediscovery

Every connected tenant whose last pass finished more than
`AZURE_DISCOVERY_INTERVAL` ago (default `12h`; `0` turns it off) is re-verified
and rediscovered automatically -- what the Verify button does, recorded with
trigger `schedule`. Checked every 5 minutes, starting a minute after boot. Safe
on every replica: the live-run index decides.

## Identity discovery

Connect and Verify start discovery **in the background**, because a
directory can hold more objects than one 120-second request can page through.
Progress and the outcome are each connector's `coverage` (`status: running`
while a pass is in flight). One run per tenant at a time.

**Tenant pass** (Microsoft Graph, AuthSec's app-only token), stored under the tenant connector:

| Read | Stored as |
|---|---|
| `GET /v1.0/users` | `cloud_identity` kind `entra_user` (UPN, mail, user type, enabled) |
| `GET /v1.0/groups`, `/groups/{id}/members` | `entra_group`, with direct member ids (first 1,000 per group) |
| `GET /v1.0/applications` | `entra_application` (app registrations) |
| `GET /v1.0/servicePrincipals` | `entra_service_principal`, or `entra_managed_identity` with the resource it belongs to |
| app and service principal `passwordCredentials` / `keyCredentials` | `cloud_secret` kind `entra_client_secret` / `entra_certificate`: name and validity only, **never a value or hint** |
| `GET /v1.0/roleManagement/directory/roleAssignments`, `/roleDefinitions` | `cloud_permission` `plane=api`: every active Microsoft Entra role assignment, built-in and custom, with the actions its definition allows; one scoped to an administrative unit or a single object is `scope_kind=prefix`, `constraint_state=conditional`, the scope in its condition (`Directory.Read.All`). PIM-eligible assignments are not read |
| `GET /v1.0/servicePrincipals/{api}/appRoleAssignedTo` (per API that defines app roles) | application permissions: `cloud_resource` kind `entra_app_role` (one per permission an API exposes, e.g. "Microsoft Graph: Mail.Read") + `cloud_permission` `plane=api` pointing at it |
| `GET /v1.0/oauth2PermissionGrants` | delegated permissions: `cloud_resource` kind `entra_delegated_scope` + `cloud_permission` with `constraint_state=bounded` (only on behalf of a signed-in user; the condition says for whom) |
| `GET /v1.0/applications/{id}/federatedIdentityCredentials` | `cloud_assume_edge` `mechanism=oidc_federation` on the app's service principal: `ci_pipeline` (GitHub Actions, GitLab, Terraform Cloud, ...), `k8s_service_account` (with `k8s_ref`), `identity` (another Entra identity) or `external_account` |
| `GET /beta/reports/servicePrincipalSignInActivities` | `cloud_identity.last_used_at` and last app-only / delegated sign-in in attrs (P1/P2) |
| `GET /beta/reports/appCredentialSignInActivities` | `cloud_secret.last_used_at` (P1/P2) |
| `GET /beta/auditLogs/signIns` (servicePrincipal, managedIdentity; last 7 days, newest 20,000 per type) | `cloud_usage` `source=entra_sign_in` (migration 142): one row per identity per resource, with counts, failures, source IPs, `ai_service` for Azure AI (OpenAI, Cognitive Services), and the `cadence`: hours of the day active, days active, the typical gap between sign-ins and whether it is `regular` (a schedule) -- never the raw times. Application permissions are then stamped `last_exercised_at` from the last sign-in to their API |
| `GET /v1.0/servicePrincipals/microsoft.graph.agentIdentity` | Microsoft Entra Agent ID agent identities: `cloud_identity` kind `entra_agent_identity`, with the blueprint it was created from (`agent_blueprint_app_id`), its agent user and `agent_listed=true` (`AgentIdentity.Read.All`). A service principal of type `ServiceIdentity` in the base listing is an agent identity too |
| `GET /v1.0/applications/microsoft.graph.agentIdentityBlueprint` | blueprints: `entra_application` with `agent_type=agent_identity_blueprint` and `agent_count`; their secrets, certificates and federated credentials are read as any app registration's -- they are the credentials the agents sign in with (`AgentIdentityBlueprint.Read.All`) |
| `GET /v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal` | the blueprints' service principals: `entra_service_principal` with `agent_type=agent_identity_blueprint_principal` (`AgentIdentityBlueprintPrincipal.Read.All`) |
| `GET /beta/users/microsoft.graph.agentUser` | agent users: `cloud_identity` kind `entra_agent_user`, with the agent identity it belongs to (`identityParentId`) |
| (derived) | `cloud_assume_edge` `mechanism=agent_identity_blueprint`: the blueprint's service principal (or the blueprint) can become each agent identity made from it; `mechanism=agent_user`: an agent identity can become its agent user |
| `GET /v1.0/subscribedSkus` | tenant attrs `licensing`: Entra ID P1/P2, Workload ID Premium, and whether sign-in data proved available |
| `GET /v1.0/policies/defaultAppManagementPolicy`, `/policies/appManagementPolicies` (+ `appliesTo`) | tenant attrs `guardrails` (credential rules), and `app_management_policy_ids` on the identities a policy applies to (`Policy.Read.All`) |
| `GET /beta/identity/conditionalAccess/policies` | tenant attrs `guardrails`: total, the policies that target service principals, and `agent_conditional_access`, the ones that target agent identities (`Policy.Read.All`; beta, where the agent conditions are) |
| `GET /v1.0/applications/{id}/owners`, `/v1.0/servicePrincipals/{id}/owners` (every app registration, and every service principal the tenant controls) | attrs `owners`; each owner also as `cloud_assume_edge` `mechanism=entra_app_owner` on what it can become |
| `GET /v1.0/copilot/admin/catalog/packages` (agents) and each agent's detail | the Microsoft 365 agent registry: tenant attrs `agent_registry`, `attrs.registry` on an agent identity it names, and a declared agent for each one, under its app's service principal when the tenant has it (`CopilotPackages.Read.All`, Agent 365 licence) |
| `GET /v1.0/appCatalogs/teamsApps?$filter=distributionMethod eq 'organization'&$expand=appDefinitions($expand=bot)` | the organization's Teams apps with a bot: tenant attrs `teams_agents`, and a declared agent for each, under its bot's service principal when the tenant has it (`AppCatalog.Read.All`) |
| `GET .../microsoft.graph.agentIdentityBlueprint/sponsors`, `.../microsoft.graph.agentIdentity/sponsors`, `/v1.0/users/{id}/sponsors` | attrs `sponsors` and `sponsor_source` on blueprints, agent identities and agent users |
| `GET .../microsoft.graph.agentIdentityBlueprint/inheritablePermissions` | the permissions each agent identity inherits from its blueprint, as derived `cloud_permission` rows |
| `GET /beta/auditLogs/directoryAudits` | attrs `audit_changes`, `audit_actions` and `created_by` on Agent ID objects |

Sign-in data needs Entra ID P1/P2 in the customer's tenant. Without it Graph
answers 403 `Authentication_RequestFromNonPremiumTenantOrB2CTenant`; the three
sign-in surfaces are recorded `unsupported` with `error_code: license_required`
(Microsoft does not offer the data), which does not make the pass partial.
Usage rows are never aged out by generation: the read covers a week, and a
resource last used a month ago was still last used then.

API permission sensitivity: **high** for `*.ReadWrite.All`, `*.FullControl.All`,
`Directory.*`, `RoleManagement.ReadWrite.*` and `full_access_as_app`; **low** for
`openid`, `profile`, `email`, `offline_access`, `User.Read`; **med** otherwise.

`cloud_identity.native_id` is the Entra object id (lowercased), so a role
assignment's `principalId` joins to its identity directly.

**Subscription pass** (ARM, AuthSec's app-only token under Reader), stored under the subscription connector:

| Read | Stored as |
|---|---|
| Azure Resource Graph | `cloud_resource` (see above) |
| `Microsoft.Authorization/roleDefinitions` + `roleAssignments` | `cloud_permission` `plane=cloud`: one row per assignment, with the role's actions and notActions |
| Resource Graph, `Microsoft.KeyVault/vaults` `accessPolicies` | `cloud_permission` `plane=cloud` on the vault, for vaults NOT on RBAC (`enableRbacAuthorization`): data access RBAC never shows. High when it reads secrets, decrypts/signs, or manages contents |
| Resource Graph, every resource with an `identity`, and AKS clusters | `cloud_workload`, one row per (resource, identity): system-assigned, each user-assigned, and the AKS kubelet identity; `runtime_kind` is the ARM type. AKS rows carry the OIDC issuer and whether workload identity is on |
| `Microsoft.ManagedIdentity/userAssignedIdentities/{id}/federatedIdentityCredentials` | `cloud_assume_edge` on the managed identity (the AKS workload identity join key) |
| Resource Graph `ResourceContainers` (the subscription and its resource groups) | the subscription connector's attrs `tags` and `stage` (`production`, `non_production`, `unknown`, from `env`/`environment`/`stage`/`tier` tags). Resources with no environment tag of their own take their resource group's, else the subscription's; a role grant on a production scope moves up one sensitivity level (low to med, med to high) |
| Resource Graph, `Microsoft.Network/publicIPAddresses` and `publicIPPrefixes`, network interfaces | the subscription connector's attrs `public_ips`: each address or prefix and what it is attached to (a VM, a load balancer, a NAT gateway), for sign-in origins |
| `Microsoft.Insights/eventtypes/management/values` (Activity Log, last 7 days) | `cloud_usage` `source=activity_log` (migration 143): one row per identity per resource provider, from SUCCEEDED operations; and `last_exercised_at` on each Azure RBAC grant whose actions and scope cover an operation its holder performed |

A role assigned ABOVE the subscription (a management group or the root) is
listed by every subscription below it. Each subscription keeps its own copy
(`native_id` suffixed `#<subscription>`), so passes over two subscriptions never
take one row from each other.

Each grant records where it applies (`scope_kind`): `account_wide` (the
subscription, or a management group above it), `prefix` (a resource group),
or `resource` (linked to its `cloud_resource` row). An assignment with an ABAC
condition is `constraint_state=conditional`; one whose role has notActions is
`negated`.

Sensitivity:
- **high**: Owner, User Access Administrator, RBAC Administrator, any custom role that can write role assignments, and privileged directory roles (Global Administrator and others).
- **med**: Contributor and other write roles.
- **low**: read-only roles.

A principal the tenant pass has not seen (deleted, or from another tenant) is
counted as `role_assignments_unresolved` and never invented.

Reconciliation is per table, each gated on the surfaces that write it, so a
guardrail read refused for want of `Policy.Read.All` never stops a deleted user
from leaving the inventory:

| Table | Aged out only when these were read in full |
|---|---|
| identities | users, groups, applications, service principals |
| secrets | applications, service principals |
| tenant grants | directory roles, app permissions, delegated permissions, agent inheritable permissions |
| API-permission resources | service principals, app permissions, delegated permissions |
| tenant federation edges | applications, federated credentials, owners |
| subscription resources | resources |
| subscription grants | role assignments, Key Vault access policies |
| workloads (all but the two below) | workloads |
| Cognitive Services accounts and Foundry projects | foundry |
| managed identity federation edges | managed identity federated credentials |

A directory object that is gone takes its grants, edges and usage with it.

What only Microsoft Entra Agent ID listed (`attrs.agent_listed`) -- the object,
its secrets, the edges landing on it, and the grants agents inherit from their
blueprints -- is aged out only by a pass that read all four Agent ID listings
in full. A pass that could not (permission not granted, throttled) leaves it as
it was, and the IGA graph keeps it through its own `agent_node`,
`can_assume_agent` and `access_edge_agent` partitions, which close only on the
same condition.

### Evidence

At the end of each pass, while it still holds its run's lease, every identity,
grant, resource and workload the pass confirmed gets a `cloud_observation`: the
Microsoft API that returned it, the coverage surface and that surface's state,
the scan run, and its identifying facts (never a secret, and never what changes
on every read, such as sign-in times). The writer is the one AWS uses: an
unchanged fact is confirmed again (`confirmation_count`, `last_confirmed_at`)
rather than written twice, and a pass that lost its lease confirms nothing.

### Suspected agents

After every run, each non-Microsoft service principal and managed identity is
tested against one rule (PRD A3, "inferred"): it obtained tokens for an Azure
AI service, or it signs in as itself AND holds application permissions, is
federated to a pipeline or a Kubernetes service account, runs on compute, or
signs in on a schedule or around the clock. Federation counts only as a
federated credential (`mechanism=oidc_federation`): an owner, who could add a
credential, says nothing about how an identity is used. A match is proposed in the
product's own agent inventory -- `discovered_agents`, `source=azure`,
`evidence_mode=inferred`, `status=unregistered`, with its signals and a
confidence in `metadata` -- for a person to claim, ignore or quarantine through
the existing `/authsec/discovery/agents` endpoints. A re-run refreshes the
evidence and never moves a person's decision. The service principal the
tenant is read with -- AuthSec's own, or the customer's own app -- is never
proposed, nor is an identity a declared agent below already accounts for (a
registry or Teams agent's app, the identity a bot or Logic Apps agent runs as).

### Declared agents (Microsoft Entra Agent ID)

Every agent identity is registered in the same inventory with
`evidence_mode=declared` -- the directory says it is an agent -- under the
fingerprint inference uses, so an identity inferred before Agent ID was read is
upgraded in place and a person's decision on it is kept. Its signals name the
blueprint, the agent user and the week's sign-ins; it is `running` when it
signed in within a week. Agent identities and blueprint principals are never
inferred. Sign-ins made by an agent carry `agent_types` on their usage row.

### Declared agents (other sources)

After Agent ID, the run registers the agents other sources declare, each
under the fingerprint of the identity it runs as when the tenant has it, so
an agent named by several sources is listed once (the first source in this
order keeps it):

| Source | `metadata.evidence_source` | Read in |
|---|---|---|
| Microsoft 365 agent registry | `agent_registry` | tenant pass |
| Microsoft Foundry agent application (published agent) | `foundry_agent_application` | subscription pass, Foundry surface |
| Microsoft Foundry project agent (data plane) | `foundry_project_agent` | subscription pass, `foundry_agents` |
| Logic Apps workflow running an agent loop (an `Agent` action) | `logic_apps_agent` | subscription pass, workloads |
| Azure Bot Service bot (its Entra app or managed identity) | `azure_bot_service` | subscription pass, workloads |
| Teams app with a bot | `teams_app_catalog` | tenant pass, `teams_apps` |

A Logic Apps agent is keyed by its workflow, since one managed identity can
serve several workflows. A bot is a workload (`microsoft.botservice/botservices`)
that runs as its app's service principal or its managed identity, so its
access is the grants of that identity.

### Agents no longer seen

After registration, an Azure agent of the tenant that this run did not refresh
is closed with a lifecycle event (`absent`), never deleted and never with an
actor, since a scan cannot say who removed it: `gone` when the source that
declared it no longer lists it, or when an inferred agent's identity left the
tenant; runtime `unknown` when an inferred agent's identity is still there but
no longer meets the rule. Each source closes only after it was read completely
in this run (and, for subscription sources, only in subscriptions this run
read); a source that failed or was partly read closes nothing. A later
sighting refreshes a closed agent as usual.

### Agent ID details (Microsoft Entra Agent ID)

Each tenant pass also reads what Agent ID records about each agent object.
Discovery only: all of it is read, nothing changes an agent, and no judgement
is drawn from it.

**Sponsors.** The sponsors of every blueprint, agent identity and agent user
become `attrs.sponsors` (`{id, kind, name, active}`; active is an enabled user
or service principal of the directory, or a group). Microsoft
documents `AgentIdentity.ReadWrite.All` as the only application permission that
reads an agent identity's OWN sponsors; AuthSec asks for read permissions only,
so when a tenant refuses that read once, each agent identity carries its
blueprint's sponsors (`sponsor_source: blueprint`) and the `agent_sponsors`
surface says so. Owners -- of blueprints and agent identities among every app
and service principal -- are read with the rest (see Owners below).

**What it inherits.** An agent identity inherits every permission granted to
its blueprint's principal on an API the blueprint lists as inheritable, for the
scopes or roles listed (`allAllowed` or `enumerated`). Microsoft merges these
into the agent's tokens and shows them nowhere in Graph, so AuthSec derives
them: one `cloud_permission` row per (grant, agent), its native id the grant's
with `#inherited:<agent object id>`, listed with `inherited: true`. In the IGA
graph they are access edges with basis `derived`. A blueprint homed in another
tenant keeps its inheritable permissions there, so its agents' inheritance is
not derived.

**What changed it.** The directory audit log (beta, for the `agentType` and
`blueprintId` Agent ID adds) is read since the last read -- the first read
reaches back 30 days, Entra's longest retention -- at most 10,000 events a
pass. Events on an Agent ID object become `attrs.audit_changes`, events it
initiated `attrs.audit_actions`, and its creation `attrs.created_by`: who, what,
when, and the NAMES of the properties changed, never their values. Each pass
adds to the history stored before (20 events per list), so it outlives Entra's
retention.

**Conditional Access.** Every Conditional Access policy that names agent
identities (by an agent's or a blueprint principal's object id, or all agents),
selects them by attribute, or applies at an agent risk level is recorded as
read in `guardrails.agent_conditional_access`.

**The Microsoft 365 agent registry.** The tenant's Copilot catalog, filtered to
agents (Package Management API, Microsoft Agent 365; it replaced the Graph
`agentRegistry` APIs): Copilot Studio and Agent Builder agents, declarative and
custom engine agents, many with no Entra agent identity. Each is recorded as
Microsoft lists it -- platform, publisher, type, Microsoft's agent class,
whether an administrator blocked it, to whom it is available and deployed --
with its use over the last 30 days (active users, sessions, last use; the
first 300 a pass). The catalog is kept on the tenant connector
(`agent_registry`); an agent identity it names carries its entry as
`attrs.registry`; every catalog agent is registered in the agent inventory as
declared (`evidence_source: agent_registry` for one with no agent identity,
under the identity otherwise).

### Owners

The owners of every app registration, and of every service principal the
tenant controls (not Microsoft's first-party ones, nor managed identities), are
read each pass (`owners` surface, Application.Read.All) and recorded as
`attrs.owners`. An owner can add a credential to what it owns and so obtain its
tokens, so each owner is also a can_assume edge (`mechanism=entra_app_owner`):
an app registration's owners onto its service principal, a service principal's
onto itself, a blueprint's onto the service principal its agents' edges start
from. The federation list names each subject AuthSec recorded
(`subject_name`).

### Sign-in origins

Entra's sign-in log gives an address, nothing more; for an identity that signs
in with a client secret, that address is the one clue to where the secret is
used. Each subscription pass records the subscription's public addresses and
prefixes (`public_ips` surface) and what each is attached to -- a VM through
its network interface, a load balancer, a NAT gateway. After every run, each
address on a sign-in usage row gets `attrs.ip_origins`: `your_azure` (one of the
connected subscriptions' addresses, with the resource), `azure` (an Azure
address that is not yours: the service tag Microsoft publishes for it, with its
service and region, read through `armnetwork`), `private`, `outside_azure`, or
`unknown` (not yours, and the service tags could not be read). AWS addresses
are not placed: the AWS scan does not record public addresses.

### Microsoft Foundry

Each subscription pass reads every Cognitive Services account through
`armcognitiveservices` (the official Resource Manager SDK) under Reader: Foundry
resources (kind `AIServices` with project management), Azure OpenAI, and
single-service accounts. For a Foundry or Azure OpenAI account it lists the
model deployments (model, version, publisher, SKU and capacity, content
filter); for a Foundry account, also its connections, its projects, and each
project's connections and published agents.

A published agent is an Agent Application under its project
(`accounts/projects/applications`), with its own Entra agent identity
blueprint and agent identity, and the deployments that run its agent versions
(`applications/agentDeployments`). Both are Resource Manager resources Reader
lists, read through the official `armcognitiveservices/v4` preview SDK (the
stable v2 has no client for them), lists only -- never the `listAgents` action
nor anything that starts, stops or invokes an agent. Each is recorded on its
project's row as `agent_applications`: name, display name, whether it is
enabled, how callers are authorized (Azure RBAC, the organization, Microsoft
365 and Teams channels), its endpoint (without query string), the agents it
exposes, the principal ids of its blueprint and agent identity, who published
it and when, and each deployment's type (Managed prompt agent, Hosted
container), state, agent versions and protocols. Where the API is not offered
for the account, the project carries `agent_applications_unavailable` instead,
and the surface is not marked partial for it.

Hub-based Foundry (Foundry classic) is read through `armmachinelearning`: a
hub is a Machine Learning workspace of kind Hub, a hub-based project one of
kind Project naming its hub. Each is recorded (`foundry_kind` `hub` or
`hub_project`) with its connections, its public network access, its managed
network's outbound rule (`isolation_mode`), and for a hub the storage account,
key vault, container registry and Application Insights it keeps its data in,
and its projects. A classic Machine Learning workspace is recorded as the
compute it is (`foundry_kind: ml_workspace`); the `foundry` surface owns all
three, under `microsoft.machinelearningservices/workspaces`.

Accounts and projects are compute that runs as a managed identity, so they are
`cloud_workload` rows under their ARM types (`microsoft.cognitiveservices/accounts`,
`.../accounts/projects`), one per identity, exactly as the workloads surface
wrote them before; the `foundry` surface owns those two runtime kinds and the
workloads surface leaves them out. What Resource Graph cannot see rides on the
row as attributes: `deployments`, `connections`, `projects`, and the account's
`local_auth_enabled` (API keys accepted), `public_network_access` and
`network_default_action`. A single-service account with no identity is not a
workload, as before.

A connection is recorded by name, category, target, auth type and whether it
is shared to every project; `secret_based` marks the auth types that store a
key, password, token or SAS in Foundry. Its credentials are never read: they
live only in the auth-type subclass, and the target is stored without its
query string or user info. A detail read that fails keeps the account and
marks it `detail_incomplete` (the list it could not read is left out, never
written empty), and makes the surface partial.

Unpublished agents, and agents of Foundry's newer agent model, are in
Foundry's data plane, which Reader does not reach. When a Foundry data-plane
role is assigned to AuthSec, each project's agents are listed
(`GET {project}/agents?api-version=v1`, surface `foundry_agents`) and recorded
on the project's row as `project_agents`: name, state, kind, model, tool
types, MCP servers and connections -- never instructions, and never a tool's
headers or keys. Their
identities are Entra agent identities, found by the
tenant pass: a Foundry agent identity blueprint trusts its project's managed
identity through a federated credential. `GET /azure/foundry` returns the
accounts and projects with, under `trusts`, every identity a project's managed
identity can become that way, and each agent identity that blueprint obtains
tokens for. Capability hosts (the Agent Service setup) are not read: the SDK
can only get one by name.

### The IGA graph

Once the graph schema has verified, each finished pass is projected into the
shared `iga_*` graph under provider `azure` (`internal/azuregraph`), in its own
transaction, the tenant first: Entra objects, credentials, API permissions,
resources, entitlements, workloads, access edges (`iga_access_edges`), group
membership, runs-as and federation (`iga_relationship`). Each app registration
is linked to its service principal in the tenant (the same appId) as
`can_assume` (`mechanism=entra_app_registration`): the app registration holds
the secrets and certificates, the service principal what they unlock. Every
row carries the pass's run as its confirmation. Reconciliation is per connector and partition,
licensed by that pass's own coverage: a row the pass did not see goes `stale`,
and is `ended` only when every surface that writes its partition was read in
full; an object is retired only when no connector supports it any more. Azure
RBAC grants carry `effective_conclusion=unknown` (deny assignments and ABAC
conditions are not evaluated); delegated permissions are `partial`, since they
act only for a signed-in user. A federation subject trusting an AKS cluster's
OIDC issuer is resolved to the Kubernetes graph's ServiceAccount when the
Kubernetes agent reports the cluster under the AKS cluster's name (resolution
basis `derived`).

## API

All routes are under `/authsec/discovery`, require authentication, and need
`discovery:read` or `discovery:admin`.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/azure/oauth/status` | read | Is the option configured |
| POST | `/azure/oauth/start` | admin | `{tenant?, login_hint?}` returns `{authorize_url, state}` |
| GET | `/azure/oauth/session?session_id=` | read | Preview tenant and subscriptions, with `can_assign_reader` |
| POST | `/azure/oauth/connect` | admin | `{session_id, subscription_ids?}`: the onboarding itself |
| POST | `/azure/connect-custom` | admin | `{tenant_id, client_id, client_secret}`: onboarding with the customer's own app (see "Your own app") |
| GET | `/azure/connectors` | read | Tenant and subscription rows |
| GET | `/azure/connectors/:id` | read | One row |
| GET | `/azure/connectors/:id/scan-runs` | read | The connector's discovery runs |
| POST | `/azure/connectors/:id/verify` | admin | Re-prove with the tenant's credentials (AuthSec's app, or the customer's own), and start a fresh discovery |
| DELETE | `/azure/connectors/:id` | admin | Revoke. A tenant revokes its subscriptions too |
| GET | `/azure/resources?connector_id=&limit=&offset=` | read | Inventory |
| GET | `/azure/identities?kind=&q=&connector_id=` | read | Users, groups, apps, service principals, managed identities |
| GET | `/azure/grants?plane=&source=&identity_id=&connector_id=` | read | Who holds which role or permission, and where. `source`: `directory_role`, `application_permission`, `delegated_permission`, `rbac_role_assignment`, `key_vault_access_policy`; `inherited` marks what an agent identity inherits from its blueprint |
| GET | `/azure/secrets` | read | App secret and certificate metadata (and last use), soonest expiry first |
| GET | `/azure/federation` | read | Federated credentials: who outside Entra can obtain an identity's tokens |
| GET | `/azure/workloads` | read | Resources that run as a managed identity, AKS clusters and their OIDC issuer |
| GET | `/azure/foundry` | read | Foundry and Cognitive Services accounts and Foundry projects, with models and connections, and the agent identities each project can become |
| GET | `/azure/usage?identity_id=&ai=true` | read | Sign-in evidence per identity per resource (with cadence), most recent first |
| GET | `/azure/evidence?object_id=` | read | How AuthSec knows: the API, run and coverage behind an Entra object and each grant it holds |
| GET | `/azure/graph/summary` | read | The Azure rows of the IGA graph, by kind and state |
| GET | `/azure/graph/blast-radius?object_id=` | read | Every live grant an Entra object reaches: its own, its groups' (nested) and those of identities it can become |

The callback is `GET /api/v1/auth/azure/callback`, unauthenticated, on the root
engine.

Revoking stops AuthSec using the connection. It does not change anything in
Azure, because AuthSec holds no right to delete its own assignments. The
customer removes access by deleting the AuthSec enterprise application, which
removes its role assignments with it. A tenant connected with the customer's
own app also has its stored client secret destroyed in Vault.

## Your own app

Instead of consenting to the AuthSec app, a customer can connect a tenant with
an app registration of their own (`POST /azure/connect-custom`). No browser
sign-in is involved and AuthSec assigns nothing:

1. The customer creates an app registration, adds the Microsoft Graph
   application permissions listed above (the same required and optional ones),
   grants admin consent, creates a client secret, and gives the app's service
   principal the Reader role on each subscription AuthSec should read.
2. AuthSec proves, with the customer's credentials (client credentials grant):
   a Graph token for that tenant, the app's service principal in it (enabled),
   its Graph permissions, and which subscriptions the app can read. An app-only
   token lists only subscriptions where the app holds a role, so one without
   Reader is simply absent, and the result says so.
3. Only then is the secret stored, in Vault at
   `kv/data/secret/workspaces/<workspace>/cloud-discovery/azure/<tenant>`
   (`VAULT_ADDR`, `VAULT_TOKEN`). It never touches Postgres: the connector's
   `auth_ref` is `azure-app:<client id>`, and the tenant's
   `provisioned_via` is `client_credentials`. A failed connect leaves no secret
   behind, and a reconnect never replaces a working secret with an unproven one.
4. The result carries `warnings`: Graph permissions that can change data, Azure
   roles beyond Reader (Owner, Contributor, User Access Administrator, RBAC
   Administrator), no readable subscription.

Every failure of the customer's own app is theirs to fix and says so (400,
`fault: customer_account`): a rejected client id or secret
(`credential_invalid`), an unknown tenant id, an app with no service principal
in the tenant, missing Graph permissions (named). None reads as AuthSec's
deployment, which is what the managed app's `ErrCredentialRejected` means.

Discovery and Verify read the tenant with its own credentials. If they cannot
be read from Vault, the tenant is not read at all -- never silently with
AuthSec's app -- and the tenant connector says so (`credential_invalid`).

**Switching.** Connecting a tenant with the other kind of app moves it: the
tenant connector takes the new credentials, and each of its subscriptions this
connect did not record is moved to them in error (its Reader belongs to the
other app) until it is connected again. Moving to the AuthSec app destroys the
customer's stored secret. The result's `warnings` say what moved.

A passing failure during Verify (throttling, Microsoft's 5xx, a timeout) leaves
the connector as it was, so scheduled discovery keeps trying.

## Testing locally

1. Set the three required `AZURE_*` variables and `REDIS_URL`, then start the backend. Migrations 141-143 apply at boot. The own-app flow also needs `VAULT_ADDR` and `VAULT_TOKEN`.
2. `GET /authsec/discovery/azure/oauth/status` should return `available: true`.
3. Call `POST /authsec/discovery/azure/oauth/start` with a workspace admin JWT, and open `authorize_url` in a browser.
4. Consent as a Global Administrator of a test tenant, then sign in with the same account.
5. Copy `session_id` from the final redirect URL.
6. Call `GET /authsec/discovery/azure/oauth/session?session_id=…` to preview.
7. Call `POST /authsec/discovery/azure/oauth/connect` with `{"session_id":"…"}`.
8. In Azure: Subscription → Access control (IAM) → Role assignments shows the AuthSec app as Reader. Running Connect again creates nothing new.
9. `GET /authsec/discovery/azure/resources` lists the inventory.
10. For a subscription in `rbac_propagating`, call `POST /authsec/discovery/azure/connectors/:id/verify` after a few minutes.

## Limitations

- Public cloud only. Azure Government and 21Vianet use other hosts.
- Directory roles are **active** memberships. PIM-eligible assignments need
  `RoleManagement.Read.Directory`, which AuthSec does not request.
- Grants are as assigned, not effective: a role held through a group is
  recorded on the group, and its members are in the group's attrs.
- Default-access assignments to apps that define no app roles (a user
  assigned to an enterprise app) are app access, not API permissions, and are
  not read.
- Sign-in data needs Entra ID P1/P2, and two of its reads exist only on Graph
  beta. The AuditLog probe uses `directoryAudits`, which every tenant has.
- The sign-in log read is bounded (7 days, newest 20,000 sign-ins per event
  type); a busier tenant reports the surface partial.
- The Kubernetes side of AKS workload identity (the service account's
  `azure.workload.identity/client-id` annotation) comes from the Kubernetes
  connector, joined on `(k8s_ref, issuer)`; Reader cannot see inside a cluster.
- The Activity Log read is bounded (7 days, the newest 20 pages); an operation
  is attributed to EVERY grant of its caller that allows it, because the log
  does not say which role Azure evaluated.
- Directory roles and delegated permissions have no last-use signal.
- Cadence hours are UTC; with few sign-ins the pattern is `insufficient`.
- A pass interrupted by a restart is abandoned by the next pass once its lease
  lapses (3 minutes); the scheduler re-runs it.
- The AKS-to-Kubernetes resolution depends on the Kubernetes agent naming the
  cluster as the AKS resource is named.
- An agent identity's own sponsors need `AgentIdentity.ReadWrite.All`, which
  AuthSec does not request; agents are shown with their blueprint's sponsors.
- The audit read is capped at 10,000 events a pass; in a busier tenant, older
  events of the window are not read.
- Foundry agents' instructions and knowledge are never read; their kind,
  model and tool types are read only when a Foundry data-plane role is
  assigned. Without one, published agents are listed with their identities,
  and any other agent is tied to its project only through the blueprint's
  federated credential on the project's managed identity.
- Logic Apps agent loops are found in Consumption workflows only; a Standard
  logic app's workflows are not read. The SDK's project model (API 2025-06-01) does not yet carry the
  project's agent identity directly.
