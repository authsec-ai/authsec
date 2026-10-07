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
tokens via `azidentity`; Microsoft Graph SDK for Graph; plain REST only for
the authorization-code redemption), `services/azure_onboarding_service.go`
(flow and RBAC), `controllers/platform/cloud_azure_controller.go`.

## One-time setup (AuthSec operator)

In AuthSec's own tenant, create **one** app registration:

1. **Supported account types:** accounts in any organizational directory (multitenant).
2. **Redirect URI, Web platform:** the value of `AZURE_REDIRECT_URI`, exactly.
   For example `https://<authsec-host>/api/v1/auth/azure/callback`.
3. **API permissions:**
   - Microsoft Graph, **Application**: `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`,
     and `Policy.Read.All` (optional, read-only: app management and Conditional Access policies),
     and `AgentIdentity.Read.All`, `AgentIdentityBlueprint.Read.All`, `AgentIdentityBlueprintPrincipal.Read.All`
     (optional, read-only: Microsoft Entra Agent ID)
   - Azure Service Management, **Delegated**: `user_impersonation`
   - Microsoft Graph, **Delegated**: `openid`, `profile`

   Declaring `user_impersonation` is required. Admin consent only grants what is
   declared. Without it, the sign-in leg asks each administrator to consent
   individually, and fails with AADSTS65001 where user consent is disabled.
4. **Certificates & secrets:** create a client secret. Put it only in the
   deployment environment.

Do **not** grant admin consent in AuthSec's own tenant on the customers' behalf.
Consent happens in each customer tenant.

`Policy.Read.All` and the three `AgentIdentity*` permissions are optional. A
tenant that consented before they were added keeps working: Connect and Verify
record each one `not_granted` with `optional: true` instead of failing. Running
Connect again shows the consent screen with them included.

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
| Tenant | `tenant` (migration 042) | tenant id | NULL | service principal object id, Graph permissions (granted, and usable, denied or license_required) |
| Subscription | `subscription` | subscription id | tenant id | display name, state, Reader assignment (status, assignment id, verified) |

## API

All routes are under `/authsec/discovery`, require authentication, and need
`discovery:read` or `discovery:admin`.

| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/azure/oauth/status` | read | Is the option configured |
| POST | `/azure/oauth/start` | admin | `{tenant?, login_hint?}` returns `{authorize_url, state}` |
| GET | `/azure/oauth/session?session_id=` | read | Preview tenant and subscriptions, with `can_assign_reader` |
| POST | `/azure/oauth/connect` | admin | `{session_id, subscription_ids?}`: the onboarding itself |
| GET | `/azure/connectors` | read | Tenant and subscription rows |
| GET | `/azure/connectors/:id` | read | One row |
| POST | `/azure/connectors/:id/verify` | admin | Re-prove with AuthSec's credentials |
| DELETE | `/azure/connectors/:id` | admin | Revoke. A tenant revokes its subscriptions too |

The callback is `GET /api/v1/auth/azure/callback`, unauthenticated, on the root
engine.

Revoking stops AuthSec using the connection. It does not change anything in
Azure, because AuthSec holds no right to delete its own assignments. The
customer removes access by deleting the AuthSec enterprise application, which
removes its role assignments with it.

## Testing locally

1. Set the three required `AZURE_*` variables and `REDIS_URL`, then start the backend. Migration 042 applies at boot.
2. `GET /authsec/discovery/azure/oauth/status` should return `available: true`.
3. Call `POST /authsec/discovery/azure/oauth/start` with a workspace admin JWT, and open `authorize_url` in a browser.
4. Consent as a Global Administrator of a test tenant, then sign in with the same account.
5. Copy `session_id` from the final redirect URL.
6. Call `GET /authsec/discovery/azure/oauth/session?session_id=…` to preview.
7. Call `POST /authsec/discovery/azure/oauth/connect` with `{"session_id":"…"}`.
8. In Azure: Subscription → Access control (IAM) → Role assignments shows the AuthSec app as Reader. Running Connect again creates nothing new.
9. For a subscription in `rbac_propagating`, call `POST /authsec/discovery/azure/connectors/:id/verify` after a few minutes.

## Limitations

- Public cloud only. Azure Government and 21Vianet use other hosts.
