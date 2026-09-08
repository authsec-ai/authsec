# Azure onboarding — consent, and whether consent bought anything

How AuthSec connects to a customer's Entra tenants, what a human has to do that
AuthSec cannot, and what is stored.

This is onboarding only. No identity scan, no permission extraction, no access
graph, no governance. Those are later tickets and none of them can start until a
tenant reaches `arm_reader_ok: true`.

Related: `docs/flows/aws-cloud-discovery-onboarding.md`, whose layering this
follows.

---

## The one fact everything follows from

**Consent is not access.** In Azure they are two grants, made by two different
people, at two different times:

- **Admin consent** is a directory action. It creates a service principal for the
  AuthSec application in the customer's tenant and grants the Graph application
  permissions the app registration asks for.
- **A role assignment** is a resource action. It is what lets that service
  principal read anything in Azure Resource Manager.

An application can be fully consented in a directory and still read nothing at
all. Every design decision below exists to keep those two states distinguishable,
which is why `arm_reader_ok` is a separate column that consent never sets, rather
than something implied by `consented_at`.

---

## The flow

```
  operator's browser        AuthSec                Microsoft / customer tenant
        │                      │                              │
        │  GET /api/azure/login│                              │
        ├─────────────────────▶│  mint one-shot state         │
        │◀──── 302 ────────────┤                              │
        │                                                     │
        │────── sign in with an Azure WORK account ──────────▶│
        │◀───── 302 back to /api/azure/callback?code=... ─────┤
        │                      │                              │
        │                      │  exchange code ─────────────▶│
        │                      │◀──── delegated ARM token ────┤
        │  Set-Cookie session  │  token → Vault               │
        │◀─────────────────────┤                              │
        │                      │                              │
        │  GET /api/azure/tenants                             │
        ├─────────────────────▶│  ARM GET /tenants ──────────▶│
        │◀──── tenant list ────┤◀─────────────────────────────┤
        │                      │                              │
        │  POST /api/azure/consent {tenantId}                 │
        ├─────────────────────▶│  mint consent state          │
        │◀──── 302 ────────────┤                              │
        │                                                     │
        │──── a TENANT ADMIN accepts the consent page ───────▶│
        │◀── 302 /callback?admin_consent=True&tenant=... ─────┤
        │                      │  upsert azure_connectors     │
        │◀──── {ok, tenant} ───┤                              │
        │                      │                              │
        │        ── somebody assigns Reader in the portal ──  │
        │                      │                              │
        │  POST /api/azure/validate-arm {tenantId}            │
        ├─────────────────────▶│  client credentials ────────▶│
        │                      │  ARM GET /subscriptions ────▶│
        │◀─ arm_reader_ok ─────┤◀─────────────────────────────┤
```

Three properties fall out of this shape and are worth stating:

- **The operator's own access is the boundary on what they can see.** The tenant
  list is ARM's `/tenants`, which returns exactly the tenants the signed-in
  account can see — the same set the portal shows under *Manage tenants*. It is
  not a directory enumeration and cannot become one.
- **AuthSec never grants consent.** It redirects a human to Microsoft's own
  consent page. Only an administrator of that directory can accept it.
- **Nothing is recorded until Microsoft says so.** A refused consent leaves no
  row. `admin_consent=True` is the only value that writes one.

---

## What the customer does, and what AuthSec does

| Step | Who | Where |
|---|---|---|
| Create the app registration, multi-tenant | AuthSec, once | AuthSec home tenant |
| Sign in with an Azure work account | operator | browser |
| Choose tenants | operator | console |
| Accept the consent page | **an admin of the customer tenant** | Microsoft |
| Assign Reader to the AuthSec app | AuthSec, as the operator | `POST /api/azure/assign-reader` |
| Verify consent granted anything | AuthSec | `POST /api/azure/validate-graph` |
| Verify Reader actually works | AuthSec | `POST /api/azure/validate-arm` |

**Accepting the consent page is the one step nothing here can perform.** It is a
human with authority in that directory authorising a foreign identity, which is
the entire security model; there is no ordering of API calls that removes it.

The Reader assignment is a different case and often confused with it. No
application can grant itself an Azure role — that has no API by design — but a
human who holds Owner or User Access Administrator can, and AuthSec sends
exactly the request that person would have sent. It succeeds precisely when they
could have done it by hand, and refuses cleanly when they could not.

---

## Permissions

### Graph application permissions

Configured on the app registration, granted by admin consent. Requested as
`https://graph.microsoft.com/.default`, which means "whatever this app is
registered to need" — the permission set is decided and reviewed in the portal
and cannot be widened from a query string.

| Permission | For |
|---|---|
| `Application.Read.All` | Reading applications and service principals in a later discovery ticket |
| `Directory.Read.All` | Directory objects those principals resolve against |
| `RoleManagement.Read.Directory` | Which principals hold which directory roles |
| `AuditLog.Read.All` | Sign-in activity, for liveness in a later ticket |

They are consented up front because consent is a human step, and asking an
administrator to repeat it per ticket is how onboarding stalls. Onboarding itself
uses them for two read-only checks only: `validate-graph` reads the `roles` claim
of an app-only token to prove consent granted something, and `app/check` reads
AuthSec's own application object. Everything else waits for discovery.

`AuditLog.Read.All` is consented but gated: `/auditLogs/signIns` needs Entra ID
P1 or P2, so on a free tier the permission is granted and the endpoint still
403s. `validate-graph` reports that as a licence gate rather than a failure.

### Delegated

`https://management.azure.com/user_impersonation` plus `offline_access`. This is
what lists tenants as the operator. `offline_access` is what makes a refresh
token appear, so a sign-in survives the hour an ARM access token lasts without
sending the operator back through a browser.

### Azure RBAC

The built-in **Reader** role, assigned to the AuthSec service principal at
subscription or root-management-group scope. Nothing narrower is requested and
nothing wider is accepted.

One exception, opt-in and temporary: `tenantWide` can raise the **operator's
own** account to User Access Administrator at root scope for the duration of a
single assignment, and always gives it back. That is a grant to a human who was
already a Global Administrator, never to the AuthSec application. See step 4.

### Never called

`GET /servicePrincipals` is never called. The service principal object id comes
from the `oid` claim of an app-only token instead, which is the same value
without a directory read.

`GET /applications` is called exactly once, for AuthSec's **own** application
object (`app/check`). The promise this flow keeps is not "never touch that
endpoint" but "never enumerate a customer's directory objects with it".

Nothing here ever writes to Microsoft Graph. No `POST /applications`, no
`POST /servicePrincipals`, no `appRoleAssignedTo`. Consent is the customer's to
give on Microsoft's own screen, and a flow that could grant itself permissions
would not be able to say that.

---

## What AuthSec stores

| Thing | Where | Notes |
|---|---|---|
| Consented tenants | `azure_connectors` | tenant id, display name, domain, `consented_at`, ARM verdict |
| Pending redirects | `azure_oauth_state` | One-shot, expiring, deleted on redemption |
| The operator's delegated token | Vault, `kv/data/secret/workspaces/<ws>/cloud-discovery/azure/sessions/<id>` | The only secret. Never in a cookie, never in a response |
| The session handle | browser cookie `authsec_azure_session` | HttpOnly, `SameSite=Lax`, path-scoped to `/api/azure`, HMAC-signed |
| The client secret | `AZURE_CLIENT_SECRET` | Read by the backend only |

`arm_reader_ok` starts `false` and only becomes `true` when an ARM Reader check
actually passes. That makes completion a single condition:

> **Onboarding is complete for a tenant when the row exists AND `arm_reader_ok` is true.**

Consent alone never sets it. "Never checked" is not lost by starting at `false` --
`arm_checked_at IS NULL` says it, and `arm_last_error` says why a check failed.

---

## API

`/api/azure/*`. The path is not a style choice: `/api/azure/callback` is fixed by
the redirect URI registered on the Entra application, and Microsoft will not
redirect anywhere else.

| Method | Path | Auth | |
|---|---|---|---|
| `GET` | `/login` | none | 302 to Microsoft. Rate limited |
| `GET` | `/callback` | none | Both redirects land here |
| `GET` | `/tenants` | `discovery:read` + session cookie | Tenants the operator can see |
| `POST` | `/consent` | `discovery:admin` | 302 to the admin consent page |
| `POST` | `/validate-graph` | `discovery:admin` | Plane 1: what consent actually granted |
| `POST` | `/reader-setup` | `discovery:read` | az / PowerShell / ARM template / portal steps |
| `POST` | `/assign-reader` | `discovery:admin` + session cookie | Plane 2: AuthSec makes the assignment |
| `POST` | `/validate-arm` | `discovery:admin` | The Reader probe |
| `GET` | `/subscriptions` | `discovery:read` | Per-subscription coverage |
| `GET` | `/connectors` | `discovery:read` | Consented tenants |
| `GET` | `/config` | `discovery:read` | Is this deployment configured at all |
| `GET` | `/app/check` | `discovery:read` | Drift check on our own app registration |

**`/login` and `/callback` are unauthenticated because they cannot be anything
else.** Both are top-level browser navigations; a redirect arriving from
Microsoft carries no bearer token, so `AuthMiddleware` would reject every
callback. They are authorised by the one-shot `azure_oauth_state` row instead,
which is also the only place the workspace and the consented tenant are read
from. The same reasoning already applies to the GitHub webhook route.

### Errors say whose problem it is

- `fault: customer_tenant` — consent refused, the app not consented there, or ARM
  refusing the read. Not an AuthSec outage.
- `fault: operator` — the sign-in expired, or a callback was replayed.
- `fault: azure` — Microsoft refused or throttled.
- `fault: authsec` — the deployment is misconfigured. Must not be shown to a
  customer as their mistake.

---

## Running it

Azure onboarding rides the normal backend. No separate process.

```bash
cp .env.example .env          # fill AZURE_*, SESSION_SECRET, VAULT_*
go build ./... && go run .    # migrations run at startup
```

Required environment: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
`AZURE_REDIRECT_URI`, `SESSION_SECRET`, plus `VAULT_ADDR` / `VAULT_TOKEN`, which
is where the operator's token goes. Missing Azure values make these routes report
themselves not configured rather than failing halfway through a redirect.

### 1. Sign in

Open in a **browser** — this is a redirect chain, not an API call.

```
http://localhost:8080/api/azure/login
```

On a deployment with more than one workspace, name it:

```
http://localhost:8080/api/azure/login?workspace_id=<uuid>
```

Ends at `{"ok":true,"step":"logged_in"}` with the session cookie set.

### 2. List tenants

```bash
curl -s http://localhost:8080/api/azure/tenants \
  -H "Authorization: Bearer $AUTHSEC_TOKEN" \
  -b cookies.txt
```

```json
[
  { "tenantId": "f448fd31-c240-4c96-8013-acded88b5df6",
    "displayName": "Contoso",
    "domains": ["contoso.onmicrosoft.com"],
    "alreadyConnected": false }
]
```

### 3. Consent one tenant

```bash
curl -i -X POST http://localhost:8080/api/azure/consent \
  -H "Authorization: Bearer $AUTHSEC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"f448fd31-c240-4c96-8013-acded88b5df6"}'
```

Answers `302` with a `Location` header. Open that URL in a browser as an
administrator **of the tenant being consented**. It returns to `/callback` and
answers:

```json
{ "ok": true, "step": "consented", "tenant": "f448fd31-..." }
```

### 4. Assign Reader

AuthSec makes the assignment itself, as the signed-in operator. The application
cannot grant itself an Azure role — nothing can — but it can send exactly the
request the operator would have sent by hand.

```bash
curl -s -X POST http://localhost:8080/api/azure/assign-reader \
  -H "Authorization: Bearer $AUTHSEC_TOKEN" \
  -H 'Content-Type: application/json' -b cookies.txt \
  -d '{"tenantId":"f448fd31-c240-4c96-8013-acded88b5df6"}'
```

Default: one assignment per subscription the operator can currently see.
Needs **Owner** or **User Access Administrator** on each.

#### `"tenantWide": true` — one grant, every subscription

```bash
  -d '{"tenantId":"f448fd31-...","tenantWide":true}'
```

One assignment at the tenant **root management group**, which covers
subscriptions created *after* today rather than a snapshot of the ones that
exist now. Mutually exclusive with `scope`.

That scope needs User Access Administrator at the root, which nobody holds by
default — Entra roles and Azure RBAC are separate systems, so administering a
directory grants nothing over its resources. Microsoft's answer is
`elevateAccess`: a Global Administrator may assign themselves that role at root
scope. It is the API behind *Microsoft Entra ID → Properties → Access
management for Azure resources*, and AuthSec calls it with the delegated token
it already holds.

Because that is the widest role in Azure RBAC, the order is fixed
([`internal/azureonboard/elevate.go`](../../internal/azureonboard/elevate.go)):

1. **Try first without elevating.** An operator who already holds the privilege
   is never elevated.
2. **On refusal, look for an existing root elevation.** If one is there it
   reflects somebody's earlier decision; removing it later would revoke standing
   access AuthSec never granted, so the call reports failure instead of touching
   it.
3. **Otherwise elevate, retry, and give it back** — on a context of its own, so
   a cancelled request cannot strand it. Root User Access Administrator does not
   expire on its own.

Every part of that is reported back and written to the audit log:

```json
{ "ok": true,
  "data": { "tenant_wide": true, "all_ok": true,
            "elevation": { "attempted": true, "elevated": true, "removed": true } } }
```

`"elevated": true` with `"removed": false` is the one state that needs a human:
the error names the manual fix. Microsoft records it independently too — Entra
audit logs under *Azure RBAC (Elevated Access)*, the Azure activity log under
`Microsoft.Authorization/elevateAccess/action`, and a standing portal banner
naming everyone currently elevated.

#### Portal fallback

When the operator holds neither privilege, the response carries `fallback` with
the az CLI, PowerShell, ARM template and this click path — nothing is
half-done:

1. Azure portal → **Subscriptions** → pick the subscription, or
   **Management groups** → the root group to cover all of them.
2. **Access control (IAM)** → **Add** → **Add role assignment**.
3. Role: **Reader** (built-in).
4. *Assign access to*: **User, group, or service principal**.
5. **Select members** → search `Authsec`.
   If nothing is found, admin consent has not completed in this tenant — the
   service principal does not exist yet. Redo step 3.
6. **Review + assign**.

### 5. Verify Reader

```bash
curl -s -X POST http://localhost:8080/api/azure/validate-arm \
  -H "Authorization: Bearer $AUTHSEC_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"f448fd31-c240-4c96-8013-acded88b5df6"}'
```

```json
{ "ok": true,
  "data": { "tenantId": "f448fd31-...", "arm_reader_ok": true,
            "subscription_count": 2,
            "subscriptions": [ { "subscriptionId": "...", "displayName": "Production", "state": "Enabled" } ] } }
```

### 6. List what is onboarded

```bash
curl -s http://localhost:8080/api/azure/connectors \
  -H "Authorization: Bearer $AUTHSEC_TOKEN"
```

---

## Reading the ARM verdict

| Response | Means |
|---|---|
| `arm_reader_ok: true`, `subscription_count > 0` | Working. |
| `arm_reader_ok: true`, `subscription_count: 0`, `warning` set | **Read the warning.** ARM accepted the app-only token but returned nothing, which almost always means Reader was never assigned. See below. |
| `arm_reader_ok: false`, `arm_checked_at` null | Consented, but the Reader check has never been run yet. |
| `arm_reader_ok: false`, error mentions `AADSTS700016` | The application has no service principal in that tenant. Consent never completed. |
| `arm_reader_ok: false`, 401/403 from ARM | ARM refused outright. |

**The empty-list case is unresolved by design.** ARM answers `200` with `"value": []`
when the token is valid but the application holds no role assignment anywhere, so
a tenant with no Reader assigned currently passes this check and gets a warning
rather than a failure. The literal specification said any `200` is a pass; the
honest reading is that an empty list means Reader is missing. The count and the
warning make the case visible without changing the verdict. The decision is
recorded in `services/azure_onboarding.go` at `ValidateARM`, and flipping it is a
one-line change.

---

## Layering

Same as AWS, for the same reasons.

```
internal/azureonboard/     provider logic. no DB, no gin, no workspace concept
  oauth.go                 URLs, one-shot state, tenant id validation, errors
  client.go                Microsoft + ARM over an interface, so a fake can drive it
        ↓
services/azure_onboarding.go       orchestration, Vault, DB writes
        ↓
repository/azure_connector_repository.go   workspace-scoped GORM access
        ↓
controllers/platform/azure_onboard_controller.go   gin, cookies, HTTP mapping
        ↓
routes/routes.go                   registration
migrations/master/015_azure_connectors.sql
```

---

## Deliberate deviations from the original specification

| Spec said | Built as | Why |
|---|---|---|
| SQLite | Postgres, migration `015` | This is the monolith. There is one database and migrations run at startup. |
| `tenant_id` unique | `UNIQUE (workspace_id, tenant_id)` | Every data operation here is workspace-scoped. Two workspaces onboarding the same tenant must not collide or see each other. |
| `state=login`, `state=consent:{id}` | `login:<nonce>`, `consent:{id}:<nonce>` + a one-shot row | A constant state cannot be validated — anyone can send it. The prefix is kept; a 256-bit nonce and the state row carry the actual security. |
| token in a server session map | token in Vault, handle in a signed cookie | A process map loses every sign-in on restart and does not exist on the second replica. |
| all six routes open | two open, four authenticated + RBAC | Only the two browser redirects *cannot* be authenticated. Leaving the other four open would be a hole, not a simplification. |

---

## Still open

1. **Never run against a live tenant.** Nothing here has touched real Azure. The
   flow is built to the documented shapes of the Microsoft identity platform and
   ARM; one real sign-in and one real consent closes this.
2. **The empty-subscription verdict**, above.
3. **No tests.** `AGENTS.md` says not to add them unless asked. The interfaces are
   in place — `azureonboard.Client` is the seam, and
   `AzureOnboardService.WithClient` is how a fake gets in.
4. **Nothing promotes a tenant to `cloud_connector`.** A tenant with
   `arm_reader_ok: true` is ready to be scanned and there is nothing yet to scan
   it. That is the next ticket, and it is where this table and the shared
   cross-cloud schema meet.
