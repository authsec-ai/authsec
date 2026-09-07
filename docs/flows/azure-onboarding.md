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
| Assign Reader to the AuthSec app | **the customer** | Azure portal, per subscription or management group |
| Verify Reader actually works | AuthSec | `POST /api/azure/validate-arm` |

The Reader assignment is the one step nothing in this flow can perform. Azure has
no API by which an application grants itself a role, which is the point.

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
| `AuditLog.Read.All` | Sign-in activity, for liveness in a later ticket |

**None of these are used by this ticket.** Onboarding calls Graph exactly zero
times. They are consented now because consent is a human step and asking an
administrator to repeat it per ticket is how onboarding stalls.

### Delegated

`https://management.azure.com/user_impersonation` plus `offline_access`. This is
what lists tenants as the operator. `offline_access` is what makes a refresh
token appear, so a sign-in survives the hour an ARM access token lasts without
sending the operator back through a browser.

### Azure RBAC

The built-in **Reader** role, assigned by the customer to the AuthSec service
principal at subscription or management-group scope. Nothing narrower is
requested and nothing wider is accepted.

### Never called

`GET /applications` and `GET /servicePrincipals` are deliberately never called.
The application object is AuthSec's own and is managed in the portal; reading it
back would add a directory-shaped dependency to a flow whose entire claim is that
it only redirects a human and reads ARM.

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
| `POST` | `/validate-arm` | `discovery:admin` | The Reader probe |
| `GET` | `/connectors` | `discovery:read` | Consented tenants |

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

### 4. Assign Reader — portal checklist

Nothing below can be done by AuthSec.

1. Azure portal → **Subscriptions** → pick the subscription.
   To cover every subscription at once, use **Management groups** → the root
   group instead, and assign there.
2. **Access control (IAM)** → **Add** → **Add role assignment**.
3. Role: **Reader** (built-in).
4. *Assign access to*: **User, group, or service principal**.
5. **Select members** → search `Authsec`.
   If nothing is found, admin consent has not completed in this tenant — the
   service principal does not exist yet. Redo step 3.
6. **Review + assign**.
7. Repeat per subscription, unless you assigned at the root management group.

Assigning at the root management group requires the assigner to have elevated
access at that scope, which is itself a deliberate action in the portal
(*Microsoft Entra ID → Properties → Access management for Azure resources*).

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
