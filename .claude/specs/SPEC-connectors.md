# SPEC: Connectors / External Services — Identity-Aware Outbound Action Broker

> **Product-boundary note:** These are AuthSec **Action Connectors**. They execute
> typed outbound provider actions and are not the Discovery Integrations or
> Remediation Integrations used by
> [Agent Identity Governance](SPEC-agentic-access-management.md). GitHub or Slack
> support here does not provide GitHub/Slack estate discovery, identity
> aggregation, entitlement ingestion, access certification, or IGA remediation.
> Agentic IGA must not depend on this connector framework.

> **What this is:** AuthSec is an **outbound action broker** for AI agents. A caller
> (agent, workload, MCP server) authenticates to AuthSec, names a connector + a **typed
> action** ("Slack.postMessage", "GA4.runReport"), and AuthSec — after authorizing the
> call against `Principal + Actor` + assignments — **injects the credential server-side,
> performs the allowlisted provider request, and returns only the provider result.** The
> caller never receives the credential.
>
> **Design rules (non-negotiable):**
> 1. No endpoint or SDK returns a usable provider credential to an agent. Action-level
>    execution + audit is the product. (Break-glass admin reveal is explicitly OUT of
>    scope — decision recorded below.)
> 2. The runtime plane authorizes on `Principal{type,id,workspace} + Actor{client_id,
>    spiffe_id?}` and **resource-bound** native tokens — never on token provenance (`tf`)
>    and never on a single auth method. SPIFFE is one actor lane.
> 3. The broker is a per-workspace **Resource Server**; every runtime token must be
>    audience-bound to it (RFC 8707).
>
> **Spec status (2026-07-06): SHIPPED AND PROVEN END-TO-END.** A real LangChain agent
> (`marco/github-commits-agent`) holding only an AuthSec client credential executed
> `github.listCommits` through the broker against a live repo; the GitHub token never
> left AuthSec; the action landed in `audit_events` attributed to the agent identity.
> Done since the 07-03 revision: console UI (list + wizard + drawer) live; GitHub
> `listCommits` action; GORM oauth-column fix; Caddy `/broker/*` route; Vault kv/
> self-healing reconciler; new-workspace RBAC provisioning fix + backfill.
> Still open: R0 schema hardening, refresh lock, idempotency/rate limits, R3 refresh
> worker + notifications, R4 user consent, R5 SDK/docs.
> **The forward plan now lives in the Agent Identity PRD** (report + PRD artifact,
> 2026-07-06): I-1 identity plumbing (last_seen, one-transaction grant, agent activity
> API) → I-2 Agent 360 page → I-3 governance → I-4 delegation (=R4). Key finding
> driving it: agent enablement today requires 4 authorizations across 4 tables, two
> with no UI (broker-RS registration, connector-executor role binding), and the
> Agents page mints credentials that authenticate nowhere.

## Summary

A **Connector** is a workspace-scoped instance of a third-party **Provider**. It owns
non-secret **config** (Postgres), one or more **Connections** (credential bindings —
workspace- or user-scoped — secrets in Vault), and its provider's typed **Actions** (the
only invocable units). Admins manage connectors, credentials, and **assignments** on the
control plane (`/authsec/connectors/*`); agents execute actions on the data plane
(`/broker/connectors/*`) with a token audience-bound to the workspace's Connector Broker
RS (`authsec://broker/connectors/{workspace_id}`). AuthSec resolves the connection,
refreshes if needed, injects the credential into a **typed provider adapter**, calls the
SaaS API, and returns the result with an allow/deny action-audit record.

Position: **identity-aware action broker — not iPaaS, not a token vault.** Moat: the
`Principal + Actor` authorization context for every caller topology plus standards-based
on-behalf-of delegation (RFC 8693 + ID-JAG/XAA — the primitives behind Okta
Cross-App-Access and MCP Enterprise-Managed Auth), applied to outbound SaaS actions with
per-action least privilege and action-outcome audit that a token vault cannot produce.

## The problem

Agents need to *act* in real apps. Teams do it three bad ways: paste API keys into agent
context (leaks, unrotatable), share one god-mode service account (no attribution, no
blast-radius control), or hardcode OAuth tokens (2am expiry breakage). **Giving agents
the ability to act in external apps is insecure, over-privileged, unauditable, and
operationally painful — and compounds with every new agent and tool.**

**One-liner:** *"Agents ask AuthSec to do things in your apps — they never see the keys,
and every action is authorized and audited."*

## Use cases

| Persona | Job | AuthSec's role |
|---|---|---|
| Ops agent | "Post the deploy summary to #releases" | `Slack.postMessage` via workspace Connection; audit: this agent ran this action |
| Analytics agent | "Last week's signup conversion?" | `GA4.runReport`; admin connected Google once (OAuth); agent sees rows, never tokens |
| Support agent (per-customer) | Act as a *specific user* | User-scoped Connection via XAA (`sub`); revoke consent → fail closed |
| MCP client | Discover/call connected apps as tools | `/broker/mcp/tools` + `/broker/mcp/call` — same policy chain, typed schemas |

## Caller identity model

Authorize on `Principal + Actor` (`internal/tokens/principal.go`) via the shared
protected-resource verifier — never on `tf` (provenance, audit-only) and never on one
auth method.

| Caller topology | Flow | `tf` | Subject | Actor |
|---|---|---|---|---|
| Standalone agent | M2M `client_credentials` (resource=broker) | `m2m` | service_account | `client_id` |
| Attested workload | SPIFFE-SVID → `/oauth/token` → M2M | `m2m` | service_account | + `spiffe_id` |
| Agent on behalf of user | XAA/ID-JAG → `jwt-bearer` (resource=broker) | `xaa` | user | `client_id` (+`spiffe_id?`) |
| Human-approved async | CIBA | `ciba` | user | `client_id` |
| MCP client | DCR + authz_code / token-exchange | varies | user/SA | `client_id` |

A raw SVID authenticates at `/oauth/token` (preserving registration/revocation
invariants); the broker only consumes the resulting AuthSec access token.

## Current state — BUILT (verified in code, 2026-07-03)

### Runtime data plane (`controllers/platform/connector_broker_controller.go`)
- `authenticate()` (:73): native-token-only verifier — rejects HMAC/Hydra-opaque, loads
  RS by unverified `aud`, requires `managed=true` + type `connector_broker`, then runs the
  **same `VerifyProtectedResourceToken()`** as native introspection (signature + DB +
  revocation + audience + registration gate + live RBAC) → `AuthContext`. Confused-deputy
  guard in place.
- `GET /broker/connectors` (:120) — enabled + agent_accessible + assigned-to-caller only.
- `GET /broker/connectors/:id/actions` (:152) — typed action catalog.
- `POST /broker/connectors/:id/actions/:key:execute` → `runAction()` (:232) policy chain:
  `connector:execute` scope → enabled + agent_accessible (fail closed) → assignment
  (client × connector × action) → typed action + adapter resolve → connection select
  (user-scope when XAA `sub` present, else workspace) → Vault credential resolve
  (`ResolveActionCredential`, fail closed, secret never returned) → on-demand OAuth
  refresh near expiry → server-side adapter execution → **allow/deny audit**
  (`connector.action.allow|deny` w/ Principal, Actor, client_id, reason).
- MCP surface: `GET /broker/mcp/tools`, `POST /broker/mcp/call` — same `runAction()` chain.

### Control plane (`controllers/platform/connector_controller.go`)
- CRUD + audit events (`connector.create|update|delete|connect_start|assign|unassign`).
- `POST /:id/connections/oauth/start` (:303) + `GET /connector-oauth/callback` (:337) —
  state + PKCE S256, 10-min one-shot `connector_oauth_states` row, Google offline-consent
  handling, token stored in Vault, workspace-scope Connection upserted w/ lifecycle.
- Assignments CRUD (:360–428).
- `GET /:id/config` (:433) — **admin control plane only**, 404 when `enabled=false`,
  returns only `connector_id,name,provider_key,enabled,config,subscriptions`.
- **No `/credentials` endpoint exists anywhere.** `VaultPath` is `json:"-"` on both
  `Connector` and `ConnectorConnection` — never serialized.

### Services
- `connector_service.go`: CRUD; `ResolveActionCredential()` (:302) broker-side resolver.
  ⚠️ `Update()` (:214) still **clobbers** the Vault blob on secret update.
- `connector_oauth_service.go`: `Start()`/`HandleCallback()`/`Refresh()` (on-demand only).
- `connector_broker_service.go`: `EnsureBrokerResourceServer()` — idempotent per-workspace
  managed RS at `authsec://broker/connectors/{ws}`; wires `connector:execute` scope →
  global permission.
- Adapters (`internal/connectoradapters/`): **Slack, GitHub**. No Google adapter yet.

### Schema (`001_bootstrap.sql`)
- `connector_providers` (:3038): + `supported_auth_methods[]`, `oauth_authorize_url`,
  `oauth_token_url`, `oauth_scopes_supported[]`, `oauth_default_scopes[]`.
- `connectors` (:3062): `UNIQUE(workspace_id,name)` + **`UNIQUE(workspace_id,id)`** (:3084)
  → composite workspace FKs available and used by assignments.
- `connector_connections` (:3095): scope workspace|user, auth_type, vault_path, lifecycle
  (status/expiry/refresh flags/last_refresh_error). ⚠️ Gaps listed below.
- `connector_assignments` (:3123): composite workspace FK; **correct partial unique
  indexes** (NULL action_key = all-actions grant). ⚠️ `client_id` is bare text.
- `connector_actions` (:3149): **keyed by `provider_key`** (catalog-level — adopted; better
  than the earlier per-connector design), adapter_key, fixed http_method, I/O schemas,
  required_scopes.
- `connector_oauth_states` (:3172): PKCE verifier `json:"-"`, 10-min TTL.
- RBAC seed: `connector:{create,read,update,delete,config,assign,execute}` (:3237).
- `mcp_tools.resource_server_id NOT NULL` (:560) — broker RS satisfies it for P-MCP.

### Corrections to earlier review claims (for the record)
- `AuthMiddleware` audience is **configurable** (`ExpectedAudience`, default `authsec-api`),
  not hardcoded; HMAC-only claim was true — hence the separate broker verifier.
- `vault_path` serialization, disabled-connector leak, and agent `/credentials` — all
  already fixed/nonexistent in code.
- **Deployment check:** production runs on K3s. After a connector backend rollout,
  confirm the protected replacement routes are present and the retired
  `/credentials` surface is absent before deploying the matching UI.

## Remaining work (the actual forward plan)

### R0 — Hardening (before any new features; mostly one schema pass + service fixes)
1. **`connector_connections` schema** (single-state rule: edit CREATE inline, wipe +
   re-bootstrap; no ALTER):
   - add `workspace_id uuid NOT NULL` + composite FK `(workspace_id, connector_id) →
     connectors(workspace_id, id)` (workspace-scoping rule)
   - `subject_user_id` → `uuid`; rename `scope` → `binding_type` (avoid OAuth-scope
     collision); CHECK constraints (binding/subject nullability, status, auth_method)
   - replace plain UNIQUE with **partial unique indexes** (`WHERE binding_type='workspace'`
     / `='user'`) — plain UNIQUE lets NULLs duplicate the workspace binding
   - add `external_account_id/label`, `token_type`, `refresh_expires_at`, `revoked_at`,
     `last_used_at`, `version int NOT NULL DEFAULT 1`
2. **Vault secret update = safe patch** (read-modify-write or per-key subpaths), not clobber
   (`connector_service.go:214`).
3. **Vault tenancy:** per-workspace path prefix policies (or per-tenant AppRole) — a single
   broad `VAULT_TOKEN` defeats tenant isolation. Document the `vault-prod` policy and
   Kubernetes service identity in the production K3s deployment spec.
4. **`connector_assignments.client_id`** → FK to `mcp_oauth_clients.client_id` (or validate
   existence on grant + cleanup on client delete; document choice).
5. **Refresh protocol (specified, not asserted):** advisory lock keyed on
   `hash(connection_id)`; single refresher, waiters block briefly then re-read; CAS
   `UPDATE ... SET version=version+1 WHERE id=$ AND version=$prev`, on conflict re-read +
   retry once; provider-401 during refresh → `status='error'`.
6. **Deploy backend to production K3s** and verify the legacy `/credentials` build
   is no longer reachable before rolling out the UI.

### R1 — Execution semantics (completes the vertical slice)
7. **Idempotency:** `Idempotency-Key` header required for mutating actions; dedup record
   keyed `(client_id, connector_id, action_key, key)` with a TTL window; replay returns the
   stored outcome.
8. **Provider-error mapping table** in the adapter framework: provider 401/403 →
   Connection `status` transition (`expired`/`error`) + 424 to caller; provider 429 →
   backoff + `Retry-After` propagation; timeouts → 504; all → audit outcome.
9. **Egress + output controls:** adapter-fixed base URL/method (exists) + explicit egress
   allowlist, redirect restriction, timeout, response-size cap, credential/header
   redaction on results and logs.
10. **Broker rate limits:** per-(client, connector) token bucket + per-connection
    concurrency cap (generic IP middleware is not enough; shared provider credential =
    shared-fate blast radius).
11. **Pagination envelope:** standardize opaque `next_cursor` pass-through in
    `output_schema` for list/report actions.
12. **Provider decision:** Slack + GitHub adapters exist — bless them as the shipped
    vertical slice; **Google (GA4 Data API, OAuth)** is the next adapter (validates the
    OAuth-connection path end-to-end). *(Recommended; flip if GA4 demo matters more.)*

### R2 — Admin UI (greenfield; console-page + RTK Query standards)
13. Connectors list (`ConsolePage`, columns: Name · Provider · Status · Agent access ·
    Assignments · Connection health · Created) + sidebar entry.
14. Create wizard (provider → details w/ Enabled + Agent-accessible toggles → access:
    write-only API-key fields **or** "Connect via OAuth" → callback return page).
15. Detail drawer: config/subscriptions; **Connections** health (binding, external
    account, status, expiry, refresh state, last error, last used — no secrets, no reveal
    button, no vault_path); **Assignments** editor (client × action); **Actions** (read-only).
16. Duplicate-name 23505 → "A connector named '{name}' already exists."

### R3 — Lifecycle & operations
17. **Background refresh worker** (multi-instance-safe via the R0 lock protocol) so unused
    connections don't go stale; health states surfaced.
18. **Connection-health notifications:** emit events on refresh failure / revocation
    (audit-log event minimum; webhook/alert integration named as deferred). The pitch is
    "no 2am breakage" — that requires push, not polling.
19. **Scope re-consent:** action requiring a scope the Connection lacks → structured 403
    with a re-consent `authorize_url`, not an opaque failure.

### R4 — User-delegated connections (XAA runtime already routes; consent flow missing)
20. Authenticated **user provider-consent** flow → user-bound Connection
    (`binding_type='user'`, external account captured) + disconnect endpoint.
    (XAA authorizes agent→broker; it does NOT create the provider grant — this flow does.)
21. Fail-closed tests: disconnect/revoke → 424 on next execute; XAA `sub` resolves only
    that user's Connection.

### R5 — MCP registration & SDKs
22. Register actions as typed `mcp_tools` rows against the broker RS (satisfies
    `resource_server_id NOT NULL`); keep `/broker/mcp/*` dynamic surface in sync.
23. SDK: `executeAction(connectorId, actionKey, input, {idempotencyKey})`,
    `getConnectionStatus(connectorId)`, XAA-acquisition helper (token-exchange → ID-JAG →
    jwt-bearer, resource=broker). Parity stubs in the other two SDKs. **No
    `getConnectorCredentials()` ever.**
24. Docs (`authsec-doc`): concepts, action-broker model, topology→flow map, OAuth connect
    + user consent, threat model. Cross-link `docs/flows/xaa-idjag.md`.

## Decisions recorded

- **Break-glass credential reveal: OUT of scope, intentionally.** Rotation is
  reconnect/replace via the OAuth or API-key flows; no admin read path. Revisit only with
  an MFA-gated, audited design if operations demand it.
- **`/config` stays, admin control plane only** — non-secret contract
  (`connector_id,name,provider_key,enabled,config,subscriptions`), 404 when disabled,
  never reachable with a broker-audience token.
- **`connector_actions` keyed by `provider_key`** (catalog-level) — adopted from code.
- **One broker RS per workspace** (not per connector) — adopted; assignments provide
  fine-grained authz.
- **Provider API versioning** — deferred; add `api_version`/versioned base_url to the
  adapter model when the first provider forces it. Named so it isn't forgotten.

## Acceptance criteria (remaining work only)

**R0**
- [ ] Re-bootstrapped `connector_connections` has workspace_id + composite FK, uuid
      subject, `binding_type`, partial unique indexes (second workspace binding rejected),
      lifecycle columns incl. `version`
- [ ] Secret update patches one key without destroying others (Vault read-back proves it)
- [ ] Two concurrent executes on an expired token → exactly one provider refresh call
- [ ] Assignment grant for a nonexistent client_id is rejected
- [ ] Live deploy no longer serves `/credentials` (curl → 404)

**R1**
- [ ] Replayed `Idempotency-Key` on a mutating action returns the stored outcome, no
      second provider call
- [ ] Forced provider 401 → Connection `status='expired'` + 424 + deny-audit
- [ ] Response larger than cap → clean error, not truncation; secret never in logs/results
- [ ] Per-client rate limit returns 429 with Retry-After

**R2**
- [ ] Wizard creates an API-key connector and an OAuth (Slack) connector end-to-end;
      `npx tsc --noEmit` exits 0
- [ ] No UI surface displays secret material or vault_path

**R3**
- [ ] Refresh worker on two instances refreshes a connection exactly once (lock proven)
- [ ] Refresh failure emits a health event; UI shows `error` status without a manual probe

**R4**
- [ ] User consent creates a user-bound Connection with external account; XAA token
      executes against it; disconnect → 424 fail-closed

**R5**
- [ ] Actions appear as `mcp_tools` rows bound to the broker RS; SDK `executeAction`
      round-trips with idempotency key

## Related docs

| Doc | Why |
|---|---|
| `authsec/docs/primitives/token-engine.md` | broker is a consumer; preserve invariants |
| `authsec/docs/flows/xaa-idjag.md` | R4 runtime delegation (agent→broker); consent flow is separate |
| `authsec/docs/primitives/schema.md` | single-state schema procedure for R0 |
| `oauth_as_controller.go` / `VerifyProtectedResourceToken` | the shared verifier |
| `Authsec-ui/docs/console-standard.md`, `rtk-query.md` | R2 patterns |
| RFC 8707 / RFC 8693 / IETF ID-JAG draft | audience binding + delegation standards |
| Google OAuth web-server flow + GA4 Data API | next adapter (R1.12) |
