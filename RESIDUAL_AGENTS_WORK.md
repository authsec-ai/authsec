# Residual Work — `clients` table removal (Phase B fallout)

**Created:** 2026-05-29 · **Owner:** TBD · **Status:** open

## Why this exists

Phase B of the tenant→workspace / OAuth-2.1 cleanup **dropped the legacy
`public.clients` table** (the v3 concept that conflated "MCP server" with "OAuth
client"). The non-agent, low-risk consumers were migrated or stubbed cleanly.
But the **AI-agent, delegation, and legacy client-management** flows depend on
`clients` in non-mechanical ways (agent-specific columns, different status
vocabulary, no creation path). Per explicit decision, we **let those break now
and track the fix-forward here** rather than block Phase B on a risky migration.

The Go code still **compiles** (`models.Client` / `sharedmodels.Client` kept as
inert structs). The breakage is **runtime only**: any query against `clients`
now hits `relation "clients" does not exist` → HTTP 500 (or a clean error where
stubbed).

## Architecture target (how to fix, in one line)

- **AI agent** = a `resource_servers` row with `application_type='ai_agent'`
  (the table already has the CHECK value + a `legacy_client_id` column). It will
  need new columns `agent_type` and `spiffe_id`, plus a decision on agent status
  (the existing `status` CHECK only allows `pending_scan/ready/degraded`; agents
  use `Active`/`revoked` — either add an `agent_status` column or model liveness
  via the existing `active` boolean).
- **OAuth client** = `mcp_oauth_clients` (global). Workspace for a client comes
  from `resource_server_client_registrations.workspace_id` or the authenticated
  JWT — never a `client_id → workspace` table lookup.

---

## Known-broken surfaces (runtime 500 unless noted)

### 1. AI Agent management — HARD BREAK
Routes: `GET/POST /uflow/admin/agents*` (admin + platform controllers).
- `controllers/admin/agent_controller.go` — `Table("clients")` at lines 77, 114, 154, 198, 241, 256, 305
- `controllers/platform/agent_controller.go` — `Table("clients")` at lines 81, 118, 157, 213, 260, 275, 324

Reads/provisions agents (`client_type='ai_agent'`) and writes `spiffe_id` back.
**Fix:** repoint to the agent's new home (resource_servers w/ `application_type='ai_agent'`).
Map columns: `client_id`→`id`, `client_type='ai_agent'`→`application_type='ai_agent'`,
`agent_type`→new column, `spiffe_id`→new column, `status`/`deleted`→reconcile with
`active`/`deleted_at`. **Also: there is no agent-creation path in the code today**
(the old client-registration controller was already deleted) — add a `CreateAgent`
handler when building the new home, or confirm agents are seeded out of band.

### 2. AI Agent delegation — HARD BREAK
- `controllers/admin/delegation_helpers.go:129` and `controllers/platform/delegation_helpers.go:131`
  — `validateClientActive`: `SELECT id FROM clients WHERE client_id=? AND status='Active'`
- `controllers/admin/delegation_policy_controller.go` — `Table("clients")` at 166, 218
- `controllers/platform/delegation_policy_controller.go` — `Table("clients")` at 153, 205

**Fix:** resolve the agent/client from `resource_servers` (its new home) instead of
`clients`; replace the `status='Active'` predicate with the agent-liveness field chosen above.

### 3. SDK delegation-token issuance — GRACEFUL ERROR (not 500)
- `controllers/admin/sdk_token_controller.go:141` and `controllers/platform/sdk_token_controller.go:140`
  — `resolveTenantIDFromClientID`: `SELECT workspace_id FROM clients WHERE client_id=$1`

Returns a normal error → token request fails with "client_id not found in clients".
**Fix:** resolve workspace via `mcp_oauth_clients` joined to
`resource_server_client_registrations.workspace_id`, or from the authenticated JWT context.

### 4. OIDC-federated signup — HARD BREAK
- `controllers/platform/oidc_controller.go:1131` and `:1474` — `INSERT INTO clients (...)`

Federated (external IdP) signup tries to create a `clients` row.
**Fix:** register an `mcp_oauth_clients` row (the federated app is an OAuth client),
not a `clients` row.

### 5. Legacy Hydra consent/login client lookup — HARD BREAK
- `internal/hydra/models/service.go:198` — `db.Table("clients").Where("client_id=? and workspace_id=?")`

Part of the legacy `-main-client` / tenant-scoped Hydra path.
**Fix:** superseded by **Phase C** (retire per-tenant Hydra client). Resolve via
`mcp_oauth_clients`. Likely deleted wholesale in Phase C.

### 6. Legacy end-user client-management endpoints — HARD BREAK
Routes: `POST /uflow/user/clients/register`, `GET /uflow/user/clients`, `POST /uflow/user/clients/get`.
- `controllers/enduser/enduser_controller.go` — `RegisterClient`, `GetClients`, `GetClientsPost`,
  `GetClientsByTenantID` (last one unrouted) use `models.Client` GORM against `clients`.

**Fix:** these manage the legacy "client" concept. Repoint to `resource_servers`
(list/register applications) or remove the endpoints + corresponding UI.

### 7. Legacy `tenantMapping` — STUBBED (clean 400, no 500)
- `services/voice_auth_service.go` `tenantMapping` — now returns a clean error.
- `controllers/enduser/enduser_auth_controller.go` `tenantMapping` — now returns a clean error.
  Affects legacy `/uflow/auth/enduser/*` SDK routes (initiate-registration, login, etc.).

**Fix:** rework voice auth + the legacy enduser SDK auth routes to resolve workspace
from host / JWT / RFC 8707 resource (see `controllers/shared/workspace_resolver.go`).

### 8. Dead code — safe to delete in a cleanup pass
- `internal/clients/library/client_library.go` — `NewClientLibrary` never called. Dead.
- `internal/clients/authmethods/service.go` `MethodsForClients` — never called. Dead.
- `models/aliases.go` `Client = sharedmodels.Client`, `internal/hydra/models/models.go`,
  and `sharedmodels.Client` itself — **kept inert** so the above compiles. Remove once
  surfaces 1–7 are migrated off `clients`.

---

## Suggested fix order

1. Decide the agent home (extend `resource_servers` vs. dedicated `agents` table) and
   land the schema (+ `CreateAgent`).
2. Migrate agent_controller ×2 + delegation (helpers + policy controllers) to it.
3. Repoint sdk_token resolvers + OIDC-federated signup to `mcp_oauth_clients`.
4. Repoint/remove enduser client-management endpoints.
5. Rework voice + legacy enduser SDK auth workspace resolution.
6. Delete dead `clients` Go code (`client_library.go`, `MethodsForClients`,
   `models.Client`/`sharedmodels.Client`/alias) and confirm
   `grep -rn 'clients' --include='*.go'` is clean.
