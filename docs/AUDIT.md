# AuthSec — Phase 0 Audit

**Date:** 2026-10-06 · **Scope:** backend `authsec` @ `e25d76f` (branch `authsec-staging`), frontend `Authsec-ui` @ `2f4a852` (branch `multitenacyV2`) · **Mode:** read-only, no code changes.

This document is the curated summary. Every issue has a row in [`ISSUES.md`](ISSUES.md) with evidence and a proposed fix. The detailed inventories (table by table, route by route, statement by statement) are under [`docs/audit/`](audit/). Those are verbatim agent working notes and are leads, not ground truth.

**Evidence levels used throughout:**
- **R**: reproduced at runtime against a scratch stack (Postgres 16 container, backend built from HEAD, no Hydra/Vault/Redis).
- **C**: verified by reading the code during this audit.
- **A**: reported, with file:line, by an audit agent and not individually re-verified. Where several independent agents reported the same thing, that is noted.

---

## 1. Executive summary

1. **Tenancy model: one shared database, with the tenant called a *workspace*.** The original design was database-per-tenant (`tenant_<uuid>` databases cloned from a template). That was removed in three steps:
   - `764a654` (2026-04-29): the multi-tenant logic moved out to a separate `mt-plugin` gRPC service.
   - `69c82a3` (2026-05-13): the "single-tenant substrate" was merged in.
   - `05e289d` (2026-06-23): the `tenant` model was deleted ("workspace fully replaces tenant").

   Today 143 of 175 tables carry `workspace_id`. Every authenticated request has a `workspace_id` claim in its JWT. So the shared-DB shape is mostly already there; what is missing is enforcement.
2. **Isolation is enforced by hand, inconsistently, with no safety net.**
   - There is no scoped data layer, no Row-Level Security, no `TENANT-EXEMPT` convention, and no isolation tests outside the IGA/cloud code.
   - Newer code is scoped carefully: IGA, cloud discovery, connectors, resource servers, applications, scope matrix, and agent policies.
   - The older "uflow" code (users, groups, sync, invites, WebAuthn/TOTP/SMS, OIDC/SAML, CIBA) trusts `workspace_id` from request bodies, looks users up by email across all tenants, or has no auth at all.
3. **The product is not safe to run as multi-tenant today.** Three cross-tenant P0s were reproduced live:
   - An anonymous request with only a workspace UUID returns an admin token for that workspace's owner.
   - Workspace A's admin can write into workspace B by putting B's ID in the request body.
   - Any workspace admin can list every workspace, including other owners' emails and password hashes.

   Code reading found roughly 30 more P0s (§5).
4. **A second tenant can't sign up through the main path.** `AdminRegister` has an unconditional "single-tenant guard" that returns 409 once one workspace exists (**R**). Three other paths still create workspaces, inconsistently.
5. **Both repos build.**
   - The backend builds, vets cleanly, boots, and applies all 41 migrations to an empty Postgres 16 in about 5 seconds. Unit tests pass except three that need Postgres on `:5432`.
   - The frontend builds and its tests pass (13 files, 118 tests), but `tsc` has 197 errors and ESLint has 282 errors.

   Many core flows are partial or broken (§6).

---

## 2. Architecture map

### 2.1 Backend: `/home/sauron/k1/authsec/merger/authsec`

| Aspect | Finding |
|---|---|
| Language / framework | Go 1.25.0, Gin 1.11. A single binary that merged 8 former microservices. |
| Entry point | `cmd/main.go`: loads `.env` (godotenv, which doesn't override existing env vars), connects to the DB, runs migrations, starts background workers, then registers routes. |
| Routing | `routes/routes.go` (2,353 lines) and `routes/iga_routes.go`. About 730 routes. Each `/authsec/<prefix>/*` group is one former service (`uflow`, `oocmgr`, `hmgr`, `clientms`, `authz`, `exsvc`, `spire`, `discovery`, `iga`, …). The OAuth 2.1 AS lives at `/oauth/*` and `/.well-known/*`. |
| Layers | `controllers/{admin,enduser,platform,shared}` → `services/` → `repository/`, `database/`. There are also `internal/*` packages for tokens, authz, policy, hydra, spire, IGA graph, cloud discovery, and more. `handlers/` holds WebAuthn, TOTP and SMS. |
| Database | PostgreSQL. 15+ is required (the schema uses `NULLS NOT DISTINCT`). CI uses 16 and 15. Access is mixed: `database/sql` + `lib/pq` raw SQL, plus GORM (AutoMigrate is disabled except for `migration_logs`). |
| Migrations | `migrations/master/NNN_*.sql` (001–042), applied at startup by `internal/migration/runner.go` and recorded in `migration_logs`. `migrations/deltas/` and `migrations/contract/` are **never applied** by the runner. `001_bootstrap.sql` is meant to equal the end state, but it has drifted (it is missing 22 tables and about 69 columns from 018–042). |
| Auth (platform) | HS256 session JWTs signed with any of three global secrets (`JWT_SECRET`, `JWT_DEF_SECRET`, `JWT_SDK_SECRET`) and checked by `middlewares/auth.go`. The tenant claim is `workspace_id`. Roles come from `role_bindings`. `RequireWorkspaceRole` checks `workspace_memberships`. `ValidateWorkspaceFromToken` compares only a `:workspace_id` **path** parameter. |
| Auth (OAuth AS) | Two stacks coexist. The legacy one (`oidc_controller`, `oocmgr`, `hmgr`, `clientms`) uses Hydra as a config store. The newer `/oauth/*` AS uses Ory Hydra for the auth-code and refresh flows, and `NativeIssuer`/NativeSealer (RS256, keys in Vault or in memory) for M2M, ID-JAG/XAA, CIBA and token exchange. Those native grants are behind `XAA_*` flags, all off by default. |
| Agent identity | Service accounts, workloads, SPIFFE (embedded SPIRE is off by default), delegation tokens, CIBA, agent action approval, MCP resource servers, and connectors with a broker. |
| External dependencies | Hydra (needed for login, auth code, refresh, introspection), Vault (secrets; with no Vault, signing keys are ephemeral), Redis (optional, but dialed anyway), SPIRE (optional), SendGrid/SMTP and Twilio (OTP delivery), AWS/GCP/Azure/GitHub/K8s (discovery). |
| Background jobs | `HydraReconciler` (every 5 minutes, plus daily and hourly goroutines, runs on **every replica** with no leader lock), the discovery scan worker, AWS scan and callback workers (need Vault), the PKI retry worker, and the IGA projection. |
| Tests | `go test ./...`: unit tests plus suites gated on a DSN (`TEST_DATABASE_URL`, `IGA_TEST_DSN`). `internal/testsupport` provides a testcontainers Postgres and fake Hydra/JWKS/MCP-RS. Integration flows are in `tests/integration/flows`, and ownership invariants in `tests/ownership`. |
| CI | `.github/workflows/go-ci.yml` (build, test, and IGA suites against a postgres:16 service), `pr-checks.yml` (opt-in integration on postgres:15), `deploy.yml` (deploys to the k3s prod namespace **on push to `authsec-staging`**), `mirror.yml`. |
| Sibling repos | `../mt-plugin`: the extracted DB-per-tenant gRPC service (131-table tenant template with `tenant_id` everywhere). No longer called by authsec; the client was deleted. `../sharedmodels`: legacy shared structs, still containing `tenant.go`. |

### 2.2 Frontend: `/home/sauron/k1/authsec/Authsec-ui`

| Aspect | Finding |
|---|---|
| Stack | React 19, Vite, TypeScript, Redux Toolkit + RTK Query, react-router 6, Radix/shadcn, Tailwind. `@tanstack/react-query` is a dependency but no `QueryClient` is ever created. |
| Entry | `src/main.tsx` → `src/App.tsx`. The store is in `src/app/store.ts`, APIs in `src/app/api/*`, auth in `src/auth/*`, pages in `src/features/*` (about 40 feature folders). |
| Config | Env vars `VITE_API_URL`, `VITE_OAUTH_BASE_URL` and `VITE_APP_NAME`. In production, `server.js` (Express) serves a runtime `/config.js` (`window.ENV`). |
| Session | The token and session live in localStorage (`sessionManager.ts`). The workspace comes from `session.workspace_id`, then the JWT claim, then the subdomain (`utils/workspace.ts`). `withSessionData()` puts `workspace_id`, `client_id` and `project_id` into request bodies. |
| Tests / CI | Vitest (13 files, none about auth or isolation). ESLint flat config. `.github/workflows/pr-checks.yml` and `deploy.yml`. |
| Branches | `multitenacyV2` is the same commit as `authsec-staging` and 269 commits ahead of `main`. `main` is stale and still tenant-era. |

### 2.3 Domain concepts → code

| Concept (CLAUDE.md) | What the code calls it | Main tables |
|---|---|---|
| Tenant / Organization | **Workspace** | `workspaces`, `workspace_domains`, `workspace_memberships` |
| User / Principal | Admin user, end user (one `users` table), membership | `users`, `workspace_memberships`, `credentials`, `mfa_methods` |
| Agent | Agent client (DCR, `/authsec/agents`), **service account**, workload, SPIFFE identity, discovered agent (IGA) | `mcp_oauth_clients`, `service_accounts`, `application_spiffe_identities`, `discovered_agents` |
| Resource / Integration | **Resource server** (shown as "Application" in the UI; MCP servers), **connector**, external service | `resource_servers`, `connectors`, `connector_connections`, `services` |
| Scope / Permission | OAuth scope, `resource:action` permission, role | `oauth_scopes`, `permissions`, `roles`, `role_permissions`, `mcp_tool_scope_map` |
| Policy | Agent policy, delegation policy, A2A brokering policy, RS access policy, PDP (`POLICY_ENGINE_MODE`) | `agent_policies*`, `delegation_policies`, `a2a_brokering_policies`, `resource_server_access_policies` |
| Grant / Delegation | Role binding, consent grant, client registration approval, delegation token, connector assignment, access request | `role_bindings`, `oauth_consent_grants`, `resource_server_client_registrations`, `delegation_tokens`, `connector_assignments`, `access_requests` |
| Token / Credential | Platform session JWT (HS256), native token (RS256, `NativeIssuer`), Hydra token, ID-JAG, JWT-SVID, SCIM token | `native_tokens`, `revoked_tokens`, `id_jag_replay_cache` |
| Audit Event | Audit events, authz decision log, issuance audit, agent action audit, connector action audit | `audit_events`, `authorization_decision_logs`, `auth_issuance_audit`, `agent_action_audit_log`, `connector_action_audit` |

---

## 3. Getting it running (verified 2026-10-06)

### Backend
- **Build:** `go build ./...` succeeds (about 80s cold).
  - **Local snag:** parts of `~/go/pkg/mod/cache/download` are owned by **root**, so the build fails with "permission denied" until that is fixed. Fix with `sudo chown -R $USER ~/go/pkg/mod`.
  - **Workaround without sudo:** `GOMODCACHE=<scratch> GOFLAGS=-modcacherw GOPROXY=file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org,direct go build ./...`
- **Vet:** `go vet ./...` is clean.
- **Test:** `go test ./...` passes 20 packages and fails 3 (`controllers/admin`, `controllers/shared`, `internal/migration`). All three failures are "Postgres not reachable on 127.0.0.1:5432". They fail rather than skip. CI provides postgres:16 on `:5432`.
- **Database:**
  ```
  docker run -d --name authsec-pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=authsec -p 127.0.0.1:55432:5432 postgres:16
  ```
  `.env` points at `localhost:5430/authdev`, which is not running locally.
- **Migrations:** run automatically at boot (set `SKIP_MIGRATIONS=true` to skip). Against an empty DB: 41 applied, 0 failed. This creates 175 tables plus `migration_logs` and seeds the system workspace `00000000-…`.
- **Run:**
  ```
  PORT=17468 DB_HOST=127.0.0.1 DB_PORT=55432 DB_NAME=authsec DB_USER=postgres DB_PASSWORD=postgres DB_SSL_MODE=disable JWT_SECRET=… JWT_DEF_SECRET=… JWT_SDK_SECRET=… TOTP_ENCRYPTION_KEY=… go run ./cmd
  ```
  - The server boots and serves requests.
  - Without Hydra, the reconciler logs errors and login, auth-code and introspection flows that need Hydra fail.
  - Without Vault, native signing keys are **ephemeral**: every restart invalidates every token (**R**).
  - With an empty `REDIS_URL`, it still dials `localhost:6379`.
  - `GET /authsec/health` and `/health` both return 404 (**R**). The health route lives under a different prefix.
- **Smoke test (R):**
  - Admin register → OTP (echoed in the response) → complete-registration → login works.
  - Login needs the **FQDN** `workspace_domain` (or an empty one), while register takes the bare label.
  - A second admin register returns **409**.

### Frontend
- `npm ci` (node_modules already present; Node 20.19.6 per `.nvmrc`, npm 10.8.2).
- `npm run build` (Vite) **succeeds**; the main chunk is 2.7 MB.
- `npx vitest run`: **13 files / 118 tests pass**.
- `npm run type-check` **fails** with 197 TS errors (TS2339 ×53, TS7006 ×36, TS2322 ×25, …). The build passes only because Vite doesn't type-check.
- `npm run lint` **fails** with 282 errors and 669 warnings (225 `no-unused-vars`, 64 `no-console`, …).
- `npx vite --port 15173` serves `/` and `/admin/login` (200).

### Environment variable names (no values)
- **Backend, fatal if missing:** `DB_USER`, `DB_PASSWORD`, `JWT_SDK_SECRET`, `JWT_DEF_SECRET`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, plus a reachable Postgres.
- **Backend, in `.env`:** `PORT GIN_MODE LOG_LEVEL ENVIRONMENT DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD DB_SCHEMA DB_SSL_MODE JWT_SECRET JWT_DEF_SECRET JWT_SDK_SECRET WEBAUTHN_RP_NAME WEBAUTHN_RP_ID WEBAUTHN_ORIGIN WEBAUTHN_TIMEOUT WEBAUTHN_DEBUG TOTP_ENCRYPTION_KEY SYNC_CONFIG_ENCRYPTION_KEY CORS_ALLOWED_ORIGINS CORS_ALLOW_ORIGIN OOC_MANAGER_URL HYDRA_ADMIN_URL ICP_SERVICE_URL BASE_URL AUTH_MANAGER_URL TENANT_DOMAIN_SUFFIX REDIS_URL VAULT_ADDR VAULT_TOKEN REQUIRE_SERVER_AUTH TOKEN_BLACKLIST_FAIL_OPEN ADMIN_CROSS_TENANT_ACCESS FORCE_HSTS`
- **Backend, feature flags (all default off/false):** `XAA_NATIVE_SEALER XAA_M2M XAA_REDEMPTION XAA_DPOP XAA_CIBA XAA_ISSUANCE ENABLE_EMBEDDED_SPIRE IGA_GRAPH_PROJECTION AUTH_ENFORCE_RESOURCE_LIST`, plus `POLICY_ENGINE_MODE` (default `off`).
- **Backend, other:** `HYDRA_PUBLIC_URL NATIVE_RSA_PRIVATE_KEY_B64 SKIP_MIGRATIONS AUTHSEC_DISABLE_HYDRA_RECONCILER AUTHSEC_HYDRA_RECONCILER_INTERVAL DCR_STALE_DAYS PENDING_APPROVAL_TTL_DAYS AUTHSEC_SPIFFE_AUDIENCE PUBLIC_UI_ORIGIN PUBLIC_UI_BASE_PATH CONNECTOR_OAUTH_<P>_* TEST_DATABASE_URL IGA_TEST_DSN`
- **Frontend:** `VITE_API_URL VITE_OAUTH_BASE_URL VITE_APP_NAME`. `server.js` also reads `VITE_HUBSPOT_ACCESS_TOKEN PORT`.

---

## 4. Tenancy audit

### 4.1 Tables

The full table-by-table inventory is in [`audit/schema-inventory.md`](audit/schema-inventory.md) §2. Summary:

| Metric | Value |
|---|---|
| Tables (SQL migrations) | 175 (162 in 001, 22 only in 027–041), plus `migration_logs` |
| With `workspace_id` | 143 |
| With no scope column | 32: about 10 legitimately global (catalogs, replay caches, `workspaces`), 13 join/child, 9 tenant data with no column |
| `workspace_id` nullable | 12, including **`users`, `roles`, `permissions`**, `audit_events`, `delegation_*`, `device_codes` |
| `workspace_id` typed `text` | `audit_events`, `spire_audit_logs` |
| FK to `workspaces` | 72 direct, 35 via composite `(workspace_id, id)` parent FK, **36 with no FK** (including users, roles, groups, service_accounts, resource_servers, native_tokens, every audit table) |
| `tenant_id` columns | 0. The rename went through 001 in place (`e9ccb83`→`67053a4`). |
| Row-Level Security | **None** |

**Tenant data with no workspace column:**
- `services` (external-service credentials, scoped only by `created_by`)
- `credentials` (WebAuthn) and `mfa_methods`, keyed by the legacy `client_id`
- `trusted_issuers`: global, but writable by any workspace admin
- `mcp_oauth_clients`: only a nullable `home_workspace_id`
- the 9 `spire_*` tables
- join tables `role_permissions`, `oauth_scope_permissions` and `mcp_tool_scope_map`, whose single-column FKs allow cross-workspace links

**Users are not strictly owned by a workspace.** A user has a nullable home `users.workspace_id` plus `workspace_memberships`, and workspace switching exists (`POST /authsec/workspaces/:id/switch` checks membership). The ADR has to decide whether a user can belong to more than one tenant.

**Workspace ID equals the first admin's user ID and `client_id`** (**R**: all three UUIDs were identical in the smoke test). That's a coupling to keep in mind when designing the backfill.

**Two conventions mark platform-global rows:** `workspace_id IS NULL` in app code and migrations 003/005, versus the system workspace `00000000-0000-0000-0000-000000000000` in 001 seeds.

### 4.2 Where tenant context is resolved

The full route table is in [`audit/request-context-and-routes.md`](audit/request-context-and-routes.md).

- **The correct path.**
  - `AuthMiddleware` verifies the HS256 JWT and sets `workspace_id` from the claim (`middlewares/auth.go:446`, `:866`).
  - Newer handlers read it back through `shared.RequireWorkspaceID(c)` (`controllers/shared/context_helpers.go:40`) or `ResolveWorkspaceIDFromToken`.
- **Taken from client input (the main defect class).** A grep found about 25 direct `c.Query`/`c.Param`/header reads and about 440 bound-struct field reads of `workspace_id`/`tenant_id`. `ValidateWorkspaceFromToken` only checks the **path** param, so a body value passes untouched. Confirmed body-trusting handlers:
  - groups (**R**), sync-configs, AD/Entra sync, admin-sync, invite, v2 group role-bindings
  - `/uflow/user/admin/{change,reset}-password`, `/uflow/user/groups/users/{add,remove}`
  - `oocmgr raw-hydra-dump`, the discovery ingress, embedded SPIRE routes
- **Taken from Host/Origin/`X-Forwarded-Host`** for pre-auth workspace and redirect resolution (`workspace_resolver.go:47`, `admin_auth_controller.go:363`, `oidc_controller.go:1660`, `hmgr_controller.go:572`). Gin trusted proxies are never configured.
- **Membership isn't re-checked per request.** Only routes with `RequireWorkspaceRole` read `workspace_memberships`, so a removed member keeps access for the token's lifetime: 24h, or 365 days for SCIM and end-user tokens.
- **Dead super-admin flag.** `ADMIN_CROSS_TENANT_ACCESS` is set in `.env` but read nowhere (removed in `764a654`). There is no explicit platform-admin role at all. Platform-global objects (trusted issuers, OIDC providers, the workspace list, master migrations) are reachable by any workspace admin, any logged-in user, or nobody.

### 4.3 Unscoped data access

Statement-level detail is in [`audit/data-access.md`](audit/data-access.md), [`audit/data-access-services.md`](audit/data-access-services.md) and [`audit/data-access-controllers.md`](audit/data-access-controllers.md). About 1,500 SQL/GORM statements were reviewed:

| Domain | Risky (approx.) | P0 | Notes |
|---|---:|---:|---|
| Users / identity | ~95 | 14 | email-only lookups, body workspace, global lists |
| Workspaces / memberships | ~12 | 1 | `GetAllTenants` |
| Agents / SAs / workloads | ~40 | 1 | SPIFFE SA lookup; most of the rest is dormant SPIRE code |
| Apps / clients / RS / IdP / issuers | ~12 | 2+ | OIDC providers, trusted issuers, approve-redirects, discovery claim→provision |
| Roles / permissions / bindings | ~10 | 2 | group/RS ids not checked against the workspace |
| Policies, grants, audit | ~7 | 0 | well scoped |
| Connectors / SCIM / sync | ~15 | 5 | sync-configs, AD/Entra |
| IGA / discovery | ~6 | 1 | unauthenticated ingress |

No shared helper adds the filter automatically. The older code keeps unscoped twins next to `…ByTenant` methods.

### 4.4 Tokens and runtime authorization

Details are in [`audit/tokens-and-runtime-authz.md`](audit/tokens-and-runtime-authz.md).

- **Platform session JWTs do carry `workspace_id` (R).** They are HS256, signed with one of three global secrets that are interchangeable. They have **no `jti`**. `aud` and `exp` are optional at verification. Lifetimes are 24h (admin), 365 days (end-user callback, SCIM, legacy CIBA). `/auth/token/generate` re-mints them indefinitely.
- **Native tokens (RS256)** carry no workspace claim; the workspace is in the `native_tokens` row. The keyset is global by design. Introspection checks signature, row, revocation, expiry, `aud == RS`, registration, and live RBAC. A resource server in workspace A can't get `active=true` for a token whose audience is B's RS.
- **The same-tenant check is incomplete.**
  - SPIFFE SVID client auth maps `spiffe_id` to a service account across **all** workspaces (**C**, `services/client_auth.go:359`).
  - Trusted issuers are global, so a `provider_name` collision maps an attacker's ID-JAG to a victim's user.
  - `ApprovePendingRedirects` and `ApproveConnection` look clients up globally.
  - The discovery claim→provision path takes `matched_client_id` from the body.
  - The broker doesn't compare the principal's workspace with the RS's workspace.
- **Policy enforcement is off by default.** `POLICY_ENGINE_MODE=off` only audits. `/authz/decision` permits by default and never evaluates the tool. An agent can approve its own pending action.
- **Revocation.**
  - Native-token revocation works and is scoped by workspace.
  - Platform JWTs can't be revoked: `TokenBlacklistMiddleware` is never mounted.
  - Revoking a delegation token only flips a DB status.
  - Revoking a consent grant doesn't revoke issued tokens.

### 4.5 Caches, jobs, webhooks, storage, logs, audit
- **Caches:** no cross-tenant leak found. Redis is unused. The in-memory JWKS cache holds a global mutex during the fetch, which is an availability risk.
- **Jobs:** the reconciler and workers process rows that carry `workspace_id`, but they run on every replica with no leader lock. The stale-DCR reaper hard-deletes **live** agent clients after 30 days, because `last_token_issued_at` is only stamped on auth-code.
- **Webhooks:** policy-warning webhook targets are checked only for `https://` (SSRF). The GitHub webhook takes the installation binding from an unsigned header.
- **Storage:** Vault paths are mostly per workspace. `services` secrets are scoped by creator, not workspace. No file storage.
- **Logs:** they include `workspace_id`, but also access/refresh tokens (`webauthn_handler.go:773`), OTPs, OIDC state, and full query strings on 4xx/5xx.
- **Audit:**
  - Tables carry `workspace_id`, but it is TEXT/nullable on `audit_events` and has no FK.
  - None of the audit tables are append-only.
  - The 101 `middlewares.Audit` calls only print to stdout, so user-management actions never reach the audit UI. End-user logins aren't audited.

### 4.6 Global unique constraints that should be per tenant

| Constraint | Effect |
|---|---|
| `resource_servers.resource_uri` (001:2173) | URI squatting; existence leak |
| `workload_identity_providers.issuer` (001:996) | One workspace can claim e.g. the GitHub Actions issuer for everyone |
| `trusted_issuers.iss` | Same, platform-wide |
| `spiffe_id` (001:965, 1773) | Collision is the impersonation key |
| TOTP backup `code` (001:1452, 1483) | Cross-user uniqueness leak |
| `device_token` (001:1392) | Redundant global unique |
| `otp_entries` keyed by email | An OTP from one workspace or flow is accepted in another |

Globally unique on purpose: OAuth `client_id`, `workspaces.workspace_domain`, `jti`.

### 4.7 What git history offers to restore
- **DB-per-tenant (`tenants.tenant_db`, template cloning, `mt-plugin`)** is not worth restoring. The mt-plugin template (131 tables, `tenant_id`) no longer matches the 175-table schema, and the client code is deleted. The dead runner hooks (`NewTenantMigrationRunner`, `GenerateWorkspaceDBName`, `ApplyICPTenantMigrations`) should be deleted.
- **Worth reusing:**
  - The deleted tenant middleware stack (`middlewares/tenant_resolution.go`, `tenant_validation.go`, `tenant_context_middleware.go` @ `764a654^`) is a reference for a resolve-once/validate middleware.
  - The tenant-era DDL (`e9ccb83:migrations/master/001_bootstrap.sql:2167-2400`).
  - The test harness in `internal/testsupport` and the invariants in `tests/ownership`.
  - The composite-FK pattern from 027 (`(workspace_id, id)`).
- **Frontend:** the session listener in `store.ts`, the `workspace_id:user_id` storage-key pattern, and IGA's workspace-keyed cache tags.

---

## 5. Highest-risk findings (P0)

See `ISSUES.md` for all rows. These are grouped by attack shape.

1. **Anonymous authentication bypass → account or workspace takeover.**
   - AS-001 admin `webauthn-callback` (**R**)
   - AS-002 end-user `webauthn-callback`
   - AS-003 anonymous WebAuthn registration plus forged-attestation fallback (**C**)
   - AS-004 anonymous TOTP/SMS enrollment
   - AS-005 SAML signature not enforced
   - AS-015 legacy CIBA
   - AS-016/017/018 registration paths that attach an attacker to an existing workspace or user
2. **Cross-tenant writes and reads by an authenticated user of another tenant.**
   - AS-006 body `workspace_id` (**R**)
   - AS-007 password change/reset
   - AS-008 global user lists
   - AS-009 workspace list with password hashes (**R**)
   - AS-010 OIDC providers
   - AS-022 raw Hydra dump
   - AS-023 end users editing admins
3. **Cross-tenant identity confusion in the agent/OAuth plane.**
   - AS-011 trusted issuers
   - AS-012 SPIFFE SA lookup (**C**)
   - AS-013 exsvc credentials
   - AS-026 discovery claim→provision
   - AS-027 approve-redirects
   - AS-014 anonymous discovery ingress
4. **Secrets.**
   - AS-019 OTP echoed in the response (**R**)
   - AS-020 hardcoded TOTP key (**R**: the warning appears even when the correct env var is set)
   - AS-024 SCIM token minting with no role check

**Coupling to watch:** the admin UI login *depends on* AS-001. `AdminAuthContext.tsx:156` posts `{email, mfa_verified:true, workspace_id}` after the client-side WebAuthn ceremony. Closing AS-001 needs a server-verified WebAuthn assertion that returns the token, shipped together with the UI change.

---

## 6. Feature health (core flows)

| # | Flow | Status | Key blockers |
|---|---|---|---|
| 1 | Sign-up / workspace creation | **Partial** | The first workspace works (**R**). A second gets 409 from the guard (**R**). Other paths bypass the guard inconsistently. `POST /uflow/admin/tenants` creates orphan workspace rows. |
| 2 | Login | **Works, but bypassable** | Password login works (**R**), but needs the FQDN domain while register takes the label. The WebAuthn callback bypass. Admin lockout never fires. The rate limits don't match the real paths, and `X-Forwarded-For` spoofing defeats them. Without Hydra the hosted login flows fail. |
| 3 | User management | **Broken / unsafe** | List works for admins (**R**). `AuthMiddleware` never sets `user_info`, so 6 delete/toggle handlers always return 401/403. Admins lack `users:delete`. `/admin/enduser/list` returns 400. The UI calls nonexistent activate/reset/change-password endpoints. |
| 4 | Agent registration | **Partial** | Service accounts and workloads work. `POST /authsec/agents` needs Hydra. `provision-identity` always returns 400 (`agent_type` is never written). The live agent and delegation code queries tables no migration creates (`agents`, `workloads`, …; **R**: absent from the DB). |
| 5 | Resource / integration setup | **Mostly works** | RS, application and connector CRUD are well scoped. OIDC IdP update is a 501 stub. The UI admin Resources page calls nonexistent endpoints. |
| 6 | Policy creation | **Partial** | Agent, risk and birthright policies work. Delegation policies with `client_id` always fail: they filter on `resource_servers.deleted_at`, which doesn't exist (**C**). Brokering gates fail open. |
| 7 | Granting agent access | **Partial** | Role bindings, consent grants, access-request approval and connector assignments work. The delegation-token path is unreachable. |
| 8 | Runtime authorization check | **Fails open** | `/authz/decision` permits by default. The policy engine is off. Introspection is sound for native tokens. |
| 9 | Token issuance / revocation | **Partial** | Only Hydra auth-code works out of the box (the `XAA_*` flags are off). Native keys are ephemeral without Vault. Platform JWTs are irrevocable. `/auth/token/oidc` upgrades any Hydra token to a 24h session. |
| 10 | Audit log | **Partial** | Readers work. Most writes only go to stdout. End-user logins aren't audited. |
| 11 | Dashboard | **Partial** | No general dashboard endpoint. The posture, access and discovery-coverage summaries work. |

---

## 7. Frontend audit

Details are in [`audit/frontend.md`](audit/frontend.md).

- **Active tenant.**
  - It is read from localStorage `session.workspace_id`, which can be seeded from a URL `?workspace_id=` or an unsigned `?handoff=`. The verified JWT claim is only the fallback.
  - `withSessionData()` puts `workspace_id`, `client_id` and `project_id` into bodies in 18 API files. That is exactly the input the backend wrongly trusts.
  - No `X-Tenant` or `X-Workspace` headers are sent.
- **Tenant switch.** None in the UI (`switchProject` is a stub), although the backend supports `/workspaces/:id/switch`.
- **Cache reset.** A store listener resets the RTK caches on session change. But when another tab signs in, `checkSession` doesn't refresh Redux, so a tab can show A's cached data while sending B's token. On logout, three API caches, the `adminWebAuthn` slice (including the token) and several sessionStorage keys survive. There is no reload.
- **Tokens.** Kept in localStorage with no CSP, no refresh, and no 401 handler. Tokens are logged to the console in two places. `server.js` exposes `VITE_HUBSPOT_ACCESS_TOKEN` in the public `/config.js` and logs it.
- **Broken integrations.** About 12 live pages call endpoints that don't exist:
  - user activate, reset and change-password
  - admin resources
  - bulk role delete
  - directory sync paths
  - the voice-agent watcher, which polls a 404 every 3s on every page
  - TOTP device delete
  - the hosted-login social callback

  Dead modules and mock pages: Vault, `src/data/*`, `test-client-service.ts`.
- **Quality gates.** `tsc` fails and lint fails. No tests cover auth, session or isolation. `scripts/audit-api-routes.sh` reports success when `rg` is missing.

---

## 8. Risks and constraints for the next phases
- **Production safety.**
  - `deploy.yml` deploys on any push to `authsec-staging`, which is the branch we are on.
  - AGENTS.md: never wipe the deployed DB; back up before migrations; rehearse every schema change on a restored prod dump; update `001_bootstrap.sql` together with every new `NNN_*.sql`.
  - The memory notes record the TOTP key typo as **live in prod**. Fixing it needs a re-encryption migration, or every TOTP user is locked out.
- **Scope of the uflow surface.** Most P0s sit in older endpoints (`/uflow/user/*`, `/uflow/admin/groups*`, `/webauthn/*`, `/oocmgr/*`, legacy CIBA, `/uflow/login/webauthn-callback`). For each one, Phase 3 must decide whether to **delete** it (if the UI or SDKs no longer use it) or **fix** it. Deleting is often the safer and smaller change. The frontend endpoint inventory (`audit/frontend.md`) tells us what is still called.
- **External dependencies for end-to-end tests.** Real login needs Hydra (a docker image is available), and stable tokens need Vault or `NATIVE_RSA_PRIVATE_KEY_B64`.
- **Repository hygiene.** `go.mod` isn't tidy (10 AWS modules marked `// indirect` are imported directly). `001_bootstrap.sql` has drifted from the numbered migrations. `deltas/` holds hand-run SQL.

## 9. Recommended order of work
1. **Contain the P0s before the multi-tenancy rebuild.** These are small, targeted fixes, each with a regression test:
   - remove or close the anonymous token mints: AS-001/002/003/004/015, plus the coordinated UI change for admin WebAuthn login
   - stop the OTP echo (AS-019)
   - force every handler to take the workspace from the token, starting with AS-006/007 (and reject a mismatched body value)
   - scope or lock down AS-008/009/010/011/012/022/023/024

   This only partly overlaps Phase 3, so the ordering question is for you (see the summary).
2. **Phase 1 ADR.** Recommendation: keep the shared DB with `workspace_id` (already 82% there). Add a resolve-once middleware, a scoped data layer, and Postgres RLS (with `SET LOCAL app.workspace_id`) as defense in depth. Introduce an explicit platform-admin realm. Decide between a single home workspace per user and memberships.
3. **Phase 2.**
   - Fix test hygiene: skip when there is no DB, and add `make test-db`.
   - Fix the tsc and lint failures.
   - Add the isolation-test harness. `internal/testsupport` and `tests/ownership` are a good base.
4. **Phase 3.**
   - Remove the single-tenant guard and pick one signup path.
   - Schema hardening, in order: FKs, NOT NULL, per-workspace uniques, workspace columns for `services`, `credentials`, `mfa_methods`, `trusted_issuers` and the join tables.
   - Migrate callers domain by domain, starting with users and groups, which have the most findings.
5. **Phase 4.** UI: take the workspace only from the verified claim, drop `withSessionData` workspace injection, fix cache reset (cross-tab and logout), implement workspace switching, and fix the broken endpoints.
