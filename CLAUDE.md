# CLAUDE.md — AuthSec Platform

This file is the persistent context for Claude Code. Read it at the start of every session. Keep it current: when a decision is made or a fact about the codebase is learned, update the relevant section in the same change.

---

## 1. What AuthSec is

AuthSec (https://authsec.ai) is a **security and authorization layer for AI agents**.

Example: a user tells an AI assistant (a ChatGPT/Gemini-style chatbot) to "book me a flight." To do that, the agent needs scoped, time-bound access to check availability, fill in passenger details, and complete payment. AuthSec decides and enforces:

- **Which** agent gets access
- **To what** (resources, tools, APIs, scopes)
- **When** (time windows, expiry, one-time vs. standing grants)
- **Where / in what context** (environment, origin, conditions)
- **On whose behalf** (the human principal who delegated authority)

All of this is managed from the AuthSec Platform (admin dashboard and APIs), and every decision is auditable.

### Core domain concepts
Names confirmed against the code on 2026-10-06. **In the code the tenant is called a "workspace"** (`workspace_id`); "tenant" survives only in legacy route and function names.

| Concept | Meaning | Name in code (main tables) |
|---|---|---|
| Tenant / Organization | A customer of AuthSec. The top-level isolation boundary. | **Workspace** (`workspaces`, `workspace_domains`, `workspace_memberships`) |
| User / Principal | A human in a tenant who owns agents and delegates authority. | Admin user / end user, both in `users`, plus memberships |
| Agent | An AI agent identity registered within a tenant. | Agent client (`mcp_oauth_clients`, `/authsec/agents`), **service account** (`service_accounts`), workload / SPIFFE identity, discovered agent (IGA) |
| Resource / Integration | An external system or tool an agent may act on (e.g. airline API). | **Resource server** (shown as "Application" in the UI; MCP servers) (`resource_servers`), **connector** (`connectors`), external service (`services`) |
| Scope / Permission | A specific capability on a resource. | OAuth scope (`oauth_scopes`), `resource:action` permission (`permissions`), role (`roles`) |
| Policy | Rules that decide whether an agent may perform an action (who / what / when / where). | `agent_policies*`, `delegation_policies`, `a2a_brokering_policies`, `resource_server_access_policies`; PDP behind `POLICY_ENGINE_MODE` |
| Grant / Delegation | A concrete, possibly time-bound authorization from a principal to an agent. | `role_bindings`, `oauth_consent_grants`, `resource_server_client_registrations`, `delegation_tokens`, `connector_assignments`, `access_requests` |
| Token / Credential | What the agent presents at runtime; must carry tenant + agent + scope claims. | Platform session JWT (HS256, `workspace_id` claim); native token (RS256 via `NativeIssuer`, workspace in the `native_tokens` row); Hydra token; ID-JAG; JWT-SVID |
| Audit Event | An immutable record of every authorization decision and admin change. | `audit_events`, `authorization_decision_logs`, `auth_issuance_audit`, `agent_action_audit_log`, `connector_action_audit` |

---

## 2. Current mission

AuthSec was originally designed as a **multi-tenant SaaS platform**. Over time that design was not followed and the platform **lost its multi-tenancy**. Many features are also broken.

The mission, in priority order:
1. **Make the platform stable**: it builds, starts, and the core flows work end to end.
2. **Restore true multi-tenancy** across backend and frontend with strict tenant isolation.
3. **Fix all existing bugs and broken features**, tracked in `docs/ISSUES.md`.

Tenant isolation is a **security property**, not a feature. A cross-tenant data leak is the worst possible bug in this product.

---

## 3. Repositories

| Repo | Path | Stack |
|---|---|---|
| Backend | `/home/sauron/k1/authsec/merger/authsec` (deployed branch `authsec-staging`; current work on `fix/p0-containment`) | Go 1.25, Gin; raw `database/sql` + `lib/pq` and GORM (no AutoMigrate); PostgreSQL 15+ (CI uses 16); Ory Hydra; Vault; optional SPIRE/Redis |
| Frontend | `/home/sauron/k1/authsec/Authsec-ui` (deployed branch `authsec-staging`; current work on `feat/ui-voice-perf`) | React 19 + Vite + TypeScript; Redux Toolkit + RTK Query; react-router 6; Radix/shadcn + Tailwind; Vitest |

Sibling repos: `../mt-plugin` (the extracted DB-per-tenant service, no longer used) and `../sharedmodels` (legacy structs).

⚠️ `deploy.yml` in both repos deploys to production **on push to `authsec-staging`**. Work on feature branches and never push without explicit approval.

### How to run
Verified on 2026-10-06. Details and error output are in `docs/AUDIT.md` §3.
- **Backend:**
  - `make build` · `make vet` · `make test` (DB-backed unit tests skip without Postgres)
  - `make test-integration`: flows, onboarding and flags-off via testcontainers. Docker required; `-p 1`.
  - `make tenant-exempt`: the scoping ratchet. Raw SQL outside `internal/tenancy` needs `// TENANT-EXEMPT: <reason>`, and the count may only go down.
  - `make dev-up` then `make run`: local Postgres, Hydra and Vault (`deploy/dev`).
  - Older form: `go build ./...` · `go vet ./...` · `go test ./...`
  - Three packages fail without Postgres on `127.0.0.1:5432`. DB-gated suites need `TEST_DATABASE_URL` / `IGA_TEST_DSN`.
  - Run with `go run ./cmd`, giving env vars as below. It listens on `PORT` (default 7468).
  - If `~/go/pkg/mod` has root-owned dirs, use `GOMODCACHE=<scratch> GOFLAGS=-modcacherw GOPROXY=file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org,direct`.
- **Frontend:**
  - `npm ci` · `npm run dev` (Vite) · `npm run build` ✅ · `npx vitest run` ✅
  - `npm run type-check` ✅ (0 errors) · `npm run lint` ✅ (0 errors, ~570 warnings) — as of 2026-10-08 on `feat/ui-voice-perf`
- **Database (local) and migrations:**
  - Start Postgres: `docker run -d --name authsec-pg -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=authsec -p 127.0.0.1:55432:5432 postgres:16`
  - Migrations in `migrations/master/NNN_*.sql` apply automatically at boot (`SKIP_MIGRATIONS=true` skips them) and are recorded in `migration_logs`. `migrations/deltas/` and `migrations/contract/` are not applied by the runner.
  - Hydra (`HYDRA_ADMIN_URL`, `HYDRA_PUBLIC_URL`) is needed for login and OAuth flows. Without Vault, signing keys are ephemeral (tokens die on restart).
  - Admin-auth endpoints are rate-limited to 5/min per IP.
- **Required env vars (names only, never values):**
  - Backend, fatal if missing: `DB_USER DB_PASSWORD JWT_SDK_SECRET JWT_DEF_SECRET WEBAUTHN_RP_NAME WEBAUTHN_RP_ID WEBAUTHN_ORIGIN`
  - Backend, usual: `PORT ENVIRONMENT DB_HOST DB_PORT DB_NAME DB_SSL_MODE JWT_SECRET TOTP_ENCRYPTION_KEY SYNC_CONFIG_ENCRYPTION_KEY HYDRA_ADMIN_URL HYDRA_PUBLIC_URL VAULT_ADDR VAULT_TOKEN REDIS_URL TENANT_DOMAIN_SUFFIX CORS_ALLOWED_ORIGINS`
  - Backend, flags (default off): `XAA_NATIVE_SEALER XAA_M2M XAA_REDEMPTION XAA_DPOP XAA_CIBA XAA_ISSUANCE ENABLE_EMBEDDED_SPIRE IGA_GRAPH_PROJECTION POLICY_ENGINE_MODE`
  - Frontend: `VITE_API_URL VITE_OAUTH_BASE_URL VITE_APP_NAME`

---

## 4. Multi-tenancy architecture (target state)

Decided in [`docs/adr/0001-tenancy-model.md`](docs/adr/0001-tenancy-model.md) (accepted 2026-10-06). In code the tenant is the **workspace** and the column is `workspace_id`; read "tenant_id" below as `workspace_id`.

**Isolation model:** shared database, `tenant_id` column on every tenant-owned table. *Decided (ADR-0001):* shared Postgres DB, tenant column **`workspace_id`**, enforced by edge resolution in `AuthMiddleware`, a scoped data layer (`internal/tenancy`), and Postgres RLS (`app.workspace_id`, `FORCE`) as defense in depth.

**Non-negotiable rules:**
1. Every tenant-owned table has a non-null `tenant_id` with a foreign key and an index (usually composite, e.g. `(tenant_id, id)`).
2. Tenant context is resolved **once**, at the edge (auth middleware), from a verified token or session. It is **never** taken from a request body, query param, or client-controlled header.
3. Tenant context flows through a single request-scoped mechanism (context object / async-local storage / DI scope). No function looks up the tenant by itself.
4. All data access goes through a tenant-scoped repository or query layer that applies the tenant filter automatically. Raw unscoped queries need a `// TENANT-EXEMPT: <reason>` comment and a review.
5. Use database-level enforcement (e.g. Postgres Row-Level Security) as defense in depth where the DB supports it. *Confirmed:* PostgreSQL 15+ (CI uses 16), which supports RLS. *Since 2026-10-07:* RLS is on for every workspace table (migration 054; see §7).
6. Lookups by ID must also match the tenant. A record from another tenant returns **404**, not 403, so callers can't confirm it exists.
7. Agent tokens and credentials carry a `tenant_id` claim. The runtime authorization check verifies that the agent, the grant, the policy, and the resource all belong to the **same tenant**.
8. Unique constraints are scoped per tenant (e.g. `UNIQUE(tenant_id, slug)`), not global, unless the value is truly global.
9. Secrets, signing keys, webhook secrets, and integration credentials are per tenant and never shared.
10. Cache keys, queue messages, background jobs, scheduled tasks, webhooks, file storage paths, logs, and metrics all carry the tenant ID.
11. Audit events are written per tenant and are append-only.
12. Platform-level super-admin access, if it exists, is explicit, separately authorized, and audited. It is never the default code path.

**Frontend rules:**
- The active tenant comes from the authenticated session, not from local state the user can edit.
- Switching tenants clears all cached data (query cache, stores) before loading the new tenant's data.
- The UI is never the security boundary. Hiding a button is UX; the backend must enforce.
- Routes and API calls must handle tenant-scoped 404s gracefully.

---

## 5. Working rules for Claude Code

- **Plan before editing.** For any non-trivial change, state the plan and the files affected first.
- **Small, reviewable changes.** One concern per commit or PR. Don't mix refactors with bug fixes.
- **Never** run destructive operations (drop tables, delete data, force-push, rewrite migrations that already ran) without explicit approval.
- **Migrations** must be forward-only and reversible where possible. Adding `tenant_id` follows this order: add a nullable column, backfill it, add NOT NULL and the FK, then add indexes and constraints. Each step is its own migration.
- **Tests come with every fix.** For every bug fixed, add a test that would have caught it. For every tenant-scoped endpoint, add a cross-tenant isolation test (tenant A cannot read, list, update, or delete tenant B's data).
- **Don't guess.** If behavior is ambiguous, check the code, the tests, and git history, then ask.
- **Never commit secrets.** Never print secret values in output.
- **Keep docs in sync:** this file, `docs/ISSUES.md`, `docs/PROGRESS.md`, and the ADRs.

### Definition of done (per change)
- [ ] Builds and lints cleanly (backend and frontend)
- [ ] Existing tests pass, and new tests cover the change
- [ ] Cross-tenant isolation tests added or updated if data access changed
- [ ] No unscoped queries introduced
- [ ] Docs updated (`ISSUES.md` status, `PROGRESS.md`, this file if context changed)

---

## 6. Project docs

| File | Purpose |
|---|---|
| `docs/AUDIT.md` | Phase 0 findings: architecture map, tenancy gaps, broken features |
| `docs/ISSUES.md` | Every known bug or gap, with an ID, severity, status, and owner repo |
| `docs/PROGRESS.md` | Running log: what was done each session and what's next |
| `docs/adr/` | Architecture Decision Records (tenancy model, auth, etc.) |

**Severity scale:** `P0` security or tenant leak · `P1` core flow broken · `P2` feature broken · `P3` minor or cosmetic

---

## 7. Known facts and decisions log
<!-- Append dated entries. Example:
- 2026-10-06: Confirmed backend uses Postgres 15; RLS will be used as defense in depth (ADR-0001).
-->
- 2026-10-06: The tenant is the **workspace** (`workspace_id`), in one shared Postgres DB. History: DB-per-tenant → `mt-plugin` extraction (`764a654`, 2026-04-29) → single-tenant substrate (`69c82a3`) → tenant model deleted (`05e289d`, 2026-06-23).
- 2026-10-06: Platform JWTs carry a `workspace_id` claim and are set into gin context by `middlewares/auth.go`. `ValidateWorkspaceFromToken` checks only the `:workspace_id` path param, so body and query values are not validated. That is the root cause of most cross-tenant findings.
- 2026-10-06: `AdminRegister` has an unconditional single-tenant guard (409 on the second workspace).
- 2026-10-06: The admin UI login relies on the unauthenticated `/uflow/login/webauthn-callback` (AS-001), so the backend and UI must be fixed together.
- 2026-10-06: `../AGENTS.md` and `../.claude/DEFINITION-OF-DONE.md` (referenced by AGENTS.md) do not exist in `merger/`. Use §5 of this file as the definition of done.
- 2026-10-06: Phase 0 audit complete. See `docs/AUDIT.md`, `docs/ISSUES.md`, `docs/PROGRESS.md`.
- 2026-10-06: ADR-0001 accepted: shared DB + `workspace_id`; users belong to one workspace, operators may hold memberships; same-workspace check on every token issuance; separate platform realm; RLS rolled out per domain in Phase 3.
- 2026-10-06: The owner asked to run all phases back to back, committing locally (never pushing). Work happens on local branches only; `authsec-staging` auto-deploys.
- 2026-10-06: Tenant isolation is enforced in four layers: (1) `AuthMiddleware` rejects any path/query/body workspace other than the token's (404) and re-checks membership per request; (2) `internal/tenancy` is the scoped data layer; (3) per-endpoint isolation tests use `TwoTenants` in `tests/integration/flows`; (4) the TENANT-EXEMPT ratchet runs in CI. RLS was enabled on 2026-10-07 (054).
- 2026-10-06: Interactive sign-in uses single-use login tickets (`internal/logintickets`, migration 043). The MFA endpoints and webauthn callbacks never trust client-asserted identity.
- 2026-10-08: Migration numbers. `authsec-staging` (deployed) owns 002–046 and continues upward from 047. This program's migrations are 101–119, in this order: login tickets, trusted-issuer workspace, tenancy expand, backfill, contract, indexes/uniques, session revocations, append-only audit, users:delete, voice sessions, **RLS (111)**, platform rows, lockouts, CIBA RS binding, OTP scope, index backfill, entra_tenant_id, resource URI per workspace, issuer per workspace. Older notes and commits call them by their former numbers 043–072; the map is in docs/PROGRESS.md (2026-10-08). New migrations of this program take 120+.
- 2026-10-07: Postgres RLS is on (111, formerly 054). Every new workspace table's migration must `SELECT public.tenancy_enable_rls('public.<table>')`; `tests/integration/flows/rls_test.go` fails otherwise. RLS restricts only transactions opened through `internal/tenancy` (they set `app.workspace_id` and run as `authsec_tenant`).
- 2026-10-07: Outbound requests to tenant-chosen URLs must use `internal/safehttp`.
- 2026-10-07: `scripts/schema-parity.sh <binary>` checks that a fresh bootstrap and an upgraded copy of the scratch DB end with the same schema. Run it after any migration. The tenant ratchet skips statements handed to the scoped layer and the RLS-only packages (`internal/igaread`, `internal/k8sread`).
- 2026-10-07: The tenant ratchet is at 0. New raw SQL must go through `tenancy.ExecContext`, `QueryContext`, `QueryRowContext` or `InsertContext` (database/sql), or `tenancy.GormExec`/`GormRaw` (GORM), all bound to `workspace_id = $1`. Otherwise it needs a specific `// TENANT-EXEMPT:` reason (`-- ` inside SQL strings).
- 2026-10-08: Discovery ingress is authenticated by staging's ingest tokens (`IGA_DISCOVERY_INGEST_AUTH` off|warn|enforce, default warn), plus a connector's actuation token, which decides workspace and source. A connector holding an actuation token cannot be spoken for without it. Set `enforce` once every collector has a token.
- 2026-10-08: Embedded SPIRE (AS-081) is multi-tenant and may run in production (`ENABLE_EMBEDDED_SPIRE`, default off). Its control-plane tables are `spire_*`, one per workspace, under RLS (migration 120). Node attestation needs an admin-minted single-use join token. Agent and mTLS routes take the workspace from the verified client certificate. Behind an ingress, set `SPIRE_TRUST_CLIENT_CERT_HEADER=true` only if the ingress overwrites the client-cert header. `SPIRE_RECONCILE` (default true) syncs the shared SPIRE server. The ratchet now counts `internal/spire`.
- 2026-10-08: Phase 6 done. The legacy `workspace_id`/`tenant_id` gin keys are retired: read the workspace with `tenancy.Workspace(c)` / `middlewares.GetWorkspaceIDFromToken`. RLS fails closed for `authsec_tenant` (130). The `authsec_platform` BYPASSRLS role (ADR §4.4) is a superuser deploy step that has not been taken.
