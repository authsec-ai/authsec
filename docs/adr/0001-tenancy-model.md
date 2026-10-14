# ADR-0001: Tenancy model

- **Status:** Accepted (2026-10-06). The owner delegated the open questions ("do what you recommend"); each decision below can be revisited by superseding this ADR.
- **Context source:** `docs/AUDIT.md` §4, `docs/ISSUES.md`, `docs/audit/schema-inventory.md`.

## 1. Context

AuthSec started as database-per-tenant: a master DB plus `tenant_<uuid>` databases cloned from a template. That was extracted to `mt-plugin` (`764a654`), and the tenant model was deleted in `05e289d`. Today the tenant is the **workspace**, a row in `workspaces`, and every tenant-owned row is meant to carry `workspace_id` in a single shared Postgres database (15+, CI 16).

The audit found:
- 143 of 175 tables already carry `workspace_id`.
- Enforcement is manual and inconsistent. There is no scoped data layer and no RLS. Many handlers trusted `workspace_id` from the request. About 36 tables lack an FK, 12 have a nullable `workspace_id`, and several global uniques should be per workspace.
- Some tenant data has no workspace column at all: `services`, `credentials`, `mfa_methods`, `trusted_issuers`, `spire_*`, and join tables.

## 2. Decision summary

| Topic | Decision |
|---|---|
| Isolation model | **Shared database, shared schema, `workspace_id` on every tenant-owned row.** Not DB-per-tenant, not schema-per-tenant. |
| Name | The tenant is called **workspace** in code and data (`workspace_id`). "Tenant" appears only in prose and legacy route names. |
| Tenant resolution | Exactly once, in `AuthMiddleware`, from the verified token. Never from body, query, path or headers. |
| Propagation | One request-scoped value, `tenancy.Context`, read through one accessor. |
| Enforcement | (1) A scoped data layer in `internal/tenancy` adds the predicate automatically. (2) Postgres Row-Level Security as defense in depth. (3) Isolation tests per endpoint. |
| Users | A `users` row belongs to exactly one workspace. Console operators may hold **memberships** in other workspaces. A token is always for one workspace, and switching re-mints after a membership check. |
| Agent runtime | Every token issuance and introspection runs a **same-workspace check**: subject, client/agent, grant, policy and resource server. The only cross-workspace path is an explicitly approved client registration. |
| Platform admin | A separate **platform realm**: its own principal table, token type and route group. It is audited and never reachable with a workspace token. |
| Frontend | The workspace comes from the verified session (token claims). Caches reset on switch, logout and cross-tab identity change. Cross-tenant 404s render as "not found". |

## 3. Isolation model and trade-offs

**Chosen: shared DB with `workspace_id`.**
- **For:**
  - It matches what the schema already is, so there is no data move.
  - One migration path and one connection pool.
  - Cross-workspace features that exist by design (approved client registrations, memberships) stay simple.
  - Postgres RLS is available as a second line of defense.
- **Against:**
  - A single missing predicate leaks data. This is mitigated by the scoped layer, RLS and isolation tests.
  - A noisy neighbour shares resources. That's acceptable at current scale; per-tenant rate limits are a separate item.
  - Per-tenant backup and restore is harder. That's a product decision, not needed now.

**Rejected:**
- *DB-per-tenant (restore `mt-plugin`):* its template (131 tables, `tenant_id`) no longer matches the 175-table schema, and the client code is deleted. Restoring it means re-porting every migration since April and re-adding dynamic connection routing across all code, which is the opposite of where the code is today.
- *Schema-per-tenant:* the same migration and routing cost, for little gain over RLS.

## 4. Tenant context: resolution, propagation, enforcement

### 4.1 Resolution (edge)
- **`AuthMiddleware`** verifies the token, then:
  - **Workspace from the token only.** Reads `workspace_id` from the verified claims, and nowhere else.
  - **Requests can only repeat it.** Any `workspace_id`/`tenant_id` in the path, query or top-level JSON body must equal the token's workspace, or the request gets **404**. This shipped in `1f17b92`. The only exemption is `POST /authsec/workspaces/:workspace_id/switch`, whose handler checks membership.
  - **Membership is re-checked on every request.** For console tokens it checks `workspace_memberships` (status `active`); for end-user tokens it checks `users.active` and `users.workspace_id`. A removed member loses access immediately, not when the token expires (fixes AS-032). This is one indexed lookup per request; there's no Redis, per the standing preference.
- **Pre-auth surfaces** (login pages, OIDC/SAML callbacks, hosted login) may resolve a workspace from a domain or login challenge. They do so **only to choose an identity provider or show branding**. No data is read or written under that workspace until a first factor is verified, and the login ticket then carries the workspace (shipped in `1042b00`).
- **Machine credentials** resolve the workspace from the credential's own row, never from claims the caller controls:
  - OAuth client → `mcp_oauth_clients` / registrations
  - service account → `service_accounts.workspace_id`
  - SVID → the workload identity provider's workspace
  - collector → its source credential

### 4.2 Propagation
- **`internal/tenancy`** defines `type Context struct { WorkspaceID uuid.UUID; PrincipalID uuid.UUID; PrincipalKind string; Realm string }`.
- **Writing it.** `tenancy.Set(c, ctx)` is called only by the auth middlewares.
- **Reading it.** `tenancy.From(c)` returns it, and **panics in tests / 500s in production if absent**, so a handler can't run unscoped by accident.
- **Background jobs** receive the workspace explicitly as a parameter or from the row they process (for example a scan run row). They never use a global.
- **Legacy context keys** (`workspace_id`, `tenant_id` in gin context) stay for compatibility until every caller has moved, then are removed in Phase 6.

### 4.3 Scoped data layer
`internal/tenancy` provides:
- **GORM:** `tenancy.DB(c)` returns `config.DB.WithContext(ctx).Scopes(tenancy.Where(ws))` plus a callback that **refuses** `Create`/`Save` of a model whose `WorkspaceID` differs from the context's.
- **database/sql:** `tenancy.Exec/Query/QueryRow(c, sql, args...)`. These require the statement to reference `$1` as `workspace_id`; the helper prepends the workspace argument. A lint test greps for `workspace_id = $1`.
- **Lookups by id:** `tenancy.Get(c, &model, id)` returns `ErrNotFound`, mapped to **404**, for another workspace's row.
- **Raw queries outside the layer** need a `// TENANT-EXEMPT: <reason>` comment. A CI script (`scripts/check-tenant-exempt.sh`) lists them, and the count may only go down.
- **Migration order:** users → memberships/roles/groups → agents/service accounts → applications/resource servers/clients → policies → grants/consents → tokens/sessions → audit → connectors/sync → discovery/IGA (already mostly scoped).

### 4.4 Database-level enforcement (RLS)
- **Policies.** Each tenant-owned table gets `ENABLE` and `FORCE ROW LEVEL SECURITY` with:
  `USING (workspace_id = current_setting('app.workspace_id', true)::uuid)` and the same `WITH CHECK`.
- **Session variable.** The scoped layer runs each request's statements in a transaction that begins with `SET LOCAL app.workspace_id = '<uuid>'`. `SET LOCAL` is per transaction, so it's safe with pooled connections.
- **Two DB roles:**
  - `authsec_app`: subject to RLS. Used by request handlers.
  - `authsec_platform`: `BYPASSRLS`. Used only by migrations, the platform realm, and jobs that legitimately span workspaces, such as the Hydra reconciler and retention jobs. Those jobs must still pass the workspace explicitly.
- **Rollout.** RLS is enabled table by table in Phase 3, *after* that domain's callers are on the scoped layer. Each table first ships with a transitional policy that also allows `current_setting('app.workspace_id', true) IS NULL`, with a log/metric on unscoped access. Phase 6 removes the transitional clause.
- **Ownership caveat.** If the application user owns the tables, RLS only applies with `FORCE`; that's why the policies use `FORCE`. A deploy step must confirm the role layout, because the production role setup isn't visible in the repo.

## 5. Tokens, claims and the same-workspace check

### 5.1 Claims
- **Platform session JWT** (console and end-user): `iss`, `aud` (per surface), `sub`, `workspace_id` (required), `typ` (`admin` | `enduser` | `sdk` | `platform`), `exp` (required), `iat`, `jti` (required).
  - **Verification** requires `exp`, `aud`, `typ` and `workspace_id`. Each token class gets its own signing key, so the three interchangeable shared HS256 secrets go away (AS-033).
  - **Revocation** is checked by `jti` against a DB table (AS-031).
- **Native agent tokens** (RS256, `NativeIssuer`) keep the `native_tokens` row as the source of truth, and also carry a `workspace_id` claim. That lets resource servers that verify locally apply the same-workspace rule. `aud` remains the resource server URI.
- **ID-JAG / XAA:** the issuer is scoped to a workspace (AS-011), and the subject maps only into the issuer's workspace.
- **Login tickets** (interactive sign-in) are already implemented: realm, workspace, user and single use.

### 5.2 Same-workspace check at runtime
`authz.SameWorkspace(subject, client, grant, policy, resourceServer)` runs on every issuance (client_credentials, jwt-bearer, token-exchange, CIBA, refresh, authorization_code completion) and on introspection:
1. **The resource server's workspace W is the tenant of the access.**
2. **Subject:**
   - a user must belong to W (`users.workspace_id = W`);
   - a service account or workload must belong to W, or to the client's home workspace when there is an approved cross-workspace registration (rule 3).
3. **Client/agent:** must have a registration on the resource server in W with status `approved`. Cross-workspace clients (home ≠ W) are allowed **only** through that approved registration. That's the deliberate MCP connection feature, and it stays opt-in and audited.
4. **Grants and policies** (role bindings, consent grants, delegation policies, agent policies, brokering policies): only rows with `workspace_id = W` are considered. Rows from another workspace are invisible, not merely denied.
5. **Default deny.** The policy engine defaults to `enforce`; `POLICY_ENGINE_MODE=off` becomes a dev-only override (AS-035).
6. **Audit.** Every decision writes `authorization_decision_logs` with `workspace_id = W`.

## 6. Schema migration and backfill plan

These rules come from AGENTS.md: the deployed DB is never wiped, every change gets the next `NNN_*.sql` plus a `001_bootstrap.sql` update, the order is expand → backfill → contract, and each step is rehearsed on a restored production dump.

1. **Inventory freeze.** The table classification in `docs/audit/schema-inventory.md` §2 becomes `docs/tenancy/tables.md`, the source of truth: tenant-owned, platform or join.
2. **Add missing columns, nullable** (one migration per domain): `services`, `credentials`, `mfa_methods`, the `spire_*` tables, the join tables (`role_permissions`, `oauth_scope_permissions`, `mcp_tool_scope_map`), and `mcp_oauth_clients.owner_workspace_id`.
3. **Backfill**, deterministically, from parents:
   - `credentials`/`mfa_methods` via `users`;
   - `services` via the creator's user;
   - join tables via the parent role, scope or tool;
   - `spire_*` via the workload/SA row.

   Rows that can't be attributed are **reported, not guessed**: the migration writes them to `tenancy_backfill_orphans` and fails the contract step until they're resolved. If a fallback owner is needed, use the existing **system workspace `00000000-0000-0000-0000-000000000000`**, never a customer workspace.
4. **Contract:**
   - `NOT NULL`.
   - FK to `workspaces(id)`, composite `(workspace_id, x) → parent(workspace_id, id)` where a parent exists. This follows the pattern from 027.
   - A `workspace_id`-leading index on every tenant table.
   - The 36 tables that have `workspace_id` but no FK get FKs, after an orphan report shows zero orphans.
   - The 12 nullable columns are made `NOT NULL`, except where `NULL` deliberately means platform, as decided below.
5. **Unique constraints:** `resource_servers.resource_uri`, `workload_identity_providers.issuer`, `trusted_issuers.iss`, `spiffe_id`, TOTP backup `code` and `device_token` become per-workspace uniques. The truly global ones stay global: OAuth `client_id`, `workspace_domain`, `jti`.
   - *Amended 2026-10-07 (AS-060):* TOTP backup codes and device tokens are per workspace (`ca8b91b`). `resource_servers.resource_uri`, `workload_identity_providers.issuer`, `trusted_issuers.iss` and `spiffe_id` **stay global for now**. Their lookups run before any workspace is known: `GetByResourceURI(uri)` in the refresh, client_credentials and jwt-bearer grants, authorize, DCR, first contact and the connector broker, and `authenticateSPIFFESVID`, which selects by `iss`. With a per-workspace unique and those lookups unchanged, two rows could share a key. Picking one is cross-tenant confusion; failing on ambiguity lets any workspace break another's token issuance by registering the same URI. Today a squatter can only pre-empt a URI nobody uses yet, which is the lesser problem.
     To finish:
     1. Add `GetByResourceURIForClient(uri, client)`, which tries the client's approved registration, then the client's home workspace, then a URI unique across workspaces.
     2. Move the callers to it.
     3. Make DCR and first contact refuse an ambiguous URI.
     4. Make the SVID path try each provider with the issuer and accept only the one whose workspace maps the verified subject.
     5. Only then replace the uniques with `(workspace_id, …)` ones.
6. **Platform rows.** One convention: platform-owned rows use `workspace_id IS NULL` **only** on tables that legitimately hold platform data (the permission catalog, platform OIDC providers, platform trusted issuers). The system-workspace seed rows in 001 are migrated to `NULL`, or the reverse; the decision is recorded in `docs/tenancy/tables.md` per table (AS-079).
   - *Decided 2026-10-07 (migration 055):* `NULL`. The tables that may hold platform rows are the ones 054 lets read `workspace_id IS NULL`: `permissions`, `roles`, `role_permissions`, `trusted_issuers`, `oidc_providers`, `sod_rules`. The system workspace keeps only its registry row, as the orphan fallback of step 3. A CHECK on `permissions`, `roles` and `role_permissions` refuses new system-workspace rows.
7. **Identity coupling.** New workspaces get an id independent of the first admin's user id. Existing coupled rows are left as is, since nothing depends on the equality once code stops assuming it (AS-083).

## 7. Platform (super-admin) access
- **Separate principals:** a `platform_admins` table (no `workspace_id`), WebAuthn-only sign-in, its own token `typ=platform` with its own signing key and short TTL (1h).
- **Separate routes:** `/authsec/platform/*` only, guarded by `RequirePlatformAdmin`, and never mounted under tenant groups. A workspace token is always rejected there.
- **What lives there:**
  - the workspace list and lifecycle (moved from `/uflow/admin/tenants`);
  - platform OIDC providers and platform trusted issuers;
  - migration status;
  - support "act as" on a workspace, which requires a reason string, issues a short-lived token marked `act_as`, and is audited in both the platform and workspace audit logs.
- **Until then**, platform operations are simply unavailable to tenants. That's what Phase 0 containment did.

## 8. Frontend tenant handling
- **Source of truth.** The active workspace comes from the verified session: the token's `workspace_id` claim, displayed via `/authsec/workspaces` membership data.
  - `localStorage` session fields are a cache of that, never an input.
  - `withSessionData` stops injecting `workspace_id`/`client_id`/`project_id` into request bodies; the backend ignores and rejects mismatches anyway.
- **Switching.** A workspace switcher calls `POST /authsec/workspaces/:id/switch`, stores the new token, then does a full reset:
  - `resetApiState()` on every RTK Query API;
  - a reset of the Redux auth and webauthn slices;
  - clearing per-workspace storage keys, which are namespaced `authsec:<workspace>:<user>:*`.
- **Logout and cross-tab.** The same reset runs on logout. A `storage` event listener runs it, and reloads, when another tab changes the identity or workspace (UI-004).
- **Routing** stays workspace-implicit: no workspace in URLs; the token decides.
- **404 handling.** A 404 from a tenant-scoped resource shows the standard "not found" page, and never a hint that the resource exists elsewhere.
- **Tokens** stay in storage for now. Moving to httpOnly cookies is a separate decision, outside this ADR (UI-011).

## 9. Consequences
- **Phase 2:** builds `internal/tenancy` (context, scoped GORM/sql helpers, RLS transaction helper) and the isolation-test harness, without migrating callers yet.
- **Phase 3:** applies sections 4–7 domain by domain, each with migrations, caller migration, isolation tests and an RLS enablement step.
- **Phase 4:** applies section 8.
- **Open, owned elsewhere:** per-tenant rate limits and quotas, per-tenant backup/restore, moving tokens to cookies.
