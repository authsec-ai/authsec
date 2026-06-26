# AuthSec backend — agent orientation

> See also: workspace root `../AGENTS.md` (product model, flows overview, ownership model, deploy).
> This file covers authsec-specific conventions, schema rules, and the deep-docs index.

## What this repo is

Go/Gin backend. One PostgreSQL database (`config.DB`). Fronts ORY Hydra for
`authorization_code` / `refresh_token` flows; mints native RS256 JWTs for M2M, XAA,
and CIBA. 90-table schema in `migrations/master/001_bootstrap.sql`.

**Workspace-centric:** everything is scoped to a `workspace_id`. No `tenant_id` in new
code (the migration is complete; only `entra_tenant_id` survives as an Azure AD concept).

## Schema ownership — hard rules

1. **Single-state, forward-only.** The entire schema lives in
   `migrations/master/001_bootstrap.sql` as hand-curated `CREATE TABLE` statements.
2. **Never add `ALTER TABLE` patch files.** Edit the `CREATE TABLE` inline, wipe the DB,
   re-bootstrap.
3. **`AutoMigrate` is allowed for `migration_logs` only** (`cmd/main.go`). Every other
   model struct is read-only from GORM's perspective.
4. **New additive migrations** (adding tables to a live DB that can't be wiped) go in
   `002_*.sql` alongside `001_bootstrap.sql`.

> Deep doc: `docs/primitives/schema.md`

## Code practices

- **Keep it clean.** No dead scaffolding, no speculative helpers, no duplicate utilities.
  Reuse before you add; delete what a change makes obsolete.
- **Surgical fixes only.** Diagnose the root cause with the full architecture in mind.
  Don't patch the first symptom. If a fix needs a structural change, do the structural change.
- **No stray `tenant_id`** in new code, JSON, JWT claims, or URL paths.
- **Error handling**: wrap with context (`fmt.Errorf("op: %w", err)`); don't swallow errors.
  Return HTTP errors from controllers — don't log-and-continue on meaningful failures.
- **Audit mutations**: every admin mutation must call `auditAdminMutation(c, wsID, action,
  resource, resourceID, statusCode, oldValues, newValues)` before returning.
- **Token issuance**: always goes through `NativeIssuer.Issue` for native tokens, never
  directly through the key manager's `Sign`. For Hydra-backed flows, proxy through
  `OAuthASService.ProxyFormToHydraPublicCapture`.
- **gofmt always**: code must be formatted (`gofmt -w`) before committing.

## Terminology

| Concept | Use | Avoid |
|---|---|---|
| Non-human M2M identity | **Service Account** | "Workload" |
| OAuth registered application | **Client** | "App" at protocol layer |
| API that accepts bearer tokens | **Resource Server** | "MCP server" at auth layer |
| Scope string | **Scope** | "Permission" at OAuth layer |
| k8s pod credential | **Workload / SVID** | "Service Account" |
| Organization unit | **Workspace** | "Tenant" |
| Cross-app identity assertion | **ID-JAG** | custom names |

## Adding a new endpoint

1. Controller method in `controllers/platform/<area>_controller.go`.
2. Route registration in the router (`router.go`).
3. Service method in `services/<area>_service.go` — DB logic, no HTTP primitives.
4. Model in `models/` — struct + `TableName()`. If a new table is needed, edit
   `001_bootstrap.sql` and wipe+rebootstrap.
5. Call `auditAdminMutation` for any create/update/delete.

## Anti-patterns to refuse

- `ALTER TABLE` patch files — edit CREATE TABLE inline
- `AutoMigrate` on anything except `migration_logs`
- Routing a `native:` kid token to Hydra introspect
- Putting `tenant_id` / `/auth/tenant/` anywhere new
- Adding tests the user didn't ask for

---

## Deep docs index

Load the relevant doc before working in that area. Each doc is code-verified and
cites real file paths + function names.

| I'm about to… | Read this first |
|---|---|
| Mint / validate / revoke / introspect tokens | [`docs/primitives/token-engine.md`](docs/primitives/token-engine.md) |
| Touch `/oauth/*` endpoints, grants, discovery, introspect, JWKS | [`docs/primitives/oauth-as.md`](docs/primitives/oauth-as.md) |
| Touch Hydra client registration, reconciler, auth-code flow | [`docs/primitives/hydra.md`](docs/primitives/hydra.md) |
| Work with token subjects (user / SA / agent / workload), `sub` claim | [`docs/primitives/identity-principals.md`](docs/primitives/identity-principals.md) |
| Add/modify scopes, roles, permissions, or role bindings | [`docs/primitives/rbac-scopes.md`](docs/primitives/rbac-scopes.md) |
| Touch SPIFFE/SVID, SPIRE entries, delegation policies, JWT-SVID | [`docs/primitives/spire.md`](docs/primitives/spire.md) |
| Add log types, modify audit helper, touch Logs API | [`docs/primitives/logs-audit.md`](docs/primitives/logs-audit.md) |
| Add a column, table, or understand schema domains | [`docs/primitives/schema.md`](docs/primitives/schema.md) |
| Implement / debug M2M (client_credentials) flow | [`docs/flows/m2m.md`](docs/flows/m2m.md) *(pending)* |
| Implement / debug XAA / ID-JAG (cross-app agent) flow | [`docs/flows/xaa-idjag.md`](docs/flows/xaa-idjag.md) *(pending)* |
| Implement / debug SPIFFE workload token exchange | [`docs/flows/spiffe-workload.md`](docs/flows/spiffe-workload.md) *(pending)* |
| Implement / debug OIDC login (authorization_code) | [`docs/flows/oidc-login.md`](docs/flows/oidc-login.md) *(pending)* |
| Implement / debug CIBA | [`docs/flows/ciba.md`](docs/flows/ciba.md) *(pending)* |
| Implement / debug MCP discovery, DCR (RFC 7591/7592) | [`docs/flows/mcp-discovery.md`](docs/flows/mcp-discovery.md) *(pending)* |
| Implement / debug federation (trusted issuers, workload IdPs, A2A) | [`docs/flows/federation.md`](docs/flows/federation.md) *(pending)* |
| Understand the full services/* + controllers/platform/* file map | [`docs/subsystems.md`](docs/subsystems.md) *(pending)* |
| Follow Go/Gin coding conventions for this repo | [`docs/coding-practices.md`](docs/coding-practices.md) *(pending)* |
