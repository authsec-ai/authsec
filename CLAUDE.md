# AuthSec — Working Notes for AI Agents

This file is the canonical orientation for Claude Code (and any other AI agent
working in this repo). It supersedes earlier docs about the mt-plugin /
multi-tenant-removal migration — that work is done and the mt-plugin
infrastructure has been deleted.

Read this before touching the database, the bootstrap, or anything that smells
like tenant/workspace scoping.

---

## Where we are right now

AuthSec is a single-deployment Go/Gin backend that fronts ORY Hydra for OAuth
2.1 / OIDC, plus an admin/end-user identity stack. There is exactly one
PostgreSQL database (`config.DB`). No tenant DBs, no dynamic switching, no
mt-plugin gRPC client. If you find references to `MTPluginClient`,
`MT_PLUGIN_GRPC_ADDR`, `tenant_db_service`, or `template_builder`, they are
stale — flag and delete.

The active migration in flight is **tenant → workspace**. The 10-day plan lives
at:

```
/Users/pc/.claude/plans/no-no-there-would-compiled-puffin.md
```

That file is authoritative for what comes next. Always reread it before
starting a phase — don't rely on memory of the plan.

**Status (2026-05-26):**

- Phase 1 (stable baseline + bug sweep) — done
- Phase 2 (workspace creation in signup, lockstep with tenants) — done, shipped
  in commit `50a6157`
- Phase 3 (JWT carries `workspace_id` always) — done
- Phase 4 (backend reads prefer workspace identity) — done
- Phases 5+6+8 collapsed (drop `tenants` table, drop `tenant_id` columns,
  drop `tenant_id` from JSON/JWT, rename `/auth/tenant/{ciba,totp}` →
  `/auth/workspace/{ciba,totp}`, UI + SDK swept in lockstep) — done,
  awaiting fresh-DB cycle and verification push
- Phases 9–10 (remaining `tenant_*` table renames + SPIRE-layer sweep +
  test/doc cleanup) — pending

Until Phase 6 lands, both `tenants` and `workspaces` exist; `workspaces.id ==
tenants.id` by construction (admin signup writes both rows in one
transaction). The startup log line `[migration:phase2] tenants=N workspaces=N
(in lockstep)` confirms the invariant on every boot.

API contract (post-collapse): JSON responses emit `workspace_id` only.
Requests accept `workspace_id` only. JWTs carry `workspace_id` only (no
`tenant_id` claim). URL path/query params use `workspace_id`. The two formerly
legacy MFA routes have been renamed: `/auth/workspace/ciba/*` and
`/auth/workspace/totp/*`. UI (`Authsec-ui`) and SDKs (`sdk-authsec`
TypeScript + Python; Go SDK was already clean) shipped in lockstep with the
backend.

---

## Schema ownership — hard rule

There is **one** source of truth for the schema:

```
migrations/master/001_bootstrap.sql
```

This file is hand-curated, single-state (no ALTER patches, no migration chain).
It currently sits around 2.5k lines and creates all 81 tables in their final
v4 shape, with every column, index, FK, and seed inlined.

GORM `AutoMigrate` is allowed for **exactly one** table: `migration_logs`. That
table records bootstrap runs. Everything else — including every model struct
in `models/` — is read-only from GORM's perspective. The structs describe what
SQL already created.

### When a schema bug surfaces (forward-only rule)

If a table is missing a column the code expects, or a column has the wrong
type, **edit the `CREATE TABLE` block in `001_bootstrap.sql` in place.** Then:

1. Commit + push
2. Wait for Jenkins to build the new image
3. Wipe the dev DB
4. Restart the pod
5. Re-run the smoke flow

Do NOT:

- Add an `ALTER TABLE` patch file (`002_fix_x.sql`, `003_fix_y.sql`, …)
- Add `db.AutoMigrate(&SomeModel{})` to make GORM add the column
- Add the missing column back to GORM tags hoping AutoMigrate picks it up

The user has stated this explicitly and repeatedly: wiping is free, backfills
and patch chains are not. Move forward, never sideways.

Example we've already done: `oauth_scopes.source` was missing from bootstrap →
added the column inline to the `CREATE TABLE public.oauth_scopes` block with
default `'discovered'` and the CHECK constraint, wiped, retested.

---

## The tenant → workspace migration in one paragraph

The legacy `tenants` table mixed three concerns: workspace identity
(`tenant_domain`, `vault_mount`, `ca_cert`), admin identity (`email`,
`password_hash`, `provider`), and a scope ID that 17 other tables FK back to.
`workspaces` was introduced as the v4 replacement but never made authoritative
— the table sat empty in production while `tenants` did all the work. The
10-day plan walks workspaces forward in additive phases (write workspace rows,
emit `workspace_id` in JWTs, switch reads, dual-emit JSON), then collapses
Phases 5–8 into one big push that drops `tenants`, drops every `tenant_id`
column, drops the deprecated `tenant_id` JSON mirror, drops the `tenant_id`
JWT claim, renames `/auth/tenant/{ciba,totp}` → `/auth/workspace/{ciba,totp}`,
and rebuilds the bootstrap as workspace-only. Phases 9–10 then sweep the
remaining `tenant_*` table names and the `internal/spire/` SPIRE-side
references. **End-state: zero "tenant" mentions in URL surface; only the
legacy `entra_tenant_id` Azure AD concept and a handful of historical
breadcrumb comments survive.**

If you're touching tenant_id or workspace_id today, **open the plan file** and
match what you're doing to the current phase. Don't freelance ahead of phase.

---

## Cluster / deploy quick reference

- Cluster: Azure AKS, cluster name `authsec`
- Backend namespace: `authsec-staging`, deployment `stage-authsec`
- Database namespace: `database-staging`, pod `postgresql-stage-primary-0`,
  user/db `authstage`/`authstage`
- CI: Jenkins builds on push to `authsec-staging` branch; deploy is `kubectl set image`
- Wipe-and-rebootstrap is the standard recovery move; the user does this
  freely and has said "i will wipe 1000 times if needed"

`git push` is the only blocker — every other tool action is pre-authorized.
**Never push without an explicit per-command instruction.**

---

## Anti-patterns to refuse

- `ALTER TABLE` patch files in `migrations/master/` — edit the CREATE inline
- `AutoMigrate(&AnythingExceptMigrationLogs{})` in `cmd/main.go`
- Reintroducing `tenant_db_service`, `MTPluginClient`, dynamic DB switching
- Backfilling data from `tenants` into `workspaces` (we just keep them in
  lockstep until Phase 6 drops the old one)
- Reintroducing `tenant_id` anywhere in new JSON/JWT/Go code — it's gone
- Reintroducing `/auth/tenant/*` routes — they were renamed to
  `/auth/workspace/{ciba,totp}/*` in the Phase 5/6/8 collapse
- Adding tests the user didn't ask for (memory note `feedback_no_unprompted_tests`)
