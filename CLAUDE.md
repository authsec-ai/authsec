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
- Phase 5 (dual JSON contract) — **current**

Until Phase 6 lands, both `tenants` and `workspaces` exist; `workspaces.id ==
tenants.id` by construction (admin signup writes both rows in one
transaction). The startup log line `[migration:phase2] tenants=N workspaces=N
(in lockstep)` confirms the invariant on every boot.

Phase 5 API contract: backend JSON responses must emit `workspace_id` as the
canonical identifier and may also emit `tenant_id` as a deprecated mirror with
the same value until Phase 8. New backend docs and examples should lead with
`workspace_id`; keep `tenant_id` only where documenting compatibility or a
legacy URL/path parameter. UI and SDK clients do not need an immediate Phase 5
change, but they must migrate to `workspace_id` before Phase 8 removes the
mirror field.

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
emit `workspace_id` in JWTs, switch reads, dual-emit JSON), then drops
`tenants` and most `tenant_id` columns in one big wipe at Phase 6, removes the
deprecated `tenant_id` JSON mirror by Phase 8, cleans up the remaining
`tenant_*` table names in Phases 7–9, and final-sweeps the Go code in Phase
10. The only two surviving "tenant" mentions at end-state are the legacy MFA
routes `/auth/tenant/totp/*` and `/auth/tenant/ciba/*`.

If you're touching tenant_id or workspace_id today, **open the plan file** and
match what you're doing to the current phase. Don't freelance ahead of phase.

---

## Cluster / deploy quick reference

- Cluster: Azure AKS, cluster name `authsec`
- Backend namespace: `authsec-dev`, deployment `dev-authsec`
- Database namespace: `database-dev`, pod `postgresql-dev-primary-0`,
  user/db `authdev`/`authdev`, password at
  `/opt/bitnami/postgresql/secrets/password` inside the pod
- CI: Jenkins builds `docker-repo.authsec.ai/authsec:authsec-dev-<N>-<SHA>` and
  retags `:development`; deploy is `kubectl set image`
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
- Treating `tenant_id` as canonical in new JSON docs or backend response work;
  in Phase 5 it is only a deprecated mirror of `workspace_id`
- Renaming routes `/auth/tenant/totp/*` or `/auth/tenant/ciba/*` — these are
  the documented legacy exception
- Adding tests the user didn't ask for (memory note `feedback_no_unprompted_tests`)
