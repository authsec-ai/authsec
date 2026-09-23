# authsec — backend agent instructions

Read the workspace [`../AGENTS.md`](../AGENTS.md) first. It owns the product
model, transition rules, and production safety contract. This file contains only
backend-specific rules; do not duplicate the workspace deployment description
here again.

## Backend role

`authsec` is the Go/Gin control plane and OAuth authorization server. It owns
workspace-scoped identity, Applications, OAuth clients, roles/scopes, Agents,
Service Accounts, Workloads, Integrations/legacy Connectors, audit, native token
issuance, and the ORY Hydra boundary.

## Engineering rules

- Preserve controller → service → repository/model layering. Controllers validate
  transport input and map errors; services own policy and transactions.
- Scope every data operation by `workspace_id` unless the object is explicitly
  platform-global.
- Issue native tokens only through `NativeIssuer`; never construct JWTs ad hoc.
- Audit security-relevant mutations and authorization decisions.
- Reuse existing services and adapters before adding a parallel abstraction.
- Do not add tests unless requested. For Go changes, run `go build ./...`,
  `go vet ./...`, and `gofmt -l` for affected files. For documentation-only
  changes, verify references and the diff; no application build is required.

## Schema contract

- The deployed database is never wiped.
- Every production schema change includes the next
  `migrations/master/NNN_name.sql` and updates `001_bootstrap.sql` to the same end
  state.
- Only `migration_logs` may use GORM `AutoMigrate`.
- Migrations run at backend startup and are verified through `migration_logs`.
- Use expand → backfill → contract for removals, renames, type changes, and new
  `NOT NULL` constraints.
- Rehearse the upgrade against a **production schema dump restored into an
  isolated scratch database**. Check fresh bootstrap separately for parity;
  bootstrap-only success does not establish upgrade compatibility. Never apply
  rehearsal SQL to the deployed database.
- Follow [`../.claude/commands/schema-change.md`](../.claude/commands/schema-change.md).

## Agentic IGA

- The active graph design is
  [`.claude/specs/SPEC-iga-phase2-graph.md`](.claude/specs/SPEC-iga-phase2-graph.md).
  The objective is the complete AWS scanning-to-graph experience, including
  read APIs and UI integration. Treat unfinished contracts as work to resolve,
  not as implemented behavior or an automatic reason to defer the user journey.
- Inspect [migrations/master](migrations/master) and the current source before
  assigning migration numbers or claiming a task is complete. Dated status
  reports do not override either; do not require reading a separate historical
  status report as the entrypoint for graph work.
- Preserve existing GitHub, Kubernetes and legacy consumers of shared IGA tables
  and APIs. Trace those consumers before structural changes. Earlier work on
  `origin/graph` may be inspected when requested or relevant; reuse requires
  verification against the current spec, not an automatic merge.
- Invariants that are not style preferences: coverage is a state, never a
  percentage; `stale` is not `ended`; a configured path is not proven access;
  conditions are recorded, never evaluated; redact before hashing;
  `(kind, uuid)` is not a foreign key; leases fence on a version, never a clock;
  no secrets, ever; the discovery role never writes.

## Production deployment

The production release procedure is documented in
[`.claude/specs/SPEC-deployment-k3s.md`](.claude/specs/SPEC-deployment-k3s.md).

- Production Deployment/container: `authsec-prod/prod-authsec` / `prod-authsec`.
- Build the local working tree as an immutable `linux/amd64` image.
- Back up Postgres before any release containing migrations.
- Roll out backend before the matching UI and verify health, migrations, OAuth
  metadata, and protected routes.
- [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) declares a push
  trigger on `authsec-staging` and manual dispatch. A push may deploy; verify
  workflow prerequisites and environment gates for release work. Do not assume
  CI is operational from the file alone. The root cutover restrictions apply.

## Deep docs

| Area | Read first |
|---|---|
| Schema | `docs/primitives/schema.md` |
| OAuth/token engine | `docs/primitives/oauth-as.md`, `docs/primitives/token-engine.md` |
| Identity principals | `docs/primitives/identity-principals.md` |
| RBAC/scopes | `docs/primitives/rbac-scopes.md` |
| SPIFFE | `docs/primitives/spire.md`, `docs/flows/spiffe-workload.md` |
| Connectors | `docs/connectors-design-review.md` |
| Coding patterns | `docs/coding-practices.md` |

## Completion

Run the applicable backend gates in
[`../.claude/DEFINITION-OF-DONE.md`](../.claude/DEFINITION-OF-DONE.md).
A review or documentation task does not require a commit or deployment.
Do not push without explicit per-command approval.
