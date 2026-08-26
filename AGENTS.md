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
- Do not add tests unless requested. Always run `go build ./...`, `go vet ./...`,
  and `gofmt -l` for affected Go code.

## Schema contract

- The deployed database is never wiped.
- Every production schema change includes the next
  `migrations/master/NNN_name.sql` and updates `001_bootstrap.sql` to the same end
  state.
- Only `migration_logs` may use GORM `AutoMigrate`.
- Migrations run at backend startup and are verified through `migration_logs`.
- Use expand → backfill → contract for removals, renames, type changes, and new
  `NOT NULL` constraints.
- Follow [`../.claude/commands/schema-change.md`](../.claude/commands/schema-change.md).

## Production deployment

The only active release path is the K3s procedure in
[`../.claude/specs/SPEC-deployment-k3s.md`](../.claude/specs/SPEC-deployment-k3s.md).

- Production Deployment/container: `authsec-prod/prod-authsec` / `prod-authsec`.
- Build the local working tree as an immutable `linux/amd64` image.
- Back up Postgres before any release containing migrations.
- Roll out backend before the matching UI and verify health, migrations, OAuth
  metadata, and protected routes.
- Pushing `authsec-staging` does not deploy the cluster.

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

Run the backend gates in [`../.claude/DEFINITION-OF-DONE.md`](../.claude/DEFINITION-OF-DONE.md).
Do not push without explicit per-command approval.
