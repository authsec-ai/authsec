# Migration Audit Checklist

> Historical note: most of this document captures the pre-surgery audit state.
> The active runtime now boots only from `migrations/v3/master/{000_schema,100_seed}.sql`
> and `migrations/v3/tenant/{000_schema,100_seed}.sql`. `mfa_methods`,
> `api_scopes`, and `scope_resource_mappings` are no longer physical tables in
> the active schema. Read the checklist below as background on what was removed,
> not as the current live state unless explicitly updated.

## Current Status

- [x] Mapped the runtime migration flow from startup to tenant database bootstrap.
- [x] Mapped the major API families to their master and tenant schema dependencies.
- [x] Mapped the actual route-enforced permission surface across the codebase.
- [x] Classified the existing migration files into base schema, feature packs, seed/backfill, and patch churn.
- [x] Identified a duplicate tenant migration version that can silently skip a migration.
- [x] Identified startup behavior that serves traffic even when master migrations fail.
- [x] Identified template-clone behavior that reports `completed` before clone finalization finishes.
- [x] Identified tenant database lookup drift between `tenants.id` and `tenants.tenant_id`.
- [x] Added a master migration for the missing `oidc_states.request_host` column.
- [x] `go build ./...` passes after the guardrail changes.
- [x] Added a runtime curl/Postman QA checklist in `docs/runtime-qa-curls.md`.
- [ ] Unify tenant database creation to one authoritative path.
- [x] Removed controller/runtime schema self-healing for `ensureScopeResourceMappingsSchema`, `mfa_methods` auto-create, and audit-table auto-create.
- [ ] Remove remaining runtime schema patch paths such as SPIRE `AutoMigrate` and `oauth_sessions` column patching.
- [ ] Resolve `mfa_methods` schema and repository contract drift.
- [ ] Resolve auth table gaps for device, voice, TOTP, and CIBA flows in the master database.
- [ ] Consolidate RBAC seeding so migrations and repositories stop racing to define the same permissions.
- [ ] Replace the current migration chain with a clean base-plus-feature-pack design.
- [ ] Remove permission/resource structures that are not authoritative for route enforcement.

## Redesign Snapshot

- The current schema chain mixes four different concerns in one place: base DDL, repair migrations, permission/bootstrap DML, and runtime/controller self-healing.
- Actual route enforcement is much smaller than the seeded RBAC catalog. The only route-enforced permissions today are:
  - `admin:access`
  - `admin:manage`
  - `users:delete`
  - `tenants:delete`
  - `clients:admin`
  - `external-service:create`
  - `external-service:read`
  - `external-service:update`
  - `external-service:delete`
  - `external-service:credentials`
- Everything else is either guarded only by auth, guarded only by `admin:access`, or exists as compatibility baggage.
- The clean target should have:
  - one authoritative RBAC core: `roles`, `permissions`, `role_permissions`, `role_bindings`
  - optional feature packs for `api_scopes`, delegation, and device auth
  - no controller/repository DDL
  - no permission DML mixed into the versioned schema chain
  - final columns present from day one, including `credentials.rp_id`, `oidc_states.request_host`, brute-force columns, and role timestamp defaults
- The full redesign is documented in [migration-redesign-spec.md](/Users/pc/Desktop/authnull/authsec/docs/migration-redesign-spec.md).

## Migration Flow

1. `cmd/main.go` initializes the master DB, creates `migration_logs` with explicit SQL, then runs V2 master migrations through `internal/migration/runner.go`.
2. If master migrations succeed, startup also launches the V2 tenant template builder in the background with `internal/migration/template_builder.go`.
3. Tenant DB creation still has multiple paths:
   - `database/tenant_db_service.go`: creates a DB and runs versioned tenant migrations in-process.
   - `controllers/admin/migration_controller.go`: creates a DB, then runs tenant migrations sync or async.
   - `controllers/admin/migration_controller.go` template clone path: clones `_authsec_tenant_template`, then rewrites the synthetic tenant ID.
   - `services/tenant_db_service.go`: applies a schema blob directly instead of versioned migrations.
4. Admin and OIDC registration flows commit master records first, then treat tenant DB provisioning as post-commit best effort.
5. Many APIs assume master `tenant_mappings` plus a fully migrated tenant DB exist before the first request.

## Migration Inventory

### Master DB migrations

- `000_comprehensive_base_schema.sql`: base master schema for tenants, users, RBAC, OIDC, clients, pending registrations, OTP, and many shared tables.
- `001_create_fluent_bit_export_configs.sql`: log export config table.
- `002_add_migration_tracking_to_tenants.sql`: adds `migration_status` and `last_migration` style tracking to `tenants`.
- `003_create_oauth_sessions.sql`: master-side OAuth session support.
- `004_add_deleted_at_to_tenant_hydra_clients.sql`: soft delete support for Hydra client rows.
- `005_add_brute_force_columns.sql`: lockout and failed-login columns on `users`.
- `006_add_rp_id_to_credentials.sql`: adds `credentials.rp_id`.
- `007_add_request_host_to_oidc_states.sql`: adds the missing column used by OIDC state persistence.
- `1004_dml_001_initial_data.sql`: base RBAC seed data.
- `1005_dml_002_test_data.sql`: test fixture data.

### Master permissions migrations

- `079_add_admin_users_active_permission.sql`: `users:active` permission.
- `082_add_admin_users_delete_permission.sql`: `users:delete` permission.
- `102_scoped_rbac_schema.sql`: scoped RBAC schema rollout.
- `103_add_user_flow_permissions.sql`: user-flow permission seed.
- `104_enforce_scoped_rbac.sql`: stricter scoped RBAC enforcement.
- `105_allow_global_rbac.sql`: allows nullable/global RBAC entities.
- `107_align_rbac_schema.sql`: aligns RBAC tables to current shape.
- `108_add_role_name_to_role_bindings.sql`: denormalized `role_name`.
- `109_add_full_permission_string.sql`: denormalized permission string.
- `110_role_bindings_username_role_scope_defaults.sql`: `username` and scope defaults on `role_bindings`.
- `111_add_username_rolename_to_tenant_role_bindings.sql`: tenant RBAC denormalization follow-up.
- `113_add_admin_wildcard_role_bindings.sql`: wildcard admin bindings in the master DB.
- `114_fix_roles_timestamps.sql`: timestamp defaults on `roles`.
- `115_drop_role_bindings_scope_integrity.sql`: relaxes `role_bindings` constraint.
- `117_external_service_permissions.sql`: external-service permission seed.
- `118_create_api_scopes.sql`: master `api_scopes` and related mappings.
- `119_fix_permissions_unique_constraint.sql`: aligns `permissions` unique constraint with repository upserts.
- `124_fix_api_scopes_tenant_fk.sql`: drops `api_scopes.tenant_id` FK in master.
- `125_reseed_tenant_admin_permissions.sql`: reseeds admin permissions for tenants.
- `200_add_migration_service_permissions.sql`: RBAC for migration APIs.
- `201_add_create_tenant_from_template_permission.sql`: RBAC for template clone.

### Tenant DB migrations

- `000_tenant_template.sql`: full tenant schema snapshot used as the base template.
- `001_add_is_primary_admin_field.sql`: adds `users.is_primary_admin`.
- `002_make_name_fields_optional.sql`: relaxes name requirements for pending registrations.
- `003_enforce_scoped_rbac_tenant.sql`: tenant scoped RBAC reset and rebuild.
- `004_create_api_scopes_tenant.sql`: tenant `api_scopes`.
- `005_fix_api_scopes_tenant_fk.sql`: drops tenant FK on `api_scopes`.
- `006_add_role_bindings_username_role_name.sql`: aligns tenant `role_bindings` columns and defaults.
- `009_dml_100_seed_external_service_rbac.sql`: external-service RBAC seed in tenant DBs.
- `010_dml_003_admin_permissions.sql`: tenant admin permission seed.
- `011_create_oauth_sessions.sql`: tenant OAuth sessions.
- `013_add_rp_id_to_credentials.sql`: adds `credentials.rp_id`.
- `014_add_brute_force_columns.sql`: lockout columns on tenant `users`.
- `015_normalize_oauth_sessions_schema.sql`: aligns tenant OAuth sessions with SDK manager.
- `016_create_scope_resource_mappings.sql`: creates `scope_resource_mappings`.
- `017_create_tenant_device_auth_tables.sql`: tenant CIBA and tenant TOTP device-auth tables.
- `018_create_delegation_tables.sql`: tenant delegation policy/token tables.

## API Dependency Map

- Admin auth: `/authsec/uflow/auth/admin/*` depends on master `tenants`, `users`, `pending_registrations`, `otp_entries`, `roles`, `role_bindings`, `permissions`, then tenant `tenants`, `users`, `projects`, `clients`.
- OIDC public/authenticated: `/authsec/uflow/oidc/*` depends on master `oidc_providers`, `oidc_states`, `oidc_user_identities`, `tenant_mappings`, `tenants`, and then tenant bootstrap tables.
- Login box and end-user registration: `/authsec/uflow/user/login`, `/register/*` depend on master `tenant_mappings`, `pending_registrations`, `otp_entries`, and tenant `users`, `clients`, `mfa_methods`, `tenant_totp_secrets`, `credentials`.
- Client management: `/authsec/clientms/*` depends on tenant `clients`, `projects`, `client_roles`, `client_groups`, plus master `tenant_mappings` and RBAC tables.
- Scopes and API scopes: admin scope APIs use master `scopes`, `scope_resource_mappings`, `api_scopes`, `api_scope_permissions`; tenant scope APIs use the tenant equivalents.
- Device, voice, TOTP, and CIBA auth: routes exist in `routes/routes.go`, but several repository tables are not created by the current master migration pack.
- Delegation and SDK token APIs: tenant `delegation_policies` and `delegation_tokens` are required, so missing migration `018` breaks those endpoints.

## Migration Churn To Eliminate

- Fold into new base migrations instead of keeping as standalone repairs:
  - master `002`, `004`, `005`, `006`, `007`
  - permissions/master `107`, `114`, `119`
  - tenant `001`, `002`, `011`, `013`, `014`, `015`
- Delete or rewrite the RBAC bandage migrations:
  - permissions/master `104`, `105`, `108`, `109`, `110`, `111`, `115`
  - tenant `003` in its current destructive form
  - tenant `006`
  - tenant `016`
- Move DML seed/backfill out of the schema chain:
  - master `1004`, `1005`
  - permissions/master `079`, `082`, `103`, `113`, `117`, `125`, `200`, `201`
  - tenant `009`, `010`
- Keep only as explicit optional feature packs after rewrite:
  - master `001` fluent-bit export configs
  - permissions/master `118` and tenant `004` for `api_scopes`
  - tenant `017` device auth
  - tenant `018` delegation

## Cleanup Checklist

- [ ] Collapse master base schema and repair migrations into one rewritten `master_base_core.sql`.
- [ ] Collapse tenant base schema and repair migrations into one rewritten `tenant_base_core.sql`.
- [ ] Rebuild tenant RBAC as a clean migration instead of destructive drop/recreate logic.
- [ ] Decide whether `scopes` is a real product feature or a removable compatibility layer.
- [ ] Remove `user_roles` fallback reads and make `role_bindings` the only role-assignment authority.
- [ ] Remove `resources` and `resource_methods` once old repository code is rewritten to use `permissions(resource, action)`.
- [ ] Replace `mfa_methods` as an authority with either a proper per-user table or a derived read model.
- [ ] Normalize WebAuthn credential ownership so `credentials` is no longer overloaded through `client_id`.
- [ ] Keep `is_primary_admin` only as a bootstrap-owner guardrail, not as an admin-creation bottleneck.
- [ ] Gate `/authsec/migration/*` behind explicit admin permissions instead of plain auth.

## Failures and Root Causes

- Duplicate tenant migration version `013` allowed a silent migration skip.
- Startup previously continued serving traffic after failed master migrations.
- `GetMigrationStatus` counted tenant template `000` as a runnable migration even though it is executed outside migration logs.
- Template clone path reported `completed` before synthetic tenant ID rewrite finished and before migration logs were backfilled.
- Tenant DB resolution used only `tenants.tenant_id`, but other code paths sometimes use `tenants.id`.
- OIDC repository writes `oidc_states.request_host`, but the base master schema did not create that column.
- `mfa_methods` is inconsistent across schema, repositories, handlers, and services; this remains unresolved.
- Auth device/voice/TOTP/CIBA repositories expect master tables that are not in the current master migration set; this remains unresolved.
- RBAC permissions are seeded by migrations and also by repositories/controllers, so the source of truth is still split.

## Stabilization Plan

- Keep one authoritative tenant schema path: versioned tenant migrations plus template clone built from those migrations.
- Fail startup on master migration failure and fail runners on the first broken migration.
- Keep migration versions globally unique within each runnable migration set.
- Backfill tenant migration logs for template clones so status endpoints stay truthful.
- Add a schema drift test suite that checks route-critical tables and columns before release.
- Move RBAC seed ownership into one place and delete overlapping seeders after parity is confirmed.
- Fix `mfa_methods` around a per-user uniqueness model, then align all repository and handler upserts to that contract.
