# Migration Redesign Spec

> Historical note: this spec was written before the V3 cutover. The live system
> now runs a V3 baseline with unified `scopes`/`scope_permissions`/`role_scopes`,
> no `mfa_methods` authority, and no runtime use of the old or V2 migration
> trees. Keep the body as design rationale and removal history, not as a
> statement of the current runtime wiring.

## Goal

Replace the current patch-heavy migration chain with a minimal, authoritative schema design that:

- keeps login, registration, and admin onboarding stable
- makes route authorization match the permission model that actually exists in code
- stops migrations, repository seeders, and controllers from all trying to define the same schema
- makes tenant database creation deterministic

This is a cleanup spec, not a cosmetic rename pass.

## What Is Broken

### 1. Schema, repair logic, and seed data are mixed together

The current chain contains:

- base schema migrations
- repair migrations such as `fix_*`, `align_*`, `normalize_*`, `allow_*`
- DML permission seeds and backfills
- runtime/controller schema self-healing

That means a fresh environment and an upgraded environment do not converge to the same shape unless every repair path, bootstrap path, and controller fallback runs exactly as expected.

### 2. RBAC is oversized compared to actual route enforcement

The router only enforces these permissions today:

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

Everything else is either:

- guarded only by `AuthMiddleware`
- guarded only by `admin:access`
- seeded but never enforced at the route layer

This is why roles/resources/scopes keep drifting: the permission catalog is much larger than the actual authz surface.

### 3. MFA and WebAuthn have split authority

Current state:

- `credentials` stores WebAuthn credential material and now has `rp_id`
- `mfa_methods` stores a second representation of enabled methods
- tenant TOTP exists in `tenant_totp_secrets`
- legacy TOTP exists in `totp_secrets`
- legacy WebAuthn also exists in `webauthn_credentials`
- login handlers query `mfa_methods`, then fall back to TOTP tables and `credentials`
- `repository/mfa_repository.go` still creates/patches `mfa_methods` at runtime and keys methods by `(client_id, method_type)` instead of a proper per-user authority

This is the main reason the login box keeps breaking.

### 4. Credential ownership is semantically wrong

The `credentials` table uses `client_id`, but code writes inconsistent values into it:

- some paths write `user.ID` into `client_id`
- some paths write `user.ClientID`
- some paths fall back to `tenant.TenantID`

So even after `rp_id` was added, the credential table still does not have a clean ownership model. That is not a migration bug only; it is a schema-contract bug.

### 5. Tenant creation has too many schema paths

Right now tenant schema can come from:

- versioned tenant migrations
- template clone
- direct schema-blob application
- controller-owned creation flows

That guarantees drift over time.

## Design Rules

These rules are non-negotiable if the cleanup is supposed to last.

- Base migrations must already contain the final agreed schema.
- No controller, repository, or service may create or alter tables at runtime.
- Permission/bootstrap DML does not belong in the structural migration chain.
- One concern, one authority:
  - route authz authority: `permissions(resource, action)`
  - role assignment authority: `role_bindings`
  - WebAuthn credential authority: one credential table
  - TOTP authority: one TOTP table per database class
- One tenant provisioning path:
  - build tenant schema from versioned tenant migrations
  - derive the tenant template from that schema
  - never maintain an unrelated schema blob by hand

## Actual API Surface And Required Schema

### Admin auth and onboarding

Routes:

- `/authsec/uflow/auth/admin/*`
- `/authsec/uflow/admin/*`
- `/authsec/scim/v2/admin/*`

Required master tables:

- `tenants`
- `users`
- `pending_registrations`
- `otp_entries`
- `roles`
- `permissions`
- `role_permissions`
- `role_bindings`
- `tenant_domains`

Notes:

- Additional admins must be created by adding user rows plus `admin` role bindings.
- `is_primary_admin` should be a bootstrap-owner flag only. It should protect against deleting the original owner, but it must not be the mechanism that limits how many admins can exist.

### End-user auth and login box

Routes:

- `/authsec/uflow/auth/enduser/*`
- `/authsec/uflow/user/*`
- `/authsec/webauthn/*`

Required tenant tables:

- `users`
- `clients`
- `pending_registrations` if tenant-local flows are kept
- `credentials` or renamed authoritative WebAuthn credential table
- one TOTP authority table
- `webauthn_sessions`
- `oauth_sessions` where OAuth login is involved

Current risk:

- `mfa_methods`, `credentials`, `tenant_totp_secrets`, `totp_secrets`, and `webauthn_credentials` overlap.

### OIDC and SAML

Routes:

- `/authsec/uflow/oidc/*`
- `/authsec/hmgr/*`
- `/authsec/oocmgr/*`

Required master tables:

- `oidc_providers`
- `oidc_states`
- `oidc_user_identities`
- `oauth_sessions`
- `tenants`
- `tenant_domains`

Required day-one columns:

- `oidc_states.request_host`

### Clients and external services

Routes:

- `/authsec/clientms/*`
- `/authsec/exsvc/services/*`

Required tenant tables:

- `clients`
- `external_services`
- `groups`
- `user_groups`

Required master tables:

- `tenant_mappings`
- RBAC core tables for admin seeding only if that behavior is retained

Notes:

- Most client routes are only authenticated, not permission-guarded.
- `clients:*` permissions are largely seed-time fiction except `clients:admin`.

### Delegation and SDK tokens

Routes:

- `/authsec/uflow/delegation-policies/*`
- `/authsec/uflow/admin/agents/*`
- `/authsec/uflow/sdk/delegation-token`

Required tenant tables:

- `delegation_policies`
- `delegation_tokens`
- `clients`

Required authz tables:

- `roles`
- `permissions`
- `role_permissions`
- `role_bindings`

Notes:

- Current delegation helpers still read `scopes` and `role_scopes`; if delegation survives, that feature needs either a clean scope model or a rewrite to plain permissions.

### Device, voice, TOTP, and CIBA

Routes:

- `/authsec/uflow/auth/device/*`
- `/authsec/uflow/auth/voice/*`
- `/authsec/uflow/auth/totp/*`
- `/authsec/uflow/auth/ciba/*`
- `/authsec/uflow/auth/tenant/*`

Required master/tenant tables must be explicit feature packs, not accidental leftovers.

Master feature pack candidates:

- `device_codes`
- `voice_sessions`
- `voice_identity_links`
- `ciba_auth_requests`
- one admin/global TOTP authority

Tenant feature pack candidates:

- `tenant_device_tokens`
- `tenant_ciba_auth_requests`
- `tenant_totp_secrets`
- `tenant_totp_backup_codes`

## Minimal Authoritative Schema

### RBAC core that should remain

Keep:

- `roles`
- `permissions`
- `role_permissions`
- `role_bindings`

Make these authoritative:

- route middleware resolves against `permissions.resource` + `permissions.action`
- every user/service assignment goes through `role_bindings`

### Optional, not core authz

Keep only if the product actually needs them:

- `groups`
- `user_groups`
- `api_scopes`
- `api_scope_permissions`
- `scopes`

Move out of core authz:

- `api_scopes` are OAuth contracts, not route permissions
- `scopes` must not be required to authorize routes unless middleware truly depends on them

### Remove or deprecate

Remove after code migration:

- `user_roles`
- `resources`
- `resource_methods`
- `scope_resource_mappings`
- denormalized `role_name`, `username`, and `full_permission_string` bandage columns if they are only there to cover legacy queries

Treat as legacy duplicates:

- `webauthn_credentials`
- any route logic still depending on `user-rbac-*`, `user-permissions`, `user-groups`, `user-clients`, `user-projects`, `user-endusers` resource namespaces

## MFA And WebAuthn Cleanup

### Required target state

For stability, pick one of these models and stick to it:

1. Keep `mfa_methods` as the authority.
2. Remove `mfa_methods` as the authority and derive MFA status from method-specific tables.

The better long-term option is `2`.

Reason:

- method-specific tables already hold the real state
- `mfa_methods` is currently polluted by runtime DDL and the wrong uniqueness model
- it is easier to build a stable read model or view than to keep synchronizing multiple authorities

### WebAuthn credential contract

If `credentials` stays, it should be rewritten to represent a user-owned credential clearly:

- `id`
- `tenant_id`
- `user_id`
- `client_id` only if truly needed by product semantics
- `rp_id` not null
- `credential_id` unique
- `public_key`
- `attestation_type`
- `aaguid`
- `sign_count`
- `transports`
- `backup_eligible`
- `backup_state`
- `created_at`
- `updated_at`

Current `client_id` overloading must stop. `user_id` has to exist from the first migration if the table is used as a user credential store.

### TOTP contract

Master/admin auth and tenant/end-user auth must not share an ambiguous table contract.

Choose:

- master/admin: one TOTP table
- tenant/end-user: one tenant TOTP table

Do not keep both `totp_secrets` and `tenant_totp_secrets` active for the same product flow unless they represent different database classes on purpose.

## Proposed V2 Migration Set

### Master

1. `master/001_base_core.sql`
2. `master/002_base_rbac.sql`
3. `master/003_admin_auth.sql`
4. `master/004_oidc_saml.sql`
5. `master/005_operations.sql`

### Tenant

1. `tenant/001_base_core.sql`
2. `tenant/002_base_rbac.sql`
3. `tenant/003_enduser_auth.sql`
4. `tenant/004_clients_groups.sql`

### Optional feature packs

1. `feature/010_api_scopes.sql`
2. `feature/020_delegation.sql`
3. `feature/030_device_auth.sql`
4. `feature/050_export_configs.sql`

### Bootstrap, not schema

1. `seed/001_bootstrap_admin_permissions.sql`
2. `seed/002_bootstrap_default_roles.sql`

These must be idempotent bootstrap jobs, not structural migrations.

## Existing Migration Disposition

### Fold into the new base

Master:

- `000_comprehensive_base_schema.sql`
- `002_add_migration_tracking_to_tenants.sql`
- `003_create_oauth_sessions.sql`
- `004_add_deleted_at_to_tenant_hydra_clients.sql`
- `005_add_brute_force_columns.sql`
- `006_add_rp_id_to_credentials.sql`
- `007_add_request_host_to_oidc_states.sql`

Tenant:

- `000_tenant_template.sql`
- `002_make_name_fields_optional.sql`
- `011_create_oauth_sessions.sql`
- `013_add_rp_id_to_credentials.sql`
- `014_add_brute_force_columns.sql`
- `015_normalize_oauth_sessions_schema.sql`

RBAC:

- only the real core from `102`, `107`, `114`, `119`

### Keep as feature packs after rewrite

- master `001_create_fluent_bit_export_configs.sql`
- master `118_create_api_scopes.sql`
- tenant `004_create_api_scopes_tenant.sql`
- tenant `017_create_tenant_device_auth_tables.sql`
- tenant `018_create_delegation_tables.sql`

### Retire

- `104_enforce_scoped_rbac.sql`
- `105_allow_global_rbac.sql`
- `108_add_role_name_to_role_bindings.sql`
- `109_add_full_permission_string.sql`
- `110_role_bindings_username_role_scope_defaults.sql`
- `111_add_username_rolename_to_tenant_role_bindings.sql`
- `115_drop_role_bindings_scope_integrity.sql`
- `124_fix_api_scopes_tenant_fk.sql`
- tenant `005_fix_api_scopes_tenant_fk.sql`
- tenant `006_add_role_bindings_username_role_name.sql`
- tenant `016_create_scope_resource_mappings.sql`

### Move out of schema chain

- master `1004_dml_001_initial_data.sql`
- master `1005_dml_002_test_data.sql`
- permissions/master `079`, `082`, `103`, `113`, `117`, `125`, `200`, `201`
- tenant `009_dml_100_seed_external_service_rbac.sql`
- tenant `010_dml_003_admin_permissions.sql`

## What Needs To Change In Code, Not Just SQL

### Route authz

Either:

- shrink seeded permissions to match real route guards

or:

- add route guards that truly enforce the larger permission model

Keeping the current mismatch is the worst option.

### MFA repository

`repository/mfa_repository.go` must stop doing DDL at runtime and must stop treating `(client_id, method_type)` as the unique identity of a user MFA method.

### Scope system

If `scopes` survives, the code using `role_scopes` must be aligned with the final schema. Right now it behaves like a half-removed feature.

### Migration APIs

`/authsec/migration/*` should not be protected by plain auth only. They need explicit admin authorization.

### Tenant provisioning

Keep one authoritative flow:

1. run master migrations
2. build tenant template from versioned tenant migrations
3. create tenant DB from that template
4. backfill migration logs deterministically

No parallel schema author should remain.

## Execution Checklist

- [ ] Freeze new patch migrations until the redesign branch exists.
- [ ] Write the V2 master base migrations.
- [ ] Write the V2 tenant base migrations.
- [ ] Move permission bootstrap out of structural migrations.
- [ ] Remove runtime DDL from repositories and controllers.
- [ ] Rewrite the credential contract to include correct ownership from day one.
- [ ] Decide the final MFA authority and delete the duplicate one.
- [ ] Remove `user_roles` fallback code.
- [ ] Remove `resources` and `resource_methods` after caller migration.
- [ ] Decide whether `scopes` is a first-class feature or dead weight.
- [ ] Lock tenant creation to one path.
- [ ] Add schema-contract tests for admin auth, end-user login, OIDC, clients, external services, delegation, and migration status.
