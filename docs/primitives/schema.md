# Schema — versioned migrations

> Read this before touching any table definition, adding a column, or running
> a migration. Files: `migrations/master/`.

## The one rule

**The production database is never wiped. Every change ships as a numbered
migration.**

There are customers in that database; losing it is not a recoverable mistake.

Two files change together for every schema change:

| File | Who it serves | Why |
|---|---|---|
| `migrations/master/NNN_description.sql` | **Existing** databases | The runner applies it in order on boot and records it |
| `migrations/master/001_bootstrap.sql` | **Fresh** databases | One-shot creation of the current state |

They must describe the same end state. Bootstrap answers *"what is the schema"*;
the numbered migration answers *"how does an older database get there"*.

## How migrations actually run

`internal/migration/runner.go`, invoked from `cmd/main.go` at startup:

1. Reads every `*.sql` in `migrations/master/`, sorted by the numeric prefix.
2. Parses `NNN_name.sql` — the number is the version, the rest is the name.
3. Skips anything already recorded in `migration_logs` as `success = true`.
4. Runs the rest, then logs version, name, duration, and outcome.

So a migration is **applied automatically on the next deploy**, exactly once, and
is auditable afterwards. You do not run `psql` by hand.

```sql
-- what has actually been applied
SELECT version, name, executed_at, success FROM migration_logs ORDER BY version;
```

`migration_logs` is the only table GORM may manage via `AutoMigrate`. Everything
else is owned by the migration files.

## Writing a migration

- **Number it next.** `002_`, `003_`, … Never reuse or renumber a version that has
  shipped; the ledger keys on it.
- **Make it re-runnable.** `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`,
  `ON CONFLICT DO NOTHING`. The runner won't re-run it, but a partly-applied
  migration must be safe to retry.
- **One concern per file**, so a failure is easy to reason about.
- **Say why in a comment.** The file is the permanent record of the decision.

## Expand and contract

The dangerous part of a schema change is not the SQL, it is the window where the
running code and the schema disagree. Sequence by direction:

**Adding** — migrate first, deploy second. New code needs the column; old code
ignores it. A nullable column, a new table, or a new index is safe to apply while
the old build is live.

**Removing or tightening** — deploy first, migrate second, and split it across two
releases:

1. **Expand** — add the new column nullable; deploy code that writes both old and
   new.
2. **Backfill** — populate the new column in batches.
3. **Contract** — once nothing reads the old column, deploy code that stops using
   it, *then* drop it or add `NOT NULL`.

Adding `NOT NULL` to a populated table, dropping a column still referenced by the
running binary, or renaming anything in one step will take production down. There
is no version of this that is safe as a single step.

## Before you touch a deployed database

Production PostgreSQL runs in the `database-prod` namespace on the K3s cluster.
Create and verify the backup on `k3s-master` before deploying any schema-changing
backend image:

```bash
mkdir -p /root/backups
AUTHSEC_BACKUP_PATH=/root/backups/authsec-pre-migration-$(date +%Y%m%dT%H%M%S).dump
kubectl exec -n database-prod postgresql-primary-0 -- sh -c \
  'export PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -Fc' \
  > "$AUTHSEC_BACKUP_PATH"
test -s "$AUTHSEC_BACKUP_PATH" && sha256sum "$AUTHSEC_BACKUP_PATH"
```

A backup you have not restored is a hypothesis. For anything beyond a purely
additive change, restore it into a scratch database and check the row counts
before you proceed. Do that in an isolated non-production PostgreSQL instance;
never create a restore-test database inside the production cluster.

## Table domains

90 tables, grouped by domain:

### Core identity & workspace
| Table | Purpose |
|---|---|
| `workspaces` | Top-level tenant unit |
| `workspace_memberships` | User ↔ workspace binding (M2M) |
| `users` | Human identities (email, profile_data jsonb) |
| `groups` / `user_groups` | Group memberships |

### OAuth clients & registration
| Table | Purpose |
|---|---|
| `mcp_oauth_clients` | Authoritative OAuth client registry (DCR + pre-registered). `home_workspace_id`, `hydra_client_id`, `sync_status`. |
| `oauth_client_secrets` | Hashed secrets for `client_secret_basic` auth |
| `oauth_client_jwks` | Public keys for `private_key_jwt` auth |
| `client_assertion_replay_cache` | Anti-replay for JWT client assertions |

### Applications (resource servers)
| Table | Purpose |
|---|---|
| `resource_servers` | Protected resources (`workspace_id NOT NULL`, `resource_uri`, `scopes_supported jsonb`, `application_type`) |
| `resource_server_access_policies` | Access control policy per RS |
| `resource_server_client_registrations` | Client ↔ RS registration (first-contact gate) |
| `resource_server_drift_events` / `_dismissals` / `_manifest_attempts` | RS manifest drift tracking |
| `application_spiffe_identities` | SPIFFE identity attached to an RS |
| `application_identity_provider_policies` | Which IdP is enabled for which application |

### RBAC & scopes
| Table | Purpose |
|---|---|
| `roles` | Named roles per workspace + RS |
| `permissions` | Named permissions (resource + action) |
| `role_permissions` | Role → permission M2M |
| `oauth_scopes` | OAuth scope values registered per workspace + RS |
| `oauth_scope_permissions` | Permission → scope M2M |
| `role_bindings` | Subject (user / group / service_account) → role for workspace + RS |
| `role_assignment_requests` | Pending role assignment requests (approve-with-role flow) |
| `scope_catalog_entries` | Preset/catalog scope definitions |
| `mcp_tool_scope_map` | Tool → scope mapping for MCP tools |
| `mcp_tools` | MCP tool definitions per RS |

### Native token engine
| Table | Purpose |
|---|---|
| `native_tokens` | Metadata-only registry for native access tokens (no raw token stored). Authoritative for introspection. `token_family` CHECK IN ('xaa','m2m','ciba'). No FK on workspace_id/resource_server_id (append-only audit). |
| `id_jag_replay_cache` | One-shot redemption guard for ID-JAG assertions, keyed per `(iss, jti)`. |
| `revoked_tokens` | Revocation source of truth (if `revoked_tokens` and `native_tokens.revoked_at` disagree, `revoked_tokens` wins). |

### Authorization flows
| Table | Purpose |
|---|---|
| `auth_request_contexts` | Server-side auth context for PKCE/authorize flow (10-min TTL, `consumed` flag) |
| `oauth_consent_grants` | Stored consent grants |
| `pkce_verifiers` | PKCE code verifier storage |
| `access_requests` | XAA access-pending requests (first-contact + approve-with-role) |
| `ciba_auth_requests` | CIBA authentication requests |
| `workspace_ciba_auth_requests` | Workspace-plane CIBA (backchannel) requests |
| `device_codes` / `device_tokens` / `workspace_device_tokens` | OAuth device flow |
| `authorization_decision_logs` | Low-level authz decision audit |

### Identity providers & federation
| Table | Purpose |
|---|---|
| `identity_providers` | OIDC/SAML IdPs per workspace |
| `oidc_providers` | OIDC provider config |
| `oidc_user_identities` | User ↔ OIDC federation link |
| `oidc_states` | OIDC flow state |
| `saml_providers` / `saml_requests` / `saml_callback_states` / `saml_sp_certificates` | SAML SP support |
| `trusted_issuers` | External issuers trusted for XAA |
| `workload_identity_providers` | OIDC/CI workload identity providers (GitHub Actions, etc.) |
| `a2a_brokering_policies` | A2A cross-app permit/deny policies |

### SPIRE / workloads
| Table | Purpose |
|---|---|
| `spire_workloads` | Registered SPIFFE workloads |
| `workload_entries` | SPIRE workload entries (selectors, TTL, SpireEntryID) |
| `spire_oidc_tokens` | JWT-SVID metadata for revocation tracking |
| `spire_audit_logs` | SPIRE-specific audit events |
| `spire_policies` / `spire_policy_rules` / `_actions` / `_conditions` / `_resources` / `_subjects` | SPIRE policy engine |
| `spire_role_bindings` | SPIFFE identity → role bindings |
| `delegation_policies` / `delegation_tokens` | Workload delegation policies |

### Service accounts
| Table | Purpose |
|---|---|
| `service_accounts` | Machine identities (name, workspace_id, resource_server_id, external_subject, owner, contact) |

### SCIM
| Table | Purpose |
|---|---|
| `scim_connections` | SCIM 2.0 provisioning connections |
| `scim_events` | SCIM event log |
| `sync_configurations` / `sync_runs` | SCIM sync state |

### Auth methods
| Table | Purpose |
|---|---|
| `credentials` | Stored credentials |
| `mfa_methods` | MFA method registrations |
| `webauthn_sessions` | WebAuthn ceremony state |
| `totp_secrets` / `totp_backup_codes` | TOTP |
| `workspace_totp_secrets` / `workspace_totp_backup_codes` | Workspace-plane TOTP (admin login) |
| `otp_entries` | One-time passwords |
| `pending_registrations` | Pre-registration (onboarding) state |

### Voice / risk
| Table | Purpose |
|---|---|
| `voice_sessions` / `voice_identity_links` | Voice authentication |
| `risk_policies` | Risk engine policies |

### Audit & logs
| Table | Purpose |
|---|---|
| `audit_events` | Authentication + admin mutation events |
| `auth_issuance_audit` | M2M token issuance records |
| `agent_action_audit_log` / `agent_action_decisions` / `agent_action_requests` / `agent_guard_settings` | Agent Shield audit |

### Misc / internal
| Table | Purpose |
|---|---|
| `workspace_domains` | Workspace-owned domain records |
| `workspace_end_user_states` | End-user state per workspace |
| `services` | Service registry |

## How to change the schema

1. Find the highest shipped migration number and add
   `migrations/master/NNN_description.sql` with the next number.
2. Update `migrations/master/001_bootstrap.sql` so a fresh database reaches the
   same final schema.
3. Test both paths: upgrade an existing database with the numbered migration and
   initialize a fresh scratch database from bootstrap.
4. Back up production as described above.
5. Deploy the immutable backend image through the K3s procedure in
   `../../../.claude/specs/SPEC-deployment-k3s.md`. The migration runner applies
   and records the change on startup.
6. Verify the backend rollout, health endpoint, and the new successful row in
   `migration_logs` before deploying any dependent UI change.

Production is never reinitialized for a schema change. Do not execute ad-hoc DDL
against it and do not insert fake success rows into `migration_logs`.

**Never** add `AutoMigrate` calls for non-`migration_logs` tables. GORM will diverge from the hand-curated schema.

## Related

`primitives/token-engine.md` (`native_tokens`, `revoked_tokens`, `id_jag_replay_cache`),
`primitives/rbac-scopes.md` (roles/permissions/scopes tables), `primitives/spire.md`
(spire_* tables).
