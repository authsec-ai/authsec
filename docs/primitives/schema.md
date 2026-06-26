# Schema — single-state bootstrap

> Read this before touching any table definition, adding a column, or running
> a migration. File: `migrations/master/001_bootstrap.sql`.

## The one rule

**The schema is single-state and forward-only.**

- `001_bootstrap.sql` is the authoritative state. It defines all 90 tables in one
  hand-curated `CREATE TABLE` file (no `pg_dump` output, no ALTER COLUMN sprinkled around).
- **Never add `ALTER TABLE` patch files.** When you need a new column, edit the
  `CREATE TABLE` inline in `001_bootstrap.sql`, wipe the database, and re-bootstrap.
- Future additive migrations land as `002_*.sql`, `003_*.sql` alongside this file.
  The migration runner (`internal/migration/runner.go`) applies them incrementally on
  top of an already-bootstrapped database.
- **`migration_logs` is the only table GORM is allowed to manage** via `AutoMigrate`.
  Everything else is owned by `001_bootstrap.sql`.

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

1. Edit the `CREATE TABLE` statement inline in `001_bootstrap.sql`.
2. Wipe the database: `docker compose down -v` (removes the Postgres volume).
3. Re-bootstrap: `docker compose up -d` (runs migrations on fresh DB).
4. If this is a **new** table being added for the first time and no data exists yet, this is all you need.
5. If the schema is live (production) and you can't wipe, write a `002_<description>.sql` patch file and document it clearly as an additive migration.

**Never** add `AutoMigrate` calls for non-`migration_logs` tables. GORM will diverge from the hand-curated schema.

## Related

`primitives/token-engine.md` (`native_tokens`, `revoked_tokens`, `id_jag_replay_cache`),
`primitives/rbac-scopes.md` (roles/permissions/scopes tables), `primitives/spire.md`
(spire_* tables).
