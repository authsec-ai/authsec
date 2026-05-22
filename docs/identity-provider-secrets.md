# Identity Provider Secret Storage

The `identity_providers.config_ref` column is the **only** field on the
workspace-owned IDP row. Everything else — SAML certificates, OIDC client
secrets, AD service-account passwords — lives outside that row. This file
documents what `config_ref` actually points at and the contract callers
must follow when reading or writing provider configuration.

## Resolution rules per `provider_type`

| `provider_type` | `config_ref` is | Resolved by |
|---|---|---|
| `saml` | `saml_providers.id` (UUID stringified) | `services.IdentityProviderService.ResolveSAMLConfig` |
| `ad`, `entra` | `sync_configurations.id` (UUID stringified) | `services.IdentityProviderService.ResolveSyncConfig` |
| `oidc`, `google` | `oidc_providers.provider_name` (platform-level) | direct lookup via `oidc_providers.provider_name` |
| `scim` | `scim_connections.id` (UUID stringified) | direct lookup |

The IDP row is the **product handle** — what the operator sees in the UI,
what controls whether the provider is enabled or disabled. The legacy
provider-specific tables stay as the **secret stores** for the lifetime of
the transition.

## Secrets

Each downstream table follows its own secret-handling convention:

### `saml_providers`

- `certificate` (text) — IdP signing certificate, PEM-encoded, public. Safe
  to store plaintext.
- No client secret field. SAML uses X.509 cert validation, not bearer
  secrets.

### `sync_configurations`

- `ad_password` (text) — service-account password for LDAP bind.
- `entra_client_secret` (text) — Microsoft Graph API secret.

Both are encrypted with `utils.Encrypt` / decrypted with `utils.Decrypt`
(AES-GCM with a key derived from `AUTHSEC_ENCRYPTION_KEY`). Migration 066
sets up the schema; the encryption is application-layer.

### `oidc_providers`

- `client_secret_vault_path` (text) — Vault KV2 path, e.g.
  `secret/data/oidc/google/clientsecret`.
- Resolved at runtime via `config.VaultClient.GetSecret(path)`. Requires
  Vault to be configured (`config.InitVault`).

### `scim_connections`

- `token_hash` (text) — SHA-256 hex digest of the bearer token. The
  plaintext token is shown exactly once at mint time
  (`POST /authsec/scim-connections`). There is no recovery path — if the
  token is lost, mint a new connection and revoke the old one.

## Decision: AES-encrypted column + Vault dual-track

After auditing, no migration to a unified secret backend is being scheduled.
The reasoning:

1. **SAML** has no secrets — keep certs in `saml_providers.certificate`.
2. **AD / Entra** sync secrets stay AES-encrypted in `sync_configurations`.
   The encryption key (`AUTHSEC_ENCRYPTION_KEY`) is the existing operational
   contract; changing it would force a re-encryption pass across the fleet
   for no security gain.
3. **OIDC** secrets stay in Vault under the existing `client_secret_vault_path`.
   Vault is already in the local-k8s stack and is the right tool for shared
   client secrets that need rotation.
4. **SCIM** tokens stay hashed — there is no recovery scenario where the
   plaintext is needed after mint, so the hash is sufficient.

This is the same model the codebase already implements. The IDP table just
adds the workspace boundary and on/off status on top — it deliberately does
**not** introduce a new secret-handling pattern.

## Future direction

If we move to a unified secret backend later, the migration path is:

1. Add a `secret_ref` column to `identity_providers` (in addition to
   `config_ref`).
2. Write a one-shot tool that walks each IDP row, reads the secret from its
   current home, writes it to the new backend, and populates `secret_ref`.
3. Switch reads to consult `secret_ref` when set, falling back to the legacy
   path.

For now `config_ref` is the only pointer and the legacy tables remain the
source of truth for both secrets and non-secret config.

## Implementation checklist for new IDP types

When adding a new `provider_type`:

1. Decide where the config (including secrets) lives — Vault, a new table,
   or an extension of `sync_configurations`.
2. Add a `Resolve<Type>Config(idp, dest)` method on
   `IdentityProviderService` mirroring the SAML/sync helpers.
3. Update the type-constant block at the top of
   [models/identity_provider.go](../models/identity_provider.go).
4. Add the constant to the migration 117 CHECK constraint (or a follow-up
   ALTER for existing deployments).
5. Add a row to the table above.
