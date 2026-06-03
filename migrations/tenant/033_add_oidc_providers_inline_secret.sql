-- 033_add_oidc_providers_inline_secret.sql
--
-- Adds an inline client_secret column to tenant.oidc_providers, matching
-- the per-tenant trust-boundary pattern already used by
-- tenant_hydra_clients.hydra_client_secret (plaintext, in-DB).
--
-- Why: the existing client_secret_vault_path requires a Vault deployment
-- per environment and we don't currently have one wired up. Storing the
-- secret in-row keeps Google/GitHub/Microsoft creds in the same trust
-- boundary as the rest of the tenant's data — same backup, same access
-- controls, same encryption-at-rest as the Postgres volume.
--
-- The vault path column stays (nullable) so a future Vault deployment can
-- migrate values out without a schema change.
--
-- federated_login_service.go reads inline first, falls back to Vault,
-- then to env-var (loadClientSecret is updated in the same commit).

ALTER TABLE oidc_providers
  ALTER COLUMN client_secret_vault_path DROP NOT NULL,
  ADD COLUMN IF NOT EXISTS client_secret TEXT NULL;
