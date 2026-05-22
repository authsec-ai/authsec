-- Migration: 126_drop_saml_providers_client_id.sql
-- Description:
--   The legacy "SAML per-client within a tenant" scoping is replaced by
--   application_identity_provider_policies. saml_providers rows are now
--   workspace-scoped (via tenant_id == workspace_id), and per-Application
--   restriction is opt-in via the policy table. The client_id column on
--   saml_providers — and on its transient state tables (saml_requests,
--   saml_callback_states) — is dead weight.

DROP INDEX IF EXISTS idx_saml_providers_client_id;
DROP INDEX IF EXISTS idx_saml_requests_client_id;
DROP INDEX IF EXISTS idx_saml_requests_tenant_client;
DROP INDEX IF EXISTS idx_saml_callback_states_client_id;
DROP INDEX IF EXISTS idx_saml_callback_states_tenant_client;

ALTER TABLE IF EXISTS saml_providers       DROP COLUMN IF EXISTS client_id;
ALTER TABLE IF EXISTS saml_requests        DROP COLUMN IF EXISTS client_id;
ALTER TABLE IF EXISTS saml_callback_states DROP COLUMN IF EXISTS client_id;
