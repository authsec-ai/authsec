-- ============================================================================
-- 119: workload_identity_providers.issuer unique per workspace (AS-060)
--
-- A public issuer (GitHub Actions, a shared SPIRE server) could be federated
-- by one workspace only. The token endpoint now tries every active provider
-- registered for a token's issuer, each verifying the signature, audience and
-- trust domain and mapping the subject within its own workspace, and accepts
-- the token only when exactly one provider does (services/client_auth.go
-- authenticateSPIFFESVID). Expand first: the per-workspace unique index is
-- created before the global one is dropped.
--
-- Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS uq_wip_workspace_issuer
    ON public.workload_identity_providers (workspace_id, issuer);
DROP INDEX IF EXISTS public.uq_wip_issuer;
CREATE INDEX IF NOT EXISTS idx_wip_issuer ON public.workload_identity_providers (issuer);
