-- ============================================================================
-- 065: auth_lockouts, totp_used_steps
--
-- auth_lockouts counts failed sign-in and second-factor attempts per account
-- (workspace, kind, subject) and records a lock (AS-034, AS-004). Updated with
-- one atomic INSERT ... ON CONFLICT ... RETURNING (internal/lockout); no Redis.
--
-- totp_used_steps records each accepted TOTP time step per user, so a code is
-- accepted once per step (replay protection, AS-004). Rows older than a few
-- minutes are pruned by the writer.
--
-- Both are workspace-owned (ADR-0001): workspace_id NOT NULL with FK, and
-- row-level security through tenancy_enable_rls (054).
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.auth_lockouts (
    workspace_id      uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    kind              text NOT NULL,
    subject           text NOT NULL,
    failures          integer NOT NULL DEFAULT 0,
    window_started_at timestamptz NOT NULL DEFAULT now(),
    locked_until      timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, kind, subject)
);

CREATE INDEX IF NOT EXISTS idx_auth_lockouts_locked_until
    ON public.auth_lockouts (locked_until) WHERE locked_until IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.totp_used_steps (
    workspace_id uuid NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL,
    step         bigint NOT NULL,
    used_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id, step)
);

SELECT public.tenancy_enable_rls('public.auth_lockouts');
SELECT public.tenancy_enable_rls('public.totp_used_steps');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authsec_tenant') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.auth_lockouts, public.totp_used_steps TO authsec_tenant;
    END IF;
END $$;
