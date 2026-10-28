-- 050_enforcement_binding.sql
-- Enforcement A/B: per-agent enforcement binding with backend selection,
-- identity mode, and policy references.
--
-- Additive and re-runnable. No transaction wrapper — each DDL statement is
-- its own implicit transaction in PostgreSQL.

-- Enforcement bindings link discovered agents to enforcement backends.
-- Resolution order: approved agent binding → policy default → workspace default.
CREATE TABLE IF NOT EXISTS public.enforcement_bindings (
    id                          uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id                uuid NOT NULL,
    agent_id                    uuid NOT NULL,
    workload_id                 uuid,
    binding_revision            integer NOT NULL DEFAULT 1,
    policy_refs                 text[] NOT NULL DEFAULT '{}',
    backend                     text NOT NULL DEFAULT 'authsec',
    backend_profile             text NOT NULL DEFAULT 'linux-managed-v1',
    identity_mode               text NOT NULL DEFAULT 'spiffe',
    identity_binding_id         uuid,
    target_execution_selector   text,
    capability_digest           text,
    plan_hash                   text,
    state                       text NOT NULL DEFAULT 'draft',
    plan_job_id                 uuid,
    blockers                    text[] DEFAULT '{}',
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT enforcement_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT enforcement_bindings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- Partial unique index: at most one non-superseded binding per agent per workspace.
CREATE UNIQUE INDEX IF NOT EXISTS enforcement_bindings_active_idx
    ON public.enforcement_bindings (workspace_id, agent_id)
    WHERE state != 'superseded';

-- Index for resolution queries by workspace and agent.
CREATE INDEX IF NOT EXISTS enforcement_bindings_ws_agent_idx
    ON public.enforcement_bindings (workspace_id, agent_id);

-- Index for resolution queries by workspace and workload.
CREATE INDEX IF NOT EXISTS enforcement_bindings_ws_workload_idx
    ON public.enforcement_bindings (workspace_id, workload_id)
    WHERE workload_id IS NOT NULL;

-- Add V2 columns to runtime_policy_revisions if not present.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'runtime_policy_revisions'
          AND column_name = 'compiler_version'
    ) THEN
        ALTER TABLE public.runtime_policy_revisions
            ADD COLUMN compiler_version text,
            ADD COLUMN backend_profile text,
            ADD COLUMN capability_digest text;
    END IF;
END $$;
