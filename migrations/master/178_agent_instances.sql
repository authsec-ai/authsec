-- 178_agent_instances.sql
--
-- Agent instances, deployers and hygiene (SPEC-secops-backend-upgrade.md W7,
-- P12; hygiene detections).
--
-- iga_agent_instances (004) had no writer. It now records each running
-- version of an agent (177's agent): the artifact (Lambda code SHA-256, a
-- container image digest, an AgentCore runtime version), the model and its
-- version, the environment, who deployed it and what spawned it. Rows of the
-- one-agent-id model name their agent in agent_ref; agent_id (an iga_agents
-- row) stays for the Phase 1 estate and becomes optional, so an AWS workload
-- is never made an iga_agents row (§2.2 of the graph spec still holds).
--
-- agent_deployer is the recorded deployer set of an agent: the first
-- instance's deployer is recorded; a later instance from a deployer outside
-- the set opens an agent_hygiene_finding (unknown_deployer) and an event,
-- until a person records that deployer.
--
-- agent_hygiene_finding holds the hygiene results: stale agents (no call in
-- 30 days on a source that sees calls), overdue keys (an IAM access key last
-- rotated more than 90 days ago) and unknown deployers. One row per (kind,
-- subject), reopened when it recurs.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

ALTER TABLE public.iga_agent_instances ALTER COLUMN agent_id DROP NOT NULL;
ALTER TABLE public.iga_agent_instances
    ADD COLUMN IF NOT EXISTS agent_ref         uuid,
    ADD COLUMN IF NOT EXISTS source_table      text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_id         text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS artifact_digest   text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS artifact_version  text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS model             text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS model_version     text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS environment       text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS deployer          text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS spawned_by        text        NOT NULL DEFAULT '',
    -- The cloud identity the instance acts as (AWS), so hygiene can read its
    -- calls (cloud_usage) without re-deriving the workload.
    ADD COLUMN IF NOT EXISTS cloud_identity_id uuid;

DO $$
BEGIN
    ALTER TABLE public.iga_agent_instances DROP CONSTRAINT IF EXISTS iga_agent_instances_agent_ref_fkey;
    ALTER TABLE public.iga_agent_instances ADD CONSTRAINT iga_agent_instances_agent_ref_fkey
        FOREIGN KEY (workspace_id, agent_ref) REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE;
    ALTER TABLE public.iga_agent_instances DROP CONSTRAINT IF EXISTS iga_agent_instances_owner_chk;
    ALTER TABLE public.iga_agent_instances ADD CONSTRAINT iga_agent_instances_owner_chk
        CHECK (agent_id IS NOT NULL OR agent_ref IS NOT NULL);
END $$;

-- One row per agent, workload and artifact: a new digest is a new instance.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agent_instances_ref
    ON public.iga_agent_instances (workspace_id, agent_ref, native_workload_id, artifact_digest)
    WHERE agent_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_agent_instances_ref
    ON public.iga_agent_instances (workspace_id, agent_ref, last_seen_at DESC)
    WHERE agent_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.agent_deployer (
    id            uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id  uuid        NOT NULL,
    agent_id      uuid        NOT NULL,
    deployer      text        NOT NULL,
    -- 'first_instance' (recorded from the agent's first instance) or a user id.
    recorded_by   text        NOT NULL DEFAULT 'first_instance',
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_deployer_pkey PRIMARY KEY (id),
    CONSTRAINT agent_deployer_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_deployer_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_deployer_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_deployer_key UNIQUE (workspace_id, agent_id, deployer),
    CONSTRAINT agent_deployer_chk CHECK (deployer <> '')
);

CREATE TABLE IF NOT EXISTS public.agent_hygiene_finding (
    id           uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL,
    kind         text        NOT NULL,
    -- Stable across runs: the agent id, the access key id (an identifier,
    -- never material), or agent id + deployer.
    subject_key  text        NOT NULL,
    agent_id     uuid,
    subject      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    evidence     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    state        text        NOT NULL DEFAULT 'open',
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    CONSTRAINT agent_hygiene_finding_pkey PRIMARY KEY (id),
    CONSTRAINT agent_hygiene_finding_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_hygiene_finding_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_hygiene_finding_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_hygiene_finding_subject_key UNIQUE (workspace_id, kind, subject_key),
    CONSTRAINT agent_hygiene_finding_kind_chk CHECK (kind IN ('stale_agent', 'overdue_key', 'unknown_deployer')),
    CONSTRAINT agent_hygiene_finding_state_chk CHECK (state IN ('open', 'resolved')),
    CONSTRAINT agent_hygiene_finding_resolved_chk CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
    CONSTRAINT agent_hygiene_finding_subject_chk CHECK (subject_key <> '')
);
CREATE INDEX IF NOT EXISTS idx_agent_hygiene_finding_list
    ON public.agent_hygiene_finding (workspace_id, state, kind, last_seen DESC, id);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_deployer');
        PERFORM public.tenancy_enable_rls('public.agent_hygiene_finding');
    END IF;
END $$;
