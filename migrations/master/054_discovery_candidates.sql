-- 054_discovery_candidates.sql
--
-- Discovery records a candidate wherever it was seen (cluster object, container,
-- process, systemd unit, or file). Filtering decides whether that candidate is
-- an agent. Non-agents stay here so they do not enter discovered_agents, which
-- is what quarantine, coverage, and policy auto-discovery count.
--
-- Idempotent. No transaction wrapper: the runner applies this file with psql -1.

CREATE TABLE IF NOT EXISTS public.discovery_candidates (
    id                  uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL,
    source              text NOT NULL,
    fingerprint         text NOT NULL,
    logical_key         text NOT NULL DEFAULT '',
    kind                text NOT NULL DEFAULT '',
    display_name        text NOT NULL DEFAULT '',
    signals             jsonb NOT NULL DEFAULT '[]'::jsonb,
    frameworks          jsonb NOT NULL DEFAULT '[]'::jsonb,
    confidence          text NOT NULL,
    decision            text NOT NULL,
    reasons             jsonb NOT NULL DEFAULT '[]'::jsonb,
    discovered_agent_id uuid,
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at         timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT discovery_candidates_pkey PRIMARY KEY (id),
    CONSTRAINT discovery_candidates_identity UNIQUE (workspace_id, source, fingerprint),
    CONSTRAINT discovery_candidates_confidence_chk CHECK (
        confidence IN ('none', 'low', 'medium', 'high')
    ),
    CONSTRAINT discovery_candidates_decision_chk CHECK (
        decision IN ('promote', 'hold')
    ),
    CONSTRAINT discovery_candidates_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT discovery_candidates_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_decision
    ON public.discovery_candidates (workspace_id, decision, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_logical
    ON public.discovery_candidates (workspace_id, logical_key)
    WHERE logical_key <> '';
