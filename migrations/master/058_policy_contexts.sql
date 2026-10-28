-- 058_policy_contexts.sql
--
-- Policy context preparation for BG05 (Local Agent Graph & Actions TRD v1.0).
-- Each row is a prepared policy context document: the canonical target,
-- base policy IDs/revisions, proposed rule, evidence refs, capability
-- requirements, unsupported reasons and projected impact. Contexts have a
-- 30-minute TTL and are cleaned up by the expiry worker.
--
-- Idempotent. No transaction wrapper: the runner applies this file with psql -1.

CREATE TABLE IF NOT EXISTS public.iga_policy_contexts (
    id                   uuid          NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid          NOT NULL,
    actor_user_id        uuid          NOT NULL,
    source_kind          text          NOT NULL,
    root_workload_id     uuid,
    graph_revision       int8,
    selected_ref         text,
    action_id            uuid,
    requested_effect     text          NOT NULL DEFAULT 'deny',
    selected_operations  text[],
    context_document     jsonb         NOT NULL,
    source_hash          text          NOT NULL,
    expires_at           timestamptz   NOT NULL,
    created_at           timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT iga_policy_contexts_pkey PRIMARY KEY (id)
);

-- Workspace-scoped lookups.
CREATE INDEX IF NOT EXISTS idx_iga_policy_contexts_ws_id
    ON public.iga_policy_contexts (workspace_id, id);

-- Cleanup looks up rows by expires_at and filters expires_at < now() in the
-- query. now() is STABLE, so it cannot appear in an index predicate.
CREATE INDEX IF NOT EXISTS idx_iga_policy_contexts_expires
    ON public.iga_policy_contexts (expires_at);

-- ---------------------------------------------------------------------------
-- BG06 — Context Save, Audit & Policy Linkage
-- ---------------------------------------------------------------------------

-- Link a revision back to the policy context it was created from.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'runtime_policy_revisions'
          AND column_name = 'origin_context_id'
    ) THEN
        ALTER TABLE public.runtime_policy_revisions
            ADD COLUMN origin_context_id uuid;
    END IF;
END $$;

-- Structured rule diff on audit records: added/removed/changed rule IDs,
-- operation, target, constraints, effect, before/after revision hashes.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'runtime_policy_audit'
          AND column_name = 'rule_diff'
    ) THEN
        ALTER TABLE public.runtime_policy_audit
            ADD COLUMN rule_diff jsonb;
    END IF;
END $$;
