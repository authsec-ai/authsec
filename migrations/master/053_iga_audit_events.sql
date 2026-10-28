-- 053_iga_audit_events.sql
--
-- Runtime policy mutations call IGAAuditService.RecordPolicyMutationEvent
-- inside the same transaction as the policy write. The service swallows the
-- error, but PostgreSQL aborts the transaction on the missing relation, so
-- POST /api/iga/v2/runtime-policies/candidates returns 500 and commits nothing.
--
-- The columns match services.IGAAuditEvent. verified_actor_id is a bare uuid,
-- the same treatment as runtime_policies.owner_user_id: the candidate system
-- actor is not a users row.
--
-- Idempotent. No transaction wrapper: the runner applies this file with psql -1.

CREATE TABLE IF NOT EXISTS public.iga_audit_events (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id      uuid NOT NULL,
    event_type        text NOT NULL,
    occurred_at       timestamptz NOT NULL,
    received_at       timestamptz NOT NULL,
    actor             text NOT NULL DEFAULT '',
    verified_actor_id uuid,
    spiffe_id         text NOT NULL DEFAULT '',
    agent_id          uuid,
    workload_id       uuid,
    execution_id      uuid,
    policy_id         uuid,
    policy_revision   integer,
    policy_hash       text NOT NULL DEFAULT '',
    rule_id           text NOT NULL DEFAULT '',
    primitive_id      text NOT NULL DEFAULT '',
    resource          text NOT NULL DEFAULT '',
    outcome           text NOT NULL DEFAULT '',
    reason            text NOT NULL DEFAULT '',
    correlation_id    text NOT NULL DEFAULT '',
    evidence_refs     text[] NOT NULL DEFAULT '{}',
    backend           text NOT NULL DEFAULT '',
    publication_id    uuid,
    binary_digest     text NOT NULL DEFAULT '',
    metadata          jsonb,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_audit_events_pkey PRIMARY KEY (id),
    CONSTRAINT iga_audit_events_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_iga_audit_ws_time
    ON public.iga_audit_events (workspace_id, occurred_at);

CREATE INDEX IF NOT EXISTS idx_iga_audit_event_type
    ON public.iga_audit_events (event_type);

CREATE INDEX IF NOT EXISTS idx_iga_audit_actor
    ON public.iga_audit_events (verified_actor_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_agent
    ON public.iga_audit_events (agent_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_policy
    ON public.iga_audit_events (policy_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_rule
    ON public.iga_audit_events (rule_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_primitive
    ON public.iga_audit_events (primitive_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_outcome
    ON public.iga_audit_events (outcome);

CREATE INDEX IF NOT EXISTS idx_iga_audit_correlation
    ON public.iga_audit_events (correlation_id);

CREATE INDEX IF NOT EXISTS idx_iga_audit_backend
    ON public.iga_audit_events (backend);

CREATE INDEX IF NOT EXISTS idx_iga_audit_spiffe
    ON public.iga_audit_events (spiffe_id);
