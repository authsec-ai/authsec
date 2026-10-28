-- 057_activity_index.sql
--
-- Activity index for BG03 + BG07 (Local Agent Graph & Actions TRD v1.0).
-- Each row is one canonical runtime activity event, projected from collector
-- observations. The activity_sequence BIGSERIAL provides a total order for
-- cursor-based catch-up reads. action_id is the stable external identifier;
-- event_id is the collector's correlation key for idempotent dedup.
--
-- Idempotent. No transaction wrapper: the runner applies this file with psql -1.

CREATE TABLE IF NOT EXISTS public.iga_runtime_activity (
    id                   uuid          NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid          NOT NULL,
    action_id            uuid          NOT NULL,
    collector_id         uuid          NOT NULL,
    batch_id             uuid          NOT NULL,
    event_id             text          NOT NULL,
    workload_id          uuid,
    runtime_instance_id  uuid,
    identity_account_id  uuid,
    resource_id          uuid,
    event_family         text          NOT NULL,
    operation            text,
    phase                text,
    result               text,
    outcome              text          NOT NULL,
    source               text,
    attribution          text,
    provenance           jsonb,
    policy_ref           uuid,
    control_ref          text,
    rule_ref             text,
    observed_at          timestamptz   NOT NULL,
    received_at          timestamptz   NOT NULL DEFAULT now(),
    indexed_at           timestamptz   NOT NULL DEFAULT now(),
    count                integer       NOT NULL DEFAULT 1,
    aggregation          text,
    mapping_status       text          NOT NULL DEFAULT 'unmapped',
    activity_version     integer       NOT NULL DEFAULT 1,
    activity_sequence    bigserial,
    retained_until       timestamptz,
    CONSTRAINT iga_runtime_activity_pkey PRIMARY KEY (id),
    CONSTRAINT iga_runtime_activity_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces (id) ON DELETE CASCADE
);

-- Workload queries: list actions for a workload, ordered by sequence.
CREATE INDEX IF NOT EXISTS idx_iga_activity_ws_workload_seq
    ON public.iga_runtime_activity (workspace_id, workload_id, activity_sequence);

-- Collector queries: list actions for a collector, ordered by sequence.
CREATE INDEX IF NOT EXISTS idx_iga_activity_ws_collector_seq
    ON public.iga_runtime_activity (workspace_id, collector_id, activity_sequence);

-- Idempotency: one action_id per workspace.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iga_activity_ws_action_id
    ON public.iga_runtime_activity (workspace_id, action_id);

-- Dedup: one event per (workspace, collector, event_id).
CREATE UNIQUE INDEX IF NOT EXISTS idx_iga_activity_ws_collector_event
    ON public.iga_runtime_activity (workspace_id, collector_id, event_id);
