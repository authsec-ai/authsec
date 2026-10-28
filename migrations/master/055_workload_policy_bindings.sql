-- Per-workload policy binding table (TRD v1.1 BE05/BE07).
CREATE TABLE IF NOT EXISTS workload_policy_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    workload_id     UUID NOT NULL,
    policy_id       UUID NOT NULL,
    revision        INT  NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','active','superseded','revoked')),
    delivery_cursor BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, workload_id, policy_id)
);
CREATE INDEX IF NOT EXISTS idx_wpb_workspace_workload
    ON workload_policy_bindings (workspace_id, workload_id);
CREATE INDEX IF NOT EXISTS idx_wpb_workspace_policy
    ON workload_policy_bindings (workspace_id, policy_id);
