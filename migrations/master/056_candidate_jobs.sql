-- 056_candidate_jobs.sql
-- Persist candidate generation jobs (TRD v1.1 §13).

CREATE TABLE IF NOT EXISTS policy_candidate_jobs (
    id              UUID PRIMARY KEY,
    workspace_id    UUID NOT NULL,
    workload_ids    JSONB NOT NULL DEFAULT '[]'::jsonb,
    graph_revision  BIGINT NOT NULL DEFAULT 0,
    evidence_window TEXT NOT NULL DEFAULT '',
    template_version TEXT NOT NULL DEFAULT 'baseline.v1',
    generator_version TEXT NOT NULL DEFAULT '',
    input_digest    TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'generating', 'completed', 'failed')),
    warnings        JSONB NOT NULL DEFAULT '[]'::jsonb,
    draft_policy_id UUID,
    error_message   TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_candidate_jobs_workspace ON policy_candidate_jobs (workspace_id);
CREATE INDEX IF NOT EXISTS idx_candidate_jobs_workspace_state ON policy_candidate_jobs (workspace_id, state);
