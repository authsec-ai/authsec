-- 163_agent_review.sql
--
-- The AWS agent review handoff (authsec-aws-agent-discovery). Inference
-- queues the AI workloads it cannot attribute (shared role, unattributed DNS)
-- in cloud_workload.attrs.agent_review; the review service polls for them,
-- claims each with a lease, and writes its verdict back to the same key
-- (services/agent_review_queue.go).
--
-- 1. A partial index on the review status, so the service's polling reads
--    only rows that have a review (its statements all carry
--    `attrs ? 'agent_review'`), never the whole table.
-- 2. authsec_agent_review: what the service's database login may do. NOLOGIN:
--    an operator grants it to the service's own login role (no password lives
--    in a migration). It reads the three tables a review needs and updates
--    only cloud_workload.attrs. It is not authsec_tenant, so with no
--    app.workspace_id set row-level security lets it see every workspace
--    (130), which a queue serving every workspace needs; it cannot write any
--    other column or table.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE INDEX IF NOT EXISTS idx_cloud_workload_agent_review_status
    ON public.cloud_workload ((attrs->'agent_review'->>'status'))
    WHERE attrs ? 'agent_review';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authsec_agent_review') THEN
        BEGIN
            CREATE ROLE authsec_agent_review NOLOGIN NOBYPASSRLS;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'authsec_agent_review not created (no CREATEROLE); create it by hand with the grants below';
            RETURN;
        END;
    END IF;
    GRANT USAGE ON SCHEMA public TO authsec_agent_review;
    GRANT SELECT ON public.cloud_workload, public.cloud_identity, public.cloud_connector TO authsec_agent_review;
    GRANT UPDATE (attrs) ON public.cloud_workload TO authsec_agent_review;
END $$;
