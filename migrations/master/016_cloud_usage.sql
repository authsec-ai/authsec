-- 016_cloud_usage.sql
--
-- Whether a permission was ever actually EXERCISED, as opposed to merely
-- granted. The difference between "this role can read every bucket" and "this
-- role has not touched S3 in 400 days" is the whole basis of a least-privilege
-- recommendation, and nothing in tickets [1] or [2] could tell them apart.
--
-- WHY THE GRAIN IS (identity, service) AND NOT (identity, action). Because that
-- is the grain AWS gives us. iam:GetServiceLastAccessedDetails reports per
-- SERVICE -- "s3, last accessed 400 days ago" -- and not per action, so it can
-- support "never touched S3" but never "used GetObject and never PutObject".
-- Recording a finer grain than the source supports would invent precision:
-- every action row would carry the same date, and a reader would reasonably
-- conclude we had per-action evidence. CloudTrail does give per-call detail and
-- would justify a finer grain, but it is rate-capped at roughly two requests a
-- second, so it is an opt-in upgrade rather than the default path -- which is
-- why source is a column and not an assumption.
--
-- WHY last_used_at IS NULLABLE AND WHAT NULL MEANS. NULL is "AWS reports this
-- service was never accessed in the tracking window", which is a positive
-- finding and the most actionable row in the table. It is NOT missing data: a
-- service AuthSec could not read produces no row at all, not a row with a NULL
-- date. The same rule the rest of this schema follows -- unreached is not
-- missing -- applies here, and keeping the two distinguishable is why an absent
-- row and a NULL date have to mean different things.
--
-- WHY THIS TABLE DOES NOT POINT AT cloud_permission. It would be the obvious
-- join, and it is wrong: service-last-accessed data is reported against a
-- PRINCIPAL, not against a policy statement. One identity's S3 access may come
-- from four statements across three policies, and AWS gives no signal about
-- which of them was the one exercised. Attaching a date to a specific statement
-- would be a guess. Aggregating from here up to cloud_permission.
-- last_exercised_at is a decision for the ticket that computes it, with its own
-- documented rule for how a service-level date maps onto statement-level rows.
--
-- WHY THE READ IS ASYNCHRONOUS, AND WHY THAT SHOWS UP IN THE SCHEMA.
-- iam:GenerateServiceLastAccessedDetails returns a JobId; the caller then polls
-- iam:GetServiceLastAccessedDetails until the job reports COMPLETED. Every
-- other AWS read in this schema is a synchronous request inside a loop. That is
-- why generated_at is recorded separately from last_seen_at: the report AWS
-- produced has its own as-of time, which can be meaningfully older than the
-- scan that stored it, and treating the two as one would date the evidence to
-- when we happened to write it down.
--
-- Applied at boot by internal/migration/runner.go, which wraps each file in its
-- own transaction. This file must not open one of its own.

CREATE TABLE IF NOT EXISTS public.cloud_usage (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    connector_id uuid NOT NULL
        REFERENCES public.cloud_connector(id) ON DELETE CASCADE,

    -- The principal the report is about. CASCADE rather than SET NULL: a usage
    -- row describes one identity's behaviour and means nothing detached from
    -- it, unlike a workload, which still exists once its role is gone.
    identity_id uuid NOT NULL
        REFERENCES public.cloud_identity(id) ON DELETE CASCADE,

    -- The AWS service namespace as AWS reports it: "s3", "dynamodb",
    -- "secretsmanager". Not an action, and not an ARN -- see the header on why
    -- the grain stops here.
    service text NOT NULL,

    -- NULL means AWS reports the service was never accessed in the tracking
    -- window. That is a finding, not missing data -- see the header.
    last_used_at timestamptz,

    -- Where the evidence came from, because the two sources support different
    -- claims and a reader must be able to tell which one produced a row.
    -- service_last_accessed | cloudtrail
    source text NOT NULL DEFAULT 'service_last_accessed',

    -- When AWS generated the report, as distinct from when this scan stored it.
    -- The report can be materially older than the scan that read it.
    generated_at timestamptz,

    attrs jsonb NOT NULL DEFAULT '{}'::jsonb,

    last_seen_generation integer NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    row_updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT cloud_usage_service_chk CHECK (service <> ''),
    CONSTRAINT cloud_usage_source_chk CHECK (
        source IN ('service_last_accessed', 'cloudtrail')
    ),
    CONSTRAINT cloud_usage_generation_chk CHECK (last_seen_generation >= 0)
);

-- One row per identity per service per source. Keeping source in the key means
-- a later CloudTrail-backed row can sit alongside the service-last-accessed one
-- for the same pair rather than silently overwriting evidence gathered a
-- different way.
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_usage_identity_service
    ON public.cloud_usage (identity_id, service, source);

-- The scan's own reconciliation query.
CREATE INDEX IF NOT EXISTS idx_cloud_usage_connector_generation
    ON public.cloud_usage (connector_id, last_seen_generation);

-- "Which of this identity's services are dormant" -- the least-privilege
-- question this table exists to answer. Partial, because a never-accessed
-- service is the row worth finding and it is the minority.
CREATE INDEX IF NOT EXISTS idx_cloud_usage_never_accessed
    ON public.cloud_usage (workspace_id, identity_id)
    WHERE last_used_at IS NULL;
