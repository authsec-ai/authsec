-- ============================================================================
-- 201: second-person changes and bulk exports of the history surface
-- (SPEC-secops-backend-upgrade.md P3 tier 3, P9 / W9).
--
-- 1. iga_history_approval: a tier-3 request on the history surface --
--    releasing a legal hold, redacting a snapshot, a bulk export. A second
--    member holding governance:approve applies it (decided_by <> requested_by),
--    except a break-glass change in a workspace with exactly one approver:
--    applied by the requester alone, with a review due within 24 hours
--    (decision 4). Self-contained on purpose: the general pending_change of
--    W5 can replace it later.
-- 2. iga_export: a bulk export produced by an applied request: the JSON
--    bundle's bytes, their sha256 and size. The bytes are dropped (content
--    NULL) once expires_at passes; the row and its hash stay.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_history_approval (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    action          text        NOT NULL CHECK (action IN ('hold_release', 'snapshot_redact', 'bulk_export')),
    subject_id      uuid,
    params          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    params_hash     text        NOT NULL CHECK (params_hash ~ '^[0-9a-f]{64}$'),
    reason          text        NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 1000),
    requested_by    uuid        NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    state           text        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'rejected', 'withdrawn', 'expired', 'failed')),
    break_glass     boolean     NOT NULL DEFAULT false,
    decided_by      uuid,
    decided_at      timestamptz,
    decision_reason text        NOT NULL DEFAULT '' CHECK (length(decision_reason) <= 1000),
    review_due_at   timestamptz,
    reviewed_by     uuid,
    reviewed_at     timestamptz,
    review_note     text        NOT NULL DEFAULT '' CHECK (length(review_note) <= 1000),
    result          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT iga_history_approval_pkey PRIMARY KEY (id),
    CONSTRAINT iga_history_approval_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_history_approval_decided_chk CHECK ((state = 'pending') = (decided_at IS NULL)),
    -- A second person decides, unless the change was a break-glass one.
    CONSTRAINT iga_history_approval_second_person_chk CHECK (break_glass OR decided_by IS NULL OR decided_by <> requested_by),
    CONSTRAINT iga_history_approval_break_glass_chk CHECK (NOT break_glass OR (review_due_at IS NOT NULL AND decided_by = requested_by)),
    CONSTRAINT iga_history_approval_review_chk CHECK ((reviewed_at IS NULL) = (reviewed_by IS NULL) AND (reviewed_by IS NULL OR reviewed_by <> requested_by)),
    CONSTRAINT iga_history_approval_subject_chk CHECK ((action = 'bulk_export') = (subject_id IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_iga_history_approval_ws_state
    ON public.iga_history_approval (workspace_id, state, requested_at DESC);
-- One open request per subject and action.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_history_approval_pending
    ON public.iga_history_approval (workspace_id, action, subject_id) WHERE state = 'pending' AND subject_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.iga_export (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    approval_id        uuid        NOT NULL,
    requested_by       uuid        NOT NULL,
    params             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    sha256             text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes         bigint      NOT NULL CHECK (size_bytes >= 0),
    item_count         integer     NOT NULL CHECK (item_count >= 0),
    content            bytea,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    download_count     integer     NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    last_downloaded_at timestamptz,
    CONSTRAINT iga_export_pkey PRIMARY KEY (id),
    CONSTRAINT iga_export_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_export_approval_key UNIQUE (workspace_id, approval_id),
    CONSTRAINT iga_export_approval_fkey FOREIGN KEY (workspace_id, approval_id)
        REFERENCES public.iga_history_approval (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_iga_export_ws_created
    ON public.iga_export (workspace_id, created_at DESC);

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_history_approval');
        PERFORM public.tenancy_enable_rls('public.iga_export');
    END IF;
END $$;
