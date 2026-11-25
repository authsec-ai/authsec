-- ============================================================================
-- 200: history snapshots (SPEC-secops-backend-upgrade.md P9 / W9).
--
-- 1. iga_snapshot: one row per (workspace, day, kind, stable id) whose
--    canonical body changed since the previous row of that stable id (rows
--    are deduplicated by hash; an object that disappears gets an "absent"
--    row). kind is inventory | policy_text | reach | metric_value |
--    metric_definition | rule_version. hash is the sha256 (hex) of the
--    canonical body and never changes; chain_hash links each row to the
--    previous row of the same stable id. Append-only: an UPDATE may only set
--    legal_hold or redact the body (a tombstone that keeps the hash); DELETE
--    only by retention (authsec.snapshot_purge = on) or a workspace purge
--    (authsec.workspace_purge = on).
-- 2. iga_snapshot_day: one row per workspace and day the job ran -- counts
--    per kind, the content hash of the rows written that day, and the
--    workspace's day chain (prev_chain_hash -> chain_hash), the daily anchor.
--    Only "purged" may change (retention removed rows of that day).
-- 3. iga_snapshot_hold: legal holds over a date range and kinds. A held row
--    (legal_hold) is never purged.
-- 4. iga_snapshot_setting: per-workspace snapshot retention (default 400 d).
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.iga_snapshot (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    snapshot_date    date        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('inventory', 'policy_text', 'reach', 'metric_value', 'metric_definition', 'rule_version')),
    stable_id        text        NOT NULL CHECK (stable_id <> '' AND length(stable_id) <= 300),
    hash             text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    body             jsonb       NOT NULL,
    absent           boolean     NOT NULL DEFAULT false,
    legal_hold       boolean     NOT NULL DEFAULT false,
    redacted         boolean     NOT NULL DEFAULT false,
    redacted_at      timestamptz,
    redacted_by      uuid,
    redaction_reason text        NOT NULL DEFAULT '' CHECK (length(redaction_reason) <= 1000),
    prev_chain_hash  text        NOT NULL DEFAULT '' CHECK (prev_chain_hash = '' OR prev_chain_hash ~ '^[0-9a-f]{64}$'),
    chain_hash       text        NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_snapshot_pkey PRIMARY KEY (id),
    CONSTRAINT iga_snapshot_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_snapshot_day_stable_key UNIQUE (workspace_id, snapshot_date, kind, stable_id),
    CONSTRAINT iga_snapshot_redacted_chk CHECK (redacted = (redacted_at IS NOT NULL)),
    CONSTRAINT iga_snapshot_redaction_reason_chk CHECK (NOT redacted OR btrim(redaction_reason) <> '')
);
-- As-of reads: the latest row of a stable id at or before a date.
CREATE INDEX IF NOT EXISTS idx_iga_snapshot_asof
    ON public.iga_snapshot (workspace_id, kind, stable_id, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS idx_iga_snapshot_ws_date
    ON public.iga_snapshot (workspace_id, snapshot_date);

CREATE TABLE IF NOT EXISTS public.iga_snapshot_day (
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    snapshot_date   date        NOT NULL,
    kinds           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    rows_written    integer     NOT NULL DEFAULT 0 CHECK (rows_written >= 0),
    content_hash    text        NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    prev_chain_hash text        NOT NULL DEFAULT '' CHECK (prev_chain_hash = '' OR prev_chain_hash ~ '^[0-9a-f]{64}$'),
    chain_hash      text        NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    purged          boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_snapshot_day_pkey PRIMARY KEY (workspace_id, snapshot_date)
);

CREATE TABLE IF NOT EXISTS public.iga_snapshot_hold (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    from_date           date        NOT NULL,
    to_date             date        NOT NULL,
    kinds               text[]      NOT NULL,
    reason              text        NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 1000),
    placed_by           uuid        NOT NULL,
    placed_at           timestamptz NOT NULL DEFAULT now(),
    released_at         timestamptz,
    released_by         uuid,
    release_approval_id uuid,
    CONSTRAINT iga_snapshot_hold_pkey PRIMARY KEY (id),
    CONSTRAINT iga_snapshot_hold_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT iga_snapshot_hold_range_chk CHECK (from_date <= to_date),
    CONSTRAINT iga_snapshot_hold_kinds_chk CHECK (cardinality(kinds) >= 1 AND kinds <@ ARRAY['inventory', 'policy_text', 'reach', 'metric_value', 'metric_definition', 'rule_version']::text[]),
    CONSTRAINT iga_snapshot_hold_released_chk CHECK ((released_at IS NULL) = (released_by IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_iga_snapshot_hold_ws_live
    ON public.iga_snapshot_hold (workspace_id, from_date) WHERE released_at IS NULL;

CREATE TABLE IF NOT EXISTS public.iga_snapshot_setting (
    workspace_id   uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    retention_days integer     NOT NULL DEFAULT 400 CHECK (retention_days BETWEEN 30 AND 3650),
    updated_by     uuid,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT iga_snapshot_setting_pkey PRIMARY KEY (workspace_id)
);

COMMENT ON TABLE public.iga_snapshot IS
    'Daily history snapshots by stable id (inventory, policy text, reach, metric values and definitions, rule versions); deduplicated by hash, chained, append-only except legal hold and redaction.';

CREATE OR REPLACE FUNCTION public.iga_snapshot_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('authsec.snapshot_purge', true) = 'on'
           OR current_setting('authsec.workspace_purge', true) = 'on' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'iga_snapshot rows are removed only by retention';
    END IF;
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.snapshot_date IS DISTINCT FROM OLD.snapshot_date
       OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.stable_id IS DISTINCT FROM OLD.stable_id
       OR NEW.hash IS DISTINCT FROM OLD.hash OR NEW.absent IS DISTINCT FROM OLD.absent
       OR NEW.prev_chain_hash IS DISTINCT FROM OLD.prev_chain_hash OR NEW.chain_hash IS DISTINCT FROM OLD.chain_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'iga_snapshot % is immutable: only legal_hold and redaction change', OLD.id;
    END IF;
    IF OLD.redacted AND (NOT NEW.redacted OR NEW.body IS DISTINCT FROM OLD.body
                         OR NEW.redacted_at IS DISTINCT FROM OLD.redacted_at
                         OR NEW.redacted_by IS DISTINCT FROM OLD.redacted_by
                         OR NEW.redaction_reason IS DISTINCT FROM OLD.redaction_reason) THEN
        RAISE EXCEPTION 'iga_snapshot % is redacted; a redaction is final', OLD.id;
    END IF;
    IF NOT NEW.redacted AND NEW.body IS DISTINCT FROM OLD.body THEN
        RAISE EXCEPTION 'iga_snapshot % body changes only by redaction', OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_iga_snapshot_guard ON public.iga_snapshot;
CREATE TRIGGER trg_iga_snapshot_guard
    BEFORE UPDATE OR DELETE ON public.iga_snapshot
    FOR EACH ROW EXECUTE FUNCTION public.iga_snapshot_guard();

CREATE OR REPLACE FUNCTION public.iga_snapshot_day_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF current_setting('authsec.workspace_purge', true) = 'on' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'iga_snapshot_day rows are append-only';
    END IF;
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.snapshot_date IS DISTINCT FROM OLD.snapshot_date
       OR NEW.kinds IS DISTINCT FROM OLD.kinds OR NEW.rows_written IS DISTINCT FROM OLD.rows_written
       OR NEW.content_hash IS DISTINCT FROM OLD.content_hash OR NEW.prev_chain_hash IS DISTINCT FROM OLD.prev_chain_hash
       OR NEW.chain_hash IS DISTINCT FROM OLD.chain_hash OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.purged AND NOT NEW.purged) THEN
        RAISE EXCEPTION 'iga_snapshot_day is append-only: only purged may be set';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_iga_snapshot_day_guard ON public.iga_snapshot_day;
CREATE TRIGGER trg_iga_snapshot_day_guard
    BEFORE UPDATE OR DELETE ON public.iga_snapshot_day
    FOR EACH ROW EXECUTE FUNCTION public.iga_snapshot_day_guard();

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_snapshot');
        PERFORM public.tenancy_enable_rls('public.iga_snapshot_day');
        PERFORM public.tenancy_enable_rls('public.iga_snapshot_hold');
        PERFORM public.tenancy_enable_rls('public.iga_snapshot_setting');
    END IF;
END $$;
