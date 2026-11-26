-- ============================================================================
-- 167: audit_events hash chain, anchors, purge gaps, write failures
-- (SPEC-secops-backend-upgrade.md F7 / P18, AS-177).
--
-- Every audit_events row written from now on is a link in its workspace's
-- chain: seq (1, 2, 3 ... per workspace_id), prev_hash (the previous link's
-- hash, 64 zeros for the first) and hash = sha256 over the row's canonical
-- form (public.audit_event_canonical: every content column, the seq and the
-- prev_hash). The BEFORE INSERT trigger assigns all three under a
-- transaction-level advisory lock per chain, so writers never fork a chain
-- and no writer can choose its own seq or hash. Rows written before this
-- migration keep seq NULL ("unchained"): 108 makes them immutable, and
-- rewriting them to add a hash is exactly what 108 forbids.
--
-- The chain key is audit_events.workspace_id as stored ('' for events with no
-- workspace, such as a pre-auth login failure: the platform chain).
--
-- audit_chain_anchor: the head (last seq, its hash) of a chain, written daily
-- and before every retention purge; never updated or deleted (except by a
-- workspace purge).
-- audit_chain_gap: one row per run of consecutive links a retention purge
-- removed, with the hash before the run and the hash of its last link, so the
-- surviving rows stay verifiable across the hole.
-- audit_write_failure: an audit row that could not be written after the
-- writer's retries, with the whole event, so the loss is visible and the
-- event is replayed into the chain later.
--
-- DELETE on audit_events, allowed for "the retention job" by 108, now needs
-- the retention job's flag (authsec.audit_retention = on) or a workspace
-- purge's (authsec.workspace_purge = on): a delete that bypasses the purge
-- would leave a hole with no gap row, and verification reports it.
--
-- workspace_id on the anchor, gap and failure tables is NULL only for the
-- platform chain (chain '' or a workspace that no longer exists); row-level
-- security hides those rows from every workspace.
--
-- Expand only. Idempotent. 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS record_class text;
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS seq bigint;
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS prev_hash text;
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS hash text;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conname = 'audit_events_record_class_chk'
                      AND conrelid = 'public.audit_events'::regclass) THEN
        ALTER TABLE public.audit_events ADD CONSTRAINT audit_events_record_class_chk
            CHECK (record_class IS NULL OR record_class IN ('admin_change', 'auth', 'access_decision', 'export', 'default'));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_events_chain
    ON public.audit_events (workspace_id, seq) WHERE seq IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_events_ws_actor_time
    ON public.audit_events (workspace_id, user_id, "timestamp");
CREATE INDEX IF NOT EXISTS idx_audit_events_ws_class_time
    ON public.audit_events (workspace_id, record_class, "timestamp");

-- One field of the canonical form: NULL is "~", anything else is its byte
-- length in UTF-8 (whatever the database encoding), a colon and the value
-- (so no value can imitate a separator).
CREATE OR REPLACE FUNCTION public.audit_chain_field(v text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN v IS NULL THEN '~' ELSE octet_length(convert_to(v, 'UTF8'))::text || ':' || v END
$$;

-- The canonical form a link's hash is taken over. internal/auditchain
-- (Canonical) builds the same string in Go, which is how verification
-- recomputes hashes without trusting this function.
CREATE OR REPLACE FUNCTION public.audit_event_canonical(e public.audit_events) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT 'authsec.audit.v1'
        || '|' || public.audit_chain_field(e.id::text)
        || '|' || public.audit_chain_field(e.workspace_id)
        || '|' || public.audit_chain_field(e.seq::text)
        || '|' || public.audit_chain_field(e.prev_hash)
        || '|' || public.audit_chain_field(e.record_class)
        || '|' || public.audit_chain_field(e.request_id)
        || '|' || public.audit_chain_field(e.actor_realm)
        || '|' || public.audit_chain_field(e.user_id)
        || '|' || public.audit_chain_field(e.action)
        || '|' || public.audit_chain_field(e.resource)
        || '|' || public.audit_chain_field(e.resource_id)
        || '|' || public.audit_chain_field(e.method)
        || '|' || public.audit_chain_field(e.path)
        || '|' || public.audit_chain_field(e.user_agent)
        || '|' || public.audit_chain_field(e.client_ip)
        || '|' || public.audit_chain_field(e.status_code::text)
        || '|' || public.audit_chain_field(e.duration::text)
        || '|' || public.audit_chain_field(e.old_values::text)
        || '|' || public.audit_chain_field(e.new_values::text)
        || '|' || public.audit_chain_field(e.error)
        || '|' || public.audit_chain_field(to_char(e."timestamp" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
$$;

CREATE TABLE IF NOT EXISTS public.audit_chain_anchor (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
    chain        text        NOT NULL,
    day          date        NOT NULL,
    last_seq     bigint      NOT NULL,
    head_hash    text        NOT NULL,
    reason       text        NOT NULL DEFAULT 'daily',
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_anchor_seq_chk CHECK (last_seq > 0),
    CONSTRAINT audit_chain_anchor_hash_chk CHECK (head_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_anchor_reason_chk CHECK (reason IN ('daily', 'purge')),
    CONSTRAINT audit_chain_anchor_chain_chk CHECK (workspace_id IS NULL OR chain = workspace_id::text),
    CONSTRAINT uq_audit_chain_anchor UNIQUE (chain, last_seq)
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_anchor_ws_day
    ON public.audit_chain_anchor (workspace_id, day);

CREATE TABLE IF NOT EXISTS public.audit_chain_gap (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
    chain        text        NOT NULL,
    from_seq     bigint      NOT NULL,
    to_seq       bigint      NOT NULL,
    prev_hash    text        NOT NULL,
    last_hash    text        NOT NULL,
    purge_run    uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_chain_gap_range_chk CHECK (from_seq >= 1 AND to_seq >= from_seq),
    CONSTRAINT audit_chain_gap_hash_chk CHECK (prev_hash ~ '^[0-9a-f]{64}$' AND last_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_gap_chain_chk CHECK (workspace_id IS NULL OR chain = workspace_id::text),
    CONSTRAINT uq_audit_chain_gap UNIQUE (chain, from_seq)
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_gap_ws_chain
    ON public.audit_chain_gap (workspace_id, chain, to_seq);

CREATE TABLE IF NOT EXISTS public.audit_write_failure (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
    event        jsonb       NOT NULL,
    error        text        NOT NULL,
    attempts     integer     NOT NULL DEFAULT 0,
    state        text        NOT NULL DEFAULT 'pending',
    notified_at  timestamptz,
    replayed_at  timestamptz,
    replayed_seq bigint,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_write_failure_state_chk CHECK (state IN ('pending', 'replayed', 'dead'))
);
CREATE INDEX IF NOT EXISTS idx_audit_write_failure_ws_state
    ON public.audit_write_failure (workspace_id, state, created_at);

COMMENT ON TABLE public.audit_chain_anchor IS
    'Heads of the audit_events hash chains (daily and before every retention purge); append-only.';
COMMENT ON TABLE public.audit_chain_gap IS
    'Runs of audit_events links removed by retention, with the hashes around them; append-only.';
COMMENT ON TABLE public.audit_write_failure IS
    'Audit events that could not be written after retries; replayed into the chain by the audit governance job.';

-- The chain: seq, prev_hash and hash are assigned here, never by the writer.
CREATE OR REPLACE FUNCTION public.audit_events_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    head_seq  bigint;
    head_hash text;
    gap_seq   bigint;
    gap_hash  text;
BEGIN
    NEW.workspace_id := COALESCE(NEW.workspace_id, '');
    IF NEW."timestamp" IS NULL THEN
        NEW."timestamp" := now();
    END IF;
    IF NEW.record_class IS NULL OR NEW.record_class = '' THEN
        NEW.record_class := 'default';
    END IF;
    -- One writer per chain at a time, until its transaction ends.
    PERFORM pg_advisory_xact_lock(1096107092, hashtext(NEW.workspace_id));
    SELECT a.seq, a.hash INTO head_seq, head_hash
      FROM public.audit_events a
     WHERE a.workspace_id = NEW.workspace_id AND a.seq IS NOT NULL
     ORDER BY a.seq DESC LIMIT 1;
    SELECT g.to_seq, g.last_hash INTO gap_seq, gap_hash
      FROM public.audit_chain_gap g
     WHERE g.chain = NEW.workspace_id
     ORDER BY g.to_seq DESC LIMIT 1;
    IF gap_seq IS NOT NULL AND (head_seq IS NULL OR gap_seq > head_seq) THEN
        head_seq := gap_seq;
        head_hash := gap_hash;
    END IF;
    NEW.seq := COALESCE(head_seq, 0) + 1;
    NEW.prev_hash := COALESCE(head_hash, repeat('0', 64));
    NEW.hash := encode(sha256(convert_to(public.audit_event_canonical(NEW), 'UTF8')), 'hex');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_chain ON public.audit_events;
CREATE TRIGGER trg_audit_events_chain
    BEFORE INSERT ON public.audit_events
    FOR EACH ROW EXECUTE FUNCTION public.audit_events_chain();

CREATE OR REPLACE FUNCTION public.audit_events_delete_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('authsec.audit_retention', true) = 'on'
       OR current_setting('authsec.workspace_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_events rows are deleted only by the audit retention job';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_delete_guard ON public.audit_events;
CREATE TRIGGER trg_audit_events_delete_guard
    BEFORE DELETE ON public.audit_events
    FOR EACH ROW EXECUTE FUNCTION public.audit_events_delete_guard();

CREATE OR REPLACE FUNCTION public.audit_chain_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('authsec.workspace_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% rows are append-only', TG_TABLE_NAME;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_chain_anchor_immutable ON public.audit_chain_anchor;
CREATE TRIGGER trg_audit_chain_anchor_immutable
    BEFORE UPDATE OR DELETE ON public.audit_chain_anchor
    FOR EACH ROW EXECUTE FUNCTION public.audit_chain_immutable();

DROP TRIGGER IF EXISTS trg_audit_chain_gap_immutable ON public.audit_chain_gap;
CREATE TRIGGER trg_audit_chain_gap_immutable
    BEFORE UPDATE OR DELETE ON public.audit_chain_gap
    FOR EACH ROW EXECUTE FUNCTION public.audit_chain_immutable();

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.audit_chain_anchor');
        PERFORM public.tenancy_enable_rls('public.audit_chain_gap');
        PERFORM public.tenancy_enable_rls('public.audit_write_failure');
    END IF;
END $$;
