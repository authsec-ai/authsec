-- 186_agent_cases.sql
--
-- Agent runtime cases (SPEC-secops-backend-upgrade.md W3 / P2): alerts that
-- belong to one incident are grouped into a case an operator works, assigns,
-- annotates, closes with an outcome and exports.
--
-- 1. agent_case: one case per incident, numbered per workspace (#1, #2, ...;
--    UNIQUE (workspace_id, number), assigned under a per-workspace lock).
--    state open|closed; a closed case always has an outcome
--    (true_positive|benign|false_positive|duplicate), who closed it and when.
--    severity admits 'low' ahead of the alerts (F8 adds it to agent_alert):
--    a case's severity is the highest of its alerts', so a case of low alerts
--    must be storable. opened_by is 'system' (clustering) or a user id.
--    exercise_id marks a drill (no table yet: no foreign key).
-- 2. agent_case_alert: membership. The primary key (workspace_id, alert_id)
--    puts an alert in at most one case. indicators are what clustering
--    matched on ("identity:<uuid>", "workload:<uuid>"; later sources add
--    access keys and provider keys). An alert removed by retention leaves
--    its case.
-- 3. agent_case_link: case-to-case relations (duplicate_of, related,
--    split_from), both ends in the same workspace (composite foreign keys).
-- 4. agent_case_note: append-only notes (at most 10 000 characters). UPDATE
--    and DELETE are refused outside a workspace purge.
-- 5. agent_case_evidence: evidence a case pins. A row names an event by
--    (source, event_id); alert_id and alert_event_ref keep the alert's own
--    sanitised reference (agent_alert.evidence trims old references, the pin
--    keeps them).
-- 6. idx_iga_gov_event_case: the case timeline is iga_gov_event rows whose
--    payload carries case_id (append-only, redacted, in the Logs view), read
--    by this index.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.agent_case (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    number           integer     NOT NULL CHECK (number > 0),
    title            text        NOT NULL CHECK (btrim(title) <> '' AND char_length(title) <= 300),
    severity         text        NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    state            text        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    outcome          text        CHECK (outcome IN ('true_positive', 'benign', 'false_positive', 'duplicate')),
    assignee_user_id uuid,
    -- The first time a person set the severity or the outcome.
    classified_at    timestamptz,
    classified_by    uuid,
    exercise_id      uuid,
    opened_by        text        NOT NULL CHECK (opened_by = 'system'
                                 OR opened_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    opened_at        timestamptz NOT NULL DEFAULT now(),
    closed_by        uuid,
    closed_at        timestamptz,
    close_reason     text        NOT NULL DEFAULT '' CHECK (char_length(close_reason) <= 1000),
    reopened_count   integer     NOT NULL DEFAULT 0 CHECK (reopened_count >= 0),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, number),
    CONSTRAINT agent_case_closed_chk CHECK ((state = 'closed') = (outcome IS NOT NULL AND closed_at IS NOT NULL AND closed_by IS NOT NULL)),
    CONSTRAINT agent_case_classified_chk CHECK ((classified_at IS NULL) = (classified_by IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_agent_case_ws_opened
    ON public.agent_case (workspace_id, opened_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_case_ws_state
    ON public.agent_case (workspace_id, state, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_case_ws_assignee
    ON public.agent_case (workspace_id, assignee_user_id) WHERE assignee_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.agent_case_alert (
    workspace_id uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    case_id      uuid        NOT NULL,
    alert_id     uuid        NOT NULL,
    indicators   text[]      NOT NULL DEFAULT '{}',
    added_by     text        NOT NULL CHECK (added_by = 'system'
                             OR added_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    added_at     timestamptz NOT NULL DEFAULT now(),
    -- One case per alert.
    PRIMARY KEY (workspace_id, alert_id),
    FOREIGN KEY (workspace_id, case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, alert_id) REFERENCES public.agent_alert (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_case_alert_case
    ON public.agent_case_alert (workspace_id, case_id);
CREATE INDEX IF NOT EXISTS idx_agent_case_alert_indicators
    ON public.agent_case_alert USING gin (indicators);

CREATE TABLE IF NOT EXISTS public.agent_case_link (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id  uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    case_id       uuid        NOT NULL,
    other_case_id uuid        NOT NULL,
    relation      text        NOT NULL CHECK (relation IN ('duplicate_of', 'related', 'split_from')),
    created_by    text        NOT NULL CHECK (created_by = 'system'
                              OR created_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, case_id, other_case_id, relation),
    CONSTRAINT agent_case_link_self_chk CHECK (case_id <> other_case_id),
    FOREIGN KEY (workspace_id, case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, other_case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_case_link_other
    ON public.agent_case_link (workspace_id, other_case_id);

CREATE TABLE IF NOT EXISTS public.agent_case_note (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    case_id        uuid        NOT NULL,
    author_user_id uuid        NOT NULL,
    body           text        NOT NULL CHECK (btrim(body) <> '' AND char_length(body) <= 10000),
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_case_note_case
    ON public.agent_case_note (workspace_id, case_id, created_at);

CREATE OR REPLACE FUNCTION public.agent_case_note_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('authsec.workspace_purge', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'agent_case_note is append-only';
END $$;
DROP TRIGGER IF EXISTS agent_case_note_no_update ON public.agent_case_note;
CREATE TRIGGER agent_case_note_no_update BEFORE UPDATE OR DELETE ON public.agent_case_note
  FOR EACH ROW EXECUTE FUNCTION public.agent_case_note_immutable();

-- pins agent_evidence_event (W1) by (source,event_id); pin_count maintained after merge
CREATE TABLE IF NOT EXISTS public.agent_case_evidence (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
    case_id         uuid        NOT NULL,
    source          text        NOT NULL CHECK (source <> '' AND char_length(source) <= 64),
    event_id        text        NOT NULL CHECK (event_id <> '' AND char_length(event_id) <= 256),
    -- The alert whose evidence reference this pin copies (no foreign key:
    -- the pin outlives the alert's retention).
    alert_id        uuid,
    alert_event_ref jsonb,
    pinned_by       text        NOT NULL CHECK (pinned_by = 'system'
                                OR pinned_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    pinned_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, case_id) REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_case_evidence_pin
    ON public.agent_case_evidence (workspace_id, case_id, source, event_id, COALESCE(alert_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX IF NOT EXISTS idx_agent_case_evidence_alert
    ON public.agent_case_evidence (workspace_id, alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_case_evidence_event
    ON public.agent_case_evidence (workspace_id, source, event_id);

-- The case timeline (iga_gov_event rows naming a case).
CREATE INDEX IF NOT EXISTS idx_iga_gov_event_case
    ON public.iga_gov_event (workspace_id, (payload->>'case_id'), id) WHERE (payload->>'case_id') IS NOT NULL;

COMMENT ON TABLE public.agent_case IS
    'Agent runtime cases: alerts grouped into one incident; every change is logged in iga_gov_event (payload case_id).';

-- Required for every workspace table; guarded as in 150.
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_case');
        PERFORM public.tenancy_enable_rls('public.agent_case_alert');
        PERFORM public.tenancy_enable_rls('public.agent_case_link');
        PERFORM public.tenancy_enable_rls('public.agent_case_note');
        PERFORM public.tenancy_enable_rls('public.agent_case_evidence');
    END IF;
END $$;
