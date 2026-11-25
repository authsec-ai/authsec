-- 220_agent_asks.sql
--
-- Asks and their delivery (SPEC-secops-backend-upgrade.md W4 / P1, C13).
--
-- An ask is a question a person must answer about an agent, an alert, a key,
-- a case, a containment, a remediation or a held gateway call. The SERVER
-- picks who decides and when it is due:
--   - the decider is the responder group resolved for the ask's agent (W7,
--     181), else the group of its estate scope, else the workspace default
--     group; the requester of the underlying action (and the ask's creator)
--     never decides (excluded_user_ids);
--   - the due time comes from the workspace's agent_ask_policy by the
--     severity of the ask's object, or an earlier external deadline whose
--     source is recorded; never from a request body.
-- path is the escalation chain (group, its leads, the default group, the
-- workspace admins); step is the current position. Past due_at the
-- escalation worker moves the ask one step on (due again hours_per_step
-- later); at the end of the path the ask stays open, marked overdue.
--
-- agent_ask_event is the ask's append-only log. agent_ask_integration holds
-- the workspace's ticketing (Jira Cloud, ServiceNow) and paging (PagerDuty
-- Events v2, Opsgenie) configuration -- the API token is in Vault
-- (secret_ref), never here. agent_ask_external is one ticket or page opened
-- for an ask or a case, and its last known state.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS public.agent_ask (
    id                       uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id             uuid        NOT NULL,
    about_kind               text        NOT NULL,
    about_id                 text        NOT NULL,
    -- The agent the decider was resolved through (W7's agent table), when any.
    agent_id                 uuid,
    case_id                  uuid,
    question                 text        NOT NULL,
    -- [{"id": "...", "label": "..."}], 2..10 entries.
    choices                  jsonb       NOT NULL,
    severity                 text        NOT NULL,
    -- The tier (SPEC P3) of what an answer decides; tier 2+ answered from
    -- Slack waits for the same person's console confirmation.
    tier                     smallint    NOT NULL DEFAULT 1,
    role                     text        NOT NULL DEFAULT 'responder',
    decider_group_id         uuid,
    decider_user_id          uuid,
    -- The people who could decide at the current step when it began.
    deciders                 uuid[]      NOT NULL DEFAULT '{}',
    resolved_via             text        NOT NULL DEFAULT '',
    path                     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    step                     integer     NOT NULL DEFAULT 0,
    excluded_user_ids        uuid[]      NOT NULL DEFAULT '{}',
    requester_user_id        uuid,
    due_at                   timestamptz NOT NULL,
    due_source               text        NOT NULL,
    external_deadline_at     timestamptz,
    external_deadline_source text        NOT NULL DEFAULT '',
    hours_per_step           integer     NOT NULL,
    state                    text        NOT NULL DEFAULT 'open',
    overdue                  boolean     NOT NULL DEFAULT false,
    overdue_at               timestamptz,
    pending_choice           text,
    pending_by               uuid,
    pending_at               timestamptz,
    answer_choice            text,
    answered_by              uuid,
    answered_at              timestamptz,
    answer_channel           text,
    answer_note              text        NOT NULL DEFAULT '',
    withdrawn_by             uuid,
    withdrawn_at             timestamptz,
    withdraw_reason          text        NOT NULL DEFAULT '',
    created_by_kind          text        NOT NULL DEFAULT 'user',
    created_by               uuid,
    -- A system ask's identity (one open ask per key).
    dedupe_key               text,
    context                  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_ask_pkey PRIMARY KEY (id),
    CONSTRAINT agent_ask_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_ask_case_fkey FOREIGN KEY (workspace_id, case_id)
        REFERENCES public.agent_case (workspace_id, id) ON DELETE SET NULL (case_id),
    CONSTRAINT agent_ask_group_fkey FOREIGN KEY (workspace_id, decider_group_id)
        REFERENCES public.responder_group (workspace_id, id) ON DELETE SET NULL (decider_group_id),
    CONSTRAINT agent_ask_about_kind_chk CHECK (about_kind IN
        ('agent', 'alert', 'key', 'case', 'containment', 'remediation', 'gateway_call')),
    CONSTRAINT agent_ask_about_id_chk CHECK (about_id <> '' AND char_length(about_id) <= 512),
    CONSTRAINT agent_ask_question_chk CHECK (btrim(question) <> '' AND char_length(question) <= 2000),
    CONSTRAINT agent_ask_choices_chk CHECK (jsonb_typeof(choices) = 'array' AND jsonb_array_length(choices) BETWEEN 2 AND 10),
    CONSTRAINT agent_ask_severity_chk CHECK (severity IN ('high', 'medium', 'low')),
    CONSTRAINT agent_ask_tier_chk CHECK (tier BETWEEN 0 AND 4),
    CONSTRAINT agent_ask_role_chk CHECK (role IN ('owner', 'responder', 'code_owner', 'approver')),
    CONSTRAINT agent_ask_path_chk CHECK (jsonb_typeof(path) = 'array'),
    CONSTRAINT agent_ask_step_chk CHECK (step >= 0),
    CONSTRAINT agent_ask_hours_chk CHECK (hours_per_step BETWEEN 1 AND 168),
    CONSTRAINT agent_ask_state_chk CHECK (state IN ('open', 'pending_step_up', 'answered', 'withdrawn', 'expired')),
    CONSTRAINT agent_ask_due_source_chk CHECK (due_source IN ('policy', 'external_deadline')),
    CONSTRAINT agent_ask_external_chk CHECK ((external_deadline_at IS NULL) = (external_deadline_source = '')),
    CONSTRAINT agent_ask_overdue_chk CHECK (overdue = (overdue_at IS NOT NULL)),
    CONSTRAINT agent_ask_pending_chk CHECK ((state = 'pending_step_up')
        = (pending_choice IS NOT NULL AND pending_by IS NOT NULL AND pending_at IS NOT NULL)),
    CONSTRAINT agent_ask_answered_chk CHECK ((state = 'answered')
        = (answer_choice IS NOT NULL AND answered_by IS NOT NULL AND answered_at IS NOT NULL AND answer_channel IS NOT NULL)),
    CONSTRAINT agent_ask_channel_chk CHECK (answer_channel IS NULL OR answer_channel IN ('console', 'slack', 'email')),
    CONSTRAINT agent_ask_withdrawn_chk CHECK ((state = 'withdrawn') = (withdrawn_at IS NOT NULL)),
    CONSTRAINT agent_ask_created_by_chk CHECK (created_by_kind IN ('user', 'system')
        AND (created_by_kind = 'system' OR created_by IS NOT NULL)),
    -- Separation: the requester of the underlying action never answers.
    CONSTRAINT agent_ask_requester_chk CHECK (answered_by IS NULL OR requester_user_id IS NULL OR answered_by <> requester_user_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_ask_ws_created
    ON public.agent_ask (workspace_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_agent_ask_ws_state
    ON public.agent_ask (workspace_id, state, due_at);
CREATE INDEX IF NOT EXISTS idx_agent_ask_ws_about
    ON public.agent_ask (workspace_id, about_kind, about_id);
CREATE INDEX IF NOT EXISTS idx_agent_ask_ws_case
    ON public.agent_ask (workspace_id, case_id) WHERE case_id IS NOT NULL;
-- The escalation worker's scan: live asks not yet at the end of their path.
CREATE INDEX IF NOT EXISTS idx_agent_ask_escalation
    ON public.agent_ask (due_at) WHERE state IN ('open', 'pending_step_up') AND NOT overdue;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_ask_open_dedupe
    ON public.agent_ask (workspace_id, dedupe_key)
    WHERE dedupe_key IS NOT NULL AND state IN ('open', 'pending_step_up');

CREATE TABLE IF NOT EXISTS public.agent_ask_event (
    id           uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL,
    ask_id       uuid        NOT NULL,
    kind         text        NOT NULL,
    step         integer     NOT NULL DEFAULT 0,
    actor_kind   text        NOT NULL DEFAULT 'system',
    actor_id     text        NOT NULL DEFAULT '',
    channel      text        NOT NULL DEFAULT '',
    detail       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_ask_event_pkey PRIMARY KEY (id),
    CONSTRAINT agent_ask_event_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_event_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_ask_event_ask_fkey FOREIGN KEY (workspace_id, ask_id)
        REFERENCES public.agent_ask (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_event_kind_chk CHECK (kind IN ('asked', 'delivered', 'delivery_failed', 'escalated', 'overdue',
        'disputed', 'step_up_pending', 'step_up_confirmed', 'step_up_lapsed', 'answered', 'withdrawn', 'expired',
        'ticket_opened', 'ticket_resolved', 'paged', 'page_resolved', 'external_failed')),
    CONSTRAINT agent_ask_event_actor_chk CHECK (actor_kind IN ('user', 'system', 'slack_user'))
);
CREATE INDEX IF NOT EXISTS idx_agent_ask_event_ask
    ON public.agent_ask_event (workspace_id, ask_id, created_at);

CREATE OR REPLACE FUNCTION public.agent_ask_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('authsec.workspace_purge', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'agent_ask_event is append-only';
END $$;
DROP TRIGGER IF EXISTS agent_ask_event_no_update ON public.agent_ask_event;
CREATE TRIGGER agent_ask_event_no_update BEFORE UPDATE OR DELETE ON public.agent_ask_event
  FOR EACH ROW EXECUTE FUNCTION public.agent_ask_event_immutable();

CREATE TABLE IF NOT EXISTS public.agent_ask_policy (
    workspace_id     uuid        NOT NULL,
    due_high_hours   integer     NOT NULL DEFAULT 4,
    due_medium_hours integer     NOT NULL DEFAULT 24,
    due_low_hours    integer     NOT NULL DEFAULT 72,
    hours_per_step   integer     NOT NULL DEFAULT 4,
    channel_slack    boolean     NOT NULL DEFAULT true,
    channel_email    boolean     NOT NULL DEFAULT true,
    channel_webhook  boolean     NOT NULL DEFAULT false,
    version          bigint      NOT NULL DEFAULT 1,
    updated_by       uuid,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_ask_policy_pkey PRIMARY KEY (workspace_id),
    CONSTRAINT agent_ask_policy_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_policy_due_chk CHECK (due_high_hours BETWEEN 1 AND 720 AND due_medium_hours BETWEEN 1 AND 720
        AND due_low_hours BETWEEN 1 AND 720),
    CONSTRAINT agent_ask_policy_step_chk CHECK (hours_per_step BETWEEN 1 AND 168)
);

CREATE TABLE IF NOT EXISTS public.agent_ask_integration (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL,
    provider           text        NOT NULL,
    category           text        NOT NULL,
    enabled            boolean     NOT NULL DEFAULT true,
    -- Non-secret settings (site URL, project key, routing region ...).
    config             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- The Vault path of the API token / routing key; never the secret.
    secret_ref         text        NOT NULL DEFAULT '',
    secret_fingerprint text        NOT NULL DEFAULT '',
    last_error         text        NOT NULL DEFAULT '',
    last_ok_at         timestamptz,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_ask_integration_pkey PRIMARY KEY (id),
    CONSTRAINT agent_ask_integration_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_integration_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_ask_integration_provider_key UNIQUE (workspace_id, provider),
    CONSTRAINT agent_ask_integration_provider_chk CHECK (
        (category = 'ticketing' AND provider IN ('jira', 'servicenow'))
        OR (category = 'paging' AND provider IN ('pagerduty', 'opsgenie'))),
    CONSTRAINT agent_ask_integration_config_chk CHECK (jsonb_typeof(config) = 'object')
);

CREATE TABLE IF NOT EXISTS public.agent_ask_external (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL,
    provider        text        NOT NULL,
    kind            text        NOT NULL,
    ask_id          uuid,
    case_id         uuid,
    external_key    text        NOT NULL DEFAULT '',
    external_url    text        NOT NULL DEFAULT '',
    state           text        NOT NULL DEFAULT 'pending',
    last_status     text        NOT NULL DEFAULT '',
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text        NOT NULL DEFAULT '',
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz,
    CONSTRAINT agent_ask_external_pkey PRIMARY KEY (id),
    CONSTRAINT agent_ask_external_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_external_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_ask_external_ask_fkey FOREIGN KEY (workspace_id, ask_id)
        REFERENCES public.agent_ask (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_external_case_fkey FOREIGN KEY (workspace_id, case_id)
        REFERENCES public.agent_case (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_ask_external_provider_chk CHECK (provider IN ('jira', 'servicenow', 'pagerduty', 'opsgenie')),
    CONSTRAINT agent_ask_external_kind_chk CHECK ((kind = 'ticket' AND provider IN ('jira', 'servicenow'))
        OR (kind = 'page' AND provider IN ('pagerduty', 'opsgenie'))),
    CONSTRAINT agent_ask_external_subject_chk CHECK ((ask_id IS NULL) <> (case_id IS NULL)),
    -- pending: not created yet; open: created; resolving: a page to resolve;
    -- resolved: closed (externally, or the page was resolved); failed: gave up.
    CONSTRAINT agent_ask_external_state_chk CHECK (state IN ('pending', 'open', 'resolving', 'resolved', 'failed')),
    CONSTRAINT agent_ask_external_resolved_chk CHECK ((state = 'resolved') = (resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_ask_external_ask
    ON public.agent_ask_external (workspace_id, provider, ask_id) WHERE ask_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_ask_external_case
    ON public.agent_ask_external (workspace_id, provider, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_ask_external_due
    ON public.agent_ask_external (next_attempt_at) WHERE state IN ('pending', 'open', 'resolving');

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent_ask');
        PERFORM public.tenancy_enable_rls('public.agent_ask_event');
        PERFORM public.tenancy_enable_rls('public.agent_ask_policy');
        PERFORM public.tenancy_enable_rls('public.agent_ask_integration');
        PERFORM public.tenancy_enable_rls('public.agent_ask_external');
    END IF;
END $$;
