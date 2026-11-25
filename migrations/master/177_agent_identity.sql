-- 177_agent_identity.sql
--
-- One agent id (SPEC-secops-backend-upgrade.md W7, P16). Before this an agent
-- was a row in whichever table saw it: an AWS workload the graph classified
-- (iga_workload), a sighting (discovered_agents, including Agent Kit
-- machines' sightings, source vm_sensor), a logical agent of the IGA estate
-- (iga_agents), an agent client (mcp_oauth_clients). A decision about "the
-- agent" had nowhere to live that covered all of them.
--
--   agent                  the stable id, its state and how it ended.
--   agent_alias            every source row that is this agent; one source row
--                          belongs to at most one agent (UNIQUE per workspace,
--                          source table and source id). A merge keeps the
--                          merged agent's aliases, re-pointed at the survivor.
--   agent_purpose_version  versioned purpose text with its assessor.
--   agent_risk_class       versioned risk class (EU AI Act tiers: minimal,
--                          limited, high, prohibited) with obligations and
--                          assessor. Raising is tier 1; lowering is tier 3 and
--                          needs a second person (agent_pending_change).
--   agent_pending_change   the minimal second-person approval of W7's tier-3
--                          changes (lowering a risk class, lowering a
--                          resource's classification): requester <> decider.
--
-- agent_identity_link(ws, table, id) is the one place the linking rules live;
-- the backfill below, the projection hooks and the periodic sweep all call it.
-- Rules, in order (a source row already linked is never moved):
--   1. iga_workload rows the graph calls an agent (provider_native_agent,
--      classified_agent) get an agent each.
--   2. discovered_agents rows: the AWS mirror names its iga_workload
--      (metadata.iga_workload_id) and joins that agent; a row with an ACCEPTED
--      discovered_agent_iga_links link joins the linked iga_agents' agent;
--      any other row gets an agent of its own. A sighting claimed into an
--      agent client (matched_client_id) also links that client.
--   3. iga_agents rows: an ACCEPTED link joins the sighting's agent; any
--      other gets an agent of its own.
-- Two agents found to be one later are merged by a person (POST .../merge),
-- never by this function.
--
-- Every table carries workspace_id, a composite foreign key and row-level
-- security. Expand only; idempotent. 001_bootstrap.sql carries the same
-- objects (without the backfill, which has nothing to read there).

CREATE TABLE IF NOT EXISTS public.agent (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL,
    display_name    text        NOT NULL DEFAULT '',
    -- Where the agent was first seen (cloud_workload, k8s_webhook, agentkit,
    -- iga, ...). Descriptive only.
    kind            text        NOT NULL DEFAULT 'unknown',
    state           text        NOT NULL DEFAULT 'active',
    ended_reason    text        NOT NULL DEFAULT '',
    -- The person who ended it; NULL for deleted_at_source (a pass, no actor).
    ended_by        uuid,
    ended_at        timestamptz,
    merged_into     uuid,
    -- Transferred: to whom (a team, a business unit), as the decider wrote it.
    transferred_to  text        NOT NULL DEFAULT '',
    -- Decision 1 keeps a responder group per estate scope; these let a named
    -- owner or sponsor replace the group later without a schema change.
    owner_user_id   uuid,
    sponsor_user_id uuid,
    version         bigint      NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_pkey PRIMARY KEY (id),
    CONSTRAINT agent_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_merged_fkey FOREIGN KEY (workspace_id, merged_into)
        REFERENCES public.agent (workspace_id, id),
    CONSTRAINT agent_state_chk CHECK (state IN
        ('active', 'retired', 'merged', 'transferred', 'deleted_at_source', 'not_an_agent')),
    CONSTRAINT agent_merged_chk CHECK ((state = 'merged') = (merged_into IS NOT NULL)),
    CONSTRAINT agent_merged_self_chk CHECK (merged_into IS NULL OR merged_into <> id),
    CONSTRAINT agent_ended_chk CHECK ((state = 'active') = (ended_at IS NULL)),
    CONSTRAINT agent_ended_reason_chk CHECK (state = 'active' OR ended_reason <> ''),
    CONSTRAINT agent_transferred_chk CHECK (state <> 'transferred' OR transferred_to <> ''),
    CONSTRAINT agent_kind_chk CHECK (kind <> '')
);
CREATE INDEX IF NOT EXISTS idx_agent_ws_state ON public.agent (workspace_id, state, created_at DESC, id);

CREATE TABLE IF NOT EXISTS public.agent_alias (
    id           uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL,
    agent_id     uuid        NOT NULL,
    source_table text        NOT NULL,
    -- text: Agent Kit recogniser ids and client ids are not uuids.
    source_id    text        NOT NULL,
    -- 'system' (projection, sweep), 'backfill' (this migration) or a user id.
    linked_by    text        NOT NULL DEFAULT 'system',
    linked_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_alias_pkey PRIMARY KEY (id),
    CONSTRAINT agent_alias_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_alias_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_alias_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_alias_source_key UNIQUE (workspace_id, source_table, source_id),
    CONSTRAINT agent_alias_source_chk CHECK (source_table IN
        ('iga_workload', 'discovered_agents', 'iga_agents', 'agentkit', 'resource_servers', 'mcp_oauth_clients')),
    CONSTRAINT agent_alias_source_id_chk CHECK (source_id <> '')
);
CREATE INDEX IF NOT EXISTS idx_agent_alias_agent ON public.agent_alias (workspace_id, agent_id);

CREATE TABLE IF NOT EXISTS public.agent_purpose_version (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id     uuid        NOT NULL,
    agent_id         uuid        NOT NULL,
    version          integer     NOT NULL,
    purpose          text        NOT NULL,
    assessor_user_id uuid        NOT NULL,
    assessed_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_purpose_version_pkey PRIMARY KEY (id),
    CONSTRAINT agent_purpose_version_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_purpose_version_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_purpose_version_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_purpose_version_key UNIQUE (workspace_id, agent_id, version),
    CONSTRAINT agent_purpose_version_chk CHECK (version > 0),
    CONSTRAINT agent_purpose_text_chk CHECK (length(purpose) BETWEEN 1 AND 2000)
);

CREATE TABLE IF NOT EXISTS public.agent_risk_class (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    agent_id            uuid        NOT NULL,
    version             integer     NOT NULL,
    risk_class          text        NOT NULL,
    -- What the class obliges ("human oversight", "logging"): a JSON array of
    -- strings, as the assessor wrote them.
    obligations         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    reason              text        NOT NULL,
    assessor_user_id    uuid        NOT NULL,
    -- Set when the version lowered the class: the second person.
    approved_by_user_id uuid,
    pending_change_id   uuid,
    assessed_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_risk_class_pkey PRIMARY KEY (id),
    CONSTRAINT agent_risk_class_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_risk_class_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_risk_class_agent_fkey FOREIGN KEY (workspace_id, agent_id)
        REFERENCES public.agent (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_risk_class_key UNIQUE (workspace_id, agent_id, version),
    CONSTRAINT agent_risk_class_version_chk CHECK (version > 0),
    CONSTRAINT agent_risk_class_chk CHECK (risk_class IN ('minimal', 'limited', 'high', 'prohibited')),
    CONSTRAINT agent_risk_class_obligations_chk CHECK (jsonb_typeof(obligations) = 'array'),
    CONSTRAINT agent_risk_class_reason_chk CHECK (reason <> ''),
    CONSTRAINT agent_risk_class_second_person_chk CHECK
        (approved_by_user_id IS NULL OR approved_by_user_id <> assessor_user_id)
);

CREATE TABLE IF NOT EXISTS public.agent_pending_change (
    id              uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL,
    kind            text        NOT NULL,
    subject_id      uuid        NOT NULL,
    -- The change as requested (the new class and obligations, or the new
    -- classification); applied verbatim by the approver.
    payload         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    reason          text        NOT NULL,
    requested_by    uuid        NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    state           text        NOT NULL DEFAULT 'pending',
    decided_by      uuid,
    decided_at      timestamptz,
    decision_reason text        NOT NULL DEFAULT '',
    CONSTRAINT agent_pending_change_pkey PRIMARY KEY (id),
    CONSTRAINT agent_pending_change_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_pending_change_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT agent_pending_change_kind_chk CHECK (kind IN
        ('agent_risk_class_lower', 'resource_classification_lower')),
    CONSTRAINT agent_pending_change_state_chk CHECK (state IN ('pending', 'applied', 'rejected', 'withdrawn')),
    CONSTRAINT agent_pending_change_reason_chk CHECK (reason <> ''),
    CONSTRAINT agent_pending_change_decided_chk CHECK ((state = 'pending') = (decided_at IS NULL)),
    -- Separation (decision 4): the requester never applies or rejects their own
    -- change; withdrawing it is theirs.
    CONSTRAINT agent_pending_change_second_person_chk CHECK
        (state NOT IN ('applied', 'rejected') OR decided_by <> requested_by),
    CONSTRAINT agent_pending_change_withdraw_chk CHECK
        (state <> 'withdrawn' OR decided_by = requested_by)
);
CREATE INDEX IF NOT EXISTS idx_agent_pending_change_list
    ON public.agent_pending_change (workspace_id, state, requested_at DESC, id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_pending_change_open
    ON public.agent_pending_change (workspace_id, kind, subject_id) WHERE state = 'pending';

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.agent');
        PERFORM public.tenancy_enable_rls('public.agent_alias');
        PERFORM public.tenancy_enable_rls('public.agent_purpose_version');
        PERFORM public.tenancy_enable_rls('public.agent_risk_class');
        PERFORM public.tenancy_enable_rls('public.agent_pending_change');
    END IF;
END $$;

-- agent_identity_link links the workspace's unlinked source rows (all of them,
-- or one: p_table/p_id) and returns how many aliases it wrote. SECURITY
-- INVOKER: under the request's row-level security it sees only p_ws's rows.
CREATE OR REPLACE FUNCTION public.agent_identity_link(p_ws uuid, p_table text DEFAULT NULL, p_id text DEFAULT NULL)
RETURNS integer LANGUAGE plpgsql AS $$
DECLARE
    n   integer := 0;
    r   record;
    aid uuid;
BEGIN
    IF p_ws IS NULL THEN
        RAISE EXCEPTION 'agent_identity_link: workspace is required';
    END IF;

    -- 1. Workloads the graph calls an agent.
    IF p_table IS NULL OR p_table = 'iga_workload' THEN
        FOR r IN
            SELECT w.id::text AS sid, w.display_name, w.provider
              FROM public.iga_workload w
             WHERE w.workspace_id = p_ws
               AND w.classification IN ('provider_native_agent', 'classified_agent')
               AND (p_id IS NULL OR w.id::text = p_id)
               AND NOT EXISTS (SELECT 1 FROM public.agent_alias a
                                WHERE a.workspace_id = p_ws AND a.source_table = 'iga_workload' AND a.source_id = w.id::text)
             ORDER BY w.created_at, w.id
        LOOP
            INSERT INTO public.agent (workspace_id, display_name, kind)
                 VALUES (p_ws, r.display_name, r.provider || '_workload') RETURNING id INTO aid;
            INSERT INTO public.agent_alias (workspace_id, agent_id, source_table, source_id)
                 VALUES (p_ws, aid, 'iga_workload', r.sid);
            n := n + 1;
        END LOOP;
    END IF;

    -- 2. Sightings.
    IF p_table IS NULL OR p_table = 'discovered_agents' THEN
        FOR r IN
            SELECT d.id::text AS sid, d.display_name, d.source, d.matched_client_id,
                   (SELECT a.agent_id FROM public.agent_alias a
                     WHERE a.workspace_id = p_ws AND a.source_table = 'iga_workload'
                       AND a.source_id = d.metadata->>'iga_workload_id') AS via_workload,
                   (SELECT a.agent_id FROM public.discovered_agent_iga_links l
                      JOIN public.agent_alias a ON a.workspace_id = l.workspace_id
                       AND a.source_table = 'iga_agents' AND a.source_id = l.iga_agent_id::text
                     WHERE l.workspace_id = p_ws AND l.discovered_agent_id = d.id AND l.state = 'accepted'
                     LIMIT 1) AS via_link
              FROM public.discovered_agents d
             WHERE d.workspace_id = p_ws
               AND (p_id IS NULL OR d.id::text = p_id)
               AND NOT EXISTS (SELECT 1 FROM public.agent_alias a
                                WHERE a.workspace_id = p_ws AND a.source_table = 'discovered_agents' AND a.source_id = d.id::text)
             ORDER BY d.first_seen_at, d.id
        LOOP
            aid := COALESCE(r.via_workload, r.via_link);
            IF aid IS NULL THEN
                INSERT INTO public.agent (workspace_id, display_name, kind)
                     VALUES (p_ws, r.display_name,
                             CASE WHEN r.source = 'vm_sensor' THEN 'agentkit' ELSE COALESCE(NULLIF(r.source, ''), 'discovered') END)
                  RETURNING id INTO aid;
            END IF;
            INSERT INTO public.agent_alias (workspace_id, agent_id, source_table, source_id)
                 VALUES (p_ws, aid, 'discovered_agents', r.sid);
            n := n + 1;
            IF r.matched_client_id IS NOT NULL THEN
                INSERT INTO public.agent_alias (workspace_id, agent_id, source_table, source_id)
                     VALUES (p_ws, aid, 'mcp_oauth_clients', r.matched_client_id::text)
                ON CONFLICT (workspace_id, source_table, source_id) DO NOTHING;
            END IF;
        END LOOP;
    END IF;

    -- 3. Logical agents of the IGA estate.
    IF p_table IS NULL OR p_table = 'iga_agents' THEN
        FOR r IN
            SELECT g.id::text AS sid, g.display_name,
                   (SELECT a.agent_id FROM public.discovered_agent_iga_links l
                      JOIN public.agent_alias a ON a.workspace_id = l.workspace_id
                       AND a.source_table = 'discovered_agents' AND a.source_id = l.discovered_agent_id::text
                     WHERE l.workspace_id = p_ws AND l.iga_agent_id = g.id AND l.state = 'accepted'
                     LIMIT 1) AS via_link
              FROM public.iga_agents g
             WHERE g.workspace_id = p_ws
               AND (p_id IS NULL OR g.id::text = p_id)
               AND NOT EXISTS (SELECT 1 FROM public.agent_alias a
                                WHERE a.workspace_id = p_ws AND a.source_table = 'iga_agents' AND a.source_id = g.id::text)
             ORDER BY g.created_at, g.id
        LOOP
            aid := r.via_link;
            IF aid IS NULL THEN
                INSERT INTO public.agent (workspace_id, display_name, kind)
                     VALUES (p_ws, r.display_name, 'iga') RETURNING id INTO aid;
            END IF;
            INSERT INTO public.agent_alias (workspace_id, agent_id, source_table, source_id)
                 VALUES (p_ws, aid, 'iga_agents', r.sid);
            n := n + 1;
        END LOOP;
    END IF;
    RETURN n;
END;
$$;

-- Backfill: every workspace's existing rows, recorded as the backfill's.
DO $$
DECLARE
    w record;
BEGIN
    FOR w IN SELECT id FROM public.workspaces LOOP
        PERFORM public.agent_identity_link(w.id);
    END LOOP;
    UPDATE public.agent_alias SET linked_by = 'backfill' WHERE linked_by = 'system';
END $$;
