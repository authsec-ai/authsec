-- ============================================================================
-- Forward delta: pre-deadline warnings (phase 1B of ENFORCEMENT-ARCHITECTURE.md §7).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_policy_warnings.sql
--
-- Depends on governance_agent_policies.sql.
--
-- WHAT THIS IS
-- §3A.4 requires that a destructive deadline is warned about before it fires. This
-- is the durable side of that: a row per (policy, deadline, channel, recipient),
-- scheduled at deadline-minus-lead, retried on failure, and sent exactly once across
-- replicas.
--
-- WHY NOT iga_durable_jobs, WHICH §3A.9 PROPOSED
-- Two reasons found on inspection, both structural:
--
--   1. iga_durable_jobs.integration_id is NOT NULL with a foreign key to
--      iga_integrations. A policy-expiry warning has no integration -- it belongs to
--      a policy, not to a connected IGA system -- so every row would need a synthetic
--      integration invented for it, and the FK would then delete warnings when an
--      unrelated integration was removed.
--   2. Nothing drains that queue. IGAManager.RunWorkerOnce exists but is called from
--      no running process, only from tests. "No scheduler needs writing" was wrong;
--      one had to be written either way.
--
-- So this reuses the PATTERN that table established -- available_at, a dedupe key,
-- attempt_count, a lease-free claim via FOR UPDATE SKIP LOCKED -- without borrowing
-- a table that structurally cannot hold the row.
--
-- WHY THE DEADLINE IS IN THE DEDUPE KEY
-- Moving a policy's expiry must schedule a NEW warning. Keyed on policy alone, an
-- operator who pushed a deletion out by a month would get no second warning, because
-- one had already been sent for a deadline that no longer exists.
--
-- A FAILED WARNING NEVER BLOCKS THE ACTION. Blocking would mean an SMTP outage
-- silently turns every destructive policy into a no-op, which is precisely the
-- failure §3A.4 exists to prevent. The failure is recorded instead, and a destructive
-- action that ran without a delivered warning is a governance exception the console
-- surfaces (agent_policy_actions.warning_delivered = false).
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- governance_notification_settings ------------------------------------------
-- One row per workspace. Separate from any policy, because the channel is an
-- operational property of the tenant -- who to tell -- and not of any one decision.
CREATE TABLE IF NOT EXISTS public.governance_notification_settings (
    workspace_id uuid PRIMARY KEY,

    -- How far ahead of a destructive deadline to warn. Default 7 days: long enough
    -- to act on during a normal working week, including a weekend.
    warning_lead interval NOT NULL DEFAULT '7 days',

    -- OPTIONAL second channel. Outbound only, so it costs nothing against EN-0 --
    -- the control plane calling a customer's Slack is not the control plane calling
    -- into a customer's cluster.
    webhook_url    text NOT NULL DEFAULT '',
    webhook_secret text NOT NULL DEFAULT '',

    -- Email can be turned off for a tenant that routes everything through the
    -- webhook. The LOOKAHEAD is still the system of record either way, so a
    -- workspace with both channels off is degraded, not blind.
    email_enabled boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT gov_notif_settings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    -- A lead of zero would "warn" at the instant of destruction, which is not a
    -- warning. An upper bound stops a typo scheduling a warning years out, where it
    -- would sit pending and look like the system had gone quiet.
    CONSTRAINT gov_notif_settings_lead_chk CHECK (
        warning_lead >= interval '1 hour' AND warning_lead <= interval '90 days'),
    -- https only. A warning naming which workload is about to be deleted is a map of
    -- what to attack during the window in which nobody is watching it.
    CONSTRAINT gov_notif_settings_webhook_chk CHECK (
        webhook_url = '' OR webhook_url LIKE 'https://%')
);

-- agent_policy_warnings -----------------------------------------------------
CREATE TABLE IF NOT EXISTS public.agent_policy_warnings (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    policy_id    uuid NOT NULL,

    -- Which agent is about to be affected. A warning names ONE agent, not a policy:
    -- "three of your agents will be deleted" is a summary, and the person who needs
    -- to act needs to know which one is theirs.
    discovered_agent_id uuid NOT NULL,

    -- The deadline being warned about, and part of the dedupe key. Moving a policy's
    -- expiry therefore schedules a fresh warning rather than reusing a sent one.
    deadline timestamptz NOT NULL,
    -- What is going to happen. Snapshotted rather than read from the policy at send
    -- time: the warning must describe what was scheduled when it was scheduled.
    on_expiry text NOT NULL,

    channel   text NOT NULL,
    -- The address or URL actually used, so "who was told" is answerable later. Part
    -- of the dedupe key, so adding a recipient warns THEM without re-warning
    -- everybody who already knew.
    recipient text NOT NULL,
    -- Why this recipient was chosen, for the audit trail: owner | author | confirmer
    -- | workspace_admin | webhook.
    recipient_role text NOT NULL DEFAULT '',

    available_at timestamptz NOT NULL,
    state        text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    last_error   text NOT NULL DEFAULT '',
    sent_at      timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT agent_policy_warnings_pkey PRIMARY KEY (id),
    CONSTRAINT agent_policy_warnings_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_policy_fkey FOREIGN KEY (policy_id)
        REFERENCES public.agent_policies(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_agent_fkey FOREIGN KEY (discovered_agent_id)
        REFERENCES public.discovered_agents(id) ON DELETE CASCADE,
    CONSTRAINT agent_policy_warnings_channel_chk CHECK (channel IN ('email', 'webhook')),
    CONSTRAINT agent_policy_warnings_state_chk CHECK (
        state IN ('pending', 'sent', 'failed', 'dead')),
    -- 'sent' must carry its timestamp, or "was this warned about" degrades to a
    -- boolean with no time attached and cannot be compared against the deadline.
    CONSTRAINT agent_policy_warnings_sent_chk CHECK (
        (state = 'sent') = (sent_at IS NOT NULL)),
    -- Fires ONCE. Two replicas scheduling in the same tick collide here rather than
    -- double-mailing an operator about the deletion of their workload.
    CONSTRAINT agent_policy_warnings_dedupe_key UNIQUE (
        policy_id, discovered_agent_id, deadline, channel, recipient)
);

-- The delivery worker's claim path: due, not yet sent, oldest first.
CREATE INDEX IF NOT EXISTS idx_agent_policy_warnings_due
    ON public.agent_policy_warnings(available_at)
    WHERE state IN ('pending', 'failed');

-- "Was this action warned about?" -- read by the reconciler when it records a
-- destructive action, and by the console when it lists governance exceptions.
CREATE INDEX IF NOT EXISTS idx_agent_policy_warnings_lookup
    ON public.agent_policy_warnings(workspace_id, discovered_agent_id, deadline);
