-- ============================================================================
-- Forward delta: human lifecycle (joiner / mover / leaver).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_jml.sql
--
-- Phase 6 of PROVISIONING-GOVERNANCE-ARCHITECTURE.md §11. Depends on
-- governance_provenance.sql.
--
-- WHY THIS IS RECONCILED, NOT EVENT-DRIVEN
-- ARCHITECTURE.md §4.5 proposed consuming `scim_events`. That table turns out to be an
-- HTTP AUDIT LOG -- method, path, status_code, ip_address -- with no semantic payload.
-- `PATCH /Users/123` could be a name change, a deactivation, or a group edit, and the
-- before/after state is not recorded anywhere. Joiner/mover/leaver cannot be derived
-- from it.
--
-- So this reconciles instead: compute the entitlements a user SHOULD have from the
-- birthright policies matching their current groups, compare against the
-- birthright-sourced grants they DO have, and act on the difference. That is strictly
-- better than an event stream would have been:
--
--   - it works for changes made through ANY path (SCIM, the admin console, direct SQL),
--     not only the ones that happened to come through SCIM
--   - it is idempotent and self-healing: a worker that was down for a day catches up on
--     its next pass rather than having missed events forever
--   - it needs no cursor table, because the desired state is computable and the actual
--     state is already in entitlement_provenance (origin='birthright')
--
-- NOTE ON `users`: the authoritative deactivation flag is `active` (models.User.Active,
-- and what the SCIM controller writes). `is_active` is a vestigial duplicate column with
-- no model field and no writer; it is deliberately left alone here rather than being
-- read, because reading the wrong one would make a leaver invisible.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- birthright_policies -------------------------------------------------------
--
-- "Everyone in this group gets this role on this Application." The joiner half of JML,
-- and the thing a mover diff is computed against.
--
-- Matching is GROUP-based (or workspace-wide). Deliberately not department- or
-- title-based: `users` has no such column, and inventing one would mean matching on a
-- field nothing populates.
CREATE TABLE IF NOT EXISTS public.birthright_policies (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',

    -- WHO it applies to.
    match_kind     text NOT NULL DEFAULT 'group',
    match_group_id uuid,

    -- WHAT they get.
    resource_server_id uuid NOT NULL,
    role_id            uuid NOT NULL,

    -- FOR HOW LONG. NULL duration means a STANDING grant, which the provenance layer
    -- requires a justification for -- so the same "ephemeral by default, permanent is
    -- the audited exception" rule applies to birthrights as to everything else.
    duration      interval,
    justification text NOT NULL DEFAULT '',

    -- What to do when a user STOPS matching (the mover case). Default 'flag', because
    -- auto-revoking on a group change would let a mistyped group membership take
    -- someone's access away with no human in the loop. Revoking is opt-in per policy.
    on_unmatch text NOT NULL DEFAULT 'flag',

    enabled    boolean NOT NULL DEFAULT true,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT birthright_policies_pkey PRIMARY KEY (id),
    CONSTRAINT birthright_policies_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_group_fkey FOREIGN KEY (match_group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_rs_fkey FOREIGN KEY (resource_server_id)
        REFERENCES public.resource_servers(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_role_fkey FOREIGN KEY (role_id)
        REFERENCES public.roles(id) ON DELETE CASCADE,
    CONSTRAINT birthright_policies_match_kind_chk CHECK (match_kind IN ('group', 'all')),
    CONSTRAINT birthright_policies_on_unmatch_chk CHECK (on_unmatch IN ('flag', 'revoke')),
    -- A group policy must name a group; an 'all' policy must not, or it would look
    -- scoped while applying to everyone.
    CONSTRAINT birthright_policies_match_chk CHECK (
        (match_kind = 'group' AND match_group_id IS NOT NULL)
     OR (match_kind = 'all'   AND match_group_id IS NULL)),
    -- A standing birthright must say why it is permanent, mirroring the provenance
    -- rule. Without this, "no duration" would quietly become the easy default for
    -- policies that apply to entire groups -- the widest blast radius there is.
    CONSTRAINT birthright_policies_standing_chk CHECK (
        duration IS NOT NULL OR justification <> ''),
    CONSTRAINT birthright_policies_name_key UNIQUE (workspace_id, name)
);

-- One policy per (match, grant) target. Stops two identically-scoped policies both
-- granting the same role, which would make the reconcile's "does this grant still have
-- a matching policy?" question ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS birthright_policies_target_key
    ON public.birthright_policies(
        workspace_id, match_kind,
        COALESCE(match_group_id, '00000000-0000-0000-0000-000000000000'::uuid),
        resource_server_id, role_id);

CREATE INDEX IF NOT EXISTS idx_birthright_policies_enabled
    ON public.birthright_policies(workspace_id) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_birthright_policies_group
    ON public.birthright_policies(match_group_id) WHERE match_group_id IS NOT NULL;

-- Leaver bookkeeping on the user -------------------------------------------
--
-- The reconcile is idempotent and needs no cursor -- desired state is computable and
-- actual state is in provenance. These columns exist only so an operator can SEE that a
-- leaver was processed, and when, without reading the audit log.
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS access_revoked_at timestamptz,
    ADD COLUMN IF NOT EXISTS access_revoked_summary text NOT NULL DEFAULT '';

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.birthright_policies') AS policies_table,
       (SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'users'
           AND column_name IN ('access_revoked_at','access_revoked_summary')) AS user_cols;
