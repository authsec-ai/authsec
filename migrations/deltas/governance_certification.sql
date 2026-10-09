-- ============================================================================
-- Forward delta: access certification (campaigns + items).
-- Run once against a LIVE database (idempotent):
--     psql "$DATABASE_URL" -f governance_certification.sql
--
-- Phase 4 of PROVISIONING-GOVERNANCE-ARCHITECTURE.md §11. Depends on
-- governance_provenance.sql and governance_sod.sql.
--
-- WHAT CERTIFICATION IS
-- Periodically, the accountable human for each entitlement confirms it is still
-- needed or revokes it. It exists because access accumulates -- people request,
-- nobody removes -- and because an auditor wants evidence that a NAMED person
-- reviewed and decided.
--
-- WHY THE QUEUE HERE IS SMALL, AND WHY THAT IS THE POINT
-- Traditional IGA certification exists because all access is standing. PG-4 inverted
-- that: grants expire by default and the expiry worker enforces it, so most access
-- never reaches a review -- it simply lapses. What genuinely needs certifying is the
-- STANDING grants, which is why standing_only is the default scope.
--
-- ITEMS ARE SNAPSHOTS, NOT LIVE JOINS
-- Certifying against live data means the thing you approved can change under you
-- mid-review, and the frozen export at close would not match what the reviewer
-- actually saw. So each item carries the grant plus its evidence as it stood when the
-- campaign was generated.
--
-- NOT a committed migration; the source of truth remains 001_bootstrap.sql.
-- ============================================================================

-- certification_campaigns --------------------------------------------------
CREATE TABLE IF NOT EXISTS public.certification_campaigns (
    id           uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',

    -- What to review. Typed in Go (services.CampaignScope) but stored as jsonb, so a
    -- new filter dimension does not need a migration. Empty means the default:
    -- standing grants only.
    scope jsonb NOT NULL DEFAULT '{}'::jsonb,

    status text NOT NULL DEFAULT 'draft',
    -- Reviewers get until this date; past it, items are overdue and escalate to the
    -- workspace owner. A campaign with no deadline is one nobody finishes.
    due_at timestamptz,

    -- The frozen export, written at close. This is the artifact an auditor reads, so
    -- it is stored rather than recomputed: recomputing it later would reflect the
    -- world as it is now, not as the reviewer found it.
    export      jsonb,
    generated_at timestamptz,
    closed_at    timestamptz,
    closed_by    uuid,

    -- Denormalised counters, maintained as decisions land, so a campaign list does not
    -- need an aggregate over every item.
    items_total    integer NOT NULL DEFAULT 0,
    items_decided  integer NOT NULL DEFAULT 0,
    items_kept     integer NOT NULL DEFAULT 0,
    items_revoked  integer NOT NULL DEFAULT 0,

    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT certification_campaigns_pkey PRIMARY KEY (id),
    CONSTRAINT certification_campaigns_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT certification_campaigns_closed_by_fkey FOREIGN KEY (closed_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_campaigns_status_chk CHECK (
        status IN ('draft', 'active', 'closed')),
    -- A closed campaign must have its export. Without this, "closed" could mean
    -- "abandoned" and the audit artifact would be silently absent.
    CONSTRAINT certification_campaigns_closed_chk CHECK (
        status <> 'closed' OR (closed_at IS NOT NULL AND export IS NOT NULL)),
    -- An active campaign must have been generated: an active campaign with no items is
    -- a review nobody can perform.
    CONSTRAINT certification_campaigns_active_chk CHECK (
        status <> 'active' OR generated_at IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS certification_campaigns_name_key
    ON public.certification_campaigns(workspace_id, name);
CREATE INDEX IF NOT EXISTS idx_certification_campaigns_status
    ON public.certification_campaigns(workspace_id, status, due_at);

-- certification_items ------------------------------------------------------
--
-- One entitlement under review. entitlement_provenance_id is the anchor: provenance is
-- already the append-only record of WHY a grant exists, so an item points at it rather
-- than re-deriving the justification.
CREATE TABLE IF NOT EXISTS public.certification_items (
    id          uuid NOT NULL DEFAULT gen_random_uuid(),
    campaign_id uuid NOT NULL,
    workspace_id uuid NOT NULL,

    -- ON DELETE SET NULL, not CASCADE: an item must survive its provenance row being
    -- removed, or closing a campaign could lose the very record it certified.
    entitlement_provenance_id uuid,

    -- The SNAPSHOT. Everything the reviewer saw, frozen at generation.
    subject_type  text NOT NULL,
    subject_id    uuid NOT NULL,
    subject_label text NOT NULL DEFAULT '',
    entitlement_label text NOT NULL DEFAULT '',
    entitlement_type  text NOT NULL DEFAULT '',
    snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Assembled evidence: why it was granted, whether it has ever been used, whether
    -- the workload is still running, and any open SoD violation. This is the
    -- difference between a real review and a rubber stamp.
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Who has to decide, resolved at generation: resource-server owner -> the human who
    -- granted it -> workspace owner. Frozen, so a later ownership change cannot
    -- silently move an in-flight review.
    reviewer_user_id uuid,
    reviewer_label   text NOT NULL DEFAULT '',
    reviewer_source  text NOT NULL DEFAULT '',

    decision      text NOT NULL DEFAULT 'pending',
    decision_note text NOT NULL DEFAULT '',
    decided_by    uuid,
    decided_at    timestamptz,
    -- Set when a 'revoke' decision was actually carried out, so a decision that failed
    -- to execute is visibly distinct from one that succeeded.
    revocation_executed_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT certification_items_pkey PRIMARY KEY (id),
    CONSTRAINT certification_items_campaign_fkey FOREIGN KEY (campaign_id)
        REFERENCES public.certification_campaigns(id) ON DELETE CASCADE,
    CONSTRAINT certification_items_workspace_fkey FOREIGN KEY (workspace_id)
        REFERENCES public.workspaces(id) ON DELETE CASCADE,
    CONSTRAINT certification_items_provenance_fkey FOREIGN KEY (entitlement_provenance_id)
        REFERENCES public.entitlement_provenance(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_reviewer_fkey FOREIGN KEY (reviewer_user_id)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_decided_by_fkey FOREIGN KEY (decided_by)
        REFERENCES public.users(id) ON DELETE SET NULL,
    CONSTRAINT certification_items_decision_chk CHECK (
        decision IN ('pending', 'keep', 'revoke', 'delegate')),
    -- A decision must record who made it and when. An undated decision is not evidence.
    CONSTRAINT certification_items_decided_chk CHECK (
        decision = 'pending' OR (decided_at IS NOT NULL)),
    -- Keeping an entitlement needs a reason as much as revoking one does: "keep"
    -- without justification is exactly the rubber stamp certification exists to stop.
    CONSTRAINT certification_items_keep_note_chk CHECK (
        decision <> 'keep' OR decision_note <> '')
);

-- One item per entitlement per campaign. Without this, re-running generation would
-- duplicate the reviewer's work and double-count the campaign totals.
CREATE UNIQUE INDEX IF NOT EXISTS certification_items_unique_key
    ON public.certification_items(campaign_id, entitlement_provenance_id)
    WHERE entitlement_provenance_id IS NOT NULL;

-- The reviewer's queue.
CREATE INDEX IF NOT EXISTS idx_certification_items_reviewer
    ON public.certification_items(workspace_id, reviewer_user_id, decision);
CREATE INDEX IF NOT EXISTS idx_certification_items_campaign
    ON public.certification_items(campaign_id, decision);

-- verify -------------------------------------------------------------------
SELECT to_regclass('public.certification_campaigns') AS campaigns_table,
       to_regclass('public.certification_items')     AS items_table;
