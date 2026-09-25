-- ============================================================================
-- 030: iga_access_edges: typed subject, lifecycle — expand only
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

ALTER TABLE public.iga_access_edges
    ADD COLUMN IF NOT EXISTS subject_identity_account_id uuid,
    ADD COLUMN IF NOT EXISTS provider          text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS basis             text NOT NULL DEFAULT 'declared',
    ADD COLUMN IF NOT EXISTS derivation_rule   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS state             text NOT NULL DEFAULT 'current',
    ADD COLUMN IF NOT EXISTS valid_from        timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS valid_to          timestamptz,
    ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_confirmed_by uuid,
    ADD COLUMN IF NOT EXISTS ended_reason      text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key        text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS partition_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS connector_id      uuid;

-- The only writer ever set subject_kind = 'identity_account' (iga_service.go:918).
UPDATE public.iga_access_edges
   SET subject_identity_account_id = subject_id, provider = 'github'
 WHERE subject_kind = 'identity_account' AND subject_identity_account_id IS NULL;

ALTER TABLE public.iga_access_edges
    ADD CONSTRAINT iga_access_edges_subject_identity_fkey
        FOREIGN KEY (workspace_id, subject_identity_account_id)
        REFERENCES public.iga_identity_accounts (workspace_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT iga_access_edges_connector_fkey
        FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE SET NULL (connector_id),
    ADD CONSTRAINT iga_access_edges_run_fkey
        FOREIGN KEY (workspace_id, last_confirmed_by)
        REFERENCES public.cloud_scan_run (workspace_id, id) ON DELETE SET NULL (last_confirmed_by),
    -- The typed column and the legacy pair agree whenever both are set.
    ADD CONSTRAINT iga_access_edges_subject_agree_chk CHECK (
        subject_identity_account_id IS NULL
        OR (subject_kind = 'identity_account' AND subject_id = subject_identity_account_id)),
    ADD CONSTRAINT iga_access_edges_basis_chk CHECK (basis IN ('declared','observed','derived','asserted')),
    ADD CONSTRAINT iga_access_edges_derivation_chk CHECK (basis <> 'derived' OR derivation_rule <> ''),
    ADD CONSTRAINT iga_access_edges_state_chk CHECK (state IN ('current','stale','ended')),
    ADD CONSTRAINT iga_access_edges_ended_chk CHECK ((state = 'ended') = (valid_to IS NOT NULL)),
    ADD CONSTRAINT iga_access_edges_ended_reason_chk CHECK ((state = 'ended') = (ended_reason <> ''));

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_access_edges_live
    ON public.iga_access_edges (workspace_id, source_key)
    WHERE source_key <> '' AND state <> 'ended';
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_subject_identity
    ON public.iga_access_edges (workspace_id, subject_identity_account_id)
    WHERE subject_identity_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iga_access_edges_partition
    ON public.iga_access_edges (workspace_id, connector_id, partition_key)
    WHERE state <> 'ended';
