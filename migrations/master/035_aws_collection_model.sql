-- ============================================================================
-- 035: AWS collection model
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

-- Targets for integration-qualified references. id is already the primary
-- key, so both are always satisfiable.
ALTER TABLE public.cloud_identity
    ADD CONSTRAINT cloud_identity_scope_key UNIQUE (workspace_id, connector_id, id);

-- Groups are identities: kind 'iam_group' (cloud_identity_kind_chk only
-- requires kind <> '', so no constraint change).

-- The role's trust document, verbatim, so the projector parses Allow AND Deny
-- statements with their conditions. trust_parse_error is non-empty when the
-- document could not be parsed: that role's trust edges go stale (§4.10).
ALTER TABLE public.cloud_identity
    ADD COLUMN IF NOT EXISTS trust_document jsonb,
    ADD COLUMN IF NOT EXISTS trust_document_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS trust_parse_error  text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS public.cloud_group_membership (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    connector_id         uuid NOT NULL,
    user_identity_id     uuid NOT NULL,
    group_identity_id    uuid NOT NULL,
    last_seen_generation integer NOT NULL,
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_group_membership_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_gm_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_user_fkey FOREIGN KEY (workspace_id, connector_id, user_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_group_fkey FOREIGN KEY (workspace_id, connector_id, group_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_gm_key UNIQUE (user_identity_id, group_identity_id)
);

-- A policy AS READ BY ONE CONNECTOR. Keyed per connector, unlike
-- cloud_resource: an AWS-managed policy attached in two accounts is two rows
-- here and ONE iga_policy, and no scanner ever reassigns another's row.
CREATE TABLE IF NOT EXISTS public.cloud_policy (
    id                   uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id         uuid NOT NULL,
    connector_id         uuid NOT NULL,
    policy_kind          text NOT NULL,     -- managed | inline
    native_id            text NOT NULL,     -- managed: ARN; inline: 'inline:' || holder ARN || ':' || name
    holder_identity_id   uuid,              -- inline only
    name                 text NOT NULL,
    policy_id            text NOT NULL DEFAULT '',  -- AWS PolicyId (ANPA…), managed only
    aws_managed          boolean NOT NULL DEFAULT false,
    version_id           text NOT NULL DEFAULT '',  -- default version, managed only
    document             jsonb,             -- NULL when the document could not be fetched
    document_hash        text NOT NULL DEFAULT '',
    -- Non-empty when the document is UNREADABLE this run: it could not be
    -- fetched ("fetch: AccessDenied") or did not parse ("parse: …"). Such a
    -- policy's statements, grants and the resources only it names go stale,
    -- never ended (§4.10).
    document_error       text NOT NULL DEFAULT '',
    last_seen_generation integer NOT NULL,
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_policy_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_policy_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT cloud_policy_scope_key UNIQUE (workspace_id, connector_id, id),
    CONSTRAINT cloud_policy_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_policy_holder_fkey FOREIGN KEY (workspace_id, connector_id, holder_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_policy_kind_chk CHECK (policy_kind IN ('managed','inline')),
    CONSTRAINT cloud_policy_inline_chk CHECK ((policy_kind = 'inline') = (holder_identity_id IS NOT NULL)),
    CONSTRAINT cloud_policy_readable_chk CHECK (document IS NOT NULL OR document_error <> ''),
    CONSTRAINT cloud_policy_key UNIQUE (connector_id, native_id)
);

CREATE TABLE IF NOT EXISTS public.cloud_policy_attachment (
    id                    uuid NOT NULL DEFAULT gen_random_uuid(),
    workspace_id          uuid NOT NULL,
    connector_id          uuid NOT NULL,
    policy_row_id         uuid NOT NULL,
    principal_identity_id uuid NOT NULL,   -- role, user or group
    attachment_kind       text NOT NULL,   -- attached | inline | boundary
    last_seen_generation  integer NOT NULL,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cloud_policy_attachment_pkey PRIMARY KEY (id),
    CONSTRAINT cloud_pa_connector_fkey FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE,
    -- Same workspace AND same integration: an attachment is one account's fact
    -- about its own policy and its own principal.
    CONSTRAINT cloud_pa_policy_fkey FOREIGN KEY (workspace_id, connector_id, policy_row_id)
        REFERENCES public.cloud_policy (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_pa_principal_fkey FOREIGN KEY (workspace_id, connector_id, principal_identity_id)
        REFERENCES public.cloud_identity (workspace_id, connector_id, id) ON DELETE CASCADE,
    CONSTRAINT cloud_pa_kind_chk CHECK (attachment_kind IN ('attached','inline','boundary')),
    CONSTRAINT cloud_pa_key UNIQUE (policy_row_id, principal_identity_id, attachment_kind)
);

-- Policy versions as evidence subjects, integration-qualified like the rest.
-- Widening the subject columns means widening the at-most-one check AND both
-- dedupe indexes, or a policy observation dedupes against the wrong key.
ALTER TABLE public.cloud_observation
    ADD COLUMN IF NOT EXISTS policy_id uuid,
    ADD CONSTRAINT cloud_observation_policy_fkey FOREIGN KEY (workspace_id, connector_id, policy_id)
        REFERENCES public.cloud_policy (workspace_id, connector_id, id) ON DELETE SET NULL (policy_id);
ALTER TABLE public.cloud_observation DROP CONSTRAINT IF EXISTS cloud_observation_subject_chk;
ALTER TABLE public.cloud_observation ADD CONSTRAINT cloud_observation_subject_chk CHECK (
      (identity_id IS NOT NULL)::int + (permission_id IS NOT NULL)::int
    + (resource_id IS NOT NULL)::int + (workload_id IS NOT NULL)::int
    + (policy_id   IS NOT NULL)::int <= 1);
DROP INDEX IF EXISTS public.uq_cloud_observation_dedupe;
CREATE UNIQUE INDEX uq_cloud_observation_dedupe ON public.cloud_observation (
    workspace_id, COALESCE(identity_id, permission_id, resource_id, workload_id, policy_id),
    source_api, content_hash);
DROP INDEX IF EXISTS public.uq_cloud_observation_dedupe_no_subject;
CREATE UNIQUE INDEX uq_cloud_observation_dedupe_no_subject
    ON public.cloud_observation (workspace_id, source_api, content_hash)
    WHERE identity_id IS NULL AND permission_id IS NULL AND resource_id IS NULL
      AND workload_id IS NULL AND policy_id IS NULL;

-- A refused claim is re-queued with a fresh requested_at (§2.10A). The
-- oldest-first claim is already indexed by 020's idx_cloud_scan_run_claimable.
