-- 043_discovery_ingest_auth.sql — authenticate the discovery ingress, and record
-- which cluster (and which OIDC issuer) a Kubernetes sweep came from.
--
-- expand only.
--
-- WHY
-- The discovery ingress (/authsec/discovery/agent-registration, /sightings,
-- /lifecycle, /resync-manifest, /rbac-snapshot) is unauthenticated: it trusts
-- the workspace_id in the body. Since the shared graph projects those payloads
-- synchronously, anyone holding a workspace UUID could inject a cluster-admin
-- grant or post a "complete" sweep that ends a real cluster's model. The agent
-- already sends `Authorization: Bearer <SOURCE_TOKEN>`; nothing checked it.
--
-- discovery_ingest_tokens holds the HASH of each token an admin mints for a
-- workspace (optionally bound to one discovery source). The plaintext is shown
-- once at mint time and never stored. A token authenticates every ingress call
-- for its workspace; revoking it is a timestamp, not a delete, so the audit
-- trail of what it authorised survives.
--
-- iga_k8s_sweep gains the cluster's UID and OIDC issuer as the agent reported
-- them. The UID lets the server refuse a sweep from a DIFFERENT cluster that
-- happens to share a name (today two such clusters silently merge). The issuer
-- is what an AWS IRSA trust names (oidc.eks.<region>.amazonaws.com/id/<x>), so
-- it is the join that lets an AWS role's trust resolve to the Kubernetes
-- ServiceAccount that can assume it.

-- 1. Ingest tokens -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.discovery_ingest_tokens (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    workspace_id        uuid        NOT NULL,
    -- NULL: valid for any discovery source in the workspace (an enrollment
    -- token used before the agent's source exists). Set: valid only for calls
    -- that resolve to this source.
    discovery_source_id uuid,
    -- sha256 of the token, hex. Never the token.
    token_hash          text        NOT NULL,
    -- the first characters of the token, for an operator to tell tokens apart
    -- in a list; never enough to use it.
    token_prefix        text        NOT NULL DEFAULT '',
    label               text        NOT NULL DEFAULT '',
    created_by          text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz,
    revoked_at          timestamptz,

    CONSTRAINT discovery_ingest_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT discovery_ingest_tokens_workspace_id_key UNIQUE (workspace_id, id),
    CONSTRAINT discovery_ingest_tokens_hash_key UNIQUE (token_hash),
    CONSTRAINT discovery_ingest_tokens_hash_chk CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT discovery_ingest_tokens_workspace_fkey
        FOREIGN KEY (workspace_id) REFERENCES public.workspaces (id) ON DELETE CASCADE,
    CONSTRAINT discovery_ingest_tokens_source_fkey
        FOREIGN KEY (workspace_id, discovery_source_id)
        REFERENCES public.discovery_sources (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_discovery_ingest_tokens_workspace
    ON public.discovery_ingest_tokens (workspace_id)
    WHERE revoked_at IS NULL;

-- 2. Which cluster a sweep came from ----------------------------------------
ALTER TABLE public.iga_k8s_sweep
    ADD COLUMN IF NOT EXISTS cluster_uid text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS oidc_issuer text NOT NULL DEFAULT '';

-- verify ----------------------------------------------------------------------
DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = 'discovery_ingest_tokens';
    IF n <> 1 THEN
        RAISE EXCEPTION '043: discovery_ingest_tokens was not created';
    END IF;

    SELECT count(*) INTO n FROM information_schema.columns
     WHERE table_name = 'iga_k8s_sweep' AND column_name IN ('cluster_uid', 'oidc_issuer');
    IF n <> 2 THEN
        RAISE EXCEPTION '043: iga_k8s_sweep did not gain cluster_uid and oidc_issuer (found %)', n;
    END IF;
END $$;
