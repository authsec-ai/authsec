-- ============================================================================
-- 028: recognition keys, continuity, provider
--
-- SPEC-iga-phase2-graph.md §3, at d9741e7 on authsec-staging. The SQL below
-- is the spec's own, applied verbatim: it is what the spec authors ran on
-- 001-026 plus the graph branch's 027 and probed (§7.6). The rationale for
-- every constraint is in that section; it is not repeated here, so the two
-- cannot drift. Never shipped before this release, so edited in place.
-- ============================================================================

-- iga_entitlements has no lifecycle column (004); the partial index needs one.
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active';
ALTER TABLE public.iga_entitlements
    DROP CONSTRAINT IF EXISTS iga_entitlements_lifecycle_chk,
    ADD CONSTRAINT iga_entitlements_lifecycle_chk CHECK (
        lifecycle IN ('active','retired','tombstoned'));

-- iga_identity_accounts
ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_attrs jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE public.iga_identity_accounts SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_identity_accounts
    DROP CONSTRAINT IF EXISTS iga_identity_accounts_continuity_chk,
    ADD CONSTRAINT iga_identity_accounts_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_identity_accounts_immutable_chk,
    ADD CONSTRAINT iga_identity_accounts_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_identity_accounts_source_key
    ON public.iga_identity_accounts (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
CREATE INDEX IF NOT EXISTS idx_iga_identity_accounts_provider
    ON public.iga_identity_accounts (workspace_id, provider, lifecycle);

-- iga_resources
ALTER TABLE public.iga_resources
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_attrs jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE public.iga_resources SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_resources
    DROP CONSTRAINT IF EXISTS iga_resources_continuity_chk,
    ADD CONSTRAINT iga_resources_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_resources_immutable_chk,
    ADD CONSTRAINT iga_resources_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_resources_source_key
    ON public.iga_resources (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';
CREATE INDEX IF NOT EXISTS idx_iga_resources_provider
    ON public.iga_resources (workspace_id, provider, lifecycle);

-- iga_entitlements
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
UPDATE public.iga_entitlements SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_entitlements
    DROP CONSTRAINT IF EXISTS iga_entitlements_continuity_chk,
    ADD CONSTRAINT iga_entitlements_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_entitlements_immutable_chk,
    ADD CONSTRAINT iga_entitlements_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_entitlements_source_key
    ON public.iga_entitlements (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_credentials: a credential's key is "gone" when revoked or expired, not retired.
ALTER TABLE public.iga_credentials
    ADD COLUMN IF NOT EXISTS provider       text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';
UPDATE public.iga_credentials SET provider = 'github' WHERE provider = '';
ALTER TABLE public.iga_credentials
    DROP CONSTRAINT IF EXISTS iga_credentials_continuity_chk,
    ADD CONSTRAINT iga_credentials_continuity_chk CHECK (continuity IN ('immutable','recognition_only')),
    DROP CONSTRAINT IF EXISTS iga_credentials_immutable_chk,
    ADD CONSTRAINT iga_credentials_immutable_chk CHECK (continuity <> 'immutable' OR immutable_key <> '');
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_credentials_source_key
    ON public.iga_credentials (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle NOT IN ('revoked','expired');

-- iga_estate_scopes: nothing populates it today; the projector does (§4.8).
ALTER TABLE public.iga_estate_scopes
    ADD COLUMN IF NOT EXISTS source_key text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_estate_scopes_source_key
    ON public.iga_estate_scopes (workspace_id, source_key) WHERE source_key <> '';
