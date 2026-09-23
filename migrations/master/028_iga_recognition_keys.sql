-- ============================================================================
-- 028: recognition keys and continuity on the canonical node tables.
--
-- SPEC-iga-phase2-graph.md §2.4. Before this migration THERE IS NO COLUMN A
-- RESCAN COULD MATCH ON. iga_agents (004:532) is id, workspace_id,
-- estate_scope_id, display_name, classification, status, rollup_state,
-- lifecycle, version, created_at, updated_at -- that is the whole table, and
-- the same is true of identity accounts, resources, entitlements and
-- credentials. "Repeat scan keeps IDs" was not a bug in the code; it was
-- impossible in the schema.
--
-- source_key is namespaced, ALWAYS: provider | partition | account | region |
-- native-id, joined with \x1f. Built in exactly one place --
-- internal/igagraph/sourcekey.go -- and never formatted inline.
--
-- THREE DECISIONS, each deliberate:
--
--   DEFAULT '' PLUS A PARTIAL UNIQUE INDEX. Existing production rows have no
--   recognition key and cannot be given one: they were minted by uuid.New()
--   from GitHub scans and nothing records their origin. A TOTAL unique index
--   would collapse every one of them into a single row. The partial index lets
--   legacy rows coexist while constraining every new one. 035 retires them,
--   as a separate PR, after one clean production scan on the new path --
--   never tighten a constraint in the release that introduces its column.
--
--   lifecycle <> 'retired' IN THE PREDICATE is what makes delete-and-recreate
--   expressible (§2.4): the retired row KEEPS its source_key, the new row
--   takes the same key, and only one of them is live. Retired objects must
--   keep their key -- the partial indexes depend on it.
--
--   iga_credentials IS INCLUDED because P2-4 gives all five upsert methods a
--   conflict target and UpsertCredential is one of them. Its key is the
--   credential's own id namespaced by its identity's source_key (§2.5).
-- ============================================================================

-- iga_entitlements has no lifecycle column ----------------------------------
-- Checked against 004:667: id, workspace_id, resource_id, native_grant_kind,
-- native_rights, normalized_rights, native_scope, remediable, created_at,
-- updated_at. The partial index predicate below would therefore fail with
-- `column "lifecycle" does not exist`. Add it matching the other tables rather
-- than special-casing the index -- a differently-shaped table here would mean
-- the projector needs a second retire path for entitlements alone.
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS lifecycle text NOT NULL DEFAULT 'active';

ALTER TABLE public.iga_entitlements
    ADD CONSTRAINT iga_entitlements_lifecycle_chk CHECK (
        lifecycle IN ('active', 'retired', 'tombstoned'));

-- PHASE 3 WARNING, recorded where a reader will actually meet it.
COMMENT ON TABLE public.iga_entitlements IS
    'One entitlement per COLLECTED GRANT OCCURRENCE, keyed by policy scope '
    '(§2.6): managed policies are shared across holders, inline policies are '
    'namespaced by the holding identity. '
    'ENTITLEMENT IDS ARE NOT STABLE ACROSS PHASE 3: Phase 3 collapses the '
    'three resource-rows of one statement into a single statement entitlement '
    'plus three grant-resource rows, which re-keys them. ATTACH NO REVIEW '
    'DECISION, NO OWNERSHIP AND NO CERTIFICATION TO AN ENTITLEMENT ID IN '
    'PHASE 2.';

-- iga_identity_accounts ------------------------------------------------------
ALTER TABLE public.iga_identity_accounts
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_identity_accounts
    ADD CONSTRAINT iga_identity_accounts_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    -- A row claiming a creation boundary must carry one. The loud failure is
    -- the point: Continuity() saying 'immutable' while ImmutableKey() returns
    -- '' would silently disable delete-and-recreate detection, and nothing
    -- downstream could notice.
    ADD CONSTRAINT iga_identity_accounts_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_identity_accounts_source_key
    ON public.iga_identity_accounts (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_resources --------------------------------------------------------------
ALTER TABLE public.iga_resources
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_resources
    ADD CONSTRAINT iga_resources_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    ADD CONSTRAINT iga_resources_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_resources_source_key
    ON public.iga_resources (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_entitlements -----------------------------------------------------------
ALTER TABLE public.iga_entitlements
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_entitlements
    ADD CONSTRAINT iga_entitlements_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    ADD CONSTRAINT iga_entitlements_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_entitlements_source_key
    ON public.iga_entitlements (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_agents -----------------------------------------------------------------
ALTER TABLE public.iga_agents
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_agents
    ADD CONSTRAINT iga_agents_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    ADD CONSTRAINT iga_agents_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_agents_source_key
    ON public.iga_agents (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle <> 'retired';

-- iga_credentials ------------------------------------------------------------
-- §2.5: a credential row is NEVER deleted and the identity keeps its id and
-- first_seen_at through any key change. iga_credentials already constrains
-- lifecycle IN ('active','expired','revoked','rotated') at 004:614 -- use it.
ALTER TABLE public.iga_credentials
    ADD COLUMN IF NOT EXISTS source_key     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS continuity     text NOT NULL DEFAULT 'recognition_only',
    ADD COLUMN IF NOT EXISTS immutable_key  text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS first_seen_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS retired_reason text NOT NULL DEFAULT '';

ALTER TABLE public.iga_credentials
    ADD CONSTRAINT iga_credentials_continuity_chk CHECK (
        continuity IN ('immutable', 'recognition_only')),
    ADD CONSTRAINT iga_credentials_immutable_chk CHECK (
        continuity <> 'immutable' OR immutable_key <> '');

-- A credential's lifecycle vocabulary differs from the node tables': a revoked
-- key is not a 'retired' row, so the predicate names the states that mean
-- "this key is gone" rather than reusing the node predicate.
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_credentials_source_key
    ON public.iga_credentials (workspace_id, source_key)
    WHERE source_key <> '' AND lifecycle NOT IN ('revoked', 'expired');

COMMENT ON COLUMN public.iga_identity_accounts.continuity IS
    'immutable only where the provider gives a creation-boundary id (IAM role '
    'RoleId AROA..., IAM user UserId AIDA...). recognition_only means the name '
    'is the strongest claim available, stored so the console can SAY so rather '
    'than implying a continuity we never verified.';

COMMENT ON COLUMN public.iga_identity_accounts.source_key IS
    'Namespaced recognition key, built only by internal/igagraph.Key. A '
    'retired row KEEPS its source_key -- the partial unique index depends on '
    'it to express delete-and-recreate.';

-- iga_estate_scopes ----------------------------------------------------------
-- §4.8: every canonical node has estate_scope_id and NOTHING IN THE TREE
-- POPULATES iga_estate_scopes -- checked. The projector must create the scope
-- before the nodes that reference it, or every object lands with a NULL scope
-- and reconciliation has no partition to work in.
--
-- To upsert it the table needs a natural key, and it has none: 004 gave it
-- only a primary key on id and UNIQUE (workspace_id, id). For AWS the scope is
-- the connected account, keyed like everything else.
--
-- Region is deliberately NOT a sub-scope in Phase 2. It would multiply
-- partitions without changing any authorization boundary -- IAM is global, and
-- a denied region is a COVERAGE fact, not a containment one.
ALTER TABLE public.iga_estate_scopes
    ADD COLUMN IF NOT EXISTS source_key text NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_estate_scopes_source_key
    ON public.iga_estate_scopes (workspace_id, source_key)
    WHERE source_key <> '';

-- verify ---------------------------------------------------------------------
SELECT c.relname AS tbl,
       count(*) FILTER (WHERE a.attname = 'source_key')    AS has_source_key,
       count(*) FILTER (WHERE a.attname = 'continuity')    AS has_continuity,
       count(*) FILTER (WHERE a.attname = 'first_seen_at') AS has_first_seen
  FROM pg_class c
  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
 WHERE c.relname IN ('iga_identity_accounts', 'iga_resources', 'iga_entitlements',
                     'iga_agents', 'iga_credentials')
 GROUP BY c.relname
 ORDER BY c.relname;
