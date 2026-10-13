-- 137_access_policies.sql
--
-- Access policies (decision, Aditya, 2026-10-13): an admin picks an S3 bucket
-- and roles from Discovery, chooses Block or Allow and a time window, and
-- presses Apply; AuthSec attaches one AuthSec-owned managed policy per role
-- and AWS enforces it. There is no approver step and no ownership.
--
-- 1. iga_gov_access_policy_version: immutable, versioned access intents of
--    an iga_gov_policy of family 'time_bound' (049 already admits it). One
--    version is 'applied' per policy; an edit supersedes it.
-- 2. iga_gov_temp_grant gains effect (allow | deny), policy_id, version_id
--    and starts_at: an access policy's deployments are temp_grant rows, one
--    per role per version, run by the existing temp_grant job.
-- 3. Two temp_grant CHECKs are widened for access-policy rows only (every row
--    valid before stays valid, and R2 grants keep both rules):
--      iga_gov_tg_sod_chk     -- the admin applies their own policy;
--      iga_gov_tg_window_chk  -- a block may have no end (9999-12-31) and an
--                                allow may start up to 30 days ahead.
-- 4. Every workspace admin role holds every governance:* permission (a
--    backfill for admin roles created after 055 / 061 by any other path).
--
-- Expand only: one table, four nullable / defaulted columns, two widened
-- CHECKs, one index, idempotent permission rows. Idempotent: safe to run
-- again. 001_bootstrap.sql carries the same objects.

CREATE TABLE IF NOT EXISTS iga_gov_access_policy_version (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  policy_id    uuid NOT NULL,
  version_no   int  NOT NULL CHECK (version_no > 0),
  intent       jsonb NOT NULL,
  intent_hash  text NOT NULL CHECK (intent_hash ~ '^sha256:[0-9a-f]{64}$'),
  status       text NOT NULL DEFAULT 'applied' CHECK (status IN ('applied','superseded')),
  created_by   uuid NOT NULL REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  status_changed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, id, policy_id),
  UNIQUE (policy_id, version_no),
  FOREIGN KEY (workspace_id, policy_id) REFERENCES iga_gov_policy (workspace_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_iga_gov_access_policy_version_applied
  ON iga_gov_access_policy_version (policy_id) WHERE status = 'applied';

-- A version never changes, except applied -> superseded.
CREATE OR REPLACE FUNCTION iga_gov_access_policy_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id = OLD.id AND NEW.workspace_id = OLD.workspace_id AND NEW.policy_id = OLD.policy_id
     AND NEW.version_no = OLD.version_no AND NEW.intent = OLD.intent AND NEW.intent_hash = OLD.intent_hash
     AND NEW.created_by = OLD.created_by AND NEW.created_at = OLD.created_at
     AND (NEW.status = OLD.status OR (OLD.status = 'applied' AND NEW.status = 'superseded')) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'iga_gov_access_policy_version % is immutable; create a new version', OLD.id;
END $$;
DROP TRIGGER IF EXISTS iga_gov_access_policy_version_immutable ON iga_gov_access_policy_version;
CREATE TRIGGER iga_gov_access_policy_version_immutable BEFORE UPDATE ON iga_gov_access_policy_version
  FOR EACH ROW EXECUTE FUNCTION iga_gov_access_policy_version_immutable();

ALTER TABLE iga_gov_temp_grant ADD COLUMN IF NOT EXISTS effect     text NOT NULL DEFAULT 'allow';
ALTER TABLE iga_gov_temp_grant ADD COLUMN IF NOT EXISTS policy_id  uuid;
ALTER TABLE iga_gov_temp_grant ADD COLUMN IF NOT EXISTS version_id uuid;
ALTER TABLE iga_gov_temp_grant ADD COLUMN IF NOT EXISTS starts_at  timestamptz;

ALTER TABLE iga_gov_temp_grant DROP CONSTRAINT IF EXISTS iga_gov_tg_effect_chk;
ALTER TABLE iga_gov_temp_grant ADD CONSTRAINT iga_gov_tg_effect_chk CHECK (effect IN ('allow','deny'));
-- An access-policy row names both its policy and version; a deny, a start
-- time or a decided-by-requester row is an access-policy row.
ALTER TABLE iga_gov_temp_grant DROP CONSTRAINT IF EXISTS iga_gov_tg_access_chk;
ALTER TABLE iga_gov_temp_grant ADD CONSTRAINT iga_gov_tg_access_chk CHECK (
  ((policy_id IS NULL) = (version_id IS NULL))
  AND (policy_id IS NOT NULL OR (effect = 'allow' AND starts_at IS NULL))
  AND (starts_at IS NULL OR starts_at < expires_at));
ALTER TABLE iga_gov_temp_grant DROP CONSTRAINT IF EXISTS iga_gov_tg_version_fk;
ALTER TABLE iga_gov_temp_grant ADD CONSTRAINT iga_gov_tg_version_fk
  FOREIGN KEY (workspace_id, version_id, policy_id) REFERENCES iga_gov_access_policy_version (workspace_id, id, policy_id);

ALTER TABLE iga_gov_temp_grant DROP CONSTRAINT IF EXISTS iga_gov_tg_sod_chk;
ALTER TABLE iga_gov_temp_grant ADD CONSTRAINT iga_gov_tg_sod_chk
  CHECK (decided_by IS NULL OR decided_by <> requested_by OR policy_id IS NOT NULL);
ALTER TABLE iga_gov_temp_grant DROP CONSTRAINT IF EXISTS iga_gov_tg_window_chk;
ALTER TABLE iga_gov_temp_grant ADD CONSTRAINT iga_gov_tg_window_chk CHECK (
  expires_at > created_at
  AND (policy_id IS NOT NULL OR expires_at <= created_at + interval '31 days'));

CREATE INDEX IF NOT EXISTS idx_iga_gov_temp_grant_policy
  ON iga_gov_temp_grant (workspace_id, policy_id, version_id) WHERE policy_id IS NOT NULL;

-- Admin by default: every workspace admin role holds every governance:*
-- permission of the platform catalog.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE r.name = 'admin' AND r.workspace_id IS NOT NULL AND p.workspace_id IS NULL
  AND p.resource = 'governance'
ON CONFLICT (role_id, permission_id) DO NOTHING;

DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.iga_gov_access_policy_version');
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.iga_gov_access_policy_version') IS NULL THEN
        RAISE EXCEPTION '137: iga_gov_access_policy_version is missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'iga_gov_access_policy_version_immutable'
                    AND tgrelid = 'public.iga_gov_access_policy_version'::regclass) THEN
        RAISE EXCEPTION '137: the version immutability trigger is missing';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'iga_gov_temp_grant' AND column_name = 'effect') THEN
        RAISE EXCEPTION '137: iga_gov_temp_grant.effect is missing';
    END IF;
END $$;
