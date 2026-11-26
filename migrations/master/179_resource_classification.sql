-- 179_resource_classification.sql
--
-- Resource classification (SPEC-secops-backend-upgrade.md W7, C12, P14).
-- cloud_resource.sensitivity was AuthSec's heuristic only. A resource now
-- also says whether it is a crown jewel, what category of data it holds and
-- where that data must reside, and who classified it.
--
-- Where a value comes from is sensitivity_source (013): heuristic_service
-- (AuthSec's rule), provider_metadata (the resource's own tags read during a
-- scan: authsec:sensitivity, authsec:data-category, authsec:residency,
-- authsec:crown-jewel; a Macie or Purview reader would write here too) or
-- customer_classification (a person, PUT /api/iga/v1/resources/:id/
-- classification). A scan never stamps over a customer's classification.
--
-- Raising is tier 0 and applies at once; lowering (sensitivity down, crown
-- jewel off) is tier 3 and waits in agent_pending_change for a second person.
--
-- Expand only; idempotent. 001_bootstrap.sql carries the same columns.

ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS crown_jewel   boolean     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS data_category text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS residency     text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS classified_by uuid,
    ADD COLUMN IF NOT EXISTS classified_at timestamptz;

DO $$
BEGIN
    ALTER TABLE public.cloud_resource DROP CONSTRAINT IF EXISTS cloud_resource_data_category_chk;
    ALTER TABLE public.cloud_resource ADD CONSTRAINT cloud_resource_data_category_chk
        CHECK (length(data_category) <= 64);
    ALTER TABLE public.cloud_resource DROP CONSTRAINT IF EXISTS cloud_resource_residency_chk;
    ALTER TABLE public.cloud_resource ADD CONSTRAINT cloud_resource_residency_chk
        CHECK (length(residency) <= 64);
    ALTER TABLE public.cloud_resource DROP CONSTRAINT IF EXISTS cloud_resource_classified_chk;
    ALTER TABLE public.cloud_resource ADD CONSTRAINT cloud_resource_classified_chk
        CHECK ((classified_by IS NULL) = (classified_at IS NULL));
END $$;

CREATE INDEX IF NOT EXISTS idx_cloud_resource_crown_jewel
    ON public.cloud_resource (workspace_id, id) WHERE crown_jewel;
