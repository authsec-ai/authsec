-- ============================================================================
-- 021: say WHICH account a resource belongs to, and WHAT it actually is.
--
-- Two things the console got wrong, both visible in a screenshot and both the
-- kind of error that becomes a misleading graph edge the moment these rows are
-- drawn as a graph.
--
-- 1. THE ACCOUNT COLUMN WAS THE OBSERVER'S, NOT THE RESOURCE'S.
--    cloud_resource records connector_id -- where the reference was seen -- and
--    the console rendered that connector's account beside every row. So
--    arn:aws:iam::429418377036:role/RefundWriterRole displayed as belonging to
--    491056652413, the account we happened to be scanning.
--
--    A policy in one account may legitimately name a resource in another; that
--    is what a cross-account grant IS. Reporting the observer's account as the
--    resource's turns a normal external reference into an apparent local
--    resource, and would later draw an edge into an account we never scanned.
--
--    The fix is not to hide the external reference but to label it: the account
--    from the ARN, and a flag saying it is not the scanned one. Whether that
--    external resource really exists stays unknown until something independently
--    discovers it -- a selector naming an ARN has never been proof the thing is
--    there.
--
-- 2. AN S3 OBJECT WAS STORED AS A BUCKET.
--    arn:aws:s3:::acme-iga-attachments/sandbox/probe.txt had its key stripped
--    to derive a name, then kept the full object ARN as native_id and the kind
--    "s3_bucket". Two objects in one bucket therefore produced two rows both
--    claiming to be that bucket, and the type counts said "3 S3 buckets" when
--    some were objects.
--
--    A bucket and an object inside it are different grant targets with different
--    blast radius. s3:DeleteObject on one key is not s3:DeleteObject on the
--    bucket, and a reviewer who cannot tell them apart cannot judge either.
-- ============================================================================

-- The account the RESOURCE lives in, parsed from its own ARN. Empty for the
-- services whose ARNs carry no account segment (S3 buckets, notably).
ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS resource_account text NOT NULL DEFAULT '';

-- True when resource_account is set and differs from the scanned account.
--
-- Stored rather than computed on read: the comparison needs the connector's
-- account, and a view that has the resource row but not the connector would
-- otherwise have to guess -- or worse, default to "local".
ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS is_external boolean NOT NULL DEFAULT false;

-- For an S3 object, the key. Empty for a bucket and for every other service.
-- Kept because the key IS the grant target, and truncating it to the bucket
-- loses the distinction the row exists to record.
ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS object_key text NOT NULL DEFAULT '';

-- Where `sensitivity` came from.
--
-- The console showed "High" with nothing behind it, so a reader could not tell
-- a customer classification from a provider fact from one of our own guesses.
-- Today every value is 'heuristic_service' -- an AuthSec rule keyed on the
-- service segment of the ARN, nothing more -- and saying so is the difference
-- between a judgement someone can weigh and an assertion they must take on
-- trust.
ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS sensitivity_source text NOT NULL DEFAULT 'heuristic_service';

ALTER TABLE public.cloud_resource
    ADD COLUMN IF NOT EXISTS sensitivity_reason text NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_resource_sensitivity_source_chk'
    ) THEN
        ALTER TABLE public.cloud_resource
            ADD CONSTRAINT cloud_resource_sensitivity_source_chk
            CHECK (sensitivity_source IN
                ('heuristic_service', 'provider_metadata', 'customer_classification', 'unknown'));
    END IF;
END $$;

-- An external resource is one whose account we know and which is not ours.
-- Without resource_account there is nothing to be external TO.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_resource_external_chk'
    ) THEN
        ALTER TABLE public.cloud_resource
            ADD CONSTRAINT cloud_resource_external_chk
            CHECK (NOT is_external OR resource_account <> '');
    END IF;
END $$;

-- Only an S3 object carries a key.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'cloud_resource_object_key_chk'
    ) THEN
        ALTER TABLE public.cloud_resource
            ADD CONSTRAINT cloud_resource_object_key_chk
            CHECK (object_key = '' OR kind = 's3_object');
    END IF;
END $$;

COMMENT ON COLUMN public.cloud_resource.resource_account IS
    'Account from the resource''s OWN ARN, not the connector that observed it.';
COMMENT ON COLUMN public.cloud_resource.is_external IS
    'The resource belongs to an account other than the one scanned. Its '
    'existence is unverified: a policy naming an ARN is not proof it is there.';
COMMENT ON COLUMN public.cloud_resource.sensitivity_source IS
    'heuristic_service | provider_metadata | customer_classification | unknown. '
    'Today everything is heuristic_service -- an AuthSec rule on the ARN''s '
    'service segment.';

-- "Which of these are not in the account I scanned?" is the question a reviewer
-- asks first about a cross-account grant.
CREATE INDEX IF NOT EXISTS idx_cloud_resource_external
    ON public.cloud_resource (workspace_id, connector_id)
    WHERE is_external;

-- Existing rows predate the parse. Their account is UNKNOWN rather than local:
-- defaulting them to the connector's account would re-assert exactly the error
-- this migration exists to correct. The next scan fills them in.
UPDATE public.cloud_resource
   SET sensitivity_source = 'unknown'
 WHERE sensitivity_source = 'heuristic_service';

-- verify -------------------------------------------------------------------
SELECT count(*) AS new_columns
  FROM information_schema.columns
 WHERE table_schema = 'public' AND table_name = 'cloud_resource'
   AND column_name IN ('resource_account','is_external','object_key',
                       'sensitivity_source','sensitivity_reason');
