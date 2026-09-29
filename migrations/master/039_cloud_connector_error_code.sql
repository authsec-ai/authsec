-- ============================================================================
-- 039: a stable classification alongside cloud_connector.last_error
--
-- last_error (010) holds the provider's own prose, which is the right thing to
-- show an operator who is debugging. It is the wrong thing to render in a
-- narrow list column: "the role could not be assumed: User: arn:aws:iam::..."
-- truncates to noise, and a reader cannot recover the class of failure from
-- the prefix.
--
-- The classification already exists in Go -- mapAWSOnboardingError runs an
-- errors.Is ladder over the same error value -- but only at HTTP-response
-- time, for the request that failed. It is never persisted, so a connector
-- read back later carries the prose and nothing else, and the console has no
-- honest way to say "Role assumption failed" without parsing the message.
--
-- This column stamps that class where the error is recorded, following the
-- precedent SurfaceCoverage.error_code set in 010's coverage blob: a code is
-- written at the point the error is understood, so no reader ever has to parse
-- the prose back into a code.
--
-- Deliberately NOT constrained to a fixed set. An unclassified failure is a
-- real outcome (the default ''), and a CHECK would turn adding a new sentinel
-- in Go into a migration.
-- ============================================================================

ALTER TABLE public.cloud_connector
    ADD COLUMN IF NOT EXISTS last_error_code text NOT NULL DEFAULT '';

COMMENT ON COLUMN public.cloud_connector.last_error_code IS
    'Stable class of the failure in last_error (e.g. assume_denied, throttled). '
    'Empty when the error was not classified. The prose stays in last_error.';
