-- ============================================================================
-- 025: a dedupe key for evidence that has no subject.
--
-- uq_cloud_observation_dedupe (022) is keyed on
-- (workspace_id, COALESCE(identity_id, permission_id, resource_id,
-- workload_id), source_api, content_hash). That COALESCE was written for the
-- four ordinary subjects, all of which are backed by a real row -- it was
-- never meant to also define what "the same fact" means for a row with none.
--
-- AgentCore Workload Identities (see AgentCoreAPI.ListWorkloadIdentities and
-- AWSWorkloadScanner.scanWorkloadIdentities) have no cloud_identity,
-- cloud_permission, cloud_resource or cloud_workload row to attach to, so
-- every one of their observations carries all four subject columns NULL. Feed
-- that into the existing COALESCE and every insert is unique regardless of
-- content: Postgres never treats two NULLs as equal for a unique index, so
-- the index that exists specifically to stop an unchanged re-read from
-- growing the table does not fire, and this one kind of evidence grows a new
-- row every single scan.
--
-- The fix is a second, partial index scoped to exactly the rows the first one
-- cannot dedupe: no subject at all. ObservationWriter.Record picks whichever
-- conflict target actually matches the row it is writing.
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_observation_dedupe_no_subject
    ON public.cloud_observation (workspace_id, source_api, content_hash)
    WHERE identity_id IS NULL
      AND permission_id IS NULL
      AND resource_id IS NULL
      AND workload_id IS NULL;

COMMENT ON INDEX uq_cloud_observation_dedupe_no_subject IS
    'Dedupe key for evidence with no subject at all (AgentCore Workload '
    'Identities today) -- uq_cloud_observation_dedupe cannot cover this case '
    'because COALESCE over four NULLs is NULL, and Postgres never treats two '
    'NULLs as equal for uniqueness.';

-- verify -------------------------------------------------------------------
SELECT count(*) AS no_subject_dedupe_index
  FROM pg_indexes
 WHERE indexname = 'uq_cloud_observation_dedupe_no_subject';
