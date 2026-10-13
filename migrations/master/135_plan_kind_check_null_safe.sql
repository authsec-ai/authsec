-- ============================================================================
-- 135: iga_gov_plan_kind_chk is NULL-safe (R2, DECISION R2-13)
--
-- 061 admits a split / split_revert plan delivered DIRECTLY only when its
-- subject is a Lambda function: (diff -> 'split' ->> 'subject_kind') =
-- 'lambda_function'. For a plan whose diff names no subject kind that
-- comparison is NULL, and a CHECK whose result is NULL passes -- so any
-- direct split without a subject kind was accepted. The comparison now
-- treats a missing kind as not a Lambda function. Every row valid under 061's
-- intent stays valid; the constraint is added NOT VALID and then validated
-- (a row that slipped through before would fail the validation and is left
-- for review rather than blocking the upgrade).
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE iga_gov_plan DROP CONSTRAINT IF EXISTS iga_gov_plan_kind_chk;
ALTER TABLE iga_gov_plan ADD CONSTRAINT iga_gov_plan_kind_chk CHECK (
    (kind IN ('split','split_revert')) = (desired_attachment = 'unchanged')
    AND (kind <> 'apply' OR desired_attachment = 'present')
    AND (kind NOT IN ('split','split_revert') OR delivery IN ('iac_pr','export')
         OR (delivery = 'direct' AND (eligibility = 'ineligible'
             OR (eligibility = 'eligible'
                 AND COALESCE(diff -> 'split' ->> 'subject_kind', '') = 'lambda_function'))))) NOT VALID;

DO $$
BEGIN
    ALTER TABLE iga_gov_plan VALIDATE CONSTRAINT iga_gov_plan_kind_chk;
EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '135: existing iga_gov_plan rows violate iga_gov_plan_kind_chk (a direct split without a Lambda subject); constraint left NOT VALID for review';
END $$;
