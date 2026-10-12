-- ============================================================================
-- 115: otp_entries.workspace_id, otp_entries.purpose
--
-- An emailed one-time code was keyed by email alone, so a code issued for one
-- flow or workspace (end-user sign-up in workspace A) could be verified or
-- deleted by another (password reset in workspace B, admin sign-up), and a
-- "verified" row from one flow unlocked another (AS-038). Each row now names
-- the flow it was issued for (purpose) and, where the workspace is known at
-- issue time, the workspace. Readers match both.
--
-- workspace_id stays nullable: workspace sign-up and admin password reset
-- run before a workspace is known. Rows written before this migration have
-- purpose '' and match no reader; they are short-lived (10-30 minutes), so
-- in-flight codes at upgrade time must be requested again.
-- ============================================================================

ALTER TABLE public.otp_entries
    ADD COLUMN IF NOT EXISTS workspace_id uuid;
ALTER TABLE public.otp_entries
    ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_otp_entries_email_purpose
    ON public.otp_entries (email, purpose);

SELECT public.tenancy_enable_rls('public.otp_entries');
