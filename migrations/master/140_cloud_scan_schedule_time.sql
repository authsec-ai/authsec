-- ============================================================================
-- 140: a chosen time of day, timezone and weekday for automatic AWS rescans.
--
-- Until now a schedule ran one interval after it was turned on, so the time of
-- day was whenever an administrator happened to switch it on. These columns let
-- the administrator choose it. All three are optional: time_of_day_minutes NULL
-- keeps the original behaviour, so every existing schedule is unchanged.
--
--   time_of_day_minutes  minutes after local midnight, on a quarter hour.
--   timezone             IANA zone name the time is read in. UTC by default.
--   day_of_week          0 = Sunday .. 6 = Saturday. Used by weekly schedules.
--
-- Expand only. Idempotent: safe to run again.
-- 001_bootstrap.sql carries the same block at its end.
-- ============================================================================

ALTER TABLE public.cloud_scan_schedule
    ADD COLUMN IF NOT EXISTS time_of_day_minutes integer,
    ADD COLUMN IF NOT EXISTS timezone            text     NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS day_of_week         smallint;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'cloud_scan_schedule_time_chk') THEN
        ALTER TABLE public.cloud_scan_schedule
            ADD CONSTRAINT cloud_scan_schedule_time_chk
            CHECK (time_of_day_minutes IS NULL
                   OR (time_of_day_minutes BETWEEN 0 AND 1439 AND time_of_day_minutes % 15 = 0));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'cloud_scan_schedule_weekday_chk') THEN
        ALTER TABLE public.cloud_scan_schedule
            ADD CONSTRAINT cloud_scan_schedule_weekday_chk
            CHECK (day_of_week IS NULL OR day_of_week BETWEEN 0 AND 6);
    END IF;
END $$;
