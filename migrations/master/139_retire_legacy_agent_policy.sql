-- Superseded pre-Phase-3 policy implementation, removed by product decision.
-- No customer migration/compatibility period is required. Shared discovery,
-- graph, workspace and runtime authorization tables are deliberately untouched.
DROP TABLE IF EXISTS public.agent_policy_warnings;
DROP TABLE IF EXISTS public.agent_policy_confirmations;
DROP TABLE IF EXISTS public.agent_policy_actions;
DROP TABLE IF EXISTS public.agent_policies;
DROP TABLE IF EXISTS public.enforcement_plans;
DROP TABLE IF EXISTS public.governance_notification_settings;

UPDATE public.iga_gov_settings SET notify_channels_source = 'phase3' WHERE notify_channels_source = 'legacy_copy';
ALTER TABLE public.iga_gov_settings DROP CONSTRAINT IF EXISTS iga_gov_settings_notify_channels_source_check;
ALTER TABLE public.iga_gov_settings ADD CONSTRAINT iga_gov_settings_notify_channels_source_check CHECK (notify_channels_source IN ('default','phase3'));
ALTER TABLE public.iga_gov_settings DROP COLUMN IF EXISTS notify_channels_copied_at;
