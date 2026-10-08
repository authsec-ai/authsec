-- ============================================================================
-- 108: audit_events rows cannot be modified
--
-- An audit record that can be rewritten is not evidence (AS-049). UPDATE is
-- refused; DELETE stays allowed for the retention job
-- (monitoring.AuditLogger.CleanupOldEvents). Numbers 045-049 are reserved
-- for the tenancy schema migrations.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events rows are append-only';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_events_immutable ON public.audit_events;
CREATE TRIGGER trg_audit_events_immutable
    BEFORE UPDATE ON public.audit_events
    FOR EACH ROW EXECUTE FUNCTION public.audit_events_immutable();
